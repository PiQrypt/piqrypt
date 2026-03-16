# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
decision_queue.py — Trust Gate Decision Queue

Manages decisions pending human approval (REQUIRE_HUMAN).

When the policy engine returns REQUIRE_HUMAN:
1. Decision is enqueued here
2. Agent is blocked — cannot proceed
3. Notifier pushes to responsible principals
4. Human approves or rejects via API or console
5. Decision is resolved — agent is unblocked or permanently blocked

Timeout policy (configurable in policy.yaml):
    on_timeout: REJECT   → decision auto-rejected (ANSSI strict / AI Act)
    on_timeout: BLOCK    → decision becomes BLOCK (AI Act high-risk)
    on_timeout: ESCALATE → forwarded to L2 principal

Compliance:
    ANSSI R9   — human must be in decision loop, no timeout bypass
    AI Act Art.14 — human oversight mechanism, always interruptible
    NIST MANAGE 2.2 — documented human oversight procedure
"""

import json
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from trustgate.decision import Decision, DecisionState, Outcome
from trustgate.human_principal import HumanPrincipal, InsufficientClearanceError


# ─── Constants ────────────────────────────────────────────────────────────────

DEFAULT_QUEUE_DIR = Path.home() / ".piqrypt" / "trustgate" / "queue"


# ─── Exceptions ───────────────────────────────────────────────────────────────

class DecisionNotFoundError(Exception):
    pass

class DecisionAlreadyResolvedError(Exception):
    pass

class DecisionTimedOutError(Exception):
    pass


# ─── Decision Queue ───────────────────────────────────────────────────────────

class DecisionQueue:
    """
    Persistent queue of decisions pending human approval.

    Each pending decision is stored as a JSON file in queue_dir/pending/.
    Resolved decisions are moved to queue_dir/resolved/.

    Thread-safe for concurrent API requests.
    """

    def __init__(
        self,
        queue_dir: Path = DEFAULT_QUEUE_DIR,
        on_timeout_default: str = "REJECT",
        audit_journal=None,
    ):
        self.queue_dir          = queue_dir
        self.on_timeout_default = on_timeout_default
        self.audit_journal      = audit_journal

        self._pending_dir  = queue_dir / "pending"
        self._resolved_dir = queue_dir / "resolved"
        self._pending_dir.mkdir(parents=True, exist_ok=True)
        self._resolved_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()

        # In-memory callbacks for real-time notification
        self._on_resolve_callbacks: List[Callable] = []

        # Start timeout watcher
        self._watcher_thread = threading.Thread(
            target=self._timeout_watcher,
            daemon=True,
            name="trustgate-timeout-watcher",
        )
        self._watcher_thread.start()

    # ── Enqueue ───────────────────────────────────────────────────────────────

    def enqueue(self, decision: Decision) -> Decision:
        """
        Add a REQUIRE_HUMAN decision to the queue.
        Agent is considered blocked until resolution.

        Returns the Decision (with timeout_at set).
        """
        if decision.outcome != Outcome.REQUIRE_HUMAN:
            raise ValueError(
                f"Only REQUIRE_HUMAN decisions can be enqueued, got {decision.outcome}"
            )

        with self._lock:
            self._persist_pending(decision)

        return decision

    # ── Approve / Reject ──────────────────────────────────────────────────────

    def approve(
        self,
        decision_id: str,
        principal: HumanPrincipal,
        token_or_session,
        justification: str = "",
        sso_secret: bytes = b"trustgate-internal-secret",
    ) -> Decision:
        """
        Approve a pending decision.

        Compliance:
            AI Act Art.14 — human approves with signed record
            ANSSI R9 — principal_id + signature stored

        Args:
            decision_id:     ID of the pending decision
            principal:       Human Principal performing the approval
            token_or_session: SSOToken (Phase 1) or open session (Phase 2)
            justification:   Optional reason — mandatory for ANSSI strict
        """
        with self._lock:
            decision = self._load_pending(decision_id)
            self._assert_not_resolved(decision)
            self._assert_not_timed_out(decision)

            # Clearance check — ANSSI R30
            principal.assert_can_approve(decision.vrs_at_decision)

            # Generate signature
            from trustgate.human_principal import SSOToken
            if isinstance(token_or_session, SSOToken):
                # Phase 1 — SSO
                signature = principal.sign_decision_sso(
                    decision_id   = decision_id,
                    outcome       = "APPROVED",
                    token         = token_or_session,
                    justification = justification,
                    secret        = sso_secret,
                )
            else:
                # Phase 2 — AISS
                signature = principal.sign_decision_aiss(
                    decision_id   = decision_id,
                    outcome       = "APPROVED",
                    justification = justification,
                )

            decision.approve(
                principal_id  = principal.record.principal_id,
                signature     = signature,
                justification = justification,
            )

            self._move_to_resolved(decision)

        # Journal update
        if self.audit_journal:
            self.audit_journal.record(decision)

        # Callbacks
        self._fire_callbacks(decision)
        return decision

    def reject(
        self,
        decision_id: str,
        principal: HumanPrincipal,
        token_or_session,
        justification: str = "",
        sso_secret: bytes = b"trustgate-internal-secret",
    ) -> Decision:
        """
        Reject a pending decision — action will be denied.

        Compliance: AI Act Art.14 — human can always stop the agent
        """
        with self._lock:
            decision = self._load_pending(decision_id)
            self._assert_not_resolved(decision)
            self._assert_not_timed_out(decision)

            principal.assert_can_approve(decision.vrs_at_decision)

            from trustgate.human_principal import SSOToken
            if isinstance(token_or_session, SSOToken):
                signature = principal.sign_decision_sso(
                    decision_id   = decision_id,
                    outcome       = "REJECTED",
                    token         = token_or_session,
                    justification = justification,
                    secret        = sso_secret,
                )
            else:
                signature = principal.sign_decision_aiss(
                    decision_id   = decision_id,
                    outcome       = "REJECTED",
                    justification = justification,
                )

            decision.reject(
                principal_id  = principal.record.principal_id,
                signature     = signature,
                justification = justification,
            )

            self._move_to_resolved(decision)

        if self.audit_journal:
            self.audit_journal.record(decision)

        self._fire_callbacks(decision)
        return decision

    # ── Query ─────────────────────────────────────────────────────────────────

    def get_pending(
        self,
        agent_id: Optional[str] = None,
        include_timed_out: bool = False,
    ) -> List[Decision]:
        """
        Return all pending decisions, optionally filtered by agent.
        Used by Trust Gate Console — Decision Queue UI.
        """
        decisions = []
        for path in sorted(self._pending_dir.glob("*.json")):
            try:
                d = self._load_from_path(path)
                if agent_id and d.agent_id != agent_id:
                    continue
                if not include_timed_out and d.is_timed_out():
                    continue
                decisions.append(d)
            except Exception:
                continue
        return decisions

    def get_decision(self, decision_id: str) -> Optional[Decision]:
        """Load a decision by ID — pending or resolved."""
        # Check pending
        pending_path = self._pending_dir / f"{decision_id}.json"
        if pending_path.exists():
            return self._load_from_path(pending_path)
        # Check resolved
        resolved_path = self._resolved_dir / f"{decision_id}.json"
        if resolved_path.exists():
            return self._load_from_path(resolved_path)
        return None

    def count_pending(self, agent_id: Optional[str] = None) -> int:
        return len(self.get_pending(agent_id=agent_id))

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def on_resolve(self, callback: Callable[[Decision], None]) -> None:
        """Register a callback invoked when a decision is resolved."""
        self._on_resolve_callbacks.append(callback)

    # ── Timeout watcher ───────────────────────────────────────────────────────

    def _timeout_watcher(self) -> None:
        """
        Background thread — checks for timed-out decisions every 30s.
        Applies on_timeout policy automatically.

        ANSSI R9: no decision left pending indefinitely.
        AI Act Art.14 §4: system must be stoppable.
        """
        while True:
            time.sleep(30)
            try:
                self._process_timeouts()
            except Exception:
                pass

    def _process_timeouts(self) -> None:
        for path in list(self._pending_dir.glob("*.json")):
            try:
                decision = self._load_from_path(path)
                if not decision.is_timed_out():
                    continue

                with self._lock:
                    # Re-check under lock
                    if not path.exists():
                        continue
                    decision = self._load_from_path(path)
                    if not decision.is_timed_out():
                        continue

                    self._apply_timeout_policy(decision)
                    self._move_to_resolved(decision)

                if self.audit_journal:
                    self.audit_journal.record(decision)

                self._fire_callbacks(decision)

            except Exception:
                continue

    def _apply_timeout_policy(self, decision: Decision) -> None:
        """Apply on_timeout policy. ANSSI R9 — no silent bypass."""
        on_timeout = self.on_timeout_default

        decision.state = DecisionState.TIMED_OUT
        decision.justification = f"Auto-{on_timeout.lower()} — timeout exceeded"

        if on_timeout == "REJECT":
            decision.outcome = Outcome.BLOCK
            decision.reason += f" [TIMED OUT → auto-rejected after {decision.timeout_at}]"

        elif on_timeout == "BLOCK":
            decision.outcome = Outcome.BLOCK
            decision.reason += " [TIMED OUT → BLOCK]"

        elif on_timeout == "ESCALATE":
            # Mark for escalation — notifier will handle
            decision.outcome = Outcome.REQUIRE_HUMAN
            decision.reason += " [TIMED OUT → escalated to L2]"
            # In full implementation: re-enqueue with L2 principals
            # For now: auto-block as safe default
            decision.outcome = Outcome.BLOCK

    # ── Internal persistence ──────────────────────────────────────────────────

    def _persist_pending(self, decision: Decision) -> None:
        path = self._pending_dir / f"{decision.decision_id}.json"
        path.write_text(decision.to_json(), encoding="utf-8")

    def _load_pending(self, decision_id: str) -> Decision:
        path = self._pending_dir / f"{decision_id}.json"
        if not path.exists():
            # Check if already resolved
            resolved = self._resolved_dir / f"{decision_id}.json"
            if resolved.exists():
                raise DecisionAlreadyResolvedError(
                    f"Decision {decision_id} is already resolved"
                )
            raise DecisionNotFoundError(f"Decision {decision_id} not found in queue")
        return self._load_from_path(path)

    def _load_from_path(self, path: Path) -> Decision:
        data = json.loads(path.read_text(encoding="utf-8"))
        # Convert hex strings back to bytes
        for field in ("trustgate_signature", "approval_signature"):
            if data.get(field) and isinstance(data[field], str):
                data[field] = bytes.fromhex(data[field])
        return Decision(**data)

    def _move_to_resolved(self, decision: Decision) -> None:
        pending_path  = self._pending_dir  / f"{decision.decision_id}.json"
        resolved_path = self._resolved_dir / f"{decision.decision_id}.json"
        resolved_path.write_text(decision.to_json(), encoding="utf-8")
        pending_path.unlink(missing_ok=True)

    def _assert_not_resolved(self, decision: Decision) -> None:
        if decision.state != DecisionState.PENDING:
            raise DecisionAlreadyResolvedError(
                f"Decision {decision.decision_id} is already in state {decision.state}"
            )

    def _assert_not_timed_out(self, decision: Decision) -> None:
        if decision.is_timed_out():
            raise DecisionTimedOutError(
                f"Decision {decision.decision_id} timed out at {decision.timeout_at}. "
                f"Auto-{self.on_timeout_default.lower()} was applied."
            )

    def _fire_callbacks(self, decision: Decision) -> None:
        for cb in self._on_resolve_callbacks:
            try:
                cb(decision)
            except Exception:
                pass
