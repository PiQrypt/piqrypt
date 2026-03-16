# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# PROPRIETARY METHOD -- Dual License
# This file contains original algorithmic methods protected by
# e-Soleau deposits DSO2026006483 and DSO2026009143 (INPI France).
#
# Licensed under the Elastic License 2.0 (ELv2) for open/internal use.
# A separate commercial license is required for:
#   - SaaS or managed service deployment to third parties
#   - Proprietary products embedding this method
#   - OEM or white-label use
# Commercial license: contact@piqrypt.com -- Subject: Commercial License Inquiry

"""
decision.py — Trust Gate Decision

Every governance decision is an immutable, signed, chainable record.
It is a first-class AISS event — auditable, exportable, legally opposable.

Compliance:
    ANSSI R9  — human approval signature + justification
    ANSSI R29 — full context logged at every decision
    ANSSI R35 — policy version + hash in every record
    AI Act Art.12 — automatic logging, tamper-proof via PiQrypt chain
    AI Act Art.14 — approval_signature proves human oversight
    NIST MANAGE 2.2 — human oversight mechanism documented

Outcomes (ordered by severity):
    ALLOW             — action permitted, no log
    ALLOW_WITH_LOG    — action permitted, full context logged
    RESTRICTED        — action permitted with reduced scope
    REQUIRE_HUMAN     — action blocked pending human approval
    BLOCK             — action denied, reason logged
    QUARANTINE        — agent suspended, all actions denied
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# ─── Outcome taxonomy ────────────────────────────────────────────────────────

class Outcome(str, Enum):
    ALLOW            = "ALLOW"
    ALLOW_WITH_LOG   = "ALLOW_WITH_LOG"
    RESTRICTED       = "RESTRICTED"
    REQUIRE_HUMAN    = "REQUIRE_HUMAN"
    BLOCK            = "BLOCK"
    QUARANTINE       = "QUARANTINE"

# Outcomes that require human approval
HUMAN_REQUIRED_OUTCOMES = {Outcome.REQUIRE_HUMAN}

# Outcomes that deny the action
BLOCKING_OUTCOMES = {Outcome.REQUIRE_HUMAN, Outcome.BLOCK, Outcome.QUARANTINE}

# Outcomes that must appear in audit journal regardless of log level
ALWAYS_LOGGED = {Outcome.REQUIRE_HUMAN, Outcome.BLOCK, Outcome.QUARANTINE}


# ─── Decision state (for REQUIRE_HUMAN flow) ─────────────────────────────────

class DecisionState(str, Enum):
    PENDING   = "PENDING"     # awaiting human approval
    APPROVED  = "APPROVED"    # human approved
    REJECTED  = "REJECTED"    # human rejected
    TIMED_OUT = "TIMED_OUT"   # timeout — policy on_timeout applied
    RESOLVED  = "RESOLVED"    # final state for ALLOW/BLOCK/QUARANTINE


# ─── EvaluationContext — full input to the policy engine ─────────────────────

@dataclass
class EvaluationContext:
    """
    Complete context provided to policy_engine.evaluate().
    Immutable snapshot of the agent's state at decision time.

    ANSSI R29 / AI Act Art.12: every field is logged in the AuditEntry.
    """
    agent_id:     str
    agent_name:   str
    role:         str
    action:       str
    payload:      dict

    # Risk scores — from Vigil
    vrs:          float          # [0, 1]
    tsi_state:    str            # STABLE | WATCH | UNSTABLE | CRITICAL
    a2c_score:    float          # [0, 1]
    trust_score:  float          # [0, 1]

    # Optional
    target_domain: Optional[str] = None
    payload_str:   Optional[str] = None    # string repr for pattern matching
    timestamp:     int           = field(default_factory=lambda: int(time.time()))
    request_id:    str           = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        if self.payload_str is None:
            try:
                self.payload_str = json.dumps(self.payload, sort_keys=True)
            except Exception:
                self.payload_str = str(self.payload)

    @property
    def payload_hash(self) -> str:
        """SHA-256 of payload — stored in audit log instead of raw payload (RGPD)."""
        return hashlib.sha256(self.payload_str.encode()).hexdigest()[:16]


# ─── Decision — the core record ───────────────────────────────────────────────

@dataclass
class Decision:
    """
    Immutable governance decision record.

    Once created, a Decision is:
    - Signed by Trust Gate (trustgate_signature)
    - Chainable as an AISS event
    - Exportable as audit evidence

    REQUIRE_HUMAN decisions gain additional fields when resolved:
    - approved_by, approval_signature, approval_timestamp, justification
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    decision_id:    str = field(default_factory=lambda: str(uuid.uuid4()))

    # ── Agent context ─────────────────────────────────────────────────────────
    agent_id:       str = ""
    agent_name:     str = ""
    role:           str = ""
    action:         str = ""
    payload_hash:   str = ""     # SHA-256[:16] — RGPD, not raw payload

    # ── Risk snapshot — ANSSI R29 / Art.12 ───────────────────────────────────
    vrs_at_decision:    float = 0.0
    tsi_state:          str   = "STABLE"
    a2c_score:          float = 0.0
    trust_score:        float = 0.0

    # ── Decision ──────────────────────────────────────────────────────────────
    outcome:        str = Outcome.ALLOW
    reason:         str = ""     # human-readable — AI Act Art.13 transparency
    state:          str = DecisionState.RESOLVED

    # ── Policy traceability — ANSSI R35 / NIST MANAGE 2.4 ────────────────────
    policy_version: str = ""
    policy_hash:    str = ""

    # ── Timing ────────────────────────────────────────────────────────────────
    timestamp:      int = field(default_factory=lambda: int(time.time()))
    timeout_at:     Optional[int] = None   # set for REQUIRE_HUMAN

    # ── Trust Gate signature ──────────────────────────────────────────────────
    # Signed by Trust Gate's own keypair — proves decision integrity
    trustgate_signature: Optional[bytes] = None

    # ── Human approval — AI Act Art.14 / ANSSI R9 ────────────────────────────
    # Populated when outcome=REQUIRE_HUMAN and state=APPROVED|REJECTED
    approved_by:         Optional[str]   = None   # principal_id
    approval_signature:  Optional[bytes] = None   # Ed25519 by principal
    approval_timestamp:  Optional[int]   = None
    justification:       Optional[str]   = None

    # ── AISS chain integration ────────────────────────────────────────────────
    aiss_event_hash:     Optional[str]   = None   # set after PiQrypt stamp
    previous_hash:       Optional[str]   = None

    @classmethod
    def from_context(
        cls,
        ctx: EvaluationContext,
        outcome: Outcome,
        reason: str,
        policy_version: str,
        policy_hash: str,
        timeout_seconds: Optional[int] = None,
    ) -> "Decision":
        """Create a Decision from an EvaluationContext."""
        state = (
            DecisionState.PENDING
            if outcome == Outcome.REQUIRE_HUMAN
            else DecisionState.RESOLVED
        )
        timeout_at = (
            ctx.timestamp + timeout_seconds
            if outcome == Outcome.REQUIRE_HUMAN and timeout_seconds
            else None
        )
        return cls(
            agent_id       = ctx.agent_id,
            agent_name     = ctx.agent_name,
            role           = ctx.role,
            action         = ctx.action,
            payload_hash   = ctx.payload_hash,
            vrs_at_decision= ctx.vrs,
            tsi_state      = ctx.tsi_state,
            a2c_score      = ctx.a2c_score,
            trust_score    = ctx.trust_score,
            outcome        = outcome,
            reason         = reason,
            state          = state,
            policy_version = policy_version,
            policy_hash    = policy_hash,
            timestamp      = ctx.timestamp,
            timeout_at     = timeout_at,
        )

    def is_blocking(self) -> bool:
        return self.outcome in BLOCKING_OUTCOMES

    def is_pending(self) -> bool:
        return self.state == DecisionState.PENDING

    def is_timed_out(self) -> bool:
        if self.timeout_at is None:
            return False
        return int(time.time()) > self.timeout_at

    def approve(
        self,
        principal_id: str,
        signature: bytes,
        justification: str = "",
    ) -> None:
        """Record human approval — AI Act Art.14 compliance."""
        if self.outcome != Outcome.REQUIRE_HUMAN:
            raise ValueError(f"Cannot approve a {self.outcome} decision")
        if self.state != DecisionState.PENDING:
            raise ValueError(f"Decision already in state {self.state}")
        self.approved_by        = principal_id
        self.approval_signature = signature
        self.approval_timestamp = int(time.time())
        self.justification      = justification
        self.state              = DecisionState.APPROVED

    def reject(
        self,
        principal_id: str,
        signature: bytes,
        justification: str = "",
    ) -> None:
        """Record human rejection — AI Act Art.14 compliance."""
        if self.outcome != Outcome.REQUIRE_HUMAN:
            raise ValueError(f"Cannot reject a {self.outcome} decision")
        if self.state != DecisionState.PENDING:
            raise ValueError(f"Decision already in state {self.state}")
        self.approved_by        = principal_id
        self.approval_signature = signature
        self.approval_timestamp = int(time.time())
        self.justification      = justification
        self.state              = DecisionState.REJECTED

    def to_audit_dict(self) -> dict:
        """Serializable dict for audit journal — ANSSI R29 / AI Act Art.12."""
        d = asdict(self)
        # Convert bytes to hex for serialization
        if d.get("trustgate_signature"):
            d["trustgate_signature"] = d["trustgate_signature"].hex()
        if d.get("approval_signature"):
            d["approval_signature"] = d["approval_signature"].hex()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_audit_dict(), sort_keys=True, indent=2)
