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
policy_engine.py — Trust Gate Policy Engine

The deterministic core of Trust Gate.

Design principles:
    - Zero AI, zero heuristics, zero non-reproducible behavior
    - Same input → same output, always, verifiably
    - Every decision has a documented reason
    - Priority order is explicit and auditable

Compliance:
    ANSSI R9  — automated critical actions forbidden → REQUIRE_HUMAN or BLOCK
    ANSSI R26 — role-based access control enforced
    ANSSI R27 — network whitelist + escalation on uncontrolled inputs
    NIST MANAGE 1.3 — risk responses prioritized by severity
    NIST MANAGE 2.2 — human oversight mechanism for high-risk actions
    AI Act Art.14 — human can always override — REQUIRE_HUMAN flow

Priority order (highest to lowest):
    1. VRS above block threshold    → BLOCK
    2. Dangerous pattern match      → BLOCK
    3. Role violation               → BLOCK
    4. TSI CRITICAL                 → BLOCK (configurable)
    5. Network domain violation     → BLOCK
    6. VRS above human threshold    → REQUIRE_HUMAN
    7. TSI UNSTABLE                 → REQUIRE_HUMAN (configurable)
    8. Escalation threshold reached → RESTRICTED
    9. TSI WATCH                    → ALLOW_WITH_LOG
    10. Default                     → ALLOW
"""

import re
import time
from typing import Optional

from trustgate.decision import Decision, EvaluationContext, Outcome
from trustgate.policy_loader import Policy


# ─── Recent alert counter (in-memory, production uses audit_journal) ──────────

_alert_counts: dict = {}   # agent_id -> list of timestamps


def _count_recent_alerts(agent_id: str, window_seconds: int = 3600) -> int:
    """Count recent WATCH+ alerts for an agent within window."""
    now = int(time.time())
    timestamps = _alert_counts.get(agent_id, [])
    recent = [t for t in timestamps if now - t < window_seconds]
    _alert_counts[agent_id] = recent
    return len(recent)


def _record_alert(agent_id: str) -> None:
    """Record an alert timestamp for escalation tracking."""
    if agent_id not in _alert_counts:
        _alert_counts[agent_id] = []
    _alert_counts[agent_id].append(int(time.time()))


# ─── Policy Engine ────────────────────────────────────────────────────────────

def evaluate(ctx: EvaluationContext, policy: Policy) -> Decision:
    """
    Evaluate an action request against the active policy.

    Deterministic. No side effects. Same inputs → same output.

    Args:
        ctx:    Complete evaluation context (agent state + action + scores)
        policy: Active policy (loaded and hash-verified)

    Returns:
        Decision — outcome + reason + full compliance metadata
    """
    outcome, reason = _evaluate_rules(ctx, policy)

    # Record alert for escalation tracking
    if outcome in (Outcome.REQUIRE_HUMAN, Outcome.BLOCK, Outcome.QUARANTINE):
        _record_alert(ctx.agent_id)

    return Decision.from_context(
        ctx             = ctx,
        outcome         = outcome,
        reason          = reason,
        policy_version  = policy.to_version_id(),
        policy_hash     = policy.content_hash,
        timeout_seconds = (
            policy.notification.timeout_seconds
            if outcome == Outcome.REQUIRE_HUMAN
            else None
        ),
    )


def _evaluate_rules(ctx: EvaluationContext, policy: Policy) -> tuple[Outcome, str]:
    """
    Core rule evaluation — returns (outcome, reason).
    Priority order documented in module docstring.
    """

    # ── Priority 1: VRS above block threshold ─────────────────────────────────
    # ANSSI R9, R27 — prohibit automated actions above risk threshold
    if ctx.vrs >= policy.thresholds.vrs_block:
        return (
            Outcome.BLOCK,
            f"VRS {ctx.vrs:.3f} >= block threshold {policy.thresholds.vrs_block} "
            f"[ANSSI R9 / NIST MANAGE 1.3]"
        )

    # ── Priority 2: Dangerous pattern match ───────────────────────────────────
    # ANSSI R25 — filter dangerous inputs
    for pattern in policy.dangerous_patterns:
        try:
            if re.search(pattern, ctx.payload_str or "", re.IGNORECASE):
                return (
                    Outcome.BLOCK,
                    f"Dangerous pattern matched: '{pattern}' "
                    f"[ANSSI R25 / NIST MAP 5.1]"
                )
        except re.error:
            # Invalid regex in policy — log and skip
            continue

    # ── Priority 3: Role violation ────────────────────────────────────────────
    # ANSSI R26, R30 — least privilege enforcement
    role_policy = policy.get_role(ctx.role)
    if not role_policy.can_use(ctx.action):
        return (
            Outcome.BLOCK,
            f"Action '{ctx.action}' not permitted for role '{ctx.role}' "
            f"[ANSSI R26/R30 — least privilege / NIST GOVERN 1.2]"
        )

    # ── Priority 4: TSI CRITICAL ──────────────────────────────────────────────
    # Agent in critical temporal drift — configurable response
    if ctx.tsi_state == "CRITICAL":
        tsi_outcome = Outcome(policy.thresholds.tsi_critical_action)
        return (
            tsi_outcome,
            f"TSI state CRITICAL — agent shows critical temporal drift "
            f"[NIST MEASURE 2.5 / AI Act Art.9]"
        )

    # ── Priority 5: Network domain violation ──────────────────────────────────
    # ANSSI R28 — Zero Trust network policy
    if ctx.target_domain:
        if (
            policy.network.block_external
            and ctx.target_domain not in policy.network.allowed_domains
        ):
            return (
                Outcome.BLOCK,
                f"Domain '{ctx.target_domain}' not in allowed_domains whitelist "
                f"[ANSSI R28 — Zero Trust network / NIST GOVERN 4.1]"
            )

    # ── Priority 6: VRS above human threshold ─────────────────────────────────
    # ANSSI R9 — human must remain in decision loop
    # AI Act Art.14 — human oversight for high-risk actions
    if ctx.vrs >= policy.thresholds.vrs_require_human:
        return (
            Outcome.REQUIRE_HUMAN,
            f"VRS {ctx.vrs:.3f} >= human threshold {policy.thresholds.vrs_require_human} "
            f"[ANSSI R9 / AI Act Art.14 — human oversight required]"
        )

    # ── Priority 7: TSI UNSTABLE ──────────────────────────────────────────────
    if ctx.tsi_state == "UNSTABLE":
        tsi_outcome = Outcome(policy.thresholds.tsi_unstable_action)
        return (
            tsi_outcome,
            f"TSI state UNSTABLE — agent Trust Score shows significant drift "
            f"[NIST MEASURE 2.5]"
        )

    # ── Priority 8: Escalation threshold ─────────────────────────────────────
    # ANSSI R27 — progressive restriction on repeated anomalies
    recent_alerts = _count_recent_alerts(ctx.agent_id)
    if recent_alerts >= policy.escalation.auto_restrict_after:
        return (
            Outcome.RESTRICTED,
            f"Escalation threshold reached: {recent_alerts} alerts in last hour "
            f"(threshold={policy.escalation.auto_restrict_after}) "
            f"[ANSSI R27 — progressive restriction]"
        )

    # ── Priority 9: TSI WATCH ─────────────────────────────────────────────────
    if ctx.tsi_state == "WATCH":
        return (
            Outcome.ALLOW_WITH_LOG,
            f"TSI state WATCH — action allowed with enhanced logging "
            f"[NIST MEASURE 2.5]"
        )

    # ── Priority 10: Default ALLOW ────────────────────────────────────────────
    return (Outcome.ALLOW, "All policy checks passed")


# ─── Simulation mode ─────────────────────────────────────────────────────────

def simulate(ctx: EvaluationContext, policy: Policy) -> dict:
    """
    Simulate policy evaluation without side effects.
    No alert counters updated. No journal entry.

    Used for:
    - Policy testing before activation (ANSSI R22)
    - CLI: piqrypt trustgate simulate --policy policy_v2.yaml
    - Dashboard: Policy Editor preview

    Returns:
        dict with outcome, reason, triggered_rules, and policy_delta hints
    """
    outcome, reason = _evaluate_rules(ctx, policy)

    # Collect all triggered rules (not just first)
    triggered = []

    if ctx.vrs >= policy.thresholds.vrs_block:
        triggered.append(f"vrs_block ({ctx.vrs:.3f} >= {policy.thresholds.vrs_block})")

    for pattern in policy.dangerous_patterns:
        try:
            if re.search(pattern, ctx.payload_str or "", re.IGNORECASE):
                triggered.append(f"dangerous_pattern: {pattern}")
        except re.error:
            pass

    role_policy = policy.get_role(ctx.role)
    if not role_policy.can_use(ctx.action):
        triggered.append(f"role_violation: {ctx.role} cannot use {ctx.action}")

    if ctx.tsi_state == "CRITICAL":
        triggered.append("tsi_critical")
    elif ctx.tsi_state == "UNSTABLE":
        triggered.append("tsi_unstable")
    elif ctx.tsi_state == "WATCH":
        triggered.append("tsi_watch")

    if ctx.vrs >= policy.thresholds.vrs_require_human:
        triggered.append(f"vrs_require_human ({ctx.vrs:.3f} >= {policy.thresholds.vrs_require_human})")

    return {
        "outcome":          outcome,
        "reason":           reason,
        "triggered_rules":  triggered,
        "policy_version":   policy.to_version_id(),
        "policy_hash":      policy.content_hash,
        "simulated":        True,
    }
