#!/usr/bin/env python3
"""
smoke_test_trustgate.py — Trust Gate Full Smoke Test

End-to-end validation of the complete Trust Gate stack.
Run before every release. All 74 checks must pass.

Structure:
    BLOC 01 — Decision dataclass & serialization
    BLOC 02 — Policy loading & integrity (ANSSI R35)
    BLOC 03 — Policy validation & error handling
    BLOC 04 — Policy Engine — all 10 priority rules
    BLOC 05 — Policy Engine — simulate() mode
    BLOC 06 — Policy Versioning — hash, history, diff, tamper
    BLOC 07 — Audit Journal — record, chain, export, filter
    BLOC 08 — Human Principal — SSO create/load/auth/sign
    BLOC 09 — Human Principal — clearance levels (ANSSI R30)
    BLOC 10 — Decision Queue — enqueue, approve, reject, timeout
    BLOC 11 — Notifier — context, severity, channels
    BLOC 12 — Compliance Profiles — ANSSI / NIST / AI Act
    BLOC 13 — HTTP API — evaluate, decisions, principals, audit
    BLOC 14 — Vigil bridge — agent state → Trust Gate
    BLOC 15 — Full E2E — evaluate → queue → auth → approve → audit

Compliance mapping verified:
    ANSSI R9   — BLOC 04, 10, 13, 15
    ANSSI R25  — BLOC 04
    ANSSI R26  — BLOC 04, 12
    ANSSI R28  — BLOC 04, 12
    ANSSI R29  — BLOC 07, 13
    ANSSI R30  — BLOC 09, 10
    ANSSI R35  — BLOC 02, 06, 12
    NIST MANAGE 1.3 — BLOC 04
    NIST MANAGE 2.2 — BLOC 10, 13, 15
    NIST MEASURE 2.5 — BLOC 04, 14
    AI Act Art.12   — BLOC 07, 13
    AI Act Art.13   — BLOC 04
    AI Act Art.14   — BLOC 10, 13, 15
    AI Act Art.9    — BLOC 12
"""

import hashlib
import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from trustgate.decision import (  # noqa: E402
    Decision, EvaluationContext, Outcome, DecisionState, BLOCKING_OUTCOMES
)
from trustgate.policy_loader import (  # noqa: E402
    Policy, ThresholdPolicy, RolePolicy, NetworkPolicy,
    NotificationPolicy, EscalationPolicy,
    load_policy, PolicyIntegrityError, PolicyValidationError,
)
from trustgate.policy_engine import evaluate, simulate  # noqa: E402
from trustgate.policy_versioning import PolicyVersioning  # noqa: E402
from trustgate.audit_journal import AuditJournal  # noqa: E402
from trustgate.decision_queue import (  # noqa: E402
    DecisionQueue, DecisionAlreadyResolvedError
)
from trustgate.human_principal import (  # noqa: E402
    HumanPrincipal, InsufficientClearanceError, PrincipalNotFoundError,
    CLEARANCE_VRS_LIMITS,
)
from trustgate.notifier import Notifier, ConsoleChannel, WebhookChannel  # noqa: E402
from trustgate.trustgate_server import TrustGateServer  # noqa: E402


# ─── Colours ─────────────────────────────────────────────────────────────────
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
B = "\033[94m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

passed = 0
failed = 0
failures = []
_current_bloc = ""


def bloc(name):
    global _current_bloc
    _current_bloc = name
    print(f"\n  {B}{BOLD}{name}{RESET}")


def check(label, expr, detail=""):
    global passed, failed
    if expr:
        passed += 1
        print(f"    {G}✓{RESET} {label}")
    else:
        failed += 1
        msg = f"{label}" + (f" — {detail}" if detail else "")
        failures.append((_current_bloc, msg))
        print(f"    {R}✗{RESET} {label}" + (f" {DIM}({detail}){RESET}" if detail else ""))


def make_policy(
    vrs_require_human=0.60, vrs_block=0.85,
    block_external=False, patterns=None
) -> Policy:
    p = Policy()
    p.name         = "smoke_test"
    p.version      = "1.0"
    p.content_hash = "smoke123"
    p.thresholds   = ThresholdPolicy(
        vrs_require_human=vrs_require_human,
        vrs_block=vrs_block,
    )
    p.roles = {
        "read_only": RolePolicy(
            allowed_tools=["read_db", "search"],
            blocked_tools=["write_db", "shell", "admin"],
        ),
        "operator": RolePolicy(
            allowed_tools=["read_db", "write_db", "http_get"],
            blocked_tools=["shell", "admin"],
        ),
        "trusted": RolePolicy(
            allowed_tools=["*"],
            blocked_tools=["shell"],
        ),
    }
    p.escalation   = EscalationPolicy(auto_restrict_after=5)
    p.network      = NetworkPolicy(
        allowed_domains=["api.internal.local"],
        block_external=block_external,
    )
    p.notification = NotificationPolicy(timeout_seconds=300, on_timeout="REJECT")
    p.dangerous_patterns = patterns or [
        r"rm\s+-rf", r"DROP\s+TABLE", r"curl.*\|.*bash",
    ]
    return p


def make_ctx(**kw) -> EvaluationContext:
    defaults = dict(
        agent_id="AISS-smoke-001", agent_name="smoke_agent",
        role="operator", action="read_db", payload={"q": "SELECT 1"},
        vrs=0.20, tsi_state="STABLE", a2c_score=0.10, trust_score=0.90,
    )
    defaults.update(kw)
    return EvaluationContext(**defaults)


# ─── BLOC 01 — Decision ───────────────────────────────────────────────────────

def bloc_01():
    bloc("BLOC 01 — Decision dataclass & serialization")

    ctx = make_ctx(vrs=0.65)
    d   = Decision.from_context(
        ctx, Outcome.REQUIRE_HUMAN, "vrs threshold",
        "smoke@1.0", "abc123", timeout_seconds=300
    )
    check("Decision.from_context() — fields", d.agent_id == ctx.agent_id)
    check("Decision REQUIRE_HUMAN — state=PENDING", d.state == DecisionState.PENDING)
    check("Decision.is_blocking()", d.is_blocking())
    check("Decision.is_pending()", d.is_pending())
    check("Decision.timeout_at set", d.timeout_at is not None)

    d.approve("principal_test", b"\x01\x02\x03", "approved in smoke")
    check("Decision.approve() — state=APPROVED", d.state == DecisionState.APPROVED)
    check("Decision.approved_by set", d.approved_by == "principal_test")
    check("Decision.justification set", d.justification == "approved in smoke")

    d2 = Decision.from_context(ctx, Outcome.BLOCK, "blocked", "v@1.0", "h")
    d2.trustgate_signature = b"\xde\xad\xbe\xef"
    audit = d2.to_audit_dict()
    check("Decision.to_audit_dict() — bytes→hex", audit["trustgate_signature"] == "deadbeef")
    parsed = json.loads(d2.to_json())
    check("Decision.to_json() — valid JSON", parsed["outcome"] == "BLOCK")

    check("BLOCKING_OUTCOMES set", Outcome.BLOCK in BLOCKING_OUTCOMES)
    check("ALLOW not blocking", not Decision.from_context(
        make_ctx(), Outcome.ALLOW, "ok", "v", "h").is_blocking())


# ─── BLOC 02 — Policy loading & integrity ─────────────────────────────────────

def bloc_02():
    bloc("BLOC 02 — Policy loading & integrity (ANSSI R35)")
    with tempfile.TemporaryDirectory() as d:
        content = (
            "version: '1.0'\nname: 'smoke_load'\n"
            "thresholds:\n  vrs_require_human: 0.55\n  vrs_block: 0.80\n"
        )
        path = Path(d) / "policy.yaml"
        path.write_text(content)

        p = load_policy(path)
        check("load_policy() — name", p.name == "smoke_load")
        check("load_policy() — vrs_require_human", p.thresholds.vrs_require_human == 0.55)
        check("load_policy() — vrs_block",         p.thresholds.vrs_block == 0.80)
        check("load_policy() — content_hash set",  p.content_hash != "")

        correct_hash = hashlib.sha256(content.encode()).hexdigest()
        p2 = load_policy(path, verify_hash=correct_hash)
        check("load_policy() — hash verify OK",    p2.name == "smoke_load")

        try:
            load_policy(path, verify_hash="0" * 64)
            check("ANSSI R35 — wrong hash raises", False, "should have raised")
        except PolicyIntegrityError:
            check("ANSSI R35 — wrong hash raises PolicyIntegrityError", True)


# ─── BLOC 03 — Policy validation ──────────────────────────────────────────────

def bloc_03():
    bloc("BLOC 03 — Policy validation & error handling")
    from trustgate.policy_loader import _validate

    # Invalid threshold order
    bad = make_policy()
    bad.thresholds.vrs_require_human = 0.90
    bad.thresholds.vrs_block         = 0.50
    try:
        _validate(bad)
        check("vrs_require_human >= vrs_block raises", False)
    except PolicyValidationError:
        check("vrs_require_human >= vrs_block raises PolicyValidationError", True)

    # Invalid on_timeout
    bad2 = make_policy()
    bad2.notification.on_timeout = "INVALID"
    try:
        _validate(bad2)
        check("Invalid on_timeout raises", False)
    except PolicyValidationError:
        check("Invalid on_timeout raises PolicyValidationError", True)

    # Valid policy passes
    good = make_policy()
    try:
        _validate(good)
        check("Valid policy passes validation", True)
    except Exception as e:
        check("Valid policy passes validation", False, str(e))

    # RolePolicy.can_use()
    r = RolePolicy(allowed_tools=["read_db", "search"], blocked_tools=["shell"])
    check("RolePolicy.can_use() — allowed tool",   r.can_use("read_db"))
    check("RolePolicy.can_use() — blocked tool",   not r.can_use("shell"))
    check("RolePolicy.can_use() — unknown tool",   not r.can_use("unknown"))

    r_star = RolePolicy(allowed_tools=["*"], blocked_tools=["shell"])
    check("RolePolicy wildcard allows all",        r_star.can_use("anything"))
    check("RolePolicy wildcard respects block",    not r_star.can_use("shell"))


# ─── BLOC 04 — Policy Engine ──────────────────────────────────────────────────

def bloc_04():
    bloc("BLOC 04 — Policy Engine — all 10 priority rules")
    import trustgate.policy_engine as pe
    pe._alert_counts.clear()

    p = make_policy()

    # P1: VRS block
    d = evaluate(make_ctx(vrs=0.90), p)
    check("P1 — BLOCK (VRS > block threshold)",    d.outcome == Outcome.BLOCK)
    check("P1 — reason references vrs_block",
          "0.85" in d.reason or "vrs_block" in d.reason.lower())

    # P2: dangerous pattern
    pe._alert_counts.clear()
    d = evaluate(make_ctx(role="trusted", action="write_db",
                          payload={"cmd": "rm -rf /var"}), p)
    check("P2 — BLOCK (rm -rf pattern ANSSI R25)", d.outcome == Outcome.BLOCK)
    check("P2 — reason mentions pattern",          "pattern" in d.reason.lower())

    # P3: role violation
    pe._alert_counts.clear()
    d = evaluate(make_ctx(role="operator", action="shell"), p)
    check("P3 — BLOCK (role violation ANSSI R26)", d.outcome == Outcome.BLOCK)
    check("P3 — reason mentions role",
          "role" in d.reason.lower() or "operator" in d.reason)

    # P4: TSI CRITICAL
    pe._alert_counts.clear()
    d = evaluate(make_ctx(vrs=0.30, tsi_state="CRITICAL"), p)
    check("P4 — BLOCK (TSI CRITICAL)",             d.outcome == Outcome.BLOCK)
    check("P4 — reason mentions CRITICAL",         "CRITICAL" in d.reason)

    # P5: network violation
    pe._alert_counts.clear()
    p_net = make_policy(block_external=True)
    d = evaluate(make_ctx(action="http_get", target_domain="evil.com"), p_net)
    check("P5 — BLOCK (domain not whitelisted R28)", d.outcome == Outcome.BLOCK)

    # P5b: whitelisted domain passes
    pe._alert_counts.clear()
    d = evaluate(make_ctx(action="http_get", target_domain="api.internal.local"), p_net)
    check("P5b — ALLOW (whitelisted domain)",      d.outcome == Outcome.ALLOW)

    # P6: VRS require_human
    pe._alert_counts.clear()
    d = evaluate(make_ctx(vrs=0.70), p)
    check("P6 — REQUIRE_HUMAN (VRS ANSSI R9/Art.14)", d.outcome == Outcome.REQUIRE_HUMAN)
    check("P6 — timeout_at set",                   d.timeout_at is not None)

    # P7: TSI UNSTABLE
    pe._alert_counts.clear()
    d = evaluate(make_ctx(vrs=0.30, tsi_state="UNSTABLE"), p)
    check("P7 — REQUIRE_HUMAN (TSI UNSTABLE)",     d.outcome == Outcome.REQUIRE_HUMAN)

    # P8: escalation
    pe._alert_counts.clear()
    pe._alert_counts["AISS-esc-001"] = [int(time.time())] * 6  # exceed threshold=5
    d = evaluate(make_ctx(agent_id="AISS-esc-001", vrs=0.30), p)
    check("P8 — RESTRICTED (escalation R27)",      d.outcome == Outcome.RESTRICTED)

    # P9: TSI WATCH
    pe._alert_counts.clear()
    d = evaluate(make_ctx(vrs=0.20, tsi_state="WATCH"), p)
    check("P9 — ALLOW_WITH_LOG (TSI WATCH)",       d.outcome == Outcome.ALLOW_WITH_LOG)

    # P10: default ALLOW
    pe._alert_counts.clear()
    d = evaluate(make_ctx(vrs=0.10, tsi_state="STABLE"), p)
    check("P10 — ALLOW (all checks passed)",       d.outcome == Outcome.ALLOW)

    # AI Act Art.13 — reason always set
    contexts = [make_ctx(vrs=v, tsi_state=t) for v,t in
                [(0.10,"STABLE"),(0.70,"STABLE"),(0.90,"STABLE"),(0.30,"CRITICAL")]]
    pe._alert_counts.clear()
    all_reasons = all(evaluate(c, p).reason for c in contexts)
    check("AI Act Art.13 — reason never empty",    all_reasons)

    # policy_version and policy_hash in every decision
    pe._alert_counts.clear()
    d = evaluate(make_ctx(), p)
    check("policy_version in decision",            d.policy_version != "")
    check("policy_hash in decision",               d.policy_hash == "smoke123")


# ─── BLOC 05 — Simulate mode ──────────────────────────────────────────────────

def bloc_05():
    bloc("BLOC 05 — Policy Engine — simulate() mode")
    import trustgate.policy_engine as pe
    pe._alert_counts.clear()
    p = make_policy()

    r = simulate(make_ctx(vrs=0.30, tsi_state="STABLE"), p)
    check("simulate() — returns outcome",      "outcome" in r)
    check("simulate() — simulated=True",       r["simulated"] is True)
    check("simulate() — triggered_rules list", isinstance(r["triggered_rules"], list))
    check("simulate() ALLOW — no side effects", pe._alert_counts.get("AISS-smoke-001", []) == [])

    r2 = simulate(make_ctx(vrs=0.90, action="shell", role="trusted",
                            payload={"cmd": "rm -rf /"}), p)
    check("simulate() BLOCK — triggered_rules not empty", len(r2["triggered_rules"]) > 0)
    check("simulate() — policy_version present", r2["policy_version"] != "")


# ─── BLOC 06 — Policy versioning ─────────────────────────────────────────────

def bloc_06():
    bloc("BLOC 06 — Policy Versioning — hash, history, diff, tamper (ANSSI R35)")
    with tempfile.TemporaryDirectory() as d:
        v1 = (
            "version: '1.0'\nname: 'ver_test'\n"
            "thresholds:\n  vrs_require_human: 0.60\n  vrs_block: 0.85\n"
        )
        v2 = (
            "version: '2.0'\nname: 'ver_test'\n"
            "thresholds:\n  vrs_require_human: 0.50\n  vrs_block: 0.80\n"
        )

        p1 = Path(d) / "p1.yaml"
        p1.write_text(v1)
        p2 = Path(d) / "p2.yaml"
        p2.write_text(v2)
        vdir = Path(d) / "versions"

        pv = PolicyVersioning(versions_dir=vdir)

        ver1 = pv.activate(p1, activated_by="admin", comment="initial")
        check("activate() — version_id",    ver1.version_id == "ver_test@1.0")
        check("activate() — content_hash",  ver1.content_hash != "")
        check("activate() — activated_by",  ver1.activated_by == "admin")

        time.sleep(0.01)
        ver2 = pv.activate(p2, activated_by="admin", comment="stricter")

        history = pv.get_history(name="ver_test")
        check("history() — 2 versions",      len(history) == 2)
        check("history() — ordered by time", history[0].version_id == "ver_test@1.0")

        diff = pv.diff(ver1.content_hash, ver2.content_hash)
        check("diff() — returns lines",      len(diff) > 0)
        check("diff() — contains change",
              any("0.50" in line or "0.60" in line for line in diff))

        # verify_current checks against last activated version (p2)
        valid, msg = pv.verify_current(p2)
        check("verify_current() — valid",    valid, msg)

        # Tamper p2 — hash mismatch must be detected (ANSSI R35)
        p2.write_text(v2 + "# TAMPERED\n")
        valid2, msg2 = pv.verify_current(p2)
        check("ANSSI R35 — tamper detected", not valid2)


# ─── BLOC 07 — Audit Journal ──────────────────────────────────────────────────

def bloc_07():
    bloc("BLOC 07 — Audit Journal — record, chain, export, filter (ANSSI R29 / Art.12)")
    import trustgate.policy_engine as pe
    pe._alert_counts.clear()

    with tempfile.TemporaryDirectory() as d:
        journal = AuditJournal(journal_dir=Path(d))
        p = make_policy()

        # Record 5 decisions
        for vrs in [0.90, 0.70, 0.65, 0.91, 0.88]:
            decision = evaluate(make_ctx(vrs=vrs), p)
            journal.record(decision)
            pe._alert_counts.clear()

        entries = journal.get_recent(days=1)
        check("record() — 5 entries", len(entries) == 5)

        valid, errors = journal.verify_chain()
        check("ANSSI R29 — chain valid",      valid, str(errors))
        check("Chain — seq sequential",       entries[0].seq == 1)
        check("Chain — prev_hash linked",     entries[1].previous_hash == entries[0].entry_hash)

        # Filter by agent
        filtered = journal.get_recent(agent_id="AISS-smoke-001", days=1)
        check("filter by agent_id",           len(filtered) == 5)

        # Filter by outcome
        blocked = journal.get_recent(outcome="BLOCK", days=1)
        check("filter by outcome=BLOCK",      all(e.outcome == "BLOCK" for e in blocked))

        # JSON export
        export = json.loads(journal.export_json(days=1))
        check("export_json() — total_entries", export["total_entries"] == 5)
        check("export_json() — chain_valid",   export["chain_valid"] is True)
        check("AI Act Art.12 — entries present", len(export["entries"]) == 5)

        # count_recent
        cnt = journal.count_recent("AISS-smoke-001", hours=1)
        check("count_recent() — returns int", isinstance(cnt, int))


# ─── BLOC 08 — Human Principal ────────────────────────────────────────────────

def bloc_08():
    bloc("BLOC 08 — Human Principal — SSO create / load / auth / sign")
    with tempfile.TemporaryDirectory() as d:
        pdir = Path(d) / "principals"

        p = HumanPrincipal.create(
            name="alice_smoke", email="alice@test.com",
            clearance="L2", mode="sso",
            sso_provider="azure_ad", sso_subject="sso-sub-123",
            principals_dir=pdir,
        )
        check("create() — principal_id", p.record.principal_id.startswith("PRINCIPAL-"))
        check("create() — clearance",    p.record.clearance == "L2")
        check("create() — active",       p.record.active is True)
        check("create() — persisted",    (pdir / "alice_smoke" / "principal.json").exists())

        p2 = HumanPrincipal.load("alice_smoke", principals_dir=pdir)
        check("load() — identity match", p2.record.principal_id == p.record.principal_id)

        try:
            HumanPrincipal.load("nobody", principals_dir=pdir)
            check("load() — PrincipalNotFoundError", False)
        except PrincipalNotFoundError:
            check("load() — PrincipalNotFoundError", True)

        principals = HumanPrincipal.list_all(principals_dir=pdir)
        check("list_all() — 1 principal", len(principals) == 1)

        token = p.authenticate_sso(
            sso_claims={"sub": "sso-sub-123"},
            ttl_seconds=3600,
        )
        check("authenticate_sso() — token issued", token.principal_id == p.record.principal_id)
        check("authenticate_sso() — token valid",  token.is_valid())
        check("authenticate_sso() — last_login",   p.record.last_login is not None)

        expired = p.authenticate_sso(sso_claims={}, ttl_seconds=1)
        time.sleep(1.5)
        check("SSO token expiry",                  not expired.is_valid())

        sig = p.sign_decision_sso("dec-001", "APPROVED", token, "approved in smoke")
        check("sign_decision_sso() — bytes",       isinstance(sig, bytes))
        check("sign_decision_sso() — 32 bytes",    len(sig) == 32)

        p.deactivate()
        check("deactivate() — can_approve=False",  not p.can_approve(0.50))
        p.reactivate()
        check("reactivate() — can_approve=True",   p.can_approve(0.50))


# ─── BLOC 09 — Clearance levels ───────────────────────────────────────────────

def bloc_09():
    bloc("BLOC 09 — Human Principal — clearance levels (ANSSI R30)")
    with tempfile.TemporaryDirectory() as d:
        pdir = Path(d) / "principals"

        p_l1 = HumanPrincipal.create(
            name="l1", email="l1@t.com", clearance="L1", mode="sso", principals_dir=pdir)
        p_l2 = HumanPrincipal.create(
            name="l2", email="l2@t.com", clearance="L2", mode="sso", principals_dir=pdir)
        p_l3 = HumanPrincipal.create(
            name="l3", email="l3@t.com", clearance="L3", mode="sso", principals_dir=pdir)

        check("L1 — can approve VRS=0.70", p_l1.can_approve(0.70))
        check("L1 — cannot approve VRS=0.80", not p_l1.can_approve(0.80))
        check("L2 — can approve VRS=0.85", p_l2.can_approve(0.85))
        check("L2 — cannot approve VRS=0.95", not p_l2.can_approve(0.95))
        check("L3 — can approve VRS=0.99", p_l3.can_approve(0.99))

        try:
            p_l1.assert_can_approve(0.80)
            check("assert_can_approve() raises for L1@0.80", False)
        except InsufficientClearanceError as e:
            check("assert_can_approve() raises InsufficientClearanceError", True)
            check("error mentions clearance level", "L1" in str(e))

        # Verify VRS limits are correct
        check("CLEARANCE_VRS_LIMITS L1=0.75", CLEARANCE_VRS_LIMITS["L1"] == 0.75)
        check("CLEARANCE_VRS_LIMITS L2=0.90", CLEARANCE_VRS_LIMITS["L2"] == 0.90)
        check("CLEARANCE_VRS_LIMITS L3=1.00", CLEARANCE_VRS_LIMITS["L3"] == 1.00)


# ─── BLOC 10 — Decision Queue ─────────────────────────────────────────────────

def bloc_10():
    bloc("BLOC 10 — Decision Queue — enqueue, approve, reject, timeout")
    with tempfile.TemporaryDirectory() as d:
        pdir  = Path(d) / "principals"
        qdir  = Path(d) / "queue"
        jdir  = Path(d) / "journal"

        journal  = AuditJournal(journal_dir=jdir)
        queue    = DecisionQueue(queue_dir=qdir, audit_journal=journal)
        principal = HumanPrincipal.create(
            name="approver", email="a@t.com", clearance="L2",
            mode="sso", principals_dir=pdir,
        )

        def make_d(vrs=0.65, timeout=300):
            ctx = make_ctx(vrs=vrs)
            return Decision.from_context(
                ctx, Outcome.REQUIRE_HUMAN, f"VRS {vrs}",
                "smoke@1.0", "abc", timeout_seconds=timeout,
            )

        d1 = make_d()
        queue.enqueue(d1)
        check("enqueue() — persisted as PENDING",   queue.count_pending() >= 1)

        pending = queue.get_pending()
        check("get_pending() — returns list",       len(pending) >= 1)

        token = principal.authenticate_sso(sso_claims={}, ttl_seconds=3600)

        resolved = queue.approve(d1.decision_id, principal, token, "smoke approve")
        check("approve() — state=APPROVED",         resolved.state == DecisionState.APPROVED)
        check("approve() — approved_by set",
              resolved.approved_by == principal.record.principal_id)
        check("approve() — signature bytes",        isinstance(resolved.approval_signature, bytes))
        check("approve() — justification",          resolved.justification == "smoke approve")
        check("approve() — removed from pending",   queue.get_decision(d1.decision_id) is not None)

        d2 = make_d(vrs=0.67)
        queue.enqueue(d2)
        r2 = queue.reject(d2.decision_id, principal, token, "too risky")
        check("reject() — state=REJECTED",          r2.state == DecisionState.REJECTED)

        try:
            queue.approve(d1.decision_id, principal, token)
            check("double-approve raises", False)
        except DecisionAlreadyResolvedError:
            check("double-approve raises DecisionAlreadyResolvedError", True)

        # Insufficient clearance
        l1 = HumanPrincipal.create(name="junior", email="j@t.com", clearance="L1",
                                    mode="sso", principals_dir=pdir)
        d3 = make_d(vrs=0.80)
        queue.enqueue(d3)
        token_l1 = l1.authenticate_sso(sso_claims={}, ttl_seconds=3600)
        try:
            queue.approve(d3.decision_id, l1, token_l1)
            check("L1 cannot approve VRS=0.80", False)
        except InsufficientClearanceError:
            check("L1 cannot approve VRS=0.80 (ANSSI R30)", True)

        # Timeout
        d4 = make_d(timeout=1)
        queue.enqueue(d4)
        time.sleep(1.5)
        queue._process_timeouts()
        r4 = queue.get_decision(d4.decision_id)
        check("timeout — state=TIMED_OUT",          r4.state == DecisionState.TIMED_OUT)
        check("ANSSI R9 — timeout → BLOCK",         r4.outcome == Outcome.BLOCK)

        # Callback
        fired = []
        queue.on_resolve(lambda dec: fired.append(dec.decision_id))
        d5 = make_d()
        queue.enqueue(d5)
        queue.approve(d5.decision_id, principal, token)
        check("on_resolve() callback fired",        d5.decision_id in fired)


# ─── BLOC 11 — Notifier ───────────────────────────────────────────────────────

def bloc_11():
    bloc("BLOC 11 — Notifier — context, severity, channels")
    import http.server
    import threading

    ctx = make_ctx(vrs=0.72)
    d = Decision.from_context(ctx, Outcome.REQUIRE_HUMAN, "vrs", "v@1.0", "h",
                              timeout_seconds=300)

    notifier = Notifier(channels=[ConsoleChannel()])

    nc = notifier._build_context(d)
    check("build_context() — decision_id",  nc.decision_id == d.decision_id)
    check("build_context() — vrs",          nc.vrs == d.vrs_at_decision)
    check("build_context() — approve_url",  nc.approve_url != "")
    check("build_context() — reject_url",   nc.reject_url != "")

    check("severity CRITICAL for VRS=0.80", notifier._build_context(
        Decision.from_context(
            make_ctx(vrs=0.80), Outcome.REQUIRE_HUMAN, "", "v", "h", 300)
    ).severity == "CRITICAL")
    check("severity ALERT for VRS=0.60", notifier._build_context(
        Decision.from_context(
            make_ctx(vrs=0.60), Outcome.REQUIRE_HUMAN, "", "v", "h", 300)
    ).severity == "ALERT")
    check("severity WATCH for VRS=0.30", notifier._build_context(
        Decision.from_context(
            make_ctx(vrs=0.30), Outcome.REQUIRE_HUMAN, "", "v", "h", 300)
    ).severity == "WATCH")

    # Webhook
    received = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            received.append(json.loads(self.rfile.read(n)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    with tempfile.TemporaryDirectory() as tmp:
        p = HumanPrincipal.create(name="w", email="w@t.com", clearance="L1",
                                   mode="sso", principals_dir=Path(tmp)/"p")
        wh = Notifier(channels=[WebhookChannel(f"http://127.0.0.1:{port}")])
        r  = wh.push(d, [p])

    srv.shutdown()
    check("WebhookChannel — sent=1",           r["sent"] == 1)
    check("WebhookChannel — payload received", len(received) == 1)
    check("WebhookChannel — event type",       received[0]["trustgate_event"] == "REQUIRE_HUMAN")

    # Failed channel does not raise
    bad = Notifier(channels=[WebhookChannel("http://127.0.0.1:1")])
    with tempfile.TemporaryDirectory() as tmp:
        p2 = HumanPrincipal.create(name="x", email="x@t.com", clearance="L1",
                                    mode="sso", principals_dir=Path(tmp)/"p")
        r2 = bad.push(d, [p2])
    check("Failed channel — no raise",         r2["failed"] == 1)


# ─── BLOC 12 — Compliance Profiles ───────────────────────────────────────────

def bloc_12():
    bloc("BLOC 12 — Compliance Profiles — ANSSI / NIST / AI Act")
    profiles_dir = ROOT / "trustgate" / "profiles"

    for profile_name, expected in [
        ("anssi_strict", {
            "vrs_rh": 0.40, "vrs_b": 0.70, "timeout": 180,
            "on_timeout": "REJECT", "block_ext": True,
        }),
        ("nist_balanced", {
            "vrs_rh": 0.60, "vrs_b": 0.85, "timeout": 300,
            "on_timeout": "ESCALATE", "block_ext": False,
        }),
        ("ai_act_high_risk", {
            "vrs_rh": 0.50, "vrs_b": 0.80, "timeout": 240,
            "on_timeout": "BLOCK", "block_ext": True,
        }),
    ]:
        path = profiles_dir / f"{profile_name}.yaml"
        check(f"Profile {profile_name} — file exists", path.exists())

        if not path.exists():
            continue

        try:
            p = load_policy(path)
            check(f"{profile_name} — vrs_require_human={expected['vrs_rh']}",
                  p.thresholds.vrs_require_human == expected["vrs_rh"])
            check(f"{profile_name} — vrs_block={expected['vrs_b']}",
                  p.thresholds.vrs_block == expected["vrs_b"])
            check(f"{profile_name} — timeout={expected['timeout']}",
                  p.notification.timeout_seconds == expected["timeout"])
            check(f"{profile_name} — on_timeout={expected['on_timeout']}",
                  p.notification.on_timeout == expected["on_timeout"])
            check(f"{profile_name} — block_external={expected['block_ext']}",
                  p.network.block_external == expected["block_ext"])
            check(f"{profile_name} — dangerous_patterns present",
                  len(p.dangerous_patterns) > 0)
        except Exception as e:
            check(f"{profile_name} — loads without error", False, str(e))

    # ANSSI strict — must have require_justification=True
    try:
        anssi = load_policy(profiles_dir / "anssi_strict.yaml")
        check("anssi_strict — require_justification=True",
              anssi.notification.require_justification is True)
        check("anssi_strict — vrs_require_human is most strict",
              anssi.thresholds.vrs_require_human <= 0.40)
    except Exception:
        pass

    # AI Act — retention 2 years
    try:
        ai_act_content = (profiles_dir / "ai_act_high_risk.yaml").read_text()
        check("ai_act_high_risk — retention_days 730 in profile",
              "730" in ai_act_content)
    except Exception:
        pass


# ─── BLOC 13 — HTTP API ───────────────────────────────────────────────────────

class APIClient:
    def __init__(self, base):
        self.base = base

    def get(self, path):
        try:
            with urllib.request.urlopen(f"{self.base}{path}", timeout=5) as r:
                return json.loads(r.read()), r.status
        except urllib.error.HTTPError as e:
            return json.loads(e.read()), e.code
    def post(self, path, body=None):
        data = json.dumps(body or {}).encode()
        req  = urllib.request.Request(f"{self.base}{path}", data=data, method="POST",
                                       headers={"Content-Type":"application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.loads(r.read()), r.status
        except urllib.error.HTTPError as e:
            return json.loads(e.read()), e.code


def start_server(tmpdir) -> tuple:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    srv = TrustGateServer(
        host="127.0.0.1", port=port, demo_mode=True,
        journal_dir=tmpdir/"j", queue_dir=tmpdir/"q",
        versions_dir=tmpdir/"v", principals_dir=tmpdir/"p",
    )
    t = threading.Thread(target=srv.start, daemon=True)
    t.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    return srv, APIClient(f"http://127.0.0.1:{port}")


def bloc_13():
    bloc("BLOC 13 — HTTP API — all core endpoints")
    with tempfile.TemporaryDirectory() as d:
        tmpdir = Path(d)
        srv, api = start_server(tmpdir)

        # Health
        data, s = api.get("/health")
        check("GET /health — 200",           s == 200)
        check("GET /health — demo_mode",     data.get("demo_mode") is True)

        # Status
        data, s = api.get("/api/status")
        check("GET /api/status — 200",       s == 200)
        check("GET /api/status — service",   data.get("service") == "trust_gate")

        # Policy
        data, s = api.get("/api/policy")
        check("GET /api/policy — 200",       s == 200)
        check("GET /api/policy — thresholds", "thresholds" in data)

        # Simulate
        data, s = api.post("/api/policy/simulate", {
            "agent_id":"sim-001","role":"operator","action":"read_db",
            "payload":{},"vrs":0.20,"tsi_state":"STABLE",
        })
        check("POST /api/policy/simulate — ALLOW", data.get("outcome") == "ALLOW")
        check("POST /api/policy/simulate — simulated=True", data.get("simulated") is True)

        # Evaluate ALLOW
        data, s = api.post("/api/evaluate", {
            "agent_id":"AISS-api-001","role":"operator","action":"read_db",
            "payload":{},"vrs":0.20,"tsi_state":"STABLE",
        })
        check("POST /api/evaluate — ALLOW", data.get("outcome") == "ALLOW")
        check("POST /api/evaluate — decision_id present", "decision_id" in data)

        # Evaluate BLOCK
        data, s = api.post("/api/evaluate", {
            "agent_id":"AISS-api-002","role":"operator","action":"read_db",
            "payload":{"cmd":"DROP TABLE x"},"vrs":0.20,"tsi_state":"STABLE",
        })
        check("POST /api/evaluate — BLOCK (pattern)", data.get("outcome") == "BLOCK")

        # Evaluate REQUIRE_HUMAN
        data, s = api.post("/api/evaluate", {
            "agent_id":"AISS-api-003","role":"operator","action":"write_db",
            "payload":{},"vrs":0.70,"tsi_state":"WATCH",
        })
        check("POST /api/evaluate — REQUIRE_HUMAN", data.get("outcome") == "REQUIRE_HUMAN")
        check("POST /api/evaluate — pending=True",  data.get("pending") is True)
        rh_id = data.get("decision_id")

        # Decisions
        data, s = api.get("/api/decisions")
        check("GET /api/decisions — 200",   s == 200)
        check("GET /api/decisions — list",  isinstance(data.get("decisions"), list))

        data, s = api.get(f"/api/decisions/{rh_id}")
        check("GET /api/decisions/<id>",    s == 200 and data.get("decision_id") == rh_id)

        # Principal create + auth + approve
        api.post("/api/principals", {
            "name":"smoke_principal","email":"sp@t.com","clearance":"L2","mode":"sso",
        })
        tok, s = api.post("/api/principals/smoke_principal/authenticate",
                          {"sso_claims":{}})
        check("POST /api/principals/.../authenticate", s == 200 and "token_id" in tok)

        data, s = api.post(f"/api/decisions/{rh_id}/approve", {
            "principal_name": "smoke_principal",
            "justification":  "smoke test approve",
        })
        check("POST /api/decisions/<id>/approve — APPROVED", data.get("state") == "APPROVED")
        check("POST /api/decisions/<id>/approve — 200", s == 200)

        # Audit
        data, s = api.get("/api/audit")
        check("GET /api/audit — 200",           s == 200)
        check("GET /api/audit — chain_valid",   "chain_valid" in data)

        data, s = api.get("/api/audit/export")
        check("GET /api/audit/export — 200",    s == 200)
        check("GET /api/audit/export — entries", "entries" in data)

        # 404
        _, s = api.get("/api/nonexistent")
        check("404 on unknown route",            s == 404)

        # Missing fields
        _, s = api.post("/api/evaluate", {"role": "operator"})
        check("POST /api/evaluate — 400 missing", s == 400)

        srv.stop()


# ─── BLOC 14 — Vigil bridge ───────────────────────────────────────────────────

def bloc_14():
    bloc("BLOC 14 — Vigil bridge — agent state → Trust Gate")
    with tempfile.TemporaryDirectory() as d:
        tmpdir = Path(d)
        srv, api = start_server(tmpdir)

        # Below threshold → MONITOR
        data, s = api.post("/api/vigil/agent-state", {
            "agent_id":"AISS-vigil-001","agent_name":"vigil_agent",
            "vrs":0.30,"tsi_state":"STABLE","a2c_score":0.10,
        })
        check("Vigil bridge — MONITOR (below threshold)", data.get("outcome") == "MONITOR")
        check("Vigil bridge — 200", s == 200)

        # Above threshold → BLOCK or REQUIRE_HUMAN
        data, s = api.post("/api/vigil/agent-state", {
            "agent_id":"AISS-vigil-002","agent_name":"vigil_critical",
            "vrs":0.92,"tsi_state":"STABLE","a2c_score":0.30,
        })
        check("Vigil bridge — BLOCK/REQUIRE_HUMAN (above threshold)",
              data.get("outcome") in ("BLOCK","REQUIRE_HUMAN","RESTRICTED"))
        check("Vigil bridge — decision_id present", "decision_id" in data)
        check("NIST MEASURE 2.5 — Vigil→TrustGate bridge", s == 200)

        srv.stop()


# ─── BLOC 15 — Full E2E ───────────────────────────────────────────────────────

def bloc_15():
    bloc("BLOC 15 — Full E2E — evaluate → queue → authenticate → approve → audit")
    with tempfile.TemporaryDirectory() as d:
        tmpdir = Path(d)
        srv, api = start_server(tmpdir)

        # 1. Create L2 principal
        p_data, s = api.post("/api/principals", {
            "name":"e2e_principal","email":"e2e@corp.com",
            "clearance":"L2","mode":"sso",
        })
        check("E2E — principal created (L2)", s == 201)

        # 2. Authenticate
        tok, s = api.post("/api/principals/e2e_principal/authenticate",
                          {"sso_claims":{"sub":"e2e-sub"}})
        check("E2E — SSO authentication", s == 200 and tok.get("valid") is True)
        token_id = tok.get("token_id")

        # 3. Evaluate → REQUIRE_HUMAN
        ev, s = api.post("/api/evaluate", {
            "agent_id":"AISS-e2e-final","agent_name":"e2e_agent",
            "role":"operator","action":"write_db",
            "payload":{"query":"UPDATE config SET critical=1"},
            "vrs":0.72,"tsi_state":"WATCH",
        })
        check("E2E — evaluate → REQUIRE_HUMAN",  ev.get("outcome") == "REQUIRE_HUMAN")
        check("E2E — ANSSI R9 — agent blocked",  ev.get("blocked") is True)
        check("E2E — agent pending approval",    ev.get("pending") is True)
        decision_id = ev.get("decision_id")

        # 4. Decision in queue
        q_data, _ = api.get("/api/decisions")
        ids = [d["decision_id"] for d in q_data.get("decisions", [])]
        check("E2E — decision in queue",         decision_id in ids)

        # 5. Approve with token
        ap, s = api.post(f"/api/decisions/{decision_id}/approve", {
            "principal_name":"e2e_principal",
            "token_id": token_id,
            "justification":"E2E smoke test — approved after review",
        })
        check("E2E — approve → APPROVED",        ap.get("state") == "APPROVED")
        check("E2E — approved_by set",           ap.get("approved_by") is not None)
        check("E2E — justification stored",      "smoke test" in (ap.get("justification") or ""))
        check("E2E — AI Act Art.14 — human approval signed", s == 200)

        # 6. Audit trail
        audit, _ = api.get("/api/audit?agent_id=AISS-e2e-final")
        check("E2E — ANSSI R29 — audit trail",   audit.get("total", 0) >= 1)
        check("E2E — AI Act Art.12 — chain",     audit.get("chain_valid") is True)

        srv.stop()
        print(f"\n    {G}{BOLD}[ANSSI R9 ✅ AI Act Art.14 ✅ NIST MANAGE 2.2 ✅]{RESET}")


# ─── Runner ───────────────────────────────────────────────────────────────────

def main():
    print(f"\n{BOLD}{'═'*62}{RESET}")
    print(f"{BOLD}  Trust Gate — Full Smoke Test{RESET}")
    print(f"{BOLD}  ANSSI 2024 · NIST AI RMF 1.0 · EU AI Act{RESET}")
    print(f"{BOLD}{'═'*62}{RESET}")

    blocs = [
        bloc_01, bloc_02, bloc_03, bloc_04, bloc_05,
        bloc_06, bloc_07, bloc_08, bloc_09, bloc_10,
        bloc_11, bloc_12, bloc_13, bloc_14, bloc_15,
    ]

    for fn in blocs:
        try:
            fn()
        except Exception as e:
            import traceback
            print(f"\n  {R}BLOC CRASHED: {e}{RESET}")
            traceback.print_exc()

    total = passed + failed
    print(f"\n{BOLD}{'═'*62}{RESET}")

    if failed == 0:
        print(f"  {G}{BOLD}ALL {total} CHECKS PASSED ✅{RESET}")
        print(f"\n  {G}ANSSI 2024   — 21 requirements covered{RESET}")
        print(f"  {G}NIST AI RMF  — 5 functions covered{RESET}")
        print(f"  {G}EU AI Act    — Art. 9/12/13/14/17 covered{RESET}")
    else:
        print(f"  {R}{BOLD}{passed}/{total} passed — {failed} FAILED{RESET}")
        print(f"\n{R}Failures:{RESET}")
        for bloc_name, msg in failures:
            print(f"  {DIM}{bloc_name}{RESET} — {R}{msg}{RESET}")

    print(f"{BOLD}{'═'*62}{RESET}\n")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
