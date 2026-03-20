"""
test_trustgate_sprint1.py — Trust Gate Sprint 1 Unit Tests

Coverage:
- decision.py        : Decision creation, approval, rejection
- policy_loader.py   : Load, validate, hash verification
- policy_engine.py   : All evaluation rules, simulate()
- audit_journal.py   : Record, retrieve, chain verify, export
- policy_versioning.py: Activate, history, diff, verify
"""

import json
import sys
import tempfile
import time
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from trustgate.decision import Decision, EvaluationContext, Outcome, DecisionState
from trustgate.policy_loader import (
    Policy, ThresholdPolicy, RolePolicy, NetworkPolicy,
    NotificationPolicy, EscalationPolicy,
    load_policy, PolicyIntegrityError, PolicyValidationError
)
from trustgate.policy_engine import evaluate, simulate
from trustgate.audit_journal import AuditJournal
from trustgate.policy_versioning import PolicyVersioning


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_policy(**overrides) -> Policy:
    """Create a standard test policy."""
    p = Policy()
    p.version         = "1.0"
    p.name            = "test_policy"
    p.content_hash    = "abc123"
    p.thresholds      = ThresholdPolicy(
        vrs_require_human = 0.60,
        vrs_block         = 0.85,
    )
    p.roles = {
        "read_only": RolePolicy(
            allowed_tools=["read_db", "search"],
            blocked_tools=["write_db", "shell"],
        ),
        "operator": RolePolicy(
            allowed_tools=["read_db", "write_db", "http_get"],
            blocked_tools=["shell"],
        ),
        "trusted": RolePolicy(
            allowed_tools=["*"],
            blocked_tools=["shell"],
        ),
    }
    p.escalation      = EscalationPolicy(auto_restrict_after=5)
    p.network         = NetworkPolicy(
        allowed_domains=["api.internal.local"],
        block_external=True,
    )
    p.notification    = NotificationPolicy(timeout_seconds=300, on_timeout="REJECT")
    p.dangerous_patterns = [
        r"rm\s+-rf",
        r"DROP\s+TABLE",
        r"curl.*\|.*bash",
    ]
    for k, v in overrides.items():
        setattr(p, k, v)
    return p


def make_ctx(**overrides) -> EvaluationContext:
    """Create a standard safe evaluation context."""
    defaults = dict(
        agent_id     = "AISS-test-001",
        agent_name   = "test_agent",
        role         = "operator",
        action       = "read_db",
        payload      = {"query": "SELECT 1"},
        vrs          = 0.20,
        tsi_state    = "STABLE",
        a2c_score    = 0.10,
        trust_score  = 0.90,
        target_domain= None,
    )
    defaults.update(overrides)
    return EvaluationContext(**defaults)


# ─── BLOC 1 — Decision ────────────────────────────────────────────────────────

def test_decision_creation():
    ctx = make_ctx()
    _ = make_policy()
    d = Decision.from_context(ctx, Outcome.ALLOW, "passed", "test@1.0", "abc123")
    assert d.outcome == Outcome.ALLOW
    assert d.agent_id == ctx.agent_id
    assert d.policy_version == "test@1.0"
    assert d.policy_hash == "abc123"
    assert not d.is_blocking()
    assert not d.is_pending()
    print("  ✓ Decision creation — fields correct")


def test_decision_require_human_flow():
    ctx = make_ctx(vrs=0.65)
    _ = make_policy()
    d = Decision.from_context(
        ctx, Outcome.REQUIRE_HUMAN, "vrs high",
        "test@1.0", "abc123", timeout_seconds=300
    )
    assert d.outcome == Outcome.REQUIRE_HUMAN
    assert d.state == DecisionState.PENDING
    assert d.is_blocking()
    assert d.is_pending()
    assert d.timeout_at is not None

    # Approve
    d.approve("principal_alice", b"fake_sig_bytes", justification="OK after review")
    assert d.state == DecisionState.APPROVED
    assert d.approved_by == "principal_alice"
    assert d.justification == "OK after review"
    print("  ✓ Decision REQUIRE_HUMAN → approve flow")


def test_decision_rejection():
    ctx = make_ctx(vrs=0.65)
    d = Decision.from_context(
        ctx, Outcome.REQUIRE_HUMAN, "vrs high",
        "test@1.0", "abc123", timeout_seconds=300
    )
    d.reject("principal_bob", b"fake_sig", justification="Too risky")
    assert d.state == DecisionState.REJECTED
    assert d.approved_by == "principal_bob"
    print("  ✓ Decision rejection flow")


def test_decision_serialization():
    ctx = make_ctx()
    d = Decision.from_context(ctx, Outcome.BLOCK, "test block", "v@1.0", "hash123")
    d.trustgate_signature = b"\x01\x02\x03"
    audit_dict = d.to_audit_dict()
    assert isinstance(audit_dict, dict)
    assert audit_dict["trustgate_signature"] == "010203"
    json_str = d.to_json()
    parsed = json.loads(json_str)
    assert parsed["outcome"] == "BLOCK"
    print("  ✓ Decision serialization — bytes to hex")


# ─── BLOC 2 — Policy Loader ───────────────────────────────────────────────────

def test_policy_load_yaml():
    policy_yaml = """
version: "1.0"
name: "unit_test"
thresholds:
  vrs_require_human: 0.60
  vrs_block: 0.85
roles:
  operator:
    allowed_tools: [read_db]
    blocked_tools: [shell]
"""
    with tempfile.NamedTemporaryFile(
        suffix=".yaml", mode="w", delete=False
    ) as f:
        f.write(policy_yaml)
        path = Path(f.name)

    try:
        policy = load_policy(path)
        assert policy.name == "unit_test"
        assert policy.thresholds.vrs_require_human == 0.60
        assert policy.thresholds.vrs_block == 0.85
        assert policy.content_hash != ""
        print("  ✓ Policy load YAML — fields correct")
    finally:
        path.unlink(missing_ok=True)


def test_policy_integrity_check():
    policy_yaml = (
        "version: '1.0'\nname: 'integrity_test'\n"
        "thresholds:\n  vrs_require_human: 0.60\n  vrs_block: 0.85\n"
    )
    import hashlib
    # Ecrire en mode binaire (newline=None) pour eviter la conversion
    # CRLF sur Windows — le hash doit correspondre exactement aux bytes ecrits.
    policy_bytes = policy_yaml.encode("utf-8")
    correct_hash = hashlib.sha256(policy_bytes).hexdigest()
    wrong_hash   = "0" * 64

    with tempfile.NamedTemporaryFile(
        suffix=".yaml", mode="wb", delete=False
    ) as f:
        f.write(policy_bytes)
        path = Path(f.name)

    try:
        # Correct hash — OK
        p = load_policy(path, verify_hash=correct_hash)
        assert p.name == "integrity_test"

        # Wrong hash — raises PolicyIntegrityError (ANSSI R35)
        try:
            load_policy(path, verify_hash=wrong_hash)
            assert False, "Should have raised PolicyIntegrityError"
        except PolicyIntegrityError as e:
            assert "tampered" in str(e).lower() or "integrity" in str(e).lower()

        print("  ✓ Policy integrity check — ANSSI R35")
    finally:
        path.unlink(missing_ok=True)


def test_policy_validation_errors():
    from trustgate.policy_loader import _validate

    bad = make_policy()
    bad.thresholds.vrs_require_human = 0.90
    bad.thresholds.vrs_block = 0.50   # < require_human — invalid

    try:
        _validate(bad)
        assert False, "Should have raised PolicyValidationError"
    except PolicyValidationError as e:
        assert "vrs_require_human" in str(e) or "vrs_block" in str(e)

    print("  ✓ Policy validation — threshold ordering enforced")


# ─── BLOC 3 — Policy Engine ───────────────────────────────────────────────────

def test_engine_allow():
    ctx    = make_ctx(vrs=0.20, tsi_state="STABLE", action="read_db", role="operator")
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.ALLOW
    print("  ✓ Policy engine — ALLOW (nominal)")


def test_engine_block_vrs():
    ctx    = make_ctx(vrs=0.90)   # above vrs_block=0.85
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.BLOCK
    assert "vrs_block" in d.reason.lower() or "0.85" in d.reason
    print("  ✓ Policy engine — BLOCK (VRS above block threshold)")


def test_engine_require_human_vrs():
    ctx    = make_ctx(vrs=0.70)   # above vrs_require_human=0.60
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.REQUIRE_HUMAN
    assert d.timeout_at is not None
    print("  ✓ Policy engine — REQUIRE_HUMAN (VRS)")


def test_engine_block_dangerous_pattern():
    ctx = make_ctx(
        action  = "shell",
        role    = "trusted",
        payload = {"cmd": "rm -rf /var/data"},
    )
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.BLOCK
    assert "pattern" in d.reason.lower() or "dangerous" in d.reason.lower()
    print("  ✓ Policy engine — BLOCK (dangerous pattern rm -rf)")


def test_engine_block_sql_injection():
    ctx = make_ctx(
        action  = "read_db",
        role    = "operator",
        payload = {"query": "DROP TABLE users"},
    )
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.BLOCK
    print("  ✓ Policy engine — BLOCK (dangerous pattern DROP TABLE)")


def test_engine_block_role_violation():
    ctx = make_ctx(action="shell", role="operator")  # shell blocked for operator
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.BLOCK
    assert "role" in d.reason.lower() or "operator" in d.reason.lower()
    print("  ✓ Policy engine — BLOCK (role violation — least privilege ANSSI R26)")


def test_engine_block_network():
    ctx = make_ctx(
        action        = "http_get",
        role          = "operator",
        target_domain = "external-site.com",   # not in allowed_domains
    )
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.BLOCK
    assert "domain" in d.reason.lower() or "whitelist" in d.reason.lower()
    print("  ✓ Policy engine — BLOCK (domain not whitelisted ANSSI R28)")


def test_engine_allow_whitelisted_domain():
    import trustgate.policy_engine as _pe
    _pe._alert_counts.clear()
    ctx = make_ctx(
        action        = "http_get",
        role          = "operator",
        target_domain = "api.internal.local",  # in allowed_domains
    )
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.ALLOW
    print("  ✓ Policy engine — ALLOW (whitelisted domain)")


def test_engine_tsi_critical():
    ctx    = make_ctx(vrs=0.30, tsi_state="CRITICAL")
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.BLOCK
    assert "CRITICAL" in d.reason
    print("  ✓ Policy engine — BLOCK (TSI CRITICAL)")


def test_engine_tsi_unstable():
    ctx    = make_ctx(vrs=0.30, tsi_state="UNSTABLE")
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.REQUIRE_HUMAN
    assert "UNSTABLE" in d.reason
    print("  ✓ Policy engine — REQUIRE_HUMAN (TSI UNSTABLE)")


def test_engine_tsi_watch():
    import trustgate.policy_engine as _pe
    _pe._alert_counts.clear()
    ctx    = make_ctx(vrs=0.20, tsi_state="WATCH")
    policy = make_policy()
    d = evaluate(ctx, policy)
    assert d.outcome == Outcome.ALLOW_WITH_LOG
    print("  ✓ Policy engine — ALLOW_WITH_LOG (TSI WATCH)")


def test_engine_simulate():
    ctx    = make_ctx(vrs=0.70, tsi_state="WATCH", action="shell", role="trusted")
    policy = make_policy()
    result = simulate(ctx, policy)
    assert "outcome" in result
    assert result["simulated"] is True
    assert isinstance(result["triggered_rules"], list)
    assert len(result["triggered_rules"]) > 0
    print(f"  ✓ Policy engine — simulate() — {len(result['triggered_rules'])} rules triggered")


def test_engine_reason_not_empty():
    """Every outcome must have a non-empty reason — AI Act Art.13 transparency."""
    contexts = [
        make_ctx(vrs=0.20, tsi_state="STABLE"),
        make_ctx(vrs=0.70),
        make_ctx(vrs=0.90),
        make_ctx(action="shell", role="operator"),
        make_ctx(tsi_state="CRITICAL", vrs=0.30),
    ]
    policy = make_policy()
    for ctx in contexts:
        d = evaluate(ctx, policy)
        assert d.reason, f"Empty reason for outcome={d.outcome}"
    print("  ✓ Policy engine — reason field always populated (AI Act Art.13)")


# ─── BLOC 4 — Audit Journal ───────────────────────────────────────────────────

def test_journal_record_and_retrieve():
    with tempfile.TemporaryDirectory() as tmpdir:
        journal = AuditJournal(journal_dir=Path(tmpdir))
        ctx     = make_ctx(vrs=0.70)
        policy  = make_policy()

        d = evaluate(ctx, policy)
        entry = journal.record(d)

        assert entry is not None
        assert entry.outcome == Outcome.REQUIRE_HUMAN
        assert entry.seq == 1
        assert entry.entry_hash != ""
        assert entry.previous_hash == ""

        entries = journal.get_recent(days=1)
        assert len(entries) == 1
        print("  ✓ Audit journal — record + retrieve")


def test_journal_chain_integrity():
    with tempfile.TemporaryDirectory() as tmpdir:
        journal = AuditJournal(journal_dir=Path(tmpdir))
        policy  = make_policy()

        # Record 5 decisions
        for i in range(5):
            ctx = make_ctx(vrs=0.70 + i * 0.02)
            d   = evaluate(ctx, policy)
            journal.record(d)

        valid, errors = journal.verify_chain()
        assert valid, f"Chain should be valid. Errors: {errors}"
        print("  ✓ Audit journal — chain integrity (5 entries)")


def test_journal_export_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        journal = AuditJournal(journal_dir=Path(tmpdir))
        policy  = make_policy()

        ctx = make_ctx(vrs=0.90)
        d   = evaluate(ctx, policy)
        journal.record(d)

        export = journal.export_json(days=1)
        parsed = json.loads(export)
        assert parsed["total_entries"] == 1
        assert "entries" in parsed
        assert parsed["chain_valid"] is True
        print("  ✓ Audit journal — JSON export")


def test_journal_filter_by_agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        journal = AuditJournal(journal_dir=Path(tmpdir))
        policy  = make_policy()

        # Two different agents
        for agent_id in ["agent_A", "agent_B", "agent_A"]:
            ctx = make_ctx(agent_id=agent_id, agent_name=agent_id, vrs=0.70)
            journal.record(evaluate(ctx, policy))

        entries_A = journal.get_recent(agent_id="agent_A", days=1)
        entries_B = journal.get_recent(agent_id="agent_B", days=1)

        assert len(entries_A) == 2
        assert len(entries_B) == 1
        print("  ✓ Audit journal — filter by agent_id")


# ─── BLOC 5 — Policy Versioning ───────────────────────────────────────────────

def test_versioning_activate():
    policy_content = (
        "version: '1.0'\nname: 'version_test'\n"
        "thresholds:\n  vrs_require_human: 0.60\n  vrs_block: 0.85\n"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = Path(tmpdir) / "policy.yaml"
        policy_path.write_text(policy_content)

        versioning = PolicyVersioning(versions_dir=Path(tmpdir) / "versions")
        v = versioning.activate(policy_path, activated_by="principal_test", comment="Initial")

        assert v.version_id == "version_test@1.0"
        assert v.content_hash != ""
        assert v.activated_by == "principal_test"
        print("  ✓ Policy versioning — activate()")


def test_versioning_history():
    policy_v1 = (
        "version: '1.0'\nname: 'hist_test'\n"
        "thresholds:\n  vrs_require_human: 0.60\n  vrs_block: 0.85\n"
    )
    policy_v2 = (
        "version: '2.0'\nname: 'hist_test'\n"
        "thresholds:\n  vrs_require_human: 0.50\n  vrs_block: 0.80\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        v1_path = Path(tmpdir) / "policy_v1.yaml"
        v2_path = Path(tmpdir) / "policy_v2.yaml"
        v1_path.write_text(policy_v1)
        v2_path.write_text(policy_v2)

        versioning = PolicyVersioning(versions_dir=Path(tmpdir) / "versions")
        versioning.activate(v1_path, activated_by="admin", comment="v1 initial")
        time.sleep(0.01)
        versioning.activate(v2_path, activated_by="admin", comment="v2 stricter")

        history = versioning.get_history(name="hist_test")
        assert len(history) == 2
        assert history[0].version_id == "hist_test@1.0"
        assert history[1].version_id == "hist_test@2.0"
        print("  ✓ Policy versioning — history (2 versions)")


def test_versioning_verify_current():
    policy_content = (
        "version: '1.0'\nname: 'verify_test'\n"
        "thresholds:\n  vrs_require_human: 0.60\n  vrs_block: 0.85\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = Path(tmpdir) / "policy.yaml"
        policy_path.write_text(policy_content)

        versioning = PolicyVersioning(versions_dir=Path(tmpdir) / "versions")
        versioning.activate(policy_path)

        valid, msg = versioning.verify_current(policy_path)
        assert valid, f"Should be valid: {msg}"

        # Tamper with the file
        policy_path.write_text(policy_content + "\n# TAMPERED\n")
        valid, msg = versioning.verify_current(policy_path)
        assert not valid
        assert "mismatch" in msg.lower() or "tampered" in msg.lower()
        print("  ✓ Policy versioning — tamper detection (ANSSI R35)")


# ─── Runner ───────────────────────────────────────────────────────────────────

def run_all():
    tests = [
        # BLOC 1 — Decision
        ("Decision creation", test_decision_creation),
        ("Decision REQUIRE_HUMAN → approve", test_decision_require_human_flow),
        ("Decision rejection", test_decision_rejection),
        ("Decision serialization", test_decision_serialization),

        # BLOC 2 — Policy Loader
        ("Policy load YAML", test_policy_load_yaml),
        ("Policy integrity check (ANSSI R35)", test_policy_integrity_check),
        ("Policy validation errors", test_policy_validation_errors),

        # BLOC 3 — Policy Engine
        ("Engine ALLOW (nominal)", test_engine_allow),
        ("Engine BLOCK (VRS > block threshold)", test_engine_block_vrs),
        ("Engine REQUIRE_HUMAN (VRS)", test_engine_require_human_vrs),
        ("Engine BLOCK (dangerous pattern rm -rf)", test_engine_block_dangerous_pattern),
        ("Engine BLOCK (dangerous pattern SQL)", test_engine_block_sql_injection),
        ("Engine BLOCK (role violation ANSSI R26)", test_engine_block_role_violation),
        ("Engine BLOCK (domain not whitelisted R28)", test_engine_block_network),
        ("Engine ALLOW (whitelisted domain)", test_engine_allow_whitelisted_domain),
        ("Engine BLOCK (TSI CRITICAL)", test_engine_tsi_critical),
        ("Engine REQUIRE_HUMAN (TSI UNSTABLE)", test_engine_tsi_unstable),
        ("Engine ALLOW_WITH_LOG (TSI WATCH)", test_engine_tsi_watch),
        ("Engine simulate() mode", test_engine_simulate),
        ("Engine reason always set (AI Act Art.13)", test_engine_reason_not_empty),

        # BLOC 4 — Audit Journal
        ("Journal record + retrieve", test_journal_record_and_retrieve),
        ("Journal chain integrity (5 entries)", test_journal_chain_integrity),
        ("Journal JSON export", test_journal_export_json),
        ("Journal filter by agent_id", test_journal_filter_by_agent),

        # BLOC 5 — Policy Versioning
        ("Versioning activate()", test_versioning_activate),
        ("Versioning history (2 versions)", test_versioning_history),
        ("Versioning tamper detection (R35)", test_versioning_verify_current),
    ]

    GREEN = "\033[92m"
    RED   = "\033[91m"
    BOLD  = "\033[1m"
    RESET = "\033[0m"
    DIM   = "\033[2m"

    print(f"\n{BOLD}Trust Gate — Sprint 1 Unit Tests{RESET}")
    print("=" * 60)

    passed = 0
    failed = 0
    failures = []

    for name, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            failed += 1
            failures.append((name, str(e)))
            print(f"  {RED}✗ {name}{RESET}")
            print(f"    {DIM}{e}{RESET}")

    print("=" * 60)
    print(f"{BOLD}Results: {GREEN}{passed} passed{RESET}", end="")
    if failed:
        print(f" / {RED}{failed} failed{RESET}")
    else:
        print()

    if failures:
        print(f"\n{RED}Failures:{RESET}")
        for name, err in failures:
            print(f"  ✗ {name}: {err}")
        sys.exit(1)
    else:
        print(f"\n{GREEN}{BOLD}All tests passed — Sprint 1 validated ✅{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    run_all()
