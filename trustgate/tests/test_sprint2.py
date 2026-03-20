"""
test_sprint2.py — Trust Gate Sprint 2 Unit Tests

Coverage:
- human_principal.py  : create, load, list, SSO auth, sign, clearance
- decision_queue.py   : enqueue, approve, reject, timeout, callbacks
- notifier.py         : build context, ConsoleChannel, WebhookChannel mock
"""

import json
import sys
import tempfile
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from trustgate.decision import Decision, EvaluationContext, Outcome, DecisionState
from trustgate.human_principal import (
    HumanPrincipal, SSOToken,
    InsufficientClearanceError, PrincipalNotFoundError,
)
from trustgate.decision_queue import (
    DecisionQueue, DecisionAlreadyResolvedError,
)
from trustgate.notifier import Notifier, ConsoleChannel
from trustgate.policy_loader import (
    Policy, ThresholdPolicy, RolePolicy, NetworkPolicy,
    NotificationPolicy, EscalationPolicy,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_policy() -> Policy:
    p = Policy()
    p.content_hash = "abc123"
    p.thresholds   = ThresholdPolicy(vrs_require_human=0.60, vrs_block=0.85)
    p.roles        = {
        "operator": RolePolicy(
            allowed_tools=["read_db", "write_db", "http_get"],
            blocked_tools=["shell"],
        ),
    }
    p.escalation      = EscalationPolicy()
    p.network         = NetworkPolicy(allowed_domains=[], block_external=False)
    p.notification    = NotificationPolicy(timeout_seconds=300, on_timeout="REJECT")
    p.dangerous_patterns = []
    return p


def make_require_human_decision(vrs: float = 0.65, timeout: int = 300) -> Decision:
    ctx = EvaluationContext(
        agent_id    = "AISS-test-001",
        agent_name  = "test_agent",
        role        = "operator",
        action      = "write_db",
        payload     = {"query": "UPDATE users SET active=false"},
        vrs         = vrs,
        tsi_state   = "WATCH",
        a2c_score   = 0.15,
        trust_score = 0.80,
    )
    return Decision.from_context(
        ctx, Outcome.REQUIRE_HUMAN,
        f"VRS {vrs:.3f} >= require_human threshold 0.60",
        "test@1.0", "abc123",
        timeout_seconds=timeout,
    )


def make_sso_token(principal: HumanPrincipal, ttl: int = 3600) -> SSOToken:
    return principal.authenticate_sso(
        sso_claims={"sub": "test-sso-subject", "email": principal.record.email},
        ttl_seconds=ttl,
    )


# ─── BLOC 1 — Human Principal ─────────────────────────────────────────────────

def test_principal_create_sso():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        p = HumanPrincipal.create(
            name           = "alice",
            email          = "alice@company.com",
            clearance      = "L2",
            mode           = "sso",
            sso_provider   = "azure_ad",
            sso_subject    = "test-sso-subject",
            principals_dir = principals_dir,
        )
        assert p.record.principal_id.startswith("PRINCIPAL-")
        assert p.record.clearance == "L2"
        assert p.record.mode == "sso"
        assert p.record.active is True

        # Record persisted
        record_path = principals_dir / "alice" / "principal.json"
        assert record_path.exists()
        print("  ✓ HumanPrincipal.create() SSO — fields + persistence")


def test_principal_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        p1 = HumanPrincipal.create(
            name="bob", email="bob@co.com", clearance="L1",
            mode="sso", principals_dir=principals_dir,
        )
        p2 = HumanPrincipal.load("bob", principals_dir=principals_dir)
        assert p2.record.principal_id == p1.record.principal_id
        assert p2.record.clearance == "L1"
        print("  ✓ HumanPrincipal.load() — identity preserved")


def test_principal_not_found():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        try:
            HumanPrincipal.load("nonexistent", principals_dir=principals_dir)
            assert False, "Should raise PrincipalNotFoundError"
        except PrincipalNotFoundError:
            pass
        print("  ✓ HumanPrincipal.load() — PrincipalNotFoundError on missing")


def test_principal_list_all():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        for name, clearance in [("alice", "L3"), ("bob", "L1"), ("charlie", "L2")]:
            HumanPrincipal.create(
                name=name, email=f"{name}@co.com",
                clearance=clearance, mode="sso",
                principals_dir=principals_dir,
            )
        principals = HumanPrincipal.list_all(principals_dir=principals_dir)
        assert len(principals) == 3
        names = [p.record.name for p in principals]
        assert "alice" in names and "bob" in names and "charlie" in names
        print("  ✓ HumanPrincipal.list_all() — 3 principals")


def test_principal_sso_authenticate():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        p = HumanPrincipal.create(
            name="alice", email="alice@co.com", clearance="L2",
            mode="sso", sso_subject="test-sso-subject",
            principals_dir=principals_dir,
        )
        token = p.authenticate_sso(
            sso_claims={"sub": "test-sso-subject"},
            ttl_seconds=3600,
        )
        assert token.principal_id == p.record.principal_id
        assert token.clearance == "L2"
        assert token.is_valid()
        assert token.token_hash != ""
        # last_login updated
        assert p.record.last_login is not None
        print("  ✓ HumanPrincipal.authenticate_sso() — token issued")


def test_principal_sso_expired_token():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        p = HumanPrincipal.create(
            name="alice", email="alice@co.com", clearance="L2",
            mode="sso", principals_dir=principals_dir,
        )
        token = p.authenticate_sso(sso_claims={}, ttl_seconds=1)
        time.sleep(2)
        assert not token.is_valid()
        print("  ✓ SSO token expiry — is_valid() returns False after TTL")


def test_principal_sign_decision_sso():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        p = HumanPrincipal.create(
            name="alice", email="alice@co.com", clearance="L2",
            mode="sso", principals_dir=principals_dir,
        )
        token = make_sso_token(p)
        sig = p.sign_decision_sso(
            decision_id   = "test-decision-001",
            outcome       = "APPROVED",
            token         = token,
            justification = "Reviewed and approved",
        )
        assert isinstance(sig, bytes)
        assert len(sig) == 32  # HMAC-SHA256
        print("  ✓ HumanPrincipal.sign_decision_sso() — HMAC-SHA256 signature")


def test_principal_clearance_levels():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        l1 = HumanPrincipal.create(
            name="l1", email="l1@co.com", clearance="L1", mode="sso", principals_dir=principals_dir
        )
        l2 = HumanPrincipal.create(
            name="l2", email="l2@co.com", clearance="L2", mode="sso", principals_dir=principals_dir
        )
        l3 = HumanPrincipal.create(
            name="l3", email="l3@co.com", clearance="L3", mode="sso", principals_dir=principals_dir
        )

        # L1: can approve VRS < 0.75
        assert l1.can_approve(0.70) is True
        assert l1.can_approve(0.80) is False

        # L2: can approve VRS < 0.90
        assert l2.can_approve(0.85) is True
        assert l2.can_approve(0.95) is False

        # L3: can approve anything
        assert l3.can_approve(0.99) is True

        # assert_can_approve raises on insufficient clearance
        try:
            l1.assert_can_approve(0.80)
            assert False, "Should raise"
        except InsufficientClearanceError as e:
            assert "L1" in str(e)

        print("  ✓ Clearance levels L1/L2/L3 — VRS limits enforced (ANSSI R30)")


def test_principal_deactivate():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        p = HumanPrincipal.create(
            name="alice", email="alice@co.com", clearance="L1",
            mode="sso", principals_dir=principals_dir,
        )
        p.deactivate()
        assert p.can_approve(0.60) is False

        p.reactivate()
        assert p.can_approve(0.60) is True
        print("  ✓ Principal deactivate/reactivate — can_approve gated")


# ─── BLOC 2 — Decision Queue ──────────────────────────────────────────────────

def test_queue_enqueue():
    with tempfile.TemporaryDirectory() as tmpdir:
        queue = DecisionQueue(queue_dir=Path(tmpdir) / "queue")
        d = make_require_human_decision()
        queue.enqueue(d)

        pending = queue.get_pending()
        assert len(pending) == 1
        assert pending[0].decision_id == d.decision_id
        assert pending[0].state == DecisionState.PENDING
        print("  ✓ DecisionQueue.enqueue() — decision persisted as pending")


def test_queue_approve():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        queue_dir      = Path(tmpdir) / "queue"

        principal = HumanPrincipal.create(
            name="alice", email="alice@co.com", clearance="L2",
            mode="sso", principals_dir=principals_dir,
        )
        token = make_sso_token(principal)
        queue = DecisionQueue(queue_dir=queue_dir)
        d     = make_require_human_decision(vrs=0.65)
        queue.enqueue(d)

        resolved = queue.approve(
            decision_id      = d.decision_id,
            principal        = principal,
            token_or_session = token,
            justification    = "Reviewed — approved",
        )

        assert resolved.state == DecisionState.APPROVED
        assert resolved.approved_by == principal.record.principal_id
        assert resolved.justification == "Reviewed — approved"
        assert isinstance(resolved.approval_signature, bytes)

        # No longer in pending
        assert queue.count_pending() == 0
        print("  ✓ DecisionQueue.approve() — signed, state=APPROVED")


def test_queue_reject():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        queue_dir      = Path(tmpdir) / "queue"

        principal = HumanPrincipal.create(
            name="bob", email="bob@co.com", clearance="L2",
            mode="sso", principals_dir=principals_dir,
        )
        token = make_sso_token(principal)
        queue = DecisionQueue(queue_dir=queue_dir)
        d     = make_require_human_decision(vrs=0.70)
        queue.enqueue(d)

        resolved = queue.reject(
            decision_id      = d.decision_id,
            principal        = principal,
            token_or_session = token,
            justification    = "Too risky",
        )

        assert resolved.state == DecisionState.REJECTED
        assert resolved.approved_by == principal.record.principal_id
        print("  ✓ DecisionQueue.reject() — state=REJECTED, signed")


def test_queue_insufficient_clearance():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        queue_dir      = Path(tmpdir) / "queue"

        # L1 principal — cannot approve VRS=0.80
        principal = HumanPrincipal.create(
            name="junior", email="j@co.com", clearance="L1",
            mode="sso", principals_dir=principals_dir,
        )
        token = make_sso_token(principal)
        queue = DecisionQueue(queue_dir=queue_dir)
        d     = make_require_human_decision(vrs=0.80)
        queue.enqueue(d)

        try:
            queue.approve(d.decision_id, principal, token)
            assert False, "Should raise InsufficientClearanceError"
        except InsufficientClearanceError as e:
            assert "L1" in str(e)

        # Decision still pending
        assert queue.count_pending() == 1
        print("  ✓ DecisionQueue — insufficient clearance rejected (ANSSI R30)")


def test_queue_double_resolve():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        queue_dir      = Path(tmpdir) / "queue"

        principal = HumanPrincipal.create(
            name="alice", email="alice@co.com", clearance="L2",
            mode="sso", principals_dir=principals_dir,
        )
        token = make_sso_token(principal)
        queue = DecisionQueue(queue_dir=queue_dir)
        d     = make_require_human_decision()
        queue.enqueue(d)
        queue.approve(d.decision_id, principal, token)

        try:
            queue.approve(d.decision_id, principal, token)
            assert False, "Should raise DecisionAlreadyResolvedError"
        except DecisionAlreadyResolvedError:
            pass
        print("  ✓ DecisionQueue — double-approve rejected")


def test_queue_timeout_auto_reject():
    with tempfile.TemporaryDirectory() as tmpdir:
        queue = DecisionQueue(
            queue_dir=Path(tmpdir) / "queue",
            on_timeout_default="REJECT",
        )
        # Decision with 1 second timeout
        d = make_require_human_decision(timeout=1)
        queue.enqueue(d)

        # Wait for timeout
        time.sleep(2)

        # Process timeouts manually (don't wait for watcher thread)
        queue._process_timeouts()

        assert queue.count_pending() == 0
        resolved = queue.get_decision(d.decision_id)
        assert resolved is not None
        assert resolved.state == DecisionState.TIMED_OUT
        assert resolved.outcome == Outcome.BLOCK
        print("  ✓ DecisionQueue — timeout → auto-BLOCK (ANSSI R9 / AI Act Art.14)")


def test_queue_callback_on_resolve():
    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        queue_dir      = Path(tmpdir) / "queue"

        resolved_decisions = []
        principal = HumanPrincipal.create(
            name="alice", email="alice@co.com", clearance="L2",
            mode="sso", principals_dir=principals_dir,
        )
        token = make_sso_token(principal)
        queue = DecisionQueue(queue_dir=queue_dir)
        queue.on_resolve(lambda d: resolved_decisions.append(d.decision_id))

        d = make_require_human_decision()
        queue.enqueue(d)
        queue.approve(d.decision_id, principal, token)

        assert d.decision_id in resolved_decisions
        print("  ✓ DecisionQueue.on_resolve() callback fired")


def test_queue_filter_by_agent():
    with tempfile.TemporaryDirectory() as tmpdir:
        queue = DecisionQueue(queue_dir=Path(tmpdir) / "queue")

        for agent_id in ["agent_A", "agent_B", "agent_A"]:
            d = make_require_human_decision()
            d.agent_id = agent_id
            queue.enqueue(d)

        assert queue.count_pending(agent_id="agent_A") == 2
        assert queue.count_pending(agent_id="agent_B") == 1
        print("  ✓ DecisionQueue — filter by agent_id")


# ─── BLOC 3 — Notifier ───────────────────────────────────────────────────────

def test_notifier_build_context():
    d = make_require_human_decision(vrs=0.72)
    notifier = Notifier(channels=[ConsoleChannel()])
    ctx = notifier._build_context(d)

    assert ctx.decision_id  == d.decision_id
    assert ctx.vrs          == d.vrs_at_decision
    assert ctx.severity     == "ALERT"
    assert ctx.approve_url  != ""
    assert ctx.reject_url   != ""
    assert ctx.timeout_at   == d.timeout_at
    print("  ✓ Notifier._build_context() — severity=ALERT for VRS=0.72")


def test_notifier_severity_levels():
    notifier = Notifier(channels=[ConsoleChannel()])

    for vrs, expected_severity in [(0.30, "WATCH"), (0.55, "ALERT"), (0.80, "CRITICAL")]:
        d = make_require_human_decision(vrs=vrs)
        ctx = notifier._build_context(d)
        assert ctx.severity == expected_severity, (
            f"VRS={vrs} expected {expected_severity}, got {ctx.severity}"
        )
    print("  ✓ Notifier severity levels — WATCH/ALERT/CRITICAL")


def test_notifier_console_channel():
    import io
    from contextlib import redirect_stdout

    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        p = HumanPrincipal.create(
            name="alice", email="alice@co.com", clearance="L2",
            mode="sso", principals_dir=principals_dir,
        )

    notifier = Notifier(channels=[ConsoleChannel()])
    d        = make_require_human_decision()

    buf = io.StringIO()
    with redirect_stdout(buf):
        result = notifier.push(d, [p])

    output = buf.getvalue()
    assert result["sent"] == 1
    assert result["failed"] == 0
    assert "REQUIRE_HUMAN" in output
    assert "test_agent" in output
    print("  ✓ Notifier ConsoleChannel — push() output correct")


def test_notifier_webhook_channel():
    """Test WebhookChannel with a mock HTTP server."""
    import http.server

    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            received.append(json.loads(body))
            self.send_response(200)
            self.end_headers()
        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port   = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        p = HumanPrincipal.create(
            name="alice", email="alice@co.com", clearance="L2",
            mode="sso", principals_dir=principals_dir,
        )

    from trustgate.notifier import WebhookChannel
    notifier = Notifier(channels=[WebhookChannel(f"http://127.0.0.1:{port}")])
    d        = make_require_human_decision()
    result   = notifier.push(d, [p])

    server.shutdown()

    assert result["sent"] == 1
    assert len(received) == 1
    assert received[0]["trustgate_event"] == "REQUIRE_HUMAN"
    assert received[0]["context"]["decision_id"] == d.decision_id
    print("  ✓ Notifier WebhookChannel — HTTP POST received by mock server")


def test_notifier_from_policy():
    policy = make_policy()
    policy.notification.channels = [{"type": "console"}]
    notifier = Notifier.from_policy(policy.notification)
    assert len(notifier.channels) == 1
    assert isinstance(notifier.channels[0], ConsoleChannel)
    print("  ✓ Notifier.from_policy() — channels built from policy")


def test_notifier_failed_channel_does_not_raise():
    """Notification failures must never raise — ANSSI R9 / AI Act Art.14."""
    from trustgate.notifier import WebhookChannel

    with tempfile.TemporaryDirectory() as tmpdir:
        principals_dir = Path(tmpdir) / "principals"
        p = HumanPrincipal.create(
            name="alice", email="alice@co.com", clearance="L2",
            mode="sso", principals_dir=principals_dir,
        )

    # Unreachable webhook
    bad_channel = WebhookChannel("http://127.0.0.1:1")
    notifier    = Notifier(channels=[bad_channel])
    d           = make_require_human_decision()

    # Must not raise
    result = notifier.push(d, [p])
    assert result["failed"] == 1
    assert result["sent"]   == 0
    print("  ✓ Notifier — unreachable channel does not raise")


# ─── Runner ───────────────────────────────────────────────────────────────────

def run_all():
    tests = [
        # BLOC 1 — Human Principal
        ("HumanPrincipal create (SSO)", test_principal_create_sso),
        ("HumanPrincipal load", test_principal_load),
        ("HumanPrincipal not found error", test_principal_not_found),
        ("HumanPrincipal list_all", test_principal_list_all),
        ("SSO authenticate — token issued", test_principal_sso_authenticate),
        ("SSO token expiry", test_principal_sso_expired_token),
        ("sign_decision_sso — HMAC-SHA256", test_principal_sign_decision_sso),
        ("Clearance levels L1/L2/L3 (ANSSI R30)", test_principal_clearance_levels),
        ("Principal deactivate/reactivate", test_principal_deactivate),

        # BLOC 2 — Decision Queue
        ("Queue enqueue — persisted as pending", test_queue_enqueue),
        ("Queue approve — signed, state=APPROVED", test_queue_approve),
        ("Queue reject — state=REJECTED", test_queue_reject),
        ("Queue insufficient clearance (ANSSI R30)", test_queue_insufficient_clearance),
        ("Queue double-approve rejected", test_queue_double_resolve),
        ("Queue timeout → auto-BLOCK (ANSSI R9)", test_queue_timeout_auto_reject),
        ("Queue on_resolve() callback", test_queue_callback_on_resolve),
        ("Queue filter by agent_id", test_queue_filter_by_agent),

        # BLOC 3 — Notifier
        ("Notifier build context", test_notifier_build_context),
        ("Notifier severity WATCH/ALERT/CRITICAL", test_notifier_severity_levels),
        ("Notifier ConsoleChannel output", test_notifier_console_channel),
        ("Notifier WebhookChannel HTTP POST", test_notifier_webhook_channel),
        ("Notifier from_policy()", test_notifier_from_policy),
        ("Notifier failed channel no raise", test_notifier_failed_channel_does_not_raise),
    ]

    GREEN = "\033[92m"
    RED   = "\033[91m"
    BOLD  = "\033[1m"
    RESET = "\033[0m"
    DIM   = "\033[2m"

    print(f"\n{BOLD}Trust Gate — Sprint 2 Unit Tests{RESET}")
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
            import traceback
            print(f"    {DIM}{traceback.format_exc().splitlines()[-1]}{RESET}")

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
        print(f"\n{GREEN}{BOLD}All tests passed — Sprint 2 validated ✅{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    run_all()
