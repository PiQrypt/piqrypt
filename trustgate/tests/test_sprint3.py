# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
test_sprint3.py — Trust Gate Sprint 3 Integration Tests

Tests the full HTTP API — every endpoint, every flow.
Server is started in a background thread for each test group.

Coverage:
    GET  /health
    GET  /api/status
    GET  /api/policy
    POST /api/policy/simulate
    POST /api/evaluate         (ALLOW, BLOCK, REQUIRE_HUMAN)
    GET  /api/decisions
    GET  /api/decisions/<id>
    POST /api/decisions/<id>/approve
    POST /api/decisions/<id>/reject
    GET  /api/principals
    POST /api/principals
    GET  /api/principals/<n>
    POST /api/principals/<n>/authenticate
    GET  /api/audit
    GET  /api/audit/export
    POST /api/vigil/agent-state
    Full REQUIRE_HUMAN flow end-to-end
"""

import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from trustgate_server import TrustGateServer


# ─── Test client helper ───────────────────────────────────────────────────────

class APIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._token = os.environ.get("TRUSTGATE_TOKEN", "")

    def _make_headers(self, extra: dict = None) -> dict:
        h = {"Content-Type": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        if extra:
            h.update(extra)
        return h

    def get(self, path: str, params: str = "") -> tuple:
        url = f"{self.base_url}{path}"
        if params:
            url += f"?{params}"
        req = urllib.request.Request(url, headers=self._make_headers())
        return self._send(req)

    def post(self, path: str, body: dict = None) -> tuple:
        data = json.dumps(body or {}).encode("utf-8")
        req  = urllib.request.Request(
            f"{self.base_url}{path}",
            data    = data,
            method  = "POST",
            headers = self._make_headers(),
        )
        return self._send(req)

    def _send(self, req) -> tuple:
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode()), resp.status
        except urllib.error.HTTPError as e:
            return json.loads(e.read().decode()), e.code


# ─── Server fixture ───────────────────────────────────────────────────────────

class ServerFixture:
    """Starts a TrustGate server in a background thread for tests."""

    def __init__(self):
        self.tmpdir    = tempfile.mkdtemp()
        self.tmppath   = Path(self.tmpdir)
        self.port      = self._find_free_port()
        _policy = self.tmppath / "policy.yaml"
        _policy.write_text(
            "version: 'test@1.0'\n"
            "name: test\n"
            "thresholds:\n"
            "  vrs_require_human: 0.60\n"
            "  vrs_block: 0.85\n"
            "roles:\n"
            "  operator:\n"
            "    allowed_tools: ['*']\n"
            "  trusted:\n"
            "    allowed_tools: ['*']\n"
            "  read_only:\n"
            "    allowed_tools: ['*']\n"
        )
        self.server    = TrustGateServer(
            host           = "127.0.0.1",
            port           = self.port,
            policy_path    = _policy,
            journal_dir    = self.tmppath / "journal",
            queue_dir      = self.tmppath / "queue",
            versions_dir   = self.tmppath / "versions",
            principals_dir = self.tmppath / "principals",
            demo_mode      = True,
        )
        self.thread = threading.Thread(
            target=self.server.start,
            daemon=True,
        )
        self.thread.start()
        self._wait_ready()
        self.client = APIClient(f"http://127.0.0.1:{self.port}")

    def _find_free_port(self) -> int:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _wait_ready(self, timeout: float = 5.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/health", timeout=1
                )
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("Server did not start in time")

    def stop(self):
        self.server.stop()


# ─── Shared fixture ───────────────────────────────────────────────────────────
# One server for all tests — faster than starting/stopping per test

_fixture: ServerFixture = None

def get_fixture() -> ServerFixture:
    global _fixture
    if _fixture is None:
        _fixture = ServerFixture()
    return _fixture


# ─── BLOC 1 — System endpoints ────────────────────────────────────────────────

def test_health():
    f = get_fixture()
    data, status = f.client.get("/health")
    assert status == 200
    assert data["status"] == "ok"
    assert data["demo_mode"] is True
    assert "policy" in data
    assert "pending" in data
    print("  ✓ GET /health — ok, demo_mode, policy, pending")


def test_status():
    f = get_fixture()
    data, status = f.client.get("/api/status")
    assert status == 200
    assert data["service"] == "trust_gate"
    assert data["port"] == f.port
    assert "pending_decisions" in data
    assert "principals" in data
    print("  ✓ GET /api/status — service info complete")


def test_404():
    f = get_fixture()
    data, status = f.client.get("/api/nonexistent")
    assert status == 404
    print("  ✓ 404 on unknown route")


# ─── BLOC 2 — Policy endpoints ────────────────────────────────────────────────

def test_get_policy():
    f = get_fixture()
    data, status = f.client.get("/api/policy")
    assert status == 200
    assert "name" in data
    assert "thresholds" in data
    assert "roles" in data
    assert data["thresholds"]["vrs_require_human"] == 0.60
    assert data["thresholds"]["vrs_block"] == 0.85
    print("  ✓ GET /api/policy — thresholds and roles present")


def test_simulate_allow():
    f = get_fixture()
    data, status = f.client.post("/api/policy/simulate", {
        "agent_id":  "sim-agent-001",
        "role":      "operator",
        "action":    "read_db",
        "payload":   {"query": "SELECT 1"},
        "vrs":       0.20,
        "tsi_state": "STABLE",
    })
    assert status == 200
    assert data["outcome"] == "ALLOW"
    assert data["simulated"] is True
    print("  ✓ POST /api/policy/simulate — ALLOW")


def test_simulate_block():
    f = get_fixture()
    data, status = f.client.post("/api/policy/simulate", {
        "agent_id":  "sim-agent-001",
        "role":      "operator",
        "action":    "read_db",
        "payload":   {"cmd": "DROP TABLE users"},
        "vrs":       0.20,
        "tsi_state": "STABLE",
    })
    assert status == 200
    assert data["outcome"] == "BLOCK"
    assert len(data["triggered_rules"]) > 0
    print("  ✓ POST /api/policy/simulate — BLOCK (dangerous pattern)")


# ─── BLOC 3 — Evaluate endpoint ───────────────────────────────────────────────

def test_evaluate_allow():
    f = get_fixture()
    data, status = f.client.post("/api/evaluate", {
        "agent_id":  "AISS-eval-001",
        "role":      "operator",
        "action":    "read_db",
        "payload":   {"query": "SELECT * FROM logs"},
        "vrs":       0.15,
        "tsi_state": "STABLE",
    })
    assert status == 200
    assert data["outcome"] == "ALLOW"
    assert data["blocked"] is False
    assert data["pending"] is False
    assert "decision_id" in data
    print("  ✓ POST /api/evaluate — ALLOW, decision_id present")


def test_evaluate_block_vrs():
    f = get_fixture()
    data, status = f.client.post("/api/evaluate", {
        "agent_id":  "AISS-eval-002",
        "role":      "operator",
        "action":    "write_db",
        "payload":   {},
        "vrs":       0.90,
        "tsi_state": "STABLE",
    })
    assert status == 200
    assert data["outcome"] == "BLOCK"
    assert data["blocked"] is True
    print("  ✓ POST /api/evaluate — BLOCK (VRS=0.90 > 0.85)")


def test_evaluate_block_pattern():
    f = get_fixture()
    data, status = f.client.post("/api/evaluate", {
        "agent_id":  "AISS-eval-003",
        "role":      "trusted",
        "action":    "write_db",
        "payload":   {"cmd": "rm -rf /"},
        "vrs":       0.10,
        "tsi_state": "STABLE",
    })
    assert status == 200
    assert data["outcome"] == "BLOCK"
    assert data["blocked"] is True
    print("  ✓ POST /api/evaluate — BLOCK (rm -rf pattern)")


def test_evaluate_require_human():
    f = get_fixture()
    data, status = f.client.post("/api/evaluate", {
        "agent_id":  "AISS-eval-004",
        "role":      "operator",
        "action":    "write_db",
        "payload":   {"query": "UPDATE users SET role='admin'"},
        "vrs":       0.70,
        "tsi_state": "WATCH",
    })
    assert status == 200
    assert data["outcome"] == "REQUIRE_HUMAN"
    assert data["blocked"]  is True
    assert data["pending"]  is True
    assert data["timeout_at"] is not None
    print("  ✓ POST /api/evaluate — REQUIRE_HUMAN (VRS=0.70), queued")
    return data["decision_id"]


def test_evaluate_missing_fields():
    f = get_fixture()
    data, status = f.client.post("/api/evaluate", {"role": "operator"})
    assert status == 400
    assert "error" in data
    print("  ✓ POST /api/evaluate — 400 on missing required fields")


# ─── BLOC 4 — Decisions endpoints ────────────────────────────────────────────

def test_list_decisions():
    f = get_fixture()
    # Ensure at least one pending decision
    f.client.post("/api/evaluate", {
        "agent_id": "AISS-queue-001", "role": "operator",
        "action": "write_db", "payload": {},
        "vrs": 0.72, "tsi_state": "STABLE",
    })
    data, status = f.client.get("/api/decisions")
    assert status == 200
    assert "total" in data
    assert "decisions" in data
    assert isinstance(data["decisions"], list)
    print(f"  ✓ GET /api/decisions — {data['total']} pending")


def test_get_decision_by_id():
    f = get_fixture()
    # Create one
    eval_data, _ = f.client.post("/api/evaluate", {
        "agent_id": "AISS-getd-001", "role": "operator",
        "action": "write_db", "payload": {},
        "vrs": 0.68, "tsi_state": "STABLE",
    })
    decision_id = eval_data["decision_id"]

    data, status = f.client.get(f"/api/decisions/{decision_id}")
    assert status == 200
    assert data["decision_id"] == decision_id
    assert data["outcome"] == "REQUIRE_HUMAN"
    print("  ✓ GET /api/decisions/<id> — decision retrieved")


def test_get_decision_not_found():
    f = get_fixture()
    data, status = f.client.get("/api/decisions/nonexistent-id")
    assert status == 404
    print("  ✓ GET /api/decisions/<id> — 404 on missing id")


# ─── BLOC 5 — Principals endpoints ───────────────────────────────────────────

def test_create_principal():
    f = get_fixture()
    data, status = f.client.post("/api/principals", {
        "name":      "alice",
        "email":     "alice@company.com",
        "clearance": "L2",
        "mode":      "sso",
    })
    assert status == 201
    assert data["name"]      == "alice"
    assert data["clearance"] == "L2"
    assert data["active"]    is True
    assert data["principal_id"].startswith("PRINCIPAL-")
    print("  ✓ POST /api/principals — principal created")


def test_list_principals():
    f = get_fixture()
    data, status = f.client.get("/api/principals")
    assert status == 200
    assert "total" in data
    assert "principals" in data
    print(f"  ✓ GET /api/principals — {data['total']} principals")


def test_get_principal():
    f = get_fixture()
    # Ensure alice exists
    f.client.post("/api/principals", {
        "name": "alice", "email": "alice@co.com",
        "clearance": "L2", "mode": "sso",
    })
    data, status = f.client.get("/api/principals/alice")
    assert status == 200
    assert data["name"] == "alice"
    print("  ✓ GET /api/principals/<n> — alice retrieved")


def test_get_principal_not_found():
    f = get_fixture()
    data, status = f.client.get("/api/principals/nobody")
    assert status == 404
    print("  ✓ GET /api/principals/<n> — 404 on missing")


def test_authenticate_principal():
    f = get_fixture()
    # Ensure alice exists
    f.client.post("/api/principals", {
        "name": "alice", "email": "alice@co.com",
        "clearance": "L2", "mode": "sso",
    })
    data, status = f.client.post("/api/principals/alice/authenticate", {
        "sso_claims": {"sub": "azure-123", "email": "alice@co.com"},
        "ttl_seconds": 3600,
    })
    assert status == 200
    assert "token_id"  in data
    assert data["clearance"] == "L2"
    assert data["valid"]     is True
    print("  ✓ POST /api/principals/alice/authenticate — token issued")


# ─── BLOC 6 — Approve / Reject flow ─────────────────────────────────────────

def test_approve_flow():
    f = get_fixture()

    # 1. Create L2 principal
    f.client.post("/api/principals", {
        "name": "approver_l2", "email": "approver@co.com",
        "clearance": "L2", "mode": "sso",
    })

    # 2. Create REQUIRE_HUMAN decision
    eval_data, _ = f.client.post("/api/evaluate", {
        "agent_id": "AISS-approve-001", "role": "operator",
        "action": "write_db", "payload": {},
        "vrs": 0.65, "tsi_state": "STABLE",
    })
    assert eval_data["outcome"] == "REQUIRE_HUMAN"
    decision_id = eval_data["decision_id"]

    # 3. Approve
    data, status = f.client.post(
        f"/api/decisions/{decision_id}/approve",
        {
            "principal_name": "approver_l2",
            "justification":  "Reviewed and approved in test",
        }
    )
    assert status == 200
    assert data["state"] == "APPROVED"
    assert data["approved_by"]  is not None
    assert data["justification"] == "Reviewed and approved in test"
    print("  ✓ Full approve flow — evaluate → REQUIRE_HUMAN → approve → APPROVED")


def test_reject_flow():
    f = get_fixture()

    f.client.post("/api/principals", {
        "name": "approver_l2", "email": "approver@co.com",
        "clearance": "L2", "mode": "sso",
    })

    eval_data, _ = f.client.post("/api/evaluate", {
        "agent_id": "AISS-reject-001", "role": "operator",
        "action": "write_db", "payload": {},
        "vrs": 0.67, "tsi_state": "STABLE",
    })
    decision_id = eval_data["decision_id"]

    data, status = f.client.post(
        f"/api/decisions/{decision_id}/reject",
        {
            "principal_name": "approver_l2",
            "justification":  "Too risky",
        }
    )
    assert status == 200
    assert data["state"] == "REJECTED"
    print("  ✓ Full reject flow — evaluate → REQUIRE_HUMAN → reject → REJECTED")


def test_approve_insufficient_clearance():
    f = get_fixture()

    # L1 cannot approve VRS=0.80
    f.client.post("/api/principals", {
        "name": "junior_l1", "email": "junior@co.com",
        "clearance": "L1", "mode": "sso",
    })

    eval_data, _ = f.client.post("/api/evaluate", {
        "agent_id": "AISS-clearance-001", "role": "operator",
        "action": "write_db", "payload": {},
        "vrs": 0.80, "tsi_state": "STABLE",
    })
    decision_id = eval_data["decision_id"]

    data, status = f.client.post(
        f"/api/decisions/{decision_id}/approve",
        {"principal_name": "junior_l1"}
    )
    assert status == 403
    assert "L1" in data["error"] or "clearance" in data["error"].lower()
    print("  ✓ Approve 403 — L1 cannot approve VRS=0.80 (ANSSI R30)")


# ─── BLOC 7 — Audit endpoints ─────────────────────────────────────────────────

def test_audit_list():
    f = get_fixture()
    # Create some decisions
    for vrs in [0.90, 0.92]:
        f.client.post("/api/evaluate", {
            "agent_id": "AISS-audit-001", "role": "operator",
            "action": "write_db", "payload": {},
            "vrs": vrs, "tsi_state": "STABLE",
        })

    data, status = f.client.get("/api/audit")
    assert status == 200
    assert "total" in data
    assert "chain_valid" in data
    assert "entries" in data
    assert data["total"] >= 2
    print(f"  ✓ GET /api/audit — {data['total']} entries, chain_valid={data['chain_valid']}")


def test_audit_filter_by_agent():
    f = get_fixture()
    f.client.post("/api/evaluate", {
        "agent_id": "AISS-filter-unique", "role": "operator",
        "action": "write_db", "payload": {},
        "vrs": 0.91, "tsi_state": "STABLE",
    })

    data, status = f.client.get("/api/audit?agent_id=AISS-filter-unique")
    assert status == 200
    assert data["total"] >= 1
    for entry in data["entries"]:
        assert entry["agent_id"] == "AISS-filter-unique"
    print("  ✓ GET /api/audit?agent_id= — filter works")


def test_audit_export():
    f = get_fixture()
    data, status = f.client.get("/api/audit/export?days=1")
    assert status == 200
    assert "export_timestamp" in data
    assert "total_entries" in data
    assert "chain_valid" in data
    assert "entries" in data
    print(f"  ✓ GET /api/audit/export — {data['total_entries']} entries exported")


# ─── BLOC 8 — Vigil bridge ───────────────────────────────────────────────────

def test_vigil_bridge_below_threshold():
    f = get_fixture()
    data, status = f.client.post("/api/vigil/agent-state", {
        "agent_id":    "AISS-vigil-001",
        "agent_name":  "vigil_agent",
        "vrs":         0.30,
        "tsi_state":   "STABLE",
        "a2c_score":   0.10,
    })
    assert status == 200
    assert data["outcome"] == "MONITOR"
    print("  ✓ POST /api/vigil/agent-state — MONITOR (VRS below threshold)")


def test_vigil_bridge_above_threshold():
    f = get_fixture()
    data, status = f.client.post("/api/vigil/agent-state", {
        "agent_id":    "AISS-vigil-002",
        "agent_name":  "vigil_critical",
        "vrs":         0.91,
        "tsi_state":   "UNSTABLE",
        "a2c_score":   0.40,
    })
    assert status == 200
    assert data["outcome"] in ("BLOCK", "REQUIRE_HUMAN", "RESTRICTED")
    assert "decision_id" in data
    print(f"  ✓ POST /api/vigil/agent-state — {data['outcome']} (VRS=0.91 > threshold)")


# ─── BLOC 9 — End-to-end REQUIRE_HUMAN flow ──────────────────────────────────

def test_full_require_human_flow():
    """
    Complete end-to-end flow:
    1. Create principal
    2. Authenticate via SSO
    3. Agent requests action → REQUIRE_HUMAN
    4. Decision appears in queue
    5. Principal approves
    6. Decision resolved with signature

    AI Act Art.14 / ANSSI R9 compliance: provable end-to-end.
    """
    f = get_fixture()

    # 1. Create L2 principal
    f.client.post("/api/principals", {
        "name": "e2e_approver", "email": "e2e@co.com",
        "clearance": "L2", "mode": "sso",
    })

    # 2. Authenticate
    auth_data, auth_status = f.client.post(
        "/api/principals/e2e_approver/authenticate",
        {"sso_claims": {"sub": "e2e-sso-sub"}}
    )
    assert auth_status == 200
    token_id = auth_data["token_id"]

    # 3. Agent requests action → REQUIRE_HUMAN
    eval_data, _ = f.client.post("/api/evaluate", {
        "agent_id":   "AISS-e2e-001",
        "agent_name": "e2e_agent",
        "role":       "operator",
        "action":     "write_db",
        "payload":    {"query": "UPDATE config SET value='new'"},
        "vrs":        0.72,
        "tsi_state":  "WATCH",
    })
    assert eval_data["outcome"] == "REQUIRE_HUMAN"
    assert eval_data["pending"] is True
    decision_id = eval_data["decision_id"]

    # 4. Verify in queue
    queue_data, _ = f.client.get("/api/decisions")
    pending_ids   = [d["decision_id"] for d in queue_data["decisions"]]
    assert decision_id in pending_ids

    # 5. Approve with token
    approve_data, approve_status = f.client.post(
        f"/api/decisions/{decision_id}/approve",
        {
            "principal_name": "e2e_approver",
            "token_id":       token_id,
            "justification":  "E2E test — verified safe",
        }
    )
    assert approve_status == 200
    assert approve_data["state"] == "APPROVED"
    assert approve_data["approved_by"]  is not None
    assert approve_data["justification"] == "E2E test — verified safe"

    # 6. Verify audit trail
    audit_data, _ = f.client.get("/api/audit?agent_id=AISS-e2e-001")
    assert audit_data["total"] >= 1

    print(
        "  ✓ FULL E2E REQUIRE_HUMAN FLOW — "
        "evaluate→queue→authenticate→approve→audit "
        "[ANSSI R9 / AI Act Art.14 ✅]"
    )


# ─── Runner ───────────────────────────────────────────────────────────────────

def run_all():
    tests = [
        # BLOC 1 — System
        ("GET /health", test_health),
        ("GET /api/status", test_status),
        ("404 on unknown route", test_404),

        # BLOC 2 — Policy
        ("GET /api/policy", test_get_policy),
        ("POST /api/policy/simulate — ALLOW", test_simulate_allow),
        ("POST /api/policy/simulate — BLOCK", test_simulate_block),

        # BLOC 3 — Evaluate
        ("POST /api/evaluate — ALLOW", test_evaluate_allow),
        ("POST /api/evaluate — BLOCK (VRS)", test_evaluate_block_vrs),
        ("POST /api/evaluate — BLOCK (pattern)", test_evaluate_block_pattern),
        ("POST /api/evaluate — REQUIRE_HUMAN", test_evaluate_require_human),
        ("POST /api/evaluate — 400 missing fields", test_evaluate_missing_fields),

        # BLOC 4 — Decisions
        ("GET /api/decisions", test_list_decisions),
        ("GET /api/decisions/<id>", test_get_decision_by_id),
        ("GET /api/decisions/<id> 404", test_get_decision_not_found),

        # BLOC 5 — Principals
        ("POST /api/principals", test_create_principal),
        ("GET /api/principals", test_list_principals),
        ("GET /api/principals/<n>", test_get_principal),
        ("GET /api/principals/<n> 404", test_get_principal_not_found),
        ("POST /api/principals/<n>/authenticate", test_authenticate_principal),

        # BLOC 6 — Approve / Reject
        ("Full approve flow", test_approve_flow),
        ("Full reject flow", test_reject_flow),
        ("Approve 403 — insufficient clearance (R30)", test_approve_insufficient_clearance),

        # BLOC 7 — Audit
        ("GET /api/audit", test_audit_list),
        ("GET /api/audit?agent_id= filter", test_audit_filter_by_agent),
        ("GET /api/audit/export", test_audit_export),

        # BLOC 8 — Vigil bridge
        ("POST /api/vigil/agent-state — MONITOR", test_vigil_bridge_below_threshold),
        ("POST /api/vigil/agent-state — BLOCK/REQUIRE_HUMAN", test_vigil_bridge_above_threshold),

        # BLOC 9 — Full E2E
        ("FULL E2E — REQUIRE_HUMAN flow (ANSSI R9 / AI Act Art.14)", test_full_require_human_flow),
    ]

    GREEN = "\033[92m"
    RED   = "\033[91m"
    BOLD  = "\033[1m"
    RESET = "\033[0m"
    DIM   = "\033[2m"

    print(f"\n{BOLD}Trust Gate — Sprint 3 Integration Tests{RESET}")
    print("=" * 60)

    # Start server once
    print("  Starting server...", end=" ", flush=True)
    get_fixture()
    print("ready\n")

    passed = 0
    failed = 0
    failures = []

    for name, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            import traceback
            failed += 1
            failures.append((name, str(e)))
            print(f"  {RED}✗ {name}{RESET}")
            print(f"    {DIM}{traceback.format_exc().splitlines()[-1]}{RESET}")

    print("\n" + "=" * 60)
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
        print(f"\n{GREEN}{BOLD}All tests passed — Sprint 3 validated ✅{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    run_all()
