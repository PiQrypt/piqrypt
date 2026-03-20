"""
Tests — bridges/openclaw/__init__.py
Bridge AuditableOpenClaw

Run: pytest test_piqrypt_openclaw.py -v
"""
import hashlib
import json
import sys
import time
import types
import unittest
from unittest.mock import patch


# ── Mock piqrypt ──────────────────────────────────────────────────────────────

def _setup_piqrypt_mock():
    events = []
    mock = types.ModuleType("piqrypt")
    mock.generate_keypair     = lambda: (b"priv" * 8, b"pub" * 8)
    mock.derive_agent_id      = lambda pub: "AGENT_" + hashlib.sha256(pub).hexdigest()[:12]
    mock.load_identity        = lambda f: {"private_key_bytes": b"key" * 8, "agent_id": "AGENT_TEST"}
    mock.stamp_event          = lambda key, aid, payload: {
        **payload,
        "_pq_agent_id": aid,
        "_pq_timestamp": time.time(),
        "_pq_sig": "mocksig",
    }
    mock.store_event          = lambda e: events.append(e)
    mock.compute_event_hash   = lambda e: hashlib.sha256(json.dumps(e, default=str).encode()).hexdigest()
    mock.export_audit_chain   = lambda path: open(path, "w").write(json.dumps(events))
    mock._events              = events
    sys.modules["piqrypt"] = mock
    return mock, events

_mock_piqrypt, _events = _setup_piqrypt_mock()


# ── Mock OpenClaw ─────────────────────────────────────────────────────────────

def _setup_openclaw_mock():
    openclaw_mod = types.ModuleType("openclaw")

    class ExecutionResult:
        def __init__(self, stdout="ok", stderr="", returncode=0):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = returncode

    class OpenClaw:
        def __init__(self, **kwargs):
            self.config = kwargs

        def execute(self, language: str, code: str, **kwargs) -> ExecutionResult:
            if "raise" in code:
                raise RuntimeError(f"Execution failed: {code}")
            return ExecutionResult(
                stdout=f"[{language}] {code[:30]}... executed",
                returncode=0,
            )

        def run_tool(self, tool_name: str, **kwargs) -> dict:
            return {"tool": tool_name, "result": "mock_result", "success": True}

    openclaw_mod.OpenClaw = OpenClaw
    openclaw_mod.ExecutionResult = ExecutionResult
    sys.modules["openclaw"] = openclaw_mod
    return OpenClaw, ExecutionResult

MockOpenClaw, MockExecutionResult = _setup_openclaw_mock()

# Import bridge
from piqrypt_openclaw import AuditableOpenClaw, stamp_action, export_audit


# ══════════════════════════════════════════════════════════════════════════════
# Tests AuditableOpenClaw — identité
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditableOpenClawIdentity(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.claw = AuditableOpenClaw(agent_name="executor")

    def test_piqrypt_id_generated(self):
        self.assertTrue(self.claw.piqrypt_id.startswith("AGENT_"))

    def test_identity_from_file(self):
        with patch("piqrypt_openclaw.aiss.load_identity",
                   return_value={"private_key_bytes": b"k"*32, "agent_id": "AGENT_FILE"}):
            claw = AuditableOpenClaw(identity_file="fake.json")
        self.assertEqual(claw.piqrypt_id, "AGENT_FILE")

    def test_ephemeral_identity(self):
        claw = AuditableOpenClaw()
        self.assertTrue(claw.piqrypt_id.startswith("AGENT_"))


# ══════════════════════════════════════════════════════════════════════════════
# Tests execute_task()
# ══════════════════════════════════════════════════════════════════════════════

class TestExecuteTask(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.claw = AuditableOpenClaw(agent_name="executor")

    def test_execute_stamps_start(self):
        _events.clear()
        self.claw.execute_task("python", "print('hello')")
        start_events = [e for e in _events if "start" in e.get("event_type", "").lower()]
        self.assertTrue(len(start_events) >= 1)

    def test_execute_stamps_complete(self):
        _events.clear()
        self.claw.execute_task("python", "print('hello')")
        complete_events = [e for e in _events if
                           "complete" in e.get("event_type", "").lower() or
                           "end" in e.get("event_type", "").lower()]
        self.assertTrue(len(complete_events) >= 1)

    def test_execute_stamps_code_hash(self):
        _events.clear()
        secret_code = "password = 'supersecret123'"
        self.claw.execute_task("python", secret_code)
        # Code must never be stored raw
        for e in _events:
            self.assertNotIn("supersecret123", json.dumps(e))
        # But code_hash must be present
        code_hash_events = [e for e in _events if "code_hash" in e]
        self.assertTrue(len(code_hash_events) >= 1)
        expected_hash = hashlib.sha256(secret_code.encode()).hexdigest()
        self.assertEqual(code_hash_events[0]["code_hash"], expected_hash)

    def test_execute_stamps_result_hash(self):
        _events.clear()
        self.claw.execute_task("python", "x = 42")
        complete_events = [e for e in _events if "result_hash" in e]
        self.assertTrue(len(complete_events) >= 1)

    def test_execute_stamps_language(self):
        _events.clear()
        self.claw.execute_task("bash", "ls -la")
        events_with_lang = [e for e in _events if "language" in e or "lang" in e]
        if events_with_lang:
            lang = events_with_lang[0].get("language") or events_with_lang[0].get("lang")
            self.assertEqual(lang, "bash")

    def test_execute_different_languages(self):
        for lang in ["python", "bash", "node", "ruby"]:
            _events.clear()
            self.claw.execute_task(lang, f"echo {lang}")
            self.assertTrue(len(_events) >= 1)

    def test_execute_returns_result(self):
        result = self.claw.execute_task("python", "print('test')")
        self.assertIsNotNone(result)

    def test_execute_error_stamped(self):
        _events.clear()
        # Code that triggers an error in our mock
        try:
            self.claw.execute_task("python", "raise RuntimeError")
        except Exception:
            pass
        error_events = [e for e in _events if "error" in e.get("event_type", "").lower()]
        self.assertTrue(len(error_events) >= 1)

    def test_execute_error_stamps_code_hash_not_content(self):
        _events.clear()
        evil_code = "raise RuntimeError  # CONFIDENTIAL"
        try:
            self.claw.execute_task("python", evil_code)
        except Exception:
            pass
        for e in _events:
            self.assertNotIn("CONFIDENTIAL", json.dumps(e))


# ══════════════════════════════════════════════════════════════════════════════
# Tests stamp_reasoning()
# ══════════════════════════════════════════════════════════════════════════════

class TestStampReasoning(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.claw = AuditableOpenClaw(agent_name="executor")

    def test_stamp_reasoning_creates_event(self):
        self.claw.stamp_reasoning("I need to analyse this data before executing")
        self.assertTrue(len(_events) >= 1)

    def test_stamp_reasoning_hashes_content(self):
        _events.clear()
        reasoning = "My secret decision process: step 1, step 2"
        self.claw.stamp_reasoning(reasoning)
        for e in _events:
            self.assertNotIn("secret decision", json.dumps(e))

    def test_stamp_reasoning_event_type(self):
        _events.clear()
        self.claw.stamp_reasoning("Because X, I will do Y")
        reasoning_events = [e for e in _events if "reason" in e.get("event_type", "").lower()]
        self.assertTrue(len(reasoning_events) >= 1)


# ══════════════════════════════════════════════════════════════════════════════
# Tests stamp_tool_call()
# ══════════════════════════════════════════════════════════════════════════════

class TestStampToolCall(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.claw = AuditableOpenClaw(agent_name="executor")

    def test_stamp_tool_call_creates_event(self):
        self.claw.stamp_tool_call("web_search", {"query": "AAPL"}, "result: AAPL $195")
        self.assertTrue(len(_events) >= 1)

    def test_stamp_tool_call_stamps_tool_name(self):
        _events.clear()
        self.claw.stamp_tool_call("calculator", {"expr": "2+2"}, "4")
        tool_events = [e for e in _events if "tool" in e.get("event_type", "").lower()]
        self.assertTrue(len(tool_events) >= 1)
        self.assertIn("calculator", json.dumps(tool_events[0]))

    def test_stamp_tool_call_hashes_args_and_result(self):
        _events.clear()
        secret_args = {"api_key": "sk-supersecret"}
        secret_result = "classified_data_xyz"
        self.claw.stamp_tool_call("api_call", secret_args, secret_result)
        for e in _events:
            self.assertNotIn("supersecret", json.dumps(e))
            self.assertNotIn("classified_data", json.dumps(e))


# ══════════════════════════════════════════════════════════════════════════════
# Tests get_suspicious_events()
# ══════════════════════════════════════════════════════════════════════════════

class TestGetSuspiciousEvents(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.claw = AuditableOpenClaw(agent_name="executor")

    def test_suspicious_events_returns_list(self):
        self.claw.execute_task("python", "x = 1")
        result = self.claw.get_suspicious_events()
        self.assertIsInstance(result, list)

    def test_error_events_may_be_suspicious(self):
        try:
            self.claw.execute_task("python", "raise RuntimeError")
        except Exception:
            pass
        # get_suspicious_events should work without crashing
        result = self.claw.get_suspicious_events()
        self.assertIsInstance(result, list)


# ══════════════════════════════════════════════════════════════════════════════
# Tests hash chaining
# ══════════════════════════════════════════════════════════════════════════════

class TestHashChaining(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.claw = AuditableOpenClaw(agent_name="executor")

    def test_last_event_hash_updated(self):
        initial = self.claw.last_event_hash
        self.claw.execute_task("python", "x = 1")
        self.assertNotEqual(self.claw.last_event_hash, initial)

    def test_sequential_executions_chained(self):
        _events.clear()
        self.claw.execute_task("python", "x = 1")
        count_after_first = len(_events)
        self.claw.execute_task("python", "y = 2")
        second_batch = _events[count_after_first:]
        if second_batch:
            self.assertIn("previous_event_hash", second_batch[0])

    def test_event_count_increments(self):
        initial = self.claw.audit_event_count
        self.claw.execute_task("python", "z = 3")
        self.assertGreater(self.claw.audit_event_count, initial)


# ══════════════════════════════════════════════════════════════════════════════
# Tests @stamp_action décorateur
# ══════════════════════════════════════════════════════════════════════════════

class TestStampAction(unittest.TestCase):

    def setUp(self):
        _events.clear()

    def test_stamp_action_stamps_start_end(self):
        @stamp_action("data_processing", agent_name="test")
        def process(data: str) -> str:
            return f"Processed: {data}"

        result = process("input_data")
        self.assertEqual(result, "Processed: input_data")
        event_types = [e["event_type"] for e in _events]
        self.assertTrue(any("start" in t for t in event_types))
        self.assertTrue(any("complete" in t or "end" in t for t in event_types))

    def test_stamp_action_stamps_result_hash(self):
        @stamp_action("compute", agent_name="test")
        def compute(x: int) -> int:
            return x * 2

        compute(21)
        complete = [e for e in _events if "complete" in e.get("event_type", "").lower()
                    or "end" in e.get("event_type", "").lower()]
        if complete:
            self.assertIn("result_hash", complete[0])

    def test_stamp_action_preserves_return(self):
        @stamp_action("identity", agent_name="test")
        def identity(x):
            return {"value": x * 3}

        self.assertEqual(identity(7), {"value": 21})

    def test_stamp_action_stamps_error(self):
        @stamp_action("failing", agent_name="test")
        def failing():
            raise ValueError("Tool failed")

        with self.assertRaises(ValueError):
            failing()
        error_events = [e for e in _events if "error" in e.get("event_type", "").lower()]
        self.assertTrue(len(error_events) >= 1)

    def test_stamp_action_preserves_function_name(self):
        @stamp_action("wrap", agent_name="test")
        def my_function():
            return "ok"
        self.assertEqual(my_function.__name__, "my_function")

    def test_stamp_action_raw_input_not_stored(self):
        @stamp_action("secret_op", agent_name="test")
        def secret_op(data: str) -> str:
            return data.upper()

        secret_op("confidential_data_xyz")
        for e in _events:
            self.assertNotIn("confidential_data_xyz", json.dumps(e))


# ══════════════════════════════════════════════════════════════════════════════
# Tests export
# ══════════════════════════════════════════════════════════════════════════════

class TestExport(unittest.TestCase):

    def test_export_audit_instance(self):
        import tempfile
        import os
        claw = AuditableOpenClaw(agent_name="test")
        _events.clear()
        claw.execute_task("python", "x = 1")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            claw.export_audit(path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)

    def test_export_audit_top_level(self):
        import tempfile
        import os
        _events.clear()
        _events.append({"event_type": "execution_complete", "result_hash": "abc"})
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_audit(path)
            self.assertTrue(os.path.exists(path))
            data = json.loads(open(path).read())
            self.assertIsInstance(data, list)
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Test cross-framework : OpenClaw + CrewAI
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossFrameworkScenario(unittest.TestCase):
    """
    CrewAI génère un script → OpenClaw l'exécute.
    Le payload_hash du script doit être identique dans les deux mémoires.
    """

    def test_script_hash_preserved_across_frameworks(self):
        _events.clear()
        claw = AuditableOpenClaw(agent_name="openclaw_executor")

        # Simuler la réception d'un script produit par CrewAI
        script = "import pandas as pd\ndf = pd.read_csv('data.csv')\nprint(df.describe())"
        payload_hash = hashlib.sha256(script.encode()).hexdigest()

        # OpenClaw estampe la réception
        claw._stamp("script_received", {
            "payload_hash": payload_hash,
            "peer": "crewai_analyst",
            "language": "python",
        })

        # Exécution
        claw.execute_task("python", script)

        # Vérifier que le payload_hash est dans la mémoire OpenClaw
        hashes = [e.get("payload_hash") for e in _events if "payload_hash" in e]
        self.assertIn(payload_hash, hashes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
