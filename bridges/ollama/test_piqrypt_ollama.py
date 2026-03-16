"""
Tests for piqrypt-ollama bridge.
Run: pytest test_piqrypt_ollama.py -v
"""
import hashlib
import json
import time
import unittest
from unittest.mock import MagicMock, patch, call


# ── Mock piqrypt so tests work without the full package ───────────────────────
import sys
import types

def _setup_piqrypt_mock():
    """Install a minimal piqrypt mock into sys.modules."""
    events_store = []
    last_hash_store = [None]

    mock_aiss = types.ModuleType("piqrypt")
    mock_aiss.generate_keypair = lambda: (b"priv" * 8, b"pub" * 8)
    mock_aiss.derive_agent_id  = lambda pub: "AGENT_" + hashlib.sha256(pub).hexdigest()[:12]
    mock_aiss.load_identity    = lambda f: {"private_key_bytes": b"key" * 8, "agent_id": "AGENT_TEST"}
    mock_aiss.stamp_event      = lambda key, aid, payload: {
        **payload,
        "_pq_agent_id": aid,
        "_pq_timestamp": time.time(),
        "_pq_sig": "mocksig",
    }
    mock_aiss.store_event      = lambda e: events_store.append(e)
    mock_aiss.compute_event_hash = lambda e: hashlib.sha256(json.dumps(e, default=str).encode()).hexdigest()
    mock_aiss.export_audit_chain = lambda path: open(path, "w").write(json.dumps(events_store))
    mock_aiss._events_store    = events_store
    sys.modules["piqrypt"] = mock_aiss
    return mock_aiss, events_store

_mock_aiss, _events = _setup_piqrypt_mock()

# ── Mock ollama ───────────────────────────────────────────────────────────────
def _setup_ollama_mock():
    mock_ollama = types.ModuleType("ollama")

    class MockClient:
        def __init__(self, host=None): pass
        def generate(self, **kwargs):
            if kwargs.get("stream"):
                return iter([
                    {"response": "Hello ", "done": False},
                    {"response": "world!", "done": True},
                ])
            return {"response": "Paris", "done": True, "eval_count": 5, "prompt_eval_count": 10}

        def chat(self, **kwargs):
            if kwargs.get("stream"):
                return iter([
                    {"message": {"role": "assistant", "content": "Hi "}, "done": False},
                    {"message": {"role": "assistant", "content": "there!"}, "done": True},
                ])
            tool_calls = []
            messages = kwargs.get("messages", [])
            last = messages[-1].get("content", "") if messages else ""
            if "weather" in last.lower() and kwargs.get("tools"):
                tool_calls = [{"function": {"name": "get_weather", "arguments": {"city": "Paris"}}}]
            return {
                "message": {"role": "assistant", "content": "Hello!", "tool_calls": tool_calls},
                "done": True,
            }

    mock_ollama.Client = MockClient
    sys.modules["ollama"] = mock_ollama
    return mock_ollama

_setup_ollama_mock()

# ── Now import the bridge ─────────────────────────────────────────────────────
from piqrypt_ollama import AuditedOllama, stamp_ollama, export_audit


class TestAuditedOllama(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.llm = AuditedOllama(
            model="llama3.2",
            agent_name="test_agent",
            tier="free",
        )
        # Clear init event for clean test counting
        _events.clear()

    # ── Identity ──────────────────────────────────────────────────────────────
    def test_ephemeral_identity_created(self):
        llm = AuditedOllama(model="llama3.2")
        self.assertTrue(llm.piqrypt_id.startswith("AGENT_"))

    def test_identity_from_file(self):
        with patch("piqrypt_ollama.aiss.load_identity", return_value={"private_key_bytes": b"k"*32, "agent_id": "AGENT_FILE"}):
            llm = AuditedOllama(model="llama3.2", identity_file="fake.json")
        self.assertEqual(llm.piqrypt_id, "AGENT_FILE")

    # ── generate() ────────────────────────────────────────────────────────────
    def test_generate_stamps_start_and_complete(self):
        _events.clear()
        self.llm.generate("What is 2+2?")
        event_types = [e["event_type"] for e in _events]
        self.assertIn("ollama_generate_start",    event_types)
        self.assertIn("ollama_generate_complete", event_types)

    def test_generate_stamps_prompt_hash(self):
        _events.clear()
        self.llm.generate("Hello world")
        start_events = [e for e in _events if e["event_type"] == "ollama_generate_start"]
        self.assertEqual(len(start_events), 1)
        self.assertIn("prompt_hash", start_events[0])
        expected = hashlib.sha256("Hello world".encode()).hexdigest()
        self.assertEqual(start_events[0]["prompt_hash"], expected)

    def test_generate_stamps_response_hash(self):
        _events.clear()
        self.llm.generate("Capital of France?")
        complete_events = [e for e in _events if e["event_type"] == "ollama_generate_complete"]
        self.assertEqual(len(complete_events), 1)
        self.assertIn("response_hash", complete_events[0])

    def test_generate_no_prompt_stamping(self):
        llm = AuditedOllama(model="llama3.2", stamp_prompts=False)
        _events.clear()
        llm.generate("Secret prompt")
        start_events = [e for e in _events if e["event_type"] == "ollama_generate_start"]
        self.assertNotIn("prompt_hash", start_events[0])

    def test_generate_returns_response(self):
        result = self.llm.generate("What is Paris?")
        self.assertIn("response", result)
        self.assertEqual(result["response"], "Paris")

    # ── generate streaming ─────────────────────────────────────────────────────
    def test_generate_stream_yields_chunks(self):
        _events.clear()
        chunks = list(self.llm.generate("Tell me a story", stream=True))
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0]["response"], "Hello ")
        self.assertEqual(chunks[1]["response"], "world!")

    def test_generate_stream_stamps_complete(self):
        _events.clear()
        list(self.llm.generate("Tell me a story", stream=True))
        event_types = [e["event_type"] for e in _events]
        self.assertIn("ollama_generate_start",           event_types)
        self.assertIn("ollama_generate_stream_complete", event_types)

    def test_generate_stream_stamps_full_response_hash(self):
        _events.clear()
        list(self.llm.generate("Tell me a story", stream=True))
        complete = [e for e in _events if "stream_complete" in e.get("event_type","")]
        self.assertEqual(len(complete), 1)
        expected = hashlib.sha256("Hello world!".encode()).hexdigest()
        self.assertEqual(complete[0]["response_hash"], expected)

    # ── chat() ────────────────────────────────────────────────────────────────
    def test_chat_stamps_start_and_complete(self):
        _events.clear()
        self.llm.chat([{"role": "user", "content": "Hi"}])
        event_types = [e["event_type"] for e in _events]
        self.assertIn("ollama_chat_start",    event_types)
        self.assertIn("ollama_chat_complete", event_types)

    def test_chat_stamps_message_count(self):
        _events.clear()
        messages = [
            {"role": "system", "content": "Be helpful"},
            {"role": "user",   "content": "Hello"},
        ]
        self.llm.chat(messages)
        start = [e for e in _events if e["event_type"] == "ollama_chat_start"][0]
        self.assertEqual(start["message_count"], 2)

    def test_chat_stream(self):
        _events.clear()
        chunks = list(self.llm.chat([{"role": "user", "content": "Hi"}], stream=True))
        self.assertEqual(len(chunks), 2)
        event_types = [e["event_type"] for e in _events]
        self.assertIn("ollama_chat_stream_complete", event_types)

    # ── hash chaining ─────────────────────────────────────────────────────────
    def test_chain_previous_event_hash(self):
        _events.clear()
        self.llm.generate("First call")
        self.llm.generate("Second call")
        # Events after first generate should have previous_event_hash
        second_start = [e for e in _events if e["event_type"] == "ollama_generate_start"][1]
        self.assertIn("previous_event_hash", second_start)

    def test_last_event_hash_updated(self):
        initial_hash = self.llm.last_event_hash
        self.llm.generate("Test")
        self.assertNotEqual(self.llm.last_event_hash, initial_hash)

    # ── tool use ──────────────────────────────────────────────────────────────
    def test_tool_call_stamped(self):
        _events.clear()
        tools = [{"type": "function", "function": {"name": "get_weather", "description": "Get weather", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}}]
        dispatcher = lambda name, args: f"Sunny in {args.get('city','?')}"
        self.llm.chat_with_tools(
            messages=[{"role": "user", "content": "weather in paris"}],
            tools=tools,
            tool_dispatcher=dispatcher,
        )
        event_types = [e["event_type"] for e in _events]
        self.assertIn("ollama_tool_call",   event_types)
        self.assertIn("ollama_tool_result", event_types)

    def test_tool_call_stamps_tool_name(self):
        _events.clear()
        tools = [{"type": "function", "function": {"name": "get_weather", "description": "Get weather", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}}]
        self.llm.chat_with_tools(
            messages=[{"role": "user", "content": "weather in paris"}],
            tools=tools,
            tool_dispatcher=lambda n, a: "Sunny",
        )
        tool_events = [e for e in _events if e["event_type"] == "ollama_tool_call"]
        self.assertTrue(len(tool_events) > 0)
        self.assertEqual(tool_events[0]["tool_name"], "get_weather")

    # ── custom stamp ──────────────────────────────────────────────────────────
    def test_stamp_event_custom(self):
        _events.clear()
        self.llm.stamp_event("custom_action", {"detail": "test"})
        self.assertEqual(len(_events), 1)
        self.assertEqual(_events[0]["event_type"], "custom_action")
        self.assertEqual(_events[0]["detail"], "test")

    # ── export ────────────────────────────────────────────────────────────────
    def test_export_audit(self):
        import tempfile, os
        self.llm.generate("Test")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            self.llm.export_audit(path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)

    # ── repr ──────────────────────────────────────────────────────────────────
    def test_repr(self):
        r = repr(self.llm)
        self.assertIn("AuditedOllama", r)
        self.assertIn("llama3.2", r)
        self.assertIn("test_agent", r)


class TestStampOllamaDecorator(unittest.TestCase):

    def setUp(self):
        _events.clear()

    def test_decorator_stamps_start_and_complete(self):
        @stamp_ollama("test_task")
        def my_func(x):
            return x * 2

        result = my_func(21)
        self.assertEqual(result, 42)
        event_types = [e["event_type"] for e in _events]
        self.assertIn("test_task_start",    event_types)
        self.assertIn("test_task_complete", event_types)

    def test_decorator_stamps_result_hash(self):
        @stamp_ollama("compute")
        def compute(x):
            return f"result_{x}"

        compute(7)
        complete = [e for e in _events if e["event_type"] == "compute_complete"][0]
        expected = hashlib.sha256("result_7".encode()).hexdigest()
        self.assertEqual(complete["result_hash"], expected)

    def test_decorator_preserves_function_name(self):
        @stamp_ollama("wrap_test")
        def original_function():
            return "ok"
        self.assertEqual(original_function.__name__, "original_function")


class TestTopLevelExport(unittest.TestCase):

    def test_export_audit_top_level(self):
        import tempfile, os
        _events.clear()
        _events.append({"event_type": "test", "data": "value"})
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            result = export_audit(path)
            self.assertEqual(result, path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
