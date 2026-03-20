"""
Tests — bridges/langchain/__init__.py
Bridge PiQryptCallbackHandler + AuditedAgentExecutor

Run: pytest test_piqrypt_langchain.py -v
"""
import hashlib
import json
import sys
import time
import types
import unittest
from unittest.mock import MagicMock, patch


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


# ── Mock LangChain ────────────────────────────────────────────────────────────

def _setup_langchain_mock():
    lc = types.ModuleType("langchain")
    agents = types.ModuleType("langchain.agents")
    tools_mod = types.ModuleType("langchain.tools")
    callbacks = types.ModuleType("langchain.callbacks.base")
    schema = types.ModuleType("langchain.schema")

    class BaseCallbackHandler:
        def on_llm_start(self, *a, **kw): pass
        def on_llm_end(self, *a, **kw): pass
        def on_llm_error(self, *a, **kw): pass
        def on_chain_start(self, *a, **kw): pass
        def on_chain_end(self, *a, **kw): pass
        def on_chain_error(self, *a, **kw): pass
        def on_tool_start(self, *a, **kw): pass
        def on_tool_end(self, *a, **kw): pass
        def on_tool_error(self, *a, **kw): pass
        def on_agent_action(self, *a, **kw): pass
        def on_agent_finish(self, *a, **kw): pass

    class AgentExecutor:
        def __init__(self, **kwargs): self.callbacks = kwargs.get("callbacks", [])
        def invoke(self, input, **kw): return {"output": "mock result"}
        def run(self, input, **kw): return "mock result"

    class BaseTool:
        name = "mock_tool"
        description = "mock"
        def _run(self, *a, **kw): return "tool result"
        def run(self, *a, **kw): return "tool result"

    class LLMResult:
        def __init__(self, generations=None):
            self.generations = generations or [[MagicMock(text="mock response")]]

    callbacks.BaseCallbackHandler = BaseCallbackHandler
    agents.AgentExecutor = AgentExecutor
    tools_mod.BaseTool = BaseTool
    schema.LLMResult = LLMResult

    sys.modules["langchain"] = lc
    sys.modules["langchain.agents"] = agents
    sys.modules["langchain.tools"] = tools_mod
    sys.modules["langchain.callbacks"] = types.ModuleType("langchain.callbacks")
    sys.modules["langchain.callbacks.base"] = callbacks
    sys.modules["langchain.schema"] = schema

    return BaseCallbackHandler, AgentExecutor, BaseTool, LLMResult

BaseCallbackHandler, AgentExecutor, BaseTool, LLMResult = _setup_langchain_mock()

# Import bridge
from piqrypt_langchain import PiQryptCallbackHandler, AuditedAgentExecutor, piqrypt_tool, stamp_chain, export_audit  # noqa: E402


# ══════════════════════════════════════════════════════════════════════════════
# Tests PiQryptCallbackHandler
# ══════════════════════════════════════════════════════════════════════════════

class TestPiQryptCallbackHandler(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.handler = PiQryptCallbackHandler(agent_name="test_agent")

    # ── Identité ──────────────────────────────────────────────────────────────

    def test_ephemeral_identity_created(self):
        h = PiQryptCallbackHandler()
        self.assertTrue(h.piqrypt_id.startswith("AGENT_"))

    def test_identity_from_file(self):
        with patch("piqrypt_langchain.aiss.load_identity",
                   return_value={"private_key_bytes": b"k"*32, "agent_id": "AGENT_FILE"}):
            h = PiQryptCallbackHandler(identity_file="fake.json")
        self.assertEqual(h.piqrypt_id, "AGENT_FILE")

    # ── LLM events ────────────────────────────────────────────────────────────

    def test_on_llm_start_stamps_event(self):
        _events.clear()
        self.handler.on_llm_start({"name": "gpt-4"}, ["What is 2+2?"])
        self.assertTrue(len(_events) >= 1)
        types_ = [e["event_type"] for e in _events]
        self.assertTrue(any("llm" in t for t in types_))

    def test_on_llm_start_hashes_prompt(self):
        _events.clear()
        prompt = "What is the capital of France?"
        self.handler.on_llm_start({"name": "gpt-4"}, [prompt])
        start_events = [e for e in _events if "llm" in e.get("event_type", "")]
        self.assertTrue(len(start_events) >= 1)
        # Prompt doit être hashé, jamais stocké brut
        for e in start_events:
            self.assertNotIn(prompt, str(e))

    def test_on_llm_end_stamps_event(self):
        _events.clear()
        result = LLMResult()
        self.handler.on_llm_end(result)
        self.assertTrue(len(_events) >= 1)

    def test_on_llm_error_stamps_event(self):
        _events.clear()
        self.handler.on_llm_error(Exception("API timeout"))
        error_events = [e for e in _events if "error" in e.get("event_type", "").lower()]
        self.assertTrue(len(error_events) >= 1)

    # ── Tool events ───────────────────────────────────────────────────────────

    def test_on_tool_start_stamps_event(self):
        _events.clear()
        self.handler.on_tool_start({"name": "search"}, "query: Paris")
        tool_events = [e for e in _events if "tool" in e.get("event_type", "")]
        self.assertTrue(len(tool_events) >= 1)

    def test_on_tool_end_stamps_event(self):
        _events.clear()
        self.handler.on_tool_end("Paris is the capital of France")
        self.assertTrue(len(_events) >= 1)

    def test_on_tool_error_stamps_event(self):
        _events.clear()
        self.handler.on_tool_error(Exception("Tool failed"))
        error_events = [e for e in _events if "error" in e.get("event_type", "").lower()]
        self.assertTrue(len(error_events) >= 1)

    # ── Chain events ──────────────────────────────────────────────────────────

    def test_on_chain_start_stamps_event(self):
        _events.clear()
        self.handler.on_chain_start({"name": "LLMChain"}, {"input": "hello"})
        self.assertTrue(len(_events) >= 1)

    def test_on_chain_end_stamps_event(self):
        _events.clear()
        self.handler.on_chain_end({"output": "result"})
        self.assertTrue(len(_events) >= 1)

    # ── Agent events ──────────────────────────────────────────────────────────

    def test_on_agent_finish_stamps_event(self):
        _events.clear()
        finish = MagicMock()
        finish.return_values = {"output": "Done"}
        self.handler.on_agent_finish(finish)
        self.assertTrue(len(_events) >= 1)

    # ── Hash chaining ─────────────────────────────────────────────────────────

    def test_last_event_hash_updated_after_event(self):
        initial = self.handler.last_event_hash
        self.handler.on_llm_start({"name": "gpt-4"}, ["test"])
        self.assertNotEqual(self.handler.last_event_hash, initial)

    def test_sequential_events_chained(self):
        _events.clear()
        self.handler.on_llm_start({"name": "gpt-4"}, ["first"])
        self.handler.on_llm_end(LLMResult())
        self.assertTrue(len(_events) >= 2)
        # Le deuxième event doit référencer le hash du premier
        if len(_events) >= 2:
            self.assertIn("previous_event_hash", _events[1])

    # ── Privacy ───────────────────────────────────────────────────────────────

    def test_raw_prompts_never_stored(self):
        _events.clear()
        secret = "my_secret_password_123"
        self.handler.on_llm_start({"name": "gpt-4"}, [secret])
        for e in _events:
            self.assertNotIn(secret, json.dumps(e))

    def test_raw_responses_never_stored(self):
        _events.clear()
        secret_response = "confidential_data_xyz"
        result = LLMResult(generations=[[MagicMock(text=secret_response)]])
        self.handler.on_llm_end(result)
        for e in _events:
            self.assertNotIn(secret_response, json.dumps(e))

    # ── Export ────────────────────────────────────────────────────────────────

    def test_export_audit(self):
        import tempfile
        import os
        self.handler.on_llm_start({"name": "gpt-4"}, ["test"])
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            self.handler.export_audit(path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)

    def test_event_count_increments(self):
        initial = self.handler.audit_event_count
        self.handler.on_llm_start({"name": "gpt-4"}, ["test"])
        self.assertGreater(self.handler.audit_event_count, initial)


# ══════════════════════════════════════════════════════════════════════════════
# Tests AuditedAgentExecutor
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditedAgentExecutor(unittest.TestCase):

    def setUp(self):
        _events.clear()
        base = AgentExecutor(agent=MagicMock(), tools=[])
        self.executor = AuditedAgentExecutor(
            executor=base,
            agent_name="executor_test",
        )

    def test_piqrypt_id_set(self):
        self.assertTrue(self.executor.piqrypt_id.startswith("AGENT_"))

    def test_invoke_stamps_events(self):
        _events.clear()
        self.executor.invoke({"input": "What is AI?"})
        self.assertTrue(len(_events) >= 1)

    def test_invoke_returns_result(self):
        result = self.executor.invoke({"input": "test"})
        self.assertIsNotNone(result)

    def test_run_stamps_events(self):
        _events.clear()
        self.executor.run("What is AI?")
        self.assertTrue(len(_events) >= 1)


# ══════════════════════════════════════════════════════════════════════════════
# Tests décorateurs
# ══════════════════════════════════════════════════════════════════════════════

class TestPiqryptTool(unittest.TestCase):

    def setUp(self):
        _events.clear()

    def test_piqrypt_tool_stamps_call(self):
        @piqrypt_tool("search", agent_name="test")
        def search(query: str) -> str:
            return f"Results for {query}"

        result = search("Paris")
        self.assertEqual(result, "Results for Paris")
        self.assertTrue(len(_events) >= 1)

    def test_piqrypt_tool_stamps_result_hash(self):
        @piqrypt_tool("compute", agent_name="test")
        def compute(x: int) -> int:
            return x * 2

        compute(21)
        complete_events = [e for e in _events if "complete" in e.get("event_type", "")]
        self.assertTrue(len(complete_events) >= 1)
        self.assertIn("result_hash", complete_events[0])

    def test_piqrypt_tool_preserves_return(self):
        @piqrypt_tool("my_tool", agent_name="test")
        def my_tool(x):
            return {"answer": x * 3}

        result = my_tool(7)
        self.assertEqual(result, {"answer": 21})

    def test_piqrypt_tool_stamps_error(self):
        @piqrypt_tool("failing_tool", agent_name="test")
        def failing_tool():
            raise ValueError("Tool exploded")

        with self.assertRaises(ValueError):
            failing_tool()
        error_events = [e for e in _events if "error" in e.get("event_type", "").lower()]
        self.assertTrue(len(error_events) >= 1)


class TestStampChain(unittest.TestCase):

    def setUp(self):
        _events.clear()

    def test_stamp_chain_stamps_start_end(self):
        @stamp_chain("my_chain", agent_name="test")
        def my_chain(x):
            return x + 1

        result = my_chain(41)
        self.assertEqual(result, 42)
        event_types = [e["event_type"] for e in _events]
        self.assertTrue(any("start" in t for t in event_types))
        self.assertTrue(any("complete" in t or "end" in t for t in event_types))

    def test_stamp_chain_preserves_name(self):
        @stamp_chain("wrap_test", agent_name="test")
        def original():
            return "ok"
        self.assertEqual(original.__name__, "original")


# ══════════════════════════════════════════════════════════════════════════════
# Tests export top-level
# ══════════════════════════════════════════════════════════════════════════════

class TestExportAudit(unittest.TestCase):

    def test_export_audit_creates_file(self):
        import tempfile
        import os
        _events.clear()
        _events.append({"event_type": "test", "data": "value"})
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            _ = export_audit(path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
