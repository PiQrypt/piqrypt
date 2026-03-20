"""
Tests — bridges/mcp/__init__.py
Bridge AuditedMCPClient

Run: pytest test_piqrypt_mcp.py -v
"""
import hashlib
import json
import sys
import time
import types
import unittest
from unittest.mock import patch
import asyncio


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

# Import bridge
from piqrypt_mcp import AuditedMCPClient, export_audit


# ── Helper async runner ───────────────────────────────────────────────────────

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Concrete testable subclass ────────────────────────────────────────────────

class MockMCPClient(AuditedMCPClient):
    """Subclass with real implementations of the abstract async methods."""

    async def _do_call_tool(self, tool_name, arguments):
        if tool_name == "fail_tool":
            raise RuntimeError("Tool unavailable")
        return {"tool": tool_name, "result": f"mock_result_for_{tool_name}", "args": arguments}

    async def _do_read_resource(self, uri):
        if uri == "file:///not_found":
            raise FileNotFoundError("Resource not found")
        return f"Content of {uri}"

    async def _do_get_prompt(self, name, arguments):
        return [
            {"role": "system", "content": f"You are a {name} assistant"},
            {"role": "user", "content": str(arguments)},
        ]


# ══════════════════════════════════════════════════════════════════════════════
# Tests — identité
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditedMCPClientIdentity(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.client = MockMCPClient(agent_name="mcp_agent")

    def test_piqrypt_id_generated(self):
        self.assertTrue(self.client.piqrypt_id.startswith("AGENT_"))

    def test_identity_from_file(self):
        with patch("piqrypt_mcp.aiss.load_identity",
                   return_value={"private_key_bytes": b"k"*32, "agent_id": "AGENT_FILE"}):
            client = MockMCPClient(identity_file="fake.json")
        self.assertEqual(client.piqrypt_id, "AGENT_FILE")

    def test_ephemeral_identity(self):
        client = MockMCPClient()
        self.assertTrue(client.piqrypt_id.startswith("AGENT_"))

    def test_two_clients_have_different_ids(self):
        c1 = MockMCPClient(agent_name="agent_1")
        c2 = MockMCPClient(agent_name="agent_2")
        self.assertNotEqual(c1.piqrypt_id, c2.piqrypt_id)


# ══════════════════════════════════════════════════════════════════════════════
# Tests — context manager (session)
# ══════════════════════════════════════════════════════════════════════════════

class TestMCPSessionLifecycle(unittest.TestCase):

    def setUp(self):
        _events.clear()

    def test_aenter_stamps_session_start(self):
        async def _test():
            client = MockMCPClient(agent_name="test")
            _events.clear()
            await client.__aenter__()
            start_events = [e for e in _events if "session" in e.get("event_type", "").lower()
                            and "start" in e.get("event_type", "").lower()]
            self.assertTrue(len(start_events) >= 1)
        run(_test())

    def test_aexit_stamps_session_end(self):
        async def _test():
            client = MockMCPClient(agent_name="test")
            await client.__aenter__()
            _events.clear()
            await client.__aexit__(None, None, None)
            end_events = [e for e in _events if "session" in e.get("event_type", "").lower()
                          and ("end" in e.get("event_type", "").lower()
                               or "stop" in e.get("event_type", "").lower())]
            self.assertTrue(len(end_events) >= 1)
        run(_test())

    def test_context_manager_stamps_both_endpoints(self):
        async def _test():
            _events.clear()
            async with MockMCPClient(agent_name="test") as client:
                pass
            session_events = [e for e in _events if "session" in e.get("event_type", "").lower()]
            self.assertGreaterEqual(len(session_events), 2)  # start + end
        run(_test())

    def test_session_stamps_server_hash_not_url(self):
        async def _test():
            _events.clear()
            secret_url = "http://internal-server.corp:8000"
            client = MockMCPClient(server_url=secret_url, agent_name="test")
            await client.__aenter__()
            for e in _events:
                self.assertNotIn(secret_url, json.dumps(e))
        run(_test())


# ══════════════════════════════════════════════════════════════════════════════
# Tests — call_tool()
# ══════════════════════════════════════════════════════════════════════════════

class TestCallTool(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.client = MockMCPClient(agent_name="mcp_agent")

    def test_call_tool_stamps_start(self):
        async def _test():
            _events.clear()
            await self.client.call_tool("search", {"query": "AAPL"})
            tool_events = [e for e in _events if "tool" in e.get("event_type", "").lower()]
            self.assertTrue(len(tool_events) >= 1)
        run(_test())

    def test_call_tool_stamps_complete(self):
        async def _test():
            _events.clear()
            await self.client.call_tool("calculate", {"expr": "2+2"})
            complete = [e for e in _events if "result" in e.get("event_type", "").lower()
                        or "complete" in e.get("event_type", "").lower()]
            self.assertTrue(len(complete) >= 1)
        run(_test())

    def test_call_tool_stamps_tool_name(self):
        async def _test():
            _events.clear()
            await self.client.call_tool("web_search", {"query": "test"})
            tool_start = [e for e in _events if "tool" in e.get("event_type", "").lower()
                          and "result" not in e.get("event_type", "").lower()]
            self.assertTrue(len(tool_start) >= 1)
            self.assertIn("web_search", json.dumps(tool_start[0]))
        run(_test())

    def test_call_tool_stamps_args_hash_not_raw(self):
        async def _test():
            _events.clear()
            secret_args = {"api_key": "sk-supersecret-key", "query": "classified"}
            await self.client.call_tool("api_call", secret_args)
            for e in _events:
                self.assertNotIn("supersecret", json.dumps(e))
                self.assertNotIn("classified", json.dumps(e))
            # But args_hash must be present
            args_hash_events = [e for e in _events if "args_hash" in e]
            self.assertTrue(len(args_hash_events) >= 1)
        run(_test())

    def test_call_tool_stamps_result_hash(self):
        async def _test():
            _events.clear()
            await self.client.call_tool("fetch_data", {"id": "42"})
            result_events = [e for e in _events if "result_hash" in e]
            self.assertTrue(len(result_events) >= 1)
        run(_test())

    def test_call_tool_returns_result(self):
        async def _test():
            result = await self.client.call_tool("search", {"query": "test"})
            self.assertIsNotNone(result)
            self.assertIn("result", result)
        run(_test())

    def test_call_tool_error_stamped(self):
        async def _test():
            _events.clear()
            with self.assertRaises(RuntimeError):
                await self.client.call_tool("fail_tool", {})
            error_events = [e for e in _events if "error" in e.get("event_type", "").lower()]
            self.assertTrue(len(error_events) >= 1)
        run(_test())

    def test_call_tool_error_stamps_tool_name(self):
        async def _test():
            _events.clear()
            try:
                await self.client.call_tool("fail_tool", {})
            except RuntimeError:
                pass
            error_events = [e for e in _events if "error" in e.get("event_type", "").lower()]
            if error_events:
                self.assertIn("fail_tool", json.dumps(error_events[0]))
        run(_test())

    def test_multiple_tool_calls_chained(self):
        async def _test():
            _events.clear()
            await self.client.call_tool("tool_a", {"x": 1})
            count_after_first = len(_events)
            await self.client.call_tool("tool_b", {"x": 2})
            second_batch = _events[count_after_first:]
            if second_batch:
                self.assertIn("previous_event_hash", second_batch[0])
        run(_test())


# ══════════════════════════════════════════════════════════════════════════════
# Tests — read_resource()
# ══════════════════════════════════════════════════════════════════════════════

class TestReadResource(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.client = MockMCPClient(agent_name="mcp_agent")

    def test_read_resource_stamps_event(self):
        async def _test():
            _events.clear()
            await self.client.read_resource("file:///reports/q4.pdf")
            resource_events = [e for e in _events if "resource" in e.get("event_type", "").lower()]
            self.assertTrue(len(resource_events) >= 1)
        run(_test())

    def test_read_resource_hashes_uri(self):
        async def _test():
            _events.clear()
            secret_uri = "file:///confidential/patient_data.db"
            await self.client.read_resource(secret_uri)
            for e in _events:
                self.assertNotIn("confidential", json.dumps(e))
                self.assertNotIn("patient_data", json.dumps(e))
            # uri_hash must be present
            uri_hash_events = [e for e in _events if "uri_hash" in e]
            self.assertTrue(len(uri_hash_events) >= 1)
        run(_test())

    def test_read_resource_stamps_content_hash(self):
        async def _test():
            _events.clear()
            await self.client.read_resource("file:///data/report.txt")
            content_events = [e for e in _events if "content_hash" in e]
            self.assertTrue(len(content_events) >= 1)
        run(_test())

    def test_read_resource_returns_content(self):
        async def _test():
            content = await self.client.read_resource("file:///data/test.txt")
            self.assertIsNotNone(content)
        run(_test())

    def test_read_resource_error_stamped(self):
        async def _test():
            _events.clear()
            with self.assertRaises(FileNotFoundError):
                await self.client.read_resource("file:///not_found")
            # At minimum a start event was emitted before error
            self.assertTrue(len(_events) >= 1)
        run(_test())


# ══════════════════════════════════════════════════════════════════════════════
# Tests — get_prompt()
# ══════════════════════════════════════════════════════════════════════════════

class TestGetPrompt(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.client = MockMCPClient(agent_name="mcp_agent")

    def test_get_prompt_stamps_event(self):
        async def _test():
            _events.clear()
            await self.client.get_prompt("analyst", {"symbol": "AAPL"})
            prompt_events = [e for e in _events if "prompt" in e.get("event_type", "").lower()]
            self.assertTrue(len(prompt_events) >= 1)
        run(_test())

    def test_get_prompt_stamps_name(self):
        async def _test():
            _events.clear()
            await self.client.get_prompt("medical_advisor", {"condition": "hypertension"})
            prompt_events = [e for e in _events if "prompt" in e.get("event_type", "").lower()]
            self.assertTrue(len(prompt_events) >= 1)
            self.assertIn("medical_advisor", json.dumps(prompt_events[0]))
        run(_test())

    def test_get_prompt_hashes_args(self):
        async def _test():
            _events.clear()
            secret_args = {"patient_id": "P12345", "condition": "classified"}
            await self.client.get_prompt("doctor", secret_args)
            for e in _events:
                self.assertNotIn("P12345", json.dumps(e))
                self.assertNotIn("classified", json.dumps(e))
        run(_test())

    def test_get_prompt_stamps_messages_hash(self):
        async def _test():
            _events.clear()
            await self.client.get_prompt("analyst", {"symbol": "MSFT"})
            result_events = [e for e in _events if "messages_hash" in e]
            self.assertTrue(len(result_events) >= 1)
        run(_test())

    def test_get_prompt_returns_messages(self):
        async def _test():
            messages = await self.client.get_prompt("analyst", {"symbol": "AAPL"})
            self.assertIsInstance(messages, list)
            self.assertTrue(len(messages) >= 1)
        run(_test())


# ══════════════════════════════════════════════════════════════════════════════
# Tests — inspection / export
# ══════════════════════════════════════════════════════════════════════════════

class TestInspectionAndExport(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.client = MockMCPClient(agent_name="mcp_agent")

    def test_audit_event_count_increments(self):
        initial = self.client.audit_event_count
        async def _test():
            await self.client.call_tool("search", {"q": "test"})
        run(_test())
        self.assertGreater(self.client.audit_event_count, initial)

    def test_last_event_hash_updated(self):
        initial = self.client.last_event_hash
        async def _test():
            await self.client.call_tool("search", {"q": "test"})
        run(_test())
        self.assertNotEqual(self.client.last_event_hash, initial)

    def test_export_audit_instance(self):
        import tempfile
        import os
        async def _test():
            await self.client.call_tool("search", {"q": "test"})
        run(_test())
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            self.client.export_audit(path)
            self.assertTrue(os.path.exists(path))
            data = json.loads(open(path).read())
            self.assertIsInstance(data, list)
        finally:
            os.unlink(path)

    def test_export_audit_top_level(self):
        import tempfile
        import os
        _events.clear()
        _events.append({"event_type": "mcp_tool_result", "result_hash": "abc"})
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_audit(path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)

    def test_repr(self):
        r = repr(self.client)
        self.assertIn("AuditedMCPClient", r)


# ══════════════════════════════════════════════════════════════════════════════
# Test cross-framework : MCP + LangChain + Session
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossFrameworkScenario(unittest.TestCase):
    """
    Un agent LangChain utilise des outils MCP.
    Chaque résultat d'outil co-signé : dans la mémoire MCP ET dans la session.
    """

    def test_tool_result_hash_preserved_cross_framework(self):
        async def _test():
            _events.clear()
            client = MockMCPClient(agent_name="mcp_tools")

            # Appel d'outil MCP
            result = await client.call_tool("market_data", {"symbol": "AAPL", "period": "1M"})

            # Hash du résultat — ce qui sera co-signé dans la session
            result_hash = hashlib.sha256(json.dumps(result, default=str).encode()).hexdigest()

            # Stamp du handoff vers LangChain (simulé sans AgentSession)
            client._stamp("result_sent_to_langchain", {
                "payload_hash": result_hash,
                "peer": "langchain_analyst",
                "tool": "market_data",
            })

            # Vérifier que le result_hash est dans la mémoire MCP
            hashes = [e.get("payload_hash") for e in _events if "payload_hash" in e]
            self.assertIn(result_hash, hashes)

        run(_test())

    def test_no_raw_data_crosses_framework_boundary(self):
        """
        Vérifier que jamais de données brutes ne transitent —
        seulement les hashes.
        """
        async def _test():
            _events.clear()
            client = MockMCPClient(agent_name="mcp_privacy")

            confidential_args = {
                "patient_id": "P99999",
                "ssn": "123-45-6789",
                "diagnosis": "CLASSIFIED_CONDITION",
            }

            try:
                await client.call_tool("medical_lookup", confidential_args)
            except Exception:
                pass

            full_log = json.dumps(_events)
            self.assertNotIn("P99999", full_log)
            self.assertNotIn("123-45-6789", full_log)
            self.assertNotIn("CLASSIFIED_CONDITION", full_log)

        run(_test())


if __name__ == "__main__":
    unittest.main(verbosity=2)
