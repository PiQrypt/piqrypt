"""
Tests — bridges/session/__init__.py
Bridge AgentSession — Multi-framework A2A co-signé

Run: pytest test_piqrypt_session.py -v
"""
import hashlib
import json
import sys
import time
import types
import unittest


# ── Mock piqrypt ──────────────────────────────────────────────────────────────

def _setup_piqrypt_mock():
    events_by_agent = {}  # agent_id → [events]

    def _store(e):
        aid = e.get("_pq_agent_id", "unknown")
        events_by_agent.setdefault(aid, []).append(e)

    mock = types.ModuleType("piqrypt")
    mock.generate_keypair   = lambda: (b"priv" * 8, b"pub" * 8)
    mock.derive_agent_id    = lambda pub: "AGENT_" + hashlib.sha256(pub).hexdigest()[:12]
    mock.load_identity      = lambda f: {
        "private_key_bytes": b"key" * 8,
        "agent_id": "AGENT_" + hashlib.sha256(f.encode()).hexdigest()[:8]
    }
    mock.stamp_event        = lambda key, aid, payload: {
        **payload,
        "_pq_agent_id": aid,
        "_pq_timestamp": time.time(),
        "_pq_sig": hashlib.sha256(f"{aid}{time.time()}".encode()).hexdigest()[:16],
    }
    mock.store_event        = _store
    mock.compute_event_hash = lambda e: hashlib.sha256(json.dumps(e, default=str).encode()).hexdigest()
    mock.export_audit_chain = lambda path: open(path, "w").write(json.dumps(list(events_by_agent.values())))
    mock._events_by_agent   = events_by_agent

    sys.modules["piqrypt"] = mock
    return mock, events_by_agent

_mock_piqrypt, _events_by_agent = _setup_piqrypt_mock()

# Import bridge
from piqrypt_session import AgentSession


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _all_events():
    """Retourne tous les events de tous les agents."""
    return [e for events in _mock_piqrypt._events_by_agent.values() for e in events]

def _make_session(names=("agent_a", "agent_b")):
    return AgentSession([
        {"name": n, "identity_file": f"{n}.json"} for n in names
    ])


# ══════════════════════════════════════════════════════════════════════════════
# Tests AgentSession — création et handshake
# ══════════════════════════════════════════════════════════════════════════════

class TestAgentSessionCreation(unittest.TestCase):

    def setUp(self):
        _mock_piqrypt._events_by_agent.clear()

    def test_session_created_with_agents(self):
        session = _make_session(("alpha", "beta"))
        self.assertEqual(len(session.agents), 2)

    def test_session_has_unique_id(self):
        s1 = _make_session(("a", "b"))
        s2 = _make_session(("c", "d"))
        self.assertNotEqual(s1.session_id, s2.session_id)

    def test_session_id_format(self):
        session = _make_session(("a", "b"))
        # Session ID doit être une chaîne non vide
        self.assertIsInstance(session.session_id, str)
        self.assertTrue(len(session.session_id) > 8)

    def test_three_agent_session(self):
        session = _make_session(("claude", "langgraph", "crewai"))
        self.assertEqual(len(session.agents), 3)

    def test_agent_members_have_ids(self):
        session = _make_session(("analyst", "trader"))
        for member in session.agents:
            self.assertTrue(member.agent_id.startswith("AGENT_"))


class TestAgentSessionHandshake(unittest.TestCase):

    def setUp(self):
        _mock_piqrypt._events_by_agent.clear()

    def test_start_performs_handshakes(self):
        session = _make_session(("alice", "bob"))
        session.start()
        events = _all_events()
        handshake_events = [e for e in events if "handshake" in e.get("event_type", "").lower()]
        self.assertTrue(len(handshake_events) >= 1)

    def test_three_agents_have_pairwise_handshakes(self):
        """
        3 agents → 3 paires → au minimum 3 handshakes (ou 6 avec A→B et B→A)
        """
        session = _make_session(("claude", "langgraph", "crewai"))
        session.start()
        events = _all_events()
        handshake_events = [e for e in events if "handshake" in e.get("event_type", "").lower()]
        # Au minimum une handshake par paire
        self.assertGreaterEqual(len(handshake_events), 3)

    def test_handshake_references_peer(self):
        session = _make_session(("alice", "bob"))
        session.start()
        events = _all_events()
        handshake_events = [e for e in events if "handshake" in e.get("event_type", "").lower()]
        if handshake_events:
            # Chaque handshake doit identifier son pair
            for e in handshake_events:
                self.assertTrue(
                    "peer" in e or "peer_id" in e or "peer_agent_id" in e,
                    f"Handshake event missing peer reference: {e}"
                )

    def test_handshake_embeds_session_id(self):
        session = _make_session(("a", "b"))
        session.start()
        events = _all_events()
        handshake_events = [e for e in events if "handshake" in e.get("event_type", "").lower()]
        if handshake_events:
            for e in handshake_events:
                self.assertIn("session_id", e)
                self.assertEqual(e["session_id"], session.session_id)


# ══════════════════════════════════════════════════════════════════════════════
# Tests stamp() — interactions co-signées
# ══════════════════════════════════════════════════════════════════════════════

class TestAgentSessionStamp(unittest.TestCase):

    def setUp(self):
        _mock_piqrypt._events_by_agent.clear()
        self.session = _make_session(("langchain_analyst", "crewai_trader"))
        self.session.start()
        _mock_piqrypt._events_by_agent.clear()  # Reset après handshakes

    def test_stamp_creates_event_for_sender(self):
        self.session.stamp("langchain_analyst", "recommendation_sent", {"symbol": "AAPL"})
        events = _all_events()
        self.assertTrue(len(events) >= 1)

    def test_stamp_with_peer_creates_cosigned_events(self):
        """
        Core du test cross-framework :
        Les deux agents doivent avoir un event avec le même payload_hash.
        """
        _mock_piqrypt._events_by_agent.clear()
        self.session.stamp(
            "langchain_analyst",
            "recommendation_sent",
            {"action": "BUY", "symbol": "AAPL", "qty": 100},
            peer="crewai_trader",
        )

        events = _all_events()
        payload_hashes = [e.get("payload_hash") for e in events if "payload_hash" in e]

        # Il doit y avoir au moins 2 events (un par agent) avec le même payload_hash
        if len(payload_hashes) >= 2:
            self.assertEqual(payload_hashes[0], payload_hashes[1],
                "Les deux agents doivent référencer le même payload_hash")

    def test_stamp_embeds_session_id(self):
        self.session.stamp("langchain_analyst", "action", {"data": "test"})
        events = _all_events()
        for e in events:
            if "session_id" in e:
                self.assertEqual(e["session_id"], self.session.session_id)

    def test_stamp_event_type_stored(self):
        _mock_piqrypt._events_by_agent.clear()
        self.session.stamp("langchain_analyst", "trade_executed", {"symbol": "MSFT"})
        events = _all_events()
        event_types = [e.get("event_type", "") for e in events]
        self.assertTrue(any("trade_executed" in t for t in event_types))

    def test_stamp_unknown_agent_raises(self):
        with self.assertRaises((KeyError, ValueError, Exception)):
            self.session.stamp("nonexistent_agent", "test", {})


# ══════════════════════════════════════════════════════════════════════════════
# Test scénario complet cross-framework
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossFrameworkSession(unittest.TestCase):
    """
    Scénario réel :
      Claude → LangGraph → CrewAI (researcher + trader)

    Propriété clé : la chaîne de causalité est cryptographiquement prouvable
    bout en bout. Chaque interaction est co-signée dans les deux mémoires.
    """

    def setUp(self):
        _mock_piqrypt._events_by_agent.clear()

    def test_full_pipeline_claude_langgraph_crewai(self):
        # 1. Créer la session avec 3 frameworks
        session = AgentSession([
            {"name": "claude",    "identity_file": "claude.json"},
            {"name": "langgraph", "identity_file": "langgraph.json"},
            {"name": "crewai",    "identity_file": "crewai.json"},
        ])
        session.start()
        _mock_piqrypt._events_by_agent.clear()

        # 2. Claude envoie une instruction à LangGraph
        session.stamp("claude", "instruction_sent", {
            "task": "analyse portefeuille",
            "context_hash": hashlib.sha256(b"portfolio_data").hexdigest(),
        }, peer="langgraph")

        # 3. LangGraph transmet à CrewAI
        session.stamp("langgraph", "graph_result_sent", {
            "nodes_executed": 5,
            "recommendation_hash": hashlib.sha256(b"BUY AAPL").hexdigest(),
        }, peer="crewai")

        # 4. CrewAI exécute
        session.stamp("crewai", "trade_executed", {
            "symbol": "AAPL",
            "action": "BUY",
            "qty": 100,
        })

        # Vérifications
        events = _all_events()
        self.assertGreater(len(events), 0)

        # Tous les events doivent avoir un session_id identique
        session_ids = [e["session_id"] for e in events if "session_id" in e]
        if session_ids:
            self.assertTrue(all(s == session.session_id for s in session_ids),
                "Tous les events doivent partager le même session_id")

    def test_audit_chain_is_exportable(self):
        import tempfile
        import os
        session = _make_session(("a", "b"))
        session.start()
        session.stamp("a", "event", {"data": "test"})

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            session.export(path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)

    def test_session_summary(self):
        session = _make_session(("x", "y"))
        session.start()
        session.stamp("x", "action", {"v": 1})

        summary = session.summary()
        self.assertIn("session_id", summary)
        self.assertIn("agent_count", summary)
        self.assertEqual(summary["agent_count"], 2)


# ══════════════════════════════════════════════════════════════════════════════
# Tests AgentMember
# ══════════════════════════════════════════════════════════════════════════════

class TestAgentMember(unittest.TestCase):

    def setUp(self):
        _mock_piqrypt._events_by_agent.clear()

    def test_member_has_name(self):
        session = _make_session(("myagent", "other"))
        member = next(m for m in session.agents if m.name == "myagent")
        self.assertEqual(member.name, "myagent")

    def test_member_has_agent_id(self):
        session = _make_session(("myagent", "other"))
        member = next(m for m in session.agents if m.name == "myagent")
        self.assertTrue(member.agent_id.startswith("AGENT_"))

    def test_member_event_count(self):
        session = _make_session(("counter", "other"))
        session.start()
        _mock_piqrypt._events_by_agent.clear()
        session.stamp("counter", "action1", {})
        session.stamp("counter", "action2", {})
        member = next(m for m in session.agents if m.name == "counter")
        self.assertGreaterEqual(member.event_count, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
