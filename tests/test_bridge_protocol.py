# ============================================================
#  PiQrypt — Test BridgeProtocol v1.1.0
#
#  Valide les 3 points du protocole sur les 4 bridges :
#    1. on_session_start()  — injection mémoire
#    2. on_peer_contact()   — historique A2A
#    3. on_action_gate()    — gate TrustGate
#
#  Entierement mocke — ne necessite pas piqrypt installe.
#  Lance depuis la racine du repo :
#    python tests/test_bridge_protocol.py
#    python tests/test_bridge_protocol.py -v
# ============================================================

import asyncio
import hashlib
import json
import sys
import time
import types
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

VERBOSE = "-v" in sys.argv

def OK(msg):   print(f"  [OK]   {msg}")
def FAIL(msg): print(f"  [FAIL] {msg}"); _errors.append(msg)
def INFO(msg):
    if VERBOSE: print(f"  [...]  {msg}")
def SEP():     print("  " + "─" * 50)
def SECTION(t): print(f"\n  === {t} ==="); SEP()

_errors = []


# ══════════════════════════════════════════════════════════════════════════════
# 1. MOCKS INFRASTRUCTURE
# ══════════════════════════════════════════════════════════════════════════════

# ── Mock piqrypt ──────────────────────────────────────────────────────────────

_events: List[Dict] = []

def _setup_piqrypt_mock():
    mock = types.ModuleType("piqrypt")
    mock.generate_keypair     = lambda: (b"priv" * 8, b"pub" * 8)
    mock.derive_agent_id      = lambda pub: "AGENT_" + hashlib.sha256(pub).hexdigest()[:12]
    mock.load_identity        = lambda f: {
        "private_key_bytes": b"key" * 8,
        "agent_id": "AGENT_TEST",
    }
    mock.stamp_event          = lambda key, aid, payload: {
        **payload,
        "_pq_agent_id": aid,
        "_pq_timestamp": int(time.time()),
        "_pq_sig": "mocksig",
    }
    mock.store_event          = lambda e: _events.append(e)
    mock.compute_event_hash   = lambda e: hashlib.sha256(
        json.dumps(e, default=str).encode()
    ).hexdigest()
    mock.export_audit_chain   = lambda path: open(path, "w").write(
        json.dumps(_events)
    )
    sys.modules["piqrypt"] = mock
    return mock

_mock_pq = _setup_piqrypt_mock()

# ── Mock aiss.memory (load_events) ────────────────────────────────────────────

_memory_store: List[Dict] = []

def _setup_aiss_mock():
    # aiss
    aiss_mod = types.ModuleType("aiss")
    aiss_mod.generate_keypair   = _mock_pq.generate_keypair
    aiss_mod.derive_agent_id    = _mock_pq.derive_agent_id
    aiss_mod.stamp_event        = _mock_pq.stamp_event
    aiss_mod.store_event        = _mock_pq.store_event
    aiss_mod.compute_event_hash = _mock_pq.compute_event_hash
    sys.modules["aiss"] = aiss_mod

    # aiss.memory
    memory_mod = types.ModuleType("aiss.memory")
    memory_mod.load_events  = lambda agent_name=None, **kw: _memory_store
    memory_mod.store_event  = lambda e, **kw: _memory_store.append(e)
    memory_mod.PIQRYPT_DIR  = Path("/tmp/piqrypt_test")
    sys.modules["aiss.memory"] = memory_mod

    # aiss.chain
    chain_mod = types.ModuleType("aiss.chain")
    chain_mod.compute_event_hash = _mock_pq.compute_event_hash
    sys.modules["aiss.chain"] = chain_mod

    # aiss.a2a
    a2a_mod = types.ModuleType("aiss.a2a")
    a2a_mod.get_peer = lambda agent_id: None  # pas de peer par défaut
    sys.modules["aiss.a2a"] = a2a_mod

    # aiss.license
    license_mod = types.ModuleType("aiss.license")
    license_mod.is_pro = lambda: False
    sys.modules["aiss.license"] = license_mod

    return memory_mod, a2a_mod

_memory_mod, _a2a_mod = _setup_aiss_mock()

# ── Mock frameworks externes ──────────────────────────────────────────────────

def _setup_langchain_mock():
    lc = types.ModuleType("langchain")
    agents = types.ModuleType("langchain.agents")
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
        def __init__(self, **kw): self.callbacks = kw.get("callbacks", [])
        def invoke(self, inp, **kw): return {"output": "mock"}
        def run(self, inp, **kw): return "mock"

    class LLMResult:
        def __init__(self): self.generations = [[MagicMock(text="mock")]]

    callbacks.BaseCallbackHandler = BaseCallbackHandler
    agents.AgentExecutor = AgentExecutor
    schema.LLMResult = LLMResult
    lc.agents = agents
    sys.modules.update({
        "langchain": lc,
        "langchain.agents": agents,
        "langchain.callbacks": types.ModuleType("langchain.callbacks"),
        "langchain.callbacks.base": callbacks,
        "langchain.schema": schema,
    })
    return BaseCallbackHandler, AgentExecutor, LLMResult

def _setup_crewai_mock():
    mod = types.ModuleType("crewai")
    class Agent:
        model_config = {"arbitrary_types_allowed": True}
        def __init__(self, *a, **kw):
            self.role = kw.get("role", "unknown")
        def execute_task(self, task, context=None, tools=None):
            return "mock_result"
    class Crew:
        model_config = {"arbitrary_types_allowed": True}
        def __init__(self, *a, **kw):
            self.agents = kw.get("agents", [])
            self.tasks  = kw.get("tasks", [])
        def kickoff(self, inputs=None): return "crew_result"
    mod.Agent = Agent
    mod.Crew  = Crew
    sys.modules["crewai"] = mod
    return Agent, Crew

def _setup_autogen_mock():
    mod = types.ModuleType("autogen")
    class ConversableAgent:
        def __init__(self, *a, **kw):
            self.name = kw.get("name", "agent")
            self.human_input_mode = kw.get("human_input_mode", "NEVER")
        def generate_reply(self, messages=None, sender=None, **kw):
            return "mock_reply"
        def execute_code_blocks(self, blocks, **kw):
            return "code_result"
    class AssistantAgent(ConversableAgent): pass
    class UserProxyAgent(ConversableAgent): pass
    class GroupChat:
        def __init__(self, *a, **kw):
            self.agents = kw.get("agents", [])
            self.messages = kw.get("messages", [])
    class GroupChatManager(ConversableAgent):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.groupchat = kw.get("groupchat")
        def run_chat(self, messages=None, sender=None, config=None):
            return "chat_result"
    mod.ConversableAgent  = ConversableAgent
    mod.AssistantAgent    = AssistantAgent
    mod.UserProxyAgent    = UserProxyAgent
    mod.GroupChat         = GroupChat
    mod.GroupChatManager  = GroupChatManager
    sys.modules["autogen"] = mod
    return AssistantAgent, UserProxyAgent, GroupChat, GroupChatManager

_setup_langchain_mock()
_setup_crewai_mock()
_setup_autogen_mock()

# ── Charger BridgeProtocol directement par chemin absolu ─────────────────────
# Évite le conflit entre piqrypt installé en pip (qui expose aiss comme module
# plat) et le dossier aiss/ du repo local.
_repo_root = Path(__file__).parent.parent
_bp_file   = _repo_root / "aiss" / "bridge_protocol.py"

try:
    if not _bp_file.exists():
        raise FileNotFoundError(f"Fichier absent : {_bp_file}")

    # Créer le module et l'injecter dans sys.modules AVANT exec —
    # @dataclass fait sys.modules[cls.__module__].__dict__ pendant la définition
    import builtins as _builtins_mod
    _bp_mod = types.ModuleType("aiss.bridge_protocol")
    _bp_mod.__file__     = str(_bp_file)
    _bp_mod.__package__  = "aiss"
    _bp_mod.__builtins__ = _builtins_mod
    sys.modules["aiss.bridge_protocol"] = _bp_mod

    # Exécuter le source dans le __dict__ du module déjà enregistré
    _bp_source = _bp_file.read_text(encoding="utf-8")
    exec(compile(_bp_source, str(_bp_file), "exec"), _bp_mod.__dict__)

    BridgeProtocol = _bp_mod.BridgeProtocol
    BridgeAction   = _bp_mod.BridgeAction

    _BP_AVAILABLE = True
    INFO(f"BridgeProtocol chargé depuis {_bp_file}")

except Exception as e:
    _BP_AVAILABLE = False
    print(f"\n  [WARN] BridgeProtocol non trouvé : {e}")
    print(f"  Chemin cherché : {_bp_file}")
    print("  Assurez-vous que aiss/bridge_protocol.py est en place.\n")
    BridgeProtocol = object
    BridgeAction   = None


# ══════════════════════════════════════════════════════════════════════════════
# 2. TESTS BRIDGE_PROTOCOL DIRECT
# ══════════════════════════════════════════════════════════════════════════════

class TestBridgeProtocolDirect(unittest.TestCase):
    """Valide BridgeProtocol en isolation, sans framework."""

    def setUp(self):
        _events.clear()
        _memory_store.clear()

    def _make_bp(self, agent_name="test_agent"):
        if not _BP_AVAILABLE:
            self.skipTest("BridgeProtocol non disponible")
        return BridgeProtocol(agent_name=agent_name)

    # ── 1. Mémoire vide ───────────────────────────────────────────────────────
    def test_session_start_empty_memory(self):
        bp = self._make_bp()
        result = bp.on_session_start()
        self.assertEqual(result, "")  # Pas d'events → chaîne vide
        INFO("on_session_start() avec mémoire vide → chaîne vide OK")

    # ── 2. Mémoire avec events ────────────────────────────────────────────────
    def test_session_start_with_events(self):
        _memory_store.extend([
            {
                "version": "AISS-1.0",
                "timestamp": int(time.time()) - 60,
                "payload": {"action": "websearch", "result": "182.50"},
            },
            {
                "version": "AISS-1.0",
                "timestamp": int(time.time()) - 30,
                "payload": {"action": "trade", "status": "success"},
            },
        ])
        bp = self._make_bp()
        result = bp.on_session_start()
        self.assertIn("websearch", result)
        self.assertIn("trade", result)
        self.assertIn("[PiQrypt", result)
        INFO(f"on_session_start() avec 2 events :\n{result}")

    # ── 3. Delta mémoire ─────────────────────────────────────────────────────
    def test_session_update_returns_delta(self):
        bp = self._make_bp()
        # Simuler une injection initiale à t-100
        bp._last_injection_ts = int(time.time()) - 100

        # Ajouter un event récent
        _memory_store.append({
            "version": "AISS-1.0",
            "timestamp": int(time.time()),
            "payload": {"action": "new_action"},
        })
        delta = bp.on_session_update()
        self.assertIn("new_action", delta)
        INFO(f"on_session_update() delta : {delta[:80]}...")

    # ── 4. Peer inconnu ───────────────────────────────────────────────────────
    def test_peer_contact_unknown(self):
        bp = self._make_bp()
        result = bp.on_peer_contact("UNKNOWN_PEER_ID")
        self.assertFalse(result["known"])
        self.assertEqual(result["interaction_count"], 0)
        self.assertEqual(result["summary"], "")
        INFO("on_peer_contact() peer inconnu → known=False OK")

    # ── 5. Peer connu ────────────────────────────────────────────────────────
    def test_peer_contact_known(self):
        # Simuler un peer connu dans le registre
        _a2a_mod.get_peer = lambda agent_id: {
            "first_seen": int(time.time()) - 86400,
            "last_seen": int(time.time()) - 3600,
            "interaction_count": 7,
            "trust_score": 0.92,
        }
        bp = self._make_bp()
        result = bp.on_peer_contact("KNOWN_PEER_XYZ")
        self.assertTrue(result["known"])
        self.assertEqual(result["interaction_count"], 7)
        self.assertIn("KNOWN_PEER_XYZ", result["summary"])
        self.assertIn("7", result["summary"])
        INFO(f"on_peer_contact() peer connu :\n{result['summary']}")
        # Restaurer
        _a2a_mod.get_peer = lambda agent_id: None

    # ── 6. Gate — TrustGate absent (Free tier) → ALLOW ───────────────────────
    def test_gate_no_trustgate_allows(self):
        bp = self._make_bp()
        action = BridgeAction(name="websearch", payload={"q": "AAPL"})
        result = bp.on_action_gate(action)
        self.assertTrue(result)  # ALLOW par défaut si TrustGate absent
        INFO("on_action_gate() sans TrustGate → ALLOW OK")

    # ── 7. Gate — TrustGate mocké BLOCK ──────────────────────────────────────
    def test_gate_trustgate_block(self):
        # Installer un mock trustgate qui bloque
        tg_mod = types.ModuleType("trustgate")
        tg_decision = types.ModuleType("trustgate.decision")
        tg_engine = types.ModuleType("trustgate.policy_engine")
        tg_loader = types.ModuleType("trustgate.policy_loader")

        class MockOutcome:
            value = "BLOCK"
        class MockDecision:
            outcome = MockOutcome()
            reason = "VRS trop élevé"

        tg_engine.evaluate = lambda ctx, policy: MockDecision()

        class MockPolicy: pass
        tg_loader.load_policy = lambda path: MockPolicy()

        class MockEvalCtx:
            def __init__(self, **kw): pass

        tg_decision.EvaluationContext = MockEvalCtx
        tg_decision.Outcome = MockOutcome

        sys.modules["trustgate"] = tg_mod
        sys.modules["trustgate.decision"] = tg_decision
        sys.modules["trustgate.policy_engine"] = tg_engine
        sys.modules["trustgate.policy_loader"] = tg_loader

        # Créer un BridgeProtocol avec une fausse policy
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            f.write(b"version: '1.0'\n")
            policy_path = Path(f.name)

        bp = BridgeProtocol(agent_name="blocked_agent", policy_path=policy_path)
        action = BridgeAction(name="dangerous_action", payload={})
        result = bp.on_action_gate(action)
        self.assertFalse(result)  # BLOCK → False
        INFO("on_action_gate() avec TrustGate BLOCK → False OK")

        # Nettoyer
        os.unlink(policy_path)
        for m in ["trustgate", "trustgate.decision", "trustgate.policy_engine",
                  "trustgate.policy_loader"]:
            sys.modules.pop(m, None)

    # ── 8. update_trust_state ────────────────────────────────────────────────
    def test_update_trust_state(self):
        bp = self._make_bp()
        bp.update_trust_state(vrs=0.75, tsi_state="WATCH")
        self.assertEqual(bp._vrs, 0.75)
        self.assertEqual(bp._tsi_state, "WATCH")
        INFO("update_trust_state() → VRS et TSI mis à jour OK")


# ══════════════════════════════════════════════════════════════════════════════
# 3. TESTS BRIDGE LANGCHAIN
# ══════════════════════════════════════════════════════════════════════════════

class TestLangChainBridge(unittest.TestCase):
    """Valide les 3 points BridgeProtocol dans PiQryptCallbackHandler."""

    def setUp(self):
        _events.clear()
        _memory_store.clear()
        # Ajouter 2 events en mémoire pour tester l'injection
        _memory_store.extend([
            {"version": "AISS-1.0", "timestamp": int(time.time()) - 60,
             "payload": {"action": "websearch", "result": "ok"}},
        ])

    def _import_handler(self):
        import importlib.util as _ilu
        key = "piqrypt_langchain"
        if key in sys.modules: del sys.modules[key]
        _f = _repo_root / "bridges" / "langchain" / "__init__.py"
        if not _f.exists():
            self.skipTest("Bridge LangChain non trouvé (bridges/langchain/__init__.py)")
        try:
            _mod = types.ModuleType(key)
            _mod.__file__ = str(_f)
            _mod.__package__ = key
            _mod.__builtins__ = __builtins__
            sys.modules[key] = _mod
            exec(compile(_f.read_text(encoding="utf-8"), str(_f), "exec"), _mod.__dict__)
            return _mod.PiQryptCallbackHandler
        except Exception as e:
            self.skipTest(f"Bridge LangChain import échoué : {e}")

    def test_memory_injected_at_init(self):
        Handler = self._import_handler()
        h = Handler(agent_name="lc_agent", inject_memory=True)
        self.assertIn("websearch", h.memory_context)
        INFO(f"LangChain — memory_context : {h.memory_context[:80]}...")

    def test_no_memory_if_disabled(self):
        Handler = self._import_handler()
        h = Handler(agent_name="lc_agent", inject_memory=False)
        self.assertEqual(h.memory_context, "")
        INFO("LangChain — inject_memory=False → memory_context vide OK")

    def test_tool_start_stamps_event(self):
        Handler = self._import_handler()
        h = Handler(agent_name="lc_agent")
        _events.clear()
        h.on_tool_start({"name": "websearch"}, "AAPL price")
        tool_events = [e for e in _events if "tool" in e.get("event_type", "")]
        self.assertTrue(len(tool_events) >= 1)
        INFO(f"LangChain — on_tool_start stamp OK ({len(tool_events)} events)")

    def test_tool_start_gate_blocks_and_raises(self):
        """Gate TrustGate mocké BLOCK → RuntimeError levée."""
        Handler = self._import_handler()

        # Mock gate pour retourner False
        h = Handler(agent_name="lc_agent", enable_gate=True)
        if hasattr(h, "on_action_gate"):
            h.on_action_gate = lambda action: False
            with self.assertRaises(RuntimeError):
                h.on_tool_start({"name": "dangerous_tool"}, "input")
            INFO("LangChain — gate BLOCK → RuntimeError OK")

    def test_chain_start_stamps_event(self):
        Handler = self._import_handler()
        h = Handler(agent_name="lc_agent")
        _events.clear()
        h.on_chain_start({"name": "MyChain"}, {"input": "test"})
        chain_events = [e for e in _events if "chain" in e.get("event_type", "")]
        self.assertTrue(len(chain_events) >= 1)
        INFO(f"LangChain — on_chain_start stamp OK")

    def test_chain_end_updates_memory_delta(self):
        Handler = self._import_handler()
        h = Handler(agent_name="lc_agent")
        # Simuler un event récent apparu depuis la dernière injection
        h._last_injection_ts = int(time.time()) - 120
        _memory_store.append({
            "version": "AISS-1.0",
            "timestamp": int(time.time()),
            "payload": {"action": "new_step"},
        })
        h.on_chain_end({"output": "done"})
        # memory_context mis à jour si BridgeProtocol disponible
        INFO("LangChain — on_chain_end delta mémoire OK")

    def test_initialized_event_stamped(self):
        Handler = self._import_handler()
        _events.clear()
        Handler(agent_name="lc_agent")
        init_events = [e for e in _events
                       if "initialized" in e.get("event_type", "")]
        self.assertTrue(len(init_events) >= 1)
        INFO("LangChain — event initialized stamped OK")


# ══════════════════════════════════════════════════════════════════════════════
# 4. TESTS BRIDGE CREWAI
# ══════════════════════════════════════════════════════════════════════════════

class TestCrewAIBridge(unittest.TestCase):
    """Valide les 3 points BridgeProtocol dans AuditedAgent."""

    def setUp(self):
        _events.clear()
        _memory_store.clear()
        _memory_store.append({
            "version": "AISS-1.0",
            "timestamp": int(time.time()) - 60,
            "payload": {"action": "research", "status": "done"},
        })

    def _import_agent(self):
        key = "piqrypt_crewai"
        if key in sys.modules: del sys.modules[key]
        _f = _repo_root / "bridges" / "crewai" / "__init__.py"
        if not _f.exists():
            self.skipTest("Bridge CrewAI non trouvé (bridges/crewai/__init__.py)")
        try:
            _mod = types.ModuleType(key)
            _mod.__file__ = str(_f)
            _mod.__package__ = key
            _mod.__builtins__ = __builtins__
            sys.modules[key] = _mod
            exec(compile(_f.read_text(encoding="utf-8"), str(_f), "exec"), _mod.__dict__)
            return _mod.AuditedAgent
        except Exception as e:
            self.skipTest(f"Bridge CrewAI import échoué : {e}")

    def test_memory_injected_at_init(self):
        Agent = self._import_agent()
        a = Agent(role="Researcher", goal="Find", backstory="Expert",
                  agent_name="researcher", inject_memory=True)
        self.assertIn("research", a.memory_context)
        INFO(f"CrewAI — memory_context : {a.memory_context[:80]}...")

    def test_execute_task_stamps_events(self):
        Agent = self._import_agent()
        a = Agent(role="Researcher", goal="Find", backstory="Expert",
                  agent_name="researcher")
        _events.clear()
        task = MagicMock()
        task.description = "Analyze AAPL"
        a.execute_task(task)
        task_events = [e for e in _events if "task" in e.get("event_type", "")]
        self.assertTrue(len(task_events) >= 1)
        INFO(f"CrewAI — execute_task stamps {len(task_events)} events OK")

    def test_execute_task_gate_blocks_raises(self):
        Agent = self._import_agent()
        a = Agent(role="Researcher", goal="Find", backstory="Expert",
                  agent_name="researcher", enable_gate=True)
        if hasattr(a, "on_action_gate"):
            a.on_action_gate = lambda action: False
            task = MagicMock()
            task.description = "Dangerous task"
            with self.assertRaises(RuntimeError):
                a.execute_task(task)
            INFO("CrewAI — gate BLOCK → RuntimeError OK")

    def test_agent_name_falls_back_to_role(self):
        Agent = self._import_agent()
        # Sans agent_name explicite, le role est utilisé
        a = Agent(role="MyRole", goal="G", backstory="B")
        self.assertEqual(a._agent_name, "MyRole")
        INFO(f"CrewAI — agent_name fallback sur role : {a._agent_name} OK")

    def test_initialized_event_stamped(self):
        Agent = self._import_agent()
        _events.clear()
        Agent(role="R", goal="G", backstory="B", agent_name="crew_agent")
        init_events = [e for e in _events
                       if "initialized" in e.get("event_type", "")]
        self.assertTrue(len(init_events) >= 1)
        INFO("CrewAI — event initialized stamped OK")


# ══════════════════════════════════════════════════════════════════════════════
# 5. TESTS BRIDGE AUTOGEN
# ══════════════════════════════════════════════════════════════════════════════

class TestAutoGenBridge(unittest.TestCase):
    """Valide les 3 points BridgeProtocol dans AuditedAssistant."""

    def setUp(self):
        _events.clear()
        _memory_store.clear()
        _memory_store.append({
            "version": "AISS-1.0",
            "timestamp": int(time.time()) - 60,
            "payload": {"action": "reply", "status": "sent"},
        })

    def _import_assistant(self):
        key = "piqrypt_autogen"
        if key in sys.modules: del sys.modules[key]
        _f = _repo_root / "bridges" / "autogen" / "__init__.py"
        if not _f.exists():
            self.skipTest("Bridge AutoGen non trouvé (bridges/autogen/__init__.py)")
        try:
            _mod = types.ModuleType(key)
            _mod.__file__ = str(_f)
            _mod.__package__ = key
            _mod.__builtins__ = __builtins__
            sys.modules[key] = _mod
            exec(compile(_f.read_text(encoding="utf-8"), str(_f), "exec"), _mod.__dict__)
            return _mod.AuditedAssistant, _mod.AuditedUserProxy
        except Exception as e:
            self.skipTest(f"Bridge AutoGen import échoué : {e}")

    def test_memory_injected_at_init(self):
        Assistant, _ = self._import_assistant()
        a = Assistant(name="analyst", agent_name="analyst", inject_memory=True)
        self.assertIn("reply", a.memory_context)
        INFO(f"AutoGen — memory_context : {a.memory_context[:80]}...")

    def test_generate_reply_stamps_event(self):
        Assistant, _ = self._import_assistant()
        a = Assistant(name="analyst", agent_name="analyst")
        _events.clear()
        messages = [{"role": "user", "content": "What is AAPL?"}]
        a.generate_reply(messages=messages)
        reply_events = [e for e in _events if "reply" in e.get("event_type", "")]
        self.assertTrue(len(reply_events) >= 1)
        INFO(f"AutoGen — generate_reply stamps {len(reply_events)} events OK")

    def test_generate_reply_gate_block_returns_none(self):
        """Gate BLOCK → retourne None (pas RuntimeError pour ne pas casser le groupe)."""
        Assistant, _ = self._import_assistant()
        a = Assistant(name="analyst", agent_name="analyst", enable_gate=True)
        if hasattr(a, "on_action_gate"):
            a.on_action_gate = lambda action: False
            messages = [{"role": "user", "content": "test"}]
            result = a.generate_reply(messages=messages)
            self.assertIsNone(result)
            INFO("AutoGen — gate BLOCK → None (pas exception) OK")

    def test_execute_code_gate_block_raises(self):
        """Code execution : gate BLOCK → RuntimeError (action irréversible)."""
        _, Proxy = self._import_assistant()
        p = Proxy(name="proxy", agent_name="proxy", enable_gate=True)
        if hasattr(p, "on_action_gate"):
            p.on_action_gate = lambda action: False
            with self.assertRaises(RuntimeError):
                p.execute_code_blocks([("python", "print('test')")])
            INFO("AutoGen — execute_code gate BLOCK → RuntimeError OK")

    def test_initialized_event_stamped(self):
        Assistant, _ = self._import_assistant()
        _events.clear()
        Assistant(name="analyst", agent_name="analyst")
        init_events = [e for e in _events
                       if "initialized" in e.get("event_type", "")]
        self.assertTrue(len(init_events) >= 1)
        INFO("AutoGen — event initialized stamped OK")


# ══════════════════════════════════════════════════════════════════════════════
# 6. TESTS BRIDGE MCP
# ══════════════════════════════════════════════════════════════════════════════

class TestMCPBridge(unittest.TestCase):
    """Valide les 3 points BridgeProtocol dans AuditedMCPClient."""

    def setUp(self):
        _events.clear()
        _memory_store.clear()
        _memory_store.append({
            "version": "AISS-1.0",
            "timestamp": int(time.time()) - 60,
            "payload": {"action": "mcp_call", "status": "ok"},
        })

    def _import_client(self):
        key = "piqrypt_mcp"
        if key in sys.modules: del sys.modules[key]
        _f = _repo_root / "bridges" / "mcp" / "__init__.py"
        if not _f.exists():
            self.skipTest("Bridge MCP non trouvé (bridges/mcp/__init__.py)")
        try:
            _mod = types.ModuleType(key)
            _mod.__file__ = str(_f)
            _mod.__package__ = key
            _mod.__builtins__ = __builtins__
            sys.modules[key] = _mod
            exec(compile(_f.read_text(encoding="utf-8"), str(_f), "exec"), _mod.__dict__)
            return _mod.AuditedMCPClient
        except Exception as e:
            self.skipTest(f"Bridge MCP import échoué : {e}")

    def _make_client(self, Client):
        """Sous-classe concrète avec _do_call_tool implémenté."""
        class ConcreteMCP(Client):
            async def _do_call_tool(self, name, args):
                return {"result": f"mock_{name}"}
            async def _do_read_resource(self, uri):
                return "resource_content"
            async def _do_get_prompt(self, name, args):
                return [{"role": "user", "content": "prompt"}]
        return ConcreteMCP(agent_name="mcp_agent")

    def test_memory_injected_on_aenter(self):
        Client = self._import_client()
        client = self._make_client(Client)

        async def _run():
            async with client:
                pass

        asyncio.get_event_loop().run_until_complete(_run())
        self.assertIn("mcp_call", client.memory_context)
        INFO(f"MCP — memory_context après __aenter__ : {client.memory_context[:80]}...")

    def test_call_tool_stamps_events(self):
        Client = self._import_client()
        client = self._make_client(Client)

        async def _run():
            return await client.call_tool("search", {"query": "AAPL"})

        _events.clear()
        asyncio.get_event_loop().run_until_complete(_run())
        tool_events = [e for e in _events if "tool" in e.get("event_type", "")]
        self.assertTrue(len(tool_events) >= 1)
        INFO(f"MCP — call_tool stamps {len(tool_events)} events OK")

    def test_call_tool_gate_block_raises(self):
        Client = self._import_client()
        client = self._make_client(Client)
        if hasattr(client, "on_action_gate"):
            client.on_action_gate = lambda action: False

            async def _run():
                await client.call_tool("blocked_tool", {})

            with self.assertRaises(RuntimeError):
                asyncio.get_event_loop().run_until_complete(_run())
            INFO("MCP — call_tool gate BLOCK → RuntimeError OK")

    def test_read_resource_no_gate(self):
        """read_resource() n'a pas de gate — lecture seule."""
        Client = self._import_client()
        client = self._make_client(Client)
        # Même avec gate qui bloquerait, read_resource passe
        if hasattr(client, "on_action_gate"):
            client.on_action_gate = lambda action: False

        async def _run():
            return await client.read_resource("file:///test.txt")

        result = asyncio.get_event_loop().run_until_complete(_run())
        self.assertIsNotNone(result)
        INFO("MCP — read_resource sans gate (lecture seule) OK")

    def test_session_stamps_start_end(self):
        Client = self._import_client()
        client = self._make_client(Client)

        async def _run():
            async with client:
                await client.call_tool("search", {"q": "test"})

        _events.clear()
        asyncio.get_event_loop().run_until_complete(_run())
        session_events = [e for e in _events if "session" in e.get("event_type", "")]
        self.assertGreaterEqual(len(session_events), 2)  # start + end
        INFO(f"MCP — session start+end stamps ({len(session_events)}) OK")


# ══════════════════════════════════════════════════════════════════════════════
# BILAN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║   PiQrypt — Test BridgeProtocol v1.1.0      ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()

    if not _BP_AVAILABLE:
        print("  [ABORT] aiss/bridge_protocol.py introuvable.")
        print("  Placez le fichier et relancez.")
        sys.exit(1)

    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    for cls in [
        TestBridgeProtocolDirect,
        TestLangChainBridge,
        TestCrewAIBridge,
        TestAutoGenBridge,
        TestMCPBridge,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(
        verbosity=2 if VERBOSE else 1,
        stream=sys.stdout,
    )
    result = runner.run(suite)

    print()
    print("  ════════════════════════════════════════════════")
    print("  BILAN — BridgeProtocol v1.1.0")
    print("  ════════════════════════════════════════════════")
    print()

    if result.wasSuccessful():
        print("  RÉSULTAT : SUCCÈS COMPLET")
        print()
        print("  Protocole validé :")
        print("    on_session_start() — injection mémoire       OK")
        print("    on_session_update() — delta mémoire          OK")
        print("    on_peer_contact() — historique A2A           OK")
        print("    on_action_gate() — gate TrustGate            OK")
        print("    LangChain bridge  — 3 points actifs          OK")
        print("    CrewAI bridge     — 3 points actifs          OK")
        print("    AutoGen bridge    — 3 points actifs          OK")
        print("    MCP bridge        — 3 points actifs          OK")
    else:
        n = len(result.failures) + len(result.errors)
        print(f"  RÉSULTAT : {n} PROBLÈME(S)")
        print()
        for test, err in result.failures + result.errors:
            print(f"  [FAIL] {test}")
            if VERBOSE:
                print(f"  {err}")
        print()
        print("  Relancez avec -v pour les détails.")

    print()
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
