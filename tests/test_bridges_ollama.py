# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — bridges/ollama/
Bridge AuditedOllama — piqrypt-ollama

ENVIRONNEMENT REQUIS :
  pip install piqrypt[ollama]   (installe le bridge + ollama)
  ollama serve                  (serveur Ollama en cours d'exécution)

Ces tests utilisent des mocks complets pour piqrypt et ollama —
ils ne nécessitent ni Ollama installé, ni serveur en cours.
Si le bridge (piqrypt_ollama) n'est pas trouvé, les tests
sont skippés proprement avec raison explicite.

Status CI : SKIP si bridge absent — pas un échec.
Pour exclure complètement : pytest -k "not ollama"
"""

import hashlib
import json
import sys
import time
import types
import unittest
from pathlib import Path

# ── Chemins ───────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bridges" / "ollama"))

# ── Mocks piqrypt + ollama ────────────────────────────────────────────────────

def _install_mocks():
    """
    Installe des mocks complets pour piqrypt et ollama.
    Permet d'exécuter les tests sans dépendances réelles.
    """
    events = []

    # Mock piqrypt
    mock_piqrypt = types.ModuleType("piqrypt")
    mock_piqrypt.generate_keypair   = lambda: (b"k" * 32, b"p" * 32)
    mock_piqrypt.derive_agent_id    = lambda pub: "AGENT_" + hashlib.sha256(pub).hexdigest()[:8]
    mock_piqrypt.load_identity      = lambda f: {
        "private_key_bytes": b"k" * 32,
        "agent_id": "AGENT_TEST"
    }
    mock_piqrypt.stamp_event        = lambda key, aid, payload: {
        **payload,
        "_sig": "mock_sig",
        "_ts": time.time(),
        "agent_id": aid,
    }
    mock_piqrypt.store_event        = lambda e: events.append(e)
    mock_piqrypt.compute_event_hash = lambda e: hashlib.sha256(
        json.dumps(e, default=str, sort_keys=True).encode()
    ).hexdigest()
    mock_piqrypt.export_audit_chain = lambda path: open(path, "w").write(
        json.dumps(events)
    )
    sys.modules["piqrypt"] = mock_piqrypt

    # Mock ollama
    class MockOllamaClient:
        def __init__(self, host=None):
            pass

        def generate(self, **kw):
            if kw.get("stream"):
                return iter([
                    {"response": "Hello ", "done": False},
                    {"response": "world!", "done": True},
                ])
            return {
                "response": "Paris",
                "done": True,
                "eval_count": 5,
                "prompt_eval_count": 3,
            }

        def chat(self, **kw):
            if kw.get("stream"):
                return iter([
                    {"message": {"role": "assistant", "content": "Hi"}, "done": True}
                ])
            tool_calls = []
            msgs = kw.get("messages", [])
            if (msgs and
                    "weather" in msgs[-1].get("content", "").lower() and
                    kw.get("tools")):
                tool_calls = [{
                    "function": {
                        "name": "get_weather",
                        "arguments": {"city": "Paris"},
                    }
                }]
            return {
                "message": {
                    "role": "assistant",
                    "content": "OK!",
                    "tool_calls": tool_calls,
                },
                "done": True,
            }

    mock_ollama = types.ModuleType("ollama")
    mock_ollama.Client = MockOllamaClient
    sys.modules["ollama"] = mock_ollama

    return events


_events = _install_mocks()


# ── Détection du bridge ───────────────────────────────────────────────────────

def _get_audited_ollama_class():
    """
    Tente d'importer AuditedOllama depuis le bridge.
    Retourne la classe ou None si le bridge est absent.
    """
    # Tentative 1 : nom de package installé
    try:
        from piqrypt_ollama import AuditedOllama
        return AuditedOllama
    except ImportError:
        pass

    # Tentative 2 : module local bridges/ollama/
    try:
        import importlib.util
        bridge_path = ROOT / "bridges" / "ollama" / "__init__.py"
        if bridge_path.exists():
            spec = importlib.util.spec_from_file_location("piqrypt_ollama", bridge_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return getattr(mod, "AuditedOllama", None)
    except Exception:
        pass

    return None


_BRIDGE_SKIP_REASON = (
    "Bridge piqrypt-ollama non trouvé.\n"
    "Pour l'installer : pip install piqrypt[ollama]\n"
    "Ces tests sont optionnels — ils ne bloquent pas la CI.\n"
    "Pour les exclure : pytest -k 'not ollama'"
)

AuditedOllamaClass = _get_audited_ollama_class()


# ══════════════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestBridgeImport(unittest.TestCase):
    """Vérifie que le bridge est importable."""

    def test_bridge_importable(self):
        if AuditedOllamaClass is None:
            self.skipTest(_BRIDGE_SKIP_REASON)
        self.assertIsNotNone(AuditedOllamaClass)

    def test_bridge_has_required_methods(self):
        if AuditedOllamaClass is None:
            self.skipTest(_BRIDGE_SKIP_REASON)
        for method in ["generate", "chat"]:
            self.assertTrue(
                hasattr(AuditedOllamaClass, method),
                f"AuditedOllama manque la méthode '{method}'"
            )


class TestAuditedOllamaGenerate(unittest.TestCase):
    """Tests de la méthode generate()."""

    def setUp(self):
        if AuditedOllamaClass is None:
            self.skipTest(_BRIDGE_SKIP_REASON)
        _events.clear()
        self.llm = AuditedOllamaClass(model="llama3.2", agent_name="test_agent")
        _events.clear()

    def test_generate_returns_response(self):
        result = self.llm.generate("Capital of France?")
        self.assertIn("response", result,
            "generate() doit retourner un dict avec 'response'")

    def test_generate_stamps_at_least_one_event(self):
        _events.clear()
        self.llm.generate("Hello")
        self.assertGreater(len(_events), 0,
            "generate() doit stamper au moins un événement AISS")

    def test_generate_streaming_yields_chunks(self):
        chunks = list(self.llm.generate("Tell me a story", stream=True))
        self.assertGreater(len(chunks), 0,
            "generate() en mode stream doit yielder des chunks")


class TestAuditedOllamaChat(unittest.TestCase):
    """Tests de la méthode chat()."""

    def setUp(self):
        if AuditedOllamaClass is None:
            self.skipTest(_BRIDGE_SKIP_REASON)
        _events.clear()
        self.llm = AuditedOllamaClass(model="llama3.2", agent_name="test_agent")
        _events.clear()

    def test_chat_stamps_events(self):
        _events.clear()
        self.llm.chat([{"role": "user", "content": "Bonjour"}])
        self.assertGreater(len(_events), 0,
            "chat() doit stamper au moins un événement AISS")

    def test_chat_streaming(self):
        chunks = list(self.llm.chat(
            [{"role": "user", "content": "Hi"}],
            stream=True
        ))
        self.assertGreater(len(chunks), 0,
            "chat() en mode stream doit yielder des chunks")


class TestAuditedOllamaChaining(unittest.TestCase):
    """Vérifie que les événements sont hash-chainés."""

    def setUp(self):
        if AuditedOllamaClass is None:
            self.skipTest(_BRIDGE_SKIP_REASON)
        _events.clear()
        self.llm = AuditedOllamaClass(model="llama3.2", agent_name="test_agent")
        _events.clear()

    def test_events_are_chained(self):
        """Après 2 appels, au moins un événement doit référencer le précédent."""
        _events.clear()
        self.llm.generate("First call")
        self.llm.generate("Second call")
        self.assertGreaterEqual(len(_events), 2,
            "2 appels doivent produire au moins 2 événements")
        chained = [e for e in _events if "previous_event_hash" in e]
        self.assertGreater(len(chained), 0,
            "Les événements doivent être hash-chainés (previous_event_hash présent)")

    def test_events_have_agent_id(self):
        """Chaque événement doit porter l'agent_id."""
        _events.clear()
        self.llm.generate("Test")
        for event in _events:
            self.assertIn("agent_id", event,
                "Chaque événement doit avoir un agent_id")


if __name__ == "__main__":
    unittest.main(verbosity=2)
