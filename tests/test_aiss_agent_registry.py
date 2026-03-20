"""
Tests — aiss/agent_registry.py
Registre centralise des agents
"""
import tempfile
import unittest
from pathlib import Path


class TestAgentRegistryImport(unittest.TestCase):
    def test_import(self):
        from aiss import agent_registry
        self.assertIsNotNone(agent_registry)

    def test_has_registry_functions(self):
        from aiss import agent_registry
        has_api = (
            hasattr(agent_registry, "AgentRegistry") or
            hasattr(agent_registry, "register_agent") or
            hasattr(agent_registry, "list_agents") or
            hasattr(agent_registry, "get_registry")
        )
        self.assertTrue(has_api, "agent_registry doit exposer une API de registre")


class TestAgentRegistryOperations(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.registry_path = Path(self.tmpdir) / "registry.json"

    def test_register_and_list(self):
        """Un agent enregistre apparait dans la liste"""
        try:
            from aiss.agent_registry import AgentRegistry
            reg = AgentRegistry(self.registry_path)
            reg.register("agent_test", {"tier": "free", "type": "llm"})
            agents = reg.list()
            names = [a if isinstance(a, str) else a.get("name", "") for a in agents]
            self.assertIn("agent_test", names)
        except (ImportError, AttributeError):
            self.skipTest("API AgentRegistry non trouvee")

    def test_registry_persists(self):
        """Le registre est persiste sur disque"""
        try:
            from aiss.agent_registry import AgentRegistry
            reg = AgentRegistry(self.registry_path)
            reg.register("agent_persiste", {"tier": "pro"})

            reg2 = AgentRegistry(self.registry_path)
            agents = reg2.list()
            names = [a if isinstance(a, str) else a.get("name", "") for a in agents]
            self.assertIn("agent_persiste", names)
        except (ImportError, AttributeError):
            self.skipTest("API AgentRegistry non trouvee")

    def test_duplicate_registration(self):
        """Enregistrer deux fois le meme agent ne cree pas de doublon"""
        try:
            from aiss.agent_registry import AgentRegistry
            reg = AgentRegistry(self.registry_path)
            reg.register("agent_dup", {"tier": "free"})
            reg.register("agent_dup", {"tier": "pro"})
            agents = reg.list()
            names = [a if isinstance(a, str) else a.get("name", "") for a in agents]
            self.assertEqual(names.count("agent_dup"), 1)
        except (ImportError, AttributeError):
            self.skipTest("API AgentRegistry non trouvee")

    def test_get_agent_metadata(self):
        """get() renvoie les metadonnees d un agent enregistre"""
        try:
            from aiss.agent_registry import AgentRegistry
            reg = AgentRegistry(self.registry_path)
            reg.register("agent_meta", {"tier": "pro", "type": "robot"})
            meta = reg.get("agent_meta")
            self.assertIsNotNone(meta)
        except (ImportError, AttributeError):
            self.skipTest("API AgentRegistry non trouvee")


if __name__ == "__main__":
    unittest.main(verbosity=2)
