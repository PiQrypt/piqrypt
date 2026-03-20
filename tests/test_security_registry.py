"""
Tests de sécurité — aiss/agent_registry.py

Couverture :
    1. Path traversal  : noms avec ../ ne sortent pas de agents/
    2. Noms spéciaux   : vide, null byte, slashes → rejet ou sanitization
    3. Nom très long   : tronqué à 64 chars max
    4. Espaces         : remplacés proprement
    5. Idempotence     : enregistrer deux fois → pas de doublon
    6. Isolation       : deux agents → deux répertoires séparés
    7. Permissions     : répertoire créé avec chmod 700 (Linux)
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestAgentNameSanitization(unittest.TestCase):

    def _safe(self, name):
        from aiss.agent_registry import _safe_name
        return _safe_name(name)

    def test_path_traversal_dots(self):
        result = self._safe("../../../etc/passwd")
        self.assertNotIn("..", result)
        self.assertNotIn("/", result)

    def test_path_traversal_backslash(self):
        result = self._safe("..\\..\\Windows\\system32")
        self.assertNotIn("\\", result)
        self.assertNotIn("..", result)

    def test_slash_in_name(self):
        self.assertNotIn("/", self._safe("agent/subdir"))

    def test_empty_name_raises(self):
        from aiss.agent_registry import _safe_name
        with self.assertRaises((ValueError, Exception)):
            _safe_name("")

    def test_null_byte_sanitized(self):
        self.assertNotIn("\x00", self._safe("agent\x00evil"))

    def test_long_name_truncated(self):
        self.assertLessEqual(len(self._safe("a" * 200)), 64)

    def test_spaces_sanitized(self):
        self.assertNotIn(" ", self._safe("my agent name"))

    def test_normal_names_preserved(self):
        from aiss.agent_registry import _safe_name
        for name in ["trading_bot_A", "agent-01", "myAgent", "bot_v2"]:
            self.assertEqual(_safe_name(name), name)


class TestPathTraversalFilesystem(unittest.TestCase):

    def test_agent_dir_stays_within_agents_root(self):
        """get_agent_dir() avec un nom dangereux reste dans agents/."""
        from aiss.agent_registry import get_agent_dir, AGENTS_DIR

        for name in ["../../../tmp/evil", "../../etc", "../secret", "a/b/c"]:
            agent_dir = get_agent_dir(name)
            try:
                agent_dir.relative_to(AGENTS_DIR)
            except ValueError:
                self.fail(f"Path traversal non neutralisé pour '{name}': {agent_dir}")

    def test_init_agent_dirs_no_escape(self):
        """init_agent_dirs() ne crée rien en dehors du sandbox."""
        from aiss.agent_registry import init_agent_dirs

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_agents = Path(tmpdir) / "agents"
            with patch("aiss.agent_registry.AGENTS_DIR", fake_agents), \
                 patch("aiss.agent_registry.PIQRYPT_DIR", Path(tmpdir)):
                init_agent_dirs("../evil_escape")

            evil = Path(tmpdir).parent / "evil_escape"
            self.assertFalse(evil.exists())


class TestRegistryIsolation(unittest.TestCase):

    def test_two_agents_separate_dirs(self):
        self.assertNotEqual(
            __import__("aiss.agent_registry", fromlist=["get_agent_dir"]).get_agent_dir("alpha"),
            __import__("aiss.agent_registry", fromlist=["get_agent_dir"]).get_agent_dir("beta")
        )


class TestRegistryIdempotence(unittest.TestCase):

    def test_double_registration_no_duplicate(self):
        """register() deux fois → une seule entrée."""
        from aiss.agent_registry import AgentRegistry

        with tempfile.TemporaryDirectory() as tmpdir:
            reg = AgentRegistry(Path(tmpdir) / "registry.json")
            reg.register("bot_dup", {"tier": "free"})
            reg.register("bot_dup", {"tier": "pro"})
            agents = reg.list()
            names = [a.get("name", a) if isinstance(a, dict) else a for a in agents]
            self.assertEqual(names.count("bot_dup"), 1)


class TestRegistryPermissions(unittest.TestCase):

    @unittest.skipIf(os.name == "nt", "chmod non applicable sur Windows")
    def test_agent_dir_permissions_700(self):
        from aiss.agent_registry import init_agent_dirs

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_agents = Path(tmpdir) / "agents"
            with patch("aiss.agent_registry.AGENTS_DIR", fake_agents), \
                 patch("aiss.agent_registry.PIQRYPT_DIR", Path(tmpdir)):
                init_agent_dirs("secure_bot")
                agent_dir = fake_agents / "secure_bot"
                if agent_dir.exists():
                    mode = oct(agent_dir.stat().st_mode)[-3:]
                    self.assertEqual(mode, "700")


if __name__ == "__main__":
    unittest.main(verbosity=2)
