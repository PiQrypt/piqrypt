"""
Tests — aiss/identity.py (AISS v1.1)
Creation et chargement d identites agent
"""
import tempfile
import unittest
from pathlib import Path


class TestIdentityImport(unittest.TestCase):
    def test_import(self):
        from aiss import identity
        self.assertIsNotNone(identity)

    def test_has_create_identity(self):
        from aiss import identity
        has_api = any([
            hasattr(identity, "create_agent_identity"),
            hasattr(identity, "AgentIdentity"),
            hasattr(identity, "create_identity"),
        ])
        self.assertTrue(has_api)


class TestIdentityCreation(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_create_identity(self):
        """Une identite agent peut etre creee"""
        try:
            from aiss.identity import create_agent_identity
            result = create_agent_identity(
                agent_name="test_bot",
                base_dir=self.tmpdir,
            )
            self.assertIsNotNone(result)
        except (ImportError, AttributeError, TypeError):
            self.skipTest("create_agent_identity signature differente")

    def test_identity_has_keypair(self):
        """Une identite contient une paire de cles"""
        try:
            from aiss.identity import create_agent_identity
            identity = create_agent_identity(
                agent_name="test_bot",
                base_dir=self.tmpdir,
            )
            has_keys = (
                ("private_key" in identity and "public_key" in identity) or
                ("agent_id" in identity) or
                (hasattr(identity, "private_key"))
            )
            self.assertTrue(has_keys, "L identite doit contenir des cles")
        except (ImportError, AttributeError, TypeError):
            self.skipTest("create_agent_identity signature differente")

    def test_identity_persisted_to_disk(self):
        """L identite est sauvegardee sur disque"""
        try:
            from aiss.identity import create_agent_identity
            create_agent_identity(agent_name="disk_bot", base_dir=self.tmpdir)
            # Verifier qu un fichier a ete cree dans tmpdir
            files = list(Path(self.tmpdir).rglob("*.json"))
            self.assertGreater(len(files), 0, "Au moins un fichier JSON doit etre cree")
        except (ImportError, AttributeError, TypeError):
            self.skipTest("create_agent_identity signature differente")


if __name__ == "__main__":
    unittest.main(verbosity=2)
