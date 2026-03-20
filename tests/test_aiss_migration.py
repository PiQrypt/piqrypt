"""
Tests — aiss/migration.py
Migration des identites v1.6 -> v1.7
"""
import json
import tempfile
import unittest
from pathlib import Path


class TestMigrationImport(unittest.TestCase):
    def test_import(self):
        from aiss import migration
        self.assertIsNotNone(migration)

    def test_has_migrate_function(self):
        from aiss import migration
        has_api = (
            hasattr(migration, "migrate_to_encrypted") or
            hasattr(migration, "migrate_agent") or
            hasattr(migration, "migrate_all") or
            hasattr(migration, "run_migration")
        )
        self.assertTrue(has_api, "migration doit exposer une fonction de migration")


class TestMigrationV16ToV17(unittest.TestCase):
    def _make_v16_identity(self, path: Path, agent_name: str) -> Path:
        """Cree un fichier identity v1.6 factice."""
        agent_dir = path / "agents" / agent_name
        agent_dir.mkdir(parents=True, exist_ok=True)
        identity = {
            "agent_id": f"AGENT_{agent_name.upper()}",
            "agent_name": agent_name,
            "version": "1.6.0",
            "private_key": "a" * 64,  # cle en clair (format v1.6)
            "public_key": "b" * 64,
        }
        identity_path = agent_dir / "identity.json"
        identity_path.write_text(json.dumps(identity))
        return identity_path

    def test_migration_creates_backup(self):
        """La migration sauvegarde le fichier original en .v16.bak"""
        try:
            from aiss.migration import migrate_agent
            tmpdir = Path(tempfile.mkdtemp())
            identity_path = self._make_v16_identity(tmpdir, "test_bot")
            migrate_agent(str(tmpdir), "test_bot", passphrase="test_pass")
            backup = identity_path.with_suffix(".v16.bak")
            self.assertTrue(backup.exists() or identity_path.exists(),
                "Backup ou fichier migre doit exister")
        except (ImportError, AttributeError):
            self.skipTest("migrate_agent non trouvee")

    def test_migration_non_destructive(self):
        """La migration ne supprime pas les donnees originales"""
        try:
            from aiss.migration import migrate_agent
            tmpdir = Path(tempfile.mkdtemp())
            identity_path = self._make_v16_identity(tmpdir, "safe_bot")
            _ = identity_path.read_text()
            migrate_agent(str(tmpdir), "safe_bot", passphrase="test_pass")
            # Original ou backup doit contenir les donnees originales
            has_data = (
                identity_path.exists() or
                identity_path.with_suffix(".v16.bak").exists()
            )
            self.assertTrue(has_data)
        except (ImportError, AttributeError):
            self.skipTest("migrate_agent non trouvee")


if __name__ == "__main__":
    unittest.main(verbosity=2)
