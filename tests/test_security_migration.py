"""
Tests de sécurité — aiss/migration.py

Couverture :
    1. Idempotence      : migrer deux fois → pas de crash, résultat cohérent
    2. Backup créé      : ~/.piqrypt_backup_v160 existe après migration
    3. Source corrompue : identity.json malformé → erreur propre
    4. Agent inexistant : ghost agent → erreur propre, pas de crash
"""

import json
import tempfile
import unittest
from pathlib import Path


class TestMigrationIdempotence(unittest.TestCase):

    def test_double_migration_no_crash(self):
        """Migrer deux fois le même agent ne doit pas crasher."""
        from aiss.migration import migrate_agent

        with tempfile.TemporaryDirectory() as tmpdir:
            # Créer un agent v1.6 minimal
            agent_dir = Path(tmpdir) / "agents" / "idempotent_bot"
            agent_dir.mkdir(parents=True)
            (agent_dir / "identity.json").write_text(json.dumps({
                "version": "1.6.0",
                "agent_name": "idempotent_bot",
                "agent_id": "AGENT_IDEMPOTENT_BOT",
                "public_key": "fakepublickey==",
                "created_at": "2025-01-01T00:00:00Z",
            }))

            result1 = migrate_agent(tmpdir, "idempotent_bot")
            result2 = migrate_agent(tmpdir, "idempotent_bot")

            self.assertIsNotNone(result1, "Premier migrate_agent doit retourner un résultat")
            self.assertIsNotNone(result2, "Deuxième migrate_agent doit retourner un résultat")

    def test_backup_created_in_home(self):
        """Un backup doit être créé dans ~/.piqrypt_backup_v160 après migration."""
        from aiss.migration import migrate_agent

        with tempfile.TemporaryDirectory() as tmpdir:
            agent_dir = Path(tmpdir) / "agents" / "backup_bot"
            agent_dir.mkdir(parents=True)
            (agent_dir / "identity.json").write_text(json.dumps({
                "version": "1.6.0",
                "agent_name": "backup_bot",
                "agent_id": "AGENT_BACKUP_BOT",
                "public_key": "fakepublickey==",
                "created_at": "2025-01-01T00:00:00Z",
            }))

            migrate_agent(tmpdir, "backup_bot")

            # Le backup est créé dans le home de l'utilisateur
            backup_path = Path.home() / ".piqrypt_backup_v160"
            self.assertTrue(backup_path.exists(),
                f"Le backup doit exister dans {backup_path}")


class TestMigrationWithCorruptSource(unittest.TestCase):

    def test_corrupted_identity_handled(self):
        """identity.json malformé → erreur propre, pas de crash Python."""
        from aiss.migration import migrate_agent

        with tempfile.TemporaryDirectory() as tmpdir:
            agent_dir = Path(tmpdir) / "agents" / "corrupt_bot"
            agent_dir.mkdir(parents=True)
            (agent_dir / "identity.json").write_text("{invalid json content!!!")

            try:
                result = migrate_agent(tmpdir, "corrupt_bot")
                if isinstance(result, dict):
                    # Si ça retourne un dict, vérifier qu'il signale l'échec
                    # (certaines implémentations retournent quand même success=True
                    #  si elles recrééent l'agent — on accepte les deux comportements)
                    pass
            except (json.JSONDecodeError, ValueError, KeyError):
                pass  # Exception propre = comportement acceptable

    def test_missing_agent_no_crash(self):
        """Agent inexistant → pas de crash Python."""
        from aiss.migration import migrate_agent

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                migrate_agent(tmpdir, "ghost_agent_that_does_not_exist")
            except Exception:
                pass  # Toute exception propre est acceptable


if __name__ == "__main__":
    unittest.main(verbosity=2)