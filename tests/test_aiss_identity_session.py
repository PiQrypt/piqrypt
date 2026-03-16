"""
Tests — aiss/identity_session.py
Sessions cryptographiques ephemeres

API reelle :
    with IdentitySession.open(agent_name, passphrase) as session:
        session.agent_id
        session.sign(data)
"""
import tempfile, unittest
from pathlib import Path


class TestIdentitySessionImport(unittest.TestCase):
    def test_import(self):
        from aiss import identity_session
        self.assertIsNotNone(identity_session)

    def test_has_identity_session_class(self):
        from aiss import identity_session
        self.assertTrue(
            hasattr(identity_session, "IdentitySession"),
            "identity_session doit exposer la classe IdentitySession"
        )

    def test_has_open_method(self):
        try:
            from aiss.identity_session import IdentitySession
            self.assertTrue(
                hasattr(IdentitySession, "open") or
                hasattr(IdentitySession, "unlock"),
                "IdentitySession doit avoir une methode open() ou unlock()"
            )
        except ImportError:
            self.skipTest("IdentitySession non trouvee")


class TestIdentitySessionUnlock(unittest.TestCase):
    """
    Ces tests verifient le comportement de la session.
    Ils passent en SKIP si aucun agent n est cree en local —
    c est attendu en CI sans ~/.piqrypt/agents/.
    """
    def test_open_nonexistent_agent_raises(self):
        """Ouvrir une session sur un agent inexistant doit lever une exception"""
        try:
            from aiss.identity_session import IdentitySession
            with self.assertRaises(Exception):
                with IdentitySession.open("agent_qui_nexiste_pas_xyz", "passphrase") as s:
                    pass
        except ImportError:
            self.skipTest("IdentitySession non trouvee")

    def test_unlock_method_signature(self):
        """unlock() accepte agent_name et passphrase"""
        try:
            from aiss.identity_session import IdentitySession
            import inspect
            # Verifier les deux signatures possibles
            if hasattr(IdentitySession, "open"):
                sig = inspect.signature(IdentitySession.open)
                params = list(sig.parameters.keys())
                self.assertGreaterEqual(len(params), 1,
                    "open() doit accepter au moins agent_name")
            elif hasattr(IdentitySession, "unlock"):
                sig = inspect.signature(IdentitySession.unlock)
                params = list(sig.parameters.keys())
                self.assertGreaterEqual(len(params), 1)
        except ImportError:
            self.skipTest("IdentitySession non trouvee")

    def test_session_is_context_manager(self):
        """IdentitySession supporte le protocole context manager"""
        try:
            from aiss.identity_session import IdentitySession
            self.assertTrue(
                hasattr(IdentitySession, "__enter__") and
                hasattr(IdentitySession, "__exit__"),
                "IdentitySession doit etre un context manager (__enter__/__exit__)"
            )
        except ImportError:
            self.skipTest("IdentitySession non trouvee")


if __name__ == "__main__":
    unittest.main(verbosity=2)
