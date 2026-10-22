# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""Tests — IdentitySession.unlock : effacement de la clé en cas d'échec, hybride natif."""
import nacl.signing  # noqa: F401

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

PASSPHRASE = "correct horse battery"


def _pq_available():
    try:
        from aiss.crypto import dilithium
        return dilithium is not None and dilithium.is_available()
    except Exception:
        return False


class TestUnlockFailure(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = patch("aiss.key_store._SCRYPT_N", 2 ** 10)
        p.start()
        self.addCleanup(p.stop)
        p = patch("aiss.identity_session.AGENTS_DIR", Path(self.tmp) / "agents")
        p.start()
        self.addCleanup(p.stop)

    def test_key_is_erased_when_identity_loading_fails(self):
        from aiss.identity import create_agent_identity
        from aiss.identity_session import IdentitySession, KeyFileCorruptedError
        import aiss.identity_session as mod

        create_agent_identity("a", passphrase=PASSPHRASE, base_dir=self.tmp)
        (Path(self.tmp) / "agents" / "a" / "identity.json").write_text("{pas du json")

        captured = []
        real_erase = mod._secure_erase
        def spy(buf):
            captured.append(buf)
            real_erase(buf)

        session = IdentitySession()
        with patch.object(mod, "_secure_erase", side_effect=spy):
            with self.assertRaises(KeyFileCorruptedError):
                session.unlock("a", PASSPHRASE)

        self.assertEqual(len(captured), 1)
        self.assertEqual(len(captured[0]), 32)
        self.assertEqual(bytes(captured[0]), b"\x00" * 32)
        self.assertIsNone(session._private_key)
        self.assertTrue(session.is_locked)

    def test_successful_unlock_still_works(self):
        from aiss.identity import create_agent_identity
        from aiss.identity_session import IdentitySession
        r = create_agent_identity("ok", passphrase=PASSPHRASE, base_dir=self.tmp)
        with IdentitySession.open("ok", PASSPHRASE) as s:
            self.assertEqual(s.agent_id, r["agent_id"])
            self.assertEqual(len(s.sign(b"x")), 64)
        self.assertTrue(s.is_locked)

    @pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")
    def test_native_hybrid_is_rejected_before_decrypting_the_key(self):
        from aiss.identity import create_agent_identity
        from aiss.identity_session import IdentitySession, UnsupportedIdentityError
        import aiss.identity_session as mod

        create_agent_identity("hy", passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        with patch.object(mod, "load_encrypted_key") as loader:
            with self.assertRaises(UnsupportedIdentityError) as ctx:
                IdentitySession().unlock("hy", PASSPHRASE)
            loader.assert_not_called()
        self.assertIn("non prise en charge par IdentitySession en 1.10", str(ctx.exception))

    @pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")
    def test_upgraded_identity_still_unlocks(self):
        from aiss.identity import create_agent_identity, upgrade_agent_identity
        from aiss.identity_session import IdentitySession
        r = create_agent_identity("up", passphrase=PASSPHRASE, base_dir=self.tmp)
        upgrade_agent_identity("up", PASSPHRASE, PASSPHRASE, base_dir=self.tmp)
        with IdentitySession.open("up", PASSPHRASE) as s:
            self.assertEqual(s.agent_id, r["agent_id"])


if __name__ == "__main__":
    unittest.main()
