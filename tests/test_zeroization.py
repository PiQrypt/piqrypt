# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — B.7 : effacement au mieux des clés privées intermédiaires.

Ces tests vérifient que les bytearray tenus par le code sont remis à zéro, y compris
en cas d'échec. Ils ne prouvent PAS l'absence de copies ailleurs en mémoire (bytes
immuables, copies des bibliothèques, swap) : l'effacement réduit la fenêtre
d'exposition, il ne la supprime pas.
"""
import nacl.signing  # noqa: F401

import tempfile
import unittest
from contextlib import contextmanager
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


@contextmanager
def _spy_erase():
    """Enregistre chaque tampon passé à _secure_erase (puis l'efface réellement)."""
    import aiss.key_store as ks
    seen = []
    real = ks._secure_erase

    def spy(buf):
        seen.append(buf)
        real(buf)

    with patch.object(ks, "_secure_erase", side_effect=spy):
        yield seen


def _sizes(seen):
    return sorted(len(b) for b in seen)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = patch("aiss.key_store._SCRYPT_N", 2 ** 10)
        p.start()
        self.addCleanup(p.stop)

    def assertAllZero(self, seen):
        self.assertTrue(seen)
        for buf in seen:
            self.assertIsInstance(buf, bytearray)
            self.assertEqual(bytes(buf), b"\x00" * len(buf))


class TestKeyStoreV2(_Base):

    def test_derived_aes_key_and_passphrase_bytes_are_erased(self):
        import secrets
        from aiss.key_store import encrypt_pq_private_key, decrypt_pq_private_key
        key = secrets.token_bytes(4032)
        with _spy_erase() as seen:
            blob = encrypt_pq_private_key(key, PASSPHRASE, n_log2=10)
            self.assertEqual(decrypt_pq_private_key(blob, PASSPHRASE), key)
        # par opération : octets de la passphrase + clé AES de 32 octets
        self.assertAllZero(seen)
        self.assertEqual(_sizes(seen).count(32), 2)
        self.assertEqual(_sizes(seen).count(len(PASSPHRASE)), 2)

    def test_erased_even_when_passphrase_is_wrong(self):
        import secrets
        from aiss.key_store import encrypt_pq_private_key, decrypt_pq_private_key, InvalidPassphraseError
        blob = encrypt_pq_private_key(secrets.token_bytes(4032), PASSPHRASE, n_log2=10)
        with _spy_erase() as seen:
            with self.assertRaises(InvalidPassphraseError):
                decrypt_pq_private_key(blob, "mauvaise passphrase")
        self.assertAllZero(seen)

    def test_public_return_types_unchanged(self):
        import secrets
        from aiss.key_store import encrypt_pq_private_key, decrypt_pq_private_key
        key = secrets.token_bytes(4032)
        blob = encrypt_pq_private_key(bytearray(key), PASSPHRASE, n_log2=10)
        self.assertIs(type(blob), bytes)
        self.assertIs(type(decrypt_pq_private_key(blob, PASSPHRASE)), bytes)


@pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")
class TestHybridFlows(_Base):

    def test_create_hybrid_erases_both_private_keys(self):
        from aiss.identity import create_agent_identity
        with _spy_erase() as seen:
            create_agent_identity("z1", passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        self.assertAllZero(seen)
        self.assertIn(32, _sizes(seen))
        self.assertIn(4032, _sizes(seen))

    def test_create_hybrid_erases_even_on_failure(self):
        from aiss.identity import create_agent_identity
        with _spy_erase() as seen:
            with patch("aiss.key_store.save_encrypted_pq_key", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    create_agent_identity("z2", passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        self.assertAllZero(seen)
        self.assertIn(4032, _sizes(seen))

    def test_upgrade_erases_both_private_keys_and_still_works(self):
        from aiss.identity import create_agent_identity, upgrade_agent_identity, verify_identity_binding
        create_agent_identity("z3", passphrase=PASSPHRASE, base_dir=self.tmp)
        with _spy_erase() as seen:
            r = upgrade_agent_identity("z3", PASSPHRASE, PASSPHRASE, base_dir=self.tmp)
        self.assertTrue(verify_identity_binding(r["identity"]))
        self.assertAllZero(seen)
        self.assertIn(4032, _sizes(seen))
        self.assertGreaterEqual(_sizes(seen).count(32), 2)  # clé Ed25519 + clé AES

    def test_upgrade_erases_even_on_failure(self):
        from aiss.identity import create_agent_identity, upgrade_agent_identity
        create_agent_identity("z4", passphrase=PASSPHRASE, base_dir=self.tmp)
        with _spy_erase() as seen:
            with patch("aiss.identity._atomic_write_json", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    upgrade_agent_identity("z4", PASSPHRASE, PASSPHRASE, base_dir=self.tmp)
        self.assertAllZero(seen)
        self.assertIn(4032, _sizes(seen))

    def test_secure_agent_key_erases_decrypted_keys(self):
        from aiss.identity import create_agent_identity, secure_agent_key
        create_agent_identity("z5", passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        with _spy_erase() as seen:
            secure_agent_key("z5", "nouvelle passphrase", PASSPHRASE, base_dir=self.tmp)
        self.assertAllZero(seen)
        self.assertIn(4032, _sizes(seen))
        self.assertIn(32, _sizes(seen))

    def test_secure_agent_key_erases_even_on_failure(self):
        from aiss.identity import create_agent_identity, secure_agent_key
        create_agent_identity("z6", passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        with _spy_erase() as seen:
            with patch("os.fsync", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    secure_agent_key("z6", "nouvelle passphrase", PASSPHRASE, base_dir=self.tmp)
        self.assertAllZero(seen)

    def test_rotation_accepts_bytearray_private_keys(self):
        from aiss.crypto import ed25519, dilithium
        from aiss.identity import (
            create_agent_identity, create_rotation_attestation_hybrid,
            verify_rotation_attestation_hybrid, load_agent_pq_key)
        from aiss.key_store import load_encrypted_key
        r = create_agent_identity("z7", passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        d = Path(self.tmp) / "agents" / "z7"
        prev_ed = bytearray(load_encrypted_key(d / "private.key.enc", PASSPHRASE))
        prev_pq = bytearray(load_agent_pq_key("z7", PASSPHRASE, base_dir=self.tmp))
        n_ed, n_pub_ed = ed25519.generate_keypair()
        n_pq, n_pub_pq = dilithium.generate_keypair()
        bufs = [prev_ed, prev_pq, bytearray(n_ed), bytearray(n_pq)]
        att = create_rotation_attestation_hybrid(
            r["identity"], bufs[0], bufs[1], bufs[2], n_pub_ed, bufs[3], n_pub_pq)
        self.assertTrue(verify_rotation_attestation_hybrid(att, r["identity"]))
        from aiss.key_store import _secure_erase
        for b in bufs:
            _secure_erase(b)
            self.assertEqual(bytes(b), b"\x00" * len(b))


if __name__ == "__main__":
    unittest.main()
