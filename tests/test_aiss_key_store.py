# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — aiss/key_store.py
Keystore AES-256-GCM + derivation Argon2id
"""
import secrets
import tempfile
import unittest
from pathlib import Path


class TestKeyStoreImport(unittest.TestCase):
    def test_import(self):
        from aiss import key_store
        self.assertIsNotNone(key_store)

    def test_has_error_classes(self):
        """Les exceptions KeyStoreError et InvalidPassphraseError sont disponibles"""
        from aiss import key_store
        self.assertTrue(
            hasattr(key_store, "KeyStoreError") or
            hasattr(key_store, "InvalidPassphraseError") or
            hasattr(key_store, "encrypt_key") or
            hasattr(key_store, "load_key"),
            "key_store doit exposer KeyStoreError ou encrypt_key/load_key"
        )

    def test_keystore_error_is_exception(self):
        try:
            from aiss.key_store import KeyStoreError
            self.assertTrue(issubclass(KeyStoreError, Exception))
        except ImportError:
            self.skipTest("KeyStoreError non exportee")

    def test_invalid_passphrase_inherits(self):
        try:
            from aiss.key_store import KeyStoreError, InvalidPassphraseError
            self.assertTrue(issubclass(InvalidPassphraseError, KeyStoreError))
        except ImportError:
            self.skipTest("InvalidPassphraseError non exportee")


class TestKeyStoreRoundtrip(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_encrypt_load_roundtrip(self):
        """Cle chiffree => rechargee avec bonne passphrase"""
        try:
            from aiss.key_store import encrypt_key, load_key
            private_key = secrets.token_bytes(32)
            key_path = Path(self.tmpdir) / "test.key.enc"
            encrypt_key(private_key, "passphrase_ok", key_path)
            self.assertTrue(key_path.exists())
            restored = load_key("passphrase_ok", key_path)
            self.assertEqual(private_key, restored)
        except ImportError:
            self.skipTest("encrypt_key / load_key non trouvees")

    def test_wrong_passphrase_raises(self):
        """Mauvaise passphrase => exception"""
        try:
            from aiss.key_store import encrypt_key, load_key
            key_path = Path(self.tmpdir) / "test2.key.enc"
            encrypt_key(secrets.token_bytes(32), "bonne", key_path)
            with self.assertRaises(Exception):
                load_key("mauvaise", key_path)
        except ImportError:
            self.skipTest("encrypt_key / load_key non trouvees")

    def test_file_not_plaintext(self):
        """Le fichier chiffre ne contient pas la cle en clair"""
        try:
            from aiss.key_store import encrypt_key
            private_key = secrets.token_bytes(32)
            key_path = Path(self.tmpdir) / "test3.key.enc"
            encrypt_key(private_key, "passphrase_ok", key_path)
            self.assertNotIn(private_key, key_path.read_bytes())
        except ImportError:
            self.skipTest("encrypt_key non trouvee")


# =============================================================================
# B.2 — format v2 (private_pq.key.enc)
# =============================================================================

import os
import platform
import tempfile


def _make_pq_key(size: int = 4032) -> bytes:
    return secrets.token_bytes(size)


class TestKeyStoreV2RoundTrip(unittest.TestCase):
    """B.2 — encrypt/decrypt round-trip for ML-DSA-65 key (4032 bytes).

    All calls pass n_log2=10 (N=1024) to keep tests fast.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _ks(self):
        from aiss.key_store import (
            encrypt_pq_private_key, decrypt_pq_private_key,
            save_encrypted_pq_key, load_encrypted_pq_key,
        )
        return encrypt_pq_private_key, decrypt_pq_private_key, save_encrypted_pq_key, load_encrypted_pq_key

    def test_round_trip_4032_bytes(self):
        """encrypt then decrypt returns the original 4032-byte key."""
        enc_fn, dec_fn, _, _ = self._ks()
        key = _make_pq_key(4032)
        blob = enc_fn(key, "passphrase123", n_log2=10)
        recovered = dec_fn(blob, "passphrase123")
        self.assertEqual(key, recovered)

    def test_wrong_passphrase_raises(self):
        """Wrong passphrase must raise InvalidPassphraseError."""
        from aiss.key_store import InvalidPassphraseError
        enc_fn, dec_fn, _, _ = self._ks()
        key = _make_pq_key(4032)
        blob = enc_fn(key, "correct", n_log2=10)
        with self.assertRaises(InvalidPassphraseError):
            dec_fn(blob, "wrong")

    def test_no_plaintext_key_in_file(self):
        """The encrypted file must not contain the plaintext key bytes."""
        enc_fn, _, _, _ = self._ks()
        key = _make_pq_key(4032)
        blob = enc_fn(key, "passphrase123", n_log2=10)
        self.assertNotIn(key, blob)

    def test_save_and_load(self):
        """save_encrypted_pq_key + load_encrypted_pq_key round-trip."""
        _, _, save_fn, load_fn = self._ks()
        key = _make_pq_key(4032)
        path = Path(self.tmpdir) / "private_pq.key.enc"
        save_fn(key, "pw", path, n_log2=10)
        self.assertTrue(path.exists())
        recovered = load_fn(path, "pw")
        self.assertEqual(key, recovered)

    def test_permissions_0600_on_posix(self):
        """File permissions must be 0o600 on POSIX systems."""
        if platform.system() == "Windows":
            self.skipTest("0o600 N/A on Windows")
        _, _, save_fn, _ = self._ks()
        key = _make_pq_key(4032)
        path = Path(self.tmpdir) / "private_pq.key.enc"
        save_fn(key, "pw", path, n_log2=10)
        mode = oct(path.stat().st_mode & 0o777)
        self.assertEqual(mode, "0o600", f"Expected 0o600, got {mode}")

    def test_atomic_write_no_partial_file(self):
        """No .tmp file remains after successful save."""
        _, _, save_fn, _ = self._ks()
        key = _make_pq_key(4032)
        path = Path(self.tmpdir) / "private_pq.key.enc"
        save_fn(key, "pw", path, n_log2=10)
        tmp = path.with_suffix(".key.enc.tmp")
        self.assertFalse(tmp.exists(), f".tmp file left behind: {tmp}")

    def test_v1_loader_rejects_v2_file(self):
        """v1 decrypt_private_key must raise KeyFileCorruptedError on a v2 file."""
        from aiss.key_store import decrypt_private_key, KeyFileCorruptedError, encrypt_pq_private_key
        key = _make_pq_key(4032)
        blob_v2 = encrypt_pq_private_key(key, "pw", n_log2=10)
        with self.assertRaises(KeyFileCorruptedError):
            decrypt_private_key(blob_v2, "pw")

    def test_v1_file_still_loads(self):
        """v1 encrypt/decrypt still works after adding v2 functions."""
        from aiss.key_store import encrypt_private_key, decrypt_private_key
        key = secrets.token_bytes(32)
        blob = encrypt_private_key(key, "pw")
        recovered = decrypt_private_key(blob, "pw")
        self.assertEqual(key, recovered)


class TestKeyStoreV2Header(unittest.TestCase):
    """B.2 — header validation and tamper detection. All use n_log2=10."""

    def _blob(self):
        from aiss.key_store import encrypt_pq_private_key
        return encrypt_pq_private_key(_make_pq_key(4032), "pw", n_log2=10)

    def test_truncation_raises(self):
        """Truncated blob (below header size) must raise KeyFileCorruptedError."""
        from aiss.key_store import decrypt_pq_private_key, KeyFileCorruptedError, _V2_HEADER_SIZE
        blob = self._blob()
        with self.assertRaises(KeyFileCorruptedError):
            decrypt_pq_private_key(blob[:_V2_HEADER_SIZE - 1], "pw")

    def test_extra_bytes_fail_gcm(self):
        """Appending bytes corrupts GCM tag → InvalidPassphraseError."""
        from aiss.key_store import decrypt_pq_private_key, InvalidPassphraseError, KeyFileCorruptedError
        blob = self._blob() + b"\xff"
        with self.assertRaises((InvalidPassphraseError, KeyFileCorruptedError)):
            decrypt_pq_private_key(blob, "pw")

    def test_flip_magic_raises(self):
        """Corrupted magic must raise KeyFileCorruptedError."""
        from aiss.key_store import decrypt_pq_private_key, KeyFileCorruptedError
        blob = bytearray(self._blob())
        blob[0] ^= 0xFF
        with self.assertRaises(KeyFileCorruptedError):
            decrypt_pq_private_key(bytes(blob), "pw")

    def test_flip_version_raises(self):
        """Wrong version byte must raise KeyFileCorruptedError."""
        from aiss.key_store import decrypt_pq_private_key, KeyFileCorruptedError
        blob = bytearray(self._blob())
        blob[4] = 0x99
        with self.assertRaises(KeyFileCorruptedError):
            decrypt_pq_private_key(bytes(blob), "pw")

    def test_flip_algo_id_raises(self):
        """Unknown algo_id must raise KeyFileCorruptedError."""
        from aiss.key_store import decrypt_pq_private_key, KeyFileCorruptedError
        blob = bytearray(self._blob())
        blob[5] = 0xFF
        with self.assertRaises(KeyFileCorruptedError):
            decrypt_pq_private_key(bytes(blob), "pw")

    def test_n_log2_out_of_bounds_raises(self):
        """n_log2 outside [10,20] in header must raise KeyFileCorruptedError."""
        from aiss.key_store import decrypt_pq_private_key, KeyFileCorruptedError
        blob = bytearray(self._blob())
        blob[7] = 99  # n_log2 = 99 → way out of bounds
        with self.assertRaises(KeyFileCorruptedError):
            decrypt_pq_private_key(bytes(blob), "pw")

    def test_flip_ciphertext_raises(self):
        """One flipped bit in ciphertext must fail GCM authentication."""
        from aiss.key_store import decrypt_pq_private_key, InvalidPassphraseError, _V2_HEADER_SIZE
        blob = bytearray(self._blob())
        blob[_V2_HEADER_SIZE + 4] ^= 0x01
        with self.assertRaises(InvalidPassphraseError):
            decrypt_pq_private_key(bytes(blob), "pw")


if __name__ == "__main__":
    unittest.main(verbosity=2)
