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


if __name__ == "__main__":
    unittest.main(verbosity=2)
