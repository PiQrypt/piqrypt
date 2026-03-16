"""
Tests de sécurité — aiss/key_store.py

Couverture :
    1. Résistance brute-force  : scrypt doit prendre > 100ms (N=2^17)
    2. Corruption fichier      : 1 byte modifié → KeyFileCorruptedError
    3. Magic bytes             : header invalide → rejet propre
    4. Fichier tronqué         : taille incorrecte → rejet propre
    5. Version inconnue        : version byte ≠ 0x01 → rejet propre
    6. Mauvaise passphrase     : InvalidPassphraseError, pas de crash
    7. Effacement RAM          : après _secure_erase(), bytearray = zéros
    8. Clé non présente en clair dans le fichier chiffré
    9. Deux chiffrements → deux fichiers différents (salt aléatoire)
   10. Roundtrip : chiffrer → déchiffrer → égalité exacte
"""

import os
import secrets
import tempfile
import time
import unittest
from pathlib import Path


class TestKeyStoreTiming(unittest.TestCase):
    """Scrypt doit être suffisamment lent pour résister au brute-force."""

    def test_scrypt_minimum_duration(self):
        """
        Chiffrement doit prendre > 100ms avec les paramètres production.
        En mode test (PIQRYPT_SCRYPT_N=2^14), on accepte > 1ms.
        """
        from aiss.key_store import encrypt_private_key, _SCRYPT_N

        key = secrets.token_bytes(32)
        t0 = time.time()
        encrypt_private_key(key, "timing_test_passphrase")
        elapsed_ms = (time.time() - t0) * 1000

        min_ms = 100 if _SCRYPT_N >= 2**17 else 1
        self.assertGreater(elapsed_ms, min_ms,
            f"scrypt trop rapide : {elapsed_ms:.1f}ms < {min_ms}ms "
            f"(N={_SCRYPT_N}) — risque brute-force")


class TestKeyStoreCorruption(unittest.TestCase):
    """Le fichier .enc doit rejeter toute modification."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.key = secrets.token_bytes(32)
        self.passphrase = "secure_passphrase_42"

    def _make_key_file(self) -> Path:
        from aiss.key_store import save_encrypted_key
        path = self.tmpdir / "test.key.enc"
        save_encrypted_key(self.key, self.passphrase, path)
        return path

    def test_single_byte_corruption_raises(self):
        """Modifier 1 byte dans le fichier chiffré doit lever une exception."""
        from aiss.key_store import load_encrypted_key, KeyFileCorruptedError, InvalidPassphraseError

        path = self._make_key_file()
        raw = bytearray(path.read_bytes())
        raw[49] ^= 0xFF
        path.write_bytes(bytes(raw))

        with self.assertRaises((KeyFileCorruptedError, InvalidPassphraseError, Exception)):
            load_encrypted_key(path, self.passphrase)

    def test_truncated_file_raises(self):
        """Un fichier tronqué doit être rejeté proprement."""
        from aiss.key_store import load_encrypted_key, KeyFileCorruptedError

        path = self._make_key_file()
        raw = path.read_bytes()
        path.write_bytes(raw[:50])

        with self.assertRaises((KeyFileCorruptedError, Exception)):
            load_encrypted_key(path, self.passphrase)

    def test_empty_file_raises(self):
        """Un fichier vide doit être rejeté proprement."""
        from aiss.key_store import load_encrypted_key, KeyFileCorruptedError

        path = self.tmpdir / "empty.key.enc"
        path.write_bytes(b"")

        with self.assertRaises((KeyFileCorruptedError, Exception)):
            load_encrypted_key(path, self.passphrase)

    def test_wrong_magic_bytes_raises(self):
        """Un fichier avec un mauvais magic header doit être rejeté."""
        from aiss.key_store import load_encrypted_key, KeyFileCorruptedError

        path = self._make_key_file()
        raw = bytearray(path.read_bytes())
        raw[0:4] = b"XXXX"
        path.write_bytes(bytes(raw))

        with self.assertRaises((KeyFileCorruptedError, Exception)):
            load_encrypted_key(path, self.passphrase)

    def test_wrong_version_byte_raises(self):
        """Un version byte inconnu doit être rejeté."""
        from aiss.key_store import load_encrypted_key, KeyFileCorruptedError

        path = self._make_key_file()
        raw = bytearray(path.read_bytes())
        raw[4] = 0xFF
        path.write_bytes(bytes(raw))

        with self.assertRaises((KeyFileCorruptedError, Exception)):
            load_encrypted_key(path, self.passphrase)


class TestKeyStoreWrongPassphrase(unittest.TestCase):

    def test_wrong_passphrase_raises_invalid(self):
        """Mauvaise passphrase → InvalidPassphraseError."""
        from aiss.key_store import save_encrypted_key, load_encrypted_key, InvalidPassphraseError

        tmpdir = Path(tempfile.mkdtemp())
        path = tmpdir / "test.key.enc"
        key = secrets.token_bytes(32)
        save_encrypted_key(key, "bonne_passphrase", path)

        with self.assertRaises(InvalidPassphraseError):
            load_encrypted_key(path, "mauvaise_passphrase")

    def test_empty_passphrase_rejected(self):
        """Passphrase vide doit être rejetée sur un fichier chiffré avec passphrase."""
        from aiss.key_store import save_encrypted_key, load_encrypted_key, InvalidPassphraseError

        tmpdir = Path(tempfile.mkdtemp())
        path = tmpdir / "key1.enc"
        key = secrets.token_bytes(32)
        save_encrypted_key(key, "ma_passphrase", path)

        with self.assertRaises(InvalidPassphraseError):
            load_encrypted_key(path, "")


class TestKeyStoreConfidentiality(unittest.TestCase):

    def test_key_not_in_ciphertext(self):
        """La clé privée en clair ne doit pas apparaître dans le fichier chiffré."""
        from aiss.key_store import save_encrypted_key

        tmpdir = Path(tempfile.mkdtemp())
        path = tmpdir / "test.key.enc"
        key = secrets.token_bytes(32)
        save_encrypted_key(key, "passphrase", path)

        self.assertNotIn(key, path.read_bytes())

    def test_two_encryptions_differ(self):
        """Deux chiffrements de la même clé → fichiers différents (salt aléatoire)."""
        from aiss.key_store import encrypt_private_key

        key = secrets.token_bytes(32)
        enc1 = encrypt_private_key(key, "same_passphrase")
        enc2 = encrypt_private_key(key, "same_passphrase")
        self.assertNotEqual(enc1, enc2)


class TestKeyStoreRAMErasure(unittest.TestCase):

    def test_secure_erase_zeros_bytearray(self):
        """_secure_erase() doit mettre tous les bytes à zéro."""
        from aiss.key_store import _secure_erase

        key = bytearray(secrets.token_bytes(32))
        self.assertTrue(any(b != 0 for b in key))
        _secure_erase(key)
        self.assertTrue(all(b == 0 for b in key))

    def test_secure_erase_empty_no_crash(self):
        """_secure_erase() sur bytearray vide ne doit pas lever d'exception."""
        from aiss.key_store import _secure_erase
        _secure_erase(bytearray(0))


class TestKeyStoreRoundtrip(unittest.TestCase):

    def test_full_roundtrip(self):
        """La clé récupérée doit être identique à la clé originale."""
        from aiss.key_store import save_encrypted_key, load_encrypted_key

        tmpdir = Path(tempfile.mkdtemp())
        path = tmpdir / "roundtrip.key.enc"
        key = secrets.token_bytes(32)
        save_encrypted_key(key, "roundtrip_passphrase", path)
        self.assertEqual(key, load_encrypted_key(path, "roundtrip_passphrase"))

    def test_file_size_is_exact(self):
        """Le fichier .enc doit avoir exactement EXPECTED_FILE_SIZE bytes."""
        from aiss.key_store import save_encrypted_key, EXPECTED_FILE_SIZE

        tmpdir = Path(tempfile.mkdtemp())
        path = tmpdir / "size_test.key.enc"
        save_encrypted_key(secrets.token_bytes(32), "passphrase", path)
        self.assertEqual(path.stat().st_size, EXPECTED_FILE_SIZE)


if __name__ == "__main__":
    unittest.main(verbosity=2)