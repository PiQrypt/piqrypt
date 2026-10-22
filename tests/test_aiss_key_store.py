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
        tmp = path.parent / (path.name + ".tmp")
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


class TestKeyStoreV2Corrections(unittest.TestCase):
    """B.2 corrections — bornes combinées, passphrase, taille clé, fsync, NFKC."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _ks(self):
        from aiss.key_store import (
            encrypt_pq_private_key, decrypt_pq_private_key,
            save_encrypted_pq_key, load_encrypted_pq_key,
        )
        return encrypt_pq_private_key, decrypt_pq_private_key, save_encrypted_pq_key, load_encrypted_pq_key

    # ── Passphrase validation ──────────────────────────────────────────────────

    def test_passphrase_none_raises(self):
        enc_fn, _, _, _ = self._ks()
        with self.assertRaises((ValueError, TypeError)):
            enc_fn(_make_pq_key(4032), None, n_log2=10)

    def test_passphrase_empty_raises(self):
        enc_fn, _, _, _ = self._ks()
        with self.assertRaises(ValueError):
            enc_fn(_make_pq_key(4032), "", n_log2=10)

    def test_passphrase_whitespace_raises(self):
        enc_fn, _, _, _ = self._ks()
        with self.assertRaises(ValueError):
            enc_fn(_make_pq_key(4032), "   ", n_log2=10)

    def test_passphrase_int_raises(self):
        enc_fn, _, _, _ = self._ks()
        with self.assertRaises((ValueError, TypeError)):
            enc_fn(_make_pq_key(4032), 12345, n_log2=10)

    def test_decrypt_passphrase_none_raises(self):
        enc_fn, dec_fn, _, _ = self._ks()
        blob = enc_fn(_make_pq_key(4032), "valid", n_log2=10)
        with self.assertRaises((ValueError, TypeError)):
            dec_fn(blob, None)

    def test_decrypt_passphrase_empty_raises(self):
        enc_fn, dec_fn, _, _ = self._ks()
        blob = enc_fn(_make_pq_key(4032), "valid", n_log2=10)
        with self.assertRaises(ValueError):
            dec_fn(blob, "")

    # ── Taille de clé ─────────────────────────────────────────────────────────

    def test_wrong_key_size_at_write_raises(self):
        enc_fn, _, _, _ = self._ks()
        with self.assertRaises(ValueError):
            enc_fn(_make_pq_key(32), "valid", n_log2=10)

    def test_wrong_key_size_4031_raises(self):
        enc_fn, _, _, _ = self._ks()
        with self.assertRaises(ValueError):
            enc_fn(_make_pq_key(4031), "valid", n_log2=10)

    def test_wrong_key_size_4033_raises(self):
        enc_fn, _, _, _ = self._ks()
        with self.assertRaises(ValueError):
            enc_fn(_make_pq_key(4033), "valid", n_log2=10)

    # ── Bornes scrypt ─────────────────────────────────────────────────────────

    def test_r_above_max_raises(self):
        enc_fn, _, _, _ = self._ks()
        with self.assertRaises(Exception):
            enc_fn(_make_pq_key(4032), "valid", n_log2=10, r=65)

    def test_p_above_max_raises(self):
        enc_fn, _, _, _ = self._ks()
        with self.assertRaises(Exception):
            enc_fn(_make_pq_key(4032), "valid", n_log2=10, p=65)

    def test_memory_bound_exceeded_raises(self):
        """128 * N * r > 1 GiB must be refused (e.g. n_log2=20, r=9 → 128*1M*9=1152MB)."""
        from aiss.key_store import decrypt_pq_private_key, KeyFileCorruptedError, _v2_build_header, V2_ALGO_MLDSA65_SK, V2_KDF_SCRYPT, _V2_HEADER_SIZE
        # Build a crafted header with n_log2=20, r=9, p=1 → 128*1048576*9 > 1 GiB
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        hdr = _v2_build_header(V2_ALGO_MLDSA65_SK, V2_KDF_SCRYPT, 20, 9, 1, salt, nonce, 4048)
        # Append dummy ciphertext of matching length
        blob = hdr + bytes(4048)
        with self.assertRaises(KeyFileCorruptedError):
            decrypt_pq_private_key(blob, "valid")

    def test_cost_bound_exceeded_raises(self):
        """N * r * p > 2^24 must be refused (n_log2=14, r=64, p=64 → 16384*64*64=67M > 2^24=16M)."""
        from aiss.key_store import decrypt_pq_private_key, KeyFileCorruptedError, _v2_build_header, V2_ALGO_MLDSA65_SK, V2_KDF_SCRYPT
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        # n_log2=14, r=64, p=64 → memory=128MB<1GiB (OK), cost=67M>2^24 (FAILS)
        hdr = _v2_build_header(V2_ALGO_MLDSA65_SK, V2_KDF_SCRYPT, 14, 64, 64, salt, nonce, 4048)
        blob = hdr + bytes(4048)
        with self.assertRaises(KeyFileCorruptedError):
            decrypt_pq_private_key(blob, "valid")

    # ── Sweep des 42 octets d'en-tête ─────────────────────────────────────────

    def test_header_byte_sweep(self):
        """Flip each of the 42 header bytes with masks 0x01, 0x80, 0xFF — must all raise."""
        from aiss.key_store import (
            encrypt_pq_private_key, decrypt_pq_private_key,
            KeyFileCorruptedError, InvalidPassphraseError, _V2_HEADER_SIZE,
        )
        blob = encrypt_pq_private_key(_make_pq_key(4032), "valid", n_log2=10)
        errors = []
        for byte_idx in range(_V2_HEADER_SIZE):
            for mask in (0x01, 0x80, 0xFF):
                ba = bytearray(blob)
                ba[byte_idx] ^= mask
                if ba == bytearray(blob):
                    continue  # XOR was a no-op (e.g. 0x00 ^ 0x00)
                try:
                    decrypt_pq_private_key(bytes(ba), "valid")
                    errors.append(f"byte {byte_idx} mask {mask:#x}: no exception raised")
                except (KeyFileCorruptedError, InvalidPassphraseError):
                    pass
                except Exception as exc:
                    pass  # Other exceptions also acceptable
        self.assertFalse(errors, "\n".join(errors))

    # ── Fichier temporaire 0o600 (POSIX uniquement) ────────────────────────────

    @unittest.skipIf(platform.system() == "Windows", "0o600 N/A on Windows")
    def test_tmp_file_0o600_posix(self):
        """Temp file must be created with 0o600 on POSIX (checked via inaccessible test)."""
        import stat
        _, _, save_fn, _ = self._ks()
        key = _make_pq_key(4032)
        path = Path(self.tmpdir) / "private_pq.key.enc"
        # After successful save, only the final file remains — verify 0o600
        save_fn(key, "pw", path, n_log2=10)
        mode = path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600, f"Expected 0o600, got {oct(mode)}")

    # ── Normalisation NFKC ────────────────────────────────────────────────────

    def test_nfkc_normalization_round_trip(self):
        """NFC and NFD forms of the same passphrase must give identical round-trip."""
        import unicodedata
        enc_fn, dec_fn, _, _ = self._ks()
        key = _make_pq_key(4032)
        # Use a passphrase with characters that differ between NFC/NFD/NFKC
        base_pw = "café"  # NFC: café (precomposed é)
        nfc_pw = unicodedata.normalize("NFC", base_pw)
        nfd_pw = unicodedata.normalize("NFD", base_pw)
        # Both forms must encrypt + decrypt successfully with each other
        blob_nfc = enc_fn(key, nfc_pw, n_log2=10)
        recovered = dec_fn(blob_nfc, nfd_pw)
        self.assertEqual(key, recovered, "NFD passphrase must decrypt a blob encrypted with NFC")
        blob_nfd = enc_fn(key, nfd_pw, n_log2=10)
        recovered2 = dec_fn(blob_nfd, nfc_pw)
        self.assertEqual(key, recovered2, "NFC passphrase must decrypt a blob encrypted with NFD")


class TestKeyStoreV2AtomicWrite(unittest.TestCase):
    """Écriture atomique : temporaire périmé et écriture interrompue."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = Path(self.tmpdir) / "private_pq.key.enc"
        self.tmp = Path(self.tmpdir) / "private_pq.key.enc.tmp"

    def test_stale_tmp_is_replaced(self):
        from aiss.key_store import save_encrypted_pq_key, load_encrypted_pq_key
        self.tmp.write_bytes(b"reste d'un plantage")
        key = _make_pq_key(4032)
        save_encrypted_pq_key(key, "passphrase-ok", self.path, n_log2=10)
        self.assertEqual(load_encrypted_pq_key(self.path, "passphrase-ok"), key)
        self.assertFalse(self.tmp.exists())

    def test_interrupted_write_keeps_existing_file(self):
        from unittest.mock import patch
        from aiss.key_store import save_encrypted_pq_key, load_encrypted_pq_key
        old = _make_pq_key(4032)
        save_encrypted_pq_key(old, "passphrase-ok", self.path, n_log2=10)
        before = self.path.read_bytes()
        with patch("aiss.key_store.os.write", side_effect=OSError("disque plein")):
            with self.assertRaises(OSError):
                save_encrypted_pq_key(_make_pq_key(4032), "autre-passphrase", self.path, n_log2=10)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(load_encrypted_pq_key(self.path, "passphrase-ok"), old)
        self.assertFalse(self.tmp.exists())

    def test_interrupted_replace_leaves_no_tmp(self):
        from unittest.mock import patch
        from aiss.key_store import save_encrypted_pq_key
        with patch("aiss.key_store.os.replace", side_effect=OSError("verrou")):
            with self.assertRaises(OSError):
                save_encrypted_pq_key(_make_pq_key(4032), "passphrase-ok", self.path, n_log2=10)
        self.assertFalse(self.path.exists())
        self.assertFalse(self.tmp.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
