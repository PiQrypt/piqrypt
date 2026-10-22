# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""Tests — secure_agent_key : écriture sans perte de clé, identités hybrides."""
import nacl.signing  # noqa: F401

import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

OLD = "ancienne passphrase"
NEW = "nouvelle passphrase"


def _pq_available():
    try:
        from aiss.crypto import dilithium
        return dilithium is not None and dilithium.is_available()
    except Exception:
        return False


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._scrypt = patch("aiss.key_store._SCRYPT_N", 2 ** 10)
        self._scrypt.start()
        self.addCleanup(self._scrypt.stop)

    def _dir(self, name):
        return Path(self.tmp) / "agents" / name

    def _secure(self, name, new=NEW, old=OLD):
        from aiss.identity import secure_agent_key
        return secure_agent_key(name, new, old, base_dir=self.tmp)

    def _tmp_files(self, name):
        return [p.name for p in self._dir(name).iterdir() if p.name.endswith(".tmp")]


class TestClassic(_Base):

    def _create(self, name="cl", passphrase=OLD):
        from aiss.identity import create_agent_identity
        return create_agent_identity(name, passphrase=passphrase, base_dir=self.tmp)

    def test_reencrypt(self):
        from aiss.key_store import load_encrypted_key, InvalidPassphraseError
        self._create()
        before = load_encrypted_key(self._dir("cl") / "private.key.enc", OLD)
        self.assertTrue(self._secure("cl"))
        path = self._dir("cl") / "private.key.enc"
        self.assertEqual(load_encrypted_key(path, NEW), before)
        with self.assertRaises(InvalidPassphraseError):
            load_encrypted_key(path, OLD)
        self.assertEqual(self._tmp_files("cl"), [])

    def test_plaintext_key_is_removed_without_bak(self):
        from aiss.key_store import load_encrypted_key, load_plaintext_key
        self._create("pl", passphrase=None)
        plain = self._dir("pl") / "private.key.json"
        before = load_plaintext_key(plain)
        self._secure("pl", old=None)
        self.assertEqual(load_encrypted_key(self._dir("pl") / "private.key.enc", NEW), before)
        self.assertFalse(plain.exists())
        self.assertFalse((self._dir("pl") / "private.key.json.bak").exists())
        self.assertEqual(sorted(p.name for p in self._dir("pl").iterdir()),
                         ["identity.json", "private.key.enc"])

    def test_plaintext_overwritten_with_zeros_before_removal(self):
        import os as _os
        self._create("pl3", passphrase=None)
        plain = self._dir("pl3") / "private.key.json"
        size = plain.stat().st_size
        seen = {}
        real_unlink = _os.unlink

        def spy(path, *a, **k):
            if str(path) == str(plain):
                seen["content"] = Path(path).read_bytes()
            return real_unlink(path, *a, **k)

        with patch("os.unlink", side_effect=spy):
            self._secure("pl3", old=None)
        self.assertEqual(seen["content"], b"\x00" * size)
        self.assertFalse(plain.exists())

    def test_removal_failure_only_warns_and_command_succeeds(self):
        import os as _os
        from aiss.key_store import load_encrypted_key
        self._create("pl4", passphrase=None)
        plain = self._dir("pl4") / "private.key.json"
        size = plain.stat().st_size
        real_unlink = _os.unlink

        def flaky(path, *a, **k):
            if str(path) == str(plain):
                raise PermissionError("verrouillé")
            return real_unlink(path, *a, **k)

        with patch("os.unlink", side_effect=flaky),                 patch("aiss.identity.logger.warning") as warn:
            self.assertTrue(self._secure("pl4", old=None))
        warn.assert_called_once()
        self.assertTrue(plain.exists())
        self.assertEqual(plain.read_bytes(), b"\x00" * size)  # déjà écrasé
        self.assertEqual(len(load_encrypted_key(self._dir("pl4") / "private.key.enc", NEW)), 32)

    def test_verification_failure_deletes_nothing(self):
        from aiss.key_store import KeyFileCorruptedError
        self._create("pl5", passphrase=None)
        plain = self._dir("pl5") / "private.key.json"
        original = plain.read_bytes()
        with patch("aiss.key_store.load_encrypted_key", return_value=b"" * 32):
            with self.assertRaises(KeyFileCorruptedError):
                self._secure("pl5", old=None)
        self.assertEqual(plain.read_bytes(), original)
        self.assertFalse((self._dir("pl5") / "private.key.json.bak").exists())
        # le fichier chiffré installé par l'appel est retiré : il masquerait la clé en clair
        self.assertFalse((self._dir("pl5") / "private.key.enc").exists())

    def test_verification_read_error_deletes_nothing(self):
        from aiss.key_store import InvalidPassphraseError
        self._create("pl6", passphrase=None)
        plain = self._dir("pl6") / "private.key.json"
        original = plain.read_bytes()
        with patch("aiss.key_store.load_encrypted_key", side_effect=InvalidPassphraseError("x")):
            with self.assertRaises(InvalidPassphraseError):
                self._secure("pl6", old=None)
        self.assertEqual(plain.read_bytes(), original)

    def test_write_failure_keeps_old_key_and_no_temp(self):
        from aiss.key_store import load_encrypted_key
        self._create()
        path = self._dir("cl") / "private.key.enc"
        original = path.read_bytes()
        with patch("os.fsync", side_effect=OSError("disque plein")):
            with self.assertRaises(OSError):
                self._secure("cl")
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(load_encrypted_key(path, OLD), load_encrypted_key(path, OLD))
        self.assertEqual(self._tmp_files("cl"), [])

    def test_replace_failure_keeps_old_key_and_no_temp(self):
        self._create()
        path = self._dir("cl") / "private.key.enc"
        original = path.read_bytes()
        with patch("os.replace", side_effect=OSError("verrou")):
            with self.assertRaises(OSError):
                self._secure("cl")
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self._tmp_files("cl"), [])

    def test_plaintext_write_failure_keeps_plaintext_key(self):
        self._create("pl2", passphrase=None)
        plain = self._dir("pl2") / "private.key.json"
        original = plain.read_bytes()
        with patch("os.fsync", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                self._secure("pl2", old=None)
        self.assertEqual(plain.read_bytes(), original)
        self.assertFalse((self._dir("pl2") / "private.key.enc").exists())
        self.assertFalse((self._dir("pl2") / "private.key.json.bak").exists())

    def test_wrong_old_passphrase_changes_nothing(self):
        from aiss.key_store import InvalidPassphraseError
        self._create()
        path = self._dir("cl") / "private.key.enc"
        original = path.read_bytes()
        with self.assertRaises(InvalidPassphraseError):
            self._secure("cl", old="mauvaise")
        self.assertEqual(path.read_bytes(), original)

    def test_classic_accepts_short_new_passphrase_as_before(self):
        self._create()
        self.assertTrue(self._secure("cl", new="court"))


@pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")
class TestHybrid(_Base):

    def _create(self, name="hy"):
        from aiss.identity import create_agent_identity
        return create_agent_identity(name, passphrase=OLD, base_dir=self.tmp, hybrid=True)

    def test_both_keys_reencrypted(self):
        from aiss.key_store import (
            load_encrypted_key, load_encrypted_pq_key, InvalidPassphraseError)
        self._create()
        d = self._dir("hy")
        ed0 = load_encrypted_key(d / "private.key.enc", OLD)
        pq0 = load_encrypted_pq_key(d / "private_pq.key.enc", OLD)
        self._secure("hy")
        self.assertEqual(load_encrypted_key(d / "private.key.enc", NEW), ed0)
        self.assertEqual(load_encrypted_pq_key(d / "private_pq.key.enc", NEW), pq0)
        with self.assertRaises(InvalidPassphraseError):
            load_encrypted_key(d / "private.key.enc", OLD)
        with self.assertRaises(InvalidPassphraseError):
            load_encrypted_pq_key(d / "private_pq.key.enc", OLD)
        self.assertEqual(self._tmp_files("hy"), [])

    def test_two_different_passphrases_refused_without_change(self):
        from aiss.key_store import InvalidPassphraseError, save_encrypted_key, load_encrypted_key
        self._create()
        d = self._dir("hy")
        # Ed25519 re-chiffrée seule avec une autre passphrase : états divergents
        ed = load_encrypted_key(d / "private.key.enc", OLD)
        save_encrypted_key(ed, "autre divergente", d / "private.key.enc")
        before = {p.name: p.read_bytes() for p in d.iterdir()}
        with self.assertRaises(InvalidPassphraseError):
            self._secure("hy", old=OLD)
        with self.assertRaises(InvalidPassphraseError):
            self._secure("hy", old="autre divergente")
        self.assertEqual(before, {p.name: p.read_bytes() for p in d.iterdir()})

    def test_pq_unreadable_changes_nothing(self):
        from aiss.key_store import InvalidPassphraseError
        self._create()
        d = self._dir("hy")
        before = {p.name: p.read_bytes() for p in d.iterdir()}
        with self.assertRaises(InvalidPassphraseError):
            self._secure("hy", old="mauvaise passphrase")
        self.assertEqual(before, {p.name: p.read_bytes() for p in d.iterdir()})

    def test_hybrid_requires_old_passphrase_and_min_length(self):
        self._create()
        with self.assertRaises(ValueError):
            self._secure("hy", old=None)
        with self.assertRaises(ValueError):
            self._secure("hy", new="court")

    def test_write_failure_changes_nothing(self):
        self._create()
        d = self._dir("hy")
        before = {p.name: p.read_bytes() for p in d.iterdir()}
        with patch("os.fsync", side_effect=OSError("disque plein")):
            with self.assertRaises(OSError):
                self._secure("hy")
        self.assertEqual(before, {p.name: p.read_bytes() for p in d.iterdir()})

    def test_failure_between_the_two_replacements_restores_pq_key(self):
        import os as _os
        from aiss.key_store import load_encrypted_key, load_encrypted_pq_key
        self._create()
        d = self._dir("hy")
        before = {p.name: p.read_bytes() for p in d.iterdir()}
        real = _os.replace
        calls = {"n": 0}

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 2:  # remplacement de la clé Ed25519
                raise OSError("verrou")
            return real(src, dst)

        with patch("os.replace", side_effect=flaky):
            with self.assertRaises(OSError):
                self._secure("hy")
        self.assertEqual(load_encrypted_key(d / "private.key.enc", OLD),
                         load_encrypted_key(d / "private.key.enc", OLD))
        self.assertEqual(len(load_encrypted_pq_key(d / "private_pq.key.enc", OLD)), 4032)
        self.assertEqual(before["private.key.enc"], (d / "private.key.enc").read_bytes())
        self.assertEqual(self._tmp_files("hy"), [])

    def test_upgraded_identity_with_plaintext_ed25519(self):
        from aiss.identity import create_agent_identity, upgrade_agent_identity
        from aiss.key_store import load_encrypted_pq_key, load_plaintext_key, load_encrypted_key
        create_agent_identity("up", passphrase=None, base_dir=self.tmp)
        upgrade_agent_identity("up", OLD, None, base_dir=self.tmp)
        d = self._dir("up")
        ed0 = load_plaintext_key(d / "private.key.json")
        self._secure("up")
        self.assertEqual(load_encrypted_key(d / "private.key.enc", NEW), ed0)
        self.assertEqual(len(load_encrypted_pq_key(d / "private_pq.key.enc", NEW)), 4032)
        self.assertFalse((d / "private.key.json").exists())
        self.assertFalse((d / "private.key.json.bak").exists())


if __name__ == "__main__":
    unittest.main()
