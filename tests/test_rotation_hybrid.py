# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""Tests — B.6 : attestation de rotation hybride AISS-2.1 (quatre signatures)."""
import nacl.signing  # noqa: F401

import base64
import copy
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


pytestmark = pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")


def _flip_b64(value: str) -> str:
    raw = bytearray(base64.b64decode(value[7:], validate=True))
    raw[0] ^= 0x01
    return "base64:" + base64.b64encode(bytes(raw)).decode("ascii")


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = patch("aiss.key_store._SCRYPT_N", 2 ** 10)
        p.start()
        self.addCleanup(p.stop)

    def _dir(self, name):
        return Path(self.tmp) / "agents" / name

    def previous(self, kind="native", name=None):
        """(identité, clé privée Ed25519, clé privée ML-DSA-65)"""
        from aiss.identity import create_agent_identity, upgrade_agent_identity, load_agent_pq_key
        from aiss.key_store import load_encrypted_key
        name = name or kind
        if kind == "native":
            r = create_agent_identity(name, passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
            ident = r["identity"]
        else:
            create_agent_identity(name, passphrase=PASSPHRASE, base_dir=self.tmp)
            ident = upgrade_agent_identity(name, PASSPHRASE, PASSPHRASE, base_dir=self.tmp)["identity"]
        priv = load_encrypted_key(self._dir(name) / "private.key.enc", PASSPHRASE)
        priv_pq = load_agent_pq_key(name, PASSPHRASE, base_dir=self.tmp)
        return ident, priv, priv_pq

    @staticmethod
    def new_keys():
        from aiss.crypto import ed25519, dilithium
        priv_ed, pub_ed = ed25519.generate_keypair()
        priv_pq, pub_pq = dilithium.generate_keypair()
        return priv_ed, pub_ed, priv_pq, pub_pq

    def attestation(self, kind="native", name=None):
        from aiss.identity import create_rotation_attestation_hybrid
        ident, priv, priv_pq = self.previous(kind, name)
        n_ed, n_pub_ed, n_pq, n_pub_pq = self.new_keys()
        att = create_rotation_attestation_hybrid(
            ident, priv, priv_pq, n_ed, n_pub_ed, n_pq, n_pub_pq)
        return att, ident, (n_pub_ed, n_pub_pq)


class TestValidRotation(_Base):

    def test_valid_from_native_and_upgraded(self):
        from aiss.identity import verify_rotation_attestation_hybrid, derive_agent_id_aiss21
        for kind in ("native", "upgraded"):
            with self.subTest(previous=kind):
                att, ident, (pub_ed, pub_pq) = self.attestation(kind)
                self.assertTrue(verify_rotation_attestation_hybrid(att, ident))
                self.assertEqual(att["type"], "key_rotation")
                self.assertEqual(att["version"], "AISS-2.1")
                self.assertEqual(att["previous_agent_id"], ident["agent_id"])
                self.assertEqual(att["new_agent_id"], derive_agent_id_aiss21(pub_ed, pub_pq))
                self.assertEqual(sorted(att["signatures"]), [
                    "new_classical", "new_post_quantum",
                    "previous_classical", "previous_post_quantum"])
                for key in ("previous_public_key_classical", "previous_public_key_pq",
                            "new_public_key_classical", "new_public_key_pq"):
                    self.assertTrue(att[key].startswith("base64:"))

    def test_creation_rejects_mismatched_private_keys(self):
        from aiss.identity import create_rotation_attestation_hybrid
        ident, priv, priv_pq = self.previous("native")
        n_ed, n_pub_ed, n_pq, n_pub_pq = self.new_keys()
        other_ed, _, other_pq, _ = self.new_keys()
        for label, args in {
            "ancienne Ed25519": (ident, other_ed, priv_pq, n_ed, n_pub_ed, n_pq, n_pub_pq),
            "ancienne ML-DSA": (ident, priv, other_pq, n_ed, n_pub_ed, n_pq, n_pub_pq),
            "nouvelle Ed25519": (ident, priv, priv_pq, other_ed, n_pub_ed, n_pq, n_pub_pq),
            "nouvelle ML-DSA": (ident, priv, priv_pq, n_ed, n_pub_ed, other_pq, n_pub_pq),
        }.items():
            with self.subTest(wrong=label):
                with self.assertRaises(ValueError):
                    create_rotation_attestation_hybrid(*args)

    def test_creation_rejects_wrong_public_key_sizes_and_bad_identity(self):
        from aiss.identity import create_rotation_attestation_hybrid, IdentityBindingError
        ident, priv, priv_pq = self.previous("native")
        n_ed, n_pub_ed, n_pq, n_pub_pq = self.new_keys()
        with self.assertRaises(ValueError):
            create_rotation_attestation_hybrid(
                ident, priv, priv_pq, n_ed, n_pub_ed[:31], n_pq, n_pub_pq)
        with self.assertRaises(IdentityBindingError):
            create_rotation_attestation_hybrid(
                dict(ident, agent_id="A" * 32), priv, priv_pq, n_ed, n_pub_ed, n_pq, n_pub_pq)


class TestTampering(_Base):

    def setUp(self):
        super().setUp()
        self.att, self.ident, _ = self.attestation("native")

    _DEFAULT = object()

    def _check(self, att, expected=False, ident=_DEFAULT):
        from aiss.identity import verify_rotation_attestation_hybrid
        if ident is self._DEFAULT:
            ident = self.ident
        self.assertEqual(verify_rotation_attestation_hybrid(att, ident), expected)

    def test_each_signature_removed(self):
        for name in self.att["signatures"]:
            with self.subTest(removed=name):
                att = copy.deepcopy(self.att)
                del att["signatures"][name]
                self._check(att)
        att = copy.deepcopy(self.att)
        del att["signatures"]
        self._check(att)

    def test_each_signature_altered(self):
        for name in self.att["signatures"]:
            with self.subTest(altered=name):
                att = copy.deepcopy(self.att)
                att["signatures"][name]["signature"] = _flip_b64(att["signatures"][name]["signature"])
                self._check(att)

    def test_each_signature_empty_or_wrong_algorithm(self):
        for name in self.att["signatures"]:
            with self.subTest(empty=name):
                att = copy.deepcopy(self.att)
                att["signatures"][name]["signature"] = ""
                self._check(att)
            with self.subTest(algorithm=name):
                att = copy.deepcopy(self.att)
                att["signatures"][name]["algorithm"] = "autre"
                self._check(att)

    def test_each_signed_field_altered(self):
        for field, value in self.att.items():
            if field == "signatures":
                continue
            if isinstance(value, int):
                new = value + 1
            elif value.startswith("base64:"):
                new = _flip_b64(value)
            else:
                new = value + "x"
            with self.subTest(field=field):
                att = copy.deepcopy(self.att)
                att[field] = new
                self._check(att)

    def test_extra_field_rejected(self):
        att = copy.deepcopy(self.att)
        att["extra"] = 1
        self._check(att)

    def test_inconsistent_new_agent_id_even_if_resigned(self):
        """new_agent_id incohérent avec les nouvelles clés, signé par les quatre clés."""
        from aiss.identity import (
            _domain_signed_message, _ROTATION_DOMAIN_PREFIX, _b64_prefixed, verify_rotation_attestation_hybrid)
        from aiss.crypto import ed25519, dilithium
        ident, priv, priv_pq = self.previous("native", "prev2")
        n_ed, n_pub_ed, n_pq, n_pub_pq = self.new_keys()
        unsigned = {k: v for k, v in self.att.items() if k != "signatures"}
        unsigned.update({
            "previous_agent_id": ident["agent_id"],
            "previous_public_key_classical": ident["public_key_classical"],
            "previous_public_key_pq": ident["public_key_pq"],
            "new_public_key_classical": _b64_prefixed(n_pub_ed),
            "new_public_key_pq": _b64_prefixed(n_pub_pq),
            "new_agent_id": "N" * 32,
        })
        msg = _domain_signed_message(_ROTATION_DOMAIN_PREFIX, unsigned)
        att = dict(unsigned, signatures={
            "previous_classical": {"algorithm": "Ed25519",
                                   "signature": _b64_prefixed(ed25519.sign(priv, msg))},
            "previous_post_quantum": {"algorithm": "ML-DSA-65",
                                      "signature": _b64_prefixed(dilithium.sign(priv_pq, msg))},
            "new_classical": {"algorithm": "Ed25519",
                              "signature": _b64_prefixed(ed25519.sign(n_ed, msg))},
            "new_post_quantum": {"algorithm": "ML-DSA-65",
                                 "signature": _b64_prefixed(dilithium.sign(n_pq, msg))},
        })
        self.assertFalse(verify_rotation_attestation_hybrid(att, ident))

    def test_wrong_previous_identity_and_replay(self):
        other, _, _ = self.previous("native", "autre")
        self._check(self.att, ident=other)
        up, _, _ = self.previous("upgraded", "autre_up")
        self._check(self.att, ident=up)
        self._check(self.att, expected=True)

    def test_previous_identity_invalid(self):
        bad = dict(self.ident, agent_id="B" * 32)
        self._check(self.att, ident=bad)
        for junk in (None, {}, [], "x"):
            with self.subTest(identity=repr(junk)):
                self._check(self.att, ident=junk)

    def test_strict_encoding(self):
        cases = {
            "prefix absent": lambda a: a.__setitem__(
                "new_public_key_classical", a["new_public_key_classical"][7:]),
            "alphabet": lambda a: a.__setitem__("new_public_key_pq", "base64:!!!!"),
            "taille Ed25519 31": lambda a: a.__setitem__(
                "previous_public_key_classical", "base64:" + base64.b64encode(b"\x01" * 31).decode()),
            "taille ML-DSA 1951": lambda a: a.__setitem__(
                "previous_public_key_pq", "base64:" + base64.b64encode(b"\x01" * 1951).decode()),
            "signature sans prefixe": lambda a: a["signatures"]["new_classical"].__setitem__(
                "signature", a["signatures"]["new_classical"]["signature"][7:]),
            "timestamp texte": lambda a: a.__setitem__("rotation_timestamp", "1"),
            "timestamp booléen": lambda a: a.__setitem__("rotation_timestamp", True),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                att = copy.deepcopy(self.att)
                mutate(att)
                self._check(att)

    def test_garbage_returns_false_without_raising(self):
        for junk in (None, {}, [], "x", {"signatures": 1}):
            with self.subTest(attestation=repr(junk)):
                self._check(junk)

    def test_rotation_domain_is_separated(self):
        from aiss.identity import create_rotation_attestation_hybrid
        ident, priv, priv_pq = self.previous("native", "dom")
        n_ed, n_pub_ed, n_pq, n_pub_pq = self.new_keys()
        with patch("aiss.identity._ROTATION_DOMAIN_PREFIX", b"PiQrypt-AISS-2.1-binding\x00"):
            # auto-contrôle de la création sous le mauvais préfixe : la vérif utilise le même
            # global patché, donc on signe puis on vérifie sous le vrai préfixe ci-dessous
            att = create_rotation_attestation_hybrid(
                ident, priv, priv_pq, n_ed, n_pub_ed, n_pq, n_pub_pq)
        self._check(att, ident=ident)

    def test_aiss1_rotation_attestation_untouched(self):
        import aiss
        old_priv, old_pub = aiss.generate_keypair()
        _, new_pub = aiss.generate_keypair()
        att = aiss.create_rotation_attestation(old_priv, old_pub, new_pub)
        self.assertIn("rotation_signature", att)
        self.assertEqual(att["version"], "AISS-1.0")
        self.assertNotIn("signatures", att)


if __name__ == "__main__":
    unittest.main()
