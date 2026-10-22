# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""Tests — B.8 : rotation hybride ancrée dans la chaîne (RFC §12.2)."""
import nacl.signing  # noqa: F401

import contextlib
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


def _make_license(tier: str):
    from aiss.license import License, TIERS
    lic = License.__new__(License)
    lic._tier = tier
    lic._payload = {
        "tier": tier, "license_id": f"test_{tier}",
        "agents_max": TIERS[tier]["agents_max"],
        "events_month": TIERS[tier]["events_month"], "expires_at": None,
    }
    lic._loaded_at = 0.0
    return lic


@contextlib.contextmanager
def _pro():
    import aiss.license as lic_module
    orig = lic_module._license
    lic_module._license = _make_license("pro")
    try:
        yield
    finally:
        lic_module._license = orig


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = patch("aiss.key_store._SCRYPT_N", 2 ** 10)
        p.start()
        self.addCleanup(p.stop)

    def _dir(self, name):
        return Path(self.tmp) / "agents" / name

    def previous(self, kind):
        from aiss.identity import create_agent_identity, upgrade_agent_identity, load_agent_pq_key
        from aiss.key_store import load_encrypted_key
        if kind == "native":
            ident = create_agent_identity(
                kind, passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)["identity"]
        else:
            create_agent_identity(kind, passphrase=PASSPHRASE, base_dir=self.tmp)
            ident = upgrade_agent_identity(kind, PASSPHRASE, PASSPHRASE, base_dir=self.tmp)["identity"]
        priv = load_encrypted_key(self._dir(kind) / "private.key.enc", PASSPHRASE)
        priv_pq = load_agent_pq_key(kind, PASSPHRASE, base_dir=self.tmp)
        return ident, priv, priv_pq

    @staticmethod
    def new_keys():
        from aiss.crypto import ed25519, dilithium
        priv_ed, pub_ed = ed25519.generate_keypair()
        priv_pq, pub_pq = dilithium.generate_keypair()
        return priv_ed, pub_ed, priv_pq, pub_pq

    def old_chain(self, kind, ident, priv, priv_pq):
        """Deux événements : AISS-2.1 (natif) ou AISS-1 (mise à niveau)."""
        import aiss
        from aiss.chain import compute_event_hash
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        events, prev = [], None
        for i in range(2):
            if kind == "native":
                with _pro():
                    ev = stamp_event_aiss2_hybrid(
                        priv, priv_pq, ident["agent_id"], {"seq": i},
                        previous_hash=prev, tsa_stamp_after=False)
            else:
                ev = aiss.stamp_event(priv, ident["agent_id"], {"seq": i}, previous_hash=prev)
            events.append(ev)
            prev = compute_event_hash(ev)
        return events, prev

    def rotate(self, kind):
        """(ancienne chaîne terminée par la rotation, identité, genèse, clés nouvelles)"""
        from aiss.chain import compute_event_hash
        from aiss.identity import create_rotation_event_aiss21, derive_agent_id_aiss21
        from aiss.stamp_aiss2 import stamp_genesis_event_aiss2_hybrid
        ident, priv, priv_pq = self.previous(kind)
        events, last_hash = self.old_chain(kind, ident, priv, priv_pq)
        n_ed, n_pub_ed, n_pq, n_pub_pq = self.new_keys()
        with _pro():
            rot = create_rotation_event_aiss21(
                ident, priv, priv_pq, n_ed, n_pub_ed, n_pq, n_pub_pq, last_hash)
            new_id = derive_agent_id_aiss21(n_pub_ed, n_pub_pq)
            genesis = stamp_genesis_event_aiss2_hybrid(
                n_ed, n_pq, n_pub_ed, new_id, {"action": "genesis_after_rotation"},
                public_key_pq=n_pub_pq, tsa_stamp_after=False,
                rotation_previous_hash=compute_event_hash(rot))
        keys = (n_ed, n_pub_ed, n_pq, n_pub_pq)
        return events + [rot], ident, genesis, keys, (priv, priv_pq)


class TestNominal(_Base):

    def test_native_and_upgraded(self):
        from aiss.identity import verify_rotation_chain
        for kind in ("native", "upgraded"):
            with self.subTest(previous=kind):
                chain, ident, genesis, _, _ = self.rotate(kind)
                self.assertTrue(verify_rotation_chain(chain, ident, genesis))
                rot = chain[-1]
                self.assertEqual(rot["version"], "AISS-2.1")
                self.assertEqual(rot["agent_id"], ident["agent_id"])
                self.assertEqual(rot["payload"]["event_type"], "key_rotation")
                self.assertEqual(len(genesis["previous_hash"]), 128)

    def test_upgraded_old_chain_links_aiss1_hash_to_rotation_event(self):
        chain, _, _, _, _ = self.rotate("upgraded")
        self.assertEqual(len(chain[-1]["previous_hash"]), 64)  # SHA-256 du dernier AISS-1

    def test_new_chain_verifies_with_its_own_identity(self):
        import aiss
        from aiss.identity import export_identity_aiss21, derive_agent_id_aiss21
        chain, ident, genesis, (n_ed, n_pub_ed, n_pq, n_pub_pq), _ = self.rotate("native")
        new_id = derive_agent_id_aiss21(n_pub_ed, n_pub_pq)
        new_identity = export_identity_aiss21(new_id, n_pub_ed, n_pub_pq)
        self.assertTrue(aiss.verify_chain([genesis], new_identity))


class TestRejections(_Base):

    def setUp(self):
        super().setUp()
        self.chain, self.ident, self.genesis, self.keys, self.old_keys = self.rotate("native")

    def _ok(self, chain=None, ident=None, genesis=None):
        from aiss.identity import verify_rotation_chain
        return verify_rotation_chain(
            self.chain if chain is None else chain,
            self.ident if ident is None else ident,
            self.genesis if genesis is None else genesis)

    def test_event_appended_after_rotation_rejected(self):
        from aiss.chain import compute_event_hash
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        priv, priv_pq = self.old_keys
        with _pro():
            late = stamp_event_aiss2_hybrid(
                priv, priv_pq, self.ident["agent_id"], {"late": True},
                previous_hash=compute_event_hash(self.chain[-1]), tsa_stamp_after=False)
        self.assertFalse(self._ok(chain=self.chain + [late]))
        self.assertTrue(self._ok())

    def test_wrong_genesis_hash_rejected(self):
        from aiss.stamp_aiss2 import stamp_genesis_event_aiss2_hybrid
        n_ed, n_pub_ed, n_pq, n_pub_pq = self.keys
        with _pro():
            default = stamp_genesis_event_aiss2_hybrid(
                n_ed, n_pq, n_pub_ed, self.genesis["agent_id"], {"x": 1},
                public_key_pq=n_pub_pq, tsa_stamp_after=False)
            other = stamp_genesis_event_aiss2_hybrid(
                n_ed, n_pq, n_pub_ed, self.genesis["agent_id"], {"x": 1},
                public_key_pq=n_pub_pq, tsa_stamp_after=False,
                rotation_previous_hash="0" * 128)
        self.assertFalse(self._ok(genesis=default))
        self.assertFalse(self._ok(genesis=other))
        tampered = copy.deepcopy(self.genesis)
        tampered["previous_hash"] = "1" * 128
        self.assertFalse(self._ok(genesis=tampered))

    def test_genesis_of_another_agent_rejected(self):
        from aiss.chain import compute_event_hash
        from aiss.stamp_aiss2 import stamp_genesis_event_aiss2_hybrid
        from aiss.identity import derive_agent_id_aiss21
        o_ed, o_pub_ed, o_pq, o_pub_pq = self.new_keys()
        with _pro():
            foreign = stamp_genesis_event_aiss2_hybrid(
                o_ed, o_pq, o_pub_ed, derive_agent_id_aiss21(o_pub_ed, o_pub_pq), {"x": 1},
                public_key_pq=o_pub_pq, tsa_stamp_after=False,
                rotation_previous_hash=compute_event_hash(self.chain[-1]))
        self.assertFalse(self._ok(genesis=foreign))

    def test_genesis_not_signed_by_new_keys_rejected(self):
        tampered = copy.deepcopy(self.genesis)
        tampered["payload"] = {"action": "autre"}
        self.assertFalse(self._ok(genesis=tampered))

    def test_rotation_attestation_of_another_identity_rejected(self):
        other, _, _ = self.previous("upgraded")
        self.assertFalse(self._ok(ident=other))

    def test_old_chain_must_verify(self):
        broken = copy.deepcopy(self.chain)
        broken[0]["payload"] = {"seq": 99}
        self.assertFalse(self._ok(chain=broken))

    def test_last_event_not_a_rotation(self):
        self.assertFalse(self._ok(chain=self.chain[:-1]))
        self.assertFalse(self._ok(chain=[self.chain[-1], self.chain[0]]))

    def test_malformed_inputs_return_false_without_raising(self):
        from aiss.identity import verify_rotation_chain
        for chain in (None, [], "x", [None], [{}], {"a": 1}):
            with self.subTest(chain=repr(chain)):
                self.assertFalse(verify_rotation_chain(chain, self.ident, self.genesis))
        for genesis in (None, {}, [], "x"):
            with self.subTest(genesis=repr(genesis)):
                self.assertFalse(verify_rotation_chain(self.chain, self.ident, genesis))
        for ident in (None, {}, [], "x"):
            with self.subTest(identity=repr(ident)):
                self.assertFalse(verify_rotation_chain(self.chain, ident, self.genesis))

    def test_concurrent_rotations_on_same_previous_hash_are_a_fork(self):
        from aiss.fork import ForkDetector, find_forks
        from aiss.identity import create_rotation_event_aiss21, verify_rotation_chain
        priv, priv_pq = self.old_keys
        last_old_hash = self.chain[-1]["previous_hash"]
        n_ed, n_pub_ed, n_pq, n_pub_pq = self.new_keys()
        with _pro():
            second = create_rotation_event_aiss21(
                self.ident, priv, priv_pq, n_ed, n_pub_ed, n_pq, n_pub_pq, last_old_hash)
        events = self.chain + [second]
        fork = ForkDetector().detect(events)
        self.assertIsNotNone(fork)
        self.assertEqual(fork.hash, last_old_hash)
        self.assertEqual(len(find_forks(events)), 1)
        self.assertFalse(verify_rotation_chain(events, self.ident, self.genesis))


class TestSelfRotationAndGenesisParameter(_Base):

    def test_creation_rejects_rotation_to_self(self):
        from aiss.identity import create_rotation_attestation_hybrid
        from aiss.crypto import ed25519, dilithium  # noqa: F401
        ident, priv, priv_pq = self.previous("native")
        pub_ed = _b64(ident["public_key_classical"])
        pub_pq = _b64(ident["public_key_pq"])
        with self.assertRaises(ValueError) as ctx:
            create_rotation_attestation_hybrid(ident, priv, priv_pq, priv, pub_ed, priv_pq, pub_pq)
        self.assertIn("soi-même", str(ctx.exception))

    def test_verification_rejects_rotation_to_self_even_if_signed(self):
        from aiss.crypto import ed25519, dilithium
        from aiss.identity import (
            _domain_signed_message, _ROTATION_DOMAIN_PREFIX, _b64_prefixed,
            verify_rotation_attestation_hybrid)
        ident, priv, priv_pq = self.previous("native")
        unsigned = {
            "version": "AISS-2.1", "type": "key_rotation",
            "previous_agent_id": ident["agent_id"],
            "previous_public_key_classical": ident["public_key_classical"],
            "previous_public_key_pq": ident["public_key_pq"],
            "new_agent_id": ident["agent_id"],
            "new_public_key_classical": ident["public_key_classical"],
            "new_public_key_pq": ident["public_key_pq"],
            "rotation_timestamp": 1,
        }
        msg = _domain_signed_message(_ROTATION_DOMAIN_PREFIX, unsigned)
        ed = {"algorithm": "Ed25519", "signature": _b64_prefixed(ed25519.sign(priv, msg))}
        pq = {"algorithm": "ML-DSA-65", "signature": _b64_prefixed(dilithium.sign(priv_pq, msg))}
        att = dict(unsigned, signatures={
            "previous_classical": ed, "previous_post_quantum": pq,
            "new_classical": ed, "new_post_quantum": pq})
        self.assertFalse(verify_rotation_attestation_hybrid(att, ident))

    def test_rotation_previous_hash_validation(self):
        from aiss.identity import derive_agent_id_aiss21
        from aiss.stamp_aiss2 import stamp_genesis_event_aiss2_hybrid
        n_ed, n_pub_ed, n_pq, n_pub_pq = self.new_keys()
        aid = derive_agent_id_aiss21(n_pub_ed, n_pub_pq)

        def stamp(h):
            with _pro():
                return stamp_genesis_event_aiss2_hybrid(
                    n_ed, n_pq, n_pub_ed, aid, {"x": 1}, public_key_pq=n_pub_pq,
                    tsa_stamp_after=False, rotation_previous_hash=h)

        for bad in ("A" * 128, "a" * 127, "a" * 129, "a" * 64, "g" * 128, "", 123, b"a" * 128):
            with self.subTest(value=repr(bad)[:20]):
                with self.assertRaises(ValueError):
                    stamp(bad)
        self.assertEqual(stamp("ab" * 64)["previous_hash"], "ab" * 64)

    def test_genesis_without_parameter_is_unchanged(self):
        import hashlib
        from aiss.identity import derive_agent_id_aiss21
        from aiss.stamp_aiss2 import stamp_genesis_event_aiss2_hybrid
        n_ed, n_pub_ed, n_pq, n_pub_pq = self.new_keys()
        aid = derive_agent_id_aiss21(n_pub_ed, n_pub_pq)
        with _pro():
            ev = stamp_genesis_event_aiss2_hybrid(
                n_ed, n_pq, n_pub_ed, aid, {"x": 1}, public_key_pq=n_pub_pq,
                tsa_stamp_after=False)
        self.assertEqual(
            ev["previous_hash"],
            hashlib.sha512(b"PiQrypt-AISS-2.1-genesis\x00" + aid.encode("ascii")).hexdigest())


def _b64(value):
    import base64
    return base64.b64decode(value[7:], validate=True)


if __name__ == "__main__":
    unittest.main()
