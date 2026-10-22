# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""Tests — la version d'événement "AISS-2.1" est comparée exactement (pas par préfixe)."""
import nacl.signing  # noqa: F401

import contextlib
import copy
import hashlib
import tempfile
import unittest
from unittest.mock import patch

import pytest


def _pq_available():
    try:
        from aiss.crypto import dilithium
        return dilithium is not None and dilithium.is_available()
    except Exception:
        return False


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


BASE_EVENT = {
    "version": "AISS-1.0", "agent_id": "a" * 32, "timestamp": 1, "nonce": "n",
    "payload": {"x": 1}, "previous_hash": None, "signature": "s",
}


class TestComputeEventHash(unittest.TestCase):

    def test_lookalike_versions_use_sha256(self):
        from aiss.chain import compute_event_hash
        from aiss.canonical import canonicalize
        for version in ("AISS-2.10", "AISS-2.1x", "AISS-2.1.1", "AISS-2.1 "):
            with self.subTest(version=version):
                event = dict(BASE_EVENT, version=version)
                h = compute_event_hash(event)
                self.assertEqual(len(h), 64)
                body = {k: v for k, v in event.items() if k != "signature"}
                self.assertEqual(h, hashlib.sha256(canonicalize(body)).hexdigest())

    def test_exact_version_still_uses_sha512(self):
        from aiss.chain import compute_event_hash
        event = dict(BASE_EVENT, version="AISS-2.1", signatures={"classical": {}, "post_quantum": {}})
        event.pop("signature")
        self.assertEqual(len(compute_event_hash(event)), 128)


@pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")
class TestVerifyChainRejectsLookalike(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = patch("aiss.key_store._SCRYPT_N", 2 ** 10)
        p.start()
        self.addCleanup(p.stop)

    def _native(self):
        from pathlib import Path
        from aiss.identity import create_agent_identity, load_agent_pq_key
        from aiss.key_store import load_encrypted_key
        ident = create_agent_identity("v", passphrase="correct horse battery",
                                      base_dir=self.tmp, hybrid=True)["identity"]
        d = Path(self.tmp) / "agents" / "v"
        return (ident, load_encrypted_key(d / "private.key.enc", "correct horse battery"),
                load_agent_pq_key("v", "correct horse battery", base_dir=self.tmp))

    def test_lookalike_version_rejected_for_every_identity_form(self):
        import aiss
        from aiss.chain import compute_event_hash
        from aiss.exceptions import InvalidChainError
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        ident, priv, priv_pq = self._native()
        with _pro():
            first = stamp_event_aiss2_hybrid(
                priv, priv_pq, ident["agent_id"], {"seq": 0}, tsa_stamp_after=False)
            second = stamp_event_aiss2_hybrid(
                priv, priv_pq, ident["agent_id"], {"seq": 1},
                previous_hash=compute_event_hash(first), tsa_stamp_after=False)
        self.assertTrue(aiss.verify_chain([first, second], ident))

        forged = copy.deepcopy(second)
        forged["version"] = "AISS-2.10"
        with self.assertRaises(InvalidChainError) as ctx:
            aiss.verify_chain([first, forged], ident)
        self.assertEqual(ctx.exception.event_index, 1)

        classical, priv_c = aiss.generate_keypair()[::-1]  # (pub, priv) -> classique
        classical_identity = aiss.export_identity(aiss.derive_agent_id(classical), classical)
        with self.assertRaises(InvalidChainError):
            aiss.verify_chain([dict(forged, agent_id=classical_identity["agent_id"])],
                              classical_identity)


if __name__ == "__main__":
    unittest.main()
