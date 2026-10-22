# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — robustesse de la vérification face à des entrées non fiables.

Toute entrée malformée doit produire une AISSError (InvalidSignatureError, InvalidChainError,
InvalidCanonicalJSONError) ou un faux pour les vérificateurs booléens : jamais AttributeError,
TypeError ou une erreur interne du canonicaliseur. Les cas valides ne changent pas.
"""
import nacl.signing  # noqa: F401

import base64
import contextlib
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

PASSPHRASE = "correct horse battery"
BIG = 2 ** 53  # premier entier hors de +/-(2^53-1)


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


class TestCanonicalizer(unittest.TestCase):

    def test_out_of_domain_values_raise_an_aiss_error_that_is_also_a_value_error(self):
        from aiss.canonical_aiss21 import canonicalize, hash_event
        from aiss.exceptions import AISSError, InvalidCanonicalJSONError
        for bad in ({"n": BIG}, {"n": -BIG}, {"n": float("nan")}, {"n": float("inf")},
                    {"n": object()}, {"n": {"m": [BIG]}}):
            with self.subTest(value=repr(bad)[:30]):
                for call in (canonicalize, hash_event):
                    with self.assertRaises(InvalidCanonicalJSONError) as ctx:
                        call(bad)
                    self.assertIsInstance(ctx.exception, AISSError)
                    self.assertIsInstance(ctx.exception, ValueError)

    def test_valid_values_unchanged(self):
        from aiss.canonical_aiss21 import canonicalize
        self.assertEqual(canonicalize({"b": 2 ** 53 - 1, "a": [1, 1.5, None]}),
                         b'{"a":[1,1.5,null],"b":9007199254740991}')

    def test_compute_event_hash_on_out_of_domain_aiss21_event(self):
        from aiss.chain import compute_event_hash
        from aiss.exceptions import AISSError
        event = {"version": "AISS-2.1", "payload": {"n": BIG}, "signatures": {}}
        with self.assertRaises(AISSError):
            compute_event_hash(event)


@pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")
class TestMalformedEvents(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = patch("aiss.key_store._SCRYPT_N", 2 ** 10)
        p.start()
        self.addCleanup(p.stop)
        from aiss.identity import create_agent_identity, load_agent_pq_key
        from aiss.key_store import load_encrypted_key
        from aiss.chain import compute_event_hash
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        self.identity = create_agent_identity(
            "rb", passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)["identity"]
        d = Path(self.tmp) / "agents" / "rb"
        priv = load_encrypted_key(d / "private.key.enc", PASSPHRASE)
        priv_pq = load_agent_pq_key("rb", PASSPHRASE, base_dir=self.tmp)
        with _pro():
            first = stamp_event_aiss2_hybrid(
                priv, priv_pq, self.identity["agent_id"], {"seq": 0}, tsa_stamp_after=False)
            second = stamp_event_aiss2_hybrid(
                priv, priv_pq, self.identity["agent_id"], {"seq": 1},
                previous_hash=compute_event_hash(first), tsa_stamp_after=False)
        self.events = [first, second]
        self.ed = base64.b64decode(self.identity["public_key_classical"][7:])
        self.pq = base64.b64decode(self.identity["public_key_pq"][7:])

    def mutate(self, fn, index=1):
        events = copy.deepcopy(self.events)
        fn(events[index])
        return events

    # -- verify_aiss2_hybrid ---------------------------------------------------
    def test_event_verification_fails_closed(self):
        from aiss.exceptions import InvalidSignatureError
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        cases = {
            "payload integer out of range": lambda e: e["payload"].__setitem__("n", BIG),
            "timestamp out of range": lambda e: e.__setitem__("timestamp", BIG),
            "negative out of range": lambda e: e["payload"].__setitem__("n", -BIG),
            "nan in payload": lambda e: e["payload"].__setitem__("n", float("nan")),
            "signatures is a list": lambda e: e.__setitem__("signatures", []),
            "signatures is null": lambda e: e.__setitem__("signatures", None),
            "classical entry is a string": lambda e: e["signatures"].__setitem__("classical", "x"),
            "signature is an integer": lambda e: e["signatures"]["classical"].__setitem__("signature", 7),
            "signature is null": lambda e: e["signatures"]["post_quantum"].__setitem__("signature", None),
            "signature key missing": lambda e: e["signatures"]["classical"].pop("signature"),
            "version is null": lambda e: e.__setitem__("version", None),
            "version is an integer": lambda e: e.__setitem__("version", 21),
            "version is a list": lambda e: e.__setitem__("version", ["AISS-2.1"]),
        }
        for label, fn in cases.items():
            with self.subTest(case=label):
                event = self.mutate(fn)[1]
                with self.assertRaises(InvalidSignatureError):
                    verify_aiss2_hybrid(event, self.ed, self.pq)

    def test_non_object_events_fail_closed(self):
        from aiss.exceptions import InvalidSignatureError
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        for junk in (None, [], "x", 5):
            with self.subTest(event=repr(junk)):
                with self.assertRaises(InvalidSignatureError):
                    verify_aiss2_hybrid(junk, self.ed, self.pq)

    def test_valid_events_still_verify(self):
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        for event in self.events:
            self.assertTrue(verify_aiss2_hybrid(event, self.ed, self.pq))

    # -- verify_chain ----------------------------------------------------------
    def test_chain_rejects_malformed_events_with_invalid_chain_error(self):
        import aiss
        from aiss.exceptions import InvalidChainError
        cases = {
            "version null": lambda e: e.__setitem__("version", None),
            "version integer": lambda e: e.__setitem__("version", 2),
            "version list": lambda e: e.__setitem__("version", ["AISS-2.1"]),
            "payload integer out of range": lambda e: e["payload"].__setitem__("n", BIG),
            "timestamp out of range": lambda e: e.__setitem__("timestamp", BIG),
        }
        for label, fn in cases.items():
            for form in ("hybrid native", "classical + pq parameter"):
                with self.subTest(case=label, identity=form):
                    events = self.mutate(fn)
                    with self.assertRaises(InvalidChainError):
                        aiss.verify_chain(events, self.identity)
        for junk in (None, "x", 3, []):
            with self.subTest(event=repr(junk)):
                with self.assertRaises(InvalidChainError):
                    aiss.verify_chain([self.events[0], junk], self.identity)

    def test_chain_with_non_text_version_and_classical_identity(self):
        import aiss
        from aiss.exceptions import InvalidChainError
        priv, pub = aiss.generate_keypair()
        identity = aiss.export_identity(aiss.derive_agent_id(pub), pub)
        event = aiss.stamp_event(priv, identity["agent_id"], {"a": 1})
        self.assertTrue(aiss.verify_chain([event], identity))
        for version in (None, 1, ["AISS-1.0"], {"v": 1}):
            with self.subTest(version=repr(version)):
                bad = dict(event, version=version)
                with self.assertRaises(InvalidChainError):
                    aiss.verify_chain([bad], identity)

    def test_audit_chain_and_report_do_not_leak_internal_errors(self):
        from aiss.exceptions import AISSError
        from aiss.verify import get_verification_report, verify_audit_chain
        events = self.mutate(lambda e: e.__setitem__("version", None))
        with self.assertRaises(AISSError):
            verify_audit_chain({"events": events, "agent_identity": self.identity})
        report = get_verification_report(events, self.identity)
        self.assertFalse(report["valid"])

    # -- vérificateurs booléens ------------------------------------------------
    def test_boolean_verifiers_return_false_for_out_of_domain_numbers(self):
        from aiss.identity import (
            create_rotation_attestation_hybrid, verify_identity_binding,
            verify_rotation_attestation_hybrid, verify_rotation_chain)
        from aiss.crypto import ed25519, dilithium
        from aiss.key_store import load_encrypted_key
        from aiss.identity import load_agent_pq_key, upgrade_agent_identity, create_agent_identity

        create_agent_identity("rb_up", passphrase=PASSPHRASE, base_dir=self.tmp)
        upgraded = upgrade_agent_identity("rb_up", PASSPHRASE, PASSPHRASE, base_dir=self.tmp)["identity"]
        self.assertTrue(verify_identity_binding(upgraded))
        bad = copy.deepcopy(upgraded)
        bad["binding"]["created_at"] = BIG
        self.assertFalse(verify_identity_binding(bad))

        d = Path(self.tmp) / "agents" / "rb"
        n_ed, n_pub_ed = ed25519.generate_keypair()
        n_pq, n_pub_pq = dilithium.generate_keypair()
        att = create_rotation_attestation_hybrid(
            self.identity, load_encrypted_key(d / "private.key.enc", PASSPHRASE),
            load_agent_pq_key("rb", PASSPHRASE, base_dir=self.tmp), n_ed, n_pub_ed, n_pq, n_pub_pq)
        self.assertTrue(verify_rotation_attestation_hybrid(att, self.identity))
        bad_att = dict(att, rotation_timestamp=BIG)
        self.assertFalse(verify_rotation_attestation_hybrid(bad_att, self.identity))
        bad_event = copy.deepcopy(self.events[1])
        bad_event["payload"] = {"event_type": "key_rotation", "attestation": bad_att}
        self.assertFalse(verify_rotation_chain(
            [self.events[0], bad_event], self.identity, copy.deepcopy(self.events[0])))


if __name__ == "__main__":
    unittest.main()
