# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — B.4 : verify_chain, verify_audit_chain, get_verification_report et garde-fous
pour les trois formes d'identité (classique, mise à niveau, hybride native).

Signature d'événements hybrides : fixture de licence Pro des autres tests (sans secret).
"""
import nacl.signing  # noqa: F401

import base64
import contextlib
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
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

    # -- fabriques d'identités ------------------------------------------------
    def make_classical(self, name="cl"):
        from aiss.identity import create_agent_identity
        from aiss.key_store import load_encrypted_key
        r = create_agent_identity(name, passphrase=PASSPHRASE, base_dir=self.tmp)
        priv = load_encrypted_key(self._dir(name) / "private.key.enc", PASSPHRASE)
        return r["identity"], priv, None, None

    def make_upgraded(self, name="up"):
        from aiss.identity import create_agent_identity, upgrade_agent_identity, load_agent_pq_key
        from aiss.key_store import load_encrypted_key
        create_agent_identity(name, passphrase=PASSPHRASE, base_dir=self.tmp)
        r = upgrade_agent_identity(name, PASSPHRASE, PASSPHRASE, base_dir=self.tmp)
        priv = load_encrypted_key(self._dir(name) / "private.key.enc", PASSPHRASE)
        priv_pq = load_agent_pq_key(name, PASSPHRASE, base_dir=self.tmp)
        pub_pq = base64.b64decode(r["identity"]["public_key_pq"][7:])
        return r["identity"], priv, priv_pq, pub_pq

    def make_native(self, name="na"):
        from aiss.identity import create_agent_identity, load_agent_pq_key
        from aiss.key_store import load_encrypted_key
        r = create_agent_identity(name, passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        priv = load_encrypted_key(self._dir(name) / "private.key.enc", PASSPHRASE)
        priv_pq = load_agent_pq_key(name, PASSPHRASE, base_dir=self.tmp)
        pub_pq = base64.b64decode(r["identity"]["public_key_pq"][7:])
        return r["identity"], priv, priv_pq, pub_pq

    # -- fabriques d'événements ----------------------------------------------
    @staticmethod
    def e1(priv, agent_id, seq, prev=None):
        import aiss
        return aiss.stamp_event(priv, agent_id, {"seq": seq}, previous_hash=prev)

    @staticmethod
    def e21(priv, priv_pq, agent_id, seq, prev=None):
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        with _pro():
            return stamp_event_aiss2_hybrid(
                priv, priv_pq, agent_id, {"seq": seq}, previous_hash=prev, tsa_stamp_after=False)

    def chain21(self, ident, priv, priv_pq, n=3):
        from aiss.chain import compute_event_hash
        events, prev = [], None
        for i in range(n):
            ev = self.e21(priv, priv_pq, ident["agent_id"], i, prev)
            events.append(ev)
            prev = compute_event_hash(ev)
        return events


class TestVerifyChainForms(_Base):

    def test_classical_unchanged(self):
        import aiss
        from aiss.chain import compute_event_hash
        ident, priv, _, _ = self.make_classical()
        a = self.e1(priv, ident["agent_id"], 0)
        b = self.e1(priv, ident["agent_id"], 1, compute_event_hash(a))
        self.assertTrue(aiss.verify_chain([a, b], ident))

    def test_native_valid(self):
        import aiss
        ident, priv, priv_pq, pub_pq = self.make_native()
        events = self.chain21(ident, priv, priv_pq)
        self.assertTrue(aiss.verify_chain(events, ident))
        self.assertTrue(aiss.verify_chain(events, ident, public_key_pq=pub_pq))

    def test_upgraded_valid_mixed_chain(self):
        import aiss
        from aiss.chain import compute_event_hash
        ident, priv, priv_pq, pub_pq = self.make_upgraded()
        a = self.e1(priv, ident["agent_id"], 0)
        b = self.e1(priv, ident["agent_id"], 1, compute_event_hash(a))
        c = self.e21(priv, priv_pq, ident["agent_id"], 2, compute_event_hash(b))
        d = self.e21(priv, priv_pq, ident["agent_id"], 3, compute_event_hash(c))
        self.assertTrue(aiss.verify_chain([a, b, c, d], ident))
        self.assertTrue(aiss.verify_chain([a, b, c, d], ident, public_key_pq=pub_pq))

    def test_upgraded_pure_aiss1_chain_valid(self):
        import aiss
        from aiss.chain import compute_event_hash
        ident, priv, _, _ = self.make_upgraded()
        a = self.e1(priv, ident["agent_id"], 0)
        b = self.e1(priv, ident["agent_id"], 1, compute_event_hash(a))
        self.assertTrue(aiss.verify_chain([a, b], ident))

    def test_event_of_another_agent_id_rejected(self):
        import aiss
        from aiss.chain import compute_event_hash
        from aiss.exceptions import InvalidChainError
        for make in (self.make_native, self.make_upgraded):
            ident, priv, priv_pq, _ = make(make.__name__)
            a = self.e21(priv, priv_pq, ident["agent_id"], 0)
            b = self.e21(priv, priv_pq, "Z" * 32, 1, compute_event_hash(a))
            with self.subTest(form=make.__name__):
                with self.assertRaises(InvalidChainError) as ctx:
                    aiss.verify_chain([a, b], ident)
                self.assertEqual(ctx.exception.event_index, 1)

    def test_aiss1_event_in_native_chain_rejected(self):
        import aiss
        from aiss.chain import compute_event_hash
        from aiss.exceptions import InvalidChainError
        ident, priv, priv_pq, _ = self.make_native()
        a = self.e21(priv, priv_pq, ident["agent_id"], 0)
        b = self.e1(priv, ident["agent_id"], 1, compute_event_hash(a))
        with self.assertRaises(InvalidChainError) as ctx:
            aiss.verify_chain([a, b], ident)
        self.assertEqual(ctx.exception.event_index, 1)
        first = self.e1(priv, ident["agent_id"], 0)
        with self.assertRaises(InvalidChainError) as ctx:
            aiss.verify_chain([first], ident)
        self.assertEqual(ctx.exception.event_index, 0)

    def test_aiss1_after_first_aiss21_rejected_for_upgraded(self):
        import aiss
        from aiss.chain import compute_event_hash
        from aiss.exceptions import InvalidChainError
        ident, priv, priv_pq, _ = self.make_upgraded()
        a = self.e1(priv, ident["agent_id"], 0)
        b = self.e21(priv, priv_pq, ident["agent_id"], 1, compute_event_hash(a))
        c = self.e1(priv, ident["agent_id"], 2, compute_event_hash(b))
        with self.assertRaises(InvalidChainError) as ctx:
            aiss.verify_chain([a, b, c], ident)
        self.assertEqual(ctx.exception.event_index, 2)

    def test_pq_parameter_different_from_identity_rejected(self):
        import aiss
        from aiss.crypto import dilithium
        from aiss.exceptions import InvalidChainError
        for make in (self.make_native, self.make_upgraded):
            ident, priv, priv_pq, _ = make(make.__name__ + "2")
            events = self.chain21(ident, priv, priv_pq, 2)
            _, other_pub = dilithium.generate_keypair()
            with self.subTest(form=make.__name__):
                with self.assertRaises(InvalidChainError):
                    aiss.verify_chain(events, ident, public_key_pq=other_pub)

    def test_wrong_pq_key_in_identity_rejected(self):
        import aiss
        from aiss.crypto import dilithium
        from aiss.exceptions import InvalidChainError
        ident, priv, priv_pq, _ = self.make_native()
        events = self.chain21(ident, priv, priv_pq, 2)
        _, other_pub = dilithium.generate_keypair()
        forged = dict(ident, public_key_pq="base64:" + base64.b64encode(other_pub).decode())
        with self.assertRaises(InvalidChainError):
            aiss.verify_chain(events, forged)

    def test_wrong_pq_signature_rejected(self):
        import aiss
        from aiss.exceptions import InvalidChainError
        ident, priv, priv_pq, _ = self.make_native()
        events = self.chain21(ident, priv, priv_pq, 2)
        sig = events[1]["signatures"]["post_quantum"]["signature"]
        raw = bytearray(base64.b64decode(sig[7:]))
        raw[10] ^= 1
        events[1]["signatures"]["post_quantum"]["signature"] = "base64:" + base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(InvalidChainError):
            aiss.verify_chain(events, ident)

    def test_altered_binding_rejected(self):
        import aiss
        from aiss.exceptions import InvalidChainError
        ident, priv, priv_pq, _ = self.make_upgraded()
        events = self.chain21(ident, priv, priv_pq, 2)
        forged = copy.deepcopy(ident)
        forged["binding"]["created_at"] += 1
        with self.assertRaises(InvalidChainError):
            aiss.verify_chain(events, forged)

    def test_ambiguous_documents_rejected(self):
        import aiss
        from aiss.exceptions import InvalidChainError
        nat, priv, priv_pq, _ = self.make_native()
        up, _, _, _ = self.make_upgraded()
        events = self.chain21(nat, priv, priv_pq, 1)
        with self.assertRaises(InvalidChainError):
            aiss.verify_chain(events, dict(nat, binding=up["binding"]))
        with self.assertRaises(InvalidChainError):
            aiss.verify_chain(events, dict(nat, public_key=up["public_key"]))

    def test_classical_identity_with_pq_param_unchanged_behaviour(self):
        import aiss
        from aiss.exceptions import InvalidChainError
        ident, priv, _, _ = self.make_classical()
        a = self.e1(priv, ident["agent_id"], 0)
        self.assertTrue(aiss.verify_chain([a], ident, public_key_pq=None))
        # sans clé PQ ni liaison, un événement AISS-2 reste refusé comme avant
        ident2, p2, pq2, _ = self.make_native("autre")
        ev = self.e21(p2, pq2, ident["agent_id"], 0)
        with self.assertRaises(InvalidChainError):
            aiss.verify_chain([ev], ident)


class TestAuditChain(_Base):

    def _tamper_signature(self, ev):
        raw = bytearray(base64.b64decode(ev["signatures"]["classical"]["signature"][7:]))
        raw[0] ^= 1
        ev["signatures"]["classical"]["signature"] = "base64:" + base64.b64encode(bytes(raw)).decode()

    def test_native_identity_with_altered_signature_raises(self):
        from aiss.verify import verify_audit_chain
        from aiss.exceptions import InvalidChainError
        ident, priv, priv_pq, _ = self.make_native()
        events = self.chain21(ident, priv, priv_pq, 2)
        self.assertTrue(verify_audit_chain({"events": events, "agent_identity": ident}))
        self._tamper_signature(events[1])
        with self.assertRaises(InvalidChainError):
            verify_audit_chain({"events": events, "agent_identity": ident})

    def test_upgraded_identity_verified_and_tamper_detected(self):
        from aiss.verify import verify_audit_chain
        from aiss.exceptions import InvalidChainError
        ident, priv, priv_pq, _ = self.make_upgraded()
        events = self.chain21(ident, priv, priv_pq, 2)
        self.assertTrue(verify_audit_chain({"events": events, "agent_identity": ident}))
        self._tamper_signature(events[0])
        with self.assertRaises(InvalidChainError):
            verify_audit_chain({"events": events, "agent_identity": ident})

    def test_identity_without_any_key_field_stays_structure_only(self):
        from aiss.verify import verify_audit_chain
        ident, priv, _, _ = self.make_classical()
        a = self.e1(priv, ident["agent_id"], 0)
        self.assertTrue(verify_audit_chain({"events": [a], "agent_identity": {"agent_id": "x"}}))
        self.assertTrue(verify_audit_chain({"events": [a]}))

    def test_classical_identity_still_fully_verified(self):
        from aiss.verify import verify_audit_chain
        from aiss.exceptions import InvalidChainError
        ident, priv, _, _ = self.make_classical()
        a = self.e1(priv, ident["agent_id"], 0)
        self.assertTrue(verify_audit_chain({"events": [a], "agent_identity": ident}))
        a["payload"] = {"seq": 99}
        with self.assertRaises(InvalidChainError):
            verify_audit_chain({"events": [a], "agent_identity": ident})


class TestVerificationReport(_Base):

    CLASSICAL_KEYS = {"valid", "signatures_valid", "chain_valid", "timestamps_valid",
                      "forks_detected", "replay_attacks", "errors"}

    def test_classical(self):
        from aiss.verify import get_verification_report
        ident, priv, _, _ = self.make_classical()
        a = self.e1(priv, ident["agent_id"], 0)
        rep = get_verification_report([a], ident)
        self.assertTrue(rep["valid"])
        self.assertIsNone(rep["binding_assurance"])
        self.assertEqual(set(rep) - {"binding_assurance"}, self.CLASSICAL_KEYS)

    def test_upgraded(self):
        from aiss.verify import get_verification_report
        ident, priv, priv_pq, _ = self.make_upgraded()
        events = self.chain21(ident, priv, priv_pq, 2)
        rep = get_verification_report(events, ident)
        self.assertTrue(rep["valid"], rep["errors"])
        self.assertEqual(rep["binding_assurance"], "classical_only")

    def test_native(self):
        from aiss.verify import get_verification_report
        ident, priv, priv_pq, _ = self.make_native()
        events = self.chain21(ident, priv, priv_pq, 2)
        rep = get_verification_report(events, ident)
        self.assertTrue(rep["valid"], rep["errors"])
        self.assertTrue(rep["signatures_valid"])
        self.assertEqual(rep["binding_assurance"], "hybrid")

    def test_native_tampered_signature_reported_without_raising(self):
        from aiss.verify import get_verification_report
        ident, priv, priv_pq, _ = self.make_native()
        events = self.chain21(ident, priv, priv_pq, 2)
        raw = bytearray(base64.b64decode(events[0]["signatures"]["classical"]["signature"][7:]))
        raw[0] ^= 1
        events[0]["signatures"]["classical"]["signature"] = "base64:" + base64.b64encode(bytes(raw)).decode()
        rep = get_verification_report(events, ident)
        self.assertFalse(rep["valid"])
        self.assertFalse(rep["signatures_valid"])
        self.assertEqual(rep["binding_assurance"], "hybrid")

    def test_invalid_identity_reported(self):
        from aiss.verify import get_verification_report
        ident, priv, priv_pq, _ = self.make_native()
        events = self.chain21(ident, priv, priv_pq, 1)
        rep = get_verification_report(events, dict(ident, agent_id="Q" * 32))
        self.assertFalse(rep["valid"])
        self.assertIsNone(rep["binding_assurance"])


class TestNativeHybridGuards(_Base):

    def _cli(self, args):
        return subprocess.run(
            # Comme le point d'entrée console : cli.main entièrement importé avant main()
            [sys.executable, "-c", "import sys; from cli.main import main; sys.exit(main())"]
            + args, cwd=str(REPO_ROOT),
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
            env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
                 "USERPROFILE": self.tmp, "HOME": self.tmp,
                 "PIQRYPT_HOME": str(Path(self.tmp) / ".piqrypt")},
        )

    def test_cli_commands_refuse_native_hybrid_identity(self):
        ident, _, _, _ = self.make_native()
        doc = {"identity": ident, "private_key": "AAAA"}
        f = Path(self.tmp) / "native.json"
        f.write_text(json.dumps(doc))
        other = Path(self.tmp) / "other.json"
        other.write_text("{}")
        keys = Path(self.tmp) / "keys.json"
        keys.write_text(json.dumps({ident["agent_id"]: doc}))
        cases = {
            "identity rotate": ["identity", "rotate", str(f), str(other)],
            "verify": ["verify", str(other), "--identity", str(f)],
            "authority create": ["authority", "create", str(f), "subject"],
            "authority verify": ["authority", "verify", str(other), str(f)],
            "authority chain": ["authority", "chain", str(other), "--pubkeys", str(keys)],
            "a2a propose": ["a2a", "propose", "--identity", str(f)],
            "a2a respond": ["a2a", "respond", "--identity", str(f), "--proposal", str(other)],
        }
        for label, argv in cases.items():
            with self.subTest(command=label):
                r = self._cli(argv)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("identité hybride native : non prise en charge par cette commande "
                              "en 1.10", r.stderr)
                self.assertNotIn("Traceback", r.stderr)

    def test_certified_export_verification_raises_explicitly(self):
        from aiss.exports import verify_certified_export
        from aiss.exceptions import AISSError
        ident, _, _, _ = self.make_native()
        export = Path(self.tmp) / "audit.json"
        export.write_text(json.dumps({"agent_identity": ident, "events": []}))
        cert = Path(self.tmp) / "audit.json.cert"
        cert.write_text(json.dumps({"export_hash": "sha256:00", "signature": "AA=="}))
        with self.assertRaises(AISSError) as ctx:
            verify_certified_export(str(export), str(cert))
        self.assertIn("non prise en charge", str(ctx.exception))

    def test_certified_export_verification_unchanged_for_other_identities(self):
        from aiss.exports import verify_certified_export
        export = Path(self.tmp) / "audit2.json"
        export.write_text(json.dumps({"agent_identity": {"public_key": "AAAA"}, "events": []}))
        cert = Path(self.tmp) / "audit2.json.cert"
        cert.write_text(json.dumps({"export_hash": "sha256:00", "signature": "AA=="}))
        self.assertFalse(verify_certified_export(str(export), str(cert)))


if __name__ == "__main__":
    unittest.main()
