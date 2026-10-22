# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""Tests — interface Signer (chantier F) : signataires, HybridSigner, intégration, conformité."""
import nacl.signing  # noqa: F401

import ast
import contextlib
import copy
import pickle
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


def _dilithium_py_available():
    try:
        import dilithium_py  # noqa: F401
        return True
    except ImportError:
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


@contextlib.contextmanager
def _deterministic_mldsa():
    """ML-DSA-65 déterministe (contexte vide) pour comparer octet pour octet."""
    from aiss.crypto import dilithium
    from dilithium_py.ml_dsa import ML_DSA_65

    def sign(sk, message):
        return ML_DSA_65.sign(bytes(sk), message, ctx=b"", deterministic=True)

    with patch.object(dilithium, "sign", side_effect=sign):
        yield


def _keys():
    from aiss.crypto import ed25519, dilithium
    priv_ed, pub_ed = ed25519.generate_keypair()
    priv_pq, pub_pq = dilithium.generate_keypair()
    return priv_ed, pub_ed, priv_pq, pub_pq


def _hybrid(priv_ed, pub_ed, priv_pq, pub_pq, **kw):
    from aiss.signer import HybridSigner, InMemoryEd25519Signer, InMemoryMlDsa65Signer
    return HybridSigner(InMemoryEd25519Signer(priv_ed, pub_ed),
                        InMemoryMlDsa65Signer(priv_pq, pub_pq), **kw)


class RemoteLikeSigner:
    """Faux signataire distant : les clés vivent dans une fermeture, hors de l'objet."""

    @staticmethod
    def make(algorithm, private_key, public_key, behaviour="ok"):
        from aiss.crypto import ed25519, dilithium
        from aiss.signer import Signer, SignerError

        state = {"closed": False}

        def remote_sign(message):
            if state["closed"]:
                raise SignerError("session closed")
            if behaviour == "raise":
                raise ConnectionError("HSM unreachable")
            if algorithm == "Ed25519":
                signature = ed25519.sign(private_key, message)
            else:
                signature = dilithium.sign(private_key, message)
            if behaviour == "short":
                return signature[:-1]
            if behaviour == "long":
                return signature + b"\x00"
            if behaviour == "wrong":
                return signature[:-1] + bytes([signature[-1] ^ 1])
            if behaviour == "none":
                return None
            return signature

        class _Remote(Signer):
            @property
            def algorithm(self):
                return algorithm

            def public_key(self):
                return public_key

            def sign(self, message):
                return remote_sign(message)

            def close(self):
                state["closed"] = True

        return _Remote()


# ─────────────────────────────────────────────────────────────────────────────
class TestInMemorySigners(unittest.TestCase):

    def test_ed25519_signer(self):
        from aiss.crypto import ed25519
        from aiss.signer import InMemoryEd25519Signer, Signer
        priv, pub, _, _ = _keys()
        signer = InMemoryEd25519Signer(bytearray(priv))
        self.assertIsInstance(signer, Signer)
        self.assertEqual(signer.algorithm, "Ed25519")
        self.assertEqual(signer.public_key(), pub)
        sig = signer.sign(b"message")
        self.assertEqual(len(sig), 64)
        self.assertTrue(ed25519.verify(pub, b"message", sig))
        self.assertEqual(sig, ed25519.sign(priv, b"message"))

    def test_mldsa_signer(self):
        from aiss.crypto import dilithium
        from aiss.signer import InMemoryMlDsa65Signer
        _, _, priv, pub = _keys()
        signer = InMemoryMlDsa65Signer(priv, pub)
        self.assertEqual(signer.algorithm, "ML-DSA-65")
        sig = signer.sign(b"message")
        self.assertEqual(len(sig), 3309)
        self.assertTrue(dilithium.verify(pub, b"message", sig))

    def test_key_sizes_are_checked(self):
        from aiss.signer import InMemoryEd25519Signer, InMemoryMlDsa65Signer, SignerError
        priv, pub, priv_pq, pub_pq = _keys()
        for build in (lambda: InMemoryEd25519Signer(priv[:31]),
                      lambda: InMemoryEd25519Signer(priv, pub[:31]),
                      lambda: InMemoryMlDsa65Signer(priv_pq[:-1], pub_pq),
                      lambda: InMemoryMlDsa65Signer(priv_pq, pub_pq[:-1])):
            with self.assertRaises(SignerError):
                build()

    def test_close_erases_the_key_and_fails_closed(self):
        from aiss.signer import InMemoryEd25519Signer, SignerError
        priv, _, _, _ = _keys()
        signer = InMemoryEd25519Signer(priv)
        buffer = signer._key
        self.assertNotEqual(bytes(buffer), b"\x00" * 32)
        signer.close()
        self.assertEqual(bytes(buffer), b"\x00" * 32)
        with self.assertRaises(SignerError):
            signer.sign(b"x")
        signer.close()  # idempotent

    def test_context_manager_closes(self):
        from aiss.signer import InMemoryEd25519Signer, SignerError
        priv, _, _, _ = _keys()
        with InMemoryEd25519Signer(priv) as signer:
            signer.sign(b"x")
        with self.assertRaises(SignerError):
            signer.sign(b"x")

    def test_private_key_is_not_exposed(self):
        from aiss.signer import InMemoryEd25519Signer
        priv, _, _, _ = _keys()
        signer = InMemoryEd25519Signer(priv)
        self.assertNotIn(priv.hex(), repr(signer))
        public_names = [n for n in dir(signer) if not n.startswith("_")]
        self.assertEqual(sorted(public_names), ["algorithm", "close", "public_key", "sign"])
        with self.assertRaises(TypeError):
            pickle.dumps(signer)
        with self.assertRaises(TypeError):
            copy.copy(signer)

    def test_signer_is_abstract(self):
        from aiss.signer import Signer
        with self.assertRaises(TypeError):
            Signer()


class TestHybridSigner(unittest.TestCase):

    def test_both_signatures_are_returned_and_verify(self):
        from aiss.crypto import ed25519, dilithium
        priv, pub, priv_pq, pub_pq = _keys()
        with _hybrid(priv, pub, priv_pq, pub_pq) as signer:
            self.assertEqual(signer.public_keys(), (pub, pub_pq))
            sig = signer.sign(b"M-prime")
        self.assertEqual((len(sig.classical), len(sig.post_quantum)), (64, 3309))
        self.assertTrue(ed25519.verify(pub, b"M-prime", sig.classical))
        self.assertTrue(dilithium.verify(pub_pq, b"M-prime", sig.post_quantum))

    def test_algorithms_are_checked(self):
        from aiss.signer import HybridSigner, InMemoryEd25519Signer, SignerError
        priv, _, _, _ = _keys()
        with self.assertRaises(SignerError):
            HybridSigner(InMemoryEd25519Signer(priv), InMemoryEd25519Signer(priv))

    def test_failures_never_return_a_single_signature(self):
        from aiss.signer import HybridSigner, SignerError
        priv, pub, priv_pq, pub_pq = _keys()
        ed_ok = lambda: RemoteLikeSigner.make("Ed25519", priv, pub)
        pq_ok = lambda: RemoteLikeSigner.make("ML-DSA-65", priv_pq, pub_pq)
        for label, ed, pq in [
            ("classical raises", RemoteLikeSigner.make("Ed25519", priv, pub, "raise"), pq_ok()),
            ("post-quantum raises", ed_ok(), RemoteLikeSigner.make("ML-DSA-65", priv_pq, pub_pq, "raise")),
            ("classical too short", RemoteLikeSigner.make("Ed25519", priv, pub, "short"), pq_ok()),
            ("classical too long", RemoteLikeSigner.make("Ed25519", priv, pub, "long"), pq_ok()),
            ("pq too short", ed_ok(), RemoteLikeSigner.make("ML-DSA-65", priv_pq, pub_pq, "short")),
            ("pq returns None", ed_ok(), RemoteLikeSigner.make("ML-DSA-65", priv_pq, pub_pq, "none")),
            ("classical wrong signature", RemoteLikeSigner.make("Ed25519", priv, pub, "wrong"), pq_ok()),
            ("pq wrong signature", ed_ok(), RemoteLikeSigner.make("ML-DSA-65", priv_pq, pub_pq, "wrong")),
        ]:
            with self.subTest(case=label):
                with self.assertRaises(SignerError):
                    HybridSigner(ed, pq).sign(b"message")

    def test_verify_after_sign_can_be_disabled_but_lengths_are_always_checked(self):
        from aiss.signer import HybridSigner, SignerError
        priv, pub, priv_pq, pub_pq = _keys()
        pq = RemoteLikeSigner.make("ML-DSA-65", priv_pq, pub_pq)
        wrong = RemoteLikeSigner.make("Ed25519", priv, pub, "wrong")
        result = HybridSigner(wrong, pq, verify_after_sign=False).sign(b"m")
        self.assertEqual(len(result.classical), 64)  # non vérifiée : à la charge de l'appelant
        short = RemoteLikeSigner.make("Ed25519", priv, pub, "short")
        with self.assertRaises(SignerError):
            HybridSigner(short, pq, verify_after_sign=False).sign(b"m")

    def test_public_key_failures_are_signer_errors(self):
        from aiss.signer import HybridSigner, Signer, SignerError
        priv, pub, priv_pq, pub_pq = _keys()

        class BrokenKey(Signer):
            algorithm = "Ed25519"

            def public_key(self):
                return b"short"

            def sign(self, message):
                return bytes(64)

        with self.assertRaises(SignerError):
            HybridSigner(BrokenKey(), RemoteLikeSigner.make("ML-DSA-65", priv_pq, pub_pq)).sign(b"m")

    def test_close_closes_both(self):
        priv, pub, priv_pq, pub_pq = _keys()
        signer = _hybrid(priv, pub, priv_pq, pub_pq)
        signer.close()
        from aiss.signer import SignerError
        with self.assertRaises(SignerError):
            signer.sign(b"m")


class TestStampIntegration(unittest.TestCase):

    def test_remote_like_signer_end_to_end(self):
        import aiss
        from aiss.chain import compute_event_hash
        from aiss.identity import derive_agent_id_aiss21, export_identity_aiss21
        from aiss.signer import HybridSigner
        from aiss.stamp_aiss2 import (
            stamp_event_aiss2_hybrid, stamp_genesis_event_aiss2_hybrid, verify_aiss2_hybrid)
        priv, pub, priv_pq, pub_pq = _keys()
        agent_id = derive_agent_id_aiss21(pub, pub_pq)
        signer = HybridSigner(RemoteLikeSigner.make("Ed25519", priv, pub),
                              RemoteLikeSigner.make("ML-DSA-65", priv_pq, pub_pq))
        with _pro():
            genesis = stamp_genesis_event_aiss2_hybrid(
                None, None, pub, agent_id, {"action": "genesis"}, public_key_pq=pub_pq,
                tsa_stamp_after=False, signer=signer)
            event = stamp_event_aiss2_hybrid(
                None, None, agent_id, {"action": "step"},
                previous_hash=compute_event_hash(genesis), tsa_stamp_after=False, signer=signer)
        self.assertTrue(verify_aiss2_hybrid(genesis, pub, pub_pq))
        self.assertTrue(verify_aiss2_hybrid(event, pub, pub_pq))
        identity = export_identity_aiss21(agent_id, pub, pub_pq)
        self.assertTrue(aiss.verify_chain([genesis, event], identity))

    def test_no_event_is_emitted_when_the_signer_misbehaves(self):
        from aiss.identity import derive_agent_id_aiss21
        from aiss.signer import HybridSigner, SignerError
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        priv, pub, priv_pq, pub_pq = _keys()
        agent_id = derive_agent_id_aiss21(pub, pub_pq)
        for behaviour in ("raise", "short", "wrong", "none"):
            for broken in ("classical", "post_quantum"):
                ed = RemoteLikeSigner.make("Ed25519", priv, pub, behaviour if broken == "classical" else "ok")
                pq = RemoteLikeSigner.make("ML-DSA-65", priv_pq, pub_pq,
                                           behaviour if broken == "post_quantum" else "ok")
                with self.subTest(behaviour=behaviour, broken=broken):
                    with _pro(), patch("aiss.stamp_aiss2.log_event_signed_alias") as logged, \
                            patch("aiss.stamp_aiss2.track") as tracked:
                        with self.assertRaises(SignerError):
                            stamp_event_aiss2_hybrid(
                                None, None, agent_id, {"a": 1}, tsa_stamp_after=False,
                                signer=HybridSigner(ed, pq))
                    logged.assert_not_called()
                    tracked.assert_not_called()

    def test_closed_signer_emits_nothing(self):
        from aiss.signer import SignerError
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        priv, pub, priv_pq, pub_pq = _keys()
        signer = _hybrid(priv, pub, priv_pq, pub_pq)
        signer.close()
        with _pro(), self.assertRaises(SignerError):
            stamp_event_aiss2_hybrid(None, None, "x" * 32, {"a": 1}, tsa_stamp_after=False,
                                     signer=signer)

    def test_keys_and_signer_are_mutually_exclusive(self):
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        priv, pub, priv_pq, pub_pq = _keys()
        signer = _hybrid(priv, pub, priv_pq, pub_pq)
        with _pro():
            with self.assertRaises(ValueError):
                stamp_event_aiss2_hybrid(priv, priv_pq, "x" * 32, {"a": 1},
                                         tsa_stamp_after=False, signer=signer)
            with self.assertRaises(ValueError):
                stamp_event_aiss2_hybrid(None, None, "x" * 32, {"a": 1}, tsa_stamp_after=False)

    def test_genesis_rejects_a_signer_with_other_public_keys(self):
        from aiss.identity import derive_agent_id_aiss21
        from aiss.stamp_aiss2 import stamp_genesis_event_aiss2_hybrid
        priv, pub, priv_pq, pub_pq = _keys()
        _, other_pub, _, other_pub_pq = _keys()
        signer = _hybrid(priv, pub, priv_pq, pub_pq)
        agent_id = derive_agent_id_aiss21(other_pub, other_pub_pq)
        with _pro(), self.assertRaises(ValueError):
            stamp_genesis_event_aiss2_hybrid(None, None, other_pub, agent_id, {"a": 1},
                                             public_key_pq=other_pub_pq, tsa_stamp_after=False,
                                             signer=signer)

    @pytest.mark.skipif(not _dilithium_py_available(), reason="dilithium-py absent")
    def test_byte_for_byte_equivalence_with_the_previous_path(self):
        from aiss.identity import derive_agent_id_aiss21
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid, stamp_genesis_event_aiss2_hybrid
        priv, pub, priv_pq, pub_pq = _keys()
        agent_id = derive_agent_id_aiss21(pub, pub_pq)
        kwargs = dict(nonce="00000000-0000-4000-8000-000000000001", timestamp=1_800_000_000,
                      tsa_stamp_after=False)
        with _pro(), _deterministic_mldsa():
            old = stamp_event_aiss2_hybrid(priv, priv_pq, agent_id, {"é": [1, 2]},
                                           previous_hash="ab" * 64, **kwargs)
            new = stamp_event_aiss2_hybrid(None, None, agent_id, {"é": [1, 2]},
                                           previous_hash="ab" * 64,
                                           signer=_hybrid(priv, pub, priv_pq, pub_pq), **kwargs)
            self.assertEqual(old, new)

            g_old = stamp_genesis_event_aiss2_hybrid(
                priv, priv_pq, pub, agent_id, {"g": 1}, public_key_pq=pub_pq,
                tsa_stamp_after=False, rotation_previous_hash="cd" * 64)
            g_new = stamp_genesis_event_aiss2_hybrid(
                None, None, pub, agent_id, {"g": 1}, public_key_pq=pub_pq,
                tsa_stamp_after=False, rotation_previous_hash="cd" * 64,
                signer=_hybrid(priv, pub, priv_pq, pub_pq))
            for event in (g_old, g_new):
                event.pop("nonce"), event.pop("timestamp")
            self.assertEqual(g_old["signatures"]["classical"]["algorithm"], "Ed25519")
            self.assertEqual(g_old["previous_hash"], g_new["previous_hash"])
            self.assertEqual(g_old["payload"], g_new["payload"])

    def test_previous_path_is_unchanged_without_signer(self):
        from aiss.identity import derive_agent_id_aiss21
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid, verify_aiss2_hybrid
        priv, pub, priv_pq, pub_pq = _keys()
        agent_id = derive_agent_id_aiss21(pub, pub_pq)
        with _pro():
            event = stamp_event_aiss2_hybrid(priv, priv_pq, agent_id, {"a": 1}, tsa_stamp_after=False)
        self.assertTrue(verify_aiss2_hybrid(event, pub, pub_pq))


class TestFileSigners(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = patch("aiss.key_store._SCRYPT_N", 2 ** 10)
        p.start()
        self.addCleanup(p.stop)

    def _identity(self, kind="native"):
        from aiss.identity import create_agent_identity, upgrade_agent_identity
        if kind == "native":
            create_agent_identity(kind, passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)
        else:
            create_agent_identity(kind, passphrase=PASSPHRASE, base_dir=self.tmp)
            upgrade_agent_identity(kind, PASSPHRASE, PASSPHRASE, base_dir=self.tmp)
        return Path(self.tmp) / "agents" / kind

    def test_signs_events_for_native_and_upgraded_identities(self):
        import json
        import aiss
        from aiss.signer_file import load_hybrid_signer
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        for kind in ("native", "upgraded"):
            with self.subTest(identity=kind):
                agent_dir = self._identity(kind)
                identity = json.loads((agent_dir / "identity.json").read_text())
                with load_hybrid_signer(agent_dir, PASSPHRASE) as signer:
                    with _pro():
                        event = stamp_event_aiss2_hybrid(
                            None, None, identity["agent_id"], {"a": 1}, tsa_stamp_after=False,
                            signer=signer)
                self.assertTrue(aiss.verify_chain([event], identity))

    def test_wrong_passphrase_fails_closed(self):
        from aiss.key_store import InvalidPassphraseError
        from aiss.signer_file import load_hybrid_signer
        agent_dir = self._identity()
        with self.assertRaises(InvalidPassphraseError):
            load_hybrid_signer(agent_dir, "mauvaise passphrase")

    def test_separate_pq_passphrase(self):
        from aiss.identity import create_agent_identity, upgrade_agent_identity
        from aiss.key_store import PQKeyPassphraseError, InvalidPassphraseError
        from aiss.signer_file import load_hybrid_signer
        create_agent_identity("sep", passphrase=PASSPHRASE, base_dir=self.tmp)
        upgrade_agent_identity("sep", "passphrase PQ distincte", PASSPHRASE, base_dir=self.tmp)
        agent_dir = Path(self.tmp) / "agents" / "sep"
        with load_hybrid_signer(agent_dir, PASSPHRASE, "passphrase PQ distincte") as signer:
            self.assertEqual(len(signer.sign(b"m").post_quantum), 3309)
        with self.assertRaises(InvalidPassphraseError):
            load_hybrid_signer(agent_dir, PASSPHRASE)

    def test_identity_mismatch_is_rejected(self):
        import json
        from aiss.signer import SignerError
        from aiss.signer_file import load_hybrid_signer
        agent_dir = self._identity()
        other = self._identity("upgraded")
        doc = json.loads((agent_dir / "identity.json").read_text())
        doc["public_key_classical"] = json.loads((other / "identity.json").read_text())["public_key"]
        doc["public_key_classical"] = "base64:" + doc["public_key_classical"]
        (agent_dir / "identity.json").write_text(json.dumps(doc))
        with self.assertRaises(SignerError):
            load_hybrid_signer(agent_dir, PASSPHRASE)

    def test_key_files_are_not_modified(self):
        from aiss.signer_file import load_hybrid_signer
        agent_dir = self._identity()
        before = {p.name: p.read_bytes() for p in agent_dir.iterdir()}
        with load_hybrid_signer(agent_dir, PASSPHRASE) as signer:
            signer.sign(b"m")
        self.assertEqual(before, {p.name: p.read_bytes() for p in agent_dir.iterdir()})

    def test_close_erases_both_keys(self):
        from aiss.signer_file import load_hybrid_signer
        agent_dir = self._identity()
        signer = load_hybrid_signer(agent_dir, PASSPHRASE)
        buffers = [signer.classical._key, signer.post_quantum._key]
        signer.close()
        for buffer in buffers:
            self.assertEqual(bytes(buffer), b"\x00" * len(buffer))


class TestConformance(unittest.TestCase):

    def test_shipped_signers_conform(self):
        from aiss.signer import InMemoryEd25519Signer, InMemoryMlDsa65Signer
        from aiss.signer_conformance import assert_hybrid_signer_conforms, assert_signer_conforms
        priv, pub, priv_pq, pub_pq = _keys()
        assert_signer_conforms(lambda: InMemoryEd25519Signer(priv, pub))
        assert_signer_conforms(lambda: InMemoryMlDsa65Signer(priv_pq, pub_pq))
        assert_hybrid_signer_conforms(lambda: _hybrid(priv, pub, priv_pq, pub_pq))

    def test_remote_like_signer_conforms(self):
        from aiss.signer_conformance import assert_signer_conforms
        priv, pub, priv_pq, pub_pq = _keys()
        assert_signer_conforms(lambda: RemoteLikeSigner.make("Ed25519", priv, pub))
        assert_signer_conforms(lambda: RemoteLikeSigner.make("ML-DSA-65", priv_pq, pub_pq))

    def test_violations_are_reported(self):
        from aiss.signer import Signer
        from aiss.signer_conformance import check_signer
        priv, pub, priv_pq, pub_pq = _keys()
        from aiss.crypto import ed25519

        class Base(Signer):
            algorithm = "Ed25519"

            def public_key(self):
                return pub

            def sign(self, message):
                return ed25519.sign(priv, message)

        class WrongSize(Base):
            def sign(self, message):
                return ed25519.sign(priv, message)[:-1]

        class WrongKey(Base):
            def public_key(self):
                return pub[:-1]

        class Unstable(Base):
            counter = 0

            def public_key(self):
                Unstable.counter += 1
                return bytes([Unstable.counter % 256]) + pub[1:]

        class ConstantSignature(Base):
            def sign(self, message):
                return ed25519.sign(priv, b"always the same")

        class OpensAfterClose(Base):
            """ne s'arrête pas à close() : échec ouvert"""

        class ExposesKey(Base):
            private_key = b"leak"

        class DoesNotVerify(Base):
            def sign(self, message):
                return bytes(64)

        expectations = {
            WrongSize: "64 bytes", WrongKey: "32 bytes", Unstable: "not stable",
            ConstantSignature: "does not verify", OpensAfterClose: "after close",
            ExposesKey: "private key is exposed", DoesNotVerify: "does not verify",
        }
        for cls, expected in expectations.items():
            with self.subTest(case=cls.__name__):
                problems = check_signer(cls)
                self.assertTrue(any(expected in p for p in problems), problems)

    def test_wrong_algorithm_is_reported(self):
        from aiss.signer import Signer
        from aiss.signer_conformance import check_signer

        class Wrong(Signer):
            algorithm = "RSA"

            def public_key(self):
                return b""

            def sign(self, message):
                return b""

        self.assertTrue(check_signer(Wrong))


class TestLicenceBoundary(unittest.TestCase):
    """aiss.signer reste MIT et ne dépend pas de key_store.py (Elastic-2.0)."""

    @staticmethod
    def _imports(path):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names.add(node.module or "")
        return names

    def test_headers_and_imports(self):
        mit = ("signer.py", "signer_conformance.py")
        for name in mit:
            path = REPO_ROOT / "aiss" / name
            self.assertEqual(path.read_text(encoding="utf-8").splitlines()[0],
                             "# SPDX-License-Identifier: MIT")
            forbidden = {i for i in self._imports(path)
                         if i.startswith(("aiss.key_store", "aiss.signer_file", "aiss.identity_session"))}
            self.assertEqual(forbidden, set(), name)
        elastic = REPO_ROOT / "aiss" / "signer_file.py"
        self.assertEqual(elastic.read_text(encoding="utf-8").splitlines()[0],
                         "# SPDX-License-Identifier: Elastic-2.0")
        self.assertIn("aiss.key_store", self._imports(elastic))


if __name__ == "__main__":
    unittest.main()
