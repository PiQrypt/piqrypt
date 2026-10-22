# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — vecteurs AISS-2.1 publiés (test_vectors_aiss21/).

(i)  le générateur est déterministe : régénérer dans un dossier temporaire redonne les
     fichiers commités (comparaison des octets, fins de ligne normalisées : un dépôt
     récupéré avec core.autocrlf=true les convertit en CRLF) ;
(ii) la bibliothèque rend, pour chaque vecteur, le verdict attendu (champ "valid").
"""
import nacl.signing  # noqa: F401

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VECTORS_DIR = REPO_ROOT / "test_vectors_aiss21"
GENERATOR = REPO_ROOT / "scripts" / "gen_aiss21_vectors.py"

FILES = ["keys.json", "agent_id.json", "hash_and_message.json", "events.json",
         "chains.json", "identities.json", "rotation.json"]


def _pq_available():
    try:
        from aiss.crypto import dilithium
        return dilithium is not None and dilithium.is_available()
    except Exception:
        return False


def _generator_available():
    try:
        import base58  # noqa: F401
        import rfc8785  # noqa: F401
        import dilithium_py  # noqa: F401
        return True
    except ImportError:
        return False


def load(name):
    with open(VECTORS_DIR / name, encoding="utf-8") as fh:
        return json.load(fh)


def _normalised(path):
    return path.read_bytes().replace(b"\r\n", b"\n")


# ─── verdicts de la bibliothèque ─────────────────────────────────────────────

def lib_agent_id(v):
    from aiss.identity import derive_agent_id_aiss21
    try:
        got = derive_agent_id_aiss21(bytes.fromhex(v["ed25519_public_key"]),
                                     bytes.fromhex(v["ml_dsa_65_public_key"]))
    except ValueError:
        return False
    return got == v["expected_agent_id"]


def lib_hash_and_message(v):
    from aiss.canonical_aiss21 import canonicalize
    from aiss.chain import compute_event_hash
    from aiss.stamp_aiss2 import _build_signed_message
    event = v["event"]
    body = {k: x for k, x in event.items() if k not in ("signatures", "trusted_timestamp")}
    j = canonicalize(body)
    return (j.hex() == v["jcs_hex"]
            and _build_signed_message(j).hex() == v["signed_message_hex"]
            and compute_event_hash(event) == v["sha512"])


def lib_event(v):
    from aiss.exceptions import AISSError
    from aiss.stamp_aiss2 import verify_aiss2_hybrid
    keys = v["verification_keys"]
    try:
        return bool(verify_aiss2_hybrid(v["event"], bytes.fromhex(keys["ed25519"]),
                                        bytes.fromhex(keys["ml_dsa_65"])))
    except AISSError:
        return False


def lib_chain(v):
    from aiss.exceptions import AISSError
    from aiss.verify import verify_chain
    try:
        return bool(verify_chain(v["events"], v["identity"]))
    except AISSError:
        return False


def lib_identity(v):
    from aiss.identity import IdentityBindingError, identity_binding_assurance
    try:
        return identity_binding_assurance(v["identity"]) == v["expected_assurance"]
    except IdentityBindingError:
        return False


def lib_rotation(v):
    from aiss.identity import verify_rotation_attestation_hybrid, verify_rotation_chain
    if v["type"] == "attestation":
        return verify_rotation_attestation_hybrid(v["attestation"], v["previous_identity"])
    return verify_rotation_chain(v["old_events"], v["previous_identity"], v["new_genesis"])


ADAPTERS = {
    "agent_id.json": lib_agent_id,
    "hash_and_message.json": lib_hash_and_message,
    "events.json": lib_event,
    "chains.json": lib_chain,
    "identities.json": lib_identity,
    "rotation.json": lib_rotation,
}


class TestVectorFiles(unittest.TestCase):

    def test_every_file_has_description_spec_version_and_valid_flags(self):
        for name in FILES:
            with self.subTest(file=name):
                d = load(name)
                self.assertTrue(d["description"])
                self.assertEqual(d["spec_version"], "AISS-2.1")
                if name == "keys.json":
                    for ag in list(d["agents"].values()) + list(d["helpers"].values()):
                        self.assertEqual(ag["ed25519"]["note"], "TEST ONLY")
                        self.assertEqual(ag["ml_dsa_65"]["note"], "TEST ONLY")
                    continue
                ids = [v["id"] for v in d["vectors"]]
                self.assertEqual(len(ids), len(set(ids)), "identifiants de vecteurs non uniques")
                for v in d["vectors"]:
                    self.assertIsInstance(v["valid"], bool)
                    if not v["valid"]:
                        self.assertTrue(v["reason"], f"{name}:{v['id']} sans reason")

    def test_both_positive_and_negative_vectors_exist(self):
        for name in ADAPTERS:
            with self.subTest(file=name):
                verdicts = {v["valid"] for v in load(name)["vectors"]}
                if name == "hash_and_message.json":
                    self.assertEqual(verdicts, {True})
                else:
                    self.assertEqual(verdicts, {True, False})


@pytest.mark.skipif(not _generator_available(), reason="base58 / rfc8785 / dilithium-py absents")
class TestGeneratorIsDeterministic(unittest.TestCase):

    @staticmethod
    def _load_generator():
        spec = importlib.util.spec_from_file_location("gen_aiss21_vectors", GENERATOR)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_regeneration_matches_committed_files(self):
        out = Path(tempfile.mkdtemp())
        self._load_generator().write_all(str(out))
        for name in FILES:
            with self.subTest(file=name):
                self.assertEqual(_normalised(out / name), _normalised(VECTORS_DIR / name),
                                 f"{name} diffère : relancer scripts/gen_aiss21_vectors.py")
        self.assertEqual(sorted(p.name for p in out.iterdir()), sorted(FILES))

    def test_generator_imports_nothing_from_aiss(self):
        source = GENERATOR.read_text(encoding="utf-8")
        self.assertNotIn("import aiss", source)
        self.assertNotIn("from aiss", source)


@pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")
class TestLibraryAgreesWithVectors(unittest.TestCase):

    def test_library_verdict_matches_expected_for_every_vector(self):
        mismatches, total = [], 0
        for name, adapter in ADAPTERS.items():
            for v in load(name)["vectors"]:
                total += 1
                verdict = adapter(v)
                if verdict != v["valid"]:
                    mismatches.append(f"{name}:{v['id']} attendu={v['valid']} bibliothèque={verdict}")
        self.assertGreater(total, 50)
        self.assertEqual(mismatches, [], "\n".join(mismatches))


@pytest.mark.skipif(not _pq_available(), reason="ML-DSA-65 backend not installed")
class TestDocumentedLimits(unittest.TestCase):

    def test_chain_without_its_first_events_is_accepted(self):
        """Limite documentée dans le README : le premier événement n'a pas à être une genèse."""
        from aiss.verify import verify_chain
        chain = next(v for v in load("chains.json")["vectors"] if v["id"] == "native_chain")
        truncated = chain["events"][2:]
        self.assertTrue(verify_chain(truncated, chain["identity"]))
        spec = importlib.util.spec_from_file_location(
            "standalone_for_limits", VECTORS_DIR / "verify_standalone.py")
        standalone = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(standalone)
        self.assertTrue(standalone.verify_chain(truncated, chain["identity"]))

    def test_concurrent_rotations_reason_matches_the_rule_that_rejects_them(self):
        vector = next(v for v in load("chains.json")["vectors"] if v["id"] == "concurrent_rotations")
        self.assertIn("previous_hash", vector["reason"])
        self.assertNotIn("fork", vector["reason"])


if __name__ == "__main__":
    unittest.main()
