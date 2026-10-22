# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — vérification réelle des jetons RFC 3161 (chantier C.2). Aucun accès réseau.

Fixture : tests/vectors_tsa/ contient des jetons RÉELS obtenus une fois de freetsa.org pour deux
événements déterministes (AISS-2.1 en SHA-512, AISS-1 en SHA-256) et la racine publique de cette
TSA (données publiques). Les requêtes sont rejouées avec urlopen simulé.
"""
import nacl.signing  # noqa: F401

import base64
import copy
import datetime
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

HERE = Path(__file__).resolve().parent
FIXTURE_DIR = HERE / "vectors_tsa"
ROOT_PEM = FIXTURE_DIR / "freetsa_cacert.pem"
REPO_ROOT = HERE.parent

try:
    import rfc3161_client  # noqa: F401
    HAS_LIB = True
except ImportError:
    HAS_LIB = False

needs_lib = pytest.mark.skipif(not HAS_LIB, reason="rfc3161-client (extra timestamp) not installed")


def load_fixture():
    with open(FIXTURE_DIR / "freetsa_events.json", encoding="utf-8") as fh:
        return json.load(fh)


def fixture_event(label):
    return copy.deepcopy(load_fixture()["events"][label])


def token_bytes(event):
    return base64.b64decode(event["trusted_timestamp"]["token"][7:])


def with_token(event, raw):
    event["trusted_timestamp"]["token"] = "base64:" + base64.b64encode(raw).decode()
    return event


def fake_response(body):
    response = MagicMock()
    response.status = 200
    response.read.return_value = body
    response.__enter__.return_value = response
    return response


# ─────────────────────────────────────────────────────────────────────────────
class TestFixtureProvenance(unittest.TestCase):

    def test_fixture_is_real_public_data_with_a_pinned_root(self):
        import hashlib
        data = load_fixture()
        self.assertEqual(data["tsa_url"], "https://freetsa.org/tsr")
        self.assertEqual(data["root"]["file_sha256"], hashlib.sha256(ROOT_PEM.read_bytes()).hexdigest())
        self.assertEqual(data["root"]["file_sha256"], data["root"]["published_file_sha256"])
        self.assertRegex(data["captured_at"], r"^2026-10-22T")
        for event in data["events"].values():
            self.assertTrue(event["trusted_timestamp"]["token"].startswith("base64:"))

    def test_no_trust_root_is_shipped_in_the_package(self):
        shipped = [p for p in (REPO_ROOT / "aiss").rglob("*") if p.suffix.lower() in (".pem", ".crt", ".cer")]
        self.assertEqual(shipped, [])


@needs_lib
class TestVerification(unittest.TestCase):

    def verify(self, event, roots=ROOT_PEM):
        from aiss.rfc3161 import verify_tsa_token
        return verify_tsa_token(event, str(roots) if roots is not None else None)

    def test_real_tokens_verify(self):
        for label, algorithm in (("aiss21", "sha512"), ("aiss1", "sha256")):
            with self.subTest(event=label):
                event = fixture_event(label)
                result = self.verify(event)
                self.assertEqual(result["status"], "verified", result)
                self.assertTrue(result["verified"])
                self.assertEqual(result["chain"], "validated")
                self.assertEqual(result["revocation"], "not_checked")
                self.assertIn("freetsa.org", result["tsa"])
                gen_time = datetime.datetime.fromtimestamp(result["gen_time"], datetime.timezone.utc)
                self.assertEqual((gen_time.year, gen_time.month, gen_time.day), (2026, 10, 22))
                self.assertEqual(event["trusted_timestamp"]["hash_algorithm"], algorithm)

    def test_gen_time_comes_from_the_token_not_from_local_fields(self):
        event = fixture_event("aiss1")
        event["trusted_timestamp"]["timestamp"] = 0
        result = self.verify(event)
        self.assertEqual(result["status"], "verified")
        self.assertGreater(result["gen_time"], 1_700_000_000)

    def test_expected_imprint_is_recomputed_from_the_event_not_read_from_the_token_fields(self):
        event = fixture_event("aiss21")
        event["trusted_timestamp"]["imprint"] = "00" * 64   # champ ignoré pour la décision
        self.assertEqual(self.verify(event)["status"], "verified")
        event["payload"]["action"] = "modified after timestamping"
        result = self.verify(event)
        self.assertEqual(result["status"], "invalid")
        self.assertIn("imprint", result["reason"])

    def test_aiss1_legacy_data_hash_is_not_trusted(self):
        event = fixture_event("aiss1")
        event["trusted_timestamp"]["data_hash"] = "00" * 32
        self.assertEqual(self.verify(event)["status"], "verified")

    @staticmethod
    def protected_positions(event):
        """Octets couverts par la signature CMS ou par la chaîne : TSTInfo (empreinte, nonce,
        genTime), valeur de signature, certificat de la TSA (corps signé par la racine)."""
        from cryptography import x509
        import rfc3161_client
        raw = token_bytes(event)
        decoded = rfc3161_client.decode_timestamp_response(raw)
        digest = bytes.fromhex(event["trusted_timestamp"].get("imprint")
                               or event["trusted_timestamp"]["data_hash"])
        leaf = next(der for der in decoded.signed_data.certificates
                    if x509.load_der_x509_certificate(der).subject.rfc4514_string().endswith("OU=TSA,O=Free TSA"))
        gen_time = decoded.tst_info.gen_time.strftime("%Y%m%d%H").encode()
        return {
            "imprint": raw.find(digest) + 5,
            "genTime": raw.find(gen_time) + 3,
            "signature value": len(raw) - 30,
            "last signature byte": len(raw) - 1,
            "TSA certificate body": raw.find(leaf) + 900,
            "TSA certificate signature": raw.find(leaf) + len(leaf) - 20,
        }

    def test_each_modified_protected_region_is_rejected(self):
        for label in ("aiss21", "aiss1"):
            raw = token_bytes(fixture_event(label))
            for region, position in self.protected_positions(fixture_event(label)).items():
                self.assertGreater(position, 0, region)
                with self.subTest(event=label, region=region):
                    mutated = bytearray(raw)
                    mutated[position] ^= 0x01
                    result = self.verify(with_token(fixture_event(label), bytes(mutated)))
                    self.assertFalse(result["verified"], result)
                    self.assertNotEqual(result["status"], "verified")

    def test_truncated_and_extended_tokens_are_rejected(self):
        for label in ("aiss21", "aiss1"):
            raw = token_bytes(fixture_event(label))
            for variant in (raw[:-1], raw[:len(raw) // 2], raw + b"\x00"):
                with self.subTest(event=label, length=len(variant)):
                    result = self.verify(with_token(fixture_event(label), variant))
                    self.assertFalse(result["verified"], result)

    def test_documented_unsigned_regions_do_not_change_the_verdict(self):
        """La copie de la racine embarquée dans le jeton n'est pas utilisée (la racine vient du
        magasin configuré) : la modifier ne change pas le verdict. Le jeton n'est donc pas
        inviolable octet par octet ; son lien avec l'événement tient à l'empreinte et à la
        signature, pas à ses octets."""
        from cryptography import x509
        import rfc3161_client
        event = fixture_event("aiss21")
        raw = token_bytes(event)
        decoded = rfc3161_client.decode_timestamp_response(raw)
        root_copy = next(der for der in decoded.signed_data.certificates
                         if x509.load_der_x509_certificate(der).subject.rfc4514_string().endswith("OU=Root CA,O=Free TSA"))
        mutated = bytearray(raw)
        mutated[raw.find(root_copy) + 1000] ^= 0x01
        result = self.verify(with_token(event, bytes(mutated)))
        self.assertEqual(result["status"], "verified")

    def test_token_of_another_event_is_rejected(self):
        event = fixture_event("aiss21")
        other = fixture_event("aiss1")
        event["trusted_timestamp"]["token"] = other["trusted_timestamp"]["token"]
        result = self.verify(event)
        self.assertEqual(result["status"], "invalid")
        self.assertIn("sha512", result["reason"])

    def test_another_root_is_rejected(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated Root")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(key.public_key()).serial_number(1)
                       .not_valid_before(now - datetime.timedelta(days=1))
                       .not_valid_after(now + datetime.timedelta(days=30))
                       .sign(key, hashes.SHA256()))
        pem = certificate.public_bytes(serialization.Encoding.PEM)
        from aiss.rfc3161 import verify_tsa_token
        for label in ("aiss21", "aiss1"):
            result = verify_tsa_token(fixture_event(label), [pem])
            self.assertEqual(result["status"], "invalid", result)
            self.assertFalse(result["verified"])

    def test_different_nonce_is_rejected(self):
        event = fixture_event("aiss21")
        event["trusted_timestamp"]["nonce"] = "1"
        result = self.verify(event)
        self.assertEqual(result["status"], "invalid")
        self.assertIn("nonce", result["reason"])

    def test_missing_nonce_is_rejected_for_aiss21_but_tolerated_for_legacy(self):
        event = fixture_event("aiss21")
        del event["trusted_timestamp"]["nonce"]
        self.assertEqual(self.verify(event)["status"], "invalid")
        legacy = fixture_event("aiss1")
        del legacy["trusted_timestamp"]["nonce"]
        self.assertEqual(self.verify(legacy)["status"], "verified")

    def test_empty_absent_and_self_declared_tokens(self):
        from aiss.rfc3161 import verify_tsa_token
        base = fixture_event("aiss21")
        for label, trusted in {
            "empty token": {"token": "", "status": "granted"},
            "base64 prefix only": {"token": "base64:", "status": "granted"},
            "null token": {"token": None, "rfc3161_token": None, "status": "verified"},
            "self-declared verified": {"status": "verified"},
            "self-declared granted": {"status": "granted", "authority": "freetsa.org"},
            "garbage base64": {"token": "base64:@@@@", "nonce": "1"},
        }.items():
            with self.subTest(case=label):
                event = dict(base, trusted_timestamp=trusted)
                result = verify_tsa_token(event, str(ROOT_PEM))
                self.assertEqual(result["status"], "invalid", result)
                self.assertFalse(result["verified"])
        pending = dict(base, trusted_timestamp={"status": "pending"})
        self.assertEqual(verify_tsa_token(pending, str(ROOT_PEM))["status"], "pending")
        no_field = {k: v for k, v in base.items() if k != "trusted_timestamp"}
        self.assertEqual(verify_tsa_token(no_field, str(ROOT_PEM))["status"], "invalid")

    def test_any_der_starting_with_0x30_is_no_longer_verified(self):
        event = fixture_event("aiss21")
        for raw in (b"\x30\x00", b"\x30\x03\x02\x01\x00", b"\x30" + b"\x00" * 200):
            with self.subTest(length=len(raw)):
                result = self.verify(with_token(copy.deepcopy(event), raw))
                self.assertNotEqual(result["status"], "verified")
                self.assertFalse(result["verified"])

    def test_refused_response_is_invalid(self):
        from aiss.rfc3161 import _der
        refused = _der(0x30, _der(0x30, _der(0x02, b"\x02")))
        result = self.verify(with_token(fixture_event("aiss21"), refused))
        self.assertEqual(result["status"], "invalid")

    def test_no_trust_root_gives_structure_only_never_verified(self):
        from aiss.rfc3161 import verify_tsa_token
        for roots in ([], tempfile.mkdtemp()):
            with self.subTest(roots=repr(roots)):
                result = verify_tsa_token(fixture_event("aiss21"), roots)
                self.assertEqual(result["status"], "structure_only")
                self.assertFalse(result["verified"])
                self.assertEqual(result["chain"], "not_validated")
                self.assertIsInstance(result["gen_time"], int)

    def test_structure_only_still_checks_imprint_and_nonce(self):
        from aiss.rfc3161 import verify_tsa_token
        event = fixture_event("aiss21")
        event["payload"]["action"] = "changed"
        self.assertEqual(verify_tsa_token(event, [])["status"], "invalid")


class TestWithoutTheLibrary(unittest.TestCase):
    """rfc3161-client absent (simulé) : au mieux structure_only, jamais verified."""

    def verify(self, event):
        from aiss.rfc3161 import verify_tsa_token
        with patch.dict(sys.modules, {"rfc3161_client": None}):
            return verify_tsa_token(event, str(ROOT_PEM))

    def test_best_case_is_structure_only(self):
        for label in ("aiss21", "aiss1"):
            result = self.verify(fixture_event(label))
            self.assertEqual(result["status"], "structure_only", result)
            self.assertFalse(result["verified"])
            self.assertEqual(result["chain"], "not_validated")
            self.assertIn("rfc3161-client", result["reason"])

    def test_obvious_forgeries_are_still_rejected(self):
        event = fixture_event("aiss21")
        event["payload"]["action"] = "changed"
        self.assertEqual(self.verify(event)["status"], "invalid")
        self.assertEqual(self.verify(with_token(fixture_event("aiss21"), b"\x30\x03\x02\x01\x00"))["status"],
                         "invalid")
        self.assertEqual(self.verify(dict(fixture_event("aiss21"), trusted_timestamp={"status": "verified"}))["status"],
                         "invalid")

    def test_make_tsa_verifier_anchors_nothing_without_the_library(self):
        from aiss.rfc3161 import make_tsa_verifier
        with patch.dict(sys.modules, {"rfc3161_client": None}):
            verifier = make_tsa_verifier(str(ROOT_PEM))
            self.assertIsNone(verifier(fixture_event("aiss21")))


class TestTrustStore(unittest.TestCase):

    def test_explicit_forms(self):
        from cryptography import x509
        from aiss.rfc3161 import load_trust_roots
        pem = ROOT_PEM.read_bytes()
        certificate = x509.load_pem_x509_certificate(pem)
        directory = Path(tempfile.mkdtemp())
        (directory / "root.pem").write_bytes(pem)
        (directory / "ignored.txt").write_text("not a certificate")
        for label, argument in {
            "path": str(ROOT_PEM), "pathlib": ROOT_PEM, "directory": str(directory),
            "pem text": pem.decode(), "pem bytes": pem, "certificate": certificate,
            "list of mixed": [pem, certificate],
        }.items():
            with self.subTest(form=label):
                roots = load_trust_roots(argument)
                self.assertGreaterEqual(len(roots), 1)
                self.assertEqual(roots[0], certificate)

    def test_explicit_empty_list_means_no_roots_even_if_an_environment_is_set(self):
        from aiss.rfc3161 import load_trust_roots
        with patch.dict(os.environ, {"PIQRYPT_TSA_TRUST_ROOTS": str(ROOT_PEM)}):
            self.assertEqual(load_trust_roots([]), [])
            self.assertEqual(len(load_trust_roots()), 1)

    def test_default_directory_under_piqrypt_home(self):
        from aiss.rfc3161 import load_trust_roots
        home = Path(tempfile.mkdtemp())
        with patch.dict(os.environ, {"PIQRYPT_HOME": str(home)}):
            os.environ.pop("PIQRYPT_TSA_TRUST_ROOTS", None)
            self.assertEqual(load_trust_roots(), [])
            (home / "tsa_roots").mkdir()
            (home / "tsa_roots" / "freetsa.pem").write_bytes(ROOT_PEM.read_bytes())
            self.assertEqual(len(load_trust_roots()), 1)

    def test_corrupt_root_file_is_ignored_with_a_warning(self):
        from aiss.rfc3161 import load_trust_roots
        directory = Path(tempfile.mkdtemp())
        (directory / "broken.pem").write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
        self.assertEqual(load_trust_roots(str(directory)), [])

    @needs_lib
    def test_verifier_for_fork_resolution(self):
        from aiss.rfc3161 import make_tsa_verifier
        verifier = make_tsa_verifier(str(ROOT_PEM))
        self.assertIsInstance(verifier(fixture_event("aiss21")), int)
        self.assertIsInstance(verifier(fixture_event("aiss1")), int)
        tampered = fixture_event("aiss21")
        tampered["payload"]["action"] = "x"
        self.assertIsNone(verifier(tampered))
        self.assertIsNone(verifier(dict(fixture_event("aiss21"), trusted_timestamp={"status": "verified"})))
        self.assertIsNone(make_tsa_verifier([])(fixture_event("aiss21")))  # structure_only

    @needs_lib
    def test_forged_branch_loses_against_a_really_anchored_one(self):
        import aiss
        from aiss.chain import compute_event_hash
        from aiss.fork import select_canonical_chain
        from aiss.rfc3161 import make_tsa_verifier

        real = fixture_event("aiss1")
        priv, pub = aiss.generate_keypair()
        agent = aiss.derive_agent_id(pub)
        forged_chain = [aiss.stamp_event(priv, agent, {"i": 0}, nonce="f0")]
        forged_chain.append(aiss.stamp_event(
            priv, agent, {"i": 1}, previous_hash=compute_event_hash(forged_chain[0]), nonce="f1"))
        forged_chain[1]["trusted_timestamp"] = {"token": "base64:AAAA", "timestamp": 0, "status": "verified"}
        long_chain = [real] + [aiss.stamp_event(priv, agent, {"j": j}, nonce=f"l{j}") for j in range(4)]
        verifier = make_tsa_verifier(str(ROOT_PEM))
        canonical, _ = select_canonical_chain([forged_chain, long_chain], tsa_verifier=verifier)
        self.assertEqual(canonical, long_chain)  # le jeton réel ancre la branche longue
        canonical, _ = select_canonical_chain([forged_chain, long_chain[1:]], tsa_verifier=verifier)
        self.assertEqual(len(canonical), 4)       # sans ancre réelle : longueur, pas la branche forgée


class TestRequestBuilding(unittest.TestCase):

    @staticmethod
    def decode(request):
        """Décodeur DER minimal d'une TimeStampReq : (version, algorithme, empreinte, nonce, certReq)."""
        from aiss.rfc3161 import _read_tlv
        tag, _, i = _read_tlv(request, 0)
        assert tag == 0x30
        tag, n, j = _read_tlv(request, i)
        version = int.from_bytes(request[j:j + n], "big")
        i = j + n
        tag, n, j = _read_tlv(request, i)      # messageImprint
        end = j + n
        tag, n2, k = _read_tlv(request, j)     # AlgorithmIdentifier
        algorithm = request[k:k + n2]
        tag, n3, m = _read_tlv(request, k + n2)
        digest = request[m:m + n3]
        i = end
        nonce = cert_req = None
        while i < len(request):
            tag, n, j = _read_tlv(request, i)
            if tag == 0x02:
                nonce = int.from_bytes(request[j:j + n], "big")
            elif tag == 0x01:
                cert_req = request[j] != 0
            i = j + n
        return version, algorithm, digest, nonce, cert_req

    def test_request_layout(self):
        from aiss.rfc3161 import _build_tsr_request
        for algorithm, size, oid_tail in (("sha256", 32, b"\x01"), ("sha384", 48, b"\x02"),
                                          ("sha512", 64, b"\x03")):
            digest = bytes(range(size))
            nonce = (1 << 62) | 0x1234
            version, alg, got_digest, got_nonce, cert_req = self.decode(
                _build_tsr_request(digest, algorithm, nonce=nonce))
            self.assertEqual(version, 1)
            self.assertIn(bytes.fromhex("608648016503040200")[:-1] + oid_tail, alg)
            self.assertEqual(got_digest, digest)
            self.assertEqual(got_nonce, nonce)
            self.assertTrue(cert_req)

    def test_invalid_arguments(self):
        from aiss.rfc3161 import _build_tsr_request
        with self.assertRaises(ValueError):
            _build_tsr_request(bytes(32), "md5")
        with self.assertRaises(ValueError):
            _build_tsr_request(bytes(31), "sha256")
        with self.assertRaises(ValueError):
            _build_tsr_request(bytes(64), "sha512", nonce=-1)

    def test_request_without_nonce_has_none(self):
        from aiss.rfc3161 import _build_tsr_request
        self.assertIsNone(self.decode(_build_tsr_request(bytes(32)))[3])


def replay(label, nonce_override=None, digest_override=None):
    """Rejoue la réponse RÉELLE de freetsa.org (liée à son nonce et à son empreinte)."""
    from aiss.rfc3161 import _imprint_for_event
    event = fixture_event(label)
    trusted = event.pop("trusted_timestamp")
    algorithm, digest, schema = _imprint_for_event(event)
    nonce = int(trusted["nonce"], 16)
    response_bytes = base64.b64decode(trusted["token"][7:])
    return event, trusted, algorithm, digest, schema, nonce, response_bytes


class TestRequestPath(unittest.TestCase):

    def run_request(self, label, *, nonce=None, digest=None, response=None, schema=None):
        from aiss import rfc3161
        event, trusted, algorithm, real_digest, real_schema, real_nonce, real_response = replay(label)
        captured = {}

        def fake_urlopen(request, timeout=None):
            captured["request"] = request
            return fake_response(response if response is not None else real_response)

        with patch("aiss.rfc3161.secrets.randbits", return_value=real_nonce if nonce is None else nonce), \
                patch("aiss.rfc3161.urllib.request.urlopen", side_effect=fake_urlopen):
            result = rfc3161.request_timestamp(
                b"", tsa_url=trusted["url"], hash_algorithm=algorithm,
                digest=real_digest if digest is None else digest, schema=schema or real_schema)
        return result, trusted, captured["request"], (algorithm, real_digest, real_nonce)

    def test_real_response_is_accepted_and_reshaped(self):
        for label in ("aiss21", "aiss1"):
            with self.subTest(event=label):
                result, trusted, request, _ = self.run_request(label)
                self.assertEqual(result["token"], trusted["token"])
                self.assertEqual(result["nonce"], trusted["nonce"])
                self.assertEqual(result["status"], "granted")
                self.assertEqual(result["authority"], "freetsa.org")
                if label == "aiss21":
                    self.assertEqual(sorted(result), ["authority", "hash_algorithm", "imprint", "nonce",
                                                      "status", "token", "url"])
                else:
                    for key in ("timestamp", "data_hash", "token_size_bytes", "nonce"):
                        self.assertIn(key, result)
                self.assertEqual(request.get_header("Content-type"), "application/timestamp-query")
                self.assertEqual(request.get_method(), "POST")

    def test_request_body_carries_the_digest_and_the_nonce(self):
        _, _, request, (algorithm, digest, nonce) = self.run_request("aiss21")
        version, _, got_digest, got_nonce, cert_req = TestRequestBuilding.decode(request.data)
        self.assertEqual((version, got_digest, got_nonce, cert_req), (1, digest, nonce, True))

    def test_response_for_another_nonce_is_rejected(self):
        from aiss.rfc3161 import TSAError
        with self.assertRaises(TSAError) as ctx:
            self.run_request("aiss21", nonce=12345)
        self.assertIn("nonce", str(ctx.exception))

    def test_response_for_another_digest_is_rejected(self):
        from aiss.rfc3161 import TSAError
        with self.assertRaises(TSAError):
            self.run_request("aiss21", digest=bytes(64))

    def test_refused_and_garbage_responses_are_rejected(self):
        from aiss.rfc3161 import TSAError, TSAVerificationError, _der
        refused = _der(0x30, _der(0x30, _der(0x02, b"\x02")))
        with self.assertRaises(TSAError):
            self.run_request("aiss21", response=refused)
        with self.assertRaises(TSAError):
            self.run_request("aiss21", response=b"not DER")

    def test_byte_level_checks_without_the_library(self):
        from aiss.rfc3161 import TSAError
        with patch.dict(sys.modules, {"rfc3161_client": None}):
            result, trusted, _, _ = self.run_request("aiss21")
            self.assertEqual(result["token"], trusted["token"])
            with self.assertRaises(TSAError):
                self.run_request("aiss21", nonce=12345)

    def test_unreachable_tsa(self):
        import urllib.error
        from aiss import rfc3161
        with patch("aiss.rfc3161.urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            with self.assertRaises(rfc3161.TSAUnavailableError):
                rfc3161.request_timestamp(b"data")

    def test_only_http_urls(self):
        from aiss import rfc3161
        for url in ("file:///etc/passwd", "ftp://example.com/tsr", "javascript:1"):
            with self.assertRaises(rfc3161.TSAError):
                rfc3161.request_timestamp(b"data", tsa_url=url)


class TestStampEventWithTsa(unittest.TestCase):

    def test_aiss21_event_gets_a_sha512_token_that_verifies(self):
        from aiss import rfc3161
        event, trusted, algorithm, digest, schema, nonce, response = replay("aiss21")
        self.assertEqual((algorithm, schema), ("sha512", "aiss21"))
        with patch("aiss.rfc3161.secrets.randbits", return_value=nonce), \
                patch("aiss.rfc3161.urllib.request.urlopen", return_value=fake_response(response)):
            stamped = rfc3161.stamp_event_with_tsa(event)
        self.assertEqual(stamped["trusted_timestamp"], trusted)
        self.assertNotIn("trusted_timestamp", event)  # l'original n'est pas modifié
        if HAS_LIB:
            self.assertEqual(rfc3161.verify_tsa_token(stamped, str(ROOT_PEM))["status"], "verified")

    def test_aiss1_event_keeps_the_sha256_behaviour(self):
        from aiss import rfc3161
        event, trusted, algorithm, digest, schema, nonce, response = replay("aiss1")
        self.assertEqual((algorithm, schema), ("sha256", "legacy"))
        with patch("aiss.rfc3161.secrets.randbits", return_value=nonce), \
                patch("aiss.rfc3161.urllib.request.urlopen", return_value=fake_response(response)):
            stamped = rfc3161.stamp_event_with_tsa(event)
        self.assertEqual(stamped["trusted_timestamp"]["token"], trusted["token"])
        self.assertEqual(stamped["trusted_timestamp"]["hash_algorithm"], "sha256")
        self.assertEqual(stamped["trusted_timestamp"]["data_hash"], digest.hex())
        if HAS_LIB:
            self.assertEqual(rfc3161.verify_tsa_token(stamped, str(ROOT_PEM))["status"], "verified")

    def test_unreachable_tsa_leaves_a_pending_placeholder_per_schema(self):
        from aiss import rfc3161
        for label, local_field in (("aiss21", False), ("aiss1", True)):
            event = replay(label)[0]
            with patch("aiss.rfc3161.request_timestamp", side_effect=rfc3161.TSAUnavailableError("down")):
                stamped = rfc3161.stamp_event_with_tsa(event)
            self.assertEqual(stamped["trusted_timestamp"]["status"], "pending")
            self.assertEqual("local_fallback_at" in stamped["trusted_timestamp"], local_field)
            self.assertEqual(rfc3161.verify_tsa_token(stamped, [])["status"], "pending")

    def test_request_is_made_with_the_algorithm_of_the_event_version(self):
        from aiss import rfc3161
        for label, algorithm in (("aiss21", "sha512"), ("aiss1", "sha256")):
            event, _, _, digest, schema, _, _ = replay(label)
            with patch("aiss.rfc3161.request_timestamp", return_value={"status": "granted"}) as request:
                rfc3161.stamp_event_with_tsa(event)
            kwargs = request.call_args.kwargs
            self.assertEqual(kwargs["hash_algorithm"], algorithm)
            self.assertEqual(kwargs["digest"], digest)
            self.assertEqual(kwargs["schema"], schema)

    def test_pending_placeholder_of_a_freshly_signed_aiss21_event(self):
        pytest.importorskip("dilithium_py")
        from aiss.crypto import dilithium, ed25519
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        import aiss.license as lic_module
        from aiss.license import License, TIERS
        priv, pub = ed25519.generate_keypair()
        priv_pq, pub_pq = dilithium.generate_keypair()
        lic = License.__new__(License)
        lic._tier, lic._loaded_at = "pro", 0.0
        lic._payload = {"tier": "pro", "license_id": "t", "agents_max": TIERS["pro"]["agents_max"],
                        "events_month": TIERS["pro"]["events_month"], "expires_at": None}
        with patch.object(lic_module, "_license", lic):
            event = stamp_event_aiss2_hybrid(priv, priv_pq, "x" * 32, {"a": 1}, tsa_stamp_after=False)
        self.assertEqual(event["trusted_timestamp"], {"status": "pending"})


class TestRetryPending(unittest.TestCase):

    def test_imprint_follows_the_event_version_and_excludes_the_pending_field(self):
        import hashlib
        from aiss import rfc3161
        from aiss.canonical import canonicalize
        from aiss.chain import compute_event_hash
        events = []
        for label in ("aiss21", "aiss1"):
            event = replay(label)[0]
            event["trusted_timestamp"] = {"status": "pending"}
            events.append(event)
        stored = []
        with patch("aiss.memory.load_events", return_value=events), \
                patch("aiss.memory.store_event", side_effect=stored.append), \
                patch("aiss.rfc3161.request_timestamp", return_value={"status": "granted", "token": "t"}) as request:
            outcome = rfc3161.retry_pending_timestamps("agent")
        self.assertEqual(outcome, {"retried": 2, "succeeded": 2, "failed": 0})
        first, second = request.call_args_list
        self.assertEqual(first.kwargs["hash_algorithm"], "sha512")
        self.assertEqual(first.kwargs["digest"], bytes.fromhex(compute_event_hash(events[0])))
        without_field = {k: v for k, v in events[1].items() if k != "trusted_timestamp"}
        self.assertEqual(second.kwargs["hash_algorithm"], "sha256")
        self.assertEqual(second.kwargs["digest"], hashlib.sha256(canonicalize(without_field)).digest())


if __name__ == "__main__":
    unittest.main()
