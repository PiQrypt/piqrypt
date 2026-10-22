# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests — chemin Pro de bout en bout SANS secret ni licence locale.

Un jeton de licence tier "pro" est signé avec une clé Ed25519 éphémère, au format de
production (JWT EdDSA), et la clé publique est injectée par monkeypatch de la résolution de
clé (aiss.license._get_active_public_key), dans un dossier de configuration temporaire.
aiss/license.py n'est pas modifié. Les tests ne lisent ni n'écrivent la licence réelle.
"""
import nacl.signing  # noqa: F401

import base64
import contextlib
import json
import os
import tempfile
import time
import unittest
import warnings
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


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _new_signing_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, base64.b64encode(public).decode()


def make_token(signing_key, tier="pro", expires_at=None, **extra) -> str:
    """Jeton JWT EdDSA au format de production (header.payload.signature, base64url)."""
    from aiss.license import TIERS
    header = _b64url(json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode())
    claims = {
        "tier": tier, "license_id": f"ephemeral_{tier}",
        "agents_max": TIERS[tier]["agents_max"], "events_month": TIERS[tier]["events_month"],
        "expires_at": expires_at,
    }
    claims.update(extra)
    payload = _b64url(json.dumps(claims).encode())
    signature = signing_key.sign(f"{header}.{payload}".encode())
    return f"{header}.{payload}.{_b64url(signature)}"


@contextlib.contextmanager
def licence_environment(token=None, public_key_b64=None):
    """HOME de licence temporaire, clé publique injectée, instance License fraîche installée."""
    import aiss.license as lic_module
    from aiss.crypto import dilithium

    config = Path(tempfile.mkdtemp())
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(lic_module, "_CONFIG_DIR", config))
        stack.enter_context(patch.object(lic_module, "_LICENSE_FILE", config / "license.jwt"))
        stack.enter_context(patch.object(lic_module, "_GRACE_FILE", config / "license.grace"))
        env = stack.enter_context(patch.dict(os.environ))
        for name in ("PIQRYPT_LICENSE_KEY", "AISS2_LICENSE_KEY", "PIQRYPT_ENV"):
            os.environ.pop(name, None)
        if token is not None:
            os.environ["PIQRYPT_LICENSE_KEY"] = token
        if public_key_b64 is not None:
            stack.enter_context(patch.object(
                lic_module, "_get_active_public_key", return_value=public_key_b64))
        instance = lic_module.License()
        stack.enter_context(patch.object(lic_module, "_license", instance))
        dilithium.reset_demo_counter()
        yield instance


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = patch("aiss.key_store._SCRYPT_N", 2 ** 10)
        p.start()
        self.addCleanup(p.stop)
        self.key, self.public_b64 = _new_signing_key()

    def pro(self, **kw):
        return licence_environment(make_token(self.key, **kw), self.public_b64)

    def free(self):
        return licence_environment(None, self.public_b64)

    def hybrid_identity(self, name="agent"):
        from aiss.identity import create_agent_identity, load_agent_pq_key
        from aiss.key_store import load_encrypted_key
        identity = create_agent_identity(
            name, passphrase=PASSPHRASE, base_dir=self.tmp, hybrid=True)["identity"]
        d = Path(self.tmp) / "agents" / name
        return (identity, load_encrypted_key(d / "private.key.enc", PASSPHRASE),
                load_agent_pq_key(name, PASSPHRASE, base_dir=self.tmp))


class TestEphemeralToken(_Base):

    def test_valid_token_gives_the_pro_tier(self):
        import aiss.license as lic_module
        from aiss.crypto import dilithium
        with self.pro() as lic:
            self.assertEqual(lic.tier, "pro")
            self.assertEqual(lic_module.get_tier(), "pro")
            self.assertTrue(lic.has_feature("quantum"))
            self.assertTrue(dilithium._has_valid_license())

    def test_no_token_is_free(self):
        with self.free() as lic:
            self.assertEqual(lic.tier, "free")

    def test_token_signed_by_another_key_is_free(self):
        other_key, _ = _new_signing_key()
        with licence_environment(make_token(other_key), self.public_b64) as lic:
            self.assertEqual(lic.tier, "free")

    def test_tampered_payload_is_free(self):
        header, payload, signature = make_token(self.key, tier="pro").split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["tier"] = "enterprise"
        forged = ".".join([header, _b64url(json.dumps(claims).encode()), signature])
        with licence_environment(forged, self.public_b64) as lic:
            self.assertEqual(lic.tier, "free")

    def test_malformed_tokens_are_free(self):
        for token in ("not-a-jwt", "a.b", "a.b.c", ".."):
            with self.subTest(token=token):
                with licence_environment(token, self.public_b64) as lic:
                    self.assertEqual(lic.tier, "free")

    def test_expired_beyond_the_grace_period_falls_back_to_free(self):
        from aiss.license import GRACE_PERIOD_SECONDS
        expired = time.time() - GRACE_PERIOD_SECONDS - 3600
        with self.pro(expires_at=expired) as lic:
            self.assertEqual(lic.tier, "free")

    def test_expired_within_the_grace_period_keeps_pro_with_a_warning(self):
        import aiss.license as lic_module
        expired = time.time() - 3600
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.pro(expires_at=expired) as lic:
                self.assertEqual(lic.tier, "pro")
                self.assertTrue((lic_module._GRACE_FILE).exists())
        self.assertTrue(any("grace" in str(w.message).lower() for w in caught))

    def test_not_yet_expired_token_is_pro(self):
        with self.pro(expires_at=time.time() + 86400) as lic:
            self.assertEqual(lic.tier, "pro")

    def test_dev_token_is_refused_in_production(self):
        token = make_token(self.key, dev=True)
        with licence_environment(token, self.public_b64) as lic:
            self.assertEqual(lic.tier, "pro")
        import aiss.license as lic_module
        with patch.dict(os.environ, {"PIQRYPT_ENV": "production"}):
            with patch.object(lic_module, "_get_active_public_key", return_value=self.public_b64):
                with patch.dict(os.environ, {"PIQRYPT_LICENSE_KEY": token}):
                    self.assertEqual(lic_module.License().tier, "free")

    def test_the_real_licence_file_is_not_used(self):
        import aiss.license as lic_module
        with self.free():
            self.assertNotEqual(lic_module._LICENSE_FILE.parent, Path.home() / ".piqrypt")


class TestProPathEndToEnd(_Base):

    def test_hybrid_identity_stamp_chain_and_verification(self):
        import aiss
        from aiss.chain import compute_event_hash
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid, stamp_genesis_event_aiss2_hybrid
        with self.pro():
            identity, priv, priv_pq = self.hybrid_identity()
            pub = base64.b64decode(identity["public_key_classical"][7:])
            pub_pq = base64.b64decode(identity["public_key_pq"][7:])
            genesis = stamp_genesis_event_aiss2_hybrid(
                priv, priv_pq, pub, identity["agent_id"], {"action": "genesis"},
                public_key_pq=pub_pq, tsa_stamp_after=False)
            second = stamp_event_aiss2_hybrid(
                priv, priv_pq, identity["agent_id"], {"action": "step"},
                previous_hash=compute_event_hash(genesis), tsa_stamp_after=False)
        self.assertEqual(genesis["version"], "AISS-2.1")
        with self.free():  # la vérification n'exige aucune licence
            self.assertTrue(aiss.verify_chain([genesis, second], identity))

    def test_upgraded_identity_mixed_chain(self):
        import aiss
        from aiss.chain import compute_event_hash
        from aiss.identity import create_agent_identity, load_agent_pq_key, upgrade_agent_identity
        from aiss.key_store import load_encrypted_key
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        with self.pro():
            created = create_agent_identity("legacy", passphrase=PASSPHRASE, base_dir=self.tmp)
            upgraded = upgrade_agent_identity("legacy", PASSPHRASE, PASSPHRASE, base_dir=self.tmp)["identity"]
            d = Path(self.tmp) / "agents" / "legacy"
            priv = load_encrypted_key(d / "private.key.enc", PASSPHRASE)
            priv_pq = load_agent_pq_key("legacy", PASSPHRASE, base_dir=self.tmp)
            first = aiss.stamp_event(priv, created["agent_id"], {"seq": 0})
            second = stamp_event_aiss2_hybrid(
                priv, priv_pq, created["agent_id"], {"seq": 1},
                previous_hash=compute_event_hash(first), tsa_stamp_after=False)
        self.assertEqual(aiss.identity_binding_assurance(upgraded), "classical_only")
        self.assertTrue(aiss.verify_chain([first, second], upgraded))

    def test_rotation_attestation_and_chained_rotation(self):
        from aiss.chain import compute_event_hash
        from aiss.crypto import dilithium, ed25519
        from aiss.identity import (
            create_rotation_attestation_hybrid, create_rotation_event_aiss21,
            derive_agent_id_aiss21, verify_rotation_attestation_hybrid, verify_rotation_chain)
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid, stamp_genesis_event_aiss2_hybrid
        with self.pro():
            identity, priv, priv_pq = self.hybrid_identity()
            pub = base64.b64decode(identity["public_key_classical"][7:])
            pub_pq = base64.b64decode(identity["public_key_pq"][7:])
            genesis = stamp_genesis_event_aiss2_hybrid(
                priv, priv_pq, pub, identity["agent_id"], {"action": "genesis"},
                public_key_pq=pub_pq, tsa_stamp_after=False)
            old_chain = [genesis]
            n_ed, n_pub = ed25519.generate_keypair()
            n_pq, n_pub_pq = dilithium.generate_keypair()

            attestation = create_rotation_attestation_hybrid(
                identity, priv, priv_pq, n_ed, n_pub, n_pq, n_pub_pq)
            self.assertTrue(verify_rotation_attestation_hybrid(attestation, identity))

            rotation = create_rotation_event_aiss21(
                identity, priv, priv_pq, n_ed, n_pub, n_pq, n_pub_pq,
                compute_event_hash(genesis))
            new_genesis = stamp_genesis_event_aiss2_hybrid(
                n_ed, n_pq, n_pub, derive_agent_id_aiss21(n_pub, n_pub_pq), {"action": "genesis"},
                public_key_pq=n_pub_pq, tsa_stamp_after=False,
                rotation_previous_hash=compute_event_hash(rotation))
        self.assertTrue(verify_rotation_chain(old_chain + [rotation], identity, new_genesis))

    def test_stamping_with_a_signer_under_the_token(self):
        from aiss.signer_file import load_hybrid_signer
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid, verify_aiss2_hybrid
        with self.pro():
            identity, _, _ = self.hybrid_identity()
            with load_hybrid_signer(Path(self.tmp) / "agents" / "agent", PASSPHRASE) as signer:
                event = stamp_event_aiss2_hybrid(
                    None, None, identity["agent_id"], {"a": 1}, tsa_stamp_after=False, signer=signer)
            pub = base64.b64decode(identity["public_key_classical"][7:])
            pub_pq = base64.b64decode(identity["public_key_pq"][7:])
            self.assertTrue(verify_aiss2_hybrid(event, pub, pub_pq))


class TestWithoutToken(_Base):

    def _material(self):
        """Clés et événement préparés sous licence, utilisés ensuite sans licence."""
        with self.pro():
            identity, priv, priv_pq = self.hybrid_identity()
        pub = base64.b64decode(identity["public_key_classical"][7:])
        pub_pq = base64.b64decode(identity["public_key_pq"][7:])
        return identity, priv, priv_pq, pub, pub_pq

    def test_stamping_functions_raise_feature_not_available(self):
        from aiss.chain import compute_event_hash
        from aiss.crypto import dilithium, ed25519
        from aiss.identity import create_rotation_event_aiss21
        from aiss.license import FeatureNotAvailableError
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid, stamp_genesis_event_aiss2_hybrid
        identity, priv, priv_pq, pub, pub_pq = self._material()
        n_ed, n_pub = ed25519.generate_keypair()
        n_pq, n_pub_pq = dilithium.generate_keypair()
        with self.free() as lic:
            self.assertEqual(lic.tier, "free")
            with self.assertRaises(FeatureNotAvailableError):
                stamp_event_aiss2_hybrid(priv, priv_pq, identity["agent_id"], {"a": 1},
                                         tsa_stamp_after=False)
            with self.assertRaises(FeatureNotAvailableError):
                stamp_genesis_event_aiss2_hybrid(
                    priv, priv_pq, pub, identity["agent_id"], {"a": 1}, public_key_pq=pub_pq,
                    tsa_stamp_after=False)
            with self.assertRaises(FeatureNotAvailableError):
                create_rotation_event_aiss21(
                    identity, priv, priv_pq, n_ed, n_pub, n_pq, n_pub_pq, "ab" * 64)

    def test_an_invalid_token_behaves_like_no_token(self):
        from aiss.license import FeatureNotAvailableError
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        identity, priv, priv_pq, _, _ = self._material()
        other_key, _ = _new_signing_key()
        with licence_environment(make_token(other_key), self.public_b64):
            with self.assertRaises(FeatureNotAvailableError):
                stamp_event_aiss2_hybrid(priv, priv_pq, identity["agent_id"], {"a": 1},
                                         tsa_stamp_after=False)

    def test_expired_token_beyond_grace_behaves_like_no_token(self):
        from aiss.license import GRACE_PERIOD_SECONDS, FeatureNotAvailableError
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        identity, priv, priv_pq, _, _ = self._material()
        with self.pro(expires_at=time.time() - GRACE_PERIOD_SECONDS - 60):
            with self.assertRaises(FeatureNotAvailableError):
                stamp_event_aiss2_hybrid(priv, priv_pq, identity["agent_id"], {"a": 1},
                                         tsa_stamp_after=False)

    def test_current_gating_observation_creation_and_attestation_are_not_gated(self):
        """Comportement actuel, documenté et non souhaité comme garantie : la création d'identité
        hybride, la mise à niveau et l'attestation de rotation ne passent pas par require_pro ;
        seule la génération/signature ML-DSA-65 consomme le compteur de démonstration hors
        licence. Un durcissement éventuel est un chantier à part."""
        from aiss.crypto import dilithium, ed25519
        from aiss.identity import (
            create_agent_identity, create_rotation_attestation_hybrid, upgrade_agent_identity,
            verify_rotation_attestation_hybrid)
        with self.free() as lic:
            self.assertEqual(lic.tier, "free")
            before = dilithium.EVENT_COUNT
            identity, priv, priv_pq = self.hybrid_identity("free_agent")
            self.assertGreater(dilithium.EVENT_COUNT, before)
            n_ed, n_pub = ed25519.generate_keypair()
            n_pq, n_pub_pq = dilithium.generate_keypair()
            attestation = create_rotation_attestation_hybrid(
                identity, priv, priv_pq, n_ed, n_pub, n_pq, n_pub_pq)
            self.assertTrue(verify_rotation_attestation_hybrid(attestation, identity))
            create_agent_identity("free_legacy", passphrase=PASSPHRASE, base_dir=self.tmp)
            upgraded = upgrade_agent_identity("free_legacy", PASSPHRASE, PASSPHRASE, base_dir=self.tmp)
            self.assertEqual(upgraded["binding_assurance"], "classical_only")

    def test_verification_needs_no_licence(self):
        import aiss
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid, verify_aiss2_hybrid
        identity, priv, priv_pq, pub, pub_pq = self._material()
        with self.pro():
            event = stamp_event_aiss2_hybrid(priv, priv_pq, identity["agent_id"], {"a": 1},
                                             tsa_stamp_after=False)
        with self.free() as lic:
            self.assertEqual(lic.tier, "free")
            self.assertTrue(verify_aiss2_hybrid(event, pub, pub_pq))
            self.assertTrue(aiss.verify_chain([event], identity))


if __name__ == "__main__":
    unittest.main()
