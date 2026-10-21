"""
Tests — AISS-2 / ML-DSA-65 (v1.9.2)

Couvre :
- Aller-retour hybride (keygen + sign + verify)
- Altération de charge et de signature ML-DSA-65
- Signature PQ retirée
- TSA indisponible / réussi (AISS-1 et AISS-2)
- verify_chain AISS-2 avec et sans clé PQ
- Rétrogradation de version (AISS-2 → AISS-1 rejetée)
- Tailles de clés FIPS 204
- Plafond PQ : licence par variable d'environnement, par license.jwt,
  jeton bidon, absence de licence
"""
# tests/test_license.py installs a fake PyNaCl via sys.modules.setdefault at
# collection time; the real import must happen before that substitution takes
# effect, otherwise nacl.signing is replaced with a stub and JWT verification
# fails at runtime.
import nacl.signing  # noqa: F401

import os
import unittest
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_license(tier: str):
    """Crée une License patchée sur un tier donné — sans secret."""
    from aiss.license import License, TIERS
    lic = License.__new__(License)
    lic._tier = tier
    lic._payload = {
        "tier": tier,
        "license_id": f"test_{tier}",
        "agents_max": TIERS[tier]["agents_max"],
        "events_month": TIERS[tier]["events_month"],
        "expires_at": None,
    }
    lic._loaded_at = 0.0
    return lic


def _keys():
    """Génère une paire Ed25519 + une paire ML-DSA-65."""
    from aiss.crypto import ed25519, dilithium
    priv_ed, pub_ed = ed25519.generate_keypair()
    priv_pq, pub_pq = dilithium.generate_keypair()
    return priv_ed, pub_ed, priv_pq, pub_pq


def _agent_id(pub_ed):
    from aiss.identity import derive_agent_id
    return derive_agent_id(pub_ed)


def _stamp(priv_ed, priv_pq, agent_id, payload=None, tsa=False):
    from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
    return stamp_event_aiss2_hybrid(
        priv_ed, priv_pq, agent_id,
        payload or {"action": "test"},
        tsa_stamp_after=tsa,
    )


# ---------------------------------------------------------------------------
# Skip guard si ML-DSA-65 non installé
# ---------------------------------------------------------------------------

def _pq_available():
    try:
        from aiss.crypto import dilithium
        return dilithium.is_available()
    except Exception:
        return False


_SKIP = not _pq_available()
_SKIP_REASON = "ML-DSA-65 backend not installed (pip install dilithium-py>=1.0.0)"

_PRO_ENV = {"AISS2_LICENSE_KEY": "any"}


# ===========================================================================
# Tailles FIPS 204
# ===========================================================================

@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestFIPS204Sizes(unittest.TestCase):

    def setUp(self):
        from aiss.crypto import dilithium
        import aiss.license as lic_module
        self._orig_lic = lic_module._license
        lic_module._license = _make_license("pro")
        dilithium.reset_demo_counter()

    def tearDown(self):
        import aiss.license as lic_module
        lic_module._license = self._orig_lic

    def test_public_key_size(self):
        from aiss.crypto import dilithium
        _, pub = dilithium.generate_keypair()
        self.assertEqual(len(pub), 1952, f"Expected 1952 bytes, got {len(pub)}")

    def test_private_key_size(self):
        from aiss.crypto import dilithium
        priv, _ = dilithium.generate_keypair()
        self.assertEqual(len(priv), 4032, f"Expected 4032 bytes, got {len(priv)}")

    def test_signature_size(self):
        from aiss.crypto import dilithium
        priv, _ = dilithium.generate_keypair()
        sig = dilithium.sign(priv, b"hello")
        self.assertEqual(len(sig), 3309, f"Expected 3309 bytes, got {len(sig)}")

    def test_get_backend_info_algorithm(self):
        from aiss.crypto import dilithium
        info = dilithium.get_backend_info()
        self.assertEqual(info["algorithm"], "ML-DSA-65")
        self.assertEqual(info["fips"], "FIPS 204")


# ===========================================================================
# Aller-retour hybride
# ===========================================================================

@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestHybridRoundTrip(unittest.TestCase):

    def setUp(self):
        import aiss.license as lic_module
        from aiss.crypto import dilithium
        self._orig_lic = lic_module._license
        lic_module._license = _make_license("pro")
        dilithium.reset_demo_counter()

    def tearDown(self):
        import aiss.license as lic_module
        lic_module._license = self._orig_lic

    def test_stamp_and_verify(self):
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        event = _stamp(priv_ed, priv_pq, aid)

        self.assertTrue(verify_aiss2_hybrid(event, pub_ed, pub_pq))

    def test_event_has_required_fields(self):
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        event = _stamp(priv_ed, priv_pq, aid)

        self.assertEqual(event["version"], "AISS-2.1")
        self.assertIn("signatures", event)
        self.assertIn("classical", event["signatures"])
        self.assertIn("post_quantum", event["signatures"])
        self.assertIn("trusted_timestamp", event)
        self.assertEqual(event["trusted_timestamp"]["status"], "pending")

    def test_trusted_timestamp_not_in_signed_content(self):
        """trusted_timestamp absent du contenu signé — le modifier ne brise pas la signature."""
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        event = _stamp(priv_ed, priv_pq, aid)

        # Modifier trusted_timestamp ne doit pas invalider la signature
        modified = dict(event)
        modified["trusted_timestamp"] = {"status": "tampered", "rfc3161_token": None}
        self.assertTrue(verify_aiss2_hybrid(modified, pub_ed, pub_pq))


# ===========================================================================
# Résistance aux altérations
# ===========================================================================

@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestTamperResistance(unittest.TestCase):

    def setUp(self):
        import aiss.license as lic_module
        from aiss.crypto import dilithium
        self._orig_lic = lic_module._license
        lic_module._license = _make_license("pro")
        dilithium.reset_demo_counter()

    def tearDown(self):
        import aiss.license as lic_module
        lic_module._license = self._orig_lic

    def _event_and_keys(self):
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        event = _stamp(priv_ed, priv_pq, aid)
        return event, pub_ed, pub_pq

    def test_payload_alteration_fails(self):
        from aiss.exceptions import InvalidSignatureError
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        event, pub_ed, pub_pq = self._event_and_keys()

        tampered = dict(event)
        tampered["payload"] = {"action": "TAMPERED"}
        with self.assertRaises(InvalidSignatureError):
            verify_aiss2_hybrid(tampered, pub_ed, pub_pq)

    def test_classical_signature_alteration_fails(self):
        from aiss.exceptions import InvalidSignatureError
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        import copy
        event, pub_ed, pub_pq = self._event_and_keys()

        tampered = copy.deepcopy(event)
        tampered["signatures"]["classical"]["signature"] = "AAAAAAAAAA"
        with self.assertRaises(InvalidSignatureError):
            verify_aiss2_hybrid(tampered, pub_ed, pub_pq)

    def test_pq_signature_alteration_fails(self):
        from aiss.exceptions import InvalidSignatureError
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        import copy
        event, pub_ed, pub_pq = self._event_and_keys()

        tampered = copy.deepcopy(event)
        tampered["signatures"]["post_quantum"]["signature"] = "AAAA"
        with self.assertRaises(InvalidSignatureError):
            verify_aiss2_hybrid(tampered, pub_ed, pub_pq)

    def test_pq_signature_removed_fails(self):
        from aiss.exceptions import InvalidSignatureError
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        import copy
        event, pub_ed, pub_pq = self._event_and_keys()

        tampered = copy.deepcopy(event)
        del tampered["signatures"]["post_quantum"]
        with self.assertRaises(InvalidSignatureError):
            verify_aiss2_hybrid(tampered, pub_ed, pub_pq)

    def test_version_downgrade_to_aiss1_skips_pq(self):
        """Un événement AISS-2 renommé AISS-1 ne passe pas verify_signature."""
        from aiss.exceptions import InvalidSignatureError
        from aiss.verify import verify_signature
        event, pub_ed, pub_pq = self._event_and_keys()

        # Retirer le champ signature (seul format attendu par verify_signature)
        degraded = {k: v for k, v in event.items() if k != "signatures"}
        degraded["version"] = "AISS-1.0"
        # Pas de champ signature → rejeté
        with self.assertRaises(InvalidSignatureError):
            verify_signature(degraded, pub_ed)


# ===========================================================================
# TSA — AISS-1 et AISS-2
# ===========================================================================

class TestTSAStamping(unittest.TestCase):

    def _aiss1_event(self):
        from aiss.crypto import ed25519
        from aiss.stamp import stamp_event
        priv, pub = ed25519.generate_keypair()
        from aiss.identity import derive_agent_id
        aid = derive_agent_id(pub)
        event = stamp_event(priv, aid, {"action": "aiss1_test"})
        return event, priv, pub

    def test_aiss1_tsa_unavailable_event_still_verifiable(self):
        """AISS-1 : TSA indisponible → l'événement reste vérifiable."""
        from aiss.rfc3161 import stamp_event_with_tsa, TSAUnavailableError
        from aiss.verify import verify_signature

        event, _, pub = self._aiss1_event()

        with patch("aiss.rfc3161.request_timestamp", side_effect=TSAUnavailableError("offline")):
            stamped = stamp_event_with_tsa(event, fail_gracefully=True)

        self.assertEqual(stamped["trusted_timestamp"]["status"], "pending")
        self.assertTrue(verify_signature(stamped, pub))

    def test_aiss1_tsa_success_event_still_verifiable(self):
        """AISS-1 : TSA réussi → l'événement reste vérifiable."""
        from aiss.rfc3161 import stamp_event_with_tsa
        from aiss.verify import verify_signature

        event, _, pub = self._aiss1_event()

        fake_tsa = {
            "status": "verified",
            "authority": "freetsa.org",
            "rfc3161_token": "AAAA",
            "timestamp": 1234567890,
        }
        with patch("aiss.rfc3161.request_timestamp", return_value=fake_tsa):
            stamped = stamp_event_with_tsa(event)

        self.assertEqual(stamped["trusted_timestamp"]["status"], "verified")
        self.assertTrue(verify_signature(stamped, pub))

    @pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
    def test_aiss2_tsa_unavailable_event_still_verifiable(self):
        """AISS-2 : TSA indisponible → les deux signatures restent vérifiables."""
        from aiss.rfc3161 import TSAUnavailableError
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        import aiss.license as lic_module
        from aiss.crypto import dilithium

        orig = lic_module._license
        lic_module._license = _make_license("pro")
        dilithium.reset_demo_counter()
        try:
            priv_ed, pub_ed, priv_pq, pub_pq = _keys()
            aid = _agent_id(pub_ed)
            with patch(
                "aiss.rfc3161.request_timestamp",
                side_effect=TSAUnavailableError("offline"),
            ):
                event = _stamp(priv_ed, priv_pq, aid, tsa=True)
            self.assertEqual(event["trusted_timestamp"]["status"], "pending")
            self.assertTrue(verify_aiss2_hybrid(event, pub_ed, pub_pq))
        finally:
            lic_module._license = orig

    @pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
    def test_aiss2_tsa_success_event_still_verifiable(self):
        """AISS-2 : TSA réussi → les deux signatures restent vérifiables."""
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        import aiss.license as lic_module
        from aiss.crypto import dilithium

        orig = lic_module._license
        lic_module._license = _make_license("pro")
        dilithium.reset_demo_counter()
        try:
            priv_ed, pub_ed, priv_pq, pub_pq = _keys()
            aid = _agent_id(pub_ed)

            fake_tsa = {
                "status": "verified",
                "authority": "freetsa.org",
                "rfc3161_token": "AAAA",
                "timestamp": 1234567890,
            }
            with patch("aiss.rfc3161.request_timestamp", return_value=fake_tsa):
                event = _stamp(priv_ed, priv_pq, aid, tsa=True)
            self.assertEqual(event["trusted_timestamp"]["status"], "verified")
            self.assertTrue(verify_aiss2_hybrid(event, pub_ed, pub_pq))
        finally:
            lic_module._license = orig


# ===========================================================================
# verify_chain AISS-2
# ===========================================================================

@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestVerifyChainAISS2(unittest.TestCase):

    def setUp(self):
        import aiss.license as lic_module
        from aiss.crypto import dilithium
        self._orig_lic = lic_module._license
        lic_module._license = _make_license("pro")
        dilithium.reset_demo_counter()

    def tearDown(self):
        import aiss.license as lic_module
        lic_module._license = self._orig_lic

    def _chain(self, n=2):
        from aiss.chain import compute_event_hash
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        events = []
        prev_hash = None
        for i in range(n):
            from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
            ev = stamp_event_aiss2_hybrid(
                priv_ed, priv_pq, aid,
                {"action": f"step_{i}"},
                previous_hash=prev_hash,
                tsa_stamp_after=False,
            )
            events.append(ev)
            prev_hash = compute_event_hash(ev)
        from aiss.crypto.ed25519 import encode_base64
        identity = {"public_key": encode_base64(pub_ed)}
        return events, identity, pub_ed, pub_pq

    def test_verify_chain_aiss2_with_pq_key(self):
        from aiss.verify import verify_chain
        events, identity, _, pub_pq = self._chain(2)
        result = verify_chain(events, identity, public_key_pq=pub_pq,
                              check_forks=False, check_replay=False)
        self.assertTrue(result)

    def test_verify_chain_aiss2_without_pq_key_raises(self):
        from aiss.verify import verify_chain
        from aiss.exceptions import InvalidChainError
        events, identity, _, _ = self._chain(1)
        with self.assertRaises(InvalidChainError):
            verify_chain(events, identity, check_forks=False, check_replay=False)

    def test_verify_chain_mixed_aiss1_then_aiss2_raises_without_pq(self):
        """Une chaîne mixte AISS-1 + AISS-2 sans clé PQ lève InvalidChainError sur l'AISS-2."""
        from aiss.stamp import stamp_event
        from aiss.chain import compute_event_hash
        from aiss.verify import verify_chain
        from aiss.exceptions import InvalidChainError
        from aiss.identity import derive_agent_id
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        from aiss.crypto.ed25519 import encode_base64

        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = derive_agent_id(pub_ed)

        ev1 = stamp_event(priv_ed, aid, {"action": "aiss1_genesis"})
        h1 = compute_event_hash(ev1)
        ev2 = stamp_event_aiss2_hybrid(
            priv_ed, priv_pq, aid,
            {"action": "aiss2_next"},
            previous_hash=h1,
            tsa_stamp_after=False,
        )
        identity = {"public_key": encode_base64(pub_ed)}

        with self.assertRaises(InvalidChainError):
            verify_chain([ev1, ev2], identity, check_forks=False, check_replay=False)


# ===========================================================================
# Plafond PQ et licence
# ===========================================================================

class TestPQDemoLimit(unittest.TestCase):
    """Teste le plafond de 1000 signatures PQ selon la source de licence."""

    def setUp(self):
        if _SKIP:
            self.skipTest(_SKIP_REASON)
        from aiss.crypto import dilithium
        dilithium.reset_demo_counter()

    def tearDown(self):
        from aiss.crypto import dilithium
        dilithium.reset_demo_counter()

    def _sign_n(self, n):
        from aiss.crypto import dilithium
        priv, pub = dilithium.generate_keypair()
        for _ in range(n):
            dilithium.sign(priv, b"test")

    def test_no_license_hits_limit(self):
        """Sans licence, le plafond s'applique après 1001 opérations."""
        from aiss.crypto import dilithium
        from aiss.exceptions import CryptoBackendError

        with patch.dict(os.environ, {}, clear=True):
            # Vider les deux variables de licence
            for k in ("AISS2_LICENSE_KEY", "PIQRYPT_LICENSE_KEY"):
                os.environ.pop(k, None)

            import aiss.license as lic_module
            orig = lic_module._license
            lic_module._license = _make_license("free")
            try:
                dilithium.reset_demo_counter()
                # 1001 appels → erreur sur le 1001e
                priv, pub = dilithium.generate_keypair()
                dilithium.EVENT_COUNT = 1000
                with self.assertRaises(CryptoBackendError):
                    dilithium.sign(priv, b"over_limit")
            finally:
                lic_module._license = orig

    def test_aiss2_license_key_env_bypasses_limit(self):
        """AISS2_LICENSE_KEY défini → pas de plafond."""
        from aiss.crypto import dilithium

        with patch.dict(os.environ, {"AISS2_LICENSE_KEY": "any_value"}):
            dilithium.reset_demo_counter()
            dilithium.EVENT_COUNT = 5000
            # Ne doit pas lever
            priv, pub = dilithium.generate_keypair()
            dilithium.sign(priv, b"no_limit")

    def test_pro_tier_license_bypasses_limit(self):
        """Licence Pro active via fixture → has_feature('quantum') == True."""
        from aiss.crypto import dilithium
        import aiss.license as lic_module

        for k in ("AISS2_LICENSE_KEY", "PIQRYPT_LICENSE_KEY"):
            os.environ.pop(k, None)

        orig = lic_module._license
        lic_module._license = _make_license("pro")
        try:
            dilithium.reset_demo_counter()
            dilithium.EVENT_COUNT = 5000
            priv, pub = dilithium.generate_keypair()
            dilithium.sign(priv, b"pro_no_limit")
        finally:
            lic_module._license = orig

    def test_bogus_piqrypt_license_key_does_not_bypass_limit(self):
        """PIQRYPT_LICENSE_KEY avec valeur invalide → Free tier → plafond actif."""
        from aiss.crypto import dilithium
        from aiss.exceptions import CryptoBackendError
        import aiss.license as lic_module

        # Env var invalide (non-JWT, non-AISS2 legacy) — doit tomber en free
        for k in ("AISS2_LICENSE_KEY",):
            os.environ.pop(k, None)

        orig = lic_module._license
        # Force un fresh License qui voit la bogus env var
        with patch.dict(os.environ, {"PIQRYPT_LICENSE_KEY": "bogus_not_a_jwt"}):
            fake_license = lic_module.License()  # loads → invalid → free
        lic_module._license = fake_license
        try:
            dilithium.reset_demo_counter()
            priv, _ = dilithium.generate_keypair()
            dilithium.EVENT_COUNT = 1000
            with self.assertRaises(CryptoBackendError):
                dilithium.sign(priv, b"bogus_key_limit")
        finally:
            lic_module._license = orig

    def test_valid_jwt_license_file_bypasses_limit(self):
        """JWT pro valide dans un fichier temporaire -> pas de plafond PQ.

        Clé ephemere generee avec PyNaCl; _get_active_public_key patche pour
        la reconnaitre. Aucune dependance sur dev_keypair.json ou
        generate_dev_licenses.
        """
        import base64
        import json
        import tempfile
        import time
        from pathlib import Path
        from unittest.mock import patch as _patch
        from aiss.crypto import dilithium
        import aiss.license as lic_module
        from nacl.signing import SigningKey

        # ---- cle ephemere Ed25519 ----
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        pub_b64 = base64.b64encode(bytes(verify_key)).decode()

        # ---- JWT pro signe avec la cle ephemere ----
        def _b64url(b: bytes) -> str:
            return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")

        header = _b64url(json.dumps({"alg": "EdDSA", "typ": "JWT"},
                                    separators=(",", ":")).encode())
        payload_data = {
            "tier": "pro",
            "agents_max": 50,
            "events_month": 500_000,
            "features": ["quantum", "tsa_rfc3161", "pqz_certified"],
            "issued_at": int(time.time()),
            "expires_at": int(time.time()) + 365 * 86400,
            "license_id": "test-ephemeral-pro-001",
        }
        payload = _b64url(json.dumps(payload_data, separators=(",", ":")).encode())
        message = f"{header}.{payload}".encode()
        sig = _b64url(signing_key.sign(message).signature)
        jwt_token = f"{header}.{payload}.{sig}"

        # ---- fichier temporaire pour _LICENSE_FILE ----
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jwt", delete=False
        ) as f:
            f.write(jwt_token)
            tmp_path = Path(f.name)

        orig_license = lic_module._license
        orig_license_file = lic_module._LICENSE_FILE
        lic_module._LICENSE_FILE = tmp_path
        try:
            for k in ("AISS2_LICENSE_KEY", "PIQRYPT_LICENSE_KEY"):
                os.environ.pop(k, None)
            with _patch("aiss.license._get_active_public_key", return_value=pub_b64):
                fresh_license = lic_module.License()
            lic_module._license = fresh_license
            self.assertTrue(
                fresh_license.has_feature("quantum"),
                "Pro JWT with ephemeral key should grant quantum feature",
            )
            dilithium.reset_demo_counter()
            priv, _ = dilithium.generate_keypair()
            dilithium.EVENT_COUNT = 5000
            dilithium.sign(priv, b"pro_jwt_no_limit")
        finally:
            lic_module._license = orig_license
            lic_module._LICENSE_FILE = orig_license_file
            try:
                tmp_path.unlink()
            except OSError:
                pass

    def test_free_tier_license_file_enforces_limit(self):
        """Fichier license.jwt avec tier free → plafond actif."""
        from aiss.crypto import dilithium
        from aiss.exceptions import CryptoBackendError
        import aiss.license as lic_module

        for k in ("AISS2_LICENSE_KEY", "PIQRYPT_LICENSE_KEY"):
            os.environ.pop(k, None)

        # Générer la paire avant de passer en free + forcer le compteur
        dilithium.reset_demo_counter()
        priv, _ = dilithium.generate_keypair()

        orig = lic_module._license
        lic_module._license = _make_license("free")
        try:
            # À 1000, le prochain appel (sign) dépasse le plafond
            dilithium.EVENT_COUNT = 1000
            with self.assertRaises(CryptoBackendError):
                dilithium.sign(priv, b"free_limit")
        finally:
            lic_module._license = orig


# ===========================================================================
# compute_event_hash — exclusion de trusted_timestamp
# ===========================================================================

class TestComputeEventHashTSA(unittest.TestCase):
    """compute_event_hash doit exclure trusted_timestamp (comme signature)."""

    def _aiss1_event(self):
        from aiss.crypto import ed25519
        from aiss.stamp import stamp_event
        from aiss.identity import derive_agent_id
        priv, pub = ed25519.generate_keypair()
        aid = derive_agent_id(pub)
        return stamp_event(priv, aid, {"action": "chain_test"}), priv, pub

    def test_hash_unchanged_without_trusted_timestamp(self):
        """Un événement sans trusted_timestamp a le même hash avant et après l'ajout."""
        from aiss.chain import compute_event_hash
        event, _, _ = self._aiss1_event()
        self.assertNotIn("trusted_timestamp", event)
        h1 = compute_event_hash(event)
        # Ajouter trusted_timestamp ne doit pas changer le hash
        event2 = dict(event)
        event2["trusted_timestamp"] = {"status": "pending", "rfc3161_token": None}
        h2 = compute_event_hash(event2)
        self.assertEqual(h1, h2)

    def test_tsa_obtained_after_chaining_verify_chain_passes(self):
        """Chaîne AISS-1 : TSA obtenu après chaînage, verify_chain doit passer."""
        from aiss.crypto import ed25519
        from aiss.stamp import stamp_event
        from aiss.chain import compute_event_hash
        from aiss.verify import verify_chain
        from aiss.identity import derive_agent_id
        from aiss.crypto.ed25519 import encode_base64
        from unittest.mock import patch

        priv, pub = ed25519.generate_keypair()
        aid = derive_agent_id(pub)

        ev1 = stamp_event(priv, aid, {"action": "genesis"})
        h1 = compute_event_hash(ev1)
        ev2 = stamp_event(priv, aid, {"action": "step2"}, previous_hash=h1)

        # Simuler un TSA obtenu sur ev1 APRES le chaînage de ev2
        fake_tsa = {"status": "verified", "authority": "freetsa.org",
                    "rfc3161_token": "AAAA", "timestamp": 1234567890}
        with patch("aiss.rfc3161.request_timestamp", return_value=fake_tsa):
            from aiss.rfc3161 import stamp_event_with_tsa
            ev1_with_tsa = stamp_event_with_tsa(ev1)

        # Maintenant la chaîne [ev1_with_tsa, ev2] doit se vérifier
        identity = {"public_key": encode_base64(pub)}
        self.assertTrue(
            verify_chain([ev1_with_tsa, ev2], identity,
                         check_forks=False, check_replay=False)
        )

    def test_test_vectors_hash_unchanged(self):
        """Les vecteurs canoniques existants n'ont pas de trusted_timestamp — hashes inchangés."""
        import json
        from pathlib import Path
        from aiss.chain import compute_event_hash

        vectors_path = Path(__file__).parents[1] / "test_vectors" / "events.json"
        if not vectors_path.exists():
            self.skipTest("test_vectors/events.json not found")

        data = json.loads(vectors_path.read_text())
        events = data if isinstance(data, list) else data.get("events", [])
        for ev in events:
            if "trusted_timestamp" not in ev and ("signature" in ev or "signatures" in ev):
                # Ajouter un trusted_timestamp bidon ne change pas le hash
                ev_with_tsa = dict(ev)
                ev_with_tsa["trusted_timestamp"] = {"status": "fake"}
                self.assertEqual(
                    compute_event_hash(ev),
                    compute_event_hash(ev_with_tsa),
                    "Hash changed when trusted_timestamp added — test_vectors at risk",
                )


# ===========================================================================
# D1 — verify_aiss2_hybrid dispatch AISS-2.0 / AISS-2.1 / inconnu
# ===========================================================================

@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestVerifyDispatch(unittest.TestCase):
    """verify_aiss2_hybrid dispatche selon event['version']."""

    def setUp(self):
        import aiss.license as lic_module
        from aiss.crypto import dilithium
        self._orig_lic = lic_module._license
        lic_module._license = _make_license("pro")
        dilithium.reset_demo_counter()

    def tearDown(self):
        import aiss.license as lic_module
        lic_module._license = self._orig_lic

    def _make_aiss20_event(self, priv_ed, priv_pq, pub_ed, agent_id):
        """Crée un événement AISS-2.0 avec l'encodage 1.9.2 (canonical + base58 + base64)."""
        import time
        from aiss.canonical import canonicalize as _c
        from aiss.crypto import ed25519 as _ed, dilithium as _dil
        from aiss.stamp import generate_nonce

        event = {
            "version": "AISS-2.0",
            "agent_id": agent_id,
            "timestamp": int(time.time()),
            "nonce": generate_nonce(),
            "payload": {"action": "d1_test"},
            "previous_hash": None,
        }
        canonical = _c(event)
        sig_ed = _ed.sign(priv_ed, canonical)
        sig_pq = _dil.sign(priv_pq, canonical)
        event["signatures"] = {
            "classical": {
                "algorithm": "Ed25519",
                "signature": _ed.encode_base58(sig_ed),
            },
            "post_quantum": {
                "algorithm": "ML-DSA-65",
                "signature": __import__("base64").b64encode(sig_pq).decode(),
            },
        }
        event["trusted_timestamp"] = {"status": "pending", "rfc3161_token": None}
        return event

    def test_aiss20_path_verifies(self):
        """Un événement AISS-2.0 valide est vérifié sur le chemin 1.9.2."""
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        event = self._make_aiss20_event(priv_ed, priv_pq, pub_ed, aid)
        self.assertTrue(verify_aiss2_hybrid(event, pub_ed, pub_pq))

    def test_aiss21_path_verifies(self):
        """Un événement AISS-2.1 valide est vérifié sur le nouveau chemin."""
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        event = _stamp(priv_ed, priv_pq, aid)
        self.assertEqual(event["version"], "AISS-2.1")
        self.assertTrue(verify_aiss2_hybrid(event, pub_ed, pub_pq))

    def test_unknown_version_raises(self):
        """Une version inconnue lève InvalidSignatureError."""
        import copy
        from aiss.exceptions import InvalidSignatureError
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        event = copy.deepcopy(_stamp(priv_ed, priv_pq, aid))
        event["version"] = "AISS-3.0"
        with self.assertRaises(InvalidSignatureError):
            verify_aiss2_hybrid(event, pub_ed, pub_pq)

    def test_aiss20_does_not_use_jcs(self):
        """AISS-2.0 n'utilise pas JCS — falsifier version 2.0 avec sig 2.1 échoue."""
        import copy
        from aiss.exceptions import InvalidSignatureError
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        # Créer un événement AISS-2.1, puis forcer la version à 2.0
        event = copy.deepcopy(_stamp(priv_ed, priv_pq, aid))
        event["version"] = "AISS-2.0"
        with self.assertRaises(InvalidSignatureError):
            verify_aiss2_hybrid(event, pub_ed, pub_pq)


# ===========================================================================
# Séparation de domaine AISS-2.1 — M' avec label d'algorithme
# ===========================================================================

@pytest.mark.skipif(_SKIP, reason=_SKIP_REASON)
class TestDomainSeparation(unittest.TestCase):
    """M' = DOMAIN_PREFIX || label_len || label || ctx_len || ctx || JCS."""

    def setUp(self):
        import aiss.license as lic_module
        from aiss.crypto import dilithium
        self._orig_lic = lic_module._license
        lic_module._license = _make_license("pro")
        dilithium.reset_demo_counter()

    def tearDown(self):
        import aiss.license as lic_module
        lic_module._license = self._orig_lic

    def _make_event_and_keys(self):
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        event = _stamp(priv_ed, priv_pq, aid)
        return event, pub_ed, pub_pq

    def test_built_message_contains_label(self):
        """_build_signed_message embeds the algorithm label in M'."""
        from aiss.stamp_aiss2 import _build_signed_message, _ALGO_LABEL, _DOMAIN_PREFIX
        msg = _build_signed_message(b"payload")
        self.assertIn(_ALGO_LABEL, msg)
        self.assertTrue(msg.startswith(_DOMAIN_PREFIX))
        # label_len byte
        prefix_len = len(_DOMAIN_PREFIX)
        label_len_byte = msg[prefix_len]
        self.assertEqual(label_len_byte, len(_ALGO_LABEL))

    def test_changed_label_invalidates_both_signatures(self):
        """Verifying with a different label in M' must fail both signatures."""
        from aiss.exceptions import InvalidSignatureError
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        import aiss.stamp_aiss2 as m

        event, pub_ed, pub_pq = self._make_event_and_keys()

        orig_label = m._ALGO_LABEL
        try:
            m._ALGO_LABEL = b"WrongLabel"  # tamper the label used in verify
            with self.assertRaises(InvalidSignatureError):
                verify_aiss2_hybrid(event, pub_ed, pub_pq)
        finally:
            m._ALGO_LABEL = orig_label

    def test_nonempty_context_invalidates_both_signatures(self):
        """Verifying with a non-empty context injected in M' must fail both signatures."""
        import aiss.stamp_aiss2 as m

        event, pub_ed, pub_pq = self._make_event_and_keys()

        orig_fn = m._build_signed_message
        def _with_context(jcs_bytes: bytes) -> bytes:
            label = m._ALGO_LABEL
            ctx = b"injected_context"
            return (
                m._DOMAIN_PREFIX + bytes([len(label)]) + label + bytes([len(ctx)]) + ctx + jcs_bytes
            )
        try:
            m._build_signed_message = _with_context
            with self.assertRaises(Exception):  # InvalidSignatureError or verify returns False
                from aiss.stamp_aiss2 import verify_aiss2_hybrid
                verify_aiss2_hybrid(event, pub_ed, pub_pq)
        finally:
            m._build_signed_message = orig_fn


# ===========================================================================
# _pro_only decorator — comportement du module-level import
# ===========================================================================

class TestProOnlyDecorator(unittest.TestCase):
    """Vérifie les quatre comportements du décorateur _pro_only après refactor."""

    def test_free_license_raises(self):
        """@_pro_only lève une erreur quand la licence est Free."""
        import aiss.license as lic_module
        from aiss.crypto import dilithium
        orig = lic_module._license
        lic_module._license = _make_license("free")
        if _SKIP:
            self.skipTest(_SKIP_REASON)
        dilithium.reset_demo_counter()
        try:
            from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
            priv_ed, pub_ed, priv_pq, pub_pq = _keys()
            aid = _agent_id(pub_ed)
            with self.assertRaises(Exception):
                stamp_event_aiss2_hybrid(priv_ed, priv_pq, aid, {"action": "test"})
        finally:
            lic_module._license = orig

    def test_no_license_module_allows_call(self):
        """Quand _require_pro est None (aiss.license absent), la fonction est appelée."""
        import aiss.stamp_aiss2 as m
        from aiss.stamp_aiss2 import _pro_only
        orig = m._require_pro
        m._require_pro = None
        called = []
        try:
            @_pro_only("test_feature")
            def _dummy():
                called.append(True)
                return "ok"
            result = _dummy()
            self.assertEqual(result, "ok")
            self.assertTrue(called)
        finally:
            m._require_pro = orig

    def test_importerror_from_require_pro_propagates(self):
        """Une ImportError levée par _require_pro (bug interne license.py) n'est pas avalée."""
        import aiss.stamp_aiss2 as m
        from aiss.stamp_aiss2 import _pro_only
        orig = m._require_pro

        def _broken(feature_name):
            raise ImportError("broken internal dep in license.py")

        m._require_pro = _broken
        try:
            @_pro_only("test_feature")
            def _dummy():
                return "ok"
            with self.assertRaises(ImportError) as ctx:
                _dummy()
            self.assertIn("broken internal dep", str(ctx.exception))
        finally:
            m._require_pro = orig

    def test_importerror_from_function_propagates(self):
        """Une ImportError levée par la fonction décorée se propage sans être masquée."""
        import aiss.stamp_aiss2 as m
        from aiss.stamp_aiss2 import _pro_only
        orig = m._require_pro
        m._require_pro = None
        try:
            @_pro_only("test_feature")
            def _raises():
                raise ImportError("missing dep inside decorated function")
            with self.assertRaises(ImportError) as ctx:
                _raises()
            self.assertIn("missing dep inside decorated function", str(ctx.exception))
        finally:
            m._require_pro = orig


class TestBase64PrefixEncoding(unittest.TestCase):
    """A.2 — AISS-2.1 signatures use 'base64:<b64>' for both Ed25519 and ML-DSA-65."""

    def _make_event(self):
        if _SKIP:
            self.skipTest(_SKIP_REASON)
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid
        priv_ed, pub_ed, priv_pq, pub_pq = _keys()
        aid = _agent_id(pub_ed)
        return stamp_event_aiss2_hybrid(
            priv_ed, priv_pq, aid, {"action": "a2_test"}, tsa_stamp_after=False
        ), pub_ed, pub_pq

    def test_ed25519_signature_has_base64_prefix(self):
        """AISS-2.1 Ed25519 signature must start with 'base64:'."""
        event, _, _ = self._make_event()
        sig = event["signatures"]["classical"]["signature"]
        self.assertTrue(
            sig.startswith("base64:"),
            f"Ed25519 signature missing base64: prefix: {sig[:30]}",
        )

    def test_ml_dsa_signature_has_base64_prefix(self):
        """AISS-2.1 ML-DSA-65 signature must start with 'base64:'."""
        event, _, _ = self._make_event()
        sig = event["signatures"]["post_quantum"]["signature"]
        self.assertTrue(
            sig.startswith("base64:"),
            f"ML-DSA-65 signature missing base64: prefix: {sig[:30]}",
        )

    def test_round_trip_verifies(self):
        """stamp + verify_aiss2_hybrid round-trip succeeds with base64: encoding."""
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        event, pub_ed, pub_pq = self._make_event()
        self.assertTrue(verify_aiss2_hybrid(event, pub_ed, pub_pq))

    def test_missing_prefix_rejected(self):
        """Verification fails if Ed25519 signature lacks 'base64:' prefix."""
        import copy
        from aiss.stamp_aiss2 import verify_aiss2_hybrid
        from aiss.exceptions import InvalidSignatureError
        event, pub_ed, pub_pq = self._make_event()
        bad = copy.deepcopy(event)
        raw = bad["signatures"]["classical"]["signature"]
        bad["signatures"]["classical"]["signature"] = raw[7:]  # strip "base64:"
        with self.assertRaises(InvalidSignatureError):
            verify_aiss2_hybrid(bad, pub_ed, pub_pq)


if __name__ == "__main__":
    unittest.main()
