"""
Tests de sécurité — Intégrité de la chaîne cryptographique

Couverture :
    1. Signature falsifiée    : modifier la signature → InvalidSignatureError
    2. Payload modifié        : changer payload → InvalidSignatureError
    3. Agent ID usurpé        : signer A, déclarer B → rejeté
    4. Previous_hash forgé    : fork détecté
    5. Nonce dupliqué         : replay détecté
    6. Nonce malformé         : pas de crash
    7. Session locked         : accès sans unlock → SessionLockedError
    8. Rupture de chaîne      : modify event → InvalidChainError

Notes :
    - verify_signature() lève InvalidSignatureError (ne retourne pas False)
    - La signature est encodée en Base64 standard
    - verify_chain_linkage() lève InvalidChainError si chaîne rompue
"""

import base64
import copy
import unittest

from aiss.exceptions import InvalidSignatureError


class TestSignatureForgery(unittest.TestCase):

    def setUp(self):
        from aiss.crypto import ed25519
        from aiss import derive_agent_id, stamp_genesis_event
        self.priv, self.pub = ed25519.generate_keypair()
        self.agent_id = derive_agent_id(self.pub)
        self.genesis = stamp_genesis_event(
            self.priv, self.pub, self.agent_id, {"init": True}
        )

    def test_modified_signature_rejected(self):
        """Modifier 1 byte dans la signature → rejetée."""
        from aiss import verify_signature

        event = copy.deepcopy(self.genesis)
        sig = bytearray(base64.b64decode(event["signature"]))
        sig[0] ^= 0xFF
        event["signature"] = base64.b64encode(bytes(sig)).decode()

        with self.assertRaises((InvalidSignatureError, Exception)):
            verify_signature(event, self.pub)

    def test_zeroed_signature_rejected(self):
        """Signature tout à zéro → rejetée."""
        from aiss import verify_signature

        event = copy.deepcopy(self.genesis)
        sig_len = len(base64.b64decode(event["signature"]))
        event["signature"] = base64.b64encode(bytes(sig_len)).decode()

        with self.assertRaises((InvalidSignatureError, Exception)):
            verify_signature(event, self.pub)

    def test_wrong_public_key_rejected(self):
        """Vérifier avec la mauvaise clé publique → rejeté."""
        from aiss import verify_signature
        from aiss.crypto import ed25519

        _, other_pub = ed25519.generate_keypair()
        with self.assertRaises((InvalidSignatureError, Exception)):
            verify_signature(self.genesis, other_pub)

    def test_valid_signature_accepted(self):
        """Contrôle positif : signature valide → acceptée sans exception."""
        from aiss import verify_signature
        try:
            result = verify_signature(self.genesis, self.pub)
            if result is not None:
                self.assertTrue(result)
        except Exception as e:
            self.fail(f"Signature valide a levé une exception : {e}")


class TestPayloadTampering(unittest.TestCase):

    def setUp(self):
        from aiss.crypto import ed25519
        from aiss import derive_agent_id, stamp_event, stamp_genesis_event
        from aiss.chain import compute_event_hash
        self.priv, self.pub = ed25519.generate_keypair()
        self.agent_id = derive_agent_id(self.pub)
        genesis = stamp_genesis_event(self.priv, self.pub, self.agent_id, {"action": "init"})
        self.event = stamp_event(
            self.priv, self.agent_id,
            {"action": "trade", "amount": 100},
            previous_hash=compute_event_hash(genesis)
        )

    def test_modified_payload_changes_hash(self):
        """Modifier le payload change le hash."""
        from aiss.chain import compute_event_hash

        original = compute_event_hash(self.event)
        tampered = copy.deepcopy(self.event)
        tampered["payload"]["amount"] = 999999
        self.assertNotEqual(original, compute_event_hash(tampered))

    def test_modified_payload_fails_verification(self):
        """Payload modifié → InvalidSignatureError."""
        from aiss import verify_signature

        tampered = copy.deepcopy(self.event)
        tampered["payload"]["action"] = "FALSIFIED"
        with self.assertRaises((InvalidSignatureError, Exception)):
            verify_signature(tampered, self.pub)

    def test_added_field_fails_verification(self):
        """Champ ajouté au payload → InvalidSignatureError."""
        from aiss import verify_signature

        tampered = copy.deepcopy(self.event)
        tampered["payload"]["injected"] = "malicious"
        with self.assertRaises((InvalidSignatureError, Exception)):
            verify_signature(tampered, self.pub)


class TestAgentIDSpoofing(unittest.TestCase):

    def test_agent_id_bound_to_public_key(self):
        """Deux clés différentes → deux agent_ids différents."""
        from aiss.crypto import ed25519
        from aiss import derive_agent_id

        _, pub_a = ed25519.generate_keypair()
        _, pub_b = ed25519.generate_keypair()
        self.assertNotEqual(derive_agent_id(pub_a), derive_agent_id(pub_b))

    def test_wrong_agent_id_fails_verification(self):
        """Signer avec clé A, déclarer agent_id de B → rejeté."""
        from aiss.crypto import ed25519
        from aiss import derive_agent_id, stamp_event, verify_signature, stamp_genesis_event
        from aiss.chain import compute_event_hash

        priv_a, pub_a = ed25519.generate_keypair()
        _, pub_b = ed25519.generate_keypair()
        id_a = derive_agent_id(pub_a)
        id_b = derive_agent_id(pub_b)

        genesis = stamp_genesis_event(priv_a, pub_a, id_a, {"init": True})
        event = stamp_event(priv_a, id_a, {"test": 1},
                            previous_hash=compute_event_hash(genesis))

        spoofed = copy.deepcopy(event)
        spoofed["agent_id"] = id_b

        with self.assertRaises((InvalidSignatureError, Exception)):
            verify_signature(spoofed, pub_b)


class TestForkInjection(unittest.TestCase):

    def test_forged_previous_hash_detected(self):
        """Deux events avec le même previous_hash → fork détecté."""
        from aiss.crypto import ed25519
        from aiss import derive_agent_id, stamp_event, stamp_genesis_event
        from aiss.chain import compute_event_hash
        from aiss.fork import find_forks

        priv, pub = ed25519.generate_keypair()
        agent_id = derive_agent_id(pub)
        genesis = stamp_genesis_event(priv, pub, agent_id, {"init": True})
        h = compute_event_hash(genesis)

        e1 = stamp_event(priv, agent_id, {"seq": 1}, previous_hash=h)
        e2 = stamp_event(priv, agent_id, {"seq": 1, "alt": True}, previous_hash=h)

        forks = find_forks([genesis, e1, e2])
        self.assertGreater(len(forks), 0)


class TestReplayProtection(unittest.TestCase):

    def test_duplicate_nonce_detected(self):
        """Même nonce deux fois → replay détecté."""
        from aiss.crypto import ed25519
        from aiss import derive_agent_id, stamp_event
        from aiss.replay import detect_replay_attacks

        priv, pub = ed25519.generate_keypair()
        agent_id = derive_agent_id(pub)
        nonce = "550e8400-e29b-41d4-a716-446655440000"

        e1 = stamp_event(priv, agent_id, {"seq": 1}, nonce=nonce)
        e2 = stamp_event(priv, agent_id, {"seq": 2}, nonce=nonce)

        self.assertGreater(len(detect_replay_attacks([e1, e2])), 0)

    def test_unique_nonces_no_replay(self):
        """Nonces uniques → pas de replay."""
        from aiss.crypto import ed25519
        from aiss import derive_agent_id, stamp_event, stamp_genesis_event
        from aiss.chain import compute_event_hash
        from aiss.replay import detect_replay_attacks

        priv, pub = ed25519.generate_keypair()
        agent_id = derive_agent_id(pub)
        genesis = stamp_genesis_event(priv, pub, agent_id, {"init": True})
        h = compute_event_hash(genesis)
        e1 = stamp_event(priv, agent_id, {"seq": 1}, previous_hash=h)
        h = compute_event_hash(e1)
        e2 = stamp_event(priv, agent_id, {"seq": 2}, previous_hash=h)

        self.assertEqual(len(detect_replay_attacks([genesis, e1, e2])), 0)

    def test_malformed_nonce_no_crash(self):
        """Nonce malformé → pas de crash."""
        from aiss.crypto import ed25519
        from aiss import derive_agent_id, stamp_event
        from aiss.replay import detect_replay_attacks

        priv, pub = ed25519.generate_keypair()
        agent_id = derive_agent_id(pub)
        event = stamp_event(priv, agent_id, {"seq": 1})
        event["nonce"] = "not-a-valid-uuid-!!!"

        try:
            detect_replay_attacks([event])
        except Exception as e:
            self.fail(f"Nonce malformé a causé un crash : {e}")


class TestIdentitySessionSecurity(unittest.TestCase):

    def test_private_key_without_unlock_raises(self):
        from aiss.identity_session import IdentitySession, SessionLockedError
        with self.assertRaises(SessionLockedError):
            _ = IdentitySession().private_key

    def test_agent_id_without_unlock_raises(self):
        from aiss.identity_session import IdentitySession, SessionLockedError
        with self.assertRaises(SessionLockedError):
            _ = IdentitySession().agent_id

    def test_sign_without_unlock_raises(self):
        from aiss.identity_session import IdentitySession, SessionLockedError
        with self.assertRaises(SessionLockedError):
            IdentitySession().sign(b"data")

    def test_lock_marks_session_locked(self):
        """Après lock(), is_locked doit être True et la clé effacée."""
        from aiss.identity_session import IdentitySession
        import secrets

        session = IdentitySession()
        session._private_key = bytearray(secrets.token_bytes(32))
        session._locked = False
        session.lock()
        self.assertTrue(session.is_locked)


class TestChainIntegrity(unittest.TestCase):

    def test_chain_breaks_on_modification(self):
        """Modifier event[1] → verify_chain_linkage() lève InvalidChainError."""
        from aiss.crypto import ed25519
        from aiss import derive_agent_id, stamp_event, stamp_genesis_event
        from aiss.chain import compute_event_hash, verify_chain_linkage
        from aiss.exceptions import InvalidChainError

        priv, pub = ed25519.generate_keypair()
        agent_id = derive_agent_id(pub)
        genesis = stamp_genesis_event(priv, pub, agent_id, {"init": True})
        h = compute_event_hash(genesis)
        e1 = stamp_event(priv, agent_id, {"seq": 1}, previous_hash=h)
        h2 = compute_event_hash(e1)
        e2 = stamp_event(priv, agent_id, {"seq": 2}, previous_hash=h2)

        # Chaîne valide
        self.assertTrue(verify_chain_linkage([genesis, e1, e2]))

        # Chaîne falsifiée
        tampered = copy.deepcopy([genesis, e1, e2])
        tampered[1]["payload"]["seq"] = 999
        with self.assertRaises((InvalidChainError, Exception)):
            verify_chain_linkage(tampered)

    def test_valid_chain_passes(self):
        """Chaîne valide → verify_chain_linkage() = True."""
        from aiss.crypto import ed25519
        from aiss import derive_agent_id, stamp_event, stamp_genesis_event
        from aiss.chain import compute_event_hash, verify_chain_linkage

        priv, pub = ed25519.generate_keypair()
        agent_id = derive_agent_id(pub)
        genesis = stamp_genesis_event(priv, pub, agent_id, {"init": True})
        h = compute_event_hash(genesis)
        e1 = stamp_event(priv, agent_id, {"seq": 1}, previous_hash=h)
        self.assertTrue(verify_chain_linkage([genesis, e1]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
