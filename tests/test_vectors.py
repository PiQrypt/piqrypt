# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Test Vectors Validation (RFC Appendix B)

All AISS implementations MUST pass these normative tests.
These vectors are the definitive source of truth for RFC compliance.

Converti de pytest vers unittest pour compatibilite avec run_all.py.
"""

import json
import unittest
from pathlib import Path

from aiss import derive_agent_id
from aiss.canonical import canonicalize, hash_canonical
from aiss.chain import compute_event_hash
from aiss.fork import find_forks
from aiss.replay import detect_replay_attacks
from aiss.crypto import ed25519


VECTORS_DIR = Path(__file__).parent.parent / "test_vectors"


class TestCanonicalVectors(unittest.TestCase):
    """Test RFC 8785 JSON Canonicalization Scheme (JCS)"""

    def test_canonical_vectors(self):
        """All canonical test vectors must pass"""
        with open(VECTORS_DIR / "canonical.json") as f:
            vectors = json.load(f)

        for test in vectors["tests"]:
            input_data = test["input"]
            expected_canonical = test["expected_canonical"]
            expected_hash = test["expected_sha256"]

            actual_canonical = canonicalize(input_data).decode("utf-8")
            self.assertEqual(actual_canonical, expected_canonical,
                f"Canonicalization failed for {test['name']}: "
                f"expected {expected_canonical}, got {actual_canonical}")

            actual_hash = hash_canonical(input_data)
            self.assertEqual(actual_hash, expected_hash,
                f"Hash failed for {test['name']}: "
                f"expected {expected_hash}, got {actual_hash}")

    def test_key_ordering(self):
        """Keys must be ordered lexicographically"""
        obj = {"z": 1, "a": 2, "m": 3}
        canonical = canonicalize(obj).decode("utf-8")
        self.assertEqual(canonical, '{"a":2,"m":3,"z":1}')

    def test_no_whitespace(self):
        """Canonical JSON must have no whitespace"""
        obj = {"key": "value"}
        canonical = canonicalize(obj).decode("utf-8")
        self.assertNotIn(" ", canonical)
        self.assertNotIn("\n", canonical)
        self.assertNotIn("\t", canonical)


class TestIdentityVectors(unittest.TestCase):
    """Test RFC Section 5-6: Agent Identity"""

    def test_identity_vectors(self):
        """Agent ID must derive correctly from public key"""
        with open(VECTORS_DIR / "identity.json") as f:
            vectors = json.load(f)

        for test in vectors["tests"]:
            public_key = bytes.fromhex(test["public_key_hex"])
            actual_agent_id = derive_agent_id(public_key)
            expected_agent_id = test["expected_agent_id"]

            self.assertEqual(actual_agent_id, expected_agent_id,
                f"Agent ID derivation failed for {test['name']}: "
                f"expected {expected_agent_id}, got {actual_agent_id}")

            self.assertEqual(len(actual_agent_id), 32,
                f"Agent ID must be 32 chars, got {len(actual_agent_id)}")

    def test_agent_id_determinism(self):
        """Same public key must always produce same agent ID"""
        priv, pub = ed25519.generate_keypair()
        self.assertEqual(derive_agent_id(pub), derive_agent_id(pub),
            "Agent ID derivation must be deterministic")

    def test_agent_id_uniqueness(self):
        """Different public keys must produce different agent IDs"""
        _, pub1 = ed25519.generate_keypair()
        _, pub2 = ed25519.generate_keypair()
        self.assertNotEqual(derive_agent_id(pub1), derive_agent_id(pub2),
            "Different keys must produce different agent IDs")


class TestEventVectors(unittest.TestCase):
    """Test RFC Section 7: Event Stamping"""

    def test_event_vectors(self):
        """All event hash vectors must match"""
        with open(VECTORS_DIR / "events.json") as f:
            vectors = json.load(f)

        for test in vectors["tests"]:
            event = test["event"]
            expected_hash = test["expected_hash"]
            actual_hash = compute_event_hash(event)
            self.assertEqual(actual_hash, expected_hash,
                f"Event hash mismatch for {test['name']}: "
                f"expected {expected_hash[:16]}..., got {actual_hash[:16]}...")

    def test_event_structure(self):
        """Events must have all required fields"""
        with open(VECTORS_DIR / "events.json") as f:
            vectors = json.load(f)

        required_fields = [
            "version", "agent_id", "timestamp", "nonce",
            "payload", "previous_hash", "signature",
        ]

        for test in vectors["tests"]:
            event = test["event"]
            for field in required_fields:
                self.assertIn(field, event,
                    f"Event {test['name']} missing required field: {field}")


class TestForkVectors(unittest.TestCase):
    """Test RFC Section 10: Fork Detection"""

    def test_fork_vectors(self):
        """Fork detection must work correctly"""
        with open(VECTORS_DIR / "fork.json") as f:
            vectors = json.load(f)

        for test in vectors["tests"]:
            events = [test["genesis"]] + test["fork_events"]
            forks = find_forks(events)

            self.assertGreater(len(forks), 0,
                f"Fork not detected for {test['name']}")
            self.assertEqual(forks[0].hash, test["expected_fork_at"],
                f"Wrong fork hash for {test['name']}")
            self.assertEqual(len(forks[0].events), test["expected_branches"],
                f"Wrong branch count for {test['name']}")

    def test_no_false_positives(self):
        """Valid chains must not trigger fork detection"""
        from aiss import stamp_event, stamp_genesis_event

        priv, pub = ed25519.generate_keypair()
        agent_id = derive_agent_id(pub)

        genesis = stamp_genesis_event(priv, pub, agent_id, {"init": True})
        event1 = stamp_event(priv, agent_id, {"seq": 1},
                             previous_hash=compute_event_hash(genesis))
        event2 = stamp_event(priv, agent_id, {"seq": 2},
                             previous_hash=compute_event_hash(event1))

        forks = find_forks([genesis, event1, event2])
        self.assertEqual(len(forks), 0, "Valid chain incorrectly flagged as fork")


class TestReplayVectors(unittest.TestCase):
    """Test RFC Section 11: Anti-Replay Protection"""

    def test_replay_vectors(self):
        """Replay attacks must be detected"""
        with open(VECTORS_DIR / "replay.json") as f:
            vectors = json.load(f)

        for test in vectors["tests"]:
            attacks = detect_replay_attacks(test["events"])

            if test["expected_replay"]:
                self.assertGreater(len(attacks), 0,
                    f"Replay not detected for {test['name']}")
                self.assertEqual(attacks[0].nonce, test["replay_nonce"],
                    f"Wrong replay nonce for {test['name']}")
            else:
                self.assertEqual(len(attacks), 0,
                    f"False positive replay detection for {test['name']}")

    def test_unique_nonces_required(self):
        """Each event must have unique nonce"""
        from aiss import stamp_event

        priv, pub = ed25519.generate_keypair()
        agent_id = derive_agent_id(pub)
        nonce = "test-nonce-12345"

        event1 = stamp_event(priv, agent_id, {"attempt": 1}, nonce=nonce)
        event2 = stamp_event(priv, agent_id, {"attempt": 2}, nonce=nonce)

        attacks = detect_replay_attacks([event1, event2])
        self.assertGreater(len(attacks), 0, "Duplicate nonce not detected")


class TestVectorCompleteness(unittest.TestCase):
    """Ensure all test vector files exist and are valid"""

    def test_all_vector_files_exist(self):
        """All required test vector files must exist"""
        required_files = [
            "canonical.json", "identity.json",
            "events.json", "fork.json", "replay.json",
        ]
        for filename in required_files:
            self.assertTrue(
                (VECTORS_DIR / filename).exists(),
                f"Missing required test vector file: {filename}")

    def test_vector_files_are_valid_json(self):
        """All test vector files must be valid JSON with required structure"""
        for json_file in VECTORS_DIR.glob("*.json"):
            with open(json_file) as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError as e:
                    self.fail(f"{json_file.name} is not valid JSON: {e}")
            self.assertIn("description", data,
                f"{json_file.name} missing 'description' field")
            self.assertIn("tests", data,
                f"{json_file.name} missing 'tests' field")


if __name__ == "__main__":
    unittest.main(verbosity=2)
