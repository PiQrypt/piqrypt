Integration tests for complete AISS workflow

Tests the full RFC-compliant workflow:
1. Identity generation
2. Event stamping
3. Chain building
4. Verification
5. Fork detection
6. Replay detection
7. Audit export
"""

import pytest
from aiss import (
    generate_keypair,
    derive_agent_id,
    export_identity,
    stamp_event,
    stamp_genesis_event,
    verify_signature,
    verify_chain,
    export_audit_chain,
    InvalidSignatureError,
    ForkDetected,
    ReplayAttackDetected,
)
from aiss.chain import compute_event_hash, append_event
from aiss.fork import find_forks
from aiss.replay import detect_replay_attacks


class TestIdentityGeneration:
    """Test RFC Section 5-6: Agent Identity"""
    
    def test_generate_keypair(self):
        """Keypair generation uses CSPRNG"""
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        
        assert len(priv1) == 32
        assert len(pub1) == 32
        assert priv1 != priv2  # Randomness
        assert pub1 != pub2
    
    def test_agent_id_derivation(self):
        """Agent ID is deterministic from public key (RFC 5.1)"""
        _, public_key = generate_keypair()
        
        agent_id1 = derive_agent_id(public_key)
        agent_id2 = derive_agent_id(public_key)
        
        assert agent_id1 == agent_id2
        assert len(agent_id1) == 32  # 32 chars as per RFC
    
    def test_identity_export(self):
        """Identity document conforms to RFC Section 6.1"""
        priv, pub = generate_keypair()
        agent_id = derive_agent_id(pub)
        
        identity = export_identity(agent_id, pub)
        
        assert identity['version'] == 'AISS-1.0'
        assert identity['agent_id'] == agent_id
        assert identity['algorithm'] == 'Ed25519'
        assert 'public_key' in identity
        assert 'created_at' in identity


class TestEventStamping:
    """Test RFC Section 7: Event Stamping"""
    
    def test_stamp_event(self):
        """Event stamping creates valid structure"""
        priv, pub = generate_keypair()
        agent_id = derive_agent_id(pub)
        
        event = stamp_event(
            priv, agent_id,
            {"action": "test", "value": 42},
            previous_hash=None
        )
        
        assert event['version'] == 'AISS-1.0'
        assert event['agent_id'] == agent_id
        assert 'timestamp' in event
        assert 'nonce' in event
        assert event['payload']['action'] == 'test'
        assert 'signature' in event
    
    def test_genesis_event(self):
        """Genesis event has special previous_hash (RFC 9.3)"""
        priv, pub = generate_keypair()
        agent_id = derive_agent_id(pub)
        
        genesis = stamp_genesis_event(priv, pub, agent_id, {"init": True})
        
        # previous_hash should be SHA256(public_key)
        from aiss.canonical import hash_bytes
        expected_hash = hash_bytes(pub)
        assert genesis['previous_hash'] == expected_hash


class TestSignatureVerification:
    """Test RFC Section 7.2: Signature Verification"""
    
    def test_valid_signature(self):
        """Valid signatures verify correctly"""
        priv, pub = generate_keypair()
        agent_id = derive_agent_id(pub)
        
        event = stamp_event(priv, agent_id, {"test": 1})
        
        # Should not raise
        assert verify_signature(event, pub)
    
    def test_invalid_signature(self):
        """Tampered events fail verification"""
        priv, pub = generate_keypair()
        agent_id = derive_agent_id(pub)
        
        event = stamp_event(priv, agent_id, {"test": 1})
        
        # Tamper with payload
        event['payload']['test'] = 2
        
        with pytest.raises(InvalidSignatureError):
            verify_signature(event, pub)


class TestHashChain:
    """Test RFC Section 9: Hash Chain"""
    
    def test_chain_linkage(self):
        """Events link via previous_hash"""
        priv, pub = generate_keypair()
        agent_id = derive_agent_id(pub)
        
        # Genesis
        event1 = stamp_genesis_event(priv, pub, agent_id, {"seq": 1})
        hash1 = compute_event_hash(event1)
        
        # Second event
        event2 = stamp_event(priv, agent_id, {"seq": 2}, previous_hash=hash1)
        
        assert event2['previous_hash'] == hash1
    
    def test_chain_verification(self):
        """Complete chain verifies correctly"""
        priv, pub = generate_keypair()
        agent_id = derive_agent_id(pub)
        identity = export_identity(agent_id, pub)
        
        # Build chain
        events = []
        genesis = stamp_genesis_event(priv, pub, agent_id, {"seq": 0})
        events.append(genesis)
        
        for i in range(1, 5):
            prev_hash = compute_event_hash(events[-1])
            event = stamp_event(priv, agent_id, {"seq": i}, previous_hash=prev_hash)
            events.append(event)
        
        # Verify chain
        assert verify_chain(events, identity)


class TestForkDetection:
    """Test RFC Section 10: Fork Detection"""
    
    def test_fork_detection(self):
        """Forks are detected correctly"""
        priv, pub = generate_keypair()
        agent_id = derive_agent_id(pub)
        
        # Create fork: two events with same previous_hash
        genesis = stamp_genesis_event(priv, pub, agent_id, {"init": True})
        genesis_hash = compute_event_hash(genesis)
        
        fork_a = stamp_event(priv, agent_id, {"branch": "A"}, previous_hash=genesis_hash)
        fork_b = stamp_event(priv, agent_id, {"branch": "B"}, previous_hash=genesis_hash)
        
        events = [genesis, fork_a, fork_b]
        forks = find_forks(events)
        
        assert len(forks) == 1
        assert forks[0].hash == genesis_hash
        assert len(forks[0].events) == 2


class TestReplayDetection:
    """Test RFC Section 11: Anti-Replay"""
    
    def test_replay_detection(self):
        """Duplicate nonces are detected"""
        priv, pub = generate_keypair()
        agent_id = derive_agent_id(pub)
        
        # Create event with specific nonce
        event1 = stamp_event(priv, agent_id, {"seq": 1}, nonce="nonce-1")
        event2 = stamp_event(priv, agent_id, {"seq": 2}, nonce="nonce-1")  # Duplicate
        
        attacks = detect_replay_attacks([event1, event2])
        
        assert len(attacks) == 1
        assert attacks[0].nonce == "nonce-1"


class TestAuditExport:
    """Test RFC Section 15: Audit Export"""
    
    def test_audit_export(self):
        """Audit export conforms to RFC"""
        priv, pub = generate_keypair()
        agent_id = derive_agent_id(pub)
        identity = export_identity(agent_id, pub)
        
        # Build small chain
        events = []
        genesis = stamp_genesis_event(priv, pub, agent_id, {"init": True})
        events.append(genesis)
        
        for i in range(3):
            prev_hash = compute_event_hash(events[-1])
            event = stamp_event(priv, agent_id, {"seq": i}, previous_hash=prev_hash)
            events.append(event)
        
        # Export
        audit = export_audit_chain(identity, events)
        
        assert audit['spec'] == 'AISS-1.0-AUDIT'
        assert audit['agent_identity'] == identity
        assert len(audit['events']) == 4
        assert 'chain_integrity_hash' in audit
        assert 'exported_at' in audit
