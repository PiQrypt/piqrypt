"""
Tests for Agent-to-Agent (A2A) handshake protocol.
"""

import pytest
from aiss.a2a import (
    initiate_handshake,
    accept_handshake,
    reject_handshake,
    verify_handshake,
    PeerRegistry,
    A2AError
)
from aiss.crypto import ed25519
from aiss.identity import derive_agent_id


def test_handshake_flow():
    """Test complete handshake flow (initiate → accept → verify)."""
    # Generate identities
    priv_a, pub_a = ed25519.generate_keypair()
    priv_b, pub_b = ed25519.generate_keypair()
    
    agent_a = derive_agent_id(pub_a)
    agent_b = derive_agent_id(pub_b)
    
    # Agent A initiates
    handshake = initiate_handshake(
        priv_a,
        agent_a,
        agent_b,
        payload={"intent": "data_sharing", "scope": "analysis"}
    )
    
    assert handshake["version"] == "A2A-HANDSHAKE-1.0"
    assert handshake["initiator_agent_id"] == agent_a
    assert handshake["responder_agent_id"] == agent_b
    assert handshake["status"] == "pending"
    assert "signature_initiator" in handshake
    assert handshake["payload"]["intent"] == "data_sharing"
    
    # Agent B accepts
    response = accept_handshake(
        priv_b,
        agent_b,
        handshake,
        counter_payload={"agreed": True}
    )
    
    assert response["status"] == "accepted"
    assert "signature_responder" in response
    assert "accepted_at" in response
    assert response["counter_payload"]["agreed"] is True
    
    # Verify handshake
    is_valid = verify_handshake(response, {
        agent_a: pub_a,
        agent_b: pub_b
    })
    
    assert is_valid is True


def test_handshake_rejection():
    """Test handshake rejection flow."""
    priv_a, pub_a = ed25519.generate_keypair()
    priv_b, pub_b = ed25519.generate_keypair()
    
    agent_a = derive_agent_id(pub_a)
    agent_b = derive_agent_id(pub_b)
    
    # Agent A initiates
    handshake = initiate_handshake(priv_a, agent_a, agent_b)
    
    # Agent B rejects
    response = reject_handshake(
        priv_b,
        agent_b,
        handshake,
        reason="Policy violation"
    )
    
    assert response["status"] == "rejected"
    assert response["rejection_reason"] == "Policy violation"
    assert "signature_responder" in response
    
    # Verify rejection
    is_valid = verify_handshake(response, {agent_a: pub_a, agent_b: pub_b})
    assert is_valid is True


def test_handshake_wrong_responder():
    """Test error when handshake sent to wrong agent."""
    priv_a, pub_a = ed25519.generate_keypair()
    priv_b, pub_b = ed25519.generate_keypair()
    priv_c, pub_c = ed25519.generate_keypair()
    
    agent_a = derive_agent_id(pub_a)
    agent_b = derive_agent_id(pub_b)
    agent_c = derive_agent_id(pub_c)
    
    # Agent A → Agent B handshake
    handshake = initiate_handshake(priv_a, agent_a, agent_b)
    
    # Agent C tries to accept (should fail)
    with pytest.raises(A2AError, match="not for this agent"):
        accept_handshake(priv_c, agent_c, handshake)


def test_peer_registry():
    """Test peer discovery registry."""
    registry = PeerRegistry()
    
    # Register agents
    priv_a, pub_a = ed25519.generate_keypair()
    priv_b, pub_b = ed25519.generate_keypair()
    
    agent_a = derive_agent_id(pub_a)
    agent_b = derive_agent_id(pub_b)
    
    registry.register(agent_a, pub_a, metadata={"role": "trading_bot"})
    registry.register(agent_b, pub_b, metadata={"role": "analysis_bot"})
    
    # Discover all peers
    peers = registry.discover()
    assert len(peers) == 2
    assert any(p["agent_id"] == agent_a for p in peers)
    assert any(p["agent_id"] == agent_b for p in peers)
    
    # Discover specific peer
    peer_a = registry.discover(agent_a)
    assert len(peer_a) == 1
    assert peer_a[0]["agent_id"] == agent_a
    assert peer_a[0]["metadata"]["role"] == "trading_bot"
    
    # Get public key
    pub_key = registry.get_public_key(agent_a)
    assert pub_key == pub_a


def test_handshake_expiration():
    """Test handshake expiration."""
    import time
    
    priv_a, pub_a = ed25519.generate_keypair()
    priv_b, pub_b = ed25519.generate_keypair()
    
    agent_a = derive_agent_id(pub_a)
    agent_b = derive_agent_id(pub_b)
    
    # Create handshake that expires in 1 second
    handshake = initiate_handshake(
        priv_a,
        agent_a,
        agent_b,
        expires_in=1
    )
    
    # Wait for expiration
    time.sleep(2)
    
    # Try to accept (should fail)
    with pytest.raises(A2AError, match="expired"):
        accept_handshake(priv_b, agent_b, handshake)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
