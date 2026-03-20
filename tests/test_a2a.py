# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests for Agent-to-Agent (A2A) handshake protocol.

Tests use the actual aiss.a2a API:
  - create_identity_proposal / verify_identity_proposal
  - create_identity_response / verify_identity_response
  - create_session_confirmation
  - build_cosigned_handshake_event
  - perform_handshake
  - register_peer / get_peer / list_peers
  - compute_trust_score
  - A2AHandshakeError
"""

import pytest
from aiss.a2a import (
    create_identity_proposal,
    verify_identity_proposal,
    create_identity_response,
    verify_identity_response,
    create_session_confirmation,
    build_cosigned_handshake_event,
    perform_handshake,
    register_peer,
    get_peer,
    list_peers,
    compute_trust_score,
    A2AHandshakeError,
)
from aiss.crypto import ed25519
from aiss.identity import derive_agent_id


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_agent():
    """Return (private_key, public_key, agent_id) tuple."""
    priv, pub = ed25519.generate_keypair()
    agent_id = derive_agent_id(pub)
    return priv, pub, agent_id


# ─── Proposal creation & verification ────────────────────────────────────────

class TestIdentityProposal:
    """Test proposal creation and verification (Step 1 of handshake)."""

    def test_create_proposal_structure(self):
        """Proposal contains required fields and valid signature."""
        priv, pub, agent_id = make_agent()
        proposal = create_identity_proposal(priv, pub, agent_id)

        assert proposal["version"] == "AISS-1.0"
        assert proposal["message_type"] == "a2a_identity_proposal"
        assert proposal["agent_id"] == agent_id
        assert "public_key" in proposal
        assert "session_nonce" in proposal
        assert "timestamp" in proposal
        assert "signature" in proposal

    def test_create_proposal_with_capabilities(self):
        """Custom capabilities are included in proposal."""
        priv, pub, agent_id = make_agent()
        caps = ["stamp", "verify", "delegate"]
        proposal = create_identity_proposal(priv, pub, agent_id, capabilities=caps)

        assert proposal["capabilities"] == caps

    def test_create_proposal_default_capabilities(self):
        """Default capabilities are assigned when none provided."""
        priv, pub, agent_id = make_agent()
        proposal = create_identity_proposal(priv, pub, agent_id)

        assert len(proposal["capabilities"]) > 0

    def test_verify_valid_proposal(self):
        """Valid proposal passes verification."""
        priv, pub, agent_id = make_agent()
        proposal = create_identity_proposal(priv, pub, agent_id)

        assert verify_identity_proposal(proposal) is True

    def test_verify_tampered_proposal_fails(self):
        """Tampered proposal raises A2AHandshakeError."""
        priv, pub, agent_id = make_agent()
        proposal = create_identity_proposal(priv, pub, agent_id)

        # Tamper with a field (not signature itself)
        proposal["timestamp"] = 0

        with pytest.raises(A2AHandshakeError):
            verify_identity_proposal(proposal)

    def test_verify_wrong_agent_id_fails(self):
        """Proposal with mismatched agent_id raises A2AHandshakeError."""
        priv_a, pub_a, agent_a = make_agent()
        _, _, agent_b = make_agent()

        proposal = create_identity_proposal(priv_a, pub_a, agent_a)
        proposal["agent_id"] = agent_b  # Inject wrong ID (also invalidates sig)

        with pytest.raises(A2AHandshakeError):
            verify_identity_proposal(proposal)


# ─── Identity response ────────────────────────────────────────────────────────

class TestIdentityResponse:
    """Test response creation and verification (Step 2 of handshake)."""

    def test_create_response_structure(self):
        """Response contains required fields."""
        priv_a, pub_a, agent_a = make_agent()
        priv_b, pub_b, agent_b = make_agent()

        proposal = create_identity_proposal(priv_a, pub_a, agent_a)
        response = create_identity_response(priv_b, pub_b, agent_b, proposal)

        assert response["version"] == "AISS-1.0"
        assert response["message_type"] == "a2a_identity_response"
        assert response["agent_id"] == agent_b
        assert response["peer_agent_id"] == agent_a
        assert "session_id" in response
        assert "proposal_hash" in response
        assert "signature" in response
        assert response["accepted"] is True

    def test_response_echoes_nonce(self):
        """Response echoes the session_nonce from proposal."""
        priv_a, pub_a, agent_a = make_agent()
        priv_b, pub_b, agent_b = make_agent()

        proposal = create_identity_proposal(priv_a, pub_a, agent_a)
        response = create_identity_response(priv_b, pub_b, agent_b, proposal)

        assert response["session_nonce"] == proposal["session_nonce"]

    def test_verify_valid_response(self):
        """Valid response passes verification."""
        priv_a, pub_a, agent_a = make_agent()
        priv_b, pub_b, agent_b = make_agent()

        proposal = create_identity_proposal(priv_a, pub_a, agent_a)
        response = create_identity_response(priv_b, pub_b, agent_b, proposal)

        assert verify_identity_response(response, proposal) is True

    def test_verify_response_nonce_mismatch_fails(self):
        """Response verified against a different proposal raises A2AHandshakeError."""
        priv_a, pub_a, agent_a = make_agent()
        priv_b, pub_b, agent_b = make_agent()
        priv_c, pub_c, agent_c = make_agent()

        proposal_a = create_identity_proposal(priv_a, pub_a, agent_a)
        response = create_identity_response(priv_b, pub_b, agent_b, proposal_a)

        # Different proposal (different nonce/hash)
        other_proposal = create_identity_proposal(priv_c, pub_c, agent_c)

        with pytest.raises(A2AHandshakeError):
            verify_identity_response(response, other_proposal)


# ─── Session confirmation ─────────────────────────────────────────────────────

class TestSessionConfirmation:
    """Test Step 3: session confirmation by initiator."""

    def test_create_session_confirmation(self):
        """Confirmation contains required fields."""
        priv_a, pub_a, agent_a = make_agent()
        priv_b, pub_b, agent_b = make_agent()

        proposal = create_identity_proposal(priv_a, pub_a, agent_a)
        response = create_identity_response(priv_b, pub_b, agent_b, proposal)
        verify_identity_response(response, proposal)

        confirmation = create_session_confirmation(priv_a, agent_a, response)

        assert confirmation["message_type"] == "a2a_session_confirmation"
        assert confirmation["agent_id"] == agent_a
        assert confirmation["session_id"] == response["session_id"]
        assert "response_hash" in confirmation
        assert "signature" in confirmation


# ─── Co-signed event ──────────────────────────────────────────────────────────

class TestCosignedEvent:
    """Test co-signed handshake event building."""

    def test_build_cosigned_event_initiator_role(self):
        """Initiator's co-signed event has correct role."""
        priv_a, pub_a, agent_a = make_agent()
        priv_b, pub_b, agent_b = make_agent()

        proposal = create_identity_proposal(priv_a, pub_a, agent_a)
        response = create_identity_response(priv_b, pub_b, agent_b, proposal)

        event = build_cosigned_handshake_event(priv_a, agent_a, proposal, response)

        assert event["payload"]["event_type"] == "a2a_handshake"
        assert event["payload"]["my_role"] == "initiator"
        assert event["payload"]["peer_agent_id"] == agent_b
        assert "peer_signature" in event["payload"]
        assert "signature" in event

    def test_build_cosigned_event_responder_role(self):
        """Responder's co-signed event has correct role."""
        priv_a, pub_a, agent_a = make_agent()
        priv_b, pub_b, agent_b = make_agent()

        proposal = create_identity_proposal(priv_a, pub_a, agent_a)
        response = create_identity_response(priv_b, pub_b, agent_b, proposal)

        event = build_cosigned_handshake_event(priv_b, agent_b, proposal, response)

        assert event["payload"]["my_role"] == "responder"
        assert event["payload"]["peer_agent_id"] == agent_a


# ─── Full orchestration ───────────────────────────────────────────────────────

class TestFullHandshake:
    """Test perform_handshake orchestration (Agent B perspective)."""

    def test_perform_handshake_returns_expected_keys(self):
        """perform_handshake returns response, cosigned_event, session_id, peer_agent_id."""
        priv_a, pub_a, agent_a = make_agent()
        priv_b, pub_b, agent_b = make_agent()

        proposal = create_identity_proposal(priv_a, pub_a, agent_a)

        result = perform_handshake(
            my_private_key=priv_b,
            my_public_key=pub_b,
            my_agent_id=agent_b,
            peer_proposal=proposal,
            store_in_memory=False,
        )

        assert "response" in result
        assert "cosigned_event" in result
        assert "session_id" in result
        assert "peer_agent_id" in result
        assert result["peer_agent_id"] == agent_a

    def test_perform_handshake_response_is_valid(self):
        """Response produced by perform_handshake verifies successfully."""
        priv_a, pub_a, agent_a = make_agent()
        priv_b, pub_b, agent_b = make_agent()

        proposal = create_identity_proposal(priv_a, pub_a, agent_a)
        result = perform_handshake(
            priv_b, pub_b, agent_b, proposal, store_in_memory=False
        )

        assert verify_identity_response(result["response"], proposal) is True

    def test_perform_handshake_rejects_invalid_proposal(self):
        """perform_handshake rejects a tampered proposal."""
        priv_a, pub_a, agent_a = make_agent()
        priv_b, pub_b, agent_b = make_agent()

        proposal = create_identity_proposal(priv_a, pub_a, agent_a)
        proposal["timestamp"] = 0  # Tamper

        with pytest.raises(A2AHandshakeError):
            perform_handshake(priv_b, pub_b, agent_b, proposal, store_in_memory=False)


# ─── Peer registry ────────────────────────────────────────────────────────────

class TestPeerRegistry:
    """Test peer registry: register_peer, get_peer, list_peers."""

    def test_register_and_retrieve_peer(self):
        """Registered peer can be retrieved by agent_id."""
        _, pub, agent_id = make_agent()
        identity = {
            "version": "AISS-1.0",
            "agent_id": agent_id,
            "public_key": ed25519.encode_base58(pub),
            "algorithm": "Ed25519",
            "capabilities": ["stamp"],
        }
        register_peer(identity)
        peer = get_peer(agent_id)

        assert peer is not None
        assert peer["identity"]["agent_id"] == agent_id

    def test_list_peers_includes_registered(self):
        """Registered peer appears in list_peers."""
        _, pub, agent_id = make_agent()
        identity = {
            "version": "AISS-1.0",
            "agent_id": agent_id,
            "public_key": ed25519.encode_base58(pub),
            "algorithm": "Ed25519",
            "capabilities": [],
        }
        register_peer(identity)
        peers = list_peers()

        assert any(p["agent_id"] == agent_id for p in peers)

    def test_unknown_peer_returns_none(self):
        """get_peer returns None for unknown agent_id."""
        result = get_peer("nonexistent-agent-000000000000000")
        assert result is None


# ─── Trust Score ──────────────────────────────────────────────────────────────

class TestTrustScore:
    """Test compute_trust_score."""

    def test_empty_events_returns_elite_score(self):
        """No events → trust score 1.0, tier 'Elite' (new agent)."""
        _, _, agent_id = make_agent()
        result = compute_trust_score(agent_id, events=[])

        assert result["trust_score"] == 1.0
        assert result["tier"] == "Elite"
        assert result["event_count"] == 0

    def test_score_components_present(self):
        """Result contains all expected keys."""
        _, _, agent_id = make_agent()
        result = compute_trust_score(agent_id, events=[])

        assert "agent_id" in result
        assert "trust_score" in result
        assert "tier" in result
        assert "components" in result

    def test_score_with_valid_events(self):
        """Valid events yield a trust score within [0, 1]."""
        from aiss.stamp import stamp_event, stamp_genesis_event
        from aiss.chain import compute_event_hash

        priv, pub, agent_id = make_agent()
        events = [stamp_genesis_event(priv, pub, agent_id, {"init": True})]
        for i in range(4):
            prev_hash = compute_event_hash(events[-1])
            events.append(stamp_event(priv, agent_id, {"seq": i}, previous_hash=prev_hash))

        result = compute_trust_score(agent_id, events=events)

        assert 0.0 <= result["trust_score"] <= 1.0
        assert result["event_count"] == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
