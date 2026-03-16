# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
Agent-to-Agent (A2A) Interaction Protocol (RFC Section 16)

Implements the full A2A handshake:
  1. Identity exchange (public keys + capabilities)
  2. Mutual signature verification
  3. Co-signed session establishment
  4. PCP event recording in both agent chains
  5. Graceful fallback when peer doesn't have PiQrypt

Free:  A2A local (same machine), plaintext events
Pro:   A2A network (remote agents), encrypted events, trust scoring

Trust Score formula (RFC Section 16.5):
  T = w1·S + w2·C + w3·X + w4·R + w5·A
"""

import time
import uuid
import json
import math
from typing import Dict, Any, Optional, List
from pathlib import Path

from aiss.crypto import ed25519
from aiss.canonical import canonicalize, hash_bytes
from aiss.exceptions import PiQryptError, InvalidSignatureError
from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Exceptions ───────────────────────────────────────────────────────────────
class A2AHandshakeError(PiQryptError):
    """Handshake failed — identity mismatch or signature invalid."""
    pass


class A2APeerNotFound(PiQryptError):
    """Peer agent identity not found in local registry."""
    pass


class A2ATrustError(PiQryptError):
    """Peer trust score too low for requested operation."""
    pass


# ─── Peer registry (local, persisted) ────────────────────────────────────────
def _registry_path() -> Path:
    from aiss.memory import PIQRYPT_DIR
    return PIQRYPT_DIR / "peers.json"


def _load_registry() -> Dict[str, Any]:
    p = _registry_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save_registry(registry: Dict[str, Any]) -> None:
    p = _registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(registry, indent=2))


def register_peer(peer_identity: Dict[str, Any]) -> None:
    """
    Store peer agent identity in local registry.

    Args:
        peer_identity: AISS identity document from peer
    """
    registry = _load_registry()
    agent_id = peer_identity["agent_id"]

    registry[agent_id] = {
        "identity": peer_identity,
        "first_seen": int(time.time()),
        "last_seen": int(time.time()),
        "interaction_count": registry.get(agent_id, {}).get("interaction_count", 0) + 1,
        "trust_score": registry.get(agent_id, {}).get("trust_score", 1.0),
    }
    _save_registry(registry)
    logger.info(f"Peer registered: {agent_id[:16]}...")


def get_peer(agent_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve peer identity from local registry."""
    registry = _load_registry()
    return registry.get(agent_id)


def list_peers() -> List[Dict[str, Any]]:
    """List all known peers with metadata."""
    registry = _load_registry()
    result = []
    for agent_id, data in registry.items():
        result.append({
            "agent_id": agent_id,
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "interaction_count": data.get("interaction_count", 0),
            "trust_score": data.get("trust_score", 1.0),
            "algorithm": data.get("identity", {}).get("algorithm", "Ed25519"),
        })
    return sorted(result, key=lambda x: x.get("last_seen", 0), reverse=True)


# ─── Handshake protocol ───────────────────────────────────────────────────────
def create_identity_proposal(
    private_key: bytes,
    public_key: bytes,
    agent_id: str,
    capabilities: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Step 1 — Create handshake proposal (sent by initiator Agent A).

    Structure:
        {
          "version": "AISS-1.0",
          "message_type": "a2a_identity_proposal",
          "agent_id": "...",
          "public_key": "...",
          "capabilities": [...],
          "session_nonce": "uuid-v4",
          "timestamp": 1234567890,
          "signature": "..."   ← signs all above fields
        }

    Args:
        private_key: Agent A's Ed25519 private key
        public_key:  Agent A's Ed25519 public key
        agent_id:    Agent A's derived ID
        capabilities: What this agent can do
        metadata:    Optional additional info

    Returns:
        Signed identity proposal dict
    """
    session_nonce = str(uuid.uuid4())
    caps = capabilities or ["stamp", "verify", "a2a"]

    proposal = {
        "version": "AISS-1.0",
        "message_type": "a2a_identity_proposal",
        "agent_id": agent_id,
        "public_key": ed25519.encode_base58(public_key),
        "capabilities": caps,
        "session_nonce": session_nonce,
        "timestamp": int(time.time()),
    }

    if metadata:
        proposal["metadata"] = metadata

    # Sign the proposal (excluding signature field)
    canonical = canonicalize(proposal)
    signature = ed25519.sign(private_key, canonical)
    proposal["signature"] = ed25519.encode_base58(signature)

    logger.info("A2A identity proposal created")

    return proposal


def verify_identity_proposal(proposal: Dict[str, Any]) -> bool:
    """
    Verify signature on incoming identity proposal.

    Args:
        proposal: Received identity proposal from peer

    Returns:
        True if signature valid

    Raises:
        A2AHandshakeError: If signature invalid
    """
    try:
        signature_b58 = proposal.get("signature")
        if not signature_b58:
            raise A2AHandshakeError("Proposal missing signature")

        public_key_b58 = proposal.get("public_key")
        if not public_key_b58:
            raise A2AHandshakeError("Proposal missing public_key")

        signature = ed25519.decode_base58(signature_b58)
        public_key = ed25519.decode_base58(public_key_b58)

        # Verify agent_id derives from public_key
        from aiss.identity import derive_agent_id
        expected_id = derive_agent_id(public_key)
        if expected_id != proposal.get("agent_id"):
            raise A2AHandshakeError(
                f"agent_id mismatch: expected {expected_id[:16]}, "
                f"got {proposal.get('agent_id', '')[:16]}"
            )

        # Verify signature over canonical proposal (without signature field)
        proposal_copy = {k: v for k, v in proposal.items() if k != "signature"}
        canonical = canonicalize(proposal_copy)

        if not ed25519.verify(public_key, canonical, signature):
            raise A2AHandshakeError("Invalid signature on identity proposal")

        logger.info("A2A proposal verified")
        return True

    except (InvalidSignatureError, ValueError) as e:
        raise A2AHandshakeError(f"Proposal verification failed: {e}")


def create_identity_response(
    private_key: bytes,
    public_key: bytes,
    agent_id: str,
    proposal: Dict[str, Any],
    capabilities: Optional[List[str]] = None,
    accepted: bool = True
) -> Dict[str, Any]:
    """
    Step 2 — Create handshake response (sent by responder Agent B).

    Includes signature over Agent A's proposal to prove B received it.

    Args:
        private_key:   Agent B's private key
        public_key:    Agent B's public key
        agent_id:      Agent B's ID
        proposal:      Agent A's proposal (already verified)
        capabilities:  Agent B's capabilities
        accepted:      Whether to accept the handshake

    Returns:
        Signed identity response dict
    """
    # First verify the incoming proposal
    verify_identity_proposal(proposal)

    session_id = str(uuid.uuid4())
    caps = capabilities or ["stamp", "verify", "a2a"]

    # Hash of A's proposal (proves B received exactly this proposal)
    proposal_canonical = canonicalize(
        {k: v for k, v in proposal.items() if k != "signature"}
    )
    proposal_hash = hash_bytes(proposal_canonical)

    response = {
        "version": "AISS-1.0",
        "message_type": "a2a_identity_response",
        "agent_id": agent_id,
        "public_key": ed25519.encode_base58(public_key),
        "capabilities": caps,
        "session_id": session_id,
        "session_nonce": proposal.get("session_nonce"),  # Echo back
        "proposal_hash": proposal_hash,                 # Binds to A's proposal
        "accepted": accepted,
        "timestamp": int(time.time()),
        "peer_agent_id": proposal.get("agent_id"),
    }

    # Sign response
    canonical = canonicalize(response)
    signature = ed25519.sign(private_key, canonical)
    response["signature"] = ed25519.encode_base58(signature)

    logger.info("A2A identity response created")

    return response


def verify_identity_response(
    response: Dict[str, Any],
    original_proposal: Dict[str, Any]
) -> bool:
    """
    Verify Agent B's response (called by Agent A after receiving response).

    Validates:
    - B's signature
    - B's agent_id derives from B's public_key
    - proposal_hash matches our original proposal
    - session_nonce matches our original nonce

    Args:
        response: Agent B's response
        original_proposal: Agent A's original proposal (without signature)

    Returns:
        True if all checks pass

    Raises:
        A2AHandshakeError: If any check fails
    """
    try:
        # Verify B's signature
        signature_b58 = response.get("signature")
        public_key_b58 = response.get("public_key")

        if not signature_b58 or not public_key_b58:
            raise A2AHandshakeError("Response missing signature or public_key")

        signature = ed25519.decode_base58(signature_b58)
        public_key = ed25519.decode_base58(public_key_b58)

        # Verify agent_id derivation
        from aiss.identity import derive_agent_id
        expected_id = derive_agent_id(public_key)
        if expected_id != response.get("agent_id"):
            raise A2AHandshakeError("Response agent_id does not match public_key")

        # Verify response signature
        response_copy = {k: v for k, v in response.items() if k != "signature"}
        canonical = canonicalize(response_copy)
        if not ed25519.verify(public_key, canonical, signature):
            raise A2AHandshakeError("Invalid signature on identity response")

        # Verify proposal binding (nonce echo + hash)
        if response.get("session_nonce") != original_proposal.get("session_nonce"):
            raise A2AHandshakeError("Session nonce mismatch — possible replay")

        proposal_copy = {k: v for k, v in original_proposal.items() if k != "signature"}
        expected_hash = hash_bytes(canonicalize(proposal_copy))
        if response.get("proposal_hash") != expected_hash:
            raise A2AHandshakeError("Proposal hash mismatch — tampered response")

        logger.info("A2A response verified")
        return True

    except (InvalidSignatureError, ValueError) as e:
        raise A2AHandshakeError(f"Response verification failed: {e}")


def create_session_confirmation(
    private_key: bytes,
    agent_id: str,
    response: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Step 3 — Agent A confirms the session (final handshake message).

    Args:
        private_key: Agent A's private key
        agent_id: Agent A's ID
        response: Agent B's verified response

    Returns:
        Signed session confirmation
    """
    response_canonical = canonicalize(
        {k: v for k, v in response.items() if k != "signature"}
    )
    response_hash = hash_bytes(response_canonical)

    confirmation = {
        "version": "AISS-1.0",
        "message_type": "a2a_session_confirmation",
        "agent_id": agent_id,
        "session_id": response.get("session_id"),
        "response_hash": response_hash,
        "timestamp": int(time.time()),
        "peer_agent_id": response.get("agent_id"),
    }

    canonical = canonicalize(confirmation)
    signature = ed25519.sign(private_key, canonical)
    confirmation["signature"] = ed25519.encode_base58(signature)

    return confirmation


def build_cosigned_handshake_event(
    my_private_key: bytes,
    my_agent_id: str,
    proposal: Dict[str, Any],
    response: Dict[str, Any],
    previous_hash: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build the co-signed PCP event recorded in BOTH agent chains after handshake.

    This event proves:
    - Both agents mutually identified each other
    - Both signatures are present (non-repudiation)
    - Exact timestamp of handshake

    The event is signed by MY key; the peer's signature is embedded from
    the response (which is their signature over the proposal).

    Args:
        my_private_key: Signing agent's private key
        my_agent_id: Signing agent's ID
        proposal: Agent A's identity proposal (with A's signature)
        response: Agent B's identity response (with B's signature)
        previous_hash: Hash of previous event in my chain

    Returns:
        Co-signed A2A handshake event for insertion into PCP chain
    """
    from aiss.stamp import generate_nonce

    session_id = response.get("session_id", str(uuid.uuid4()))
    peer_id = (
        response.get("agent_id") if response.get("agent_id") != my_agent_id
        else proposal.get("agent_id")
    )

    # Determine my role (initiator or responder)
    if proposal.get("agent_id") == my_agent_id:
        my_role = "initiator"
        peer_signature_field = response.get("signature")  # B's sig
    else:
        my_role = "responder"
        peer_signature_field = proposal.get("signature")  # A's sig

    payload = {
        "event_type": "a2a_handshake",
        "session_id": session_id,
        "my_role": my_role,
        "peer_agent_id": peer_id,
        "peer_signature": peer_signature_field,  # Peer's sig embedded
        "capabilities_agreed": list(
            set(proposal.get("capabilities", [])) &
            set(response.get("capabilities", []))
        ),
        "participants": [my_agent_id, peer_id],
    }

    event = {
        "version": "AISS-1.0",
        "agent_id": my_agent_id,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": payload,
        "previous_hash": previous_hash or "genesis",
    }

    # Sign the event
    event_copy = {k: v for k, v in event.items()}
    canonical = canonicalize(event_copy)
    signature = ed25519.sign(my_private_key, canonical)
    event["signature"] = ed25519.encode_base58(signature)

    logger.info("Co-signed handshake event created")

    return event


# ─── Full handshake orchestration ────────────────────────────────────────────
def perform_handshake(
    my_private_key: bytes,
    my_public_key: bytes,
    my_agent_id: str,
    peer_proposal: Dict[str, Any],
    my_capabilities: Optional[List[str]] = None,
    previous_hash: Optional[str] = None,
    store_in_memory: bool = True
) -> Dict[str, Any]:
    """
    Complete A2A handshake from Agent B's perspective (responding to proposal).

    Flow:
        1. Verify peer's proposal
        2. Create response
        3. Build co-signed PCP event
        4. Store in memory (both free and pro)
        5. Register peer in local registry

    Args:
        my_private_key: This agent's private key
        my_public_key: This agent's public key
        my_agent_id: This agent's ID
        peer_proposal: Incoming proposal from Agent A (already received)
        my_capabilities: What this agent can do
        previous_hash: Hash of previous event in this agent's chain
        store_in_memory: Whether to auto-store in PCP chain

    Returns:
        Dict with: response, cosigned_event, session_id
    """
    # Step 1: Verify proposal
    verify_identity_proposal(peer_proposal)

    # Step 2: Build response
    response = create_identity_response(
        my_private_key, my_public_key, my_agent_id,
        peer_proposal, my_capabilities
    )

    # Step 3: Build co-signed event
    event = build_cosigned_handshake_event(
        my_private_key, my_agent_id,
        peer_proposal, response,
        previous_hash
    )

    # Step 4: Store in memory
    if store_in_memory:
        from aiss.memory import store_event
        store_event(event)

        # Register peer
        peer_identity = {
            "version": peer_proposal.get("version", "AISS-1.0"),
            "agent_id": peer_proposal.get("agent_id"),
            "public_key": peer_proposal.get("public_key"),
            "algorithm": "Ed25519",
            "capabilities": peer_proposal.get("capabilities", []),
        }
        register_peer(peer_identity)

    logger.info("A2A handshake complete")

    return {
        "response": response,
        "cosigned_event": event,
        "session_id": response.get("session_id"),
        "peer_agent_id": peer_proposal.get("agent_id"),
    }


# ─── Fallback: interaction with non-PiQrypt peer ─────────────────────────────
def record_external_interaction(
    private_key: bytes,
    agent_id: str,
    peer_identifier: str,
    interaction_data: Dict[str, Any],
    previous_hash: Optional[str] = None,
    store_in_memory: bool = True
) -> Dict[str, Any]:
    """
    Record interaction with a peer that doesn't have PiQrypt installed.

    RFC Section 16.4 — Fallback protocol.
    The interaction is recorded unilaterally in the AISS agent's chain.

    The event includes a note that the peer doesn't implement AISS,
    and a hash of the interaction data for integrity proof.

    Args:
        private_key: This agent's private key
        agent_id: This agent's ID
        peer_identifier: Any identifier for the non-AISS peer
        interaction_data: The interaction content (will be hashed)
        previous_hash: Hash of previous event in chain
        store_in_memory: Whether to auto-store

    Returns:
        Signed interaction event
    """
    from aiss.stamp import generate_nonce
    from aiss.canonical import hash_bytes

    # Hash the interaction data (don't store raw if sensitive)
    interaction_json = json.dumps(interaction_data, sort_keys=True)
    interaction_hash = hash_bytes(interaction_json.encode())

    payload = {
        "event_type": "external_interaction",
        "peer_identifier": peer_identifier,
        "piqrypt_available": False,
        "interaction_hash": interaction_hash,
        "note": "Peer does not implement AISS. Interaction recorded unilaterally.",
    }

    event = {
        "version": "AISS-1.0",
        "agent_id": agent_id,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": payload,
        "previous_hash": previous_hash or "genesis",
    }

    canonical = canonicalize(event)
    signature = ed25519.sign(private_key, canonical)
    event["signature"] = ed25519.encode_base58(signature)

    if store_in_memory:
        from aiss.memory import store_event
        store_event(event)

    logger.pro_hint(
        f"Peer '{peer_identifier[:20]}' does not use PiQrypt — "
        "interaction recorded unilaterally (no mutual verification)"
    )

    return event


# ─── Trust Score (RFC Section 16.5) ──────────────────────────────────────────

def compute_trust_score(
    agent_id: str,
    events: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Compute Trust Score T for an agent.

    T = w1·S + w2·C + w3·X + w4·R + w5·A

    S = Signature Integrity  = valid_sigs / total_sigs
    C = Chain Stability      = 1 - (fork_events / total_events)
    X = Cross-Agent Validation = cross_validated / total_external
    R = Replay Resistance    = 1 - (replay_attempts / total_events)
    A = Anomaly Stability    = e^(-k * anomaly_rate)

    Args:
        agent_id: Agent to score
        events: Events to analyze (loads from memory if None)

    Returns:
        Dict with score, components, tier
    """
    if events is None:
        from aiss.memory import load_events
        events = load_events(agent_id=agent_id)

    if not events:
        return {
            "agent_id": agent_id,
            "trust_score": 1.0,
            "tier": "Elite",
            "components": {},
            "event_count": 0,
            "note": "No events — new agent"
        }

    total = len(events)

    # S: Signature integrity
    valid_sigs = 0
    sig_errors = 0
    for e in events:
        if e.get("signature"):
            valid_sigs += 1
        else:
            sig_errors += 1
    S = valid_sigs / total if total > 0 else 1.0

    # C: Chain stability (fork events)
    prev_hashes = [e.get("previous_hash") for e in events if e.get("previous_hash")]
    fork_events = len(prev_hashes) - len(set(prev_hashes))
    fork_events = max(0, fork_events)
    C = 1.0 - (fork_events / total)
    C = max(0.0, C)

    # X: Cross-agent validation
    a2a_events = [
        e for e in events
        if e.get("payload", {}).get("event_type") in ("a2a_handshake", "a2a_message")
    ]
    validated_a2a = sum(
        1 for e in a2a_events
        if e.get("payload", {}).get("peer_signature")
    )
    X = validated_a2a / len(a2a_events) if a2a_events else 1.0

    # R: Replay resistance (nonce uniqueness)
    nonces = [e.get("nonce") for e in events if e.get("nonce")]
    duplicates = len(nonces) - len(set(nonces))
    R = 1.0 - (duplicates / total)
    R = max(0.0, R)

    # A: Anomaly stability
    anomalies = sig_errors + fork_events + duplicates
    anomaly_rate = anomalies / total
    k = 10.0  # sensitivity factor
    A = math.exp(-k * anomaly_rate)

    # Weighted sum
    w1, w2, w3, w4, w5 = 0.25, 0.20, 0.25, 0.15, 0.15
    T = w1 * S + w2 * C + w3 * X + w4 * R + w5 * A
    T = round(min(1.0, max(0.0, T)), 4)

    # Tier
    if T > 0.95:
        tier = "Elite"
    elif T >= 0.90:
        tier = "A+"
    elif T >= 0.80:
        tier = "A"
    elif T >= 0.70:
        tier = "B"
    else:
        tier = "At Risk"

    return {
        "agent_id": agent_id,
        "trust_score": T,
        "tier": tier,
        "components": {
            "S_signature_integrity": round(S, 4),
            "C_chain_stability": round(C, 4),
            "X_cross_agent_validation": round(X, 4),
            "R_replay_resistance": round(R, 4),
            "A_anomaly_stability": round(A, 4),
        },
        "event_count": total,
        "a2a_interactions": len(a2a_events),
    }


def update_peer_trust_score(agent_id: str) -> Optional[float]:
    """
    Recompute and persist trust score for a peer agent.

    Args:
        agent_id: Peer agent ID to update

    Returns:
        New trust score, or None if peer not found
    """
    registry = _load_registry()
    if agent_id not in registry:
        return None

    from aiss.memory import load_events
    events = load_events(agent_id=agent_id)
    result = compute_trust_score(agent_id, events)

    registry[agent_id]["trust_score"] = result["trust_score"]
    registry[agent_id]["trust_tier"] = result["tier"]
    registry[agent_id]["last_scored"] = int(time.time())
    _save_registry(registry)

    return result["trust_score"]


# ─── A2A Message (post-handshake) ─────────────────────────────────────────────
def create_a2a_message(
    private_key: bytes,
    agent_id: str,
    peer_agent_id: str,
    message_type: str,
    data: Dict[str, Any],
    session_id: Optional[str] = None,
    previous_hash: Optional[str] = None,
    store_in_memory: bool = True
) -> Dict[str, Any]:
    """
    Create a signed A2A message event (post-handshake interaction).

    Args:
        private_key: Sender's private key
        agent_id: Sender's agent ID
        peer_agent_id: Recipient's agent ID
        message_type: e.g. "task_delegation", "task_completed", "dispute"
        data: Message payload
        session_id: Optional existing session ID
        previous_hash: Hash of previous event in sender's chain
        store_in_memory: Auto-store in memory

    Returns:
        Signed A2A message event
    """
    from aiss.stamp import generate_nonce

    payload = {
        "event_type": "a2a_message",
        "message_type": message_type,
        "peer_agent_id": peer_agent_id,
        "data": data,
        "participants": [agent_id, peer_agent_id],
    }

    if session_id:
        payload["session_id"] = session_id

    event = {
        "version": "AISS-1.0",
        "agent_id": agent_id,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": payload,
        "previous_hash": previous_hash or "genesis",
    }

    canonical = canonicalize(event)
    signature = ed25519.sign(private_key, canonical)
    event["signature"] = ed25519.encode_base58(signature)

    if store_in_memory:
        from aiss.memory import store_event
        store_event(event)

    logger.info("A2A message created")

    return event


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    # Registry
    "register_peer",
    "get_peer",
    "list_peers",
    # Handshake steps
    "create_identity_proposal",
    "verify_identity_proposal",
    "create_identity_response",
    "verify_identity_response",
    "create_session_confirmation",
    "build_cosigned_handshake_event",
    # Orchestration
    "perform_handshake",
    # Fallback
    "record_external_interaction",
    # Messaging
    "create_a2a_message",
    # Trust
    "compute_trust_score",
    "update_peer_trust_score",
    # Exceptions
    "A2AHandshakeError",
    "A2APeerNotFound",
    "A2ATrustError",
]
