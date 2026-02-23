"""
Agent-to-Agent (A2A) Handshake Protocol

Enables autonomous agents to discover, authenticate, and collaborate
with mutual cryptographic proof.

Protocol Flow:
    1. Agent A discovers Agent B (DHT, registry, or direct)
    2. Agent A initiates handshake
    3. Agent B accepts/rejects
    4. Both agents sign mutual agreement
    5. Proof stored in both audit trails

Example:
    >>> # Agent A initiates
    >>> handshake = initiate_handshake(
    ...     agent_a_private_key,
    ...     agent_a_id,
    ...     agent_b_id,
    ...     payload={"intent": "data_sharing"}
    ... )
    
    >>> # Agent B accepts
    >>> response = accept_handshake(
    ...     agent_b_private_key,
    ...     agent_b_id,
    ...     handshake
    ... )
    
    >>> # Both verify
    >>> verify_handshake(response, {agent_a_id: pub_a, agent_b_id: pub_b})
"""

import time
import uuid
from typing import Dict, Any, Optional, List

from aiss.crypto import ed25519
from aiss.canonical import canonicalize_json
from aiss.exceptions import PiQryptError
from aiss.logger import get_logger

logger = get_logger(__name__)


# ─── Exceptions ───────────────────────────────────────────────────────────────

class A2AError(PiQryptError):
    """Agent-to-Agent protocol error."""
    pass


# ─── Handshake Protocol ────────────────────────────────────────────────────────

def initiate_handshake(
    initiator_private_key: bytes,
    initiator_agent_id: str,
    responder_agent_id: str,
    payload: Optional[Dict[str, Any]] = None,
    expires_in: int = 3600
) -> Dict[str, Any]:
    """
    Initiate A2A handshake.
    
    Args:
        initiator_private_key: Initiator's Ed25519 private key (32 bytes)
        initiator_agent_id: Initiator's agent ID
        responder_agent_id: Responder's agent ID
        payload: Optional handshake data (intent, terms, etc.)
        expires_in: Handshake validity in seconds (default: 1h)
    
    Returns:
        Handshake dict (send to responder)
    
    Example:
        >>> handshake = initiate_handshake(
        ...     priv_key,
        ...     "agent_A",
        ...     "agent_B",
        ...     payload={"intent": "collaborate", "scope": "data_analysis"}
        ... )
    """
    timestamp = int(time.time())

    handshake = {
        "version": "A2A-HANDSHAKE-1.0",
        "initiator_agent_id": initiator_agent_id,
        "responder_agent_id": responder_agent_id,
        "timestamp": timestamp,
        "expires_at": timestamp + expires_in,
        "nonce_initiator": str(uuid.uuid4()),
        "payload": payload or {},
        "status": "pending"
    }

    # Initiator signs
    canonical = canonicalize_json(handshake).encode()
    signature = ed25519.sign(initiator_private_key, canonical)
    handshake["signature_initiator"] = ed25519.encode_base64(signature)

    logger.piqrypt(
        f"A2A handshake initiated: {initiator_agent_id} → {responder_agent_id}"
    )

    return handshake


def accept_handshake(
    responder_private_key: bytes,
    responder_agent_id: str,
    handshake: Dict[str, Any],
    counter_payload: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Accept A2A handshake.
    
    Args:
        responder_private_key: Responder's Ed25519 private key
        responder_agent_id: Responder's agent ID
        handshake: Handshake dict from initiator
        counter_payload: Optional response data
    
    Returns:
        Completed handshake (send back to initiator)
    
    Raises:
        A2AError: If handshake invalid or expired
    
    Example:
        >>> response = accept_handshake(
        ...     priv_key,
        ...     "agent_B",
        ...     handshake,
        ...     counter_payload={"agreed": True, "terms": "..."}
        ... )
    """
    # Verify responder matches
    if handshake.get("responder_agent_id") != responder_agent_id:
        raise A2AError(
            f"Handshake not for this agent (expected {responder_agent_id}, "
            f"got {handshake.get('responder_agent_id')})"
        )

    # Check expiration
    if int(time.time()) > handshake.get("expires_at", 0):
        raise A2AError("Handshake expired")

    # Add responder data
    handshake["nonce_responder"] = str(uuid.uuid4())
    handshake["status"] = "accepted"
    handshake["accepted_at"] = int(time.time())

    if counter_payload:
        handshake["counter_payload"] = counter_payload

    # Responder signs (including initiator signature)
    canonical = canonicalize_json(handshake).encode()
    signature = ed25519.sign(responder_private_key, canonical)
    handshake["signature_responder"] = ed25519.encode_base64(signature)

    logger.piqrypt(
        f"A2A handshake accepted: {responder_agent_id} ← {handshake['initiator_agent_id']}"
    )

    return handshake


def reject_handshake(
    responder_private_key: bytes,
    responder_agent_id: str,
    handshake: Dict[str, Any],
    reason: str
) -> Dict[str, Any]:
    """
    Reject A2A handshake.
    
    Args:
        responder_private_key: Responder's Ed25519 private key
        responder_agent_id: Responder's agent ID
        handshake: Handshake dict from initiator
        reason: Rejection reason
    
    Returns:
        Rejected handshake (send back to initiator)
    """
    # Verify responder matches
    if handshake.get("responder_agent_id") != responder_agent_id:
        raise A2AError("Handshake not for this agent")

    # Mark rejected
    handshake["status"] = "rejected"
    handshake["rejected_at"] = int(time.time())
    handshake["rejection_reason"] = reason
    handshake["nonce_responder"] = str(uuid.uuid4())

    # Sign rejection
    canonical = canonicalize_json(handshake).encode()
    signature = ed25519.sign(responder_private_key, canonical)
    handshake["signature_responder"] = ed25519.encode_base64(signature)

    logger.piqrypt(
        f"A2A handshake rejected: {responder_agent_id} ← {handshake['initiator_agent_id']} "
        f"(reason: {reason})"
    )

    return handshake


def verify_handshake(
    handshake: Dict[str, Any],
    public_keys: Dict[str, bytes]
) -> bool:
    """
    Verify A2A handshake signatures.
    
    Args:
        handshake: Completed handshake dict
        public_keys: Dict mapping agent_id → public_key
    
    Returns:
        True if both signatures valid
    
    Raises:
        A2AError: If verification fails
    
    Example:
        >>> verify_handshake(handshake, {
        ...     "agent_A": public_key_a,
        ...     "agent_B": public_key_b
        ... })
    """
    initiator_id = handshake.get("initiator_agent_id")
    responder_id = handshake.get("responder_agent_id")

    # Get public keys
    initiator_pub = public_keys.get(initiator_id)
    responder_pub = public_keys.get(responder_id)

    if not initiator_pub:
        raise A2AError(f"Missing public key for initiator: {initiator_id}")
    if not responder_pub:
        raise A2AError(f"Missing public key for responder: {responder_id}")

    # Verify initiator signature
    sig_init_b64 = handshake.get("signature_initiator")
    if not sig_init_b64:
        raise A2AError("Missing initiator signature")

    sig_init = ed25519.decode_base64(sig_init_b64)

    # Remove responder fields for initiator verification
    init_handshake = {
        k: v for k, v in handshake.items()
        if k not in ["signature_responder", "nonce_responder", "accepted_at",
                     "rejected_at", "rejection_reason", "counter_payload"]
    }
    init_handshake.pop("signature_initiator", None)

    canonical_init = canonicalize_json(init_handshake).encode()

    try:
        ed25519.verify(initiator_pub, canonical_init, sig_init)
    except Exception as e:
        raise A2AError(f"Initiator signature verification failed: {e}")

    # Verify responder signature (if accepted/rejected)
    if handshake.get("status") in ["accepted", "rejected"]:
        sig_resp_b64 = handshake.get("signature_responder")
        if not sig_resp_b64:
            raise A2AError("Missing responder signature")

        sig_resp = ed25519.decode_base64(sig_resp_b64)

        # Remove responder signature for verification
        resp_handshake = {k: v for k, v in handshake.items() if k != "signature_responder"}
        canonical_resp = canonicalize_json(resp_handshake).encode()

        try:
            ed25519.verify(responder_pub, canonical_resp, sig_resp)
        except Exception as e:
            raise A2AError(f"Responder signature verification failed: {e}")

    logger.piqrypt(f"A2A handshake verified: {initiator_id} ↔ {responder_id}")

    return True


# ─── Peer Discovery (Basic) ────────────────────────────────────────────────────

class PeerRegistry:
    """
    Simple in-memory peer registry.
    
    In production, use:
    - DHT (Distributed Hash Table)
    - Central registry server
    - Blockchain-based discovery
    """

    def __init__(self):
        self._peers: Dict[str, Dict[str, Any]] = {}

    def register(self, agent_id: str, public_key: bytes, metadata: Dict[str, Any] = None):
        """Register agent in registry."""
        self._peers[agent_id] = {
            "agent_id": agent_id,
            "public_key": ed25519.encode_base64(public_key),
            "metadata": metadata or {},
            "registered_at": int(time.time())
        }
        logger.piqrypt(f"Peer registered: {agent_id}")

    def discover(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Discover peers.
        
        Args:
            agent_id: Optional specific agent to find
        
        Returns:
            List of peer info dicts
        """
        if agent_id:
            peer = self._peers.get(agent_id)
            return [peer] if peer else []

        return list(self._peers.values())

    def get_public_key(self, agent_id: str) -> Optional[bytes]:
        """Get public key for agent."""
        peer = self._peers.get(agent_id)
        if peer:
            return ed25519.decode_base64(peer["public_key"])
        return None


# ─── Helper Functions ──────────────────────────────────────────────────────────

def handshake_to_event(handshake: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
    """
    Convert handshake to AISS event for audit trail.
    
    Args:
        handshake: Completed handshake
        agent_id: Agent storing this event
    
    Returns:
        AISS-1.0 event dict
    """
    return {
        "version": "AISS-1.0",
        "agent_id": agent_id,
        "timestamp": handshake.get("accepted_at") or handshake.get("timestamp"),
        "nonce": handshake.get("nonce_initiator") if agent_id == handshake.get("initiator_agent_id") else handshake.get("nonce_responder"),
        "payload": {
            "event_type": "a2a_handshake",
            "peer_agent_id": handshake.get("responder_agent_id") if agent_id == handshake.get("initiator_agent_id") else handshake.get("initiator_agent_id"),
            "status": handshake.get("status"),
            "handshake_data": handshake.get("payload"),
            "handshake_complete": handshake
        },
        "previous_hash": "genesis",  # Caller should set proper previous_hash
        "signature": handshake.get("signature_initiator") if agent_id == handshake.get("initiator_agent_id") else handshake.get("signature_responder")
    }


__all__ = [
    "initiate_handshake",
    "accept_handshake",
    "reject_handshake",
    "verify_handshake",
    "PeerRegistry",
    "handshake_to_event",
    "A2AError",
]
