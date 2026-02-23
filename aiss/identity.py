"""
Agent Identity Management (RFC Sections 5-6)

This module implements:
- Deterministic agent ID derivation (Section 5.1)
- Identity document generation (Section 6)
- Key rotation attestation (Section 12)
"""

import time
from typing import Dict, Any, Tuple

from aiss.crypto import ed25519
from aiss.canonical import hash_bytes
from aiss.exceptions import InvalidAgentIDError


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate Ed25519 keypair for agent identity.

    Uses cryptographically secure random number generator (CSPRNG)
    as required by RFC Section 14.1.

    Returns:
        Tuple of (private_key_bytes, public_key_bytes)

    Example:
        >>> private_key, public_key = generate_keypair()
        >>> agent_id = derive_agent_id(public_key)
    """
    return ed25519.generate_keypair()


def derive_agent_id(public_key: bytes) -> str:
    """
    Derive deterministic agent ID from public key.

    RFC Section 5.1 mandates:
        agent_id = BASE58( SHA256(public_key_bytes) )[0:32]

    This ensures:
    - Collision resistance (~186 bits entropy)
    - No registry dependency
    - Cryptographic binding to identity
    - Verifiability

    Args:
        public_key: 32-byte Ed25519 public key

    Returns:
        32-character Base58 agent ID

    Example:
        >>> public_key = b'\\x01' * 32  # Example key
        >>> agent_id = derive_agent_id(public_key)
        >>> len(agent_id)
        32
    """
    # Hash the public key
    key_hash = hash_bytes(public_key)

    # Convert hex to bytes for Base58 encoding
    hash_bytes_val = bytes.fromhex(key_hash)

    # Encode to Base58 and truncate to 32 chars
    agent_id = ed25519.encode_base58(hash_bytes_val)[:32]

    return agent_id


def verify_agent_id(agent_id: str, public_key: bytes) -> bool:
    """
    Verify that agent_id correctly derives from public_key.

    Args:
        agent_id: Claimed agent ID
        public_key: Public key bytes

    Returns:
        True if agent_id is valid

    Raises:
        InvalidAgentIDError: If agent_id does not match
    """
    derived = derive_agent_id(public_key)
    if agent_id != derived:
        raise InvalidAgentIDError(agent_id, derived)
    return True


def export_identity(
    agent_id: str,
    public_key: bytes,
    algorithm: str = "Ed25519",
    metadata: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Export agent identity document (RFC Section 6.1).

    Creates AISS-1.0 compliant identity document with:
    - version: AISS-1.0
    - agent_id: Deterministic ID
    - public_key: Base58 encoded
    - algorithm: Signature algorithm
    - created_at: Unix UTC timestamp
    - metadata: Optional application data

    Args:
        agent_id: Agent ID (must match public_key)
        public_key: Public key bytes
        algorithm: Signature algorithm (default: Ed25519)
        metadata: Optional metadata dict

    Returns:
        Identity document dict

    Example:
        >>> private_key, public_key = generate_keypair()
        >>> agent_id = derive_agent_id(public_key)
        >>> identity = export_identity(agent_id, public_key)
        >>> identity['version']
        'AISS-1.0'
    """
    # Verify agent_id matches public_key
    verify_agent_id(agent_id, public_key)

    identity = {
        "version": "AISS-1.0",
        "agent_id": agent_id,
        "public_key": ed25519.encode_base64(public_key),
        "algorithm": algorithm,
        "created_at": int(time.time())
    }

    if metadata:
        identity["metadata"] = metadata

    return identity


def create_rotation_attestation(
    old_private_key: bytes,
    old_public_key: bytes,
    new_public_key: bytes
) -> Dict[str, Any]:
    """
    Create key rotation attestation (RFC Section 12).

    When rotating keys, agent_id changes (since it derives from public_key).
    This attestation proves continuity between old and new identities.

    The attestation is signed by the OLD private key to prove:
    "I (old agent) certify that (new agent) is my successor"

    Args:
        old_private_key: Current private key (to sign attestation)
        old_public_key: Current public key
        new_public_key: New public key

    Returns:
        Rotation attestation document

    Example:
        >>> old_priv, old_pub = generate_keypair()
        >>> new_priv, new_pub = generate_keypair()
        >>> attestation = create_rotation_attestation(old_priv, old_pub, new_pub)
        >>> attestation['attestation_type']
        'key_rotation'
    """
    from aiss.canonical import canonicalize

    old_agent_id = derive_agent_id(old_public_key)
    new_agent_id = derive_agent_id(new_public_key)

    # Build attestation (without signature)
    attestation = {
        "version": "AISS-1.0",
        "attestation_type": "key_rotation",
        "previous_agent_id": old_agent_id,
        "previous_public_key": ed25519.encode_base64(old_public_key),
        "new_agent_id": new_agent_id,
        "new_public_key": ed25519.encode_base64(new_public_key),
        "rotation_timestamp": int(time.time())
    }

    # Sign with old key
    canonical = canonicalize(attestation)
    signature = ed25519.sign(old_private_key, canonical)
    attestation["rotation_signature"] = ed25519.encode_base64(signature)

    return attestation


# Public API
__all__ = [
    "generate_keypair",
    "derive_agent_id",
    "verify_agent_id",
    "export_identity",
    "create_rotation_attestation",
]


def create_rotation_pcp_event(
    old_private_key: bytes,
    old_public_key: bytes,
    new_public_key: bytes,
    previous_hash: str,
    store_in_memory: bool = True
) -> dict:
    """
    Create key rotation as a PROPER PCP chain event (RFC Section 9.4 / 12).

    FIXES: Previous implementation returned a standalone document.
    This function inserts the rotation as the FINAL event of the old chain,
    and binds the new chain's genesis to this event's hash.

    Flow:
        old_chain: E1 → E2 → ... → En → ROTATION_EVENT ← this function
        new_chain: genesis(new_pubkey, prev=hash(ROTATION_EVENT)) → E1' → ...

    Args:
        old_private_key: Current private key (signs the rotation event)
        old_public_key:  Current public key
        new_public_key:  New public key
        previous_hash:   Hash of last event in old chain
        store_in_memory: Auto-store in PCP memory

    Returns:
        Rotation event dict (signed, ready for chain insertion)

    Example:
        >>> rot_event = create_rotation_pcp_event(old_priv, old_pub, new_pub, last_hash)
        >>> rot_hash = compute_event_hash(rot_event)
        >>> # New chain genesis uses rot_hash as previous_hash
        >>> genesis = stamp_genesis_event(new_priv, new_pub, new_id, payload,
        ...                               rotation_previous_hash=rot_hash)
    """
    import time
    import uuid
    from aiss.canonical import canonicalize

    old_agent_id = derive_agent_id(old_public_key)
    new_agent_id = derive_agent_id(new_public_key)

    rotation_payload = {
        "event_type": "key_rotation",
        "attestation_type": "key_rotation",
        "previous_agent_id": old_agent_id,
        "previous_public_key": ed25519.encode_base64(old_public_key),
        "new_agent_id": new_agent_id,
        "new_public_key": ed25519.encode_base64(new_public_key),
        "rotation_timestamp": int(time.time()),
    }

    event = {
        "version": "AISS-1.0",
        "agent_id": old_agent_id,
        "timestamp": int(time.time()),
        "nonce": str(uuid.uuid4()),
        "payload": rotation_payload,
        "previous_hash": previous_hash,
    }

    canonical = canonicalize(event)
    signature = ed25519.sign(old_private_key, canonical)
    event["signature"] = ed25519.encode_base64(signature)

    if store_in_memory:
        try:
            from aiss.memory import store_event
            store_event(event)
        except Exception:
            pass  # Memory may not be initialized

    return event
