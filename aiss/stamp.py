# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
Event Stamping (RFC Section 7)

This module implements cryptographic event stamping with:
- Timestamp generation
- Nonce generation (anti-replay)
- Hash chain linking
- Ed25519 signature
"""

import time
import uuid
from typing import Dict, Any, Optional

from aiss.crypto import ed25519
from aiss.canonical import canonicalize
from aiss.exceptions import NonceError


def generate_nonce() -> str:
    """
    Generate unique nonce for anti-replay protection (RFC Section 11).

    Uses UUIDv4 for cryptographic randomness and global uniqueness.
    Alternative formats like ULID or KSUID are also acceptable.

    Returns:
        UUID string (e.g., "550e8400-e29b-41d4-a716-446655440000")
    """
    return str(uuid.uuid4())


def stamp_event(
    private_key: bytes,
    agent_id: str,
    payload: Dict[str, Any],
    previous_hash: Optional[str] = None,
    nonce: Optional[str] = None,
    timestamp: Optional[int] = None
) -> Dict[str, Any]:
    """
    Create and sign an event stamp (RFC Section 7).

    This is the core operation for agent actions. Each event:
    - Links to previous event via hash chain
    - Contains unique nonce (anti-replay)
    - Includes UTC timestamp
    - Signed with agent's private key

    Args:
        private_key: Agent's Ed25519 private key
        agent_id: Agent ID (must match private_key)
        payload: Event data (will be canonicalized)
        previous_hash: Hash of previous event (None for genesis)
        nonce: Optional nonce (auto-generated if None)
        timestamp: Optional Unix timestamp (auto-generated if None)

    Returns:
        Signed event dict conforming to RFC Section 7.1

    Raises:
        NonceError: If nonce is invalid

    Example:
        >>> from aiss import generate_keypair, derive_agent_id
        >>> private_key, public_key = generate_keypair()
        >>> agent_id = derive_agent_id(public_key)
        >>> event = stamp_event(
        ...     private_key,
        ...     agent_id,
        ...     {"action": "trade", "symbol": "BTC", "amount": 0.5},
        ...     previous_hash=None  # Genesis event
        ... )
        >>> event['version']
        'AISS-1.0'
        >>> 'signature' in event
        True
    """
    # Generate nonce if not provided
    if nonce is None:
        nonce = generate_nonce()
    elif not nonce:
        raise NonceError("Nonce cannot be empty")

    # Generate timestamp if not provided (Unix UTC seconds)
    if timestamp is None:
        timestamp = int(time.time())

    # Build event structure (without signature)
    event = {
        "version": "AISS-1.0",
        "agent_id": agent_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "payload": payload,
        "previous_hash": previous_hash
    }

    # Canonicalize and sign
    canonical = canonicalize(event)
    signature = ed25519.sign(private_key, canonical)

    # Add signature to event
    event["signature"] = ed25519.encode_base64(signature)

    return event


def stamp_genesis_event(
    private_key: bytes,
    public_key: bytes,
    agent_id: str,
    payload: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Create genesis (first) event in a chain (RFC Section 9.3).

    The genesis event uses a special previous_hash computed as:
        previous_hash = SHA256(agent_public_key_bytes)

    This binds the chain cryptographically to the agent's identity
    and prevents genesis collision attacks.

    Args:
        private_key: Agent's private key
        public_key: Agent's public key
        agent_id: Agent ID
        payload: Genesis event data

    Returns:
        Genesis event dict

    Example:
        >>> private_key, public_key = generate_keypair()
        >>> agent_id = derive_agent_id(public_key)
        >>> genesis = stamp_genesis_event(
        ...     private_key,
        ...     public_key,
        ...     agent_id,
        ...     {"action": "initialize", "version": "1.0"}
        ... )
        >>> genesis['previous_hash'][:16]  # Will be SHA256 of public key
    """
    from aiss.canonical import hash_bytes

    # Compute genesis previous_hash from public key (RFC Section 9.3)
    genesis_hash = hash_bytes(public_key)

    return stamp_event(
        private_key=private_key,
        agent_id=agent_id,
        payload=payload,
        previous_hash=genesis_hash
    )


# Public API
__all__ = [
    "generate_nonce",
    "stamp_event",
    "stamp_genesis_event",
]
