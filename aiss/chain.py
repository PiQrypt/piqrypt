# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
Hash Chain Operations (RFC Section 9)

This module implements:
- Event hash computation
- Chain integrity verification
- Chain building and traversal
"""

from typing import Dict, Any, List

from aiss.canonical import canonicalize
from aiss.exceptions import InvalidChainError


def compute_event_hash(event: Dict[str, Any]) -> str:
    """
    Compute SHA-256 hash of event (RFC Section 9.1).

    Hash is computed over the canonical JSON of the event
    EXCLUDING the signature field.

    Args:
        event: Event dict

    Returns:
        Hexadecimal SHA-256 hash

    Example:
        >>> event = {
        ...     "version": "AISS-1.0",
        ...     "agent_id": "test",
        ...     "timestamp": 1234567890,
        ...     "nonce": "unique-id",
        ...     "payload": {"action": "test"},
        ...     "previous_hash": "genesis",
        ...     "signature": "sig..."
        ... }
        >>> event_hash = compute_event_hash(event)
        >>> len(event_hash)
        64
    """
    # Create copy without signature
    event_copy = event.copy()
    event_copy.pop('signature', None)

    # Canonicalize and hash
    canonical = canonicalize(event_copy)
    import hashlib
    return hashlib.sha256(canonical).hexdigest()


def compute_chain_hash(events: List[Dict[str, Any]]) -> str:
    """
    Compute integrity hash of entire chain.

    This is the hash of all event hashes concatenated.
    Used for audit export (RFC Section 15).

    Args:
        events: List of events in order

    Returns:
        Hexadecimal SHA-256 hash of chain
    """
    import hashlib
    chain_hasher = hashlib.sha256()

    for event in events:
        event_hash = compute_event_hash(event)
        chain_hasher.update(event_hash.encode('utf-8'))

    return chain_hasher.hexdigest()


def verify_chain_linkage(events: List[Dict[str, Any]]) -> bool:
    """
    Verify hash chain linkage (RFC Section 9.2).

    Validates that each event correctly references the hash
    of the previous event:
        current_event.previous_hash == SHA256(previous_event)

    Args:
        events: List of events in chronological order

    Returns:
        True if chain is valid

    Raises:
        InvalidChainError: If chain linkage is broken
    """
    if not events:
        return True

    for i in range(1, len(events)):
        current = events[i]
        previous = events[i - 1]

        # Compute hash of previous event
        expected_hash = compute_event_hash(previous)

        # Check if current event references it
        actual_hash = current.get('previous_hash')

        if actual_hash != expected_hash:
            raise InvalidChainError(
                f"Chain broken: event {i} previous_hash mismatch",
                event_index=i
            )

    return True


def verify_monotonic_timestamps(events: List[Dict[str, Any]]) -> bool:
    """
    Verify timestamps are monotonically increasing (RFC Section 8).

    AISS-1: SHOULD enforce (warning only)
    AISS-2: MUST enforce (exception)

    Args:
        events: List of events

    Returns:
        True if timestamps are monotonic

    Raises:
        InvalidChainError: If timestamps are not monotonic
    """
    if not events:
        return True

    for i in range(1, len(events)):
        current_ts = events[i].get('timestamp', 0)
        previous_ts = events[i - 1].get('timestamp', 0)

        if current_ts < previous_ts:
            raise InvalidChainError(
                f"Non-monotonic timestamps: event {i} ({current_ts}) < event {i-1} ({previous_ts})",
                event_index=i
            )

    return True


def append_event(
    chain: List[Dict[str, Any]],
    new_event: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Append event to chain with validation.

    Validates:
    - previous_hash matches last event
    - timestamp is monotonic

    Args:
        chain: Existing event chain
        new_event: Event to append

    Returns:
        Updated chain

    Raises:
        InvalidChainError: If event cannot be appended
    """
    if not chain:
        # First event - no validation needed
        return [new_event]

    # Verify linkage
    last_event = chain[-1]
    expected_hash = compute_event_hash(last_event)
    actual_hash = new_event.get('previous_hash')

    if actual_hash != expected_hash:
        raise InvalidChainError(
            f"Cannot append: previous_hash mismatch (expected {expected_hash[:16]}..., got {actual_hash[:16]}...)"
        )

    # Verify timestamp
    last_ts = last_event.get('timestamp', 0)
    new_ts = new_event.get('timestamp', 0)

    if new_ts < last_ts:
        raise InvalidChainError(
            f"Cannot append: timestamp ({new_ts}) < last event ({last_ts})"
        )

    # Append
    return chain + [new_event]


def get_chain_info(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get summary information about a chain.

    Returns:
        Dict with chain metadata:
        - length: Number of events
        - first_timestamp: Timestamp of first event
        - last_timestamp: Timestamp of last event
        - chain_hash: Integrity hash
        - agent_id: Agent ID (if all events from same agent)
    """
    if not events:
        return {
            "length": 0,
            "chain_hash": None
        }

    agent_ids = set(e.get('agent_id') for e in events)

    return {
        "length": len(events),
        "first_timestamp": events[0].get('timestamp'),
        "last_timestamp": events[-1].get('timestamp'),
        "chain_hash": compute_chain_hash(events),
        "agent_id": agent_ids.pop() if len(agent_ids) == 1 else None,
        "multiple_agents": len(agent_ids) > 1
    }


# Public API
__all__ = [
    "compute_event_hash",
    "compute_chain_hash",
    "verify_chain_linkage",
    "verify_monotonic_timestamps",
    "append_event",
    "get_chain_info",
]
