# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
Anti-Replay Protection (RFC Section 11)

Replay attacks occur when an adversary re-submits a previously valid
signed event. AISS prevents this using unique nonces.

This module provides:
- Nonce uniqueness tracking
- Replay attack detection
- Configurable retention policies
"""

import time
from typing import Dict, Set, Optional, List
from collections import defaultdict

from aiss.exceptions import ReplayAttackDetected, NonceError


class NonceStore:
    """
    Nonce storage and replay detection (RFC Section 11).

    Tracks seen nonces per agent to prevent replay attacks.

    AISS-1: Minimum 24-hour retention
    AISS-2: 7-year retention (audit period)
    """

    def __init__(self, retention_hours: int = 24):
        """
        Initialize nonce store.

        Args:
            retention_hours: How long to retain nonces (default: 24)
        """
        self.retention_hours = retention_hours
        self.retention_seconds = retention_hours * 3600

        # Map: agent_id -> set of (nonce, timestamp) tuples
        self.nonces: Dict[str, Set[tuple]] = defaultdict(set)

    def check_and_add(self, agent_id: str, nonce: str, timestamp: Optional[int] = None) -> None:
        """
        Check if nonce is unique and add to store.

        Args:
            agent_id: Agent ID
            nonce: Nonce to check
            timestamp: Event timestamp (for expiration tracking)

        Raises:
            ReplayAttackDetected: If nonce already seen
            NonceError: If nonce is invalid
        """
        if not nonce:
            raise NonceError("Nonce cannot be empty")

        if timestamp is None:
            timestamp = int(time.time())

        # Check if nonce already exists for this agent
        agent_nonces = self.nonces[agent_id]

        for existing_nonce, _ in agent_nonces:
            if existing_nonce == nonce:
                raise ReplayAttackDetected(agent_id, nonce)

        # Add new nonce
        agent_nonces.add((nonce, timestamp))

    def cleanup_expired(self) -> int:
        """
        Remove expired nonces (older than retention period).

        Returns:
            Number of nonces removed

        Example:
            >>> store = NonceStore(retention_hours=24)
            >>> # ... add nonces ...
            >>> removed = store.cleanup_expired()
            >>> print(f"Cleaned up {removed} expired nonces")
        """
        current_time = int(time.time())
        cutoff_time = current_time - self.retention_seconds
        removed_count = 0

        for agent_id in list(self.nonces.keys()):
            agent_nonces = self.nonces[agent_id]

            # Filter out expired nonces
            valid_nonces = {
                (nonce, ts) for nonce, ts in agent_nonces
                if ts >= cutoff_time
            }

            removed_count += len(agent_nonces) - len(valid_nonces)

            if valid_nonces:
                self.nonces[agent_id] = valid_nonces
            else:
                # Remove agent if no nonces left
                del self.nonces[agent_id]

        return removed_count

    def get_nonce_count(self, agent_id: Optional[str] = None) -> int:
        """
        Get count of stored nonces.

        Args:
            agent_id: Specific agent (None for all agents)

        Returns:
            Number of nonces
        """
        if agent_id:
            return len(self.nonces.get(agent_id, set()))
        else:
            return sum(len(nonces) for nonces in self.nonces.values())

    def clear(self) -> None:
        """Clear all stored nonces."""
        self.nonces.clear()

    def export_state(self) -> Dict[str, List[tuple]]:
        """
        Export nonce store state for persistence.

        Returns:
            Dict mapping agent_id to list of (nonce, timestamp) tuples
        """
        return {
            agent_id: list(nonces)
            for agent_id, nonces in self.nonces.items()
        }

    def import_state(self, state: Dict[str, List[tuple]]) -> None:
        """
        Import nonce store state from persistence.

        Args:
            state: Exported state dict
        """
        self.nonces.clear()
        for agent_id, nonce_list in state.items():
            self.nonces[agent_id] = set(nonce_list)


def detect_replay_attacks(events: List[Dict]) -> List[ReplayAttackDetected]:
    """
    Detect replay attacks in event list.

    Scans events for duplicate nonces within same agent.

    Args:
        events: List of events to check

    Returns:
        List of ReplayAttackDetected exceptions

    Example:
        >>> attacks = detect_replay_attacks(events)
        >>> if attacks:
        ...     print(f"Found {len(attacks)} replay attacks")
    """
    store = NonceStore()
    attacks = []

    for event in events:
        agent_id = event.get('agent_id')
        nonce = event.get('nonce')
        timestamp = event.get('timestamp')

        if not agent_id or not nonce:
            continue

        try:
            store.check_and_add(agent_id, nonce, timestamp)
        except ReplayAttackDetected as e:
            attacks.append(e)

    return attacks


def validate_nonces(events: List[Dict]) -> bool:
    """
    Validate that all events have unique nonces.

    Args:
        events: List of events

    Returns:
        True if all nonces are unique

    Raises:
        ReplayAttackDetected: If duplicate nonce found
    """
    attacks = detect_replay_attacks(events)
    if attacks:
        raise attacks[0]
    return True


# Public API
__all__ = [
    "NonceStore",
    "detect_replay_attacks",
    "validate_nonces",
]
