# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Agent History — v1.6

Provides load_full_history() for reconstructing complete agent memory
across key rotation boundaries.

Problem solved:
    When an agent rotates its keys, its agent_id changes.
    load_events(agent_id=new_id) only returns events from the new chain.
    This module traverses the rotation chain to return the complete history.

Usage:
    from aiss.history import load_full_history

    # Returns complete chronological history across all key rotations
    history = load_full_history("agent_id_B")
    # → includes events from agent_id_A (before rotation) + agent_id_B (after)

Architecture:
    Rotation event in chain A:
        payload.event_type   = "key_rotation"
        payload.new_agent_id = agent_id_B
        payload.previous_agent_id = agent_id_A

    load_full_history() uses the SQLite index (successor_agent_id column)
    to traverse the chain without scanning all events.

    If the index is unavailable, falls back to linear scan.
"""

import time
from typing import List, Dict, Any, Optional

from aiss.logger import get_logger

logger = get_logger(__name__)


# ─── History entry ────────────────────────────────────────────────────────────

def _make_rotation_marker(from_id: str, to_id: str, timestamp: int) -> Dict[str, Any]:
    """
    Create a synthetic marker event for key rotation display.
    Not stored — used only in history output for clarity.
    """
    return {
        "_marker": True,
        "event_type": "key_rotation",
        "from_agent_id": from_id,
        "to_agent_id": to_id,
        "timestamp": timestamp,
        "note": "Key rotation — identity chain continues",
    }


# ─── Core function ────────────────────────────────────────────────────────────

def load_full_history(
    agent_id: str,
    include_markers: bool = False,
    max_depth: int = 20,
) -> List[Dict[str, Any]]:
    """
    Load complete chronological event history for an agent identity,
    traversing key rotation boundaries automatically.

    v1.6 — resolves the key rotation memory gap.

    Args:
        agent_id:        Any agent_id in the rotation chain
                         (can be oldest, newest, or any in between)
        include_markers: If True, inserts synthetic marker events at
                         each rotation boundary for display purposes.
                         Markers have "_marker": True — filter them out
                         for cryptographic operations.
        max_depth:       Maximum number of rotations to traverse
                         (prevents infinite loops on corrupted data)

    Returns:
        List of events in chronological order (oldest first).
        If include_markers=True, rotation boundary markers are inserted.

    Example:
        # Agent rotated keys twice: A → B → C
        history = load_full_history("agent_id_C")
        # Returns: [events_A..., rotation_A→B, events_B..., rotation_B→C, events_C...]

        # Filter out markers for cryptographic use
        real_events = [e for e in history if not e.get("_marker")]

    Raises:
        No exceptions — returns empty list on error (logs warning).
    """
    from aiss.memory import load_events

    # Step 1: Get the full identity chain via index
    identity_chain = _resolve_identity_chain(agent_id, max_depth=max_depth)

    logger.debug(f"[PiQrypt] Full history: resolved chain {identity_chain}")

    if not identity_chain:
        # Fallback: just load this agent's events
        return load_events(agent_id=agent_id)

    # Step 2: Load events for each identity in chronological order
    full_history = []

    for i, aid in enumerate(identity_chain):
        # Load events for this identity
        chain_events = load_events(agent_id=aid)

        if not chain_events:
            continue

        # Add rotation marker between chains (if requested)
        if include_markers and i > 0:
            # Find the rotation event that connects the previous chain to this one
            prev_id = identity_chain[i - 1]
            rotation_ts = _find_rotation_timestamp(chain_events, prev_id) or (
                chain_events[0].get("timestamp", int(time.time())) - 1
            )
            marker = _make_rotation_marker(prev_id, aid, rotation_ts)
            full_history.append(marker)

        full_history.extend(chain_events)

    # Step 3: Sort chronologically (events from different chains may interleave)
    real_events = [e for e in full_history if not e.get("_marker")]
    markers = [e for e in full_history if e.get("_marker")]

    if include_markers:
        # Merge and sort: real events by timestamp, markers inserted at boundary
        return _merge_with_markers(real_events, markers)
    else:
        return sorted(real_events, key=lambda e: e.get("timestamp", 0))


def _resolve_identity_chain(agent_id: str, max_depth: int = 20) -> List[str]:
    """
    Resolve the complete identity chain for an agent_id.

    Uses SQLite index if available (fast path).
    Falls back to scanning events for rotation links (slow path).

    Returns:
        List of agent_ids in chronological order (oldest first).
        Example: ["agent_id_A", "agent_id_B", "agent_id_C"]
    """
    # Fast path: use index
    try:
        from aiss.index import get_index
        from aiss.license import is_pro

        encrypted = is_pro()
        with get_index(encrypted=encrypted) as idx:
            chain = idx.get_full_identity_chain(agent_id)
            if len(chain) >= 1:
                logger.debug(f"[PiQrypt] Identity chain (index): {chain}")
                return chain
    except Exception as e:
        logger.debug(f"[PiQrypt] Index unavailable for chain resolution: {e}")

    # Slow path: linear scan
    return _resolve_chain_linear_scan(agent_id, max_depth=max_depth)


def _resolve_chain_linear_scan(agent_id: str, max_depth: int = 20) -> List[str]:
    """
    Resolve identity chain by scanning events for key_rotation payloads.
    Used when SQLite index is unavailable or not yet populated.
    """
    from aiss.memory import load_events

    visited = set()
    chain = [agent_id]
    visited.add(agent_id)

    # Walk backwards: find events where new_agent_id == agent_id
    current = agent_id
    depth = 0
    while depth < max_depth:
        all_events = load_events()  # All events
        predecessor = None

        for event in all_events:
            payload = event.get("payload", {})
            if (
                payload.get("event_type") == "key_rotation"
                and payload.get("new_agent_id") == current
            ):
                predecessor = event.get("agent_id")
                break

        if not predecessor or predecessor in visited:
            break

        chain.insert(0, predecessor)
        visited.add(predecessor)
        current = predecessor
        depth += 1

    # Walk forwards: find key_rotation events in current chain
    current = agent_id
    depth = 0
    while depth < max_depth:
        chain_events = load_events(agent_id=current)
        successor = None

        for event in chain_events:
            payload = event.get("payload", {})
            if payload.get("event_type") == "key_rotation":
                successor = payload.get("new_agent_id")
                break

        if not successor or successor in visited:
            break

        chain.append(successor)
        visited.add(successor)
        current = successor
        depth += 1

    return chain


def _find_rotation_timestamp(events: List[Dict[str, Any]], from_agent_id: str) -> Optional[int]:
    """Find the timestamp of a key_rotation event linking from_agent_id to the current chain."""
    for event in events:
        payload = event.get("payload", {})
        if (
            payload.get("event_type") == "key_rotation"
            and payload.get("previous_agent_id") == from_agent_id
        ):
            return event.get("timestamp")
    return None


def _merge_with_markers(
    events: List[Dict[str, Any]],
    markers: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Merge real events and rotation markers into a single chronological list.
    Markers are inserted just before the first event of the new chain.
    """
    result = sorted(events, key=lambda e: e.get("timestamp", 0))

    for marker in sorted(markers, key=lambda m: m.get("timestamp", 0)):
        # Insert marker just before first event after its timestamp
        ts = marker.get("timestamp", 0)
        insert_pos = len(result)
        for i, ev in enumerate(result):
            if ev.get("timestamp", 0) >= ts:
                insert_pos = i
                break
        result.insert(insert_pos, marker)

    return result


# ─── History summary ──────────────────────────────────────────────────────────

def get_history_summary(agent_id: str) -> Dict[str, Any]:
    """
    Get a summary of an agent's full history including rotation info.

    Returns:
        Dict with:
        - identity_chain: list of agent_ids in order
        - total_events: total event count across all identities
        - rotations: number of key rotations
        - earliest_timestamp: oldest event
        - latest_timestamp: newest event
        - per_identity: breakdown per agent_id

    Example:
        summary = get_history_summary("agent_id_B")
        print(f"Total: {summary['total_events']} events across {summary['rotations']} rotations")
    """
    from aiss.memory import load_events

    identity_chain = _resolve_identity_chain(agent_id)
    per_identity = []
    total_events = 0
    earliest = None
    latest = None

    for aid in identity_chain:
        events = load_events(agent_id=aid)
        count = len(events)
        total_events += count

        timestamps = [e.get("timestamp", 0) for e in events if e.get("timestamp")]
        oldest = min(timestamps) if timestamps else None
        newest = max(timestamps) if timestamps else None

        if oldest and (earliest is None or oldest < earliest):
            earliest = oldest
        if newest and (latest is None or newest > latest):
            latest = newest

        per_identity.append({
            "agent_id": aid,
            "event_count": count,
            "oldest_timestamp": oldest,
            "newest_timestamp": newest,
        })

    return {
        "agent_id": agent_id,
        "identity_chain": identity_chain,
        "total_events": total_events,
        "rotations": max(0, len(identity_chain) - 1),
        "earliest_timestamp": earliest,
        "latest_timestamp": latest,
        "per_identity": per_identity,
    }


# ─── Public API ───────────────────────────────────────────────────────────────

__all__ = [
    "load_full_history",
    "get_history_summary",
]
