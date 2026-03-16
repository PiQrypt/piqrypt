# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
Fork Detection & Canonical History Rule (RFC AISS-1.1 Sections 6 and 14)

A fork occurs when multiple events reference the same previous_hash.
This indicates either:
- Parallel execution by multiple agent instances
- Malicious attempt to rewrite history
- Implementation error

Canonical History Rule (RFC §6):
When multiple valid branches exist from the same agent identity,
a DETERMINISTIC selection algorithm must be applied so all
independent verifiers reach the IDENTICAL result.

Selection order (RFC §6.3):
  Step 1 — Most events anchored to a trusted timestamp (TSA token)
  Step 2 — Earliest trusted anchor timestamp among tied chains
  Step 3 — Longest chain (most events)
  Step 4 — Lexicographically lowest final event hash (tie-breaker)

Fork statuses (RFC §6.4 / §6.5):
  FORK_DETECTED          — standard fork
  FORK_AFTER_FINALIZATION — fork after TSA-anchored event (security incident)
  NON_CANONICAL_HISTORY   — non-selected branch in canonical resolution
"""

from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict

from aiss.exceptions import ForkDetected
from aiss.chain import compute_event_hash


class ForkDetector:
    """
    Fork detection engine (RFC Section 10.1).

    Scans event sequences to detect fork conditions.
    """

    def __init__(self):
        self.previous_hash_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def add_event(self, event: Dict[str, Any]) -> None:
        """
        Add event to fork detector.

        Args:
            event: Event to track
        """
        prev_hash = event.get('previous_hash')
        if prev_hash:
            self.previous_hash_map[prev_hash].append(event)

    def detect(self, events: List[Dict[str, Any]]) -> Optional[ForkDetected]:
        """
        Detect forks in event list.

        Returns:
            ForkDetected exception if fork found, None otherwise

        Example:
            >>> detector = ForkDetector()
            >>> fork = detector.detect(events)
            >>> if fork:
            ...     print(f"Fork at {fork.hash}")
        """
        # Reset state
        self.previous_hash_map.clear()

        # Build previous_hash -> events mapping
        for event in events:
            self.add_event(event)

        # Check for multiple events with same previous_hash
        for prev_hash, event_list in self.previous_hash_map.items():
            if len(event_list) > 1:
                return ForkDetected(prev_hash, event_list)

        return None

    def detect_and_raise(self, events: List[Dict[str, Any]]) -> None:
        """
        Detect forks and raise exception if found.

        Raises:
            ForkDetected: If fork condition detected
        """
        fork = self.detect(events)
        if fork:
            raise fork


def find_forks(events: List[Dict[str, Any]]) -> List[ForkDetected]:
    """
    Find all forks in event list.

    Args:
        events: List of events to scan

    Returns:
        List of ForkDetected exceptions (one per fork)

    Example:
        >>> forks = find_forks(events)
        >>> for fork in forks:
        ...     print(f"Fork: {len(fork.events)} branches at {fork.hash[:16]}...")
    """
    detector = ForkDetector()
    forks = []

    # Build mapping
    for event in events:
        detector.add_event(event)

    # Find all forks
    for prev_hash, event_list in detector.previous_hash_map.items():
        if len(event_list) > 1:
            forks.append(ForkDetected(prev_hash, event_list))

    return forks


def resolve_fork_by_timestamp(fork: ForkDetected) -> Dict[str, Any]:
    """
    Resolve fork by selecting event with latest timestamp.

    This is one possible resolution strategy (RFC Section 10.2).
    Applications may implement different strategies:
    - First seen wins
    - Highest nonce wins
    - Manual resolution
    - Reject all branches

    Args:
        fork: ForkDetected exception

    Returns:
        Event with latest timestamp
    """
    return max(fork.events, key=lambda e: e.get('timestamp', 0))


def resolve_fork_by_first_seen(fork: ForkDetected) -> Dict[str, Any]:
    """
    Resolve fork by selecting first event in list.

    This assumes events list is ordered by reception time.

    Args:
        fork: ForkDetected exception

    Returns:
        First event in fork
    """
    return fork.events[0]


def get_fork_resolution_info(fork: ForkDetected) -> Dict[str, Any]:
    """
    Get detailed information about a fork for manual resolution.

    Returns:
        Dict with fork details:
        - hash: previous_hash where fork occurred
        - branch_count: Number of branches
        - branches: List of branch info dicts
    """
    branches = []

    for i, event in enumerate(fork.events):
        branches.append({
            "branch_id": i,
            "event_hash": compute_event_hash(event),
            "timestamp": event.get('timestamp'),
            "nonce": event.get('nonce'),
            "payload": event.get('payload')
        })

    return {
        "hash": fork.hash,
        "branch_count": len(fork.events),
        "branches": branches
    }


# ─── Canonical History Rule (RFC §6) ─────────────────────────────────────────

# Fork status codes
STATUS_FORK_DETECTED           = "FORK_DETECTED"
STATUS_FORK_AFTER_FINALIZATION = "FORK_AFTER_FINALIZATION"
STATUS_NON_CANONICAL           = "NON_CANONICAL_HISTORY"
STATUS_CANONICAL               = "CANONICAL"


def _count_anchored_events(chain: List[Dict[str, Any]]) -> int:
    """Count events in chain that have a trusted_timestamp (TSA token)."""
    return sum(
        1 for e in chain
        if e.get("trusted_timestamp") and e["trusted_timestamp"].get("rfc3161_token")
    )


def _earliest_trusted_timestamp(chain: List[Dict[str, Any]]) -> int:
    """
    Return the earliest verifiable trusted timestamp in the chain.
    Returns int.max if no anchored events exist.
    """
    anchored_ts = [
        e["trusted_timestamp"].get("timestamp", int(1e18))
        for e in chain
        if e.get("trusted_timestamp") and e["trusted_timestamp"].get("rfc3161_token")
    ]
    return min(anchored_ts) if anchored_ts else int(1e18)


def select_canonical_chain(
    branches: List[List[Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Select the canonical chain from multiple valid branches (RFC §6.3).

    All conforming implementations MUST produce identical results
    when given the same input.

    Selection algorithm (applied in order):

    Step 1 — Most TSA-anchored events
    Step 2 — Earliest trusted anchor timestamp
    Step 3 — Longest chain
    Step 4 — Lexicographically lowest final event hash (deterministic tie-breaker)

    Args:
        branches: List of event chains (each chain is a list of events)

    Returns:
        Tuple of (canonical_chain, non_canonical_branch_ids)

    Example:
        >>> canonical, others = select_canonical_chain([chain_a, chain_b])
        >>> # All verifiers will select the same canonical_chain
    """
    if not branches:
        return [], []
    if len(branches) == 1:
        return branches[0], []

    def sort_key(chain: List[Dict[str, Any]]) -> tuple:
        anchored   = _count_anchored_events(chain)           # Step 1: more is better → negate
        earliest   = _earliest_trusted_timestamp(chain)      # Step 2: earlier is better
        length     = len(chain)                               # Step 3: longer is better → negate
        last_hash  = compute_event_hash(chain[-1]) if chain else "z" * 64  # Step 4: lower is better

        return (
            -anchored,    # negate: more anchored events = lower key = selected first
            earliest,     # earlier timestamp selected first
            -length,      # negate: longer chain selected first
            last_hash,    # lexicographically lowest
        )

    sorted_branches = sorted(range(len(branches)), key=lambda i: sort_key(branches[i]))
    canonical_idx = sorted_branches[0]
    non_canonical_idxs = sorted_branches[1:]

    return branches[canonical_idx], [str(i) for i in non_canonical_idxs]


def detect_fork_after_finalization(
    canonical_chain: List[Dict[str, Any]],
    non_canonical_chains: List[List[Dict[str, Any]]],
) -> bool:
    """
    Detect if fork occurs after a TSA-finalized event (RFC §6.5).

    A FORK_AFTER_FINALIZATION indicates intentional or compromised
    behavior and MUST trigger a security incident response.

    Args:
        canonical_chain:     The selected canonical chain
        non_canonical_chains: Non-selected branches

    Returns:
        True if fork occurred after a finalized (TSA-anchored) event
    """
    if not non_canonical_chains:
        return False

    # Find the last anchored event hash in canonical chain
    last_anchor_hash = None
    for event in reversed(canonical_chain):
        if event.get("trusted_timestamp") and event["trusted_timestamp"].get("rfc3161_token"):
            last_anchor_hash = compute_event_hash(event)
            break

    if last_anchor_hash is None:
        return False  # No anchored events → standard fork, not finalization breach

    # Check if any non-canonical branch diverges AFTER this anchor
    canonical_hashes = {compute_event_hash(e) for e in canonical_chain}

    for branch in non_canonical_chains:
        for event in branch:
            ev_hash = compute_event_hash(event)
            if ev_hash not in canonical_hashes:
                # This event is only in the non-canonical branch
                # If the previous_hash is in canonical chain → diverges after anchor
                prev = event.get("previous_hash", "")
                if prev in canonical_hashes:
                    # Check if divergence happens after last_anchor_hash
                    # by verifying last_anchor_hash appears before this divergence point
                    for i, ev in enumerate(canonical_chain):
                        if compute_event_hash(ev) == last_anchor_hash:
                            # The anchor is in the canonical chain
                            # and the divergence happens somewhere after it
                            for j, ev2 in enumerate(canonical_chain):
                                if compute_event_hash(ev2) == prev and j >= i:
                                    return True
    return False


def classify_fork(
    canonical_chain: List[Dict[str, Any]],
    non_canonical_chains: List[List[Dict[str, Any]]],
) -> str:
    """
    Classify fork type for reporting (RFC §6.4 / §6.5).

    Returns:
        STATUS_FORK_AFTER_FINALIZATION or STATUS_FORK_DETECTED
    """
    if detect_fork_after_finalization(canonical_chain, non_canonical_chains):
        return STATUS_FORK_AFTER_FINALIZATION
    return STATUS_FORK_DETECTED


def resolve_fork_canonical(
    branches: List[List[Dict[str, Any]]],
    raise_on_security_incident: bool = True,
) -> Dict[str, Any]:
    """
    High-level fork resolution using Canonical History Rule (RFC §6).

    This is the MANDATORY resolution method for AISS-1.1+.
    Applications MUST use this instead of resolve_fork_by_timestamp
    to ensure interoperability.

    Args:
        branches:                   List of event chains (branches)
        raise_on_security_incident: Raise exception on FORK_AFTER_FINALIZATION

    Returns:
        Dict with:
            canonical_chain:  The authoritative chain
            status:           Fork classification
            non_canonical:    Non-selected branches
            accountable:      Canonical chain length

    Raises:
        ForkAfterFinalizationError: If fork after TSA-finalized event
                                    (and raise_on_security_incident=True)

    Example:
        >>> result = resolve_fork_canonical([branch_a, branch_b])
        >>> canonical = result["canonical_chain"]
        >>> print(result["status"])  # FORK_DETECTED or FORK_AFTER_FINALIZATION
    """
    from aiss.logger import get_logger
    log = get_logger(__name__)

    canonical, non_canonical_ids = select_canonical_chain(branches)
    non_canonical = [branches[int(i)] for i in non_canonical_ids]

    status = classify_fork(canonical, non_canonical)

    if status == STATUS_FORK_AFTER_FINALIZATION:
        log.piqrypt_warn(
            f"FORK AFTER FINALIZATION detected — "
            f"{len(non_canonical)} non-canonical branch(es). "
            f"Security incident response required."
        )
        if raise_on_security_incident:
            raise ForkAfterFinalizationError(
                "Fork detected after TSA-finalized event. "
                "This indicates intentional or compromised behavior. "
                "Trigger security incident response."
            )
    else:
        log.piqrypt(
            f"Fork resolved: canonical chain selected "
            f"({len(canonical)} events, {_count_anchored_events(canonical)} TSA-anchored)"
        )

    return {
        "canonical_chain": canonical,
        "status": status,
        "non_canonical": non_canonical,
        "canonical_length": len(canonical),
        "tsa_anchored_events": _count_anchored_events(canonical),
    }


class ForkAfterFinalizationError(ForkDetected):
    """
    Fork occurred after a TSA-finalized event (RFC §6.5).

    This is a security incident — indicates intentional or compromised behavior.
    MUST trigger security incident response procedure.
    """
    def __init__(self, message: str = "Fork after finalization"):
        self.message = message
        super().__init__("FINALIZATION_BREACH", [])

    def __str__(self):
        return f"FORK_AFTER_FINALIZATION: {self.message}"


# ─── Public API ───────────────────────────────────────────────────────────────

__all__ = [
    # Existing
    "ForkDetector",
    "find_forks",
    "resolve_fork_by_timestamp",
    "resolve_fork_by_first_seen",
    "get_fork_resolution_info",
    # Canonical History Rule (RFC §6) — NEW in v1.2.0
    "STATUS_FORK_DETECTED",
    "STATUS_FORK_AFTER_FINALIZATION",
    "STATUS_NON_CANONICAL",
    "STATUS_CANONICAL",
    "select_canonical_chain",
    "detect_fork_after_finalization",
    "classify_fork",
    "resolve_fork_canonical",
    "ForkAfterFinalizationError",
]
