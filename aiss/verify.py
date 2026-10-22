# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
Signature and Chain Verification

This module implements complete verification logic:
- Signature verification (RFC Section 7.2)
- Chain integrity (RFC Section 9)
- Fork detection (RFC Section 10)
- Replay detection (RFC Section 11)
"""

from typing import Dict, Any, List, Optional

from aiss.crypto import ed25519
from aiss.canonical import canonicalize
from aiss.chain import compute_event_hash, verify_chain_linkage, verify_monotonic_timestamps
from aiss.fork import ForkDetector
from aiss.replay import NonceStore
from aiss.exceptions import (
    InvalidSignatureError,
    InvalidChainError,
)


def verify_signature(event: Dict[str, Any], public_key: bytes) -> bool:
    """
    Verify Ed25519 signature on event (RFC Section 7.2).

    Validates that:
    1. Event has signature field
    2. Signature is valid Base58
    3. Signature verifies against canonical event (without signature field)

    Args:
        event: Event dict with signature
        public_key: Agent's public key bytes

    Returns:
        True if signature is valid

    Raises:
        InvalidSignatureError: If signature verification fails

    Example:
        >>> verify_signature(event, public_key)
        True
    """
    # Extract signature
    signature_b58 = event.get('signature')
    if not signature_b58:
        raise InvalidSignatureError("Event missing signature field")

    try:
        signature = ed25519.decode_base64(signature_b58)
    except Exception as e:
        raise InvalidSignatureError(f"Invalid signature encoding: {e}")

    # Reconstruct the signed content: remove signature and trusted_timestamp
    # (trusted_timestamp is added after signing — it is not covered by the signature)
    event_copy = {k: v for k, v in event.items() if k not in ("signature", "trusted_timestamp")}

    # Canonicalize
    canonical = canonicalize(event_copy)

    # Verify signature
    try:
        return ed25519.verify(public_key, canonical, signature)
    except InvalidSignatureError:
        raise
    except Exception as e:
        raise InvalidSignatureError(f"Signature verification error: {e}")


def verify_event(
    event: Dict[str, Any],
    public_key: bytes,
    previous_event: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Verify complete event validity.

    Checks:
    - Signature validity
    - Hash chain linkage (if previous_event provided)
    - Required fields present

    Args:
        event: Event to verify
        public_key: Agent's public key
        previous_event: Previous event in chain (None for genesis)

    Returns:
        True if event is valid

    Raises:
        InvalidSignatureError: If signature invalid
        InvalidChainError: If chain linkage broken
    """
    # Verify signature
    verify_signature(event, public_key)

    # Check required fields
    required = ['version', 'agent_id', 'timestamp', 'nonce', 'payload', 'previous_hash']
    for field in required:
        if field not in event:
            raise InvalidChainError(f"Missing required field: {field}")

    # Verify chain linkage if previous event provided
    if previous_event:
        expected_hash = compute_event_hash(previous_event)
        actual_hash = event.get('previous_hash')

        if actual_hash != expected_hash:
            raise InvalidChainError(
                f"Chain linkage broken: expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
            )

    return True


# ─── Formes d'identité AISS-2.1 (B.4) ────────────────────────────────────────

def _identity_form(identity: Dict[str, Any]) -> str:
    """
    Classe un document d'identité :
      - "classical" : public_key seul (AISS-1, comportement inchangé)
      - "upgraded"  : identité AISS-1 mise à niveau (public_key + public_key_pq + binding)
      - "native"    : identité hybride native (public_key_classical + public_key_pq)

    Raises:
        InvalidChainError: document ambigu (public_key_classical avec binding ou public_key)
    """
    if "public_key_classical" in identity:
        if "binding" in identity or "public_key" in identity:
            raise InvalidChainError(
                "Ambiguous identity: public_key_classical cannot be combined with "
                "binding or public_key"
            )
        return "native"
    if "binding" in identity or "public_key_pq" in identity:
        return "upgraded"
    return "classical"


def _resolve_aiss21_identity(identity, form, public_key_pq_param):
    """
    Valide une identité AISS-2.1 (dérivation des deux clés, ou liaison valide) et
    renvoie (public_key_ed25519, public_key_pq, binding_assurance).

    Raises:
        InvalidChainError: identité invalide, ou public_key_pq fourni différent de
            celui de l'identité (jamais de choix silencieux)
    """
    from aiss.identity import IdentityBindingError, identity_binding_assurance, _decode_b64_prefixed

    try:
        assurance = identity_binding_assurance(identity)
        source = identity if form == "native" else identity["binding"]
        public_key = _decode_b64_prefixed(source["public_key_classical"], "public_key_classical", 32)
        public_key_pq = _decode_b64_prefixed(source["public_key_pq"], "public_key_pq", 1952)
    except (IdentityBindingError, KeyError, TypeError) as e:
        raise InvalidChainError(f"Invalid AISS-2.1 identity: {e}")

    if public_key_pq_param is not None and bytes(public_key_pq_param) != public_key_pq:
        raise InvalidChainError(
            "public_key_pq parameter differs from the identity's ML-DSA-65 key"
        )
    return public_key, public_key_pq, assurance


def _check_aiss21_events(events: List[Dict[str, Any]], identity: Dict[str, Any], form: str) -> None:
    """agent_id des événements et règle anti-downgrade (erreur avec l'index)."""
    agent_id = identity.get("agent_id")
    seen_aiss21 = False
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            raise InvalidChainError("Event must be an object", i)
        if event.get("agent_id") != agent_id:
            raise InvalidChainError("Event agent_id does not match identity agent_id", i)
        is_21 = event.get("version") == "AISS-2.1"
        if form == "native" and not is_21:
            raise InvalidChainError(
                "Downgrade: a native hybrid identity only accepts AISS-2.1 events", i)
        if form == "upgraded":
            if seen_aiss21 and not is_21:
                raise InvalidChainError(
                    "Downgrade: no AISS-1 or AISS-2.0 event may follow the first AISS-2.1 event", i)
            seen_aiss21 = seen_aiss21 or is_21


def verify_chain(
    events: List[Dict[str, Any]],
    identity: Dict[str, Any],
    check_forks: bool = True,
    check_replay: bool = True,
    check_timestamps: bool = True,
    public_key_pq: Optional[bytes] = None,
) -> bool:
    """
    Verify complete event chain integrity (RFC Section 15.1).

    Performs comprehensive validation:
    1. All signatures valid
    2. Hash chain continuity
    3. No forks (optional)
    4. No replay attacks (optional)
    5. Monotonic timestamps (optional)

    Args:
        events: List of events in chronological order
        identity: Agent identity document
        check_forks: Enable fork detection (default: True)
        check_replay: Enable replay detection (default: True)
        check_timestamps: Enable timestamp validation (default: True)
        public_key_pq: ML-DSA-65 public key bytes — required for AISS-2 events;
            if the chain contains AISS-2 events and this is None, raises InvalidChainError

    Returns:
        True if chain is valid

    Raises:
        InvalidSignatureError: If any signature invalid
        InvalidChainError: If chain linkage broken
        ForkDetected: If fork condition found
        ReplayAttackDetected: If duplicate nonce found

    Example:
        >>> verify_chain(events, agent_identity)
        True
    """
    if not isinstance(events, (list, tuple)):
        raise InvalidChainError(
            f"events must be a list of event objects, got {type(events).__name__}")
    if not isinstance(identity, dict):
        raise InvalidChainError(
            f"identity must be an object, got {type(identity).__name__}")

    if not events:
        return True

    form = _identity_form(identity)
    if form != "classical":
        # AISS-2.1 identity (upgraded or native hybrid): keys come from the validated identity
        public_key, public_key_pq, _ = _resolve_aiss21_identity(identity, form, public_key_pq)
        _check_aiss21_events(events, identity, form)
    else:
        # Extract public key from identity
        public_key_b58 = identity.get('public_key')
        if not public_key_b58:
            raise InvalidChainError("Identity missing public_key field")

        try:
            public_key = ed25519.decode_base64(public_key_b58)
        except Exception as e:
            raise InvalidChainError(f"Invalid public key encoding: {e}")

    # Verify all signatures
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            raise InvalidChainError("Event must be an object", i)
        version = event.get("version", "")
        if not isinstance(version, str):
            raise InvalidChainError("Event version must be a string", i)
        if version.startswith("AISS-2"):
            if public_key_pq is None:
                raise InvalidChainError(
                    f"Event {i} is AISS-2 but no public_key_pq provided — "
                    "pass the ML-DSA-65 public key to verify_chain()",
                    i,
                )
            try:
                from aiss.stamp_aiss2 import verify_aiss2_hybrid
                verify_aiss2_hybrid(event, public_key, public_key_pq)
            except Exception as e:
                raise InvalidChainError(
                    f"AISS-2 signature verification failed at event {i}: {e}", i
                )
        else:
            try:
                verify_signature(event, public_key)
            except InvalidSignatureError as e:
                raise InvalidChainError(f"Signature verification failed at event {i}: {e}", i)

    # Verify chain linkage
    verify_chain_linkage(events)

    # Check timestamps if requested
    if check_timestamps:
        verify_monotonic_timestamps(events)

    # Check for forks if requested
    if check_forks:
        detector = ForkDetector()
        detector.detect_and_raise(events)

    # Check for replay attacks if requested
    if check_replay:
        nonce_store = NonceStore()
        for event in events:
            agent_id = event.get('agent_id')
            nonce = event.get('nonce')
            timestamp = event.get('timestamp')

            if agent_id and nonce:
                nonce_store.check_and_add(agent_id, nonce, timestamp)

    return True


def get_verification_report(
    events: List[Dict[str, Any]],
    identity: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate detailed verification report.

    Returns comprehensive validation results without raising exceptions.

    Args:
        events: List of events
        identity: Agent identity

    Returns:
        Verification report dict with:
        - valid: Overall validity (bool)
        - signatures_valid: All signatures valid (bool)
        - chain_valid: Chain linkage valid (bool)
        - forks_detected: List of fork hashes
        - replay_attacks: List of replay attack nonces
        - errors: List of error messages
    """
    report = {
        "valid": True,
        "signatures_valid": True,
        "chain_valid": True,
        "timestamps_valid": True,
        "forks_detected": [],
        "replay_attacks": [],
        "errors": [],
        "binding_assurance": None,  # "hybrid", "classical_only" or None (classical identity)
    }

    if not events:
        return report

    # Verify signatures
    try:
        form = _identity_form(identity)
        if form == "classical":
            public_key = ed25519.decode_base64(identity.get('public_key'))
            for i, event in enumerate(events):
                verify_signature(event, public_key)
        else:
            from aiss.stamp_aiss2 import verify_aiss2_hybrid
            public_key, public_key_pq, assurance = _resolve_aiss21_identity(identity, form, None)
            report["binding_assurance"] = assurance
            _check_aiss21_events(events, identity, form)
            for i, event in enumerate(events):
                if str(event.get("version", "")).startswith("AISS-2"):
                    verify_aiss2_hybrid(event, public_key, public_key_pq)
                else:
                    verify_signature(event, public_key)
    except Exception as e:
        report["signatures_valid"] = False
        report["valid"] = False
        report["errors"].append(f"Signature error: {e}")

    # Verify chain
    try:
        verify_chain_linkage(events)
    except Exception as e:
        report["chain_valid"] = False
        report["valid"] = False
        report["errors"].append(f"Chain error: {e}")

    # Verify timestamps
    try:
        verify_monotonic_timestamps(events)
    except Exception as e:
        report["timestamps_valid"] = False
        report["valid"] = False
        report["errors"].append(f"Timestamp error: {e}")

    # Check forks
    try:
        from aiss.fork import find_forks
        forks = find_forks(events)
        if forks:
            report["forks_detected"] = [f.hash for f in forks]
            report["valid"] = False
    except Exception as e:
        report["errors"].append(f"Fork detection error: {e}")

    # Check replay attacks
    try:
        from aiss.replay import detect_replay_attacks
        attacks = detect_replay_attacks(events)
        if attacks:
            report["replay_attacks"] = [a.nonce for a in attacks]
            report["valid"] = False
    except Exception as e:
        report["errors"].append(f"Replay detection error: {e}")

    return report


# Public API (see extended __all__ at end of file)


def verify_audit_chain(audit_data: Dict[str, Any]) -> bool:
    """
    Verify an audit chain document (used by certification service).

    Accepts an audit dict with 'events' list and optional 'agent_identity'.
    Validates event structure and chain linkage without requiring signatures
    (events may not include public key in audit context).

    Args:
        audit_data: Audit document dict with 'events' key

    Returns:
        True if chain structure is valid

    Raises:
        InvalidChainError: If chain linkage is broken or events are malformed
    """
    from aiss.chain import verify_chain_linkage

    events = audit_data.get("events", [])
    if not events:
        return True

    # If identity with public key is provided, do full signature verification
    identity = audit_data.get("agent_identity") or audit_data.get("identity")
    if isinstance(identity, dict) and any(
        field in identity
        for field in ("public_key", "public_key_classical", "public_key_pq", "binding")
    ):
        return verify_chain(events, identity, check_forks=False, check_replay=False)

    # Otherwise verify chain linkage only (structural integrity)
    verify_chain_linkage(events)
    return True


__all__ = [
    "verify_signature",
    "verify_event",
    "verify_chain",
    "verify_audit_chain",
    "get_verification_report",
]
