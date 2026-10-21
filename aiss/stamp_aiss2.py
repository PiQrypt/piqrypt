# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
AISS-2 Hybrid Signatures (RFC AISS-1.1 Section 11.3)

Post-quantum + classical dual signatures for maximum security.
Includes mandatory fields for AISS-2 compliance (RFC §11.3):
  - trusted_timestamp:  RFC 3161 TSA token (required, may be pending)
  - authority_chain:    Delegation chain from legal entity to agent
  - signatures:         Ed25519 + ML-DSA-65 dual signatures

Cryptographic algorithms:
  - Ed25519   (classical, backward compatible)
  - ML-DSA-65 (post-quantum, NIST FIPS 204)

Recommended by NIST until 2030+ for transition period.
"""

import time
import base64
from typing import Dict, Any, Optional, List

from aiss.crypto import ed25519, dilithium
from aiss.canonical import canonicalize
from aiss.stamp import generate_nonce
from aiss.logger import log_event_signed_alias, log_debug
from aiss.telemetry import track
from aiss.exceptions import CryptoBackendError


def _pro_only(feature_name: str):
    """Decorator: enforce Pro tier when running inside piqrypt (ELv2).
    No-op in aiss-standard (MIT) where license.py is absent."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                from aiss.license import require_pro as _rp
                return _rp(feature_name)(func)(*args, **kwargs)
            except ImportError:
                return func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    return decorator


@_pro_only("AISS-2 hybrid signatures")
def stamp_event_aiss2_hybrid(
    private_key_ed25519: bytes,
    private_key_dilithium: bytes,
    agent_id: str,
    payload: Dict[str, Any],
    previous_hash: Optional[str] = None,
    nonce: Optional[str] = None,
    timestamp: Optional[int] = None,
    authority_chain: Optional[List[Dict[str, Any]]] = None,
    tsa_stamp_after: bool = True,
) -> Dict[str, Any]:
    """
    Create AISS-2 event with hybrid signatures (Ed25519 + Dilithium3).

    RFC §11.3 mandatory AISS-2 fields added:
      - authority_chain:   Delegation chain (optional but recommended)
      - trusted_timestamp: RFC 3161 TSA token (requested automatically if Pro)

    Args:
        private_key_ed25519:   Ed25519 private key (32 bytes)
        private_key_dilithium: Dilithium3 private key
        agent_id:              Agent ID
        payload:               Event data
        previous_hash:         Hash of previous event (None for genesis)
        nonce:                 Optional nonce (auto-generated if None)
        timestamp:             Optional Unix timestamp (auto-generated if None)
        authority_chain:       Optional list of authority statements (RFC §5)
        tsa_stamp_after:       Auto-request TSA timestamp after signing (default: True)

    Returns:
        AISS-2.0 event with dual signatures, authority chain, and TSA token

    Raises:
        AISSError:           If Pro license not active
        CryptoBackendError:  If Dilithium backend not available

    Example:
        >>> event = stamp_event_aiss2_hybrid(
        ...     priv_ed25519, priv_dilithium, agent_id,
        ...     {"action": "contract_signed", "value": 1000000},
        ...     authority_chain=[authority_stmt]
        ... )
        >>> event["version"]
        'AISS-2.0'
        >>> "trusted_timestamp" in event
        True
    """
    # Check Dilithium backend availability
    if not dilithium or not dilithium.is_available():
        raise CryptoBackendError(
            "ML-DSA-65",
            "AISS-2 requires ML-DSA-65 backend.\n"
            "Install: pip install liboqs-python>=0.12.0"
        )

    # Generate nonce and timestamp if not provided
    if nonce is None:
        nonce = generate_nonce()

    if timestamp is None:
        timestamp = int(time.time())

    # Build event structure (without signatures)
    event = {
        "version": "AISS-2.0",
        "agent_id": agent_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "payload": payload,
        "previous_hash": previous_hash,
    }

    # Add authority chain if provided (RFC §11.3)
    if authority_chain:
        event["authority_chain"] = authority_chain

    # Canonicalize for signing — trusted_timestamp is NOT included (it is a detached field
    # added after signing so that the TSA token does not invalidate the signatures).
    canonical = canonicalize(event)

    log_debug("aiss2_signing", "Generating hybrid signatures", {
        "payload_type": payload.get("event_type", "unknown"),
        "canonical_size": len(canonical),
        "has_authority_chain": bool(authority_chain),
    })

    # Sign with Ed25519 (classical)
    sig_ed25519 = ed25519.sign(private_key_ed25519, canonical)

    # Sign with Dilithium3 (post-quantum)
    sig_dilithium = dilithium.sign(private_key_dilithium, canonical)

    # Add dual signatures
    event["signatures"] = {
        "classical": {
            "algorithm": "Ed25519",
            "signature": ed25519.encode_base58(sig_ed25519)
        },
        "post_quantum": {
            "algorithm": "ML-DSA-65",
            "signature": base64.b64encode(sig_dilithium).decode('utf-8')
        }
    }

    # Add trusted_timestamp placeholder AFTER signing (detached — not covered by signatures)
    event["trusted_timestamp"] = {
        "status": "pending",
        "rfc3161_token": None,
        "tsa_id": None,
        "timestamp": None,
    }

    # Request TSA timestamp (Pro feature — graceful degradation if offline)
    if tsa_stamp_after:
        try:
            from aiss.rfc3161 import stamp_event_with_tsa
            event = stamp_event_with_tsa(event)
        except Exception as e:
            log_debug("aiss2_tsa_skip", "TSA timestamp deferred", {"reason": str(e)})
            # Leave trusted_timestamp.status = "pending"

    # Logging
    log_event_signed_alias(agent_id, payload.get("event_type", "unknown"), nonce)
    log_debug("aiss2_signed", "Hybrid signatures generated", {
        "ed25519_size": len(sig_ed25519),
        "dilithium_size": len(sig_dilithium),
        "tsa_status": event.get("trusted_timestamp", {}).get("status", "unknown"),
    })

    # Telemetry
    track("event_signed",
          aiss_version="2.0",
          hybrid=True,
          payload_type=payload.get("event_type"),
          has_tsa=event.get("trusted_timestamp", {}).get("status") == "verified")

    return event


@_pro_only("AISS-2 genesis events")
def stamp_genesis_event_aiss2_hybrid(
    private_key_ed25519: bytes,
    private_key_dilithium: bytes,
    public_key_ed25519: bytes,
    agent_id: str,
    payload: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Create AISS-2 genesis event with hybrid signatures

    Args:
        private_key_ed25519: Ed25519 private key
        private_key_dilithium: Dilithium3 private key
        public_key_ed25519: Ed25519 public key (for genesis hash)
        agent_id: Agent ID
        payload: Genesis event data

    Returns:
        AISS-2.0 genesis event
    """
    from aiss.canonical import hash_bytes

    # Compute genesis previous_hash from Ed25519 public key
    # (maintains compatibility with AISS-1)
    genesis_hash = hash_bytes(public_key_ed25519)

    return stamp_event_aiss2_hybrid(
        private_key_ed25519,
        private_key_dilithium,
        agent_id,
        payload,
        previous_hash=genesis_hash
    )


def verify_aiss2_hybrid(event: Dict[str, Any], public_key_ed25519: bytes, public_key_dilithium: bytes) -> bool:
    """
    Verify AISS-2 hybrid signatures

    Args:
        event: AISS-2.0 event
        public_key_ed25519: Ed25519 public key
        public_key_dilithium: Dilithium3 public key

    Returns:
        True if both signatures valid

    Raises:
        InvalidSignatureError: If either signature invalid
    """
    from aiss.exceptions import InvalidSignatureError

    # Extract signatures
    signatures = event.get("signatures")
    if not signatures:
        raise InvalidSignatureError("AISS-2 event missing signatures field")

    classical = signatures.get("classical")
    post_quantum = signatures.get("post_quantum")

    if not classical or not post_quantum:
        raise InvalidSignatureError("AISS-2 event missing classical or post_quantum signature")

    # Reconstruct the signed content: remove signatures and trusted_timestamp
    # (trusted_timestamp is a detached field — it was never covered by the signatures)
    event_copy = {k: v for k, v in event.items() if k not in ("signatures", "trusted_timestamp")}

    # Canonicalize
    canonical = canonicalize(event_copy)

    # Verify Ed25519
    try:
        sig_ed25519 = ed25519.decode_base58(classical["signature"])
        ed25519.verify(public_key_ed25519, canonical, sig_ed25519)
    except Exception as e:
        raise InvalidSignatureError(f"Ed25519 signature verification failed: {e}")

    # Verify Dilithium3
    try:
        sig_dilithium = base64.b64decode(post_quantum["signature"])
        if not dilithium.verify(public_key_dilithium, canonical, sig_dilithium):
            raise InvalidSignatureError("Dilithium3 signature verification failed")
    except Exception as e:
        raise InvalidSignatureError(f"Dilithium3 signature verification failed: {e}")

    log_debug("aiss2_verified", "Hybrid signatures verified", {
        "ed25519": "valid",
        "ml_dsa_65": "valid"
    })

    return True


# Public API
__all__ = [
    "stamp_event_aiss2_hybrid",
    "stamp_genesis_event_aiss2_hybrid",
    "verify_aiss2_hybrid",
]
