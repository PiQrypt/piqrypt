# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
AISS-2.1 Hybrid Signatures (RFC AISS-1.1 Section 11.3)

Post-quantum + classical dual signatures for maximum security.
Includes mandatory fields for AISS-2.1 compliance (RFC §11.3):
  - trusted_timestamp:  RFC 3161 TSA token (required, may be pending)
  - authority_chain:    Delegation chain from legal entity to agent
  - signatures:         Ed25519 + ML-DSA-65 dual signatures

Cryptographic algorithms:
  - Ed25519   (classical, backward compatible)
  - ML-DSA-65 (post-quantum, NIST FIPS 204)

Both algorithms sign M' = "PiQrypt-AISS-2.1" || 0x00 || label_len || label || 0x00 || JCS-canonical-event,
where label = "Ed25519+ML-DSA-65". Domain separation prevents cross-protocol replay (RFC AISS-1.1 §11.3).
Canonicalization uses RFC 8785 JCS (rfc8785 package) — distinct from AISS-1 canonical.py.

Recommended by NIST until 2030+ for transition period.
"""

import time
import base64
import binascii
from typing import Dict, Any, Optional, List

from aiss.crypto import ed25519, dilithium
from aiss.canonical_aiss21 import canonicalize as _jcs_canonicalize
from aiss.stamp import generate_nonce
from aiss.logger import log_event_signed_alias, log_debug
from aiss.telemetry import track
from aiss.exceptions import CryptoBackendError

# Pro-tier enforcement — imported at module level so ImportError from within
# aiss.license (e.g. a missing dependency) is never silently swallowed.
# Only the case where the module itself is absent (aiss-standard MIT build)
# is tolerated: ModuleNotFoundError with e.name == "aiss.license".
try:
    from aiss.license import require_pro as _require_pro
except ModuleNotFoundError as _e:
    if _e.name == "aiss.license":
        _require_pro = None  # type: ignore[assignment]
    else:
        raise

# Domain-separation prefix for AISS-2.1 signed messages (RFC AISS-1.1 §11.3).
# M' = _DOMAIN_PREFIX + len(label) + label + len(ctx) + ctx + JCS-canonical
# Both Ed25519 and ML-DSA-65 sign the identical M'.
_DOMAIN_PREFIX = b"PiQrypt-AISS-2.1\x00"
_ALGO_LABEL = b"Ed25519+ML-DSA-65"


def _build_signed_message(jcs_bytes: bytes) -> bytes:
    """Return the domain-separated message M' that both signatures cover."""
    label = _ALGO_LABEL
    return _DOMAIN_PREFIX + bytes([len(label)]) + label + b"\x00" + jcs_bytes


def _pro_only(feature_name: str):
    """Decorator: enforce Pro tier when running inside piqrypt (ELv2).
    No-op in aiss-standard (MIT) where aiss.license is absent."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if _require_pro is not None:
                return _require_pro(feature_name)(func)(*args, **kwargs)
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
    Create AISS-2.1 event with hybrid signatures (Ed25519 + ML-DSA-65).

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
        AISS-2.1 event with dual signatures, authority chain, and TSA token

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
        'AISS-2.1'
        >>> "trusted_timestamp" in event
        True
    """
    # Check Dilithium backend availability
    if not dilithium or not dilithium.is_available():
        raise CryptoBackendError(
            "ML-DSA-65",
            "AISS-2 requires ML-DSA-65 backend.\n"
            "Install: pip install liboqs-python>=0.16"
        )

    # Generate nonce and timestamp if not provided
    if nonce is None:
        nonce = generate_nonce()

    if timestamp is None:
        timestamp = int(time.time())

    # Build event structure (without signatures)
    event = {
        "version": "AISS-2.1",
        "agent_id": agent_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "payload": payload,
        "previous_hash": previous_hash,
    }

    # Add authority chain if provided (RFC §11.3)
    if authority_chain:
        event["authority_chain"] = authority_chain

    # Canonicalize for signing via RFC 8785 JCS (AISS-2.1 path).
    # trusted_timestamp is NOT included — detached field added after signing.
    jcs_bytes = _jcs_canonicalize(event)
    signed_msg = _build_signed_message(jcs_bytes)

    log_debug("aiss2_signing", "Generating hybrid signatures", {
        "payload_type": payload.get("event_type", "unknown"),
        "jcs_size": len(jcs_bytes),
        "has_authority_chain": bool(authority_chain),
    })

    # Sign M' with Ed25519 (classical)
    sig_ed25519 = ed25519.sign(private_key_ed25519, signed_msg)

    # Sign M' with ML-DSA-65 (post-quantum) — same message as Ed25519
    sig_dilithium = dilithium.sign(private_key_dilithium, signed_msg)

    # Add dual signatures — AISS-2.1 uses "base64:<b64>" for both algorithms.
    # AISS-2.0 kept base58 (Ed25519) and plain base64 (ML-DSA); this is the new format.
    event["signatures"] = {
        "classical": {
            "algorithm": "Ed25519",
            "signature": "base64:" + base64.b64encode(sig_ed25519).decode('utf-8')
        },
        "post_quantum": {
            "algorithm": "ML-DSA-65",
            "signature": "base64:" + base64.b64encode(sig_dilithium).decode('utf-8')
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
          aiss_version="2.1",
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
    payload: Dict[str, Any],
    public_key_pq: Optional[bytes] = None,
    tsa_stamp_after: bool = True,
) -> Dict[str, Any]:
    """
    Crée l'événement genèse AISS-2.1 avec signatures hybrides.

    Lorsque public_key_pq est fourni (chemin recommandé) :
    - Vérifie que agent_id == derive_agent_id_aiss21(public_key_ed25519, public_key_pq).
    - Calcule le hash genèse : SHA-512(b"PiQrypt-AISS-2.1-genesis\\x00" || agent_id)
      (128 caractères hex, AISS-2.1, spécification à rédiger — chantier G).

    Lorsque public_key_pq est absent (compatibilité ascendante) :
    - Hash genèse : SHA-256(public_key_ed25519) (64 caractères hex, convention AISS-1).
    - Réservé aux migrations ; le nouveau code doit toujours fournir public_key_pq.

    Args:
        private_key_ed25519:   Clé privée Ed25519
        private_key_dilithium: Clé privée ML-DSA-65
        public_key_ed25519:    Clé publique Ed25519 (hash genèse legacy)
        agent_id:              Agent ID (doit correspondre aux clés si public_key_pq fourni)
        payload:               Données de l'événement genèse
        public_key_pq:         Clé publique ML-DSA-65 (chemin AISS-2.1 recommandé)
        tsa_stamp_after:       Demander un horodatage TSA après signature (défaut : True)

    Returns:
        Événement genèse AISS-2.1

    Raises:
        ValueError: Si agent_id incohérent avec les clés (public_key_pq fourni)
    """
    import hashlib as _hashlib
    from aiss.canonical import hash_bytes
    from aiss.identity import derive_agent_id_aiss21

    if public_key_pq is not None:
        computed_id = derive_agent_id_aiss21(public_key_ed25519, public_key_pq)
        if computed_id != agent_id:
            raise ValueError(
                f"agent_id incohérent avec les clés : fourni {agent_id!r}, "
                f"calculé {computed_id!r}"
            )
        # AISS-2.1 genesis: SHA-512 domain-separated over agent_id
        data = b"PiQrypt-AISS-2.1-genesis\x00" + agent_id.encode("ascii")
        genesis_hash = _hashlib.sha512(data).hexdigest()
    else:
        # Chemin legacy : SHA-256 de la clé publique Ed25519 (convention AISS-1)
        genesis_hash = hash_bytes(public_key_ed25519)

    return stamp_event_aiss2_hybrid(
        private_key_ed25519,
        private_key_dilithium,
        agent_id,
        payload,
        previous_hash=genesis_hash,
        tsa_stamp_after=tsa_stamp_after,
    )


def verify_aiss2_hybrid(event: Dict[str, Any], public_key_ed25519: bytes, public_key_dilithium: bytes) -> bool:
    """
    Verify AISS-2.0 or AISS-2.1 hybrid signatures, dispatching on event["version"].

    - AISS-2.0: verifies using AISS-1 canonical.py (stdlib), Ed25519 base58,
      ML-DSA-65 plain base64 — unchanged behaviour from 1.9.2.
    - AISS-2.1: verifies using RFC 8785 JCS + domain-separated M'.
    - Any other version: raises InvalidSignatureError.

    Args:
        event: AISS-2.x event dict
        public_key_ed25519: Ed25519 public key
        public_key_dilithium: ML-DSA-65 public key

    Returns:
        True if both signatures are valid

    Raises:
        InvalidSignatureError: If either signature invalid or version unsupported
    """
    from aiss.exceptions import InvalidSignatureError

    version = event.get("version", "")
    if version == "AISS-2.0":
        return _verify_aiss2_0(event, public_key_ed25519, public_key_dilithium)
    elif version == "AISS-2.1":
        return _verify_aiss2_1(event, public_key_ed25519, public_key_dilithium)
    else:
        raise InvalidSignatureError(
            f"Unsupported AISS version for hybrid verification: {version!r}. "
            "Expected 'AISS-2.0' or 'AISS-2.1'."
        )


def _verify_aiss2_0(
    event: Dict[str, Any],
    public_key_ed25519: bytes,
    public_key_dilithium: bytes,
) -> bool:
    """AISS-2.0 verification path (1.9.2 behaviour, never changed)."""
    from aiss.exceptions import InvalidSignatureError
    from aiss.canonical import canonicalize as _canonical_v1

    signatures = event.get("signatures")
    if not signatures:
        raise InvalidSignatureError("AISS-2.0 event missing signatures field")

    classical = signatures.get("classical")
    post_quantum = signatures.get("post_quantum")
    if not classical or not post_quantum:
        raise InvalidSignatureError("AISS-2.0 event missing classical or post_quantum signature")

    event_copy = {k: v for k, v in event.items() if k not in ("signatures", "trusted_timestamp")}
    canonical = _canonical_v1(event_copy)

    try:
        sig_ed25519 = ed25519.decode_base58(classical["signature"])
        ed25519.verify(public_key_ed25519, canonical, sig_ed25519)
    except Exception as exc:
        raise InvalidSignatureError(f"Ed25519 signature verification failed: {exc}")

    try:
        sig_dilithium = base64.b64decode(post_quantum["signature"])
        if not dilithium.verify(public_key_dilithium, canonical, sig_dilithium):
            raise InvalidSignatureError("ML-DSA-65 signature verification failed")
    except Exception as exc:
        raise InvalidSignatureError(f"ML-DSA-65 signature verification failed: {exc}")

    log_debug("aiss2_verified", "AISS-2.0 hybrid signatures verified", {"ed25519": "valid", "ml_dsa_65": "valid"})
    return True


def _verify_aiss2_1(
    event: Dict[str, Any],
    public_key_ed25519: bytes,
    public_key_dilithium: bytes,
) -> bool:
    """AISS-2.1 verification: RFC 8785 JCS + domain-separated M'."""
    from aiss.exceptions import InvalidSignatureError

    signatures = event.get("signatures")
    if not signatures:
        raise InvalidSignatureError("AISS-2.1 event missing signatures field")

    classical = signatures.get("classical")
    post_quantum = signatures.get("post_quantum")

    if not classical or not post_quantum:
        raise InvalidSignatureError("AISS-2.1 event missing classical or post_quantum signature")

    # Reconstruct M': strip detached fields, JCS-canonicalize, prepend domain prefix.
    event_copy = {k: v for k, v in event.items() if k not in ("signatures", "trusted_timestamp")}
    jcs_bytes = _jcs_canonicalize(event_copy)
    signed_msg = _build_signed_message(jcs_bytes)

    # Verify Ed25519 — AISS-2.1 uses "base64:<b64>" encoding (strict alphabet).
    try:
        raw_ed = classical["signature"]
        if not raw_ed.startswith("base64:"):
            raise InvalidSignatureError("Ed25519 signature must use 'base64:' prefix in AISS-2.1")
        try:
            sig_ed25519 = base64.b64decode(raw_ed[7:], validate=True)
        except binascii.Error as exc:
            raise InvalidSignatureError(f"Ed25519 signature contains invalid base64 characters: {exc}")
        ed25519.verify(public_key_ed25519, signed_msg, sig_ed25519)
    except InvalidSignatureError:
        raise
    except Exception as e:
        raise InvalidSignatureError(f"Ed25519 signature verification failed: {e}")

    # Verify ML-DSA-65 — AISS-2.1 uses "base64:<b64>" encoding (strict alphabet).
    try:
        raw_pq = post_quantum["signature"]
        if not raw_pq.startswith("base64:"):
            raise InvalidSignatureError("ML-DSA-65 signature must use 'base64:' prefix in AISS-2.1")
        try:
            sig_dilithium = base64.b64decode(raw_pq[7:], validate=True)
        except binascii.Error as exc:
            raise InvalidSignatureError(f"ML-DSA-65 signature contains invalid base64 characters: {exc}")
        if not dilithium.verify(public_key_dilithium, signed_msg, sig_dilithium):
            raise InvalidSignatureError("ML-DSA-65 signature verification failed")
    except InvalidSignatureError:
        raise
    except Exception as e:
        raise InvalidSignatureError(f"ML-DSA-65 signature verification failed: {e}")

    log_debug("aiss2_verified", "AISS-2.1 hybrid signatures verified", {"ed25519": "valid", "ml_dsa_65": "valid"})
    return True


# Public API
__all__ = [
    "stamp_event_aiss2_hybrid",
    "stamp_genesis_event_aiss2_hybrid",
    "verify_aiss2_hybrid",
]
