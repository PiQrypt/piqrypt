"""
RFC 3161 Trusted Timestamp Authority (TSA) Integration (RFC Section 7.1 / 8.2)

Provides legally admissible timestamps from independent third-party TSAs.
PRO feature — required for AISS-2 compliance.

Supported TSAs (free):
  - freetsa.org    (1000 req/day)
  - timestamp.digicert.com
  - tsa.entrust.net

Graceful degradation: if TSA unreachable, event is stored with local
timestamp and a note that trusted timestamp is pending.
"""

import hashlib
import base64
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from aiss.exceptions import PiQryptError
from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Exceptions ───────────────────────────────────────────────────────────────
class TSAError(PiQryptError):
    """TSA request failed."""
    pass


class TSAUnavailableError(TSAError):
    """TSA server not reachable — graceful degradation applies."""
    pass


class TSAVerificationError(TSAError):
    """TSA token verification failed."""
    pass


# ─── TSA Configuration ────────────────────────────────────────────────────────
DEFAULT_TSA_SERVERS = [
    {
        "name": "freetsa.org",
        "url": "https://freetsa.org/tsr",
        "policy": "free",
        "daily_limit": 1000,
    },
    {
        "name": "digicert",
        "url": "http://timestamp.digicert.com",
        "policy": "commercial",
        "daily_limit": None,
    },
]

DEFAULT_TIMEOUT = 10  # seconds


# ─── RFC 3161 Request building ────────────────────────────────────────────────
def _build_tsr_request(data_hash: bytes, hash_algorithm: str = "sha256") -> bytes:
    """
    Build a minimal RFC 3161 TimeStampReq (DER encoded).

    Structure (simplified):
        TimeStampReq ::= SEQUENCE {
            version     INTEGER { v1(1) },
            messageImprint MessageImprint,
            certReq     BOOLEAN DEFAULT FALSE
        }
        MessageImprint ::= SEQUENCE {
            hashAlgorithm AlgorithmIdentifier,
            hashedMessage OCTET STRING
        }

    This is a minimal implementation using raw DER encoding.
    For production, use python-pkcs11 or cryptography.x509.
    """
    # SHA-256 OID: 2.16.840.1.101.3.4.2.1
    sha256_oid = bytes([
        0x30, 0x0d,          # SEQUENCE (13 bytes)
        0x06, 0x09,          # OID (9 bytes)
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  # SHA-256 OID
        0x05, 0x00,          # NULL
    ])

    # MessageImprint
    hash_octet = bytes([0x04, len(data_hash)]) + data_hash
    msg_imprint = bytes([0x30, len(sha256_oid) + len(hash_octet)]) + sha256_oid + hash_octet

    # Version INTEGER 1
    version = bytes([0x02, 0x01, 0x01])

    # certReq BOOLEAN TRUE (we want the cert)
    cert_req = bytes([0x01, 0x01, 0xff])

    # TimeStampReq SEQUENCE
    inner = version + msg_imprint + cert_req
    tsr = bytes([0x30, len(inner)]) + inner

    return tsr


def _parse_tsr_response(response_bytes: bytes) -> Dict[str, Any]:
    """
    Parse RFC 3161 TimeStampResp minimally.

    Returns basic status and token info.
    Full DER parsing would require pyasn1 or cryptography library.
    """
    # Minimal check: first bytes should be SEQUENCE (0x30)
    if not response_bytes or response_bytes[0] != 0x30:
        raise TSAVerificationError("Invalid TSR response — not a DER SEQUENCE")

    # PKIStatusInfo is first element — status 0x00 = granted
    # This is a simplified check; proper implementation needs full ASN.1 parser
    status_granted = b'\x02\x01\x00'  # INTEGER 0 (granted)
    status_granted_with_mods = b'\x02\x01\x01'  # INTEGER 1 (grantedWithMods)

    response_b64 = base64.b64encode(response_bytes).decode("ascii")

    # Minimal status extraction
    is_granted = (
        status_granted in response_bytes[:50] or
        status_granted_with_mods in response_bytes[:50]
    )

    return {
        "status": "granted" if is_granted else "unknown",
        "token_b64": response_b64,
        "token_size_bytes": len(response_bytes),
    }


# ─── TSA request ──────────────────────────────────────────────────────────────
def request_timestamp(
    data: bytes,
    tsa_url: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT
) -> Dict[str, Any]:
    """
    Request a trusted timestamp from a TSA (RFC 3161).

    PRO feature. Gracefully degrades if TSA unreachable.

    Args:
        data: Bytes to timestamp (typically canonical event JSON)
        tsa_url: TSA URL (defaults to freetsa.org)
        timeout: Request timeout in seconds

    Returns:
        TSA token dict:
        {
            "authority": "freetsa.org",
            "timestamp": 1739382403,
            "token": "base64:...",
            "hash_algorithm": "sha256",
            "data_hash": "hex...",
            "status": "granted"
        }

    Raises:
        TSAUnavailableError: If TSA unreachable (caller should handle gracefully)
        TSAError: If TSA returns error status

    Example:
        >>> from aiss.rfc3161 import request_timestamp
        >>> from aiss.canonical import canonicalize
        >>> token = request_timestamp(canonicalize(event))
        >>> event["trusted_timestamp"] = token
    """
    from aiss.license import require_pro
    require_pro("trusted_timestamps")

    url = tsa_url or DEFAULT_TSA_SERVERS[0]["url"]
    tsa_name = next(
        (s["name"] for s in DEFAULT_TSA_SERVERS if s["url"] == url),
        url
    )

    # Hash the data
    data_hash = hashlib.sha256(data).digest()
    data_hash_hex = data_hash.hex()

    # Build request
    tsr_request = _build_tsr_request(data_hash)

    logger.info(f"Requesting trusted timestamp from {tsa_name}")

    try:
        req = urllib.request.Request(
            url,
            data=tsr_request,
            headers={
                "Content-Type": "application/timestamp-query",
                "Content-Length": str(len(tsr_request)),
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise TSAError(f"TSA returned HTTP {resp.status}")
            response_bytes = resp.read()

        parsed = _parse_tsr_response(response_bytes)

        result = {
            "authority": tsa_name,
            "url": url,
            "timestamp": int(time.time()),  # approx — real time in token
            "token": f"base64:{parsed['token_b64']}",
            "hash_algorithm": "sha256",
            "data_hash": data_hash_hex,
            "status": parsed["status"],
            "token_size_bytes": parsed["token_size_bytes"],
        }

        logger.info("Trusted timestamp received")

        return result

    except urllib.error.URLError as e:
        raise TSAUnavailableError(
            f"TSA '{tsa_name}' unreachable: {e}\n"
            "Event will be stored with local timestamp only.\n"
            "Run 'piqrypt timestamp --retry' later to add trusted timestamp."
        )
    except TSAError:
        raise
    except Exception as e:
        raise TSAError(f"TSA request failed: {e}")


def stamp_event_with_tsa(
    event: Dict[str, Any],
    tsa_url: Optional[str] = None,
    fail_gracefully: bool = True
) -> Dict[str, Any]:
    """
    Add a trusted timestamp to an already-signed event.

    The TSA signs the canonical form of the event (including its Ed25519
    signature), providing independent proof that the event existed at time T.

    Args:
        event: Already-signed AISS event
        tsa_url: TSA URL (defaults to freetsa.org)
        fail_gracefully: If True, return event without TSA on network error

    Returns:
        Event with 'trusted_timestamp' field added

    Example:
        >>> event = stamp_event(priv, agent_id, payload)
        >>> event = stamp_event_with_tsa(event)
        >>> event["trusted_timestamp"]["authority"]
        'freetsa.org'
    """
    from aiss.canonical import canonicalize

    canonical_bytes = canonicalize(event)

    try:
        tsa_token = request_timestamp(canonical_bytes, tsa_url=tsa_url)
        event = dict(event)
        event["trusted_timestamp"] = tsa_token

        logger.info("Trusted timestamp added to event")

    except TSAUnavailableError as e:
        if fail_gracefully:
            logger.warning(
                f"TSA unavailable — stored with local timestamp only: {e}"
            )
            event = dict(event)
            event["trusted_timestamp"] = {
                "status": "pending",
                "note": "TSA unavailable at stamp time. Retry with: piqrypt timestamp --retry",
                "local_fallback_at": int(time.time()),
            }
        else:
            raise

    return event


def verify_tsa_token(
    event: Dict[str, Any],
    expected_data: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Verify a TSA token embedded in an event.

    For full verification of the token's TSA signature, the cryptography
    library with x509 support is needed. This function performs available checks.

    Args:
        event: Event containing trusted_timestamp field
        expected_data: Optional original data to verify hash against

    Returns:
        Verification result dict
    """
    tsa = event.get("trusted_timestamp")

    if not tsa:
        return {
            "verified": False,
            "status": "NO_TSA_TOKEN",
            "message": "No trusted_timestamp field in event"
        }

    if tsa.get("status") == "pending":
        return {
            "verified": False,
            "status": "TSA_PENDING",
            "message": "Trusted timestamp was not obtained at stamp time"
        }

    # Verify hash if data provided
    if expected_data:
        data_hash = hashlib.sha256(expected_data).hexdigest()
        if data_hash != tsa.get("data_hash"):
            return {
                "verified": False,
                "status": "HASH_MISMATCH",
                "message": "TSA token data hash does not match event"
            }

    token_b64 = tsa.get("token", "").replace("base64:", "")

    if not token_b64:
        return {
            "verified": False,
            "status": "INVALID_TOKEN",
            "message": "TSA token is empty"
        }

    try:
        token_bytes = base64.b64decode(token_b64)
    except Exception:
        return {
            "verified": False,
            "status": "INVALID_TOKEN",
            "message": "TSA token is not valid base64"
        }

    # Try cryptography library for full verification
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509 import load_der_x509_certificate
        # Full TSA token verification would require pkcs7/cms parsing
        # For now: basic structure check
        is_valid_der = token_bytes[0] == 0x30

        return {
            "verified": is_valid_der,
            "status": "STRUCTURE_VALID" if is_valid_der else "INVALID_STRUCTURE",
            "authority": tsa.get("authority"),
            "token_timestamp": tsa.get("timestamp"),
            "message": (
                "Token structure valid. Full TSA signature verification "
                "requires: pip install cryptography"
                if is_valid_der
                else "Invalid DER structure in TSA token"
            )
        }
    except ImportError:
        # Basic check only
        is_valid_der = len(token_bytes) > 10 and token_bytes[0] == 0x30
        return {
            "verified": is_valid_der,
            "status": "BASIC_CHECK_ONLY",
            "authority": tsa.get("authority"),
            "token_timestamp": tsa.get("timestamp"),
            "message": (
                "Basic structure check passed. "
                "Install cryptography for full verification: pip install cryptography"
            )
        }


# ─── Retry pending timestamps ─────────────────────────────────────────────────
def retry_pending_timestamps(
    agent_id: str,
    tsa_url: Optional[str] = None
) -> Dict[str, int]:
    """
    Retry TSA timestamp for events where it failed at stamp time.

    Called by: piqrypt timestamp --retry

    Args:
        agent_id: Agent whose events to retry
        tsa_url: TSA URL to use

    Returns:
        {"retried": N, "succeeded": M, "failed": K}
    """
    from aiss.memory import load_events, store_event
    from aiss.canonical import canonicalize

    events = load_events(agent_id=agent_id)
    pending = [
        e for e in events
        if e.get("trusted_timestamp", {}).get("status") == "pending"
    ]

    retried = 0
    succeeded = 0
    failed = 0

    for event in pending:
        retried += 1
        try:
            canonical_bytes = canonicalize(event)
            token = request_timestamp(canonical_bytes, tsa_url=tsa_url)
            event["trusted_timestamp"] = token
            store_event(event)
            succeeded += 1
            logger.info(f"Timestamp retry succeeded for event {event.get('nonce', '')[:8]}")
        except (TSAError, TSAUnavailableError) as e:
            failed += 1
            logger.warning(f"Timestamp retry failed: {e}")

    return {"retried": retried, "succeeded": succeeded, "failed": failed}


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    "request_timestamp",
    "stamp_event_with_tsa",
    "verify_tsa_token",
    "retry_pending_timestamps",
    "DEFAULT_TSA_SERVERS",
    "TSAError",
    "TSAUnavailableError",
    "TSAVerificationError",
]
