# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
RFC 3161 trusted timestamps (TSA tokens).

A TSA token proves that a given digest existed at the time (genTime) read from a token signed
by a Time-Stamp Authority. Requesting a token needs no extra dependency. VERIFYING one needs
the optional extra:  pip install "piqrypt[timestamp]"  (rfc3161-client).

What is timestamped:
  - AISS-2.1 events: the chain hash of the event (compute_event_hash, SHA-512, 64 bytes),
    hashAlgorithm sha512. The imprint is recomputed from the event at verification time.
  - AISS-1 and AISS-2.0 events: SHA-256 of the AISS-1 canonical form of the event without
    trusted_timestamp (unchanged behaviour).

The trusted_timestamp field is DETACHED: no signature covers it, so its presence, its
self-declared "status" and any local time prove nothing. Only verify_tsa_token(...)
["status"] == "verified" does, and only relative to the trust roots the caller configured.
No root certificate is shipped with the package. Certificate revocation (OCSP, CRL) is not
checked. A token from a free public TSA such as freetsa.org is not a qualified electronic time
stamp (eIDAS) and this module makes no claim about legal value.

Graceful degradation: if the TSA is unreachable the event is stored with a "pending"
trusted_timestamp that retry_pending_timestamps can complete later.

Compatibility note: with rfc3161-client 1.0.9, responses from DigiCert and Entrust (observed
2026-10-22) cannot be parsed (non-canonical DER SET ordering in the embedded certificates), so
their tokens verify as "invalid" (fail closed). freetsa.org tokens verify.
"""

import base64
import binascii
import hashlib
import os
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Union

from aiss.exceptions import PiQryptError
from aiss.logger import get_logger
from aiss.tsa_token import tsa_token_value

logger = get_logger(__name__)


# ─── Exceptions ───────────────────────────────────────────────────────────────
class TSAError(PiQryptError):
    """TSA request failed."""
    pass


class TSAUnavailableError(TSAError):
    """TSA server not reachable, graceful degradation applies."""
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
TRUST_ROOTS_ENV = "PIQRYPT_TSA_TRUST_ROOTS"

_OID_TLV = {
    "sha256": bytes.fromhex("0609608648016503040201"),
    "sha384": bytes.fromhex("0609608648016503040202"),
    "sha512": bytes.fromhex("0609608648016503040203"),
}
_OID_DOTTED = {
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}
_DIGEST_SIZE = {"sha256": 32, "sha384": 48, "sha512": 64}


# ─── DER helpers and request building ────────────────────────────────────────
def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_integer(n: int) -> bytes:
    return _der(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big"))


def _build_tsr_request(
    data_hash: bytes,
    hash_algorithm: str = "sha256",
    nonce: Optional[int] = None,
    cert_req: bool = True,
) -> bytes:
    """
    Build an RFC 3161 TimeStampReq (DER).

        TimeStampReq ::= SEQUENCE { version INTEGER {v1(1)}, messageImprint, nonce INTEGER
                                    OPTIONAL, certReq BOOLEAN DEFAULT FALSE }

    `data_hash` is the digest to timestamp; its size must match `hash_algorithm`
    (sha256, sha384 or sha512). certReq asks the TSA to embed its certificates, which
    verification needs.
    """
    if hash_algorithm not in _OID_TLV:
        raise ValueError(f"unsupported hash algorithm {hash_algorithm!r}")
    if len(data_hash) != _DIGEST_SIZE[hash_algorithm]:
        raise ValueError(f"{hash_algorithm} digest must be {_DIGEST_SIZE[hash_algorithm]} bytes")
    if nonce is not None and nonce < 0:
        raise ValueError("nonce must not be negative")
    algorithm_identifier = _der(0x30, _OID_TLV[hash_algorithm] + b"\x05\x00")
    message_imprint = _der(0x30, algorithm_identifier + _der(0x04, data_hash))
    body = _der(0x02, b"\x01") + message_imprint
    if nonce is not None:
        body += _der_integer(nonce)
    if cert_req:
        body += _der(0x01, b"\xff")
    return _der(0x30, body)


def _read_tlv(data: bytes, offset: int):
    tag = data[offset]
    length = data[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[start:start + count], "big")
        start += count
    return tag, length, start


def _pki_status(response: bytes) -> Optional[int]:
    """PKIStatus INTEGER of a TimeStampResp (0 granted, 1 grantedWithMods, 2+ refused)."""
    try:
        tag, _, body = _read_tlv(response, 0)
        if tag != 0x30:
            return None
        tag, _, info = _read_tlv(response, body)
        if tag != 0x30:
            return None
        tag, length, value = _read_tlv(response, info)
        if tag != 0x02:
            return None
        return int.from_bytes(response[value:value + length], "big")
    except IndexError:
        return None


def _parse_tsr_response(response_bytes: bytes) -> Dict[str, Any]:
    """Minimal parse of a TimeStampResp: DER SEQUENCE and PKIStatus (no signature check)."""
    if not response_bytes or response_bytes[0] != 0x30:
        raise TSAVerificationError("Invalid TSR response, not a DER SEQUENCE")
    status = _pki_status(response_bytes)
    return {
        "status": "granted" if status in (0, 1) else "unknown",
        "pki_status": status,
        "token_b64": base64.b64encode(response_bytes).decode("ascii"),
        "token_size_bytes": len(response_bytes),
    }


def _check_response_matches_request(
    response: bytes, hash_algorithm: str, digest: bytes, nonce: int
) -> None:
    """The response must be granted and echo the request's digest, algorithm and nonce.

    With rfc3161-client the response is decoded and compared field by field. Without it (or
    if it cannot parse this TSA's response) a byte-level check looks for the digest and the DER
    nonce in the response. Neither verifies the TSA signature: that is verify_tsa_token's job."""
    status = _pki_status(response)
    if status not in (0, 1):
        raise TSAError(f"TSA did not grant the timestamp (PKIStatus {status})")
    try:
        import rfc3161_client
        decoded = rfc3161_client.decode_timestamp_response(response)
        info = decoded.tst_info
    except ImportError:
        decoded = None
    except Exception as exc:
        logger.warning(f"TSA response not parsable by rfc3161-client ({exc}); byte-level checks only")
        decoded = None
    if decoded is not None:
        if info.message_imprint.hash_algorithm.dotted_string != _OID_DOTTED[hash_algorithm]:
            raise TSAError("TSA response uses another hash algorithm than the request")
        if info.message_imprint.message != digest:
            raise TSAError("TSA response imprint differs from the request")
        if info.nonce != nonce:
            raise TSAError("TSA response nonce differs from the request")
        return
    if digest not in response:
        raise TSAError("TSA response does not contain the requested imprint")
    if _der_integer(nonce) not in response:
        raise TSAError("TSA response does not echo the request nonce")


# ─── TSA request ──────────────────────────────────────────────────────────────
def request_timestamp(
    data: bytes,
    tsa_url: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    *,
    hash_algorithm: str = "sha256",
    digest: Optional[bytes] = None,
    schema: str = "legacy",
) -> Dict[str, Any]:
    """
    Request a trusted timestamp from a TSA (RFC 3161).

    Args:
        data:           Bytes to timestamp (hashed with `hash_algorithm`), ignored if `digest`
        tsa_url:        TSA URL (defaults to freetsa.org); http or https only
        timeout:        Request timeout in seconds
        hash_algorithm: "sha256" (default), "sha384" or "sha512"
        digest:         Precomputed digest to timestamp (size must match hash_algorithm)
        schema:         "legacy" (AISS-1 and AISS-2.0 events) or "aiss21"

    Returns:
        "aiss21": {"status": "granted", "token": "base64:...", "hash_algorithm", "imprint" (hex),
                   "nonce" (hex), "authority", "url"}
        "legacy": the previous fields (authority, url, timestamp, token, hash_algorithm,
                  data_hash, status, token_size_bytes) plus "nonce" (hex). The local
                  "timestamp" is the request time and is NOT a proof.

    The request carries a random nonce and the response must echo it, along with the digest.

    Raises:
        TSAUnavailableError: TSA unreachable (callers handle it gracefully)
        TSAError: refused request, or a response that does not match the request
    """
    url = tsa_url or DEFAULT_TSA_SERVERS[0]["url"]
    if not url.lower().startswith(("http://", "https://")):
        raise TSAError("TSA URL must be http or https")
    tsa_name = next((s["name"] for s in DEFAULT_TSA_SERVERS if s["url"] == url), url)

    if digest is None:
        digest = hashlib.new(hash_algorithm, data).digest()
    nonce = secrets.randbits(63) | (1 << 62)
    try:
        tsr_request = _build_tsr_request(digest, hash_algorithm, nonce=nonce)
    except ValueError as exc:
        raise TSAError(str(exc))

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
        if parsed["status"] != "granted":
            raise TSAError(f"TSA did not grant the timestamp (PKIStatus {parsed['pki_status']})")
        _check_response_matches_request(response_bytes, hash_algorithm, digest, nonce)

        token = f"base64:{parsed['token_b64']}"
        if schema == "aiss21":
            result = {
                "status": "granted",
                "token": token,
                "hash_algorithm": hash_algorithm,
                "imprint": digest.hex(),
                "nonce": format(nonce, "x"),
                "authority": tsa_name,
                "url": url,
            }
        else:
            result = {
                "authority": tsa_name,
                "url": url,
                "timestamp": int(time.time()),  # local request time, NOT a proof
                "token": token,
                "hash_algorithm": hash_algorithm,
                "data_hash": digest.hex(),
                "nonce": format(nonce, "x"),
                "status": parsed["status"],
                "token_size_bytes": parsed["token_size_bytes"],
            }

        logger.info("Trusted timestamp received")
        return result

    except urllib.error.URLError as e:
        raise TSAUnavailableError(
            f"TSA '{tsa_name}' unreachable: {e}\n"
            "Event will be stored with a pending trusted timestamp.\n"
            "Run 'piqrypt timestamp --retry' later to add trusted timestamp."
        )
    except TSAError:
        raise
    except Exception as e:
        raise TSAError(f"TSA request failed: {e}")


def _imprint_for_event(event: Dict[str, Any]):
    """(hash_algorithm, digest, schema) of what a TSA token commits to for this event."""
    if event.get("version") == "AISS-2.1":
        from aiss.chain import compute_event_hash
        return "sha512", bytes.fromhex(compute_event_hash(event)), "aiss21"
    from aiss.canonical import canonicalize
    event_for_tsa = {k: v for k, v in event.items() if k != "trusted_timestamp"}
    return "sha256", hashlib.sha256(canonicalize(event_for_tsa)).digest(), "legacy"


def _pending_placeholder(event: Dict[str, Any], note: str) -> Dict[str, Any]:
    if event.get("version") == "AISS-2.1":
        return {"status": "pending", "note": note}
    return {"status": "pending", "note": note, "local_fallback_at": int(time.time())}


def stamp_event_with_tsa(
    event: Dict[str, Any],
    tsa_url: Optional[str] = None,
    fail_gracefully: bool = True
) -> Dict[str, Any]:
    """
    Add a trusted timestamp to an already-signed event.

    The trusted_timestamp field is detached: it is not covered by the event signatures, so
    adding the token does not invalidate them.

    What the TSA token commits to:
      - AISS-2.1: the chain hash of the event (SHA-512 of the JCS form without signatures and
        trusted_timestamp), hashAlgorithm sha512;
      - AISS-1 / AISS-2.0: SHA-256 of canonicalize(event without trusted_timestamp).

    Args:
        event: Already-signed AISS event
        tsa_url: TSA URL (defaults to freetsa.org)
        fail_gracefully: If True, return the event with a pending trusted_timestamp when the
            TSA is unreachable

    Returns:
        Event with the 'trusted_timestamp' field set

    Example:
        >>> event = stamp_event(priv, agent_id, payload)
        >>> event = stamp_event_with_tsa(event)
        >>> event["trusted_timestamp"]["authority"]
        'freetsa.org'
    """
    hash_algorithm, digest, schema = _imprint_for_event(event)

    try:
        tsa_token = request_timestamp(
            b"", tsa_url=tsa_url, hash_algorithm=hash_algorithm, digest=digest, schema=schema)
        event = dict(event)
        event["trusted_timestamp"] = tsa_token

        logger.info("Trusted timestamp added to event")

    except TSAUnavailableError as e:
        if fail_gracefully:
            logger.warning(
                f"TSA unavailable, stored with a pending trusted timestamp: {e}"
            )
            event = dict(event)
            event["trusted_timestamp"] = _pending_placeholder(
                event, "TSA unavailable at stamp time. Retry with: piqrypt timestamp --retry")
        else:
            raise

    return event


# ─── Trust roots ──────────────────────────────────────────────────────────────
TrustRoots = Union[None, str, os.PathLike, Iterable[Any]]


def _certificates_from_bytes(raw: bytes) -> List[Any]:
    from cryptography import x509
    try:
        return list(x509.load_pem_x509_certificates(raw))
    except ValueError:
        return [x509.load_der_x509_certificate(raw)]


def _certificates_from_path(path: Path) -> List[Any]:
    certificates: List[Any] = []
    files = sorted(p for p in path.iterdir() if p.suffix.lower() in (".pem", ".crt", ".cer")) \
        if path.is_dir() else [path]
    for file in files:
        try:
            certificates.extend(_certificates_from_bytes(file.read_bytes()))
        except Exception as exc:
            logger.warning(f"TSA trust root {file} ignored: {exc}")
    return certificates


def load_trust_roots(trust_roots: TrustRoots = None) -> List[Any]:
    """
    Resolve the TSA trust store into a list of x509 certificates.

    Order: the `trust_roots` argument (a path to a PEM file or a directory, or an iterable of
    PEM text, PEM/DER bytes, paths or certificates); else the PIQRYPT_TSA_TRUST_ROOTS
    environment variable (paths separated by os.pathsep); else the directory
    ~/.piqrypt/tsa_roots/ (under PIQRYPT_HOME when set). No root is shipped with the package:
    an empty result means no chain can be validated.
    """
    from cryptography import x509
    certificates: List[Any] = []

    def add_item(item: Any) -> None:
        if isinstance(item, x509.Certificate):
            certificates.append(item)
        elif isinstance(item, (str, os.PathLike)) and not (
                isinstance(item, str) and "BEGIN CERTIFICATE" in item):
            certificates.extend(_certificates_from_path(Path(item)))
        elif isinstance(item, str):
            certificates.extend(_certificates_from_bytes(item.encode("ascii")))
        elif isinstance(item, (bytes, bytearray)):
            certificates.extend(_certificates_from_bytes(bytes(item)))
        else:
            raise TypeError(f"unsupported trust root {type(item).__name__}")

    if trust_roots is not None:
        if isinstance(trust_roots, (str, os.PathLike, bytes, bytearray, x509.Certificate)):
            add_item(trust_roots)
        else:
            for item in trust_roots:
                add_item(item)
        return certificates
    env = os.environ.get(TRUST_ROOTS_ENV)
    if env:
        for part in env.split(os.pathsep):
            if part.strip():
                certificates.extend(_certificates_from_path(Path(part.strip())))
        return certificates
    home = Path(os.environ.get("PIQRYPT_HOME", str(Path.home() / ".piqrypt")))
    default_dir = home / "tsa_roots"
    if default_dir.is_dir():
        certificates.extend(_certificates_from_path(default_dir))
    return certificates


# ─── Verification ─────────────────────────────────────────────────────────────
def _result(status: str, reason: str, **extra: Any) -> Dict[str, Any]:
    result = {
        "status": status,
        "verified": status == "verified",
        "reason": reason,
        "gen_time": None,
        "tsa": None,
        "chain": "not_validated",
        "revocation": "not_checked",
    }
    result.update(extra)
    return result


def _decode_token(value: str) -> bytes:
    raw = value[7:] if value.startswith("base64:") else value
    return base64.b64decode(raw, validate=True)


def _tsa_subject(decoded: Any) -> Optional[str]:
    try:
        from cryptography import x509
        signers = list(decoded.signed_data.signer_infos)
        if len(signers) != 1:
            return None
        signer = signers[0]
        for der in decoded.signed_data.certificates:
            certificate = x509.load_der_x509_certificate(der)
            if certificate.issuer == signer.issuer and certificate.serial_number == signer.serial_number:
                return certificate.subject.rfc4514_string()
    except Exception:
        return None
    return None


def verify_tsa_token(event: Dict[str, Any], trust_roots: TrustRoots = None) -> Dict[str, Any]:
    """
    Verify the TSA token carried by an event.

    The expected hash algorithm and digest are RECOMPUTED from the event; nothing is read from
    the token or from the event's own data_hash/imprint fields for that purpose. Checked: the
    token is a granted TimeStampResp, its message imprint (algorithm and bytes) equals the
    recomputed one, the nonce kept in trusted_timestamp equals the token's, and, when trust
    roots are configured, the CMS signature, the TSA certificate (critical extendedKeyUsage
    timeStamping), the chain to a configured root, and the certificate validity at genTime.

    Returns a dict:
        status:     "verified" | "structure_only" | "pending" | "invalid"
        verified:   True only when status == "verified"
        reason:     human explanation
        gen_time:   genTime read from the token (UTC epoch seconds), None if unreadable;
                    unauthenticated unless status == "verified"
        tsa:        subject of the TSA certificate, when found
        chain:      "validated" or "not_validated"
        revocation: always "not_checked" (no OCSP or CRL in 1.10)

    "structure_only" means a well-formed token whose chain was NOT validated (no trust root
    configured, or rfc3161-client absent). It is never "verified".
    """
    trusted = event.get("trusted_timestamp") if isinstance(event, dict) else None
    value = tsa_token_value(event)
    if value is None:
        if isinstance(trusted, dict) and trusted.get("status") == "pending":
            return _result("pending", "no TSA token was obtained yet")
        return _result("invalid", "the event carries no TSA token")

    try:
        token_bytes = _decode_token(value)
    except (binascii.Error, ValueError):
        return _result("invalid", "the TSA token is not valid base64")
    if not token_bytes:
        return _result("invalid", "the TSA token is empty")

    try:
        hash_algorithm, digest, schema = _imprint_for_event(event)
    except Exception as exc:
        return _result("invalid", f"the event imprint cannot be recomputed: {exc}")

    stored_nonce = trusted.get("nonce")
    nonce_value: Optional[int] = None
    if stored_nonce is not None:
        try:
            nonce_value = int(stored_nonce, 16) if isinstance(stored_nonce, str) else None
        except ValueError:
            nonce_value = None
        if nonce_value is None:
            return _result("invalid", "the stored nonce is not a hexadecimal string")
    elif schema == "aiss21":
        return _result("invalid", "the stored nonce is missing")

    try:
        import rfc3161_client
    except ImportError:
        rfc3161_client = None

    if rfc3161_client is None:
        if _pki_status(token_bytes) not in (0, 1):
            return _result("invalid", "the token is not a granted TimeStampResp")
        if digest not in token_bytes:
            return _result("invalid", "the token does not contain the recomputed imprint")
        if nonce_value is not None and _der_integer(nonce_value) not in token_bytes:
            return _result("invalid", "the token does not contain the stored nonce")
        return _result(
            "structure_only",
            "rfc3161-client is not installed: structure checked, chain not validated "
            "(pip install \"piqrypt[timestamp]\")")

    try:
        decoded = rfc3161_client.decode_timestamp_response(token_bytes)
        info = decoded.tst_info
    except Exception as exc:
        return _result("invalid", f"the token cannot be parsed by rfc3161-client: {exc}")

    gen_time = int(info.gen_time.timestamp())
    subject = _tsa_subject(decoded)
    common = {"gen_time": gen_time, "tsa": subject}
    if int(decoded.status) != 0:
        return _result("invalid", f"PKIStatus {int(decoded.status)} is not granted", **common)
    if info.message_imprint.hash_algorithm.dotted_string != _OID_DOTTED[hash_algorithm]:
        return _result("invalid", f"the token does not use {hash_algorithm}", **common)
    if info.message_imprint.message != digest:
        return _result("invalid", "the token imprint differs from the event imprint", **common)
    if nonce_value is not None and info.nonce != nonce_value:
        return _result("invalid", "the token nonce differs from the stored nonce", **common)

    try:
        roots = load_trust_roots(trust_roots)
    except Exception as exc:
        return _result("invalid", f"trust roots unreadable: {exc}", **common)
    if not roots:
        return _result(
            "structure_only",
            "no TSA trust root configured: imprint and nonce match, chain not validated", **common)

    try:
        builder = rfc3161_client.VerifierBuilder(roots=roots)
        if nonce_value is not None:
            builder = builder.nonce(nonce_value)
        builder.build().verify(decoded, digest)
    except Exception as exc:
        return _result("invalid", f"verification failed: {exc}", **common)
    return _result(
        "verified", "signature, certificate, chain, imprint and nonce verified",
        chain="validated", **common)


def make_tsa_verifier(trust_roots: TrustRoots = None) -> Callable[[Dict[str, Any]], Optional[int]]:
    """
    Verifier for aiss.fork: returns genTime (int) for an event whose token is VERIFIED against
    the trust roots, None otherwise (structure_only, pending, invalid, absent).

    The trust roots are loaded once. The canonical-chain selection is deterministic for the same
    input and the same trust store.
    """
    roots = load_trust_roots(trust_roots)

    def verifier(event: Dict[str, Any]) -> Optional[int]:
        result = verify_tsa_token(event, roots)
        return result["gen_time"] if result["status"] == "verified" else None

    return verifier


# ─── Retry pending timestamps ─────────────────────────────────────────────────
def retry_pending_timestamps(
    agent_id: str,
    tsa_url: Optional[str] = None
) -> Dict[str, int]:
    """
    Retry TSA timestamp for events where it failed at stamp time.

    The imprint follows the event version (see stamp_event_with_tsa). Called by:
    piqrypt timestamp --retry

    Args:
        agent_id: Agent whose events to retry
        tsa_url: TSA URL to use

    Returns:
        {"retried": N, "succeeded": M, "failed": K}
    """
    from aiss.memory import load_events, store_event

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
            hash_algorithm, digest, schema = _imprint_for_event(event)
            token = request_timestamp(
                b"", tsa_url=tsa_url, hash_algorithm=hash_algorithm, digest=digest, schema=schema)
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
    "make_tsa_verifier",
    "load_trust_roots",
    "retry_pending_timestamps",
    "DEFAULT_TSA_SERVERS",
    "TRUST_ROOTS_ENV",
    "TSAError",
    "TSAUnavailableError",
    "TSAVerificationError",
]
