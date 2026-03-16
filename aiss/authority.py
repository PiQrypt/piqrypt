# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Authority Binding Layer (RFC AISS-1.1 Section 5)

Implements verifiable delegation chains connecting real-world entities
to automated decisions:

    Legal Entity
        ↓ delegates
    Operational System
        ↓ authorizes
    AI Model
        ↓ instantiates
    Agent Instance
        ↓ emits
    Decision Event

Key distinction (RFC §5.5):
    Integrity  = the agent produced the event         [always verifiable]
    Authority  = the agent was ALLOWED to produce it  [requires authority chain]

Integrity MAY exist without authority.
Authority MUST NOT be assumed from integrity.

RFC §5.4 — Validation returns one of:
    VALID_AUTHORIZED        — integrity + authority verified
    VALID_UNAUTHORIZED      — integrity verified, authority invalid/missing
    INVALID                 — integrity check failed
"""

import time
import uuid
from typing import Dict, Any, List, Optional, Tuple

from aiss.crypto import ed25519
from aiss.canonical import canonicalize
from aiss.exceptions import PiQryptError
from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

AUTHORITY_VERSION = "AISS-1.0"

# Verification result codes (RFC §5.4)
RESULT_VALID_AUTHORIZED   = "VALID_AUTHORIZED"
RESULT_VALID_UNAUTHORIZED = "VALID_UNAUTHORIZED"
RESULT_INVALID            = "INVALID"


# ─── Exceptions ───────────────────────────────────────────────────────────────

class AuthorityError(PiQryptError):
    """Authority chain validation failed."""
    pass


class AuthorityExpiredError(AuthorityError):
    """Authority statement is outside its validity period."""
    pass


class AuthorityScopeError(AuthorityError):
    """Requested action is outside the authority scope."""
    pass


class AuthorityRevokedError(AuthorityError):
    """Authority has been revoked."""
    pass


class AuthorityChainBrokenError(AuthorityError):
    """Authority chain has a gap or invalid signature."""
    pass


# ─── Authority Statement ──────────────────────────────────────────────────────

def create_authority_statement(
    issuer_private_key: bytes,
    issuer_id: str,
    subject_id: str,
    scope: List[str],
    validity_days: int = 365,
    revocation_reference: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a signed Authority Statement (RFC §5.3).

    An Authority Statement delegates operational authority from issuer
    to subject for a defined scope and validity period.

    Args:
        issuer_private_key: Issuer's Ed25519 private key
        issuer_id:          Issuer identity (agent_id or human label)
        subject_id:         Subject receiving authority (agent_id)
        scope:              List of permitted action types
        validity_days:      Duration of validity (default: 365 days)
        revocation_reference: URL or reference to revocation mechanism

    Returns:
        Signed authority statement dict

    Example:
        >>> stmt = create_authority_statement(
        ...     priv_key, "acme_corp", "trading_agent_01",
        ...     scope=["execute_order", "modify_position"],
        ...     validity_days=90
        ... )
    """
    now = int(time.time())
    end = now + (validity_days * 86400)

    statement = {
        "version": AUTHORITY_VERSION,
        "statement_id": str(uuid.uuid4()),
        "issuer_id": issuer_id,
        "subject_id": subject_id,
        "scope": sorted(scope),          # RFC §7: lexicographic order (RFC 8785)
        "validity_period": {
            "start": now,
            "end": end,
        },
    }

    if revocation_reference:
        statement["revocation_reference"] = revocation_reference

    # Sign the statement (without signature field)
    canonical = canonicalize(statement)
    signature = ed25519.sign(issuer_private_key, canonical)
    statement["signature"] = ed25519.encode_base64(signature)

    logger.piqrypt(f"Authority statement created: {issuer_id} → {subject_id} [{', '.join(scope)}]")
    return statement


def verify_authority_statement(
    statement: Dict[str, Any],
    issuer_public_key: bytes,
    requested_action: Optional[str] = None,
    at_timestamp: Optional[int] = None,
) -> bool:
    """
    Verify a single authority statement (RFC §5.4).

    Checks:
    1. Signature validity
    2. Validity period
    3. Scope (if action provided)

    Args:
        statement:       Authority statement to verify
        issuer_public_key: Issuer's public key
        requested_action: Action to check against scope (optional)
        at_timestamp:    Timestamp to check validity (default: now)

    Returns:
        True if valid

    Raises:
        AuthorityExpiredError:   Outside validity window
        AuthorityScopeError:     Action not in scope
        InvalidSignatureError:   Signature verification failed
    """
    from aiss.exceptions import InvalidSignatureError

    at_ts = at_timestamp or int(time.time())

    # 1. Verify signature
    stmt_copy = {k: v for k, v in statement.items() if k != "signature"}
    canonical = canonicalize(stmt_copy)
    try:
        sig_bytes = ed25519.decode_base64(statement["signature"])
        if not ed25519.verify(issuer_public_key, canonical, sig_bytes):
            raise InvalidSignatureError("Authority statement signature invalid")
    except Exception as e:
        raise InvalidSignatureError(f"Authority statement signature error: {e}") from e

    # 2. Check validity period
    validity = statement.get("validity_period", {})
    start = validity.get("start", 0)
    end = validity.get("end", 0)
    if at_ts < start or at_ts > end:
        raise AuthorityExpiredError(
            f"Authority expired or not yet valid "
            f"(valid {start}–{end}, checked at {at_ts})"
        )

    # 3. Check scope
    if requested_action is not None:
        scope = statement.get("scope", [])
        if requested_action not in scope:
            raise AuthorityScopeError(
                f"Action '{requested_action}' not in scope {scope}"
            )

    return True


# ─── Authority Chain ──────────────────────────────────────────────────────────

def build_authority_chain(statements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build ordered authority delegation chain (RFC §5.2).

    Validates that each statement's subject_id matches next statement's issuer_id,
    forming a continuous delegation chain.

    Args:
        statements: List of authority statements in order (top → bottom)

    Returns:
        Validated ordered chain

    Raises:
        AuthorityChainBrokenError: Chain has gaps or inconsistencies
    """
    if not statements:
        return []

    for i in range(len(statements) - 1):
        current_subject = statements[i].get("subject_id")
        next_issuer = statements[i + 1].get("issuer_id")
        if current_subject != next_issuer:
            raise AuthorityChainBrokenError(
                f"Chain broken at step {i}: "
                f"subject_id='{current_subject}' ≠ next issuer_id='{next_issuer}'"
            )

    return statements


def validate_authority_chain(
    chain: List[Dict[str, Any]],
    public_keys: Dict[str, bytes],
    requested_action: Optional[str] = None,
    at_timestamp: Optional[int] = None,
) -> Tuple[str, List[str]]:
    """
    Validate full authority chain top-to-bottom (RFC §5.4).

    Args:
        chain:            Ordered list of authority statements
        public_keys:      Dict mapping issuer_id → public_key_bytes
        requested_action: Action to check against final scope
        at_timestamp:     Timestamp for validity checks

    Returns:
        Tuple of (result_code, list_of_errors)
        result_code: VALID_AUTHORIZED | VALID_UNAUTHORIZED | INVALID

    Example:
        >>> result, errors = validate_authority_chain(
        ...     chain, {"acme_corp": pub_key},
        ...     requested_action="execute_order"
        ... )
        >>> assert result == RESULT_VALID_AUTHORIZED
    """
    at_ts = at_timestamp or int(time.time())
    errors = []

    if not chain:
        return RESULT_VALID_UNAUTHORIZED, ["No authority chain provided"]

    for i, statement in enumerate(chain):
        issuer_id = statement.get("issuer_id", "")
        subject_id = statement.get("subject_id", "")

        # Get issuer public key
        issuer_pk = public_keys.get(issuer_id)
        if issuer_pk is None:
            errors.append(f"Step {i}: No public key for issuer '{issuer_id}'")
            return RESULT_VALID_UNAUTHORIZED, errors

        # Check action scope only on the LAST statement (direct authority)
        action_to_check = requested_action if i == len(chain) - 1 else None

        try:
            verify_authority_statement(
                statement, issuer_pk,
                requested_action=action_to_check,
                at_timestamp=at_ts,
            )
        except AuthorityExpiredError as e:
            errors.append(f"Step {i} ({issuer_id}→{subject_id}): {e}")
            return RESULT_VALID_UNAUTHORIZED, errors
        except AuthorityScopeError as e:
            errors.append(f"Step {i} ({issuer_id}→{subject_id}): {e}")
            return RESULT_VALID_UNAUTHORIZED, errors
        except Exception as e:
            errors.append(f"Step {i} ({issuer_id}→{subject_id}): signature error: {e}")
            return RESULT_VALID_UNAUTHORIZED, errors

    # Check chain continuity
    try:
        build_authority_chain(chain)
    except AuthorityChainBrokenError as e:
        errors.append(str(e))
        return RESULT_VALID_UNAUTHORIZED, errors

    return RESULT_VALID_AUTHORIZED, []


def get_accountable_authority(chain: List[Dict[str, Any]]) -> Optional[str]:
    """
    Return the highest validated authority in the chain (RFC §5.7).

    The highest validated authority is the accountable authority
    for attribution purposes.

    Args:
        chain: Validated authority chain

    Returns:
        issuer_id of top-level authority, or None if chain empty
    """
    if not chain:
        return None
    return chain[0].get("issuer_id")


# ─── Event Authority Annotation ───────────────────────────────────────────────

def annotate_event_with_authority(
    event: Dict[str, Any],
    authority_chain: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Annotate an AISS-2 event with its authority chain (RFC §11.3).

    Used before signing the event — authority chain is embedded
    so verification is fully offline.

    Args:
        event:           Event dict (before final signature)
        authority_chain: List of authority statements

    Returns:
        Event dict with authority_chain field added
    """
    event["authority_chain"] = authority_chain
    return event


def extract_authority_chain(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract authority chain from an AISS-2 event.

    Args:
        event: AISS-2 event dict

    Returns:
        Authority chain (empty list if not present)
    """
    return event.get("authority_chain", [])


# ─── Public API ───────────────────────────────────────────────────────────────

__all__ = [
    # Constants
    "RESULT_VALID_AUTHORIZED",
    "RESULT_VALID_UNAUTHORIZED",
    "RESULT_INVALID",
    # Exceptions
    "AuthorityError",
    "AuthorityExpiredError",
    "AuthorityScopeError",
    "AuthorityRevokedError",
    "AuthorityChainBrokenError",
    # Functions
    "create_authority_statement",
    "verify_authority_statement",
    "build_authority_chain",
    "validate_authority_chain",
    "get_accountable_authority",
    "annotate_event_with_authority",
    "extract_authority_chain",
]
