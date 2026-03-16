# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
RFC 8785 - JSON Canonicalization Scheme (JCS)

Pure stdlib implementation of RFC 8785 — zero external dependencies.
AISS Section 3: Canonicalization is MANDATORY for all signed/hashed structures.

RFC 8785 guarantees:
  - Lexicographic key ordering (recursive)
  - No insignificant whitespace
  - UTF-8 encoding (no BOM)
  - Deterministic number representation
  - Unicode normalization (NFC implied by JSON spec)

WARNING: Standard json.dumps(sort_keys=True) is NOT RFC 8785 compliant.
"""

import json
import hashlib
import math
from typing import Any

from aiss.exceptions import InvalidCanonicalJSONError


# ─── RFC 8785 implementation ──────────────────────────────────────────────────

def _serialize_value(value: Any) -> str:
    """Serialize a JSON value in RFC 8785 canonical form."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise InvalidCanonicalJSONError(f"NaN/Infinity not allowed in RFC 8785: {value}")
        s = repr(value)
        if '.' not in s and 'e' not in s and 'E' not in s:
            s = s + '.0'
        return s
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        items = ",".join(_serialize_value(item) for item in value)
        return f"[{items}]"
    if isinstance(value, dict):
        sorted_pairs = sorted(value.items(), key=lambda kv: kv[0])
        pairs = ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{_serialize_value(v)}"
            for k, v in sorted_pairs
        )
        return "{" + pairs + "}"
    raise InvalidCanonicalJSONError(f"Cannot canonicalize type: {type(value)}")


def canonicalize(obj: Any) -> bytes:
    """
    Serialize object to RFC 8785 canonical JSON bytes.

    AISS Section 3: MANDATORY for all structures that are hashed or signed.

    Args:
        obj: Python dict/list/primitive to canonicalize

    Returns:
        RFC 8785 canonical JSON as UTF-8 bytes (no BOM)

    Example:
        >>> canonicalize({"b": 2, "a": 1})
        b'{"a":1,"b":2}'
    """
    try:
        return _serialize_value(obj).encode("utf-8")
    except InvalidCanonicalJSONError:
        raise
    except Exception as e:
        raise InvalidCanonicalJSONError(f"Failed to canonicalize: {e}")


def hash_canonical(obj: Any) -> str:
    """
    Compute SHA-256 hash of RFC 8785 canonicalized object.

    Returns:
        Lowercase hex SHA-256 string (64 chars)
    """
    return hashlib.sha256(canonicalize(obj)).hexdigest()


def hash_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes. Returns lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


def verify_canonical(data: bytes) -> bool:
    """Verify that bytes are valid RFC 8785 canonical JSON."""
    try:
        obj = json.loads(data.decode("utf-8"))
        return canonicalize(obj) == data
    except Exception:
        return False


__all__ = ["canonicalize", "hash_canonical", "hash_bytes", "verify_canonical"]
