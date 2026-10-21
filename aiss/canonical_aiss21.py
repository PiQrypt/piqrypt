# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
RFC 8785 JCS canonicalization for AISS-2.1 events.

This module is used ONLY for AISS-2.1 events. AISS-1 continues to use
aiss.canonical (stdlib implementation frozen by test_vectors/).

Backed by rfc8785 >= 0.1.4 (Apache-2.0).
"""

import hashlib
from typing import Any

try:
    import rfc8785 as _rfc8785
    _AVAILABLE = True
except ImportError:  # pragma: no cover
    _AVAILABLE = False


def is_available() -> bool:
    """True when the rfc8785 package is installed."""
    return _AVAILABLE


def canonicalize(obj: Any) -> bytes:
    """
    Serialize obj to RFC 8785 canonical JSON bytes.

    Uses the rfc8785 package for strict conformance (floats, exponents,
    Unicode key ordering). Required for AISS-2.1 sign and hash paths.

    Raises:
        ImportError: if rfc8785 is not installed
        ValueError: if obj contains non-serializable values (NaN, Infinity)
    """
    if not _AVAILABLE:
        raise ImportError(
            "rfc8785 is required for AISS-2.1 canonicalization.\n"
            "Install: pip install 'rfc8785>=0.1.4,<0.2'"
        )
    return _rfc8785.dumps(obj)


def hash_event(obj: Any) -> str:
    """
    SHA-512 hash of the RFC 8785 canonical form of obj.

    Used for AISS-2.1 chain hashes (previous_hash, compute_event_hash).
    Returns lowercase hex string (128 chars).
    """
    return hashlib.sha512(canonicalize(obj)).hexdigest()


__all__ = ["is_available", "canonicalize", "hash_event"]
