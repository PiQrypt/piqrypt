# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Ed25519 Cryptographic Backend (AISS-1)

RFC 8032 compliant Ed25519 using Python stdlib 'cryptography' package.
Zero external dependencies beyond 'cryptography' (ships with Python 3.x).

Encoding strategy:
  - agent_id   : BASE58(SHA256(pubkey))[:32]  — human-readable, per AISS spec
  - signatures : Base64url (URL-safe, exact byte preservation, JSON-friendly)
  - public keys in events : Base64 standard (compact, exact)
  - stored keys in identity files : Base64 (compact, safe, exact roundtrip)

Base58 is used ONLY for agent_id derivation (truncated, no roundtrip needed).
"""

import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from aiss.exceptions import InvalidSignatureError, CryptoBackendError

# ─── Base58 (Bitcoin alphabet) — for agent_id only ────────────────────────────
_B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58_encode_truncated(data: bytes, length: int = 32) -> str:
    """
    Encode bytes to Base58 and truncate to `length` chars.
    Used ONLY for agent_id derivation. No roundtrip needed.
    """
    n = int.from_bytes(data, "big")
    chars = []
    while n:
        n, r = divmod(n, 58)
        chars.append(_B58[r:r+1])
    for b in data:
        if b == 0:
            chars.append(b"1")
        else:
            break
    return b"".join(reversed(chars)).decode("ascii")[:length]


# ─── Key generation ────────────────────────────────────────────────────────────

def generate_keypair() -> tuple:
    """
    Generate Ed25519 keypair using CSPRNG (RFC Section 14.1).

    Returns:
        (private_key_bytes: bytes[32], public_key_bytes: bytes[32])
    """
    try:
        key = Ed25519PrivateKey.generate()
        priv = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )
        pub = key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        return priv, pub
    except Exception as e:
        raise CryptoBackendError("Ed25519", f"Key generation failed: {e}")


# ─── Signing ──────────────────────────────────────────────────────────────────

def sign(private_key: bytes, message: bytes) -> bytes:
    """
    Sign message with Ed25519 private key (constant-time, RFC 14.1).

    Args:
        private_key: 32-byte Ed25519 private key
        message:     Bytes to sign (typically RFC 8785 canonical JSON)

    Returns:
        64-byte signature
    """
    try:
        key = Ed25519PrivateKey.from_private_bytes(private_key)
        return key.sign(message)
    except Exception as e:
        raise CryptoBackendError("Ed25519", f"Signing failed: {e}")


# ─── Verification ─────────────────────────────────────────────────────────────

def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify Ed25519 signature.

    Args:
        public_key: 32-byte Ed25519 public key
        message:    Original message bytes
        signature:  64-byte signature

    Returns:
        True if valid

    Raises:
        InvalidSignatureError
    """
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key)
        pub.verify(signature, message)
        return True
    except InvalidSignature:
        raise InvalidSignatureError("Ed25519 signature verification failed")
    except Exception as e:
        raise CryptoBackendError("Ed25519", f"Verification error: {e}")


# ─── Encoding helpers ─────────────────────────────────────────────────────────

def encode_base58(data: bytes, truncate: int = None) -> str:
    """
    Encode bytes to Base58.
    For agent_id: encode_base58(sha256(pubkey), truncate=32)
    For other uses: prefer encode_base64 (exact roundtrip).
    """
    n = int.from_bytes(data, "big")
    chars = []
    while n:
        n, r = divmod(n, 58)
        chars.append(_B58[r:r+1])
    for b in data:
        if b == 0:
            chars.append(b"1")
        else:
            break
    result = b"".join(reversed(chars)).decode("ascii")
    return result[:truncate] if truncate else result


def decode_base58(encoded: str) -> bytes:
    """
    Decode Base58 to bytes.
    NOTE: Only reliable for agent_id (truncated) lookup, not exact roundtrip of arbitrary bytes.
    Use decode_base64 for exact signature roundtrips.
    """
    try:
        n = 0
        for c in encoded:
            n = n * 58 + _B58.index(c.encode())
        result = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        leading = len(encoded) - len(encoded.lstrip("1"))
        return b"\x00" * leading + result
    except (ValueError, AttributeError) as e:
        raise ValueError(f"Invalid Base58: {e}")


def encode_base64(data: bytes) -> str:
    """
    Encode bytes to standard Base64 string.
    Used for signatures and keys in events/identity files.
    Guarantees exact roundtrip.
    """
    return base64.b64encode(data).decode("ascii")


def decode_base64(encoded: str) -> bytes:
    """
    Decode Base64 string to bytes. Exact roundtrip guaranteed.
    """
    try:
        return base64.b64decode(encoded)
    except Exception as e:
        raise ValueError(f"Invalid Base64: {e}")


def derive_agent_id_from_pubkey(public_key_bytes: bytes) -> str:
    """
    AISS §5.1: agent_id = BASE58(SHA256(public_key_bytes))[:32]
    """
    h = hashlib.sha256(public_key_bytes).digest()
    return encode_base58(h, truncate=32)


# Public API
__all__ = [
    "generate_keypair",
    "sign",
    "verify",
    "encode_base58",
    "decode_base58",
    "encode_base64",
    "decode_base64",
    "derive_agent_id_from_pubkey",
]
