# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Dilithium3 Cryptographic Backend (AISS-2) - Hybrid Implementation

NIST FIPS 204 compliant post-quantum signature scheme.
Supports multiple backends with automatic fallback:
  1. liboqs-python (preferred, faster, C-based)
  2. dilithium-py (fallback, pure Python)

Installation:
    pip install liboqs-python  # Preferred
    OR
    pip install dilithium-py   # Fallback

Usage:
    from aiss.crypto import dilithium

    priv, pub = dilithium.generate_keypair()
    sig = dilithium.sign(priv, message)
    valid = dilithium.verify(pub, message, sig)
"""

import os
from aiss.exceptions import CryptoBackendError

# Initialize backend availability flags
AVAILABLE = False
BACKEND_NAME = "unavailable"
USE_LIBOQS = False
USE_DILITHIUM_PY = False

# Try liboqs first (preferred) - but verify it actually works
try:
    import oqs
    # Test that oqs can actually create a Dilithium3 instance
    test_signer = oqs.Signature("Dilithium3")
    AVAILABLE = True
    BACKEND_NAME = "liboqs-python"
    USE_LIBOQS = True
except (ImportError, RuntimeError, Exception):
    # If oqs doesn't work (import fails, runtime error, or any other issue), skip it
    pass

# Fall back to dilithium-py if liboqs not available
if not AVAILABLE:
    try:
        from dilithium_py.dilithium import Dilithium3
        AVAILABLE = True
        BACKEND_NAME = "dilithium-py"
        USE_DILITHIUM_PY = True
    except ImportError:
        pass

# Demo mode tracking
DEMO_MODE = not os.getenv("AISS2_LICENSE_KEY")
EVENT_COUNT = 0
DEMO_LIMIT = 1000


def _check_available():
    """Check if any Dilithium backend is available"""
    if not AVAILABLE:
        raise CryptoBackendError(
            "Dilithium3",
            "Post-quantum crypto not installed.\n"
            "Install one of:\n"
            "  pip install liboqs-python  (recommended)\n"
            "  pip install dilithium-py   (pure Python)\n"
        )


def _check_license():
    """Check license and demo limits"""
    global EVENT_COUNT

    if DEMO_MODE:
        EVENT_COUNT += 1
        if EVENT_COUNT > DEMO_LIMIT:
            raise CryptoBackendError(
                "Dilithium3",
                f"Demo limit reached ({DEMO_LIMIT} events).\n"
                f"Get free OSS license: https://piqrypt.com/oss\n"
                f"Or set AISS2_LICENSE_KEY environment variable"
            )

        # Warning every 100 events
        if EVENT_COUNT % 100 == 0:
            print(f"⚠️  AISS-2 Demo Mode: {EVENT_COUNT}/{DEMO_LIMIT} events used")


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate Dilithium3 keypair.

    Returns:
        Tuple of (private_key_bytes, public_key_bytes)

    Raises:
        CryptoBackendError: If Dilithium3 backend not available
    """
    _check_available()
    _check_license()

    try:
        if USE_LIBOQS:
            # liboqs backend
            signer = oqs.Signature("Dilithium3")
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
            return private_key, public_key

        elif USE_DILITHIUM_PY:
            # dilithium-py backend
            # Note: returns (public, private), so we swap
            public_key, private_key = Dilithium3.keygen()
            return private_key, public_key
        else:
            raise CryptoBackendError("Dilithium3", "No backend available")

    except Exception as e:
        raise CryptoBackendError("Dilithium3", f"Key generation failed: {e}")


def sign(private_key: bytes, message: bytes) -> bytes:
    """
    Sign message with Dilithium3 private key.

    Args:
        private_key: Dilithium3 private key bytes
        message: Message bytes to sign

    Returns:
        Dilithium3 signature bytes (~3293 bytes)

    Raises:
        CryptoBackendError: If backend not available or signing fails
    """
    _check_available()
    _check_license()

    try:
        if USE_LIBOQS:
            # liboqs backend
            signer = oqs.Signature("Dilithium3", private_key)
            return signer.sign(message)

        elif USE_DILITHIUM_PY:
            # dilithium-py backend
            return Dilithium3.sign(private_key, message)
        else:
            raise CryptoBackendError("Dilithium3", "No backend available")

    except Exception as e:
        raise CryptoBackendError("Dilithium3", f"Signing failed: {e}")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify Dilithium3 signature.

    Args:
        public_key: Dilithium3 public key bytes
        message: Original message bytes
        signature: Signature to verify

    Returns:
        True if signature is valid, False otherwise

    Raises:
        CryptoBackendError: If backend not available
    """
    _check_available()

    try:
        if USE_LIBOQS:
            # liboqs backend
            verifier = oqs.Signature("Dilithium3")
            return verifier.verify(message, signature, public_key)

        elif USE_DILITHIUM_PY:
            # dilithium-py backend
            return Dilithium3.verify(public_key, message, signature)
        else:
            return False

    except Exception:
        # Verification failure is not an error, just invalid signature
        return False


def is_available() -> bool:
    """
    Check if Dilithium3 backend is available.

    Returns:
        True if AISS-2 crypto is available
    """
    return AVAILABLE


def get_backend_info() -> dict:
    """
    Get backend information.

    Returns:
        Dict with backend details including which implementation is being used
    """
    info = {
        "backend": BACKEND_NAME,
        "available": AVAILABLE,
        "algorithm": "Dilithium3" if AVAILABLE else None,
        "demo_mode": DEMO_MODE,
        "events_used": EVENT_COUNT if DEMO_MODE else None,
        "events_limit": DEMO_LIMIT if DEMO_MODE else None,
        "license_key_set": bool(os.getenv("AISS2_LICENSE_KEY"))
    }

    if AVAILABLE:
        if USE_LIBOQS:
            info["implementation"] = "liboqs (C)"
            info["performance"] = "high"
        elif USE_DILITHIUM_PY:
            info["implementation"] = "dilithium-py (Python)"
            info["performance"] = "medium"

    return info


def reset_demo_counter():
    """Reset demo event counter (for testing)"""
    global EVENT_COUNT
    EVENT_COUNT = 0


# Public API
__all__ = [
    "generate_keypair",
    "sign",
    "verify",
    "is_available",
    "get_backend_info",
    "reset_demo_counter",
]
