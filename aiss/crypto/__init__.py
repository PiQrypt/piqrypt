# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
AISS Cryptographic Backends

This module provides pluggable crypto backends:
- ed25519: AISS-1 (REQUIRED)
- dilithium_liboqs: AISS-2 (OPTIONAL, liboqs-python)
"""

from aiss.crypto import ed25519

__all__ = ["ed25519"]

# Try liboqs-python backend first (compatible with cffi>=2.0)
try:
    from aiss.crypto import dilithium_liboqs
    __all__.append("dilithium_liboqs")
    # Alias for backward compatibility
    dilithium = dilithium_liboqs
    __all__.append("dilithium")
except ImportError:
    dilithium = None
    dilithium_liboqs = None
