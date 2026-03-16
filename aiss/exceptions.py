# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
AISS Exception Classes

All exceptions raised by the AISS library.
"""


class AISSError(Exception):
    """Base exception for all AISS errors"""
    pass


class InvalidSignatureError(AISSError):
    """Raised when signature verification fails (RFC Section 7.2)"""

    def __init__(self, message: str = "Invalid signature"):
        super().__init__(message)


class ForkDetected(AISSError):
    """Raised when fork condition is detected (RFC Section 10)

    A fork occurs when multiple events reference the same previous_hash.
    """

    def __init__(self, hash: str, events: list):
        self.hash = hash
        self.events = events
        super().__init__(
            f"Fork detected: {len(events)} events reference previous_hash {hash[:16]}..."
        )


class ReplayAttackDetected(AISSError):
    """Raised when duplicate nonce is detected (RFC Section 11)"""

    def __init__(self, agent_id: str, nonce: str):
        self.agent_id = agent_id
        self.nonce = nonce
        super().__init__(
            f"Replay attack detected: duplicate nonce {nonce} for agent {agent_id[:16]}..."
        )


class InvalidChainError(AISSError):
    """Raised when hash chain validation fails (RFC Section 9)"""

    def __init__(self, message: str, event_index: int = None):
        self.event_index = event_index
        if event_index is not None:
            message = f"{message} (at event index {event_index})"
        super().__init__(message)


class InvalidCanonicalJSONError(AISSError):
    """Raised when JSON is not RFC 8785 compliant (RFC Section 3)"""

    def __init__(self, message: str = "Invalid canonical JSON"):
        super().__init__(message)


class InvalidAgentIDError(AISSError):
    """Raised when agent_id does not match derived value (RFC Section 5.1)"""

    def __init__(self, claimed: str, derived: str):
        self.claimed = claimed
        self.derived = derived
        super().__init__(
            f"Agent ID mismatch: claimed={claimed[:16]}... derived={derived[:16]}..."
        )


class TimestampError(AISSError):
    """Raised when timestamp validation fails (RFC Section 8)"""

    def __init__(self, message: str):
        super().__init__(message)


class NonceError(AISSError):
    """Raised when nonce is invalid or missing (RFC Section 11)"""

    def __init__(self, message: str):
        super().__init__(message)


class CryptoBackendError(AISSError):
    """Raised when cryptographic backend is unavailable"""

    def __init__(self, backend: str, message: str = None):
        self.backend = backend
        if message:
            super().__init__(f"{backend} backend error: {message}")
        else:
            super().__init__(f"{backend} backend not available")


# Alias for backward compatibility
PiQryptError = AISSError


class LicenseError(AISSError):
    """Raised when license validation fails"""
    def __init__(self, message: str = "Invalid or missing license"):
        super().__init__(message)
