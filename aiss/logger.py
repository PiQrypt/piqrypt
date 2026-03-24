# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
PiQrypt Structured Logger

Implements the exact log design from Mode Opératoire §7.

Four levels (RFC §18 logging spec):
  INFO     — normal operation, reassures
  WARNING  — risk detected, alerts without blocking
  PRO_HINT — non-aggressive Pro suggestion (ONLY during real actions, never at startup)
  ERROR    — critical failure

Rules (Mode Opératoire §7.7):
  - PRO_HINT appears ONLY during real user actions
  - PRO_HINT is NEVER aggressive, NEVER repeated per session
  - No blocking on Free features — only inform
  - Messages must REASSURE first, then INFORM, then SUGGEST

Exact log messages per action (Mode Opératoire §7 LISTING):
  Agent start:       [PiQrypt] Identity initialized
                     [PiQrypt] Local trust chain active
                     [PiQrypt] Memory protection enabled
  Event signed:      [PiQrypt] Event signed (hash: 3fa2e...)
  Chain verified:    [PiQrypt] Chain integrity verified
  Export Free:       [PiQrypt] Export created: audit.json
                     [PiQrypt] Export integrity not certified (Pro feature available)
  Certified w/o lic: [PiQrypt] Certified export requires Pro license
                     [PiQrypt] Certified exports provide cryptographic proof for audits
  Status Free:       [PiQrypt] Agent operating with local-only trust
                     [PiQrypt] Network trust available (Pro)
  Multi-agent:       [PiQrypt] Agent has interacted with N external agents
                     [PiQrypt] Network verification available (Pro)
  Replay Free:       [PiQrypt] Advanced replay detection not enabled (Pro)
  Memory unlock:     [PiQrypt] Memory unlocked
  Memory lock:       [PiQrypt] Memory locked
  Memory migrate:    [PiQrypt] Migrating N events to encrypted storage...
                     [PiQrypt] Migration complete: N events encrypted
  A2A handshake:     [PiQrypt] A2A handshake initiated with peer
                     [PiQrypt] A2A handshake complete: trust established
  RFC3161 stamp:     [PiQrypt] Trusted timestamp obtained from TSA
                     [PiQrypt] TSA unreachable — local timestamp only
  Archive create:    [PiQrypt] Archive created: agent.pqz (N events)
  Archive import:    [PiQrypt] Archive imported: N events loaded
"""

import logging
import sys
import os
from typing import Optional, Dict

# ─── Custom PRO_HINT level ─────────────────────────────────────────────────────
PRO_HINT_LEVEL = 25  # Between INFO(20) and WARNING(30)
logging.addLevelName(PRO_HINT_LEVEL, "PRO_HINT")

# Track PRO_HINT messages already shown this session (prevent repetition)
_shown_hints: set = set()


class PiQryptLogger(logging.Logger):
    """Logger with PRO_HINT level and [PiQrypt] prefix."""

    def pro_hint(self, message: str, *args, **kwargs):
        """
        Non-aggressive Pro feature suggestion.
        Only shown once per session per unique message.
        Only called during real user actions, never at startup.
        """
        global _shown_hints
        if message in _shown_hints:
            return  # Never repeat
        if self.isEnabledFor(PRO_HINT_LEVEL):
            _shown_hints.add(message)
            self._log(PRO_HINT_LEVEL, message, args, **kwargs)

    def piqrypt(self, message: str, *args, **kwargs):
        """[PiQrypt] prefixed INFO log — the standard user-facing format."""
        self.info(f"[PiQrypt] {message}", *args, **kwargs)

    def piqrypt_hint(self, message: str, *args, **kwargs):
        """[PiQrypt] prefixed PRO_HINT — appears only during real actions."""
        self.pro_hint(f"[PiQrypt] {message}", *args, **kwargs)

    def piqrypt_warn(self, message: str, *args, **kwargs):
        """[PiQrypt] prefixed WARNING."""
        self.warning(f"[PiQrypt] {message}", *args, **kwargs)

    def piqrypt_error(self, message: str, *args, **kwargs):
        """[PiQrypt] prefixed ERROR."""
        self.error(f"[PiQrypt] {message}", *args, **kwargs)


logging.setLoggerClass(PiQryptLogger)


# ─── Logger factory ────────────────────────────────────────────────────────────

def get_logger(name: str) -> PiQryptLogger:
    """
    Get a PiQrypt logger for a module.

    Usage:
        log = get_logger(__name__)
        log.piqrypt("Event signed (hash: 3fa2e...)")
        log.piqrypt_hint("Network trust available (Pro)")
    """
    log = logging.getLogger(name)
    if not log.handlers:
        _configure_logger(log)
    return log  # type: ignore


def _configure_logger(log: logging.Logger):
    """Configure PiQrypt-style console output."""
    level_name = os.getenv("PIQRYPT_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    # PRO_HINT level must be enabled if INFO is enabled
    log.setLevel(min(level, PRO_HINT_LEVEL))

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log.level)

    class PiQryptFormatter(logging.Formatter):
        def format(self, record):
            if record.levelno == PRO_HINT_LEVEL:
                record.levelname = "HINT"
            return super().format(record)

    formatter = PiQryptFormatter(
        fmt="%(message)s",  # Clean output: just the message
        datefmt="%H:%M:%S"
    )
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.propagate = False


# ─── Configure root piqrypt logger ────────────────────────────────────────────
_root = logging.getLogger("piqrypt")
if not _root.handlers:
    _configure_logger(_root)


# ─── Convenience functions — exact messages from Mode Opératoire §7 ───────────

def log_identity_initialized(agent_id: str):
    """Agent startup — 3 lines per spec."""
    log = get_logger("piqrypt.identity")
    log.piqrypt("Identity initialized")
    log.piqrypt("Local trust chain active")
    log.piqrypt("Memory protection enabled")


def log_event_signed(agent_id: str, event_hash: str):
    """[PiQrypt] Event signed (hash: 3fa2e...)"""
    log = get_logger("piqrypt.stamp")
    log.piqrypt(f"Event signed (hash: {event_hash[:5]}...)")


def log_chain_verified(agent_id: str, event_count: int, chain_hash: str = ""):
    """[PiQrypt] Chain integrity verified"""
    log = get_logger("piqrypt.verify")
    log.piqrypt("Chain integrity verified")


def log_export_created(filepath: str, certified: bool = False):
    """Free export + PRO_HINT for certification."""
    log = get_logger("piqrypt.exports")
    log.piqrypt(f"Export created: {filepath}")
    if not certified:
        log.piqrypt_hint("Export integrity not certified (Pro feature available)")


def log_certified_export_required():
    """When user attempts certified export without Pro license."""
    log = get_logger("piqrypt.exports")
    log.piqrypt("Certified export requires Pro license")
    log.piqrypt("Certified exports provide cryptographic proof for audits")


def log_certified_export_created(filepath: str):
    """Certified export success."""
    log = get_logger("piqrypt.exports")
    log.piqrypt(f"Certified export created: {filepath}")
    log.piqrypt(f"Certificate: {filepath}.cert")


def log_status_free(event_count: int):
    """piqrypt status — Free tier output with PRO_HINT."""
    log = get_logger("piqrypt.status")
    log.piqrypt("Agent operating with local-only trust")
    if event_count > 0:
        log.piqrypt_hint("Network trust available (Pro)")


def log_multi_agent_interaction(peer_count: int):
    """When agent has interacted with external agents."""
    log = get_logger("piqrypt.a2a")
    log.piqrypt(f"Agent has interacted with {peer_count} external agent{'s' if peer_count != 1 else ''}")
    log.piqrypt_hint("Network verification available (Pro)")


def log_replay_detection_limited():
    """Free tier replay detection limited."""
    log = get_logger("piqrypt.replay")
    log.piqrypt_hint("Advanced replay detection not enabled (Pro)")


def log_memory_unlocked(tier: str = "pro"):
    """Memory successfully unlocked."""
    get_logger("piqrypt.memory").piqrypt("Memory unlocked")


def log_memory_locked():
    """Memory session locked."""
    get_logger("piqrypt.memory").piqrypt("Memory locked")


def log_memory_migration_start(event_count: int):
    """Starting Free→Pro migration."""
    get_logger("piqrypt.memory").piqrypt(f"Migrating {event_count} events to encrypted storage...")


def log_memory_migration_complete(event_count: int):
    """Migration complete."""
    get_logger("piqrypt.memory").piqrypt(f"Migration complete: {event_count} events encrypted")


def log_a2a_handshake_initiated(peer_id: str):
    """A2A handshake started."""
    get_logger("piqrypt.a2a").piqrypt(f"A2A handshake initiated with peer {peer_id[:16]}...")


def log_a2a_handshake_complete(peer_id: str, trust_score: float = None):
    """A2A handshake completed."""
    log = get_logger("piqrypt.a2a")
    msg = f"A2A handshake complete: trust established with {peer_id[:16]}..."
    if trust_score is not None:
        msg += f" (trust: {trust_score:.2f})"
    log.piqrypt(msg)


def log_rfc3161_obtained(tsa_url: str):
    """TSA timestamp obtained."""
    get_logger("piqrypt.rfc3161").piqrypt(f"Trusted timestamp obtained from TSA ({tsa_url})")


def log_rfc3161_unavailable():
    """TSA unreachable — graceful degradation."""
    get_logger("piqrypt.rfc3161").piqrypt_warn("TSA unreachable — local timestamp only")


def log_archive_created(filepath: str, event_count: int, encrypted: bool = False):
    """Archive .pqz created."""
    enc_note = " (encrypted)" if encrypted else ""
    get_logger("piqrypt.archive").piqrypt(f"Archive created: {filepath} ({event_count} events{enc_note})")


def log_archive_imported(filepath: str, event_count: int):
    """Archive .pqz imported."""
    get_logger("piqrypt.archive").piqrypt(f"Archive imported: {event_count} events loaded from {filepath}")


def log_key_rotation(old_id: str, new_id: str):
    """Key rotation completed."""
    log = get_logger("piqrypt.identity")
    log.piqrypt(f"Key rotation: {old_id[:16]}... → {new_id[:16]}...")
    log.piqrypt("Rotation event recorded in PCP chain")


def log_license_activated(tier: str, license_id: str = ""):
    """License activated."""
    get_logger("piqrypt.license").piqrypt(f"License activated: {tier.upper()}")


def log_fork_detected(hash_prefix: str, branch_count: int):
    """Fork detected in chain."""
    get_logger("piqrypt.fork").piqrypt_warn(
        f"Fork detected at {hash_prefix}... ({branch_count} branches) — investigate immediately"
    )


def log_replay_detected(nonce_prefix: str):
    """Replay attack detected."""
    get_logger("piqrypt.replay").piqrypt_error(
        f"Replay attack detected: duplicate nonce {nonce_prefix}..."
    )


# Reset session hints (e.g. for testing)
def reset_hints():
    global _shown_hints
    _shown_hints = set()


# Convenience aliases
def log_event_signed_alias(agent_id: str, event_type: str, nonce: str):
    """Compatibility alias."""
    log_event_signed(agent_id, nonce[:8])


def log_identity_created(agent_id: str, algorithm: str):
    log_identity_initialized(agent_id)


def log_identity_rotated(old_id: str, new_id: str):
    log_key_rotation(old_id, new_id)


def log_audit_exported(agent_id: str, event_count: int, fmt: str):
    log_export_created(f"audit.{fmt}", certified=False)


def log_error(error_type: str, message: str, details: Optional[Dict] = None):
    get_logger("piqrypt").piqrypt_error(f"{error_type}: {message}")


def log_debug(event_type: str, message: str, data: Optional[Dict] = None):
    get_logger("piqrypt").debug(f"[PiQrypt] {event_type}: {message}")


__all__ = [
    "get_logger",
    "log_identity_initialized", "log_identity_created", "log_identity_rotated",
    "log_event_signed", "log_chain_verified",
    "log_export_created", "log_certified_export_required", "log_certified_export_created",
    "log_status_free", "log_multi_agent_interaction", "log_replay_detection_limited",
    "log_memory_unlocked", "log_memory_locked",
    "log_memory_migration_start", "log_memory_migration_complete",
    "log_a2a_handshake_initiated", "log_a2a_handshake_complete",
    "log_rfc3161_obtained", "log_rfc3161_unavailable",
    "log_archive_created", "log_archive_imported",
    "log_key_rotation", "log_license_activated",
    "log_fork_detected", "log_replay_detected",
    "log_error", "log_debug", "reset_hints",
    "PRO_HINT_LEVEL",
]
