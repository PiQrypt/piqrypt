"""
AISS (Agent Identity and Signature Standard)
PiQrypt v1.2.0

RFC Compliance:
- RFC 8785  (JSON Canonicalization Scheme) — MANDATORY
- RFC 8032  (Ed25519 signatures)
- RFC 3161  (Trusted Timestamps — Pro)
- RFC 4122  (UUID v4 nonces)
- NIST FIPS 204 (ML-DSA-65 / Dilithium3 — AISS-2)
- AISS-1.0 (Free), AISS-2.0 (Pro/OSS)

Quick Start — Free:
    >>> from aiss import generate_keypair, derive_agent_id, stamp_event
    >>> from aiss.memory import store_event
    >>> priv, pub = generate_keypair()
    >>> agent_id = derive_agent_id(pub)
    >>> event = stamp_event(priv, agent_id, {"action": "trade_executed"})
    >>> store_event(event)

Quick Start — A2A:
    >>> from aiss.a2a import create_identity_proposal, perform_handshake
    >>> proposal = create_identity_proposal(priv, pub, agent_id)

Quick Start — Archive (Pro):
    >>> from aiss.archive import create_archive
    >>> create_archive(events, identity, "backup.pqz", passphrase="strong-pass")
"""

__version__ = "1.6.0"

# Core AISS-1
from aiss.identity import (
    generate_keypair, derive_agent_id, export_identity,
    create_rotation_attestation,
    create_rotation_pcp_event,
)
from aiss.stamp import stamp_event, stamp_genesis_event
from aiss.verify import verify_signature, verify_chain, verify_event
from aiss.chain import compute_event_hash, compute_chain_hash, append_event
from aiss.exports import export_audit_chain
from aiss.exceptions import (
    AISSError, InvalidSignatureError, ForkDetected,
    ReplayAttackDetected, InvalidChainError, CryptoBackendError,
)

# License
from aiss.license import (
    is_pro, is_oss, get_tier, get_license_info,
    activate_license, deactivate_license, require_pro,
)

# Logging with PRO_HINT level
from aiss.logger import get_logger

# Telemetry
from aiss.telemetry import (
    track, enable_telemetry, disable_telemetry,
    is_telemetry_enabled, get_telemetry_status,
)

# Badges
from aiss.badges import (
    generate_badge, generate_badge_svg, get_badge_embed_code,
)

# Memory System (v1.2.0)
from aiss.memory import (
    init_memory_dirs,
    store_event, store_event_free, store_event_pro,
    load_events, load_events_free, load_events_pro,
    search_events,
    unlock, lock, is_unlocked,
    migrate_to_encrypted,
    get_memory_stats,
    MemoryLockedError, MemoryCorruptedError, PassphraseError,
)

# Memory Index (v1.2.0 Sprint 3)
from aiss.index import (
    MemoryIndex, get_index,
)

# External Certification (v1.3.0)
from aiss.external_cert import (
    create_certification_request,
    validate_and_certify,
    verify_piqrypt_certification,
    load_ca_public_key,
    CertificationError,
)

# A2A Protocol (v1.2.0)
from aiss.a2a import (
    create_identity_proposal, verify_identity_proposal,
    create_identity_response, verify_identity_response,
    create_session_confirmation,
    build_cosigned_handshake_event,
    perform_handshake,
    record_external_interaction,
    create_a2a_message,
    register_peer, get_peer, list_peers,
    update_peer_trust_score,
    A2AHandshakeError, A2APeerNotFound, A2ATrustError,
)

# RFC 3161 Trusted Timestamps (Pro)
from aiss.rfc3161 import (
    request_timestamp,
    stamp_event_with_tsa,
    verify_tsa_token,
    retry_pending_timestamps,
    TSAError, TSAUnavailableError,
)

# Portable Archives (.pqz)
from aiss.archive import (
    create_archive,
    import_archive,
    ArchiveError, ArchiveCorruptedError,
)

# Authority Binding Layer (RFC §5) — NEW v1.2.0
from aiss.authority import (
    create_authority_statement,
    verify_authority_statement,
    build_authority_chain,
    validate_authority_chain,
    get_accountable_authority,
    annotate_event_with_authority,
    extract_authority_chain,
    RESULT_VALID_AUTHORIZED,
    RESULT_VALID_UNAUTHORIZED,
    RESULT_INVALID,
    AuthorityError,
    AuthorityExpiredError,
    AuthorityScopeError,
    AuthorityChainBrokenError,
)

# Canonical History Rule (RFC §6) — extended in v1.2.0
from aiss.fork import (
    ForkDetector,
    find_forks,
    resolve_fork_by_timestamp,
    resolve_fork_by_first_seen,
    get_fork_resolution_info,
    select_canonical_chain,
    detect_fork_after_finalization,
    classify_fork,
    resolve_fork_canonical,
    ForkAfterFinalizationError,
    STATUS_FORK_DETECTED,
    STATUS_FORK_AFTER_FINALIZATION,
    STATUS_NON_CANONICAL,
    STATUS_CANONICAL,
)

# AISS-2 hybrid (Pro/OSS)
from aiss.stamp_aiss2 import (
    stamp_event_aiss2_hybrid, stamp_genesis_event_aiss2_hybrid, verify_aiss2_hybrid,
)
# Agent Context — system prompt for LLM agents (v1.5.0)
from aiss.agent_context import (
    get_system_prompt,
    get_agent_metadata,
    build_agent_context,
)

# Trust Score — v1.6.0
from aiss.trust_score import (
    compute_trust_score,
    compute_I, compute_V_t, compute_D_t, compute_F, compute_R,
    temporal_weight,
    build_trust_signal,
    get_a2c_risk,
    DEFAULT_WEIGHTS,
    TIERS,
)

# TSI — Trust Stability Index — v1.6.0
from aiss.tsi_engine import (
    compute_tsi,
    get_tsi_history,
    get_tsi_summary,
    reset_tsi_baseline,
    TSI_STATES,
)

# History — full rotation chain — v1.6.0
from aiss.history import (
    load_full_history,
    get_history_summary,
)
