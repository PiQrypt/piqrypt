# PiQrypt v1.5.0 — AISS RFC Implementation Status

**Version:** 1.5.0  
**Date:** 2026-02-24  
**AISS RFC:** v1.1  
**Status:** Production Ready (Level 2)

---

## Overview

PiQrypt is the reference implementation of the AISS (Agent Identity and Signature Standard) v1.1.

**Repository:** https://github.com/piqrypt/piqrypt  
**Standard:** https://github.com/piqrypt/aiss-spec

---

## Conformance Matrix

### Core AISS-1.0 (Free Tier)

| RFC Section | Feature | Status | Module | Version |
|-------------|---------|--------|--------|---------|
| **§5** | **Agent Identity** | ✅ Complete | `aiss/identity.py` | v1.0.0 |
| §5.1 | Deterministic ID derivation | ✅ | `aiss/identity.py` | v1.0.0 |
| §5.2 | Base58 encoding | ✅ | `aiss/identity.py` | v1.0.0 |
| **§6** | **Identity Document** | ✅ Complete | `aiss/identity.py` | v1.0.0 |
| §6.1 | AISS-1 structure | ✅ | `aiss/identity.py` | v1.0.0 |
| **§7** | **Event Stamping** | ✅ Complete | `aiss/stamp.py` | v1.0.0 |
| §7.1 | Ed25519 signatures | ✅ | `aiss/crypto/ed25519.py` | v1.0.0 |
| §7.2 | RFC 8785 canonicalization | ✅ | `aiss/canonical.py` | v1.0.0 |
| **§8** | **Timestamps** | ✅ Complete | `aiss/stamp.py` | v1.0.0 |
| §8.1 | Unix epoch timestamps | ✅ | `aiss/stamp.py` | v1.0.0 |
| **§9** | **Hash Chains** | ✅ Complete | `aiss/chain.py` | v1.0.0 |
| §9.1 | SHA-256 chaining | ✅ | `aiss/chain.py` | v1.0.0 |
| §9.2 | Previous event hash | ✅ | `aiss/chain.py` | v1.0.0 |
| **§10** | **Fork Detection** | ✅ Complete | `aiss/fork.py` | v1.0.0 |
| §10.1 | Branch detection | ✅ | `aiss/fork.py` | v1.0.0 |
| §10.2 | Canonical resolution | ✅ | `aiss/fork.py` | v1.2.0 |
| **§11** | **Anti-Replay** | ✅ Complete | `aiss/replay.py` | v1.0.0 |
| §11.1 | UUID v4 nonces | ✅ | `aiss/replay.py` | v1.0.0 |
| **§12** | **Key Rotation** | ✅ Complete | `aiss/identity.py` | v1.1.0 |
| §12.1 | Rotation event | ✅ | `aiss/identity.py` | v1.1.0 |
| §12.2 | Chain continuity | ✅ | `aiss/identity.py` | v1.1.0 |

---

### AISS-2.0 (Pro/OSS/Enterprise)

| RFC Section | Feature | Status | Module | Version |
|-------------|---------|--------|--------|---------|
| **§6.2** | **Identity AISS-2** | ✅ Complete | `aiss/identity.py` | v1.0.0 |
| §6.2.1 | Authority chain | ✅ | `aiss/authority.py` | v1.2.0 |
| **§7.3** | **Event Stamp AISS-2** | ✅ Complete | `aiss/stamp_aiss2.py` | v1.2.0 |
| §7.3.1 | Hybrid signatures (Ed25519 + Dilithium3) | ✅ | `aiss/stamp_aiss2.py` | v1.2.0 |
| §7.3.2 | Authority chain field | ✅ | `aiss/stamp_aiss2.py` | v1.2.0 |
| **§8.2** | **RFC 3161 Timestamps** | ✅ Complete | `aiss/rfc3161.py` | v1.1.0 |
| §8.2.1 | TSA integration | ✅ | `aiss/rfc3161.py` | v1.1.0 |
| §8.2.2 | FreeTSA support | ✅ | `aiss/rfc3161.py` | v1.1.0 |
| **§13** | **Key Lifecycle** | ✅ Complete | `aiss/identity.py` | v1.1.0 |
| §13.1 | Secure generation | ✅ | `aiss/crypto/` | v1.0.0 |
| §13.2 | Encrypted storage | ✅ | `aiss/memory.py` | v1.1.0 |
| **Crypto** | **Dilithium3** | ✅ Complete | `aiss/crypto/dilithium_liboqs.py` | v1.1.0 |
| | ML-DSA-65 (NIST FIPS 204) | ✅ | `aiss/crypto/dilithium_liboqs.py` | v1.1.0 |

---

### AISS v1.1 Extensions (New)

| RFC Section | Feature | Status | Module | Version |
|-------------|---------|--------|--------|---------|
| **§14** | **Authority Binding** | ✅ Complete | `aiss/authority.py` | v1.2.0 |
| §14.1 | Chain delegation | ✅ | `aiss/authority.py` | v1.2.0 |
| §14.2 | Revocation | ✅ | `aiss/authority.py` | v1.2.0 |
| **§15** | **Canonical History** | ✅ Complete | `aiss/fork.py` | v1.2.0 |
| §15.1 | Fork resolution rules | ✅ | `aiss/fork.py` | v1.2.0 |
| §15.2 | Finalization property | ✅ | `aiss/fork.py` | v1.2.0 |
| **§16** | **A2A Handshake** | ✅ Complete | `aiss/a2a.py` | **v1.5.0** |
| §16.1 | Handshake protocol | ✅ | `aiss/a2a.py` | v1.5.0 |
| §16.2 | Co-signed events | ✅ | `aiss/a2a.py` | v1.5.0 |
| §16.3 | Memory recording | ✅ | `aiss/a2a.py` | v1.5.0 |
| §16.5 | Trust scoring | ✅ Complete | `aiss/a2a.py` | v1.5.0 |

---

### Operations & Exports

| RFC Section | Feature | Status | Module | Version |
|-------------|---------|--------|--------|---------|
| **§18** | **Audit Export** | ✅ Complete | `aiss/exports.py` | v1.0.0 |
| §18.1 | JSON export | ✅ | `aiss/exports.py` | v1.0.0 |
| §18.2 | Certified export (Pro) | ✅ | `aiss/exports.py` | v1.1.0 |
| **§19** | **Compliance Profile** | ✅ Complete | `aiss/exports.py` | v1.1.0 |
| §19.1 | SOC2 mapping | ✅ | `aiss/exports.py` | v1.1.0 |
| **Archive** | **Portable .pqz** | ✅ Complete | `aiss/archive.py` | v1.1.0 |
| | AES-256-GCM encryption | ✅ | `aiss/archive.py` | v1.1.0 |
| | Standalone decrypt.py | ✅ | `aiss/templates/decrypt.py` | v1.1.0 |

---

### PiQrypt Extensions (Beyond AISS)

| Feature | Status | Module | Version |
|---------|--------|--------|---------|
| **External Certification** | ✅ Complete | `aiss/external_cert.py` | v1.3.0 |
| CA-signed export (email workflow) | ✅ | `aiss/external_cert.py` | v1.3.0 |
| Certification request (.zip) | ✅ | `aiss/external_cert.py` | v1.3.0 |
| CA public key verification | ✅ | `aiss/ca/piqrypt-ca-public.key` | v1.3.0 |
| **Verification Engine** | ✅ Complete | `aiss/verify.py` | v1.0.0 |
| Signature verification | ✅ | `aiss/verify.py` | v1.0.0 |
| Chain integrity report | ✅ | `aiss/verify.py` | v1.0.0 |
| **Visual Badges (simple)** | ✅ Complete | `aiss/badges.py` | v1.5.0 |
| Markdown/HTML embed codes | ✅ | `aiss/badges.py` | v1.5.0 |
| Tier-aware badge generation | ✅ | `aiss/badges.py` | v1.5.0 |
| **Memory System** | ✅ Complete | `aiss/memory.py` | v1.1.0 |
| Free: JSON plaintext | ✅ | `aiss/memory.py` | v1.1.0 |
| Pro: AES-256-GCM encrypted | ✅ | `aiss/memory.py` | v1.1.0 |
| **SQLite Indexing** | ✅ Complete | `aiss/index.py` | v1.1.0 |
| Fast search | ✅ | `aiss/index.py` | v1.1.0 |
| **License System** | ✅ Complete | `aiss/license.py` | v1.1.0 |
| Free/Pro/OSS/Enterprise | ✅ | `aiss/license.py` | v1.1.0 |
| **Certification Service** | ✅ Complete | `aiss/certification.py` | **v1.5.0** |
| Simple (€9) | ✅ | `aiss/certification.py` | v1.5.0 |
| Timestamp (€29) | ✅ | `aiss/certification.py` | v1.5.0 |
| Post-Quantum (€99) | ✅ | `aiss/certification.py` | v1.5.0 |
| **Badge Generation** | ✅ Complete | `aiss/cert_badges.py` | **v1.5.0** |
| SVG badges | ✅ | `aiss/cert_badges.py` | v1.5.0 |
| Public verification | ✅ | `aiss/cert_badges.py` | v1.5.0 |
| **Structured Logging** | ✅ Complete | `aiss/logger.py` | v1.1.0 |
| PRO_HINT system | ✅ | `aiss/logger.py` | v1.1.0 |
| **Telemetry** | ✅ Complete | `aiss/telemetry.py` | v1.1.0 |
| Anonymous analytics | ✅ | `aiss/telemetry.py` | v1.1.0 |

---

### Planned Features (Future)

| RFC Section | Feature | Status | Target Version |
|-------------|---------|--------|----------------|
| **§17** | **ML-KEM-768** | 🔲 Planned | v2.0.0 |
| | Key exchange | 🔲 | v2.0.0 |
| **§20.2** | **Witness Network** | 🔲 Planned | v1.7.0 |
| | Distributed trust | 🔲 | v1.7.0 |
| **§20.3** | **Blockchain Anchoring** | 🔲 Planned | v1.7.0 |
| | Public ledger | 🔲 | v1.7.0 |
| **Trust Scoring** | **Dashboard UI** | 🔲 Planned | v1.6.0 |
| | Visual interface | 🔲 | v1.6.0 |
| | I/V/D/F metrics display | 🔲 | v1.6.0 |

---

### Agent Examples

| Feature | Status | Module | Version |
|---------|--------|--------|---------|
| **HR Assistant Agent** | ✅ Example | `agents/examples/hr-assistant.py` | v1.5.0 |
| **Trading Bot Agent** | ✅ Example | `agents/examples/trading-bot.py` | v1.5.0 |

---

**Per RFC §22.1:**

| Level | Description | PiQrypt Status |
|-------|-------------|----------------|
| **Level 1** | Basic compliance (§5-12) | ✅ v1.0.0 |
| **Level 2** | Production ready (§5-16) | ✅ v1.5.0 |
| **Level 3** | Regulated environments | 🔲 v2.0.0 (pending HSM audit) |

**Current:** **Level 2 — Production Ready**

---

## Testing

**Test Coverage:**
- Unit tests: 135 test functions across 11 test files ✅
- Integration tests: `test_integration.py` (12 tests) ✅
- Coverage: 85%+

**Test Files:**
- `test_sprint1a.py` — Core AISS-1 features (12 tests)
- `test_vectors.py` — RFC normative test vectors (14 tests)
- `test_a2a.py` — A2A handshake protocol (22 tests)
- `test_integration.py` — End-to-end integration (12 tests)
- `test_certification.py` — Certification service (52 tests)
- `test_external_cert.py` — External CA certification (12 tests)
- `test_rfc3161_e2e.py` — RFC 3161 TSA (3 tests)
- `test_cli_authority.py` — Authority CLI (3 tests)
- `test_cli_certified_export.py` — Certified export CLI (1 test)
- `test_archive_index.py` — Archive & index (2 tests)
- `test_memory_index.py` — Memory indexing (2 tests)

---

## CLI Tool

**Installation:**
```bash
pip install piqrypt
```

**Commands:**
```bash
piqrypt identity create <file>            # Generate keypair
piqrypt identity rotate <file>            # Rotate keys
piqrypt stamp <identity> --payload        # Sign event
piqrypt verify <audit>                    # Verify chain
piqrypt export <audit>                    # Export audit (JSON)
piqrypt certify-request <audit> <cert>    # Create external cert request (CA email workflow)
piqrypt certify-verify <cert>             # Verify PiQrypt CA certification
piqrypt hash <file>                       # Compute event hash
piqrypt authority create/verify/chain     # Authority management
piqrypt license activate/status/deactivate # License management
piqrypt badge generate <cert_id>          # Badge generation [v1.5]
piqrypt telemetry enable/disable/status   # Manage telemetry
piqrypt memory status/unlock/lock/search/encrypt  # Memory management
piqrypt a2a propose/respond/peers         # A2A protocol [v1.5]
piqrypt archive create/import             # Portable .pqz archives
piqrypt status                            # Show system status
```

---

## MCP Integration

**Repository:** https://github.com/piqrypt/piqrypt-mcp-server  
**Version:** 1.4.0

**MCP Tools Exposed:**
- `piqrypt_stamp_event`
- `piqrypt_verify_chain`
- `piqrypt_export_audit`
- `piqrypt_search_events`

**Clients Supported:**
- Claude Desktop
- n8n workflows
- Custom MCP clients

---

## Standards Compliance

**Cryptographic:**
- ✅ RFC 8032 (Ed25519)
- ✅ RFC 8785 (JSON Canonicalization)
- ✅ RFC 3161 (TSA Timestamps)
- ✅ NIST FIPS 204 (Dilithium3)
- ✅ NIST FIPS 197 (AES-256-GCM)

**Security:**
- ✅ SOC2 alignment
- ✅ ISO 27001 controls
- ✅ HIPAA audit trail requirements
- ✅ GDPR Art. 5.1.f (integrity)

---

## License

**Core:** MIT License  
**Pro Features:** Proprietary (Free/Pro/OSS/Enterprise tiers)

---

## Changelog v1.5.0 (2026-02-24)

**New Features:**
- ✅ A2A Handshake protocol (§16) — full implementation including trust scoring
- ✅ Trust scoring (`compute_trust_score`, `update_peer_trust_score`) — implemented in v1.5.0
- ✅ Certification pay-per service (€9/€29/€99) — `aiss/certification.py`
- ✅ Badge generation (SVG) — `aiss/cert_badges.py` + `aiss/badges.py`
- ✅ External CA certification (email workflow) — `aiss/external_cert.py`
- ✅ Public verification pages
- ✅ Webhook automation (Stripe + Google Drive)
- ✅ Agent examples (HR Assistant, Trading Bot) — `agents/examples/`

**Improvements:**
- ✅ RFC vendor-neutrality
- ✅ Documentation dated
- ✅ Version coherence across repos
- ✅ Expanded CLI with 16+ commands

**Tests:**
- ✅ 135 test functions across 11 test files
- ✅ A2A scenarios covered (22 tests)
- ✅ Certification workflow tested (52 tests)
- ✅ External certification tested (12 tests)

---

**For detailed implementation notes, see:** `docs/` directory in repository.

---

*PiQrypt v1.5.0 — Reference Implementation of AISS v1.1*  
*https://github.com/piqrypt/piqrypt*
