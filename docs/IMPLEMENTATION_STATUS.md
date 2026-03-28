# PiQrypt v1.7.1 — AISS RFC v2.0 Implementation Status

**Version:** 1.7.1  
**Date:** 2026-03-23
**AISS RFC:** v2.0  
**Status:** Production Ready (Level 2)

---

## Overview

PiQrypt is the reference implementation of the AISS (Agent Identity and Signature Standard) v2.0.

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
| §13.2 | Encrypted storage | ✅ | `aiss/key_store.py` | **v1.8.4** |
| **Crypto** | **Dilithium3** | ✅ Complete | `aiss/crypto/dilithium_liboqs.py` | v1.1.0 |
| | ML-DSA-65 (NIST FIPS 204) | ✅ | `aiss/crypto/dilithium_liboqs.py` | v1.1.0 |

---

### AISS v2.0 Extensions

| RFC Section | Feature | Status | Module | Version |
|-------------|---------|--------|--------|---------|
| **§14** | **Authority Binding** | ✅ Complete | `aiss/authority.py` | v1.2.0 |
| §14.1 | Chain delegation | ✅ | `aiss/authority.py` | v1.2.0 |
| §14.2 | Revocation | ✅ | `aiss/authority.py` | v1.2.0 |
| **§15** | **Canonical History** | ✅ Complete | `aiss/fork.py` | v1.2.0 |
| §15.1 | Fork resolution rules | ✅ | `aiss/fork.py` | v1.2.0 |
| §15.2 | Finalization property | ✅ | `aiss/fork.py` | v1.2.0 |
| **§16** | **A2A Handshake** | ✅ Complete | `aiss/a2a.py` | v1.5.0 |
| §16.1 | Handshake protocol | ✅ | `aiss/a2a.py` | v1.5.0 |
| §16.2 | Co-signed events | ✅ | `aiss/a2a.py` | v1.5.0 |
| §16.3 | Memory recording | ✅ | `aiss/a2a.py` | v1.5.0 |
| §16.5 | Trust scoring | ✅ | `aiss/trust_score.py` | v1.5.0 |

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
| **KeyStore — Encrypted Key Storage** | ✅ Complete | `aiss/key_store.py` | **v1.8.4** |
| scrypt N=2¹⁷ + AES-256-GCM | ✅ | `aiss/key_store.py` | v1.8.4 |
| Magic bytes validation (`PQKY`) | ✅ | `aiss/key_store.py` | v1.8.4 |
| RAM erasure (`_secure_erase`) | ✅ | `aiss/key_store.py` | v1.8.4 |
| Fixed file size (97 bytes) | ✅ | `aiss/key_store.py` | v1.8.4 |
| **Agent Registry** | ✅ Complete | `aiss/agent_registry.py` | **v1.8.4** |
| Class `AgentRegistry` (OO API) | ✅ | `aiss/agent_registry.py` | v1.8.4 |
| Path traversal protection | ✅ | `aiss/agent_registry.py` | v1.8.4 |
| Per-agent directory isolation | ✅ | `aiss/agent_registry.py` | v1.8.4 |
| **TSI Engine** | ✅ Complete | `aiss/tsi_engine.py` | **v1.5.0** |
| Trust State Index (STABLE/WATCH/UNSTABLE/CRITICAL) | ✅ | `aiss/tsi_engine.py` | v1.5.0 |
| 24h drift detection | ✅ | `aiss/tsi_engine.py` | v1.5.0 |
| **A2C Detector** | ✅ Complete | `aiss/a2c_detector.py` | **v1.5.0** |
| 16 relational anomaly scenarios | ✅ | `aiss/a2c_detector.py` | v1.5.0 |
| Risk scoring 0.0–1.0 | ✅ | `aiss/a2c_detector.py` | v1.5.0 |
| **Anomaly Monitor + VRS** | ✅ Complete | `aiss/anomaly_monitor.py` | **v1.5.0** |
| Composite VRS score | ✅ | `aiss/anomaly_monitor.py` | v1.5.0 |
| Alert journal with deduplication | ✅ | `aiss/anomaly_monitor.py` | v1.5.0 |
| **Vigil Server** | ✅ Stable | `vigil/vigil_server.py` | **v1.7.1** |
| HTTP dashboard (port 18421) | ✅ | `vigil/vigil_server.py` | v1.5.0 |
| REST API `/api/summary`, `/api/alerts` | ✅ | `vigil/vigil_server.py` | v1.5.0 |
| Live backend with TSI hook | ✅ | `vigil/vigil_server.py` | v1.5.0 |
| Agent CRUD + memory export + certify | ✅ | `vigil/vigil_server.py` | v1.7.1 |
| Two-step agent delete with pqz backup | ✅ | `vigil/vigil_server.py` | v1.7.1 |
| **Trust-server** | ✅ Production | Render deployed · TSA RFC 3161 · Dilithium3 · verify endpoint | **v1.7.1** |
| **Identity Session** | ✅ Complete | `aiss/identity_session.py` | v1.5.0 |
| Lock/unlock with RAM erasure | ✅ | `aiss/identity_session.py` | v1.5.0 |
| `SessionLockedError` protection | ✅ | `aiss/identity_session.py` | v1.5.0 |
| **External Certification** | ✅ Complete | `aiss/external_cert.py` | v1.3.0 |
| CA-signed export (email workflow) | ✅ | `aiss/external_cert.py` | v1.3.0 |
| **Verification Engine** | ✅ Complete | `aiss/verify.py` | v1.0.0 |
| **Memory System** | ✅ Complete | `aiss/memory.py` | v1.1.0 |
| Free: JSON plaintext | ✅ | `aiss/memory.py` | v1.1.0 |
| Pro: AES-256-GCM encrypted | ✅ | `aiss/memory.py` | v1.1.0 |
| Agent isolation via registry | ✅ | `aiss/memory.py` | v1.8.4 |
| **SQLite Indexing** | ✅ Complete | `aiss/index.py` | v1.2.0 |
| Key rotation chain traversal | ✅ | `aiss/index.py` | v1.6.0 |
| Session search | ✅ | `aiss/index.py` | v1.6.0 |
| **Migration** | ✅ Complete | `aiss/migration.py` | v1.8.4 |
| v1.6→v1.7 non-destructive | ✅ | `aiss/migration.py` | v1.8.4 |
| Automatic backup creation | ✅ | `aiss/migration.py` | v1.8.4 |
| **License System** | ✅ Complete | `aiss/license.py` | v1.1.0 |
| **Certification Service** | ✅ Complete | `aiss/certification.py` | v1.5.0 |
| **Structured Logging** | ✅ Complete | `aiss/logger.py` | v1.1.0 |
| **Telemetry** | ✅ Complete | `aiss/telemetry.py` | v1.1.0 |
| **MCP Integration** | ✅ Complete | `@piqrypt/mcp-server` | v1.4.0 |

---

### TrustGate — Governance Engine (Pro+)

| Feature | Status | Module | Version |
|---------|--------|--------|---------|
| Policy engine (deterministic, 10-priority) | ✅ Complete | `trustgate/policy_engine.py` | v1.8.4 |
| Hash-chained governance journal | ✅ Complete | `trustgate/audit_journal.py` | v1.8.4 |
| Immutable policy versioning + SHA-256 | ✅ Complete | `trustgate/policy_versioning.py` | v1.8.4 |
| REQUIRE_HUMAN with TTL + auto-deny | ✅ Complete | `trustgate/decision.py` | v1.8.4 |
| Policy simulation (dry-run) | ✅ Complete | `trustgate/policy_engine.py` | v1.8.4 |
| 3 built-in compliance profiles | ✅ Complete | `trustgate/profiles/` | v1.8.4 |
| EU AI Act Art.14 human oversight | ✅ Complete | `trustgate/policy_engine.py` | v1.8.4 |

### AgentSession — Cross-Framework Co-Signed Sessions

| Feature | Status | Module | Version |
|---------|--------|--------|---------|
| N-agent session with pairwise handshakes | ✅ Complete | `bridges/session/__init__.py` | v1.8.4 |
| Same interaction_hash in both memories | ✅ Complete | `bridges/session/__init__.py` | v1.8.4 |
| Payload auto-hashing (RGPD by design) | ✅ Complete | `bridges/session/__init__.py` | v1.8.4 |
| Cross-framework audit export | ✅ Complete | `bridges/session/__init__.py` | v1.8.4 |

### Framework Bridges (9)

| Bridge | Status | Module | Version |
|--------|--------|--------|---------|
| LangChain | ✅ Complete | `bridges/langchain/` | v1.8.4 |
| CrewAI | ✅ Complete | `bridges/crewai/` | v1.8.4 |
| AutoGen | ✅ Complete | `bridges/autogen/` | v1.8.4 |
| OpenClaw | ✅ Complete | `bridges/openclaw/` | v1.8.4 |
| Session | ✅ Complete | `bridges/session/` | v1.8.4 |
| MCP | ✅ Complete | `bridges/mcp/` | v1.8.4 |
| Ollama | ✅ Complete | `bridges/ollama/` | v1.8.4 |
| ROS2 | ✅ Complete | `bridges/ros/` | v1.8.4 |
| RPi | ✅ Complete | `bridges/rpi/` | v1.8.4 |

### Planned Features (Future)

| RFC Section | Feature | Status | Target Version |
|-------------|---------|--------|----------------|
| **§17** | **ML-KEM-768** | 🔲 Planned | v2.0.0 |
| | Key exchange | 🔲 | v2.0.0 |
| **§20.2** | **Witness Network** | 🔲 Planned | v2.0.0 |
| | Distributed trust | 🔲 | v2.0.0 |
| **§20.3** | **Blockchain Anchoring** | 🔲 Planned | v2.0.0 |
| | Public ledger | 🔲 | v2.0.0 |
| **HSM** | **Hardware Security Module** | 🔲 Planned | v2.0.0 |
| | Level 3 compliance | 🔲 | v2.0.0 |

---

## Testing

**Test Results (v1.7.1):**

| Suite | Tests | Status |
|-------|-------|--------|
| Functional — key_store | 7 | ✅ |
| Functional — agent_registry | 6 | ✅ |
| Functional — identity_session | 6 | ✅ |
| Functional — migration | 4 | ✅ |
| Functional — tsi_engine | 7 | ✅ |
| Functional — a2c_detector | 16 | ✅ |
| Functional — anomaly_monitor | 7 | ✅ |
| Functional — trust_score | 6 | ✅ |
| Functional — identity | 5 | ✅ |
| Functional — memory | 5 | ✅ |
| Functional — vigil_server | 7 | ✅ |
| RFC Test Vectors | 14 | ✅ |
| Security — keystore | 14 | ✅ |
| Security — registry | 12 | ✅ + 1 skip (chmod/Windows) |
| Security — chain | 19 | ✅ |
| Security — session | 7 | ✅ |
| Security — migration | 4 | ✅ |
| Security — memory | 4 | ✅ |
| Ollama bridge | 6 | ⏭ skipped (external dep) |
| **Total** | **472** | **472 passed · 14 skipped · 0 failed — CI vert Python 3.9-3.12** |

**Security coverage:**
- Cryptographic resistance: timing, corruption, forgery, RAM erasure
- Filesystem: path traversal, sanitization, isolation, permissions
- Protocol: replay, fork injection, agent ID spoofing, chain integrity
- Session: lock/unlock, key erasure, context manager

---

## Conformance Level

**Per RFC §22.1:**

| Level | Description | Status |
|-------|-------------|--------|
| **Level 1** | Basic compliance (§5-12) | ✅ since v1.0.0 |
| **Level 2** | Production ready (§5-16) | ✅ since v1.5.0 |
| **Level 3** | Regulated environments (HSM audit) | 🔲 v2.0.0 |

**Current: Level 2 — Production Ready**

---

## CLI Tool
```bash
pip install piqrypt
```
```bash
piqrypt identity create <file>            # Generate keypair
piqrypt identity rotate <file>            # Rotate keys
piqrypt stamp <identity> --payload        # Sign event
piqrypt verify <audit>                    # Verify chain
piqrypt export <audit>                    # Export audit (JSON)
piqrypt certify-request <audit> <cert>    # External cert request
piqrypt certify-verify <cert>             # Verify CA certification
piqrypt history <agent_id>               # Full history with rotation
piqrypt memory status/unlock/lock/search/encrypt
piqrypt a2a propose/respond/peers
piqrypt archive create/import
piqrypt badge generate <cert_id>
piqrypt telemetry enable/disable/status
piqrypt status
```

---

## Standards Compliance

| Standard | Purpose |
|----------|---------|
| RFC 8032 (Ed25519) | Agent signatures |
| RFC 8785 (JCS) | JSON canonicalization |
| RFC 3161 | Trusted timestamps |
| NIST FIPS 204 (ML-DSA-65) | Post-quantum signatures |
| NIST FIPS 197 (AES-256-GCM) | Symmetric encryption |
| scrypt (Colin Percival, 2009) | Key derivation (N=2¹⁷) |

**Regulatory alignment:** SOC2 · ISO 27001 · HIPAA · GDPR Art. 5.1.f

---

## MCP Integration

**Repository:** https://github.com/piqrypt/piqrypt-mcp-server  
**Tools:** `piqrypt_stamp_event` · `piqrypt_verify_chain` · `piqrypt_export_audit` · `piqrypt_search_events`  
**Clients:** Claude Desktop · n8n · custom MCP clients

---

## License

**Core:** MIT License  
**Pro Features:** Proprietary (Free/Pro/OSS/Enterprise tiers)  
**IP:** e-Soleau DSO2026006483 (INPI France — 19/02/2026)

---

*PiQrypt v1.7.1 — Reference Implementation of AISS v2.0*  
*https://github.com/piqrypt/piqrypt*

---

**Intellectual Property Notice**

Core protocol concepts described in this document were deposited
via e-Soleau with the French National Institute of Industrial Property (INPI):

Primary deposit:  DSO2026006483 — 19 February 2026
Addendum:         DSO2026009143 — 12 March 2026

These deposits establish proof of authorship and prior art
for the PCP protocol specification and PiQrypt reference implementation.

PCP (Proof of Continuity Protocol) is an open protocol specification.
It may be implemented independently by any compliant system.
PiQrypt is the reference implementation.

© 2026 PiQrypt — contact@piqrypt.com
