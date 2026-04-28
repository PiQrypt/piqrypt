# PiQrypt v1.9.0 â€” AISS RFC v2.0 Implementation Status

**Version:** 1.9.0  
**Date:** 2026-04-20
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
| **Â§5** | **Agent Identity** | âœ… Complete | `aiss/identity.py` | v1.0.0 |
| Â§5.1 | Deterministic ID derivation | âœ… | `aiss/identity.py` | v1.0.0 |
| Â§5.2 | Base58 encoding | âœ… | `aiss/identity.py` | v1.0.0 |
| **Â§6** | **Identity Document** | âœ… Complete | `aiss/identity.py` | v1.0.0 |
| Â§6.1 | AISS-1 structure | âœ… | `aiss/identity.py` | v1.0.0 |
| **Â§7** | **Event Stamping** | âœ… Complete | `aiss/stamp.py` | v1.0.0 |
| Â§7.1 | Ed25519 signatures | âœ… | `aiss/crypto/ed25519.py` | v1.0.0 |
| Â§7.2 | RFC 8785 canonicalization | âœ… | `aiss/canonical.py` | v1.0.0 |
| **Â§8** | **Timestamps** | âœ… Complete | `aiss/stamp.py` | v1.0.0 |
| Â§8.1 | Unix epoch timestamps | âœ… | `aiss/stamp.py` | v1.0.0 |
| **Â§9** | **Hash Chains** | âœ… Complete | `aiss/chain.py` | v1.0.0 |
| Â§9.1 | SHA-256 chaining | âœ… | `aiss/chain.py` | v1.0.0 |
| Â§9.2 | Previous event hash | âœ… | `aiss/chain.py` | v1.0.0 |
| **Â§10** | **Fork Detection** | âœ… Complete | `aiss/fork.py` | v1.0.0 |
| Â§10.1 | Branch detection | âœ… | `aiss/fork.py` | v1.0.0 |
| Â§10.2 | Canonical resolution | âœ… | `aiss/fork.py` | v1.2.0 |
| **Â§11** | **Anti-Replay** | âœ… Complete | `aiss/replay.py` | v1.0.0 |
| Â§11.1 | UUID v4 nonces | âœ… | `aiss/replay.py` | v1.0.0 |
| **Â§12** | **Key Rotation** | âœ… Complete | `aiss/identity.py` | v1.1.0 |
| Â§12.1 | Rotation event | âœ… | `aiss/identity.py` | v1.1.0 |
| Â§12.2 | Chain continuity | âœ… | `aiss/identity.py` | v1.1.0 |

---

### AISS-2.0 (Pro/OSS/Enterprise)

| RFC Section | Feature | Status | Module | Version |
|-------------|---------|--------|--------|---------|
| **Â§6.2** | **Identity AISS-2** | âœ… Complete | `aiss/identity.py` | v1.0.0 |
| Â§6.2.1 | Authority chain | âœ… | `aiss/authority.py` | v1.2.0 |
| **Â§7.3** | **Event Stamp AISS-2** | âœ… Complete | `aiss/stamp_aiss2.py` | v1.2.0 |
| Â§7.3.1 | Hybrid signatures (Ed25519 + Dilithium3) | âœ… | `aiss/stamp_aiss2.py` | v1.2.0 |
| Â§7.3.2 | Authority chain field | âœ… | `aiss/stamp_aiss2.py` | v1.2.0 |
| **Â§8.2** | **RFC 3161 Timestamps** | âœ… Complete | `aiss/rfc3161.py` | v1.1.0 |
| Â§8.2.1 | TSA integration | âœ… | `aiss/rfc3161.py` | v1.1.0 |
| Â§8.2.2 | FreeTSA support | âœ… | `aiss/rfc3161.py` | v1.1.0 |
| **Â§13** | **Key Lifecycle** | âœ… Complete | `aiss/identity.py` | v1.1.0 |
| Â§13.1 | Secure generation | âœ… | `aiss/crypto/` | v1.0.0 |
| Â§13.2 | Encrypted storage | âœ… | `aiss/key_store.py` | **v1.8.4** |
| **Crypto** | **Dilithium3** | âœ… Complete | `aiss/crypto/dilithium_liboqs.py` | v1.1.0 |
| | ML-DSA-65 (NIST FIPS 204) | âœ… | `aiss/crypto/dilithium_liboqs.py` | v1.1.0 |

---

### AISS v2.0 Extensions

| RFC Section | Feature | Status | Module | Version |
|-------------|---------|--------|--------|---------|
| **Â§14** | **Authority Binding** | âœ… Complete | `aiss/authority.py` | v1.2.0 |
| Â§14.1 | Chain delegation | âœ… | `aiss/authority.py` | v1.2.0 |
| Â§14.2 | Revocation | âœ… | `aiss/authority.py` | v1.2.0 |
| **Â§15** | **Canonical History** | âœ… Complete | `aiss/fork.py` | v1.2.0 |
| Â§15.1 | Fork resolution rules | âœ… | `aiss/fork.py` | v1.2.0 |
| Â§15.2 | Finalization property | âœ… | `aiss/fork.py` | v1.2.0 |
| **Â§16** | **A2A Handshake** | âœ… Complete | `aiss/a2a.py` | v1.5.0 |
| Â§16.1 | Handshake protocol | âœ… | `aiss/a2a.py` | v1.5.0 |
| Â§16.2 | Co-signed events | âœ… | `aiss/a2a.py` | v1.5.0 |
| Â§16.3 | Memory recording | âœ… | `aiss/a2a.py` | v1.5.0 |
| Â§16.5 | Trust scoring | âœ… | `aiss/trust_score.py` | v1.5.0 |

---

### Operations & Exports

| RFC Section | Feature | Status | Module | Version |
|-------------|---------|--------|--------|---------|
| **Â§18** | **Audit Export** | âœ… Complete | `aiss/exports.py` | v1.0.0 |
| Â§18.1 | JSON export | âœ… | `aiss/exports.py` | v1.0.0 |
| Â§18.2 | Certified export (Pro) | âœ… | `aiss/exports.py` | v1.1.0 |
| **Â§19** | **Compliance Profile** | âœ… Complete | `aiss/exports.py` | v1.1.0 |
| Â§19.1 | SOC2 mapping | âœ… | `aiss/exports.py` | v1.1.0 |
| **Archive** | **Portable .pqz** | âœ… Complete | `aiss/archive.py` | v1.1.0 |
| | AES-256-GCM encryption | âœ… | `aiss/archive.py` | v1.1.0 |
| | Standalone decrypt.py | âœ… | `aiss/templates/decrypt.py` | v1.1.0 |

---

### PiQrypt Extensions (Beyond AISS)

| Feature | Status | Module | Version |
|---------|--------|--------|---------|
| **KeyStore â€” Encrypted Key Storage** | âœ… Complete | `aiss/key_store.py` | **v1.8.4** |
| scrypt N=2Â¹â· + AES-256-GCM | âœ… | `aiss/key_store.py` | v1.8.4 |
| Magic bytes validation (`PQKY`) | âœ… | `aiss/key_store.py` | v1.8.4 |
| RAM erasure (`_secure_erase`) | âœ… | `aiss/key_store.py` | v1.8.4 |
| Fixed file size (97 bytes) | âœ… | `aiss/key_store.py` | v1.8.4 |
| **Agent Registry** | âœ… Complete | `aiss/agent_registry.py` | **v1.8.4** |
| Class `AgentRegistry` (OO API) | âœ… | `aiss/agent_registry.py` | v1.8.4 |
| Path traversal protection | âœ… | `aiss/agent_registry.py` | v1.8.4 |
| Per-agent directory isolation | âœ… | `aiss/agent_registry.py` | v1.8.4 |
| **TSI Engine** | âœ… Complete | `aiss/tsi_engine.py` | **v1.5.0** |
| Trust State Index (STABLE/WATCH/UNSTABLE/CRITICAL) | âœ… | `aiss/tsi_engine.py` | v1.5.0 |
| 24h drift detection | âœ… | `aiss/tsi_engine.py` | v1.5.0 |
| **A2C Detector** | âœ… Complete | `aiss/a2c_detector.py` | **v1.5.0** |
| 16 relational anomaly scenarios | âœ… | `aiss/a2c_detector.py` | v1.5.0 |
| Risk scoring 0.0â€“1.0 | âœ… | `aiss/a2c_detector.py` | v1.5.0 |
| **Anomaly Monitor + VRS** | âœ… Complete | `aiss/anomaly_monitor.py` | **v1.5.0** |
| Composite VRS score | âœ… | `aiss/anomaly_monitor.py` | v1.5.0 |
| Alert journal with deduplication | âœ… | `aiss/anomaly_monitor.py` | v1.5.0 |
| **Vigil Server** | âœ… Stable | `vigil/vigil_server.py` | **v1.7.1** |
| HTTP dashboard (port 18421) | âœ… | `vigil/vigil_server.py` | v1.5.0 |
| REST API `/api/summary`, `/api/alerts` | âœ… | `vigil/vigil_server.py` | v1.5.0 |
| Live backend with TSI hook | âœ… | `vigil/vigil_server.py` | v1.5.0 |
| Agent CRUD + memory export + certify | âœ… | `vigil/vigil_server.py` | v1.7.1 |
| Two-step agent delete with pqz backup | âœ… | `vigil/vigil_server.py` | v1.7.1 |
| **Trust-server** | âœ… Production | Render deployed Â· TSA RFC 3161 Â· Dilithium3 Â· verify endpoint | **v1.7.1** |
| **Identity Session** | âœ… Complete | `aiss/identity_session.py` | v1.5.0 |
| Lock/unlock with RAM erasure | âœ… | `aiss/identity_session.py` | v1.5.0 |
| `SessionLockedError` protection | âœ… | `aiss/identity_session.py` | v1.5.0 |
| **External Certification** | âœ… Complete | `aiss/external_cert.py` | v1.3.0 |
| CA-signed export (email workflow) | âœ… | `aiss/external_cert.py` | v1.3.0 |
| **Verification Engine** | âœ… Complete | `aiss/verify.py` | v1.0.0 |
| **Memory System** | âœ… Complete | `aiss/memory.py` | v1.1.0 |
| Free: JSON plaintext | âœ… | `aiss/memory.py` | v1.1.0 |
| Pro: AES-256-GCM encrypted | âœ… | `aiss/memory.py` | v1.1.0 |
| Agent isolation via registry | âœ… | `aiss/memory.py` | v1.8.4 |
| **SQLite Indexing** | âœ… Complete | `aiss/index.py` | v1.2.0 |
| Key rotation chain traversal | âœ… | `aiss/index.py` | v1.6.0 |
| Session search | âœ… | `aiss/index.py` | v1.6.0 |
| **Migration** | âœ… Complete | `aiss/migration.py` | v1.8.4 |
| v1.6â†’v1.7 non-destructive | âœ… | `aiss/migration.py` | v1.8.4 |
| Automatic backup creation | âœ… | `aiss/migration.py` | v1.8.4 |
| **License System** | âœ… Complete | `aiss/license.py` | v1.1.0 |
| **Certification Service** | âœ… Complete | `aiss/certification.py` | v1.5.0 |
| **Structured Logging** | âœ… Complete | `aiss/logger.py` | v1.1.0 |
| **Telemetry** | âœ… Complete | `aiss/telemetry.py` | v1.1.0 |
| **MCP Integration** | âœ… Complete | `@piqrypt/mcp-server` | v1.4.0 |

---

### TrustGate â€” Governance Engine (Pro+)

| Feature | Status | Module | Version |
|---------|--------|--------|---------|
| Policy engine (deterministic, 10-priority) | âœ… Complete | `trustgate/policy_engine.py` | v1.8.4 |
| Hash-chained governance journal | âœ… Complete | `trustgate/audit_journal.py` | v1.8.4 |
| Immutable policy versioning + SHA-256 | âœ… Complete | `trustgate/policy_versioning.py` | v1.8.4 |
| REQUIRE_HUMAN with TTL + auto-deny | âœ… Complete | `trustgate/decision.py` | v1.8.4 |
| Policy simulation (dry-run) | âœ… Complete | `trustgate/policy_engine.py` | v1.8.4 |
| 3 built-in compliance profiles | âœ… Complete | `trustgate/profiles/` | v1.8.4 |
| EU AI Act Art.14 human oversight | âœ… Complete | `trustgate/policy_engine.py` | v1.8.4 |

### AgentSession â€” Cross-Framework Co-Signed Sessions

| Feature | Status | Module | Version |
|---------|--------|--------|---------|
| N-agent session with pairwise handshakes | âœ… Complete | `bridges/session/__init__.py` | v1.8.4 |
| Same interaction_hash in both memories | âœ… Complete | `bridges/session/__init__.py` | v1.8.4 |
| Payload auto-hashing (RGPD by design) | âœ… Complete | `bridges/session/__init__.py` | v1.8.4 |
| Cross-framework audit export | âœ… Complete | `bridges/session/__init__.py` | v1.8.4 |

### Framework Bridges (10)

| Bridge | Status | Module | Version |
|--------|--------|--------|---------|
| LangChain | âœ… Complete | `bridges/langchain/` | v1.8.4 |
| CrewAI | âœ… Complete | `bridges/crewai/` | v1.8.4 |
| AutoGen | âœ… Complete | `bridges/autogen/` | v1.8.4 |
| OpenClaw | âœ… Complete | `bridges/openclaw/` | v1.8.4 |
| Session | âœ… Complete | `bridges/session/` | v1.8.4 |
| MCP | âœ… Complete | `bridges/mcp/` | v1.8.4 |
| Ollama | âœ… Complete | `bridges/ollama/` | v1.8.4 |
| ROS2 | âœ… Complete | `bridges/ros/` | v1.8.4 |
| RPi | âœ… Complete | `bridges/rpi/` | v1.8.4 |

### Planned Features (Future)

| RFC Section | Feature | Status | Target Version |
|-------------|---------|--------|----------------|
| **Â§17** | **ML-KEM-768** | ðŸ”² Planned | v2.0.0 |
| | Key exchange | ðŸ”² | v2.0.0 |
| **Â§20.2** | **Witness Network** | ðŸ”² Planned | v2.0.0 |
| | Distributed trust | ðŸ”² | v2.0.0 |
| **Â§20.3** | **Blockchain Anchoring** | ðŸ”² Planned | v2.0.0 |
| | Public ledger | ðŸ”² | v2.0.0 |
| **HSM** | **Hardware Security Module** | ðŸ”² Planned | v2.0.0 |
| | Level 3 compliance | ðŸ”² | v2.0.0 |

---

## Testing

**Test Results (v1.7.1):**

| Suite | Tests | Status |
|-------|-------|--------|
| Functional â€” key_store | 7 | âœ… |
| Functional â€” agent_registry | 6 | âœ… |
| Functional â€” identity_session | 6 | âœ… |
| Functional â€” migration | 4 | âœ… |
| Functional â€” tsi_engine | 7 | âœ… |
| Functional â€” a2c_detector | 16 | âœ… |
| Functional â€” anomaly_monitor | 7 | âœ… |
| Functional â€” trust_score | 6 | âœ… |
| Functional â€” identity | 5 | âœ… |
| Functional â€” memory | 5 | âœ… |
| Functional â€” vigil_server | 7 | âœ… |
| RFC Test Vectors | 14 | âœ… |
| Security â€” keystore | 14 | âœ… |
| Security â€” registry | 12 | âœ… + 1 skip (chmod/Windows) |
| Security â€” chain | 19 | âœ… |
| Security â€” session | 7 | âœ… |
| Security â€” migration | 4 | âœ… |
| Security â€” memory | 4 | âœ… |
| Ollama bridge | 6 | â­ skipped (external dep) |
| **Total** | **472** | **472 passed Â· 14 skipped Â· 0 failed â€” CI vert Python 3.9-3.12** |

**Security coverage:**
- Cryptographic resistance: timing, corruption, forgery, RAM erasure
- Filesystem: path traversal, sanitization, isolation, permissions
- Protocol: replay, fork injection, agent ID spoofing, chain integrity
- Session: lock/unlock, key erasure, context manager

---

## Conformance Level

**Per RFC Â§22.1:**

| Level | Description | Status |
|-------|-------------|--------|
| **Level 1** | Basic compliance (Â§5-12) | âœ… since v1.0.0 |
| **Level 2** | Production ready (Â§5-16) | âœ… since v1.5.0 |
| **Level 3** | Regulated environments (HSM audit) | ðŸ”² v2.0.0 |

**Current: Level 2 â€” Production Ready**

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
| scrypt (Colin Percival, 2009) | Key derivation (N=2Â¹â·) |

**Regulatory alignment:** SOC2 Â· ISO 27001 Â· HIPAA Â· GDPR Art. 5.1.f

---

## MCP Integration

**Repository:** https://github.com/piqrypt/piqrypt-mcp-server  
**Tools:** `piqrypt_stamp_event` Â· `piqrypt_verify_chain` Â· `piqrypt_export_audit` Â· `piqrypt_search_events`  
**Clients:** Claude Desktop Â· n8n Â· custom MCP clients

---

## License

**Core:** MIT License  
**Pro Features:** Proprietary (Free/Pro/OSS/Enterprise tiers)  
**IP:** e-Soleau DSO2026006483 (INPI France â€” 19/02/2026)

---

*PiQrypt v1.9.0 â€” Reference Implementation of AISS v2.0*  
*https://github.com/piqrypt/piqrypt*

---

**Intellectual Property Notice**

Core protocol concepts described in this document were deposited
via e-Soleau with the French National Institute of Industrial Property (INPI):

Primary deposit:  DSO2026006483 â€” 19 February 2026
Addendum:         DSO2026009143 â€” 12 March 2026

These deposits establish proof of authorship and prior art
for the PCP protocol specification and PiQrypt reference implementation.

PCP (Proof of Continuity Protocol) is an open protocol specification.
It may be implemented independently by any compliant system.
PiQrypt is the reference implementation.

Â© 2026 PiQrypt â€” contact@piqrypt.com
