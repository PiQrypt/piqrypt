# Changelog

All notable changes to PiQrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.7.1] - 2026-03-23

### ✅ TrustGate — Governance Engine (New Major Component)

**Overview:** TrustGate is PiQrypt's fourth and top layer — a deterministic policy engine that intercepts agent actions before execution and applies governance rules derived from EU AI Act, NIST AI RMF, and ANSSI guidelines. Every decision is signed, hash-chained, and auditable.

**Design principle:** Zero AI, zero heuristics, zero non-reproducible behavior. Same input → same output, always, verifiably.

**`trustgate/policy_engine.py` — Deterministic Rule Engine**
- 10-priority evaluation order, fully documented and auditable
- Priority 1: VRS above block threshold → BLOCK [ANSSI R9 / NIST MANAGE 1.3]
- Priority 2: Dangerous pattern match (regex on full payload_str) → BLOCK [ANSSI R25]
- Priority 3: Role violation (least privilege) → BLOCK [ANSSI R26/R30]
- Priority 4: TSI CRITICAL → BLOCK or REQUIRE_HUMAN (configurable) [NIST MEASURE 2.5]
- Priority 5: Network domain violation (Zero Trust) → BLOCK [ANSSI R28]
- Priority 6: VRS above human threshold → REQUIRE_HUMAN [AI Act Art.14]
- Priority 7: TSI UNSTABLE → REQUIRE_HUMAN (configurable)
- Priority 8: Escalation threshold reached → RESTRICTED
- Priority 9: TSI WATCH → ALLOW_WITH_LOG
- Priority 10: Default → ALLOW
- `simulate()` — dry-run evaluation for policy testing without side effects

**`trustgate/policy_loader.py` — Hash-Verified Policy Loading**
- YAML policy files with SHA-256 content hash verification on every load (ANSSI R35)
- Three compliance profiles included: `ai_act_high_risk.yaml`, `nist_balanced.yaml`, `anssi_strict.yaml`
- `PolicyIntegrityError` on hash mismatch — tampered policy files are rejected
- Role-action binding: `allowed_actions` per role, `dangerous_patterns` as regex list
- Network whitelist, VRS thresholds, escalation config — all in policy file

**`trustgate/decision.py` — Signed Decision Records**
- `Decision` dataclass: outcome + reason + compliance references + policy hash at decision time
- Outcomes: ALLOW / ALLOW_WITH_LOG / REQUIRE_HUMAN / RESTRICTED / BLOCK / QUARANTINE
- `Decision.approve(principal_id)` / `Decision.reject(principal_id)` — human oversight flow
- Timeout: REQUIRE_HUMAN decisions auto-expire after configurable TTL (default 300s) → BLOCK

**`trustgate/audit_journal.py` — Hash-Chained Governance Log**
- Every TrustGate decision appended to a hash-linked journal (same mechanism as AISS event chain)
- `JournalEntry.compute_hash()` — SHA-256 over canonical JSON excluding self-hash
- Export: signed JSON or PDF, with chain integrity verification
- Compliance: ANSSI R29, AI Act Art.12, NIST MANAGE 4.1

**`trustgate/policy_versioning.py` — Immutable Policy History**
- Every policy activation creates a version record: hash, activated_by, timestamp, comment
- `PolicyVersioning.diff(v1, v2)` — human-readable diff between policy versions
- Policy history is append-only — never deleted
- Compliance: ANSSI R35, NIST GOVERN 6.2, AI Act Art.9/17

**`trustgate/human_principal.py` — Human Oversight Registry**
- `HumanPrincipal` with role-based permissions (approver / auditor / admin)
- Authentication via HMAC token (v1.7.1) — OIDC/SSO planned for v1.8.0
- `DecisionQueue` — live queue of pending REQUIRE_HUMAN decisions

**`trustgate/trustgate_server.py` — HTTP Governance API**
- Full REST API on port 8422 (localhost only)
- Endpoints: `/api/evaluate`, `/api/decisions`, `/api/decisions/<id>/approve`, `/api/decisions/<id>/reject`, `/api/principals`, `/api/audit`, `/api/policy/simulate`, `/api/vigil/agent-state`
- Integrated with Vigil via `/api/vigil/agent-state` push endpoint

**TrustGate Tests — 3 sprints, complete coverage**
- `test_sprint1.py`: Decision, PolicyLoader, PolicyEngine, AuditJournal, PolicyVersioning
- `test_sprint2.py`: HumanPrincipal, DecisionQueue, Notifier, full REQUIRE_HUMAN flow
- `test_sprint3.py`: Full HTTP API integration — every endpoint, every flow

---

### ✅ 9 Framework Bridges — Complete Ecosystem Coverage

**New bridges in v1.7.1** (in addition to MCP bridge from v1.4.0):

| Bridge | Package | Status |
|--------|---------|--------|
| `piqrypt-langchain` | LangChain / LangGraph | ✅ Tested |
| `piqrypt-crewai` | CrewAI multi-agent crews | ✅ Tested |
| `piqrypt-autogen` | Microsoft AutoGen | ✅ Tested |
| `piqrypt-openclaw` | OpenClaw reasoning agents | ✅ Tested |
| `piqrypt-session` | Cross-framework multi-agent sessions | ✅ Tested |
| `piqrypt-mcp` | Model Context Protocol (v1.4.0) | ✅ Tested |
| `piqrypt-ollama` | Ollama local LLMs | ✅ Tested (external dep) |
| `piqrypt-ros2` | ROS2 robotics | ✅ Tested |
| `piqrypt-rpi` | Raspberry Pi edge agents | ✅ Tested |

Each bridge provides a drop-in wrapper that signs every agent action into the AISS chain without modifying application logic.

---

### ✅ AgentSession — Cross-Framework Co-Signed Audit Trails (New)

**`bridges/session/__init__.py` — `AgentSession` class**

The first tool to provide cryptographic co-signatures across framework boundaries. Every cross-agent interaction is co-signed in **both** agents' memories with the **same payload_hash** — making tampering immediately detectable regardless of which framework each agent uses.

Key properties:
- `session.start()` — performs N*(N-1)/2 pairwise Ed25519 A2A handshakes before any interaction
- `session.stamp(agent, event_type, payload, peer=peer)` — co-signed interaction: both agents sign, same `interaction_hash` in both memories
- Raw payloads never stored — only SHA-256 hashes (RGPD by design)
- `session.export(path)` — full cross-framework audit trail as JSON
- Framework-agnostic: Claude, LangGraph, CrewAI, AutoGen, ROS2, RPi in the same session

```python
from piqrypt_session import AgentSession

session = AgentSession([
    {"name": "claude",    "identity_file": "~/.piqrypt/claude.json"},
    {"name": "langgraph", "identity_file": "~/.piqrypt/langgraph.json"},
    {"name": "crewai",    "identity_file": "~/.piqrypt/crewai.json"},
])
session.start()
session.stamp("claude", "instruction_sent", {"task": "analyse"}, peer="langgraph")
session.export("audit.json")
```

---

### ✅ Vigil — Major Enhancements

**External Peer Observation (§ 15 RFC AISS v2.0)**
- Agents can declare external peers not registered in the local installation
- External peer events contribute to A2C correlation scoring
- Network graph in Vigil dashboard displays both registered and external peers

**Fork Detection — FORK_AFTER_FINALIZATION**
- New critical anomaly: fork detected after a TSA-anchored FINAL event
- Immediately escalated to TrustGate as CRITICAL
- Documented in Alert Journal with chain evidence

**Demo Enhancements**
- `demo_families.py` — 3 families of agents (ALPHA, BETA, GAMMA), `--family` selector
- `start_families.ps1` / `start_legacy.ps1` — single Vigil window launchers (Windows)
- External peers visible in Vigil network graph

---

### ✅ Documentation — Complete Protocol Corpus

**New documents produced for v1.7.1:**

| Document | Description |
|----------|-------------|
| `WHITEPAPER_v2.0.md` | PiQrypt technical whitepaper with PCP positioning |
| `RFC_AISS_v2.0.md` | 1790-line normative RFC (26 sections + 8 appendices) |
| `RFC_AISS_v2.0_narrative.md` | RFC v2.0 + 17 PCP narrative blocks + §21.4 extended threat model |
| `PCP_Protocol_Paper.md` | Proof of Continuity Protocol — infrastructure positioning paper |
| `ESOLEAU_ADDENDUM_v2.md` | e-Soleau addendum DSO2026009143 — 12/03/2026 (v1.7.1 additions) |
| `SECURITY.md` | Complete security policy, threat model, known limitations |

**RFC AISS v2.0 — New sections vs v1.1:**
- §14 PCP Architecture
- §15 External Peer Observation
- §19 Vigil complete (TSI / VRS / A2C)
- §20 TrustGate complete
- §21.4 Extended Threat Scenarios (5 new threat classes)
- Appendix E: 9 bridges specification
- Appendix F: Vigil API reference
- Appendix G: TrustGate YAML schema

---

### ✅ Test Suite — 325 Tests Passing

| Suite | Tests | Status |
|-------|-------|--------|
| Core AISS (chain, crypto, identity) | 143 | ✅ All pass |
| Security (61 dedicated tests) | 61 | ✅ All pass |
| TrustGate (3 sprints) | ~80 | ✅ All pass |
| Vigil server | 14 | ✅ All pass |
| Bridges (8 frameworks) | ~27 | ✅ All pass |
| **Total** | **325** | **✅ 325/325** |

Known infrastructure failures (17, not counted above):
- External certification endpoint (requires live `api.piqrypt.com`)
- Live TSA server (requires network)
- Pro-tier features without valid Pro license

Smoke test: 70/74 (4 acceptable failures — Pro features, external deps)

---

### ✅ IP & Legal

- e-Soleau addendum prepared: v1.7.1 additions (TrustGate, 9 bridges, AgentSession, PCP corpus)
- Deposits: DSO2026006483 (19/02/2026) + DSO2026009143 (12/03/2026) — INPI France

---

### Documentation

- Added 5 SVG diagrams in `docs/diagrams/` :
  `architecture_four_layers`, `trustgate_decision_flow`,
  `agent_session_cosign`, `license_tiers`,
  `pcp_protocol_stack`
- Added `docs/diagrams/README.md` — index of all diagrams
- Added `docs/A2A_SESSION_GUIDE.md` — complete AgentSession guide
- Strengthened `README.md` positioning :
  OAuth/PCP analogy, TrustGate advisory clarification,
  AgentSession cross-framework section,
  1-line integration callout, proof of disobedience bullet
- Fixed contact email in `INTEGRATION.md`

---

### Known Limitations (v1.7.1)

| Limitation | Impact | Planned |
|-----------|--------|---------|
| `verify_tsa_token()` checks DER structure only — no CMS/PKCS7 verification | Forged TSA token could pass | v1.8.0 |
| Vigil/TrustGate use static `VIGIL_TOKEN`/`TRUSTGATE_TOKEN` env var | No per-user auth | v1.8.0 OIDC/SSO |
| JSON flat-file event storage | Degrades >100k events/agent | v2.0 PostgreSQL |
| `license.py` HMAC (Free tier) is client-side | Bypassable by motivated developer | By design |


---

## [1.7.0] - 2026-03-02

### ✅ Security Hardening & API Stabilization

**KeyStore — Cryptographic Reinforcement**
- scrypt parameters: N=2¹⁷, r=8, p=1 — brute-force resistance guaranteed (>400ms/attempt)
- AES-256-GCM encryption with 96-bit nonce and 128-bit authentication tag
- Magic bytes `PQKY` + version byte validation on load — corrupted files rejected cleanly
- `_secure_erase()` — private key zeroed in RAM after use
- Fixed file size: exactly 97 bytes per `.key.enc` file
- New aliases: `encrypt_key()`, `load_key()` for backward compatibility
- New exceptions: `KeyFileCorruptedError`, `InvalidPassphraseError`
- Exposed constants: `MAGIC`, `VERSION`, `EXPECTED_FILE_SIZE`, `_SCRYPT_N`

**AgentRegistry — Object-Oriented API**
- New class `AgentRegistry(registry_path)` wrapping standalone functions
- Methods: `.register()`, `.list()`, `.get()`
- Path traversal protection: `_safe_name()` sanitizes all agent names
- `../`, backslashes, null bytes, spaces → neutralized
- Names truncated to 64 characters maximum
- Agent directories created with `chmod 700` (Linux/Mac)
- Backward compatible with existing standalone functions

**TSI Engine — API Fix**
- `compute_tsi()` now returns both `tsi_state` and `tsi` keys (alias)
- Fixes compatibility with downstream consumers expecting short key

**Identity — base_dir Support**
- `create_agent_identity()` now accepts optional `base_dir` parameter
- Enables isolated test environments without touching `~/.piqrypt`

**Memory — base_dir Support**
- `init_memory_dirs()`, `store_event_free()`, `load_events_free()` accept optional `agent_name`
- Full agent isolation via registry

**Migration — Compatibility Alias**
- New `migrate_agent(base_dir, agent_name, passphrase)` alias for `run_migration()`
- Backward compatible with v1.6.0 call signatures

### ✅ Test Suite — Complete Coverage

**RFC Test Vectors (NEW)**
- `tests/test_vectors.py` — 14 normative RFC compliance tests
- Covers: JCS canonicalization, agent ID derivation, event hashing, fork detection, replay protection
- Converted from pytest to unittest for consistency with test runner

**Security Tests (NEW — 45 tests)**
- `test_security_keystore.py` — 14 tests: timing, corruption, magic bytes, RAM erasure, confidentiality
- `test_security_registry.py` — 13 tests: path traversal, sanitization, isolation, permissions
- `test_security_chain.py` — 19 tests: signature forgery, payload tampering, agent ID spoofing, fork injection
- `test_security_session.py` — 7 tests: lock/unlock, RAM erasure, context manager
- `test_security_migration.py` — 4 tests: idempotence, backup verification, corrupt source handling
- `test_security_memory.py` — 4 tests: flood resistance, injection, unicode, agent isolation

**Test Results**
- Total: 143 tests executed
- Passed: 136/143
- Skipped: 7 (Ollama bridge — external dependency not installed)
- Failed: 0

**Cross-Platform**
- All tests pass on Windows (PowerShell) and Linux
- `os.devnull` used instead of `/dev/null` in test runner

### ✅ Bug Fixes
- `test_aiss_tsi_engine.py` rewritten to use `tempfile` + `patch(TSI_DIR)` instead of fragile `builtins.open` mock — fixes Windows compatibility
- `run_all.py` — added `import os` (was missing, caused `NameError` on some platforms)

---

## [1.6.0] - 2026-02-25

### ✅ Key Rotation Chain — Complete Memory Continuity

**Problem solved:** When an agent rotates its keys, its agent_id changes. Previous versions
could not reconstruct the full history across rotation boundaries — `search_events(agent_id=new)`
only returned post-rotation events.

**New: `load_full_history(agent_id)`**
- Automatically traverses key rotation chain (A → B → C → ...)
- Works from any identity in the chain (oldest, newest, or middle)
- Supports N successive rotations (recursive algorithm)
- Fast path via SQLite index, slow path via linear scan fallback
- `include_markers=True` inserts synthetic rotation markers for display

**New: `get_history_summary(agent_id)`**
- Returns identity chain, total event count, rotation count, timestamps
- Per-identity breakdown (events, date range)

**Updated: `search_events()`** — 2 new parameters
- `session_id`: filter events by multi-agent session (native SQL via index)
- `follow_rotation=True`: expand participant to full identity chain automatically

**Updated: SQLite index schema**
- New column: `successor_agent_id` — indexed for O(1) rotation chain traversal
- New column: `session_id` — indexed for O(1) session search
- New: `MemoryIndex.find_successor(agent_id)`
- New: `MemoryIndex.find_predecessor(agent_id)`
- New: `MemoryIndex.get_full_identity_chain(agent_id)`
- New: `MemoryIndex.search_by_session(session_id)`
- New: `MemoryIndex.migrate_schema()` — safe auto-migration for existing index.db
- `get_stats()` now reports `sessions_count` and `rotations_count`

**New CLI: `piqrypt history <agent_id>`**
- Displays complete chronological history with rotation markers
- `--chain`: show identity chain only
- `--summary`: statistics only
- `--json`: machine-readable output
- `--limit N`: pagination

**Updated CLI: `piqrypt memory search`** — 2 new flags
- `--session <session_id>`: filter by session
- `--follow-rotation`: include events from entire rotation chain

**Migration:** Existing `index.db` files are automatically migrated on first use.
No data loss. New columns default to NULL for pre-existing events.

**Tests:** 90/90 passing (functional suite)

---

## [1.5.0] - 2026-02-22

### ✅ Trust Scoring & Behavioral Monitoring

**New: TSI Engine (`aiss/tsi_engine.py`)**
- Trust State Index: STABLE / WATCH / UNSTABLE / CRITICAL
- Drift detection over 24h sliding window
- Persistence of TSI baseline per agent

**New: A2C Detector (`aiss/a2c_detector.py`)**
- 16 relational anomaly scenarios
- Risk scoring 0.0–1.0, severity: NONE / LOW / MEDIUM / HIGH / CRITICAL

**New: Anomaly Monitor (`aiss/anomaly_monitor.py`)**
- VRS (Vigil Risk Score) composite: TS + TSI + A2C + chain integrity
- Alert journal with deduplication

**New: Vigil Server (`vigil/vigil_server.py`)**
- HTTP dashboard on port 8421
- REST API: `/api/summary`, `/api/alerts`, `/health`
- Live backend with TSI hook

**Tests:** 69/69 passing

---

## [1.4.0] - 2026-02-18

### ✅ MCP Integration — Model Context Protocol

**PiQrypt MCP Server (NEW PACKAGE)**
- Separate package: `@piqrypt/mcp-server` (TypeScript/Node.js)
- 4 MCP tools: `piqrypt_stamp_event`, `piqrypt_verify_chain`, `piqrypt_export_audit`, `piqrypt_search_events`
- Compatible with Claude Desktop, n8n 1.88+, custom MCP clients
- Stdio transport (local IPC, no network)

**Python Bridge**
- `bridge.py` — subprocess wrapper for PiQrypt CLI
- Process isolation: all crypto remains in Python core
- Security: private keys never exposed to MCP layer

**RFC Compliance**
- ✅ RFC AISS-1.1 compliant (MCP = transport layer only)
- ✅ Identical legal standing to CLI-signed events

**Tests:** 32/32 passing

---

## [1.3.0] - 2026-02-18

### ✅ External Certification by PiQrypt Inc.

**New Module: `aiss/external_cert.py`**
- `create_certification_request()` — package audit + cert into ZIP
- `validate_and_certify()` — PiQrypt-side validation + certification
- `verify_piqrypt_certification()` — user-side verification

**CLI Commands**
- `piqrypt certify-request`
- `piqrypt certify-verify`

**Tests:** 28/28 passing

---

## [1.2.0] - 2026-02-17

### ✅ Memory Indexation & Archives

**New: Memory Index System**
- `aiss/index.py` — SQLite-backed index for fast event search
- `MemoryIndex` class: `search()`, `search_by_hash_prefix()`, `find_by_nonce()`
- Search 10–1000x faster than linear scan

**New: Portable Archives**
- `create_archive()` — includes `index.json` for search without decryption
- `decrypt.py` v2 — interactive shell + fast search

**Tests:** 26/26 passing

---

## [1.1.0] - 2026-02-17

### ✅ Certified Export & Deep Status

- Extended `cmd_export()` — `--certified` flag
- `certify_export()` — cryptographic certificate (.cert file)
- CLI `verify-export` command

**Tests:** 22/22 passing

---

## [1.0.0] - 2026-02-16

### ✅ Initial Public Release

- Ed25519 signatures (AISS-1.0)
- Dilithium3 post-quantum signatures (AISS-2.0)
- Hash chain verification + fork detection
- Authority Binding Layer + Canonical History Rule
- Memory system (Free plaintext, Pro encrypted)
- RFC 3161 timestamps
- A2A handshake
- License system (Free/Pro/OSS)
- CLI (32 commands)

**Tests:** 18/18 passing

---

## Contact

**Email:** piqrypt@gmail.com  
**GitHub:** https://github.com/piqrypt/piqrypt  
**PyPI:** https://pypi.org/project/piqrypt/

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
