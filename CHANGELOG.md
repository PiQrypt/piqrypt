# Changelog

All notable changes to PiQrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.4.0] - 2026-02-18

### ✅ MCP Integration — Model Context Protocol

**PiQrypt MCP Server (NEW PACKAGE)**
- Separate package: `@piqrypt/mcp-server` (TypeScript/Node.js)
- Repository: https://github.com/piqrypt/piqrypt-mcp-server
- 4 MCP tools: `piqrypt_stamp_event`, `piqrypt_verify_chain`, `piqrypt_export_audit`, `piqrypt_search_events`
- Compatible with Claude Desktop, n8n 1.88+, custom MCP clients
- Stdio transport (local IPC, no network)

**Python Bridge**
- `bridge.py` — subprocess wrapper for PiQrypt CLI
- Process isolation: all crypto remains in Python core
- Security: private keys never exposed to MCP layer
- Events signed via MCP are **cryptographically identical** to CLI-signed events

**Documentation**
- RFC Appendix F: MCP Integration (see `docs/RFC.md`)
- MCP compliance documentation
- Integration guides (Claude Desktop, n8n)
- Security model + audit logging

**RFC Compliance**
- ✅ RFC AISS-1.1 compliant (MCP = transport layer only)
- ✅ No modification of cryptographic operations
- ✅ Identical legal standing to CLI-signed events
- ✅ Same Ed25519/Dilithium3 signatures
- ✅ Same RFC 8785 canonical JSON
- ✅ Authority Binding Layer compatible
- ✅ Canonical History Rule compatible
- ✅ External certification compatible

**Use Cases Enabled**
- AI agents (Claude Desktop with MCP)
- n8n workflow automation (no-code audit trail)
- Trading bots (SEC/FINRA compliance via MCP)
- HR automation (GDPR compliance)
- Healthcare AI (HIPAA audit trail)

**Distribution**
- PiQrypt Core: PyPI (`pip install piqrypt`)
- MCP Server: npm (`npm install @piqrypt/mcp-server`)

**Tests**
- MCP bridge tests: 4/4 passing
- Total tests: 32/32 passing

---

## [1.3.0] - 2026-02-18

### ✅ External Certification by PiQrypt Inc.

**Certification Authority (CA)**
- Generated PiQrypt CA keypair (Ed25519) for external certification
- CA public key distributed in `aiss/ca/piqrypt-ca-public.key`
- CA private key stored securely offline

**New Module: `aiss/external_cert.py`**
- `create_certification_request()` — package audit + cert into ZIP for email
- `validate_and_certify()` — PiQrypt-side validation + certification generation
- `verify_piqrypt_certification()` — user-side verification of PiQrypt certificate
- Exception: `CertificationError`

**CLI Commands**
- `piqrypt certify-request AUDIT.json AUDIT.json.cert --email user@company.com`
- `piqrypt certify-verify AUDIT.piqrypt-certified`

**Validation Script (PiQrypt Staff)**
- `scripts/validate_certification_request.py` — validates and certifies exports
- Email-based workflow (no backend required)

**Legal Value**
- Self-certification: Agent signs own export
- External certification: PiQrypt Inc. (trusted third party) independently verifies
- 10x stronger legal standing for audits, compliance, litigation

**Tests**
- 2 new tests (workflow + CLI)
- Total: 28/28 passing

---

## [1.2.0] - 2026-02-17

### ✅ Sprint 3 — Memory Indexation & Archives

**Part 1: Memory Index System**
- New module `aiss/index.py` — SQLite-backed index for fast event search
- `MemoryIndex` class — search(), search_by_hash_prefix(), find_by_nonce()
- Integration in `memory.py` — auto-update index on store_event
- Search 10-1000x faster than linear scan
- Index location: `~/.piqrypt/events/*/index.db`

**Part 2: Portable Archives with Search**
- Updated `create_archive()` — includes `index.json` for search without decryption
- Archive structure v1.1: data.enc/json + **index.json** + decrypt.py v2
- `decrypt.py` v2 standalone — interactive shell + fast search
- Selective decryption — only decrypt matching events
- Export filtered results

**Tests**
- 4 new tests
- Total: 26/26 passing

---

## [1.1.0] - 2026-02-17

### Sprint 2 — Certified Export & Deep Status

**Certified Export**
- Extended `cmd_export()` — `--certified` flag
- `certify_export()` — creates cryptographic certificate (.cert file)
- CLI `verify-export` command

**Tests**
- 4 new tests
- Total: 22/22 passing

---

## [1.0.0] - 2026-02-16

### Initial Public Release

**Core Features**
- Ed25519 signatures (AISS-1.0)
- Dilithium3 post-quantum signatures (AISS-2.0)
- Hash chain verification
- Fork detection
- Authority Binding Layer
- Canonical History Rule
- Memory system (Free plaintext, Pro encrypted)
- RFC 3161 timestamps
- A2A handshake
- License system (Free/Pro/OSS)
- Telemetry (opt-in)
- CLI (32 commands)
- Tests: 18/18 passing

---

## Contact

**Email:** piqrypt@gmail.com  
**GitHub:** https://github.com/piqrypt/piqrypt  
**PyPI:** https://pypi.org/project/piqrypt/
