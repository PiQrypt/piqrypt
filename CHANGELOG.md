# Changelog

All notable changes to PiQrypt will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.10.0] - 2026-10-23

This release adds AISS-2.1 (hybrid Ed25519 + ML-DSA-65 with domain separation), real RFC 3161
verification, a Signer interface, and published test vectors. It also changes how several
existing checks behave, because some of them accepted more than they should have. Read
"Behaviour changes" before upgrading.

### Security

- **Fork resolution no longer trusts a detached, unsigned field.** `aiss.fork` counted an event
  as anchored when its `trusted_timestamp` carried a non-empty token, and broke ties with the
  self-declared `trusted_timestamp.timestamp`. Anyone can add that field to a branch. An event now
  counts as anchored only when a `tsa_verifier` supplied by the caller declares its token verified
  and returns its genTime. Without a verifier no event is anchored: the first two steps are
  neutral and the choice falls to chain length, then hash.
- **`verify_tsa_token` really verifies.** The previous implementation reported `verified` for any
  DER blob starting with byte 0x30. It now checks the CMS signature, the TSA certificate
  (critical `timeStamping` extended key usage), the chain to a root of the trust store, the
  imprint recomputed from the event, the nonce, and certificate validity at genTime. See
  `docs/TIMESTAMPS.md` for what is still not checked (revocation first).
- **`secure_agent_key` no longer destroys the private key on failure.** The old key was deleted
  before the new file was written. The new file is now written to a temporary file and installed
  with `os.replace`, and a plaintext key is removed only after the installed encrypted file has
  been read back and compared.
- **`IdentitySession.unlock` erases the key** it had loaded when the identity file turns out to be
  invalid. Previously the key stayed in memory in a locked session.

### Added

- **AISS-2.1 event format.** Hybrid signatures over a domain-separated message
  `M' = b"PiQrypt-AISS-2.1\x00" || len(label) || label || 0x00 || JCS(event)`, with
  `label = b"Ed25519+ML-DSA-65"` and an empty ML-DSA context. The signed content excludes
  `signatures` and `trusted_timestamp`. Chain hash is SHA-512 (128 hexadecimal characters).
  Signatures are `base64:` prefixed and decoded strictly. Canonicalization is RFC 8785 through
  the new `aiss/canonical_aiss21.py`; `rfc8785>=0.1.4,<0.2` becomes a core dependency. The version
  string is compared by exact equality: `AISS-2.10` is an unknown version, not AISS-2.1.
  AISS-1 and AISS-2.0 events keep their formats and remain verifiable. AISS-1 is frozen by
  `test_vectors/`.
- **Hybrid identities.** `create_agent_identity(hybrid=True)` and
  `piqrypt identity create --hybrid` create an Ed25519 + ML-DSA-65 identity (passphrase required,
  8 characters minimum, one distinct salt per key). `derive_agent_id_aiss21`,
  `export_identity_aiss21` and `load_agent_pq_key` are new. The genesis hash of a hybrid agent is
  derived from its `agent_id`.
- **Upgrade of an existing identity.** `upgrade_agent_identity` and `piqrypt identity upgrade`
  add an ML-DSA-65 key pair to an AISS-1 identity without changing its `agent_id`, through an
  `identity_binding` signed by both keys. The binding is classical-only in assurance, because the
  historical `agent_id` does not commit to the ML-DSA key. `verify_identity_binding` and
  `identity_binding_assurance` recompute that level and never read a declared value. The previous
  `identity.json` is kept as `identity.pre-upgrade.json`.
- **Key store v2** for the ML-DSA-65 private key (`private_pq.key.enc`, magic `PQKY`, version
  0x02): AES-256-GCM with the 42-byte header as associated data, scrypt, bounded parameters
  checked on read and write, atomic write, mandatory passphrase, NFKC normalization. The v1 file
  (`private.key.enc`) is unchanged and a v1 loader rejects a v2 blob.
- **Chain verification for the new identity forms.** `verify_chain` and `get_verification_report`
  distinguish classical, upgraded and native hybrid identities, check the `agent_id` of every
  event, reject ambiguous identity documents, and apply an anti-downgrade rule (a native hybrid
  chain accepts only AISS-2.1; an upgraded chain accepts no AISS-1 or AISS-2.0 event after its
  first AISS-2.1 event). The report exposes `binding_assurance`.
- **Hybrid key rotation anchored in the chain.** `create_rotation_attestation_hybrid` and
  `verify_rotation_attestation_hybrid` (four signatures under a dedicated domain prefix),
  `create_rotation_event_aiss21`, `verify_rotation_chain`, and the `rotation_previous_hash`
  parameter of `stamp_genesis_event_aiss2_hybrid`. A rotation to the same `agent_id` is rejected.
  `create_rotation_attestation` (AISS-1) is unchanged.
- **Signer interface** (`aiss.signer` and `aiss.signer_conformance`, MIT; `aiss.signer_file`,
  Elastic-2.0): `Signer`, `HybridSigner`, in-memory and encrypted-file signers, reusable
  conformance checks, and an optional trailing `signer` parameter on
  `stamp_event_aiss2_hybrid` and `stamp_genesis_event_aiss2_hybrid`. See `docs/SIGNER.md`. No
  HSM, KMS or PKCS#11 module has been tested.
- **RFC 3161 verification.** `aiss.rfc3161.verify_tsa_token(event, trust_roots=None)` and
  `make_tsa_verifier`, behind the new optional extra `timestamp` (`rfc3161-client>=1.0.9,<2`).
  Statuses are `verified`, `structure_only`, `pending` and `invalid`. For AISS-2.1 events the
  imprint is the SHA-512 chain hash; AISS-1 and AISS-2.0 stay on SHA-256. Requests carry a nonce
  that the response must echo. PiQrypt ships no trust root. `get_verification_report` gains an
  informational `tsa` section (counts per status, details for every event not verified, number
  of roots used) that never changes `valid`. See `docs/TIMESTAMPS.md`.
- **Test vectors.** NIST ACVP ML-DSA-65 vectors (keyGen, sigVer, sigGen; deterministic groups) are
  reproduced by dilithium-py. `test_vectors_aiss21/` holds 57 AISS-2.1 vectors (agent_id, hash and
  signed message, events, chains, identities, rotation, positive and negative) produced by the
  deterministic generator `scripts/gen_aiss21_vectors.py`, plus `verify_standalone.py`, an
  independent verifier that imports nothing from `aiss` or `piqrypt`. These are interoperability
  test data, not a certification.
- **`.github/workflows/interop-liboqs.yml`** (manual trigger only) and `scripts/interop_liboqs.py`
  to cross-check liboqs and dilithium-py on the vectors. **This workflow has never been run.**

### Behaviour changes

- `verify_tsa_token(event, trust_roots=None)`: the `expected_data` parameter is removed. Statuses
  are lowercase strings. Code that relied on any 0x30-prefixed DER being `verified` will now see
  `structure_only` or `invalid`. A pending placeholder is `{"status": "pending"}`.
- `aiss.fork` functions (`select_canonical_chain`, `detect_fork_after_finalization`,
  `classify_fork`, `resolve_fork_canonical`) take an optional `tsa_verifier`. The default (none)
  anchors nothing. `aiss.tsa_token.has_tsa_token` is the single structural check (MIT) and proves
  nothing by itself.
- `request_timestamp` and `retry_pending_timestamps` follow the event version (SHA-512 for
  AISS-2.1). The wording "legally admissible" and similar statements about legal value are
  removed from the RFC 3161 code, its docstrings and its messages.
- `verify_chain` raises `InvalidChainError` (with the event index) for a non-text version or an
  event that is not an object, and for inputs of the wrong type (events not a list or tuple,
  identity not a dictionary). `verify_aiss2_hybrid` turns any malformed input into
  `InvalidSignatureError`. An integer outside +/-(2^53-1) in an AISS-2.1 event raises
  `InvalidCanonicalJSONError` (also a `ValueError`). Valid inputs give the same verdict as before.
- `piqrypt certify-verify` changed what it prints, not what it checks. It no longer prints
  "PiQrypt Certification VALID", "independently certified" or "Valid for legal and compliance
  purposes". It prints that the attestation signature was verified locally, lists what this
  command checked and did not check, presents the attestation values as declared by the issuer, and
  states that the attestation is not an independent audit and not a legal or regulatory
  statement. File formats, JSON fields, exit codes and API return values are unchanged. Scripts
  that parse the old output text must be updated. New attestations carry a factual
  `legal_statement` that lists the checks actually made.
- `piqrypt stamp` refuses an identity that has a `public_key_pq` (it only produces AISS-1 events).
  `piqrypt identity rotate` refuses such an identity (it would drop the ML-DSA key); use
  `create_rotation_event_aiss21` and `verify_rotation_chain`. CLI commands that read
  `identity['public_key']`, and the certified-export verification, refuse a native hybrid identity
  with an explicit error and exit code 1. `IdentitySession` refuses a native hybrid identity with
  `UnsupportedIdentityError`.
- `secure_agent_key` accepts `old_passphrase_pq` (default: `old_passphrase`) so that the two keys of
  an upgraded identity can be under different passphrases; a refused ML-DSA key raises
  `PQKeyPassphraseError`. An Ed25519 key that is encrypted but given no `old_passphrase` raises a
  clear `ValueError`.
- `stamp_genesis_event_aiss2_hybrid` accepts `public_key_pq`, `tsa_stamp_after` and
  `rotation_previous_hash`. Existing callers are unaffected.
- Extras: `post-quantum` is now `liboqs-python>=0.16.0.1` for Python 3.10 and later (0.16.0
  is affected by GHSA-pw23-r5gj-42g8); `timestamp` is new; `rfc3161-client` is added to `dev`.
  `post-quantum-py` (dilithium-py) is unchanged. See "Known limitations" about that backend.
- The project description (PyPI summary) is now "Trust infrastructure for autonomous AI agents:
  identity, observability, governance".
- Licence gating is unchanged in this release (see `docs/LIMITS_AND_POSTURE.md`).
- TrustGate: ANSSI references. Decision reasons, error messages, the console and the documentation no longer cite ANSSI R22, R26, R28, R30 or R35: in the ANSSI guide ANSSI-PA-102 (2024) those numbers cover other topics than the controls they were attached to. R9, R25, R27 and R29 are kept. The `anssi_strict` profile keeps its name and its thresholds. The profile, the console and the smoke tests no longer state compliance, a coverage percentage or a count of requirements covered. These are references, not an assessment of compliance with the ANSSI guide, the NIST AI RMF or the EU AI Act.
- TrustGate: NIST and EU AI Act tags corrected. Tags attached to controls they did not describe were fixed or removed in decision reasons (`[NIST MEASURE 2.5]` is now `[NIST MEASURE 2.4]`; NIST MAP 5.1, GOVERN 1.2, GOVERN 4.1 and AI Act Art.9 are removed from the pattern, role, network and TSI CRITICAL reasons), docstrings, the console and the profiles. Journals already written keep their old text. No threshold, rule or outcome changed.
- Wording. Docstrings, READMEs and banners no longer say "tamper-proof", "immutable" or "GDPR-compliant", and the ML-DSA-65 docstrings no longer say Dilithium3. The long documents carry a scope notice, a wrong fine amount in the PCP paper was corrected (Article 99(4): EUR 15 million or 3%), and the badge snippets no longer claim compliance. No logic changed.

### Licensing

- `aiss/key_store.py` and `aiss/logger.py` are now released under the MIT license (they were Elastic-2.0). Their code is unchanged. `aiss/signer_file.py` remains Elastic-2.0. Versions released before 1.10.0 keep the license they were published under.
- The ML-DSA-65 backend (`aiss/crypto/dilithium_liboqs.py`) no longer applies its 1000 operation per-process limit when the module `aiss.license` does not exist, which is the case in the `aiss-standard` (MIT) build. Releases of `aiss-standard` up to 2.0.2 applied it. In `piqrypt` nothing changes: the limit still applies without a licence that grants the quantum feature.

### Fixed

- `secure_agent_key` no longer leaves `private.key.json.bak` behind when it encrypts a plaintext
  key: after verification the plaintext file is overwritten with zeros, synced and removed. If
  removal fails a warning is logged and the operation still succeeds. Overwriting does not
  guarantee physical erasure on journaled file systems or SSDs. Backups left by earlier versions
  are not removed automatically; delete them yourself once you have checked the encrypted key.
- `_tsa_report` raised `AttributeError` in an MIT-only installation when `trusted_timestamp` was
  not an object. Such a value is now counted as `invalid` and listed in `details`.
- Double-encoded characters (UTF-8 read as cp1252 and saved again) are repaired in
  `docs/RFC_AISS_v2.0.md`, `docs/RFC_AISS_v2.0_narrative.md`, `docs/IMPLEMENTATION_STATUS.md`,
  `bridges/hermes/__init__.py` and its tests. Code and test logic are unchanged. The restored
  characters include em dashes and arrows in those three documents.

### Tests

- Suites for AISS-2.1 events, identities, bindings, rotation, key store v2, strict base64, fork
  anchoring, RFC 3161 (real fixtures from freetsa.org in SHA-512 and SHA-256, no network), the
  Signer interface, fail-closed verification, and the Pro licence path with an ephemeral token
  signed by a throwaway key. `tests/test_verify_standalone.py` runs the independent verifier with
  `aiss` and `piqrypt` imports blocked and compares its verdicts with the library's.

### Known limitations

- The normative text of AISS-2.1 is not published yet. Until it is, the vectors and the reference
  implementation define the format, and `verify_standalone.py` guards against the implementation
  defining the specification by itself.
- ML-DSA-65 is exercised against NIST ACVP vectors through dilithium-py only. The liboqs
  interoperability workflow has never run. The pure-Python fallback is not constant time and its
  authors state that it is not meant for cryptographic use; install the `post-quantum` extra for
  signing.
- No revocation check on TSA certificates, no trust root shipped, no qualified timestamps. Tokens
  from DigiCert and Entrust currently verify as `invalid` because `rfc3161-client` 1.0.9 cannot parse
  them.
- The attestation read by `piqrypt certify-verify` contains no hash of the audit data in the same
  file, so the command cannot link the two.
- A chain passed to `verify_chain` is not required to start at a genesis event, and a fork can only
  be detected by comparing two logs.
- No hardware security module has been tested. Identity bindings and hybrid rotation attestations
  are not yet adapted to the Signer interface.
- The persistent ML-DSA certificate authority announced in the 1.9.2 notes is not part of 1.10.0.
  It is planned for 1.11.
- TrustGate HTTP approvals are not authenticated per person, and the TrustGate journal hash covers only
  12 of its fields. See SECURITY.md. Planned for 1.10.1.
- `get_scope_assessment` matches keywords inside words. It is a heuristic, not a determination.
- `trustgate/smoke_test_trustgate.py` fails mostly on its HTTP blocks (13 to 15): the script sends no
  bearer token and the server answers 401. The pytest suites of TrustGate pass.

---

## [1.9.2] - 2026-10-21

### Fixed

- **`aiss/crypto/dilithium_liboqs.py`**: Replaced Dilithium3 (round 3, 3293-byte signatures)
  with ML-DSA-65 (NIST FIPS 204, 3309-byte signatures). Key sizes: public 1952 B, private 4032 B,
  signature 3309 B. The liboqs backend now requires `oqs.Signature("ML-DSA-65")`
  (liboqs-python >= 0.12.0); the pure-Python fallback uses `dilithium_py.ml_dsa.ML_DSA_65`
  (dilithium-py >= 1.0.0). Signatures produced by either Dilithium3 variant are not verifiable
  with ML-DSA-65 and vice versa.

- **`aiss/stamp_aiss2.py`**: `stamp_event_aiss2_hybrid` raised a `TypeError` on every call:
  `log_event_signed(agent_id, event_type, nonce)` passed 3 arguments to a 2-argument function.
  Replaced with `log_event_signed_alias`, the existing 3-argument alias in `logger.py`.

- **`aiss/stamp_aiss2.py`, `aiss/verify.py`, `aiss/rfc3161.py`**: `trusted_timestamp` is now
  a detached field, excluded from signed content. `stamp_event_aiss2_hybrid` inserts the
  `{"status": "pending"}` placeholder after signatures, not before. `verify_aiss2_hybrid` and
  `verify_signature` strip `trusted_timestamp` before canonicalization. `stamp_event_with_tsa`
  canonicalizes without `trusted_timestamp`. Adding or updating a TSA token no longer invalidates
  Ed25519 or ML-DSA-65 signatures.

- **`aiss/chain.py`**: `compute_event_hash` now excludes `trusted_timestamp` in addition to
  `signature`. A TSA token obtained after an event is already linked into a chain no longer breaks
  chain verification.

- **`aiss/crypto/dilithium_liboqs.py`**: The PQ demo limit of 1000 operations previously only
  checked `AISS2_LICENSE_KEY`. The check is now lazy and accepts any Pro+ license recognized by
  `aiss.license.get_license().has_feature("quantum")` (covers `AISS2_LICENSE_KEY`, a verified JWT
  in `PIQRYPT_LICENSE_KEY`, and `license.jwt`). A non-empty but invalid `PIQRYPT_LICENSE_KEY`
  falls back to Free tier and keeps the limit active.

- **`aiss/verify.py`**: `verify_chain` silently ignored AISS-2 events (missing `signature`
  field). Events whose version starts with `AISS-2` are now dispatched to `verify_aiss2_hybrid`.
  Without `public_key_pq`, an `InvalidChainError` is raised; there is no silent fallback to
  Ed25519-only verification.

- **`aiss/certification.py`**: `certify_pq_bundle` generates an ephemeral ML-DSA-65 key pair
  on each call with no anchor to a persistent CA. The `post_quantum` certificate field and
  docstring now reflect this limitation. The `.pqz` archive is documented as a standard ZIP
  (unencrypted at this tier). A persistent ML-DSA CA is planned for v1.10.0.

### Changed

- `pyproject.toml`: floor versions raised from `liboqs-python>=0.8.0` to `>=0.12.0` and from
  `dilithium-py>=0.1.0` to `>=1.0.0` so that ML-DSA-65 is available.
- CI workflow: `dilithium-py>=1.0.0` is now installed explicitly so post-quantum tests run in CI.
- Labels `"ML-DSA-65 (Dilithium3)"` corrected to `"ML-DSA-65"` in `certification.py`,
  `agent_context.py`, `stamp_aiss2.py`, and `__init__.py`.

### Tests

- New file `tests/test_aiss2_ml_dsa.py` (28 tests): FIPS 204 sizes, hybrid round-trip,
  `trusted_timestamp` excluded from signed content and from chain hash, tamper detection on
  payload and signatures, PQ signature removal, TSA unavailable/success for AISS-1 and AISS-2,
  `verify_chain` with and without PQ key, mixed AISS-1 + AISS-2 chain, version downgrade,
  PQ demo limit by license source including bogus env var and valid dev JWT. `_make_license`
  fixture forces a tier without network or secret.

### Notes

- ML-DSA-65 signatures are not compatible with the former Dilithium3 round 3 signatures.

---

## [1.9.1] - 2026-06-01

### Changed
- Telemetry is now enabled by default on fresh installs (opt-out model)
  Existing users with a telemetry.json config are unaffected
  PIQRYPT_TELEMETRY=0 env var still disables at any time

### Added
- First-run telemetry notice in CLI (printed once before any command)
- Telemetry opt-out notice in onboarding dashboard (static/onboarding/index.html)
- "install" telemetry event sent on first CLI run

### Fixed
- cli/main.py: split `import json, os` into two lines (ruff E401)

### Docs
- TELEMETRY.md updated to reflect opt-out model

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
- Authentication via HMAC token (v1.7.1) — OIDC/SSO planned for v1.8.4
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
| `verify_tsa_token()` checks DER structure only — no CMS/PKCS7 verification | Forged TSA token could pass | v1.8.4 |
| Vigil/TrustGate use static `VIGIL_TOKEN`/`TRUSTGATE_TOKEN` env var | No per-user auth | v1.8.4 OIDC/SSO |
| JSON flat-file event storage | Degrades >100k events/agent | v2.0 PostgreSQL |
| `license.py` HMAC (Free tier) is client-side | Bypassable by motivated developer | By design |


---

## [1.8.5] - 2026-03-29

### Changed
- CI green: 501 tests passing on all OS/Python versions
- Fixed aiss mock contamination in test_bridge_protocol.py
- Fixed piqrypt.aiss namespace conflict (piqrypt* -> piqrypt in packages.find)
- BridgeProtocol v1.1.0 — 9 bridges unified

## [1.8.4] - 2026-03-02

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
