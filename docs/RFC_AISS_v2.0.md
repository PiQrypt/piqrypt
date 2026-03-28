# AISS — Agent Identity and Signature Standard
## RFC v2.0 — Standards Track

```
Status:     Standards Track — Public Review Draft
Version:    2.0.0
Date:       March 2026
Supersedes: AISS RFC v1.1
Repository: https://github.com/piqrypt/aiss-spec
Authors:    PiQrypt
Contact:    contact@piqrypt.com
IP:         e-Soleau DSO2026006483 + DSO2026009143 (INPI France)
```

---

## Abstract

This document specifies AISS v2.0 (Agent Identity and Signature Standard), the cryptographic foundation of the Proof of Continuity Protocol (PCP). AISS defines deterministic agent identity, tamper-evident event chains, cross-agent trust establishment, and the structural interfaces between the four PCP layers: AISS, PiQrypt Core, Vigil, and TrustGate.

Version 2.0 extends AISS v1.1 with:

- **§ 17 — TrustGate**: formal specification of the governance and human oversight gate
- **§ 15 — External Peer Observation**: unilateral recording of interactions with non-AISS systems
- **§ 14 — PCP Protocol Stack**: formal definition of the four-layer architecture
- **§ 16 — Vigil Behavioral Monitoring**: complete VRS, TSI, and A2C specifications
- Updated conformance table (v1.7.1 — 325 tests passing)
- Updated bridge framework appendix (9 bridges)

AISS does not evaluate the correctness, legality, safety, or quality of a decision.  
AISS establishes **verifiable attribution** and **historical integrity** across time and interactions.

---

## Table of Contents

```
PART I — FOUNDATIONS
  0.  Purpose and Legal Effect
  1.  Introduction
  2.  Terminology
  3.  Canonicalization (MANDATORY)
  4.  Cryptographic Algorithms

PART II — PROTOCOL
  5.  Agent Identity
  6.  Agent Identity Document
  7.  Event Stamp Structure
  8.  Timestamp Requirements
  9.  Hash Chain Specification
  10. Fork Handling
  11. Anti-Replay Protection
  12. Key Rotation
  13. Key Lifecycle Management

PART III — TRUST & CONTINUITY
  14. Proof of Continuity Protocol (PCP) — Architecture
  15. External Peer Observation
  16. Agent-to-Agent (A2A) Protocol
  17. Authority Binding Layer
  18. Canonical History Rule

PART IV — MONITORING & GOVERNANCE
  19. Vigil — Behavioral Monitoring
  20. TrustGate — Governance & Human Oversight

PART V — OPERATIONS
  21. Security Requirements
  22. Audit Export Format
  23. Compliance Profile (AISS-2)
  24. Privacy Considerations
  25. Test Vectors (Normative)
  26. Reference Implementation

APPENDICES
  A. Compliance Mapping
  B. Test Vectors Index
  C. Implementation Guidance
  D. Security Disclaimer
  E. Framework Bridge Specifications
  F. Vigil API Reference
  G. TrustGate Policy Schema
  H. Security Test Coverage
```

---

## 0. Purpose and Legal Effect

### 0.1 Purpose

The Agent Identity Signature Standard (AISS) defines a cryptographic procedure for the generation, chaining, and verification of signed decision events produced by an autonomous or semi-autonomous software system.

The objective of AISS is to enable any independent verifier to determine, **without reliance on a trusted third party**, whether a given sequence of events:

- Was emitted by a uniquely identified agent instance
- Originates from an explicitly delegated authority
- Has remained unaltered since its creation
- Preserves its original chronological order
- Was subject to behavioural monitoring and governance evaluation (AISS-2)

> AISS does not evaluate the correctness, legality, safety, or quality of a decision.  
> AISS establishes **verifiable attribution** and **historical integrity**.

### 0.2 Scope

AISS applies to autonomous or semi-autonomous software systems capable of emitting decisions or actions, including but not limited to:

- Software agents and AI models
- Machine learning inference systems
- Robotic control systems (ROS2, edge, IoT)
- Automated transaction engines
- Decision-support and orchestration services
- Multi-agent coordination systems

AISS is transport-independent and storage-independent. The standard defines verifiable evidence, not communication protocols.

### 0.3 Verifiable Decision Record (VDR)

A sequence of AISS-compliant events constitutes a **Verifiable Decision Record (VDR)**.

A valid VDR provides cryptographic proof that:

> A specific agent instance produced a specific decision at a specific point in its internal history, under a delegated authority, that this record has not been modified or selectively removed since issuance, and that the agent's behaviour was monitored throughout (AISS-2).

### 0.4 Legal Effect of a Valid Record

If a VDR is validated according to § 26 (Verification Procedure), the following are cryptographically established:

| Property | Established |
|----------|-------------|
| **Emission** | The decision originated from the private key corresponding to the declared agent identity |
| **Integrity** | The decision content has not been altered after signature |
| **Continuity** | No prior event has been removed or modified without detection |
| **Sequence** | The relative order of events is preserved |
| **Governance** (AISS-2) | Each TrustGate decision is itself a signed event in the chain |

AISS validation does **NOT** establish:

- That input data was correct
- That the decision was appropriate
- That the system behaved safely
- That the authority was legally compliant
- That real-world execution matched the decision

> **AISS establishes attribution, not legitimacy.**

### 0.5 Responsibility Semantics

AISS provides technical attribution between: a decision, an executing agent instance, and a declared delegating authority. Legal responsibility derived from this attribution is outside the scope of this specification and MUST be defined by applicable jurisdiction or contractual agreement.

### 0.6 Non-Repudiation

Within this standard, **non-repudiation** means:

> The inability for a delegating authority to credibly deny that the identified agent instance emitted the recorded decision sequence, after successful verification of a valid VDR.

Non-repudiation applies to **emission only** — not to intent, correctness, or consequence.

### 0.7 Independence of Verification

Verification of an AISS record MUST be performable:

- Offline, without contacting the issuing system
- Without trusting the implementer
- Using only publicly defined algorithms

Two independent conforming implementations MUST reach identical verification results.

---

## 1. Introduction

AISS defines a deterministic, cryptographically verifiable identity and signing framework for autonomous agents. The standard addresses the fundamental challenge of establishing trust between agents without relying on centralized certificate authorities or blockchain infrastructure.

### 1.1 Goals

AISS enables:

- Deterministic agent identity derivation from cryptographic keys
- Verifiable event signing with cryptographic signatures (Ed25519, ML-DSA-65)
- Hash-chained audit trails providing tamper-evidence
- Cross-platform verification and interoperability
- Agent-to-Agent (A2A) trust establishment without centralized PKI
- Post-quantum readiness (AISS-2)
- Behavioural monitoring integration (Vigil, TSI, VRS)
- Human oversight gate integration (TrustGate)
- Observation of interactions with non-AISS external systems

### 1.2 Profiles

| Profile | Purpose | Cryptography | Use Case |
|---------|---------|-------------|----------|
| **AISS-1** | General interoperability | Ed25519, SHA-256 | Development, non-critical agents |
| **AISS-2** | Regulated environments | ML-DSA-65 + Ed25519 hybrid, RFC 3161 | Finance, healthcare, legal, government, high-risk AI |

### 1.3 Non-Goals

AISS does NOT:

- Define consensus mechanisms
- Specify network transport protocols
- Mandate storage backend implementations
- Guarantee privacy (see § 24)
- Evaluate correctness or safety of agent decisions
- Replace TLS for transport security

### 1.4 Relationship Between AISS and PCP

AISS defines the cryptographic identity, signature, and hash-chain mechanisms — Layer 1 of the PCP stack.

The Proof of Continuity Protocol (PCP) extends AISS across four layers:

```
AISS        → cryptographic identity, event signing, hash chains
PiQrypt     → fork resolution, TSA integration, certification, anti-replay
Vigil       → behavioural monitoring (TSI, VRS, A2C), real-time dashboard
TrustGate   → policy enforcement, human oversight gate
```

Full PCP architecture is specified in § 14.

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are interpreted as described in RFC 2119.

| Term | Definition |
|------|------------|
| **Agent** | An autonomous software entity capable of making decisions and taking actions |
| **Agent Identity** | A cryptographically bound identifier derived from an agent's public key |
| **Event** | A discrete action or decision recorded and signed by an agent |
| **Stamp** | The act of signing an event and linking it to the hash chain |
| **Hash Chain** | A sequence of events where each event cryptographically references the hash of the previous event |
| **Genesis Event** | The first event in a hash chain with no predecessor (`previous_hash` = `"0" × 64`) |
| **Fork** | A condition where two or more events reference the same `previous_hash` |
| **VDR** | Verifiable Decision Record — a complete, validated event chain |
| **PCP** | Proof of Continuity Protocol — the full four-layer trust stack |
| **PAC** | Proof of Agent Continuity — the aggregate property established by a valid PCP record |
| **TSA** | Time Stamping Authority — external RFC 3161 timestamp provider |
| **TSI** | Trust State Index — behavioural stability indicator (STABLE / WATCH / UNSTABLE / CRITICAL) |
| **VRS** | Vigil Risk Score — composite real-time risk metric [0.0 → 1.0] |
| **A2C** | Agent-to-Context detector — relational anomaly detection across agent interactions |
| **TrustGate** | Governance and human oversight layer — evaluates actions against policy before execution |
| **External Peer** | A system interacting with a monitored agent that is not itself equipped with AISS |
| **Canonical Chain** | The single valid history selected by the Canonical History Rule when a fork exists |

---

## 3. Canonicalization (MANDATORY)

All JSON structures that are hashed or signed MUST use **RFC 8785** (JSON Canonicalization Scheme — JCS).

> **CRITICAL**: No alternative serialization method is permitted. Implementations that do not use RFC 8785 are non-compliant.

### 3.1 RFC 8785 Requirements

- Lexicographic ordering of object keys (recursive)
- Removal of all insignificant whitespace
- UTF-8 encoding without BOM
- Specific number representation (IEEE 754)
- Unicode normalization

### 3.2 Common Pitfalls

```python
# NON-COMPLIANT — json.dumps with sort_keys is NOT RFC 8785
import json
json.dumps(obj, sort_keys=True)   # ✗

# COMPLIANT
import canonicaljson
canonicaljson.encode_canonical_json(obj)   # ✓
```

### 3.3 Signature Scope

The signature covers the RFC 8785 canonical form of the **complete event object excluding the `signature` field** (or `signatures` object for AISS-2).

Implementations MUST remove the signature field before computing the signing bytes, then append the field after signing.

---

## 4. Cryptographic Algorithms

### 4.1 AISS-1 Algorithms

| Component | Algorithm | Standard | Encoding |
|-----------|-----------|----------|----------|
| Signature | Ed25519 | RFC 8032 | Base64 (RFC 4648) |
| Hash function | SHA-256 | NIST FIPS 180-4 | Hex (lowercase) |
| Canonicalization | JCS | RFC 8785 | UTF-8 |
| Agent ID derivation | BASE58(SHA256(pubkey))[0:32] | — | Base58 (Bitcoin alphabet) |
| Nonce | UUIDv4 | RFC 4122 | String |

> **Encoding note**: Agent IDs use Base58 for human readability. All signatures and keys embedded in events use standard Base64 (RFC 4648). Do not mix these encodings.

### 4.2 AISS-2 Algorithms

| Component | Algorithm | Standard | Encoding |
|-----------|-----------|----------|----------|
| Signature (primary) | ML-DSA-65 (Dilithium3) | NIST FIPS 204 | Base64 |
| Signature (compat) | Ed25519 | RFC 8032 | Base64 |
| Key encapsulation | ML-KEM-768 | NIST FIPS 203 | Base64 |
| Hash function | SHA-512 | NIST FIPS 180-4 | Hex |
| Canonicalization | JCS | RFC 8785 | UTF-8 |
| Timestamps | RFC 3161 TSP | IETF | — |
| Key encryption | AES-256-GCM | NIST FIPS 197 | — |
| Key derivation | scrypt | RFC 7914 | N=2¹⁷, r=8, p=1 |

### 4.3 Key Storage Requirements

**Level 2 (AISS-1 production):**

Private keys MUST be stored encrypted using the following scheme:

```
passphrase + salt (32 bytes random)
    ↓ scrypt(N=2¹⁷, r=8, p=1)          # ≥ 400ms per derivation — intentional
    ↓
derived_key (32 bytes)
    ↓ AES-256-GCM(nonce=12 bytes random)
    ↓
.key.enc = MAGIC(4) + VERSION(1) + SALT(32) + NONCE(12) + CIPHER(32) + TAG(16)
         = 97 bytes exactly
```

File format invariants:
- Magic bytes `PQKY` (4 bytes) — format validation on load
- Fixed total size of 97 bytes — detects truncation and padding attacks
- AES-GCM authentication tag — any byte modification is detected

**Level 3 (AISS-2):**  
HSM integration REQUIRED (FIPS 140-3 Level 2+). All Level 2 requirements apply additionally.

### 4.4 Quantum Resistance Timeline

| Period | Status |
|--------|--------|
| 2026 | Ed25519 secure (~10 years before credible quantum threat) |
| 2030–2035 | First cryptographically-relevant quantum computers expected |
| 2035+ | Ed25519 potentially vulnerable (Shor's algorithm) |
| **PiQrypt strategy** | **Hybrid Ed25519 + ML-DSA-65 for AISS-2 — archives remain valid post-quantum** |

---

## 5. Agent Identity

### 5.1 Deterministic Agent ID Derivation

```
agent_id = BASE58( SHA256(public_key_bytes) )[0:32]
```

**Example:** `5Z8nY7KpL9mN3qR4sT6uV8wX`

**Rationale:** 32 Base58 characters ≈ 186 bits of entropy. Collision probability negligible up to 2⁹³ agents.

### 5.2 Properties

| Property | Guarantee |
|----------|-----------|
| **Deterministic** | Same public key always produces same agent ID |
| **Collision-resistant** | SHA-256 birthday paradox < 0.01% at 10²⁷ agents |
| **No registry dependency** | Generated independently without coordination |
| **Cryptographic binding** | Identity cannot be claimed without the private key |
| **Portable** | Survives infrastructure changes, model upgrades, environment migrations |
| **Verifiable** | Any party can recompute and verify derivation |

### 5.3 Human-Readable Labels

Labels (e.g., `"trader-alpha-01"`) MAY appear in metadata but are NOT authoritative identifiers. The `agent_id` field is the sole canonical identifier.

### 5.4 Agent Directory Isolation

Each agent MUST be allocated an isolated storage directory under `~/.piqrypt/agents/<sanitized_name>/`.

Implementations MUST enforce:

- **Name sanitization**: `../`, backslashes, null bytes, spaces — all neutralized by `_safe_name()` before path construction
- **Path traversal protection**: all computed paths verified to remain within `~/.piqrypt/agents/`
- **Directory permissions**: `chmod 700` per agent directory (Linux/macOS)
- **Idempotency**: re-registering an agent updates metadata; never duplicates

---

## 6. Agent Identity Document

```json
{
  "version":    "AISS-1.0",
  "agent_id":   "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "public_key": "base64:Hy8k9P2Q3r4S5t6U7v8W9x0Y1z2A3b4C5d6E7f",
  "algorithm":  "Ed25519",
  "created_at": 1739382293,
  "metadata": {
    "label":     "trader-alpha-01",
    "framework": "langchain",
    "version":   "0.1.0"
  }
}
```

> Keys in lexicographic order per RFC 8785.

**AISS-2 Identity Document (hybrid):**

```json
{
  "version":            "AISS-2.0",
  "agent_id":           "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "public_key_classical": "base64:...",
  "public_key_pq":      "base64:...",
  "algorithms":         ["Ed25519", "ML-DSA-65"],
  "authority_chain": [
    {
      "authority_id":          "ORG_ROOT_CA",
      "delegation_signature":  "base64:..."
    }
  ],
  "created_at": 1739382293
}
```

---

## 7. Event Stamp Structure

### 7.1 AISS-1 Event

```json
{
  "agent_id":       "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "nonce":          "550e8400-e29b-41d4-a716-446655440000",
  "payload": {
    "event_type":   "trade_executed",
    "symbol":       "AAPL",
    "quantity":     100,
    "price":        150.25
  },
  "previous_hash":  "a3f7e8c9d1b2a4f6e8c0d2b4a6f8e0c2d4b6a8f0e2c4b6a8",
  "signature":      "base64:3k9XmL4nP8qR9sT0uV1wX2yZ3a4B5c6D...",
  "timestamp":      1739382400,
  "version":        "AISS-1.0"
}
```

> `signature` is a Base64-encoded Ed25519 signature over the RFC 8785 canonical form of the event **excluding** the `signature` field.

### 7.2 AISS-2 Event (Hybrid)

```json
{
  "agent_id":       "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "nonce":          "...",
  "payload":        { ... },
  "previous_hash":  "...",
  "signatures": {
    "classical": {
      "algorithm":  "Ed25519",
      "signature":  "base64:..."
    },
    "post_quantum": {
      "algorithm":  "ML-DSA-65",
      "signature":  "base64:..."
    }
  },
  "timestamp":      1739382400,
  "trusted_timestamp": {
    "authority":    "freetsa.org",
    "token":        "base64:...",
    "timestamp":    1739382403
  },
  "version":        "AISS-2.0"
}
```

### 7.3 Field Requirements

| Field | Requirement |
|-------|-------------|
| `version` | MUST be `"AISS-1.0"` or `"AISS-2.0"` |
| `agent_id` | MUST be 32-character Base58 string derived per § 5.1 |
| `timestamp` | MUST be Unix UTC seconds (integer) |
| `nonce` | MUST be unique per event within agent scope; UUIDv4 RECOMMENDED |
| `previous_hash` | MUST reference SHA-256 hex hash of immediately preceding event (excluding its signature); genesis events use 64 × `"0"` |
| `payload` | MUST contain complete event data; MUST NOT be null or empty |
| `signature` | MUST sign the RFC 8785 canonical form of the event excluding the `signature` field |

### 7.4 Genesis Event

The genesis event is the first event in a chain. It has no predecessor.

```json
{
  "agent_id":      "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "nonce":         "uuid-v4",
  "payload":       { "event_type": "genesis", "agent_name": "trader-alpha-01" },
  "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "signature":     "base64:...",
  "timestamp":     1739382293,
  "version":       "AISS-1.0"
}
```

---

## 8. Timestamp Requirements

### 8.1 AISS-1

- Format: Unix UTC seconds (integer)
- Clock drift tolerance: ±300 seconds
- Monotonic timestamps SHOULD be enforced within a single chain
- Time source: system clock (NTP synchronization RECOMMENDED)

### 8.2 AISS-2

- Format: Unix UTC seconds (integer)
- Clock drift tolerance: ±60 seconds (strictly enforced)
- Monotonic timestamps MUST be enforced
- RFC 3161 trusted timestamping REQUIRED for every event
- External NTP/PTP time source REQUIRED
- Drift > 10 seconds MUST trigger a security alert

### 8.3 TSA Token Validation

RFC 3161 tokens MUST be validated by verifying:

1. TSA certificate chain to a trusted root
2. Timestamp falls within token validity period
3. Message hash in token matches event hash
4. Token has not been revoked (OCSP or CRL)

---

## 9. Hash Chain Specification

### 9.1 Event Hash Calculation

```
event_hash = SHA256( JCS(event_excluding_signature_field) )
```

For AISS-2: `SHA512( JCS(event_excluding_signatures_object) )`

### 9.2 Chain Linkage Rule

```
current_event.previous_hash == event_hash(previous_event)
```

For genesis: `current_event.previous_hash == "0" × 64`

### 9.3 Verification Algorithm

```
for i in range(1, len(events)):
    expected = hash(events[i-1])
    if events[i].previous_hash != expected:
        raise InvalidChainError(f"Chain broken at index {i}")
    if not verify_signature(events[i], public_key):
        raise InvalidSignatureError(f"Invalid signature at index {i}")
```

### 9.4 Chain Integrity Properties

| Property | Guarantee |
|----------|-----------|
| **Tamper detection** | Any modification to any event breaks all subsequent hashes |
| **Deletion detection** | Removing an event breaks the chain at the gap |
| **Insertion detection** | Inserting an event without the correct previous hash is detectable |
| **Ordering** | The relative order of events is cryptographically enforced |

---

## 10. Fork Handling

### 10.1 Fork Definition

A fork occurs when two or more events share the same `previous_hash`, producing two valid branches from the same chain state:

```
Event 0
  ↓
Event 1
  ├──→ Event 2a  (Branch A — hash: abc...)
  └──→ Event 2b  (Branch B — hash: def...)  ← FORK DETECTED
```

### 10.2 Fork Classification

| Classification | Meaning |
|----------------|---------|
| `FORK_DETECTED` | Two valid branches exist; resolution pending |
| `NON_CANONICAL_HISTORY` | Branch not selected by Canonical History Rule (§ 18) |
| `FORK_AFTER_FINALIZATION` | Fork after a TSA-anchored event — indicates compromise attempt |

### 10.3 Vigil Response

When a fork is detected, the Vigil server MUST:

1. Raise a `CRITICAL`-severity alert in the Alert Journal
2. Record the fork in the Risk Narrative with both branch hashes
3. Transmit the fork event to TrustGate (if active) with outcome `AUDIT`
4. Apply the Canonical History Rule (§ 18) and log the selected branch

### 10.4 Fork Alert Structure

```json
{
  "alert_type":    "chain_fork",
  "severity":      "CRITICAL",
  "agent_id":      "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "branch_a_hash": "abc...",
  "branch_b_hash": "def...",
  "detected_at":   1739382500,
  "canonical":     "branch_a",
  "resolution":    "tsa_timestamp"
}
```

---

## 11. Anti-Replay Protection

### 11.1 AISS-1

- Nonce: UUIDv4 per event
- Nonce retention: minimum 24 hours
- Duplicate nonce within retention window: MUST be rejected and flagged as replay

### 11.2 AISS-2

- Nonce retention MUST persist for the full audit period (minimum 7 years)
- Collision detection MUST trigger a security alert
- `valid_until` timestamp REQUIRED on replay-detection window
- Replay detection MUST be auditable (detection events recorded in chain)

### 11.3 Detection Algorithm

```python
seen_nonces = set()
for event in events:
    if event.nonce in seen_nonces:
        raise ReplayAttackError(f"Duplicate nonce: {event.nonce}")
    seen_nonces.add(event.nonce)
```

---

## 12. Key Rotation

### 12.1 Identity Continuity Model

Key rotation generates a new `agent_id`. Continuity between old and new identity is proved via a rotation attestation recorded as the **final event of the old chain**:

```json
{
  "version":           "AISS-1.0",
  "attestation_type":  "key_rotation",
  "previous_agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "previous_public_key": "base64:...",
  "new_agent_id":      "9B3xY4kL5mN6pQ7rS8tU9vW0",
  "new_public_key":    "base64:...",
  "rotation_signature": "base64:...",
  "rotation_timestamp": 1739400000,
  "previous_hash":     "...",
  "signature":         "base64:...",
  "version":           "AISS-1.0"
}
```

### 12.2 Rotation Requirements

- `rotation_signature` MUST be signed with the previous private key
- Rotation attestation MUST be the last event of the old chain
- New chain genesis MUST reference the rotation attestation hash in `previous_hash`
- Old key MUST be added to revocation list

### 12.3 Continuity Chain

```
Old Chain: [... event N-1] → [rotation_attestation] ─── (hash reference)
                                                              ↓
New Chain:                                           [genesis referencing rotation]
                                                              ↓
                                                     [event 1] → [event 2] → ...
```

---

## 13. Key Lifecycle Management

### 13.1 AISS-1 — Level 2 (Software)

- CSPRNG for key generation (REQUIRED)
- Private key zeroization (`_secure_erase()`) after every use (REQUIRED)
- Encrypted storage per § 4.3 (REQUIRED)
- Annual key rotation policy (RECOMMENDED)
- Key escrow: NOT PERMITTED without explicit authority delegation

### 13.2 AISS-2 — Level 3 (Hardware)

- HSM integration REQUIRED (FIPS 140-3 Level 2+)
- All Level 2 requirements additionally apply
- Documented destruction procedure (REQUIRED)
- Incident response plan (REQUIRED)
- Independent security audit (annual, REQUIRED)

> PiQrypt v1.7.1 implements Level 2 key lifecycle. Level 3 HSM support is planned for v2.1.

---

## 14. Proof of Continuity Protocol (PCP) — Architecture

### 14.1 Definition

The Proof of Continuity Protocol (PCP) is the complete four-layer trust infrastructure for autonomous agents. AISS is its cryptographic foundation (Layer 1).

PCP establishes **Proof of Agent Continuity (PAC)**:

```
PAC = Identity Integrity         (AISS)
    + Event Chain Integrity      (PiQrypt Core)
    + Interaction Traceability   (A2A + External Peer Observation)
    + Behavioural Stability      (Vigil — TSI, VRS, A2C)
    + Policy Compliance          (TrustGate)
```

PAC does not verify the *correctness* of decisions. It verifies who made them, when, how they relate to prior actions, whether behaviour remained coherent, and whether a human approved critical actions.

### 14.2 Four-Layer Stack

```
┌──────────────────────────────────────────────────────┐
│  TRUSTGATE  — Policy · Human oversight · Governance  │  Layer 4
├──────────────────────────────────────────────────────┤
│  VIGIL      — TSI · VRS · A2C · Network graph        │  Layer 3
├──────────────────────────────────────────────────────┤
│  PIQRYPT    — Fork · TSA · .pqz · Certification      │  Layer 2
├──────────────────────────────────────────────────────┤
│  AISS       — Identity · Stamps · Hash chains · A2A  │  Layer 1
└──────────────────────────────────────────────────────┘
```

### 14.3 Agent Lifecycle Under PCP

```
Create Identity (AISS §5)
        ↓
Agent Initialization
        ↓
Agent Action / Decision
        ↓
Event Signing + Hash Chain Linking (AISS §7–9)
        ↓
External Peer Observation (§15, if applicable)
        ↓
Behavioural Monitoring — VRS updated (Vigil §19)
        ↓
TrustGate Policy Evaluation (§20)
        ↓
    ALLOW │ DENY │ AUDIT │ ESCALATE
        ↓         ↓
    Compliance Storage (.pqz)
```

### 14.4 Interface Contracts Between Layers

**AISS → PiQrypt Core:**  
PiQrypt Core consumes AISS-signed events and:
- Applies fork detection and Canonical History Rule
- Attaches RFC 3161 TSA tokens (AISS-2)
- Packages events into .pqz certification bundles
- Exposes the audit export endpoint

**PiQrypt Core → Vigil:**  
On every event stamp, PiQrypt Core MUST transmit to Vigil:
- `agent_id`, `timestamp`, `payload.event_type`
- Current chain length and `previous_hash`
- `peer_id` and `external: true/false` (if interaction event)
- Any fork or replay alert

**Vigil → TrustGate:**  
After computing VRS, Vigil MUST transmit to TrustGate:
- Current VRS value and state (SAFE / WATCH / ALERT / CRITICAL)
- TSI state
- Any active A2C alert
- Risk Narrative summary

**TrustGate → Chain:**  
Every TrustGate decision (ALLOW / DENY / AUDIT / ESCALATE) MUST be stamped as a signed event appended to the agent's AISS chain (§ 20.4).

---

## 15. External Peer Observation

### 15.1 Definition

External Peer Observation is the unilateral recording, by a PiQrypt-equipped agent, of its interactions with systems that are **not themselves equipped with AISS**.

The external system has no knowledge of PiQrypt. The observation is one-sided: PiQrypt records what the monitored agent does, from the monitored agent's perspective.

### 15.2 External Interaction Event Structure

```json
{
  "version":      "AISS-1.0",
  "agent_id":     "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "nonce":        "uuid-v4",
  "payload": {
    "event_type":      "external_interaction",
    "peer_id":         "binance_ws",
    "peer_type":       "burst_open",
    "latency_ms":      7,
    "status":          "200",
    "external":        true,
    "aiss_available":  false
  },
  "previous_hash": "...",
  "signature":     "base64:...",
  "timestamp":     1739382400
}
```

### 15.3 External Peer Profile Types

Implementations SHOULD classify external peers by interaction pattern to enable behavioural baseline detection:

| Pattern | Description | Trigger | Examples |
|---------|-------------|---------|---------|
| `burst_open` | High-volume bursts at market open/close | 09:00, 17:30 (± 15min) | Binance WS, Bloomberg Terminal, Polygon.io |
| `burst` | Spikes around deployment events | On push/deploy | GitHub webhook, GitLab CI, Docker registry |
| `scheduled` | Fixed daily sessions | 3× per day at fixed hours | Anthropic API, OpenAI API, Instagram API |
| `steady` | Continuous low-volume flow | Constant interval | Prometheus, Redis, Vault |

### 15.4 Auto-Discovery and Registration

When an unregistered peer is observed, implementations SHOULD:

1. Create a `peers.json` entry with `external: true`
2. Record `external_type` (one of the patterns in § 15.3)
3. Compute `avg_latency_ms` from observed events (rolling 24h window)
4. Compute initial trust contribution based on interaction regularity
5. Inject the peer as a distinct node in the Vigil network graph (outer ring)

This registration requires no manual configuration. It is derived entirely from observed interactions.

### 15.5 Anomaly Detection on External Peers

The A2C detector (§ 19.4) MUST evaluate external peer interactions for:

- **Concentration**: proportion of total interactions directed at a single external peer
- **Temporal synchronisation**: multiple agents calling the same external endpoint within a tight time window
- **Latency anomaly**: observed latency deviating > 3σ from established baseline for this peer type
- **Abnormal burst**: interaction count per time window deviating > 3σ from peer type baseline

### 15.6 Vigil Network Graph Integration

External peers MUST be visually distinguished in the Vigil network graph:

- Positioned on an outer ring (radius > internal agents ring)
- Rendered as a distinct shape (e.g., diamond) with a different colour (e.g., blue)
- Labelled with `peer_id` and `avg_latency_ms`
- Connected to interacting agents by differently styled edges (e.g., thinner, lower opacity)

---

## 16. Agent-to-Agent (A2A) Protocol

### 16.1 Handshake Sequence

```
Agent A (initiator)                      Agent B (responder)
        │
        │── identity_proposal ──────────→
        │                                │
        │← identity_response ────────────│
        │                                │
        │── session_confirm ─────────────→
        │                                │
        │  Both agents MUST append       │
        │  co-signed handshake event     │
        │  to their own AISS chains      │
```

### 16.2 Co-Signed Handshake Event

```json
{
  "version":            "AISS-1.0",
  "event_type":         "a2a_handshake",
  "session_id":         "uuid-v4",
  "initiator": {
    "agent_id":         "5Z8nY7KpL9mN3qR4sT6uV8wX",
    "public_key":       "base64:...",
    "signature":        "base64:..."
  },
  "responder": {
    "agent_id":         "9B3xY4kL5mN6pQ7rS8tU9vW0",
    "public_key":       "base64:...",
    "signature":        "base64:..."
  },
  "capabilities_agreed": ["task_delegation", "result_validation"],
  "timestamp":          1739382400
}
```

Each agent's `signature` covers the canonical form of the event excluding both signature fields.

### 16.3 Memory Recording Requirements

After handshake completion:

- Each agent MUST record the co-signed event in its own AISS chain
- Free tier: stored in plaintext local memory
- Pro tier: stored encrypted (AES-256-GCM per § 4.3)

### 16.4 Non-AISS Peer Fallback (External Interaction)

When an agent interacts with a non-AISS peer, it MUST record the interaction unilaterally per § 15:

```json
{
  "version":        "AISS-1.0",
  "event_type":     "external_interaction",
  "peer_identifier": "non-aiss-system-id",
  "aiss_available": false,
  "interaction_hash": "sha256:...",
  "signature":      "base64:...",
  "note":           "Peer does not implement AISS. Interaction recorded unilaterally."
}
```

### 16.5 Trust Score

The Trust Score is a derived metric of PCP, computed from the agent's interaction history:

```
T = w1·S + w2·C + w3·X + w4·R + w5·A

S = Signature Integrity Score  = valid_sigs / total_sigs
C = Chain Stability Score      = 1 - (fork_events / total_events)
X = Cross-Agent Validation     = cross_validated / total_external_interactions
R = Replay Resistance          = 1 - (replay_attempts / total_events)
A = Anomaly Stability          = e^(-k × anomaly_rate)

Default weights: w1=0.25, w2=0.20, w3=0.25, w4=0.15, w5=0.15
```

| Score Range | Tier |
|-------------|------|
| > 0.95 | Elite |
| 0.90–0.95 | A+ |
| 0.80–0.90 | A |
| 0.70–0.80 | B |
| < 0.70 | At Risk |

---

## 17. Authority Binding Layer

### 17.1 Objective

The Authority Binding Layer establishes a verifiable delegation chain connecting a real-world entity to an automated decision. This layer provides the technical attribution required to determine legal responsibility, but does not itself define it.

### 17.2 Delegation Hierarchy

```
Legal Entity (organisation)
        ↓  signs delegation
Operational System
        ↓  authorises
AI Model (version hash)
        ↓  instantiates
Agent Instance (agent_id)
        ↓  emits
Decision Event (signed, hash-chained)
```

### 17.3 Authority Statement Structure

```json
{
  "issuer_id":   "org_acme_trading_system",
  "subject_id":  "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "scope":       ["trade_execution", "risk_assessment"],
  "validity_period": {
    "not_before": 1739000000,
    "not_after":  1770536000
  },
  "revocation_reference": "https://revoke.acme.com/agents",
  "signature":   "base64:..."
}
```

### 17.4 Verification Protocol

1. Verify each signature in the delegation chain
2. Verify validity periods overlap the decision timestamp
3. Verify scope permits the emitted event type
4. Verify no revocation at verification time

**Failure result:** `VALID BUT UNAUTHORIZED` (integrity holds; authority does not)

### 17.5 Delegation Semantics

| Property | Meaning |
|----------|---------|
| **Integrity** | The agent produced the event |
| **Authority** | The agent was permitted to produce it |

> Integrity MAY exist without authority. Authority MUST NOT be assumed from integrity alone.

### 17.6 Revocation

Revocation affects authority attribution but MUST NOT invalidate historical integrity. Past valid events remain cryptographically valid after revocation.

---

## 18. Canonical History Rule

### 18.1 Objective

The Canonical History Rule ensures that independent verifiers always select the **same valid history** when a fork exists. All conforming implementations MUST apply identical selection logic.

### 18.2 Canonical Selection Algorithm

Given multiple valid branches from the same agent identity, implementations MUST apply in order:

**Step 1 — Anchored Continuity**  
Select the branch with the greatest number of events anchored to an external RFC 3161 TSA.

**Step 2 — Earliest Trust Anchor**  
If equal: select the branch whose most recent anchored event has the earliest verifiable trusted timestamp.

**Step 3 — Longest Chain**  
If equal: select the branch with the greatest number of valid sequential events.

**Step 4 — Deterministic Tie-Breaker**  
If equal: select the branch whose final event hash is lexicographically lowest (hex string comparison).

> All conforming implementations MUST produce identical results for the same input.

### 18.3 Fork Classification

| Classification | Condition |
|----------------|-----------|
| `FORK_DETECTED` | Two valid branches exist; resolution pending |
| `NON_CANONICAL_HISTORY` | Branch not selected by the algorithm above |
| `FORK_AFTER_FINALIZATION` | Fork after a TSA-anchored event — indicates compromise attempt |

### 18.4 Finalization Property

An event anchored to a TSA becomes **FINAL** when:
- Its TSA token is valid and verifiable
- Its parent chain is canonical

A FINAL event cannot be superseded. Any branch forking after a FINAL event MUST be classified as `FORK_AFTER_FINALIZATION` and escalated to TrustGate.

---

## 19. Vigil — Behavioural Monitoring

### 19.1 Role in PCP

Vigil is Layer 3 of the PCP stack. It consumes AISS events from PiQrypt Core and computes continuous behavioural risk metrics for each monitored agent.

Vigil does not sign or modify events. It observes and scores.

### 19.2 Trust State Index (TSI)

The TSI evaluates behavioural stability over a 24-hour sliding window of trust score history:

| State | Condition | Vigil Action |
|-------|-----------|-------------|
| `STABLE` | Score stable; Δ24h ≥ -0.08 | No alert |
| `WATCH` | Mild drift; -0.15 ≤ Δ24h < -0.08 | `MEDIUM` alert logged |
| `UNSTABLE` | Significant deviation; Δ24h < -0.15 | `HIGH` alert raised |
| `CRITICAL` | `UNSTABLE` persisting > 48h | `CRITICAL` alert; TrustGate notified |

TSI state is exposed via the Vigil API at `/api/summary` and per-agent at `/api/agent/<id>`.

### 19.3 Vigil Risk Score (VRS)

The VRS is a composite real-time risk score in [0.0 → 1.0], recomputed on every event:

```
VRS = w_tsi × TSI_weight
    + w_ts  × (1 - TrustScore)
    + w_a2c × A2C_risk
    + w_ch  × ChainIssueScore

Default weights:
  w_tsi = 0.30
  w_ts  = 0.35
  w_a2c = 0.20
  w_ch  = 0.15
```

VRS States:

| State | VRS Range | Default Action |
|-------|-----------|---------------|
| `SAFE` | [0.00 – 0.25) | Normal operation |
| `WATCH` | [0.25 – 0.50) | `MEDIUM` alert |
| `ALERT` | [0.50 – 0.75) | `HIGH` alert; TrustGate `AUDIT` |
| `CRITICAL` | [0.75 – 1.00] | `CRITICAL` alert; TrustGate `ESCALATE` |

### 19.4 A2C Detector — Relational Anomaly Detection

The A2C (Agent-to-Context) detector evaluates four relational anomaly patterns across the interaction graph:

| Pattern | Definition | Threshold |
|---------|------------|-----------|
| **Concentration** | Proportion of interactions directed at a single peer | > 80% |
| **Entropy drop** | Sudden reduction in interaction diversity (Shannon entropy) | Δ > 50% in 1h window |
| **Synchronisation** | Multiple agents acting in tight temporal lock-step | < 500ms spread across > 3 agents |
| **Silence break** | Abnormal burst following a period of inactivity | > 10× baseline rate after > 2h silence |

A2C evaluates both agent-to-agent (§ 16) and agent-to-external-peer (§ 15) interactions.

### 19.5 Risk Narrative

For each monitored agent, Vigil MUST generate a human-readable narrative prioritising the highest-severity anomaly. The narrative is exposed via `/api/agent/<id>` and displayed in the dashboard.

Example:
```
⛓ FORK DETECTED — Event chain fork on merge
  → Canonical branch resolved by TSA timestamp (branch A selected).
  → Non-canonical branch logged. Recommend: review Events #2a vs #2b.
  → TrustGate notified: AUDIT triggered.
```

### 19.6 Network Graph

The Vigil dashboard MUST render a real-time network graph showing:

- **Internal agents**: positioned on an inner ring; rendered as circles coloured by VRS state
- **External peers**: positioned on an outer ring; rendered as distinct shapes (e.g., diamonds) with latency label
- **Edges**: directed, annotated with interaction frequency and latency
- **External peer edges**: visually distinguished (thinner, lower opacity, different colour)

### 19.7 Vigil HTTP API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | HTML dashboard (self-contained, no CDN) |
| `/api/summary` | GET | All agents: VRS, TSI, alerts, external peers |
| `/api/alerts` | GET | Active alerts (filtered by severity) |
| `/api/agent/<id>` | GET | Per-agent detail: events, VRS, narrative, peers |
| `/health` | GET | Server health check |

Full API schema is specified in Appendix F.

---

## 20. TrustGate — Governance & Human Oversight

### 20.1 Role in PCP

TrustGate is Layer 4 of the PCP stack — the policy enforcement and human oversight gate. It is the direct technical implementation of EU AI Act Art. 14 (human oversight mandatory for high-risk AI systems).

TrustGate receives VRS and TSI from Vigil, evaluates each proposed action against a configurable policy profile, and returns a decision before the action is executed.

### 20.2 Decision Outcomes

| Outcome | Meaning | Chain Event |
|---------|---------|-------------|
| `ALLOW` | Action is policy-compliant | Signed `trustgate_allow` event appended |
| `DENY` | Action is blocked by policy | Signed `trustgate_deny` event with reason appended |
| `AUDIT` | Action allowed; flagged for manual review | Signed `trustgate_audit` event appended |
| `ESCALATE` | Human operator must approve before execution | Signed `trustgate_escalate` event; execution paused |

### 20.3 Policy Evaluation Inputs

TrustGate evaluates each action using:

| Input | Source |
|-------|--------|
| `vrs` | Vigil (current VRS value) |
| `tsi_state` | Vigil (STABLE / WATCH / UNSTABLE / CRITICAL) |
| `a2c_active` | Vigil (boolean: active A2C alert) |
| `event_type` | AISS event payload |
| `policy_profile` | YAML configuration per agent |
| `chain_state` | Fork status, finalization state |

### 20.4 The Governance Chain Invariant

Every TrustGate decision MUST be stamped as a signed AISS event and appended to the agent's chain. This means:

> The governance record is cryptographically inseparable from the action record.

A TrustGate DENY cannot be removed from the chain without breaking chain integrity. A TrustGate ALLOW is linked to the chain state at the moment of approval.

**TrustGate event structure:**

```json
{
  "version":       "AISS-1.0",
  "agent_id":      "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "nonce":         "uuid-v4",
  "payload": {
    "event_type":  "trustgate_decision",
    "outcome":     "DENY",
    "reason":      "VRS=0.82 exceeds CRITICAL threshold for event_type=trade_execution",
    "policy_ref":  "finance_high_risk_v1",
    "vrs_at_decision": 0.82,
    "tsi_at_decision": "UNSTABLE"
  },
  "previous_hash": "...",
  "signature":     "base64:...",
  "timestamp":     1739382450
}
```

### 20.5 ESCALATE and Human Approval

When TrustGate issues `ESCALATE`:

1. Agent execution MUST pause
2. A signed `trustgate_escalate` event is appended to the chain
3. A notification is dispatched to the configured human operator channel
4. A TTL timer starts (configurable; default 300 seconds)
5. If the human approves: a signed `trustgate_human_allow` event is appended; execution resumes
6. If the human denies or TTL expires: a signed `trustgate_deny` event is appended; action is blocked

The default behaviour on TTL expiry is DENY. This implements a **fail-safe by default** principle.

### 20.6 Policy Profile Schema

TrustGate policy profiles are YAML files per agent:

```yaml
agent_id: "5Z8nY7KpL9mN3qR4sT6uV8wX"
policy_version: "1.0"

thresholds:
  vrs_watch:    0.25
  vrs_alert:    0.50
  vrs_critical: 0.75

rules:
  - event_type: "trade_execution"
    vrs_min_for_deny:    0.75
    vrs_min_for_escalate: 0.50
    tsi_states_for_deny: ["CRITICAL"]
    tsi_states_for_escalate: ["UNSTABLE", "CRITICAL"]

  - event_type: "data_export"
    always_audit: true

escalate:
  channel: "slack"
  webhook: "https://hooks.slack.com/..."
  ttl_seconds: 300
  default_on_timeout: "DENY"

frameworks:
  - eu_ai_act_art14
  - nist_ai_rmf_govern_1_2
  - anssi_2024_r30

audit_all: true
```

Full policy schema is specified in Appendix G.

### 20.7 Supported Compliance Frameworks

| Framework | Controls |
|-----------|---------|
| EU AI Act | Art. 9 (risk management), Art. 12 (inviolable logs), Art. 14 (human oversight) |
| NIST AI RMF | GOVERN 1.2, MANAGE 2.2, MEASURE 2.5 |
| ANSSI 2024 | R25 (pattern filtering), R29 (audit trail), R30 (clearance-based access) |
| Custom | YAML-configurable rules per agent profile |

### 20.8 Availability

TrustGate is available in AISS-2 / Pro+ tier deployments. It is not part of the AISS-1 free tier.

---

## 21. Security Requirements

### 21.1 Cryptographic Implementation

- Constant-time cryptographic operations (prevent timing side-channels)
- Cryptographically secure entropy (OS CSPRNG)
- Private key zeroization (`_secure_erase()`) after every use
- Strict input validation on all event fields
- Agent name sanitization preventing path traversal

### 21.2 Threat Model

| Attack | Coverage |
|--------|---------|
| Retroactive event modification | ✅ Hash chain invalidates all subsequent events |
| Decision repudiation | ✅ Ed25519 / ML-DSA-65 non-repudiation |
| Identity fabrication | ✅ Deterministic derivation from private key |
| Selective event deletion | ✅ Chain hash break detectable |
| History divergence (fork) | ✅ Canonical History Rule (§ 18) |
| Replay attack | ✅ UUIDv4 nonce + retention |
| Timestamp backdating | ✅ RFC 3161 TSA (AISS-2) |
| Brute-force key attack | ✅ scrypt N=2¹⁷ (Level 2) / HSM (Level 3) |
| Key in RAM after use | ✅ `_secure_erase()` zeros bytearray |
| Path traversal (agent names) | ✅ `_safe_name()` sanitization |
| Agent impersonation | ✅ Public key binding in identity document |
| Unsupervised critical action | ✅ TrustGate ESCALATE / DENY (AISS-2) |
| Anomalous behavioural drift | ✅ Vigil TSI / VRS / A2C continuous monitoring |
| FORK_AFTER_FINALIZATION | ✅ Detected and escalated to TrustGate |
| Quantum attack (2035+) | ✅ ML-DSA-65 hybrid (AISS-2) |

| Attack | Outside AISS Scope |
|--------|-------------------|
| Incorrect input data to agent | ❌ |
| Compromised sensors | ❌ |
| Algorithmic bias or incorrect decisions | ❌ |
| Full OS/network compromise | ❌ |
| Social engineering of human operators | ❌ |

### 21.3 Attack Scenarios — Detailed

**Modify past event:**
```
Attacker changes Event 5 payload
  → SHA-256(Event 5) changes
  → Event 6.previous_hash mismatch
  → verify_chain_linkage() raises InvalidChainError ✅
```

**Brute-force .key.enc passphrase:**
```
Attacker tries 1,000,000 passphrases/second (GPU)
  → scrypt N=2¹⁷ = ~400ms per attempt on modern hardware
  → Effective rate: ~2.5 attempts/second
  → 10⁸ common passphrases → ~4.6 years ✅
```

**Replay attack:**
```
Attacker resends Event 3 with original signature
  → detect_replay_attacks() finds duplicate nonce
  → ReplayAttackError raised ✅
```

**Agent acts without human approval (ESCALATE timeout):**
```
Agent proposes high-risk action
  → VRS = 0.82 → TrustGate: ESCALATE
  → Human does not respond within TTL (300s)
  → TrustGate: DENY — signed event appended to chain ✅
```

---

## 22. Audit Export Format

### 22.1 Export Structure

```json
{
  "spec":            "AISS-1.0-AUDIT",
  "exported_at":     1739500000,
  "agent_identity": {
    "agent_id":      "5Z8nY7KpL9mN3qR4sT6uV8wX",
    "algorithm":     "Ed25519",
    "public_key":    "base64:..."
  },
  "chain_integrity_hash": "sha256:...",
  "event_count":     1247,
  "events":          [ ... ],
  "trustgate_decisions": [ ... ],
  "fork_log":        [ ... ],
  "replay_log":      [ ... ]
}
```

### 22.2 Integrity Verification Procedure

Auditors MUST execute these steps in order:

1. Validate agent identity structure (public key format, agent_id derivation)
2. Verify all event signatures against the declared public key
3. Validate hash chain continuity (each `previous_hash` matches)
4. Detect fork conditions (duplicate `previous_hash` values)
5. Detect replay attempts (duplicate nonces)
6. Validate timestamp monotonicity
7. Verify TrustGate decision chain integrity (each TrustGate event in chain)
8. For AISS-2: validate all RFC 3161 TSA tokens

### 22.3 .pqz Bundle Format

The `.pqz` format is PiQrypt's portable, self-contained audit bundle:

| Component | Content | Tier |
|-----------|---------|------|
| `events.json` | Full AISS event chain (RFC 8785 canonical) | All |
| `identity.json` | Agent identity document | All |
| `chain_hash.txt` | SHA-256 of full event chain | All |
| `signature.ed25519` | Ed25519 signature over chain_hash | All |
| `signature.mldsa65` | ML-DSA-65 signature over chain_hash | Pro+ |
| `tsa_token.tsr` | RFC 3161 TSA token | Pro+ |
| `certificate.pdf` | Human-readable audit certificate | Pro+ |
| `registry_hash.txt` | SHA-256 published to public GitHub registry | Pro+ |

---

## 23. Compliance Profile (AISS-2)

AISS-2 is REQUIRED for:

- Regulated financial systems (banks, trading, payment processors)
- Healthcare systems handling protected health information (PHI)
- Legal contract enforcement systems
- Government-grade infrastructure
- High-risk AI systems under EU AI Act

AISS-2 additionally requires:

- External security audit before production deployment
- SOC2 / ISO 27001 / NIST CSF compliance documentation
- Comprehensive incident response logging
- Data retention compliance per applicable jurisdiction
- TrustGate deployment (§ 20)
- Annual review of cryptographic algorithms and key lifecycle

---

## 24. Privacy Considerations

Hash chains MAY conflict with GDPR "right to be forgotten" requirements.

**AISS-compliant approaches for GDPR alignment:**

- Store hashes of personal data, not raw data (payload contains hash reference, not PII)
- Actual data stored in encrypted off-chain storage with independent key management
- Selective disclosure via zero-knowledge proofs (planned for v2.1)
- Data minimization: stamp only what is necessary for accountability
- Right to erasure: off-chain data can be deleted; chain integrity is unaffected

> Deleting off-chain data does not break chain integrity. The chain hash of a deleted payload remains valid even if the payload content is no longer accessible.

---

## 25. Test Vectors (Normative)

All AISS-compliant implementations MUST pass the normative test vectors:

```
/test_vectors/canonical.json   — RFC 8785 canonicalization (14 vectors)
/test_vectors/identity.json    — Agent ID derivation determinism (8 vectors)
/test_vectors/events.json      — Event hashing and signatures (16 vectors)
/test_vectors/chain.json       — Hash chain verification (10 vectors)
/test_vectors/fork.json        — Fork detection and canonical resolution (6 vectors)
/test_vectors/replay.json      — Anti-replay protection (5 vectors)
/test_vectors/rotation.json    — Key rotation and continuity (4 vectors)
/test_vectors/a2a.json         — A2A handshake verification (4 vectors)
/test_vectors/external.json    — External peer observation (4 vectors)  [v2.0 NEW]
/test_vectors/trustgate.json   — TrustGate decision chain (6 vectors)  [v2.0 NEW]
```

### 25.1 Required Test Coverage

- ✅ Canonical JSON serialization (RFC 8785)
- ✅ Agent ID derivation determinism and uniqueness
- ✅ Valid signature generation and verification
- ✅ Invalid signature detection (bit flip, truncation)
- ✅ Event hash computation
- ✅ Genesis event structure
- ✅ Hash chain linkage validation
- ✅ Fork condition detection
- ✅ Canonical history rule determinism
- ✅ Replay attack detection
- ✅ Key rotation attestation and continuity
- ✅ A2A handshake verification
- ✅ External peer interaction recording (v2.0)
- ✅ TrustGate decision chain integrity (v2.0)

---

## 26. Reference Implementation

### 26.1 Conformance Levels

| Level | Requirements |
|-------|-------------|
| **Level 1 — Basic** | RFC 8785, Ed25519, all normative test vectors, fork detection |
| **Level 2 — Production** | Level 1 + security audit, key encryption (scrypt+AES-GCM), key zeroization, key rotation, CLI |
| **Level 3 — Regulated (AISS-2)** | Level 2 + HSM (FIPS 140-3), RFC 3161, ML-DSA-65, TrustGate, compliance documentation, annual review |

### 26.2 Reference Implementation — PiQrypt

**Repository:** https://github.com/piqrypt/piqrypt  
**Install:** `pip install piqrypt`

| Version | Conformance | Tests |
|---------|-------------|-------|
| v1.0.0 | Level 1 | 18/18 |
| v1.5.0 | Level 2 | 69/69 |
| v1.8.4 | Level 2 | 136/143 (7 skipped — external Ollama) |
| **v1.7.1** | **Level 2** | **325 passed, 17 known infrastructure failures** |

The 17 known failures in v1.7.1 are infrastructure-dependent (external cert authority, live server, Pro-tier features not activated in CI). They are not protocol failures.

---

## Appendix A — Compliance Mapping

| Framework | Control | AISS Implementation |
|-----------|---------|---------------------|
| **EU AI Act** | Art. 12 — Inviolable logging | Hash-chained signed events |
| **EU AI Act** | Art. 14 — Human oversight | TrustGate ESCALATE/DENY (§ 20) |
| **EU AI Act** | Art. 9 — Risk management | VRS composite scoring (§ 19.3) |
| **SOC2** | CC6.1 Identity verification | Deterministic agent ID (§ 5) |
| **SOC2** | CC6.2 Logical access | Signature verification |
| **SOC2** | CC6.6 Audit trail | Hash chain + .pqz export |
| **ISO 27001** | 5.16 Identity management | Ed25519 agent identity |
| **ISO 27001** | 8.15 Logging | Tamper-evident event chain |
| **NIST CSF** | ID.AM-2 Asset inventory | Agent registry (§ 5.4) |
| **NIST CSF** | PR.AC-7 Authentication | Cryptographic signature |
| **NIST CSF** | DE.CM-7 Event monitoring | Fork/replay detection |
| **NIST CSF** | RS.AN-1 Forensic analysis | Chain reconstruction |
| **NIST AI RMF** | GOVERN 1.2 | TrustGate policy engine |
| **NIST AI RMF** | MANAGE 2.2 | Vigil VRS monitoring |
| **NIST AI RMF** | MEASURE 2.5 | A2C anomaly detection |
| **HIPAA** | §164.312 Audit controls | Immutable event chain |
| **GDPR** | Art. 5.1.f Integrity | Tamper-evident chains |
| **GDPR** | Art. 22 Explanation | Signed decision payload |
| **SEC** | Rule 17a-4 7-year retention | .pqz certified exports |
| **SOX** | §404 Internal controls | Signed decision records |
| **ANSSI 2024** | R25 Pattern filtering | A2C detector (§ 19.4) |
| **ANSSI 2024** | R29 Audit trail | Hash chain + .pqz |
| **ANSSI 2024** | R30 Clearance-based access | TrustGate ALLOW/DENY |

---

## Appendix B — Test Vectors Index

Full normative test vectors are published in the AISS-spec repository:

```
https://github.com/piqrypt/aiss-spec/test_vectors/
```

The PiQrypt reference implementation includes `tests/test_vectors.py` — all normative vectors passing as of v1.7.1.

---

## Appendix C — Implementation Guidance

### Python (Reference)

```python
from aiss import (
    stamp_event, stamp_genesis_event, derive_agent_id,
    verify_chain, detect_replay_attacks
)
from aiss.crypto import ed25519

# Generate keypair
private_key, public_key = ed25519.generate_keypair()
agent_id = derive_agent_id(public_key)

# Genesis
genesis = stamp_genesis_event(
    private_key, public_key, agent_id,
    {"event_type": "genesis", "agent_name": "my_agent"}
)

# Subsequent events
event = stamp_event(
    private_key, agent_id,
    {"event_type": "trade_executed", "symbol": "AAPL", "quantity": 100},
    previous_hash=genesis["event_hash"]
)

# Verify
verify_chain([genesis, event])          # raises InvalidChainError on tamper
detect_replay_attacks([genesis, event]) # raises ReplayAttackError on duplicate nonce
```

### Critical Pitfalls

- ❌ Do NOT use `json.dumps(sort_keys=True)` — not RFC 8785 compliant
- ❌ Do NOT truncate `agent_id` below 32 characters
- ❌ Do NOT include the `signature` field when computing the event hash
- ❌ Do NOT store private keys in plaintext — use scrypt + AES-256-GCM
- ❌ Do NOT assume authority from integrity alone (§ 17.5)
- ❌ Do NOT use Base58 for signatures — Base58 is for `agent_id` only; signatures use Base64
- ❌ Do NOT bypass TrustGate for high-VRS events in AISS-2 deployments
- ❌ Do NOT allow execution after `ESCALATE` without explicit human approval or TTL expiry

---

## Appendix D — Security Disclaimer

AISS provides cryptographic identity primitives and does NOT guarantee:

- System-level security
- Protection against compromised hosts
- Regulatory compliance without additional system-level controls
- Protection against social engineering
- Correctness of agent decisions

**CRITICAL:** Independent security review by qualified experts is REQUIRED for all production AISS-2 deployments. PiQrypt security contact: security@piqrypt.com

---

## Appendix E — Framework Bridge Specifications

PiQrypt implements AISS integration for 9 agent frameworks. Each bridge is a lightweight wrapper that stamps events at natural integration points without requiring application code changes.

### E.1 Integration Principle

```
Framework execution
        ↓
Bridge intercepts at integration point
        ↓
stamp_event(private_key, agent_id, {event_type, ...})
        ↓
Framework execution resumes
        ↓
Vigil receives event (<10ms overhead)
```

### E.2 Bridge Table

| Bridge | Framework | Integration Point | Event Types Stamped |
|--------|-----------|------------------|--------------------|
| `bridges/langchain/` | LangChain | `PiQryptCallbackHandler` | `llm_start`, `llm_end`, `tool_start`, `tool_end`, `chain_start`, `chain_end` |
| `bridges/crewai/` | CrewAI | Agent wrapper | `agent_action`, `task_delegation`, `inter_agent_message` |
| `bridges/autogen/` | AutoGen | Message interceptor | `message_sent`, `message_received`, `group_chat_step` |
| `bridges/mcp/` | MCP | Tool middleware | `tool_call`, `tool_result`, `resource_read` |
| `bridges/ollama/` | Ollama | Request wrapper | `inference_start`, `inference_end`, `model_loaded` |
| `bridges/ros2/` | ROS2 | `AuditedLifecycleNode` | `lifecycle_transition`, `topic_publish`, `topic_subscribe`, `service_call` |
| `bridges/rpi/` | Raspberry Pi | `AuditedPiAgent` | `gpio_read`, `gpio_write`, `sensor_sample`, `actuator_command` |
| `bridges/session/` | Session | Session manager | `session_start`, `a2a_handshake`, `session_end`, `state_transition` |
| `bridges/openclaw/` | OpenClaw | Action stamper | `action_proposed`, `action_executed`, `action_result` |

### E.3 LangChain Example

```python
from langchain.agents import AgentExecutor
from piqrypt.bridges.langchain import PiQryptCallbackHandler

handler = PiQryptCallbackHandler(agent_name="my_agent")
executor = AgentExecutor(agent=agent, callbacks=[handler])

# Every LLM call, tool invocation, and chain step is automatically stamped.
# No changes to application code required.
```

### E.4 ROS2 Example

```python
from piqrypt.bridges.ros2 import AuditedLifecycleNode

class MyRobotNode(AuditedLifecycleNode):
    def __init__(self):
        super().__init__("my_robot", agent_name="robot_arm_01")

    def on_activate(self, state):
        # lifecycle transition automatically stamped
        return super().on_activate(state)
```

---

## Appendix F — Vigil API Reference

### F.1 Endpoints

| Endpoint | Method | Auth | Response |
|----------|--------|------|----------|
| `/` | GET | None | HTML dashboard (self-contained) |
| `/api/summary` | GET | None (local) | JSON: all agents + external peers |
| `/api/alerts` | GET | None | JSON: active alerts |
| `/api/agent/<agent_id>` | GET | None | JSON: per-agent detail |
| `/api/agent/<agent_id>/events` | GET | None | JSON: last N events |
| `/health` | GET | None | JSON: `{"status": "ok"}` |

### F.2 `/api/summary` Response Schema

```json
{
  "agents": [
    {
      "agent_name":    "trader-alpha-01",
      "agent_id":      "5Z8nY7KpL9mN3qR4sT6uV8wX",
      "vrs":           0.18,
      "state":         "SAFE",
      "tsi":           "STABLE",
      "trust_score":   0.91,
      "event_count":   12480,
      "last_event_ts": 1739382400,
      "alerts":        [],
      "a2c_peers":     ["binance_ws", "bloomberg_terminal"],
      "is_external":   false
    },
    {
      "agent_name":    "binance_ws",
      "is_external":   true,
      "external_type": "burst_open",
      "avg_latency_ms": 5,
      "vrs":           0.0,
      "state":         "STABLE",
      "tier":          "external"
    }
  ],
  "alerts": [...],
  "computed_at": 1739382500
}
```

---

## Appendix G — TrustGate Policy Schema

Full YAML schema for TrustGate policy profiles:

```yaml
# TrustGate Policy Profile Schema v1.0
# Required for AISS-2 / Pro+ deployments

agent_id:       string          # REQUIRED: 32-char Base58 agent_id
policy_version: string          # REQUIRED: semantic version

thresholds:
  vrs_watch:    float           # Default: 0.25
  vrs_alert:    float           # Default: 0.50
  vrs_critical: float           # Default: 0.75

rules:
  - event_type: string          # REQUIRED: matches payload.event_type
    vrs_min_for_deny:    float  # VRS threshold above which action is DENY
    vrs_min_for_escalate: float # VRS threshold above which action is ESCALATE
    tsi_states_for_deny: list   # TSI states that trigger DENY
    tsi_states_for_escalate: list  # TSI states that trigger ESCALATE
    always_audit: bool          # If true, every instance is AUDIT regardless of VRS

escalate:
  channel:   string             # "slack" | "email" | "webhook" | "sms"
  target:    string             # webhook URL, email address, or phone number
  ttl_seconds: integer          # Default: 300 — timeout before auto-DENY
  default_on_timeout: string    # "DENY" (default) | "ALLOW"

frameworks:
  - string                      # One or more of:
                                # eu_ai_act_art14, eu_ai_act_art9, eu_ai_act_art12
                                # nist_ai_rmf_govern_1_2, nist_ai_rmf_manage_2_2
                                # anssi_2024_r25, anssi_2024_r29, anssi_2024_r30
                                # custom (requires custom_rules block)

audit_all: bool                 # If true, EVERY action produces a trustgate_audit event
```

---

## Appendix H — Security Test Coverage

PiQrypt v1.7.1 includes 61 dedicated security tests:

| Category | Tests | Coverage |
|----------|-------|---------|
| KeyStore | 14 | Timing attacks, file corruption, magic byte validation, RAM erasure, confidentiality |
| Agent Registry | 13 | Path traversal (12 attack vectors), name sanitization, directory isolation, permissions |
| Chain Integrity | 19 | Signature forgery, payload tampering, agent ID spoofing, fork injection, replay |
| Session Security | 7 | Lock/unlock, key erasure after use, context manager |
| Migration | 4 | Idempotence, backup verification, corrupt source handling |
| Memory | 4 | Flood, injection, unicode, cross-agent isolation |
| **Total** | **61** | — |

All 61 security tests pass on Windows (PowerShell) and Linux as of v1.7.1.

---

*AISS RFC v2.0 — Standards Track*  
*https://github.com/piqrypt/aiss-spec*  
*Status: Public Review Draft*  
*Date: March 2026*  
*Supersedes: AISS RFC v1.1 (2026-03-02)*

*© 2026 PiQrypt — e-Soleau DSO2026006483 (INPI France) + Addendum 2026*

*AISS does not evaluate the correctness of decisions.*  
*It establishes verifiable attribution and historical integrity.*

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
