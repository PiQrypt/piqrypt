# AISS — Agent Identity and Signature Standard
## RFC v1.1 — Candidate Adoption

**Status:** Public Review Draft — Standards Track Candidate  
**Version:** 1.1.0  
**Date:** 2026-02-21  
**Repository:** https://github.com/piqrypt/aiss-spec

---

## Abstract

This document specifies AISS (Agent Identity and Signature Standard), a cryptographically verifiable framework for autonomous agent identity and event authentication. AISS enables deterministic identity derivation, tamper-evident audit trails via hash chains, and cross-platform verification without centralized infrastructure.

The standard defines two profiles:
- **AISS-1**: General interoperability baseline (Ed25519, free)
- **AISS-2**: Regulated environments — post-quantum cryptography, external timestamping, compliance documentation (Pro/OSS)

---

## Table of Contents

```
PART I — FOUNDATIONS
  0. Purpose and Legal Effect
  1. Introduction
  2. Terminology
  3. Canonicalization (MANDATORY)
  4. Cryptographic Algorithms

PART II — PROTOCOL
  5. Agent Identity
  6. Agent Identity Document
  7. Event Stamp Structure
  8. Timestamp Requirements
  9. Hash Chain Specification
  10. Fork Handling
  11. Anti-Replay Protection
  12. Key Rotation
  13. Key Lifecycle Management (AISS-2)

PART III — TRUST & RESPONSIBILITY (v1.1 NEW)
  14. Authority Binding Layer
  15. Canonical History Rule
  16. Agent-to-Agent (A2A) Interaction

PART IV — OPERATIONS
  17. Security Requirements
  18. Audit Export Format
  19. Compliance Profile (AISS-2)
  20. Privacy Considerations
  21. Test Vectors (Normative)
  22. Reference Implementation

APPENDICES
  A. Compliance Mapping
  B. Test Vectors
  C. Implementation Guidance
  D. Security Disclaimer
```

---

## 0. Purpose and Legal Effect *(v1.1 — NEW)*

### 0.1 Purpose

The Agent Identity Signature Standard (AISS) defines a cryptographic procedure for the generation, chaining, and verification of signed decision events produced by an automated system.

The objective of AISS is to enable any independent verifier to determine, **without reliance on a trusted third party**, whether a given sequence of events:

- Was emitted by a uniquely identified agent instance
- Originates from an explicitly delegated authority
- Has remained unaltered since its creation
- Preserves its original chronological order

> AISS does not evaluate the correctness, legality, safety, or quality of a decision.  
> AISS only establishes **verifiable attribution** and **historical integrity**.

### 0.2 Scope

AISS applies to autonomous or semi-autonomous software systems capable of emitting decisions or actions, including but not limited to:

- Software agents and AI models
- Machine learning inference systems
- Robotic control systems
- Automated transaction engines
- Decision-support services

AISS is transport-independent and storage-independent. The standard defines verifiable evidence, not communication protocols.

### 0.3 Verifiable Decision Record (VDR)

A sequence of AISS-compliant events constitutes a **Verifiable Decision Record (VDR)**.

A valid VDR provides cryptographic proof that:
> A specific agent instance produced a specific decision at a specific point in its internal history, under a delegated authority, and that this record has not been modified or selectively removed since issuance.

### 0.4 Legal Effect of a Valid Record

If a Verifiable Decision Record is validated according to Section 22 (Verification Procedure), the following statements are cryptographically established:

| Property | Established |
|---|---|
| **Emission** | The decision originated from the private key corresponding to the declared agent identity |
| **Integrity** | The decision content has not been altered after signature |
| **Continuity** | No prior event in the chain has been removed or modified without detection |
| **Sequence** | The relative order of events inside the record is preserved |

AISS validation does **NOT** establish:
- That input data was correct
- That the decision was appropriate
- That the system behaved safely
- That the authority was legally compliant
- That real-world execution matched the decision

> **AISS establishes attribution, not legitimacy.**

### 0.5 Responsibility Semantics

AISS provides technical attribution between: a decision, an executing agent instance, and a declared delegating authority.

The interpretation of legal responsibility derived from this attribution is outside the scope of this specification and MUST be defined by applicable jurisdiction or contractual agreement.

### 0.6 Non-Repudiation Definition

Within the context of this standard, **non-repudiation** means:

> The inability for a delegating authority to credibly deny that the identified agent instance emitted the recorded decision sequence, after successful verification of a valid record.

Non-repudiation applies to **emission only** — not to intent, correctness, or consequence.

### 0.7 Independence of Verification

Verification of an AISS record MUST be performable:
- Offline, without contacting the issuing system
- Without trusting the implementer
- Using only publicly defined algorithms

Two independent conforming implementations MUST reach identical verification results.

---

## 1. Introduction

AISS defines a deterministic, cryptographically verifiable identity and signing framework for autonomous agents operating in multi-agent systems. The standard addresses the fundamental challenge of establishing trust between agents without relying on centralized certificate authorities or blockchain infrastructure.



### 1.1 Goals

AISS enables:
- Agent-to-Agent (A2A) trust establishment without centralized PKI
- Deterministic agent identity derivation from cryptographic keys
- Verifiable event stamping with cryptographic signatures
- Hash-chained audit trails providing tamper-evidence
- Cross-platform verification and interoperability
- Post-quantum readiness (AISS-2)

### 1.2 Profiles

| Profile | Purpose | Crypto | Use Case |
|---|---|---|---|
| **AISS-1** | General interoperability | Ed25519, SHA-256 | Prototyping, non-critical agents |
| **AISS-2** | Regulated environments | ML-DSA-65 + Ed25519 hybrid | Finance, healthcare, legal, government |

### 1.3 Non-Goals

AISS does NOT:
- Define consensus mechanisms
- Provide network transport layer specifications
- Specify storage backend implementations
- Mandate specific key management systems beyond baseline requirements
- Guarantee privacy (see Section 20)
- Evaluate correctness or safety of agent decisions

### 1.4 Relationship Between AISS and PCP

AISS defines the cryptographic identity, signature, and hash-chain mechanisms.

AISS is a core component of the broader Proof-of-Continuity Protocol (PCP).

PCP extends AISS by integrating:
- Fork resolution rules (Canonical History Rule)
- Anti-replay guarantees
- Key rotation continuity
- Cross-agent handshake mechanisms
- Trust Score computation
- Temporal anchoring (TSA integration in AISS-2)

AISS ensures cryptographic continuity.
PCP ensures systemic continuity.

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in RFC 2119.

| Term | Definition |
|---|---|
| **Agent** | An autonomous software entity capable of making decisions and taking actions |
| **Agent Identity** | A cryptographically bound identifier derived from an agent's public key |
| **Event** | A discrete action or decision recorded and signed by an agent |
| **Hash Chain** | A sequence of events where each event cryptographically references the hash of the previous event |
| **Genesis Event** | The first event in a hash chain with no predecessor |
| **Fork** | A condition where two or more events reference the same previous event hash |
| **VDR** | Verifiable Decision Record — a complete, validated event chain |
| **PCP** | Proof-of-Continuity Protocol — the full protocol stack of which AISS is the core |
| **TSA** | Time Stamping Authority — external RFC 3161 timestamp provider |

---

## 3. Canonicalization (MANDATORY)

All JSON structures that are hashed or signed MUST use **RFC 8785** (JSON Canonicalization Scheme).

> **CRITICAL**: No alternative serialization methods are permitted. Implementations that do not use RFC 8785 are non-compliant.

### 3.1 RFC 8785 Requirements

- Lexicographic ordering of object keys
- Removal of all insignificant whitespace
- UTF-8 encoding without BOM
- Specific number representation
- Unicode normalization

### 3.2 Common Pitfalls

```python
# WRONG — NOT RFC 8785 compliant
json.dumps(obj, sort_keys=True)

# CORRECT
import canonicaljson
canonicaljson.encode_canonical_json(obj)
```

---

## 4. Cryptographic Algorithms

### 4.1 AISS-1 Algorithms

| Component | Algorithm |
|---|---|
| Signature | Ed25519 (RFC 8032) |
| Hash Function | SHA-256 |
| Canonicalization | RFC 8785 (JCS) |
| Encoding | Base58 (Bitcoin alphabet) |
| Nonce | UUIDv4 (RFC 4122) |

### 4.2 AISS-2 Algorithms

| Component | Algorithm |
|---|---|
| Signature (primary) | ML-DSA-65 (NIST FIPS 204) |
| Signature (compat) | Ed25519 (RFC 8032) |
| Key Encapsulation | ML-KEM-768 (NIST FIPS 203) |
| Hash Function | SHA-512 |
| Canonicalization | RFC 8785 (JCS) |
| Encoding | Base58 + Base64 |
| Timestamps | RFC 3161 (mandatory) |

---

## 5. Agent Identity

### 5.1 Deterministic Agent ID Derivation

```
agent_id = BASE58( SHA256(public_key_bytes) )[0:32]
```

**Rationale**: 32 Base58 characters ≈ 186 bits of entropy. Negligible collision probability up to 2^93 agents.

### 5.2 Properties

- **Collision Resistance**: Birthday paradox < 0.01% at 10^27 agents
- **No Registry Dependency**: Generated independently without coordination
- **Cryptographic Binding**: Identity cannot be claimed without private key
- **Verifiability**: Any party can verify derivation

### 5.3 Human-Readable Labels

Labels (e.g., `"trader-alpha-01"`) MAY appear in metadata but are NOT authoritative identifiers.

---

## 6. Agent Identity Document

```json
{
  "algorithm": "Ed25519",
  "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX1yA2z",
  "created_at": 1739382293,
  "metadata": {
    "framework": "langchain",
    "label": "trader-alpha-01",
    "version": "0.1.0"
  },
  "public_key": "Hy8k9P2Q3r4S5t6U7v8W9x0Y1z2A3b4C5d6E7f",
  "version": "AISS-1.0"
}
```

> Note: Keys in lexicographic order per RFC 8785.

---

## 7. Event Stamp Structure

### 7.1 AISS-1 Event

```json
{
  "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX1yA2z",
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "payload": {
    "action": "reduce_position",
    "data": { "amount": 0.5, "symbol": "BTC-USD" },
    "type": "decision"
  },
  "previous_hash": "a3f7e8c9d1b2a4f6e8c0d2b4a6f8e0c2",
  "signature": "3k9XmL4nP8qR9sT0uV1wX2yZ3a4B5c6D",
  "timestamp": 1739382400,
  "version": "AISS-1.0"
}
```

### 7.2 AISS-2 Event (Hybrid)

```json
{
  "agent_id": "...",
  "nonce": "...",
  "payload": { ... },
  "previous_hash": "...",
  "signatures": {
    "classical": {
      "algorithm": "Ed25519",
      "signature": "..."
    },
    "post_quantum": {
      "algorithm": "ML-DSA-65",
      "signature": "..."
    }
  },
  "timestamp": 1739382400,
  "trusted_timestamp": {
    "authority": "freetsa.org",
    "token": "base64:...",
    "timestamp": 1739382403
  },
  "version": "AISS-2.0"
}
```

### 7.3 Field Requirements

| Field | Requirement |
|---|---|
| `timestamp` | MUST be Unix UTC seconds (integer) |
| `nonce` | MUST be unique per event within agent scope (UUIDv4 recommended) |
| `payload` | MUST contain complete event data |
| `previous_hash` | MUST reference hash of immediately preceding event |
| `signature` | MUST sign canonicalized event excluding signature field itself |

---

## 8. Timestamp Requirements

### 8.1 AISS-1

- Format: Unix UTC seconds (integer)
- Clock drift tolerance: ±300 seconds
- Monotonic timestamps SHOULD be enforced within single chain
- Time source: system clock (NTP synchronization recommended)

### 8.2 AISS-2

- Clock drift tolerance: ±60 seconds (strictly enforced)
- Monotonic timestamps MUST be enforced
- RFC 3161 trusted timestamping REQUIRED
- External NTP/PTP time source REQUIRED
- Drift > 10 seconds MUST trigger security alert

---

## 9. Hash Chain Specification

### 9.1 Event Hash Calculation

```
event_hash = SHA256( JCS(event_without_signature) )
```

### 9.2 Chain Linkage

```
current_event.previous_hash == SHA256(previous_event_without_signature)
```

### 9.3 Genesis Event

The genesis `previous_hash` MUST be:

```
previous_hash = SHA256(agent_public_key_bytes)
```

This cryptographically binds genesis to agent identity, preventing genesis collision attacks.

### 9.4 Rotation Continuity *(v1.1 — CORRECTED)*

When an agent rotates its key, the rotation attestation MUST be recorded as a PCP event in the **old chain** before the new chain begins. This creates an unbroken cryptographic thread across key rotations.

```
old_chain:  E1 → E2 → ... → En → ROTATION_EVENT ← signed by old key
new_chain:  genesis(new_pubkey) → E1' → E2' → ...
            where genesis.previous_hash references ROTATION_EVENT.hash
```

---

## 10. Fork Handling

A fork occurs when two or more events reference the same `previous_hash`.

### 10.1 Fork Detection

```
if count(events where previous_hash == X) > 1:
    return FORK_DETECTED
```

### 10.2 AISS-1 Fork Behavior

- Fork detection MUST be implemented
- Resolution policy is application-defined
- Applications MAY choose: latest timestamp, first seen, manual resolution

### 10.3 AISS-2 Fork Behavior

- Multi-instance coordination protocol REQUIRED
- Fork events MUST be logged to immutable audit trail
- Unauthorized forks MUST trigger security incident response
- See Section 15 (Canonical History Rule) for authoritative resolution

---

## 11. Anti-Replay Protection

### 11.1 AISS-1

- Nonce REQUIRED in all events
- Nonce MUST be unique within `agent_id` scope
- UUIDv4 RECOMMENDED
- Duplicate nonce MUST invalidate event
- Retention: minimum 24 hours

### 11.2 AISS-2

- Nonce retention MUST persist for full audit period (minimum 7 years)
- Collision detection MUST trigger security alert
- `valid_until` timestamp REQUIRED
- Replay detection MUST be auditable

---

## 12. Key Rotation

### 12.1 Identity Continuity Model

Key rotation generates a NEW `agent_id`. Continuity is proved via a rotation attestation **recorded as a PCP event** in the old chain:

```json
{
  "attestation_type": "key_rotation",
  "new_agent_id": "9B3xY4kL5mN6pQ7rS8tU9vW0xY1zA",
  "new_public_key": "Qw8e9r0T1y2U3i4O5p6A7s8D9f0G",
  "previous_agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX1yA2z",
  "previous_public_key": "Hy8k9P2Q3r4S5t6U7v8W9x0Y1z2A",
  "rotation_signature": "signed_by_previous_key",
  "rotation_timestamp": 1739400000,
  "version": "AISS-1.0"
}
```

### 12.2 Rotation Requirements

- `rotation_signature` MUST be signed with previous private key
- Rotation attestation MUST be inserted as final event of old chain
- New chain genesis MUST reference rotation attestation hash
- Old key revocation list MUST be maintained

---

## 13. Key Lifecycle Management (AISS-2)

- CSPRNG for key generation
- Private key zeroization after use
- HSM integration REQUIRED (FIPS 140-3 Level 2+)
- Annual key rotation policy
- Documented destruction procedure
- Incident response plan

---

## 14. Authority Binding Layer *(v1.1 — NEW)*

### 14.1 Objective

The Authority Binding Layer establishes a verifiable delegation chain connecting a real-world entity to an automated decision. This layer does not define legal responsibility but provides the technical attribution required to determine it.

### 14.2 Delegation Hierarchy

```
Legal Entity
    ↓ delegates
Operational System
    ↓ authorizes
AI Model
    ↓ instantiates
Agent Instance
    ↓ emits
Decision Event
```

Each level MUST be bound to the next using a signed authorization statement.

### 14.3 Authority Statement Structure

```json
{
  "issuer_id": "org_acme_trading_system",
  "subject_id": "5Z8nY7KpL9mN3qR4sT6uV8wX1yA2z",
  "scope": ["trade_execution", "risk_assessment"],
  "validity_period": {
    "not_before": 1739000000,
    "not_after": 1770536000
  },
  "revocation_reference": "https://revoke.acme.com/agents",
  "signature": "..."
}
```

### 14.4 Verification Protocol

1. Verify each signature in the delegation chain
2. Verify validity periods overlap the decision timestamp
3. Verify scope permits the emitted event type
4. Verify no revocation at verification time

**Failure result**: `VALID BUT UNAUTHORIZED`

### 14.5 Delegation Semantics

| Property | Meaning |
|---|---|
| **Integrity** | The agent produced the event |
| **Authority** | The agent was allowed to produce it |

> Integrity MAY exist without authority. Authority MUST NOT be assumed from integrity.

### 14.6 Revocation

Revocation affects authority attribution but MUST NOT invalidate historical integrity. Past valid events remain valid after revocation.

---

## 15. Canonical History Rule *(v1.1 — NEW)*

### 15.1 Objective

The Canonical History Rule ensures that independent verifiers always select the **same valid history** when multiple valid chains exist for the same agent identity.

### 15.2 Canonical Selection Algorithm

Given multiple valid branches from the same agent identity, implementations MUST apply the following ordered criteria:

**Step 1 — Anchored Continuity**  
Select the chain with the greatest number of events anchored to an external trusted timestamp (RFC 3161).

**Step 2 — Earliest Trust Anchor**  
If equal: select the chain whose most recent anchored event has the earliest verifiable trusted timestamp.

**Step 3 — Longest Chain**  
If equal: select the chain with the greatest number of valid sequential events.

**Step 4 — Deterministic Tie-Breaker**  
If equal: select the chain whose final event hash is lexicographically lowest.

> All conforming implementations MUST produce identical results.

### 15.3 Fork Classification

| Classification | Meaning |
|---|---|
| `FORK_DETECTED` | Two valid branches exist, resolution pending |
| `NON_CANONICAL_HISTORY` | Branch not selected by canonical rule |
| `FORK_AFTER_FINALIZATION` | Fork after anchored event — indicates compromise |

### 15.4 Finalization Property

An event anchored to a TSA becomes **FINAL** when its timestamp is verifiable and its parent chain is canonical. A FINAL event cannot be superseded.

### 15.5 Canonical Resolution Determinism

When multiple branches exist, the canonical chain MUST be deterministically selected using:

1. Valid TSA timestamp (if available)
2. Earliest valid timestamp
3. Highest cumulative chain length
4. Deterministic lexicographic tie-breaker

All conforming implementations MUST reach identical canonical chain selection.

---

## 16. Agent-to-Agent (A2A) Interaction

### 16.1 Handshake Protocol

The A2A handshake establishes mutual cryptographic trust between two agents:

```
Agent A                              Agent B
   |                                    |
   |── identity_proposal ──────────────>|
   |   {agent_id_A, pubkey_A,           |
   |    capabilities, timestamp,        |
   |    sig_A}                          |
   |                                    |
   |<── identity_response ──────────────|
   |   {agent_id_B, pubkey_B,           |
   |    capabilities, session_id,       |
   |    sig_B, sig_B_over_A_proposal}   |
   |                                    |
   |── session_confirmation ───────────>|
   |   {session_id,                     |
   |    sig_A_over_B_response}          |
   |                                    |
   |  Both agents record co-signed      |
   |  handshake event in their chains   |
```

### 16.2 Co-Signed Event Structure

```json
{
  "version": "AISS-1.0",
  "event_type": "a2a_handshake",
  "session_id": "uuid-v4",
  "initiator": {
    "agent_id": "...",
    "signature": "..."
  },
  "responder": {
    "agent_id": "...",
    "signature": "..."
  },
  "capabilities_agreed": ["task_delegation", "result_validation"],
  "timestamp": 1739382400
}
```

### 16.3 Memory Recording

After handshake completion:
- Each agent MUST record the co-signed event in its own PCP chain
- Each agent MUST store the peer's identity document
- Free: stored in plaintext local memory
- Pro: stored encrypted (AES-256-GCM)

### 16.4 Fallback (Non-AISS Peer)

When an AISS-compliant agent interacts with a non-AISS peer:

```json
{
  "version": "AISS-1.0",
  "event_type": "external_interaction",
  "peer_identifier": "non-aiss-agent-id",
  "aiss_available": false,
  "interaction_hash": "sha256:...",
  "signature": "...",
  "note": "Peer does not implement AISS. Interaction recorded unilaterally."
}
```

### 16.5 Trust Score Accumulation

The Trust Score is a derived metric of the Proof-of-Continuity Protocol (PCP).

It does not replace cryptographic verification.
It provides an observable continuity indicator based on PCP-compliant events.

Trust between agents accumulates via verified interactions. The Trust Score T is defined as:

```
T = w1·S + w2·C + w3·X + w4·R + w5·A

Where:
  S = Signature Integrity Score  = valid_sigs / total_sigs
  C = Chain Stability Score      = 1 - (fork_events / total_events)
  X = Cross-Agent Validation     = cross_validated / total_external
  R = Replay Resistance          = 1 - (replay_attempts / total_events)
  A = Anomaly Stability          = e^(-k × anomaly_rate)

Default weights: w1=0.25, w2=0.20, w3=0.25, w4=0.15, w5=0.15
```

| Score | Tier |
|---|---|
| > 0.95 | Elite |
| 0.90–0.95 | A+ |
| 0.80–0.90 | A |
| 0.70–0.80 | B |
| < 0.70 | At Risk |

---

## 17. Security Requirements

### 17.1 Cryptographic Implementation

- Constant-time cryptographic operations (prevent timing attacks)
- Cryptographically secure entropy (CSPRNG)
- Side-channel attack protection
- Private key zeroization after use
- Strict input validation

### 17.2 Threat Model

| Attack | AISS Coverage |
|---|---|
| Retroactive alteration | ✅ Hash chain invalidates all subsequent events |
| Decision repudiation | ✅ Ed25519/ML-DSA signature |
| Identity fabrication | ✅ Deterministic derivation from private key |
| Selective event deletion | ✅ Chain hash break detectable |
| History divergence | ✅ Canonical History Rule (Section 15) |
| Replay attack | ✅ UUIDv4 nonce + retention |
| Fork / cloning | ✅ Fork detection + Canonical Rule |
| Timestamp backdating | ✅ RFC 3161 TSA (AISS-2) |

| Attack | Outside AISS Scope |
|---|---|
| Incorrect input data | ❌ |
| Compromised sensors | ❌ |
| Algorithmic bias | ❌ |
| OS/network compromise | ❌ |

---

## 18. Audit Export Format

```json
{
  "agent_identity": {
    "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX1yA2z",
    "algorithm": "Ed25519",
    "public_key": "Hy8k9P2Q3r4S5t6U7v8W9x0Y1z2A"
  },
  "chain_integrity_hash": "sha256:...",
  "events": [ ... ],
  "exported_at": 1739500000,
  "spec": "AISS-1.0-AUDIT"
}
```

### 18.1 Integrity Verification Procedure

Auditors MUST:
1. Validate agent identity structure
2. Verify all event signatures
3. Validate hash chain continuity
4. Detect fork conditions
5. Detect replay attempts (duplicate nonces)
6. Validate timestamp monotonicity

---

## 19. Compliance Profile (AISS-2)

AISS-2 is REQUIRED for:
- Regulated financial systems (banks, trading, payment)
- Healthcare systems handling PHI
- Legal contract enforcement
- Government-grade infrastructure

Additional requirements: external security audit, SOC2/ISO27001/NIST CSF mapping, comprehensive incident logging, data retention compliance.

---

## 20. Privacy Considerations

Hash chains MAY conflict with GDPR "right to be forgotten".

**Recommended approaches**:
- Store hashes of personal data, not raw data
- Encrypted off-chain storage for actual data
- Selective disclosure (zero-knowledge proofs where applicable)
- Data minimization principles

---

## 21. Test Vectors (Normative)

All AISS-compliant implementations MUST pass these test vectors.

### 21.1 Identity Canonicalization

Input:
```json
{"version": "AISS-1.0", "agent_id": "test123", "public_key": "testkey", "algorithm": "Ed25519", "created_at": 1234567890}
```

Expected RFC 8785 canonical form:
```
{"agent_id":"test123","algorithm":"Ed25519","created_at":1234567890,"public_key":"testkey","version":"AISS-1.0"}
```

### 21.2 Required Test Coverage

- ✅ Canonical JSON serialization
- ✅ Valid signature generation and verification
- ✅ Invalid signature detection
- ✅ Fork condition detection
- ✅ Replay attack detection
- ✅ Key rotation attestation
- ✅ A2A handshake verification
- ✅ Chain continuity across rotation

---

## 22. Reference Implementation

### 22.1 Conformance Levels

| Level | Requirements |
|---|---|
| **Level 1 — Basic** | RFC 8785, Ed25519, test vectors, fork detection |
| **Level 2 — Production** | Security audit, constant-time ops, key rotation, CLI tool |
| **Level 3 — Regulated (AISS-2)** | HSM, RFC 3161, compliance docs, annual review |

### 22.2 Reference Implementations

**AISS Specification Repository:**  
https://github.com/piqrypt/aiss-spec

**Known Implementations:**

- **PiQrypt** (Python): https://github.com/piqrypt/piqrypt
  ```bash
  pip install piqrypt
  ```

- **Community Implementations:**  
  See AISS-spec repository for complete list of conformant implementations.

**Conformance Testing:**  
All implementations should pass the normative test vectors in `/vectors` directory of the AISS-spec repository.

---

## Appendix A — Compliance Mapping

| Framework | Control | AISS Implementation |
|---|---|---|
| SOC2 CC6.1 | Identity verification | Agent identity document |
| SOC2 CC6.2 | Logical access | Signature verification |
| SOC2 CC6.6 | Audit trail | Hash chain |
| ISO 27001 5.16 | Identity management | Deterministic agent ID |
| ISO 27001 8.15 | Logging | Event chain stamping |
| NIST CSF ID.AM-2 | Asset inventory | Agent registry |
| NIST CSF PR.AC-7 | Authentication | Cryptographic signature |
| NIST CSF DE.CM-7 | Event monitoring | Fork/replay detection |
| NIST CSF RS.AN-1 | Forensic analysis | Chain reconstruction |
| HIPAA 164.312 | Audit controls | Immutable event chain |
| SOX Section 404 | Internal controls | Signed decision records |

---

## Appendix B — Test Vectors

Full normative test vectors are published in the reference implementation repository at:  
`/test_vectors/` — covering identity, events, chain, fork, replay, rotation, and A2A.

---

## Appendix C — Implementation Guidance

### Python (Reference)

```python
import canonicaljson
from nacl.signing import SigningKey
import hashlib, base58

private_key = SigningKey.generate()
public_key = private_key.verify_key
pub_bytes = bytes(public_key)
agent_id = base58.b58encode(hashlib.sha256(pub_bytes).digest())[:32].decode()

event = {"agent_id": agent_id, "timestamp": 1234567890, "nonce": "uuid...", ...}
canonical = canonicaljson.encode_canonical_json(event)
signature = private_key.sign(canonical).signature
```

### Critical Pitfalls

- ❌ Do NOT use `json.dumps(sort_keys=True)` — not RFC 8785 compliant
- ❌ Do NOT truncate agent_id below 32 characters
- ❌ Do NOT include signature field when computing event hash
- ❌ Do NOT store private keys in plaintext
- ❌ Do NOT assume authority from integrity alone (Section 14.5)

---

## Appendix D — Security Disclaimer

AISS provides cryptographic identity primitives and does NOT guarantee:
- System-level security
- Protection against compromised hosts
- Regulatory compliance without system-level controls
- Protection against social engineering

**CRITICAL**: Independent security review by qualified experts is REQUIRED for all production AISS-2 deployments.

---

## Appendix E — Reserved

*This appendix is reserved for future use.*

---

*AISS RFC v1.1 — Standards Track Candidate*  
*https://github.com/piqrypt/aiss-spec*  
*Status: Public Review Draft*


## Appendix F — Protocol Integration Examples

### F.1 Model Context Protocol (MCP)

AISS can be integrated with communication protocols like MCP (Model Context Protocol) for AI agent systems.

**Integration approach:**
- MCP acts as transport layer (JSON-RPC over stdio)
- All cryptographic operations remain in the core implementation
- Events signed via MCP are identical to CLI-signed events
- Same security model, same RFC compliance

**Example tools exposed via MCP:**
- `stamp_event` (sign decision)
- `verify_chain` (verify integrity)
- `export_audit` (export trail)
- `search_events` (query history)

**Security consideration:** Private keys must NEVER be exposed to the MCP layer.

**Reference implementations:**
- PiQrypt MCP Server: https://github.com/piqrypt/piqrypt-mcp-server

### F.2 REST API Integration

AISS implementations may expose REST APIs for enterprise integration:

```http
POST /api/v1/events
Authorization: Bearer <token>
Content-Type: application/json

{
  "agent_id": "...",
  "payload": {...},
  "timestamp": 1234567890
}
```

**Critical:** API authentication must be separate from AISS cryptographic identity.

