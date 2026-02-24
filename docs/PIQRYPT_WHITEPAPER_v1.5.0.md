# PiQrypt Technical Whitepaper
## Cryptographic Audit Trails for Autonomous AI Agents

**Version:** 1.5.0  
**Date:** 2026-02-21  
**Authors:** PiQrypt Inc.  
**Contact:** piqrypt@gmail.com

---

## Abstract

As AI agents increasingly make autonomous decisions in critical domains—trading, healthcare, autonomous vehicles, HR—the absence of tamper-proof audit trails creates legal, compliance, and safety risks. Traditional logging systems are editable, lack cryptographic proof, and fail to meet regulatory requirements for non-repudiation.

PiQrypt introduces a cryptographic framework built on the Agent Identity and Signature Standard (AISS v1.1), enabling:

1. **Deterministic agent identity** derived from public keys
2. **Cryptographically signed event chains** (Ed25519 + Dilithium3)
3. **Tamper-evident hash chains** detecting unauthorized modifications
4. **Post-quantum resistance** for 50+ year archival security
5. **Legal admissibility** with RFC 3161 timestamping
6. **Compliance-ready** exports (SOC2, HIPAA, GDPR, SEC)

This paper presents the technical architecture, cryptographic foundations, and economic model enabling verifiable AI agent decision trails at scale.

---

## Table of Contents

```
1. Introduction
2. Problem Statement
3. System Architecture
4. Cryptographic Foundations
5. Agent Identity Protocol
6. Event Signing & Chaining
7. Fork Detection & Resolution
8. Agent-to-Agent Protocol
9. Certification Service
10. Security Analysis
11. Compliance Mapping
12. Economic Model
13. Implementation
14. Future Work
15. Conclusion
```

---

## 1. Introduction

### 1.1 Context

AI agents operate across critical domains:
- **Finance:** Automated trading systems executing millions of transactions
- **Healthcare:** Diagnostic AI recommending treatments
- **Autonomous Vehicles:** Real-time navigation decisions
- **HR:** Automated candidate evaluation and hiring

**Current gap:** These systems lack cryptographically verifiable decision trails.

### 1.2 Motivation

**Regulatory requirements:**
- SEC Rule 17a-4: 7-year audit trail for financial transactions
- HIPAA § 164.312: Audit controls for health information systems
- GDPR Art. 22: Right to explanation for automated decisions
- SOX Section 404: Internal control documentation

**Technical requirements:**
- Non-repudiation (agent cannot deny actions)
- Tamper-evidence (modifications detectable)
- Temporal proof (timestamps verifiable)
- Post-quantum security (50+ year validity)

### 1.3 Contributions

This paper presents:

1. **AISS Protocol** — Vendor-neutral standard for agent identity and event signing
2. **PiQrypt Implementation** — Production-ready Python/TypeScript stack
3. **Certification Service** — Pay-per-proof model (€9-€99)
4. **A2A Protocol** — Agent-to-agent trust establishment
5. **Economic Analysis** — Sustainable business model

---

## 2. Problem Statement

### 2.1 Traditional Logging Limitations

**Standard log files:**
```
[2026-02-21 10:00:00] INFO: Trade executed AAPL 100 @ 150.25
[2026-02-21 10:05:00] INFO: Trade executed TSLA 50 @ 280.50
```

**Vulnerabilities:**
- ✗ Editable post-facto (no tamper detection)
- ✗ No cryptographic proof of authorship
- ✗ Timestamps can be backdated
- ✗ Repudiable ("that's not my log")
- ✗ Quantum-vulnerable (RSA/ECDSA breakable by 2035)

### 2.2 Requirements

**R1. Identity:** Deterministic, unforgeable agent identification  
**R2. Integrity:** Tamper-evident event chains  
**R3. Non-repudiation:** Cryptographic attribution  
**R4. Temporality:** Verifiable timestamps  
**R5. Post-quantum:** Resistance to quantum attacks  
**R6. Privacy:** Separation of identity and content  
**R7. Performance:** <10ms overhead per event  
**R8. Compliance:** SEC, HIPAA, GDPR, SOC2 ready  

---

## 3. System Architecture

### 3.1 High-Level Design

```
┌────────────────────────────────────────────────────────────┐
│                    AI Agent Application                    │
│              (Trading Bot, Diagnostic AI, etc.)            │
└─────────────────────────┬──────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│                    PiQrypt Layer                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Identity │  │  Stamp   │  │  Chain   │  │   A2A    │  │
│  │  Module  │  │  Module  │  │  Module  │  │  Module  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Memory  │  │  Export  │  │  Certify │  │  Badge   │  │
│  │  Module  │  │  Module  │  │  Module  │  │  Module  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────┐
│                 Cryptographic Storage                      │
│  Free: JSON plaintext  |  Pro: AES-256-GCM encrypted      │
└────────────────────────────────────────────────────────────┘
```

### 3.2 Components

**Core Modules:**

1. **Identity Module** — Agent ID derivation (§4)
2. **Stamp Module** — Event signing (§5)
3. **Chain Module** — Hash chain verification (§6)
4. **Fork Module** — Branch detection & resolution (§7)
5. **A2A Module** — Agent handshake protocol (§8)
6. **Certification Module** — External proof service (§9)

**Support Modules:**

7. **Memory Module** — Encrypted storage (Pro)
8. **Export Module** — Audit trail export
9. **Badge Module** — Public verification badges
10. **License Module** — Tier management (Free/Pro/Enterprise)

---

## 4. Cryptographic Foundations

### 4.1 Algorithms

| Algorithm | Standard | Purpose | Security Level |
|-----------|----------|---------|----------------|
| **Ed25519** | RFC 8032 | Classical signatures | 128-bit |
| **Dilithium3** | NIST FIPS 204 | Post-quantum signatures | 256-bit PQ |
| **SHA-256** | NIST FIPS 180-4 | Hash chains | 128-bit |
| **AES-256-GCM** | NIST FIPS 197 | Encryption (Pro) | 256-bit |
| **PBKDF2-SHA256** | RFC 8018 | Key derivation | 128-bit |

### 4.2 Why Ed25519 + Dilithium3?

**Ed25519 (Classical):**
- ✅ Fast (64μs per signature)
- ✅ Small (32-byte keys, 64-byte signatures)
- ✅ Deterministic (no random k)
- ✅ Widely adopted (OpenSSH, Signal)

**Dilithium3 (Post-Quantum):**
- ✅ NIST standardized (FIPS 204, 2024)
- ✅ Quantum-resistant (lattice-based)
- ✅ Performance (2.5ms signature, 1.2ms verify)
- ⚠️ Larger (1952-byte keys, 3309-byte signatures)

**Hybrid Approach (AISS-2.0):**
```
Signature = Sign_Ed25519(event) || Sign_Dilithium3(event)
```

**Benefits:**
- If Ed25519 broken by quantum → Dilithium3 remains valid
- If Dilithium3 cryptanalysis → Ed25519 remains valid
- Gradual transition (Ed25519 now, PQ future-proof)

### 4.3 Canonicalization (RFC 8785)

**Problem:** JSON is not deterministic.

```json
{"a": 1, "b": 2}  ≠  {"b": 2, "a": 1}  (different byte strings)
```

**Solution:** RFC 8785 Canonical JSON

```python
import canonicaljson

event = {"agent_id": "...", "timestamp": 123, "payload": {...}}
canonical_bytes = canonicaljson.encode_canonical_json(event)
signature = ed25519.sign(private_key, canonical_bytes)
```

**Properties:**
- Deterministic (same JSON → same bytes)
- Sortable keys (alphabetical)
- No whitespace
- UTF-8 encoded

---

## 5. Agent Identity Protocol

### 5.1 Deterministic ID Derivation

```python
# Generate keypair
private_key = Ed25519.generate()  # 32 bytes
public_key = private_key.public_key()  # 32 bytes

# Derive agent ID
agent_id = Base58(SHA256(public_key))[:32]
# Example: "5Z8nY7KpL9mN3qR4sT6uV8wX"
```

**Properties:**
- **Deterministic:** Same public key → same agent ID
- **Collision-resistant:** SHA-256 (2^128 space)
- **Human-readable:** Base58 (no ambiguous chars)
- **Compact:** 32 characters

### 5.2 Identity Document (AISS-1.0)

```json
{
  "version": "AISS-1.0",
  "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "public_key": "base64:MCowBQYDK2VwAyEA...",
  "algorithm": "Ed25519",
  "created_at": "2026-02-21T10:00:00Z"
}
```

### 5.3 Identity Document (AISS-2.0 — Pro)

```json
{
  "version": "AISS-2.0",
  "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "public_key_classical": "base64:...",
  "public_key_pq": "base64:...",
  "algorithms": ["Ed25519", "ML-DSA-65"],
  "authority_chain": [
    {
      "authority_id": "COMPANY_ROOT_CA",
      "delegation_signature": "base64:..."
    }
  ],
  "created_at": "2026-02-21T10:00:00Z"
}
```

---

## 6. Event Signing & Chaining

### 6.1 Event Structure

```json
{
  "version": "AISS-1.0",
  "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "timestamp": 1739395200,
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "previous_event_hash": "sha256:abc123...",
  "payload": {
    "event_type": "trade_executed",
    "symbol": "AAPL",
    "quantity": 100,
    "price": 150.25
  },
  "signature": "base64:..."
}
```

### 6.2 Signing Process

```python
def stamp_event(private_key, agent_id, payload):
    event = {
        "version": "AISS-1.0",
        "agent_id": agent_id,
        "timestamp": int(time.time()),
        "nonce": str(uuid.uuid4()),
        "previous_event_hash": get_last_event_hash(),
        "payload": payload
    }
    
    # Canonicalize
    canonical = canonicaljson.encode_canonical_json(event)
    
    # Sign
    signature = ed25519.sign(private_key, canonical)
    event["signature"] = encode_base64(signature)
    
    return event
```

### 6.3 Hash Chain

```
Event 0 (Genesis)
  ↓
  hash(Event 0) → previous_event_hash
  ↓
Event 1
  ↓
  hash(Event 1) → previous_event_hash
  ↓
Event 2
  ↓
  ... (chain continues)
```

**Properties:**
- **Immutability:** Modifying Event 1 breaks hash of Event 2
- **Ordering:** Chronological sequence enforced
- **Completeness:** Missing events detectable

---

## 7. Fork Detection & Resolution

### 7.1 Fork Scenario

```
Event 0
  ↓
Event 1
  ├─── Event 2a (Branch A)
  └─── Event 2b (Branch B)  ← FORK!
```

### 7.2 Canonical Resolution Rule

**Tie-break by:**
1. **TSA timestamp** (if available) — earliest wins
2. **Event timestamp** — earliest wins
3. **Event hash** — lexicographically smallest

```python
def resolve_fork(branch_a, branch_b):
    # Rule 1: TSA timestamp
    if branch_a.has_tsa and branch_b.has_tsa:
        return branch_a if branch_a.tsa_time < branch_b.tsa_time else branch_b
    
    # Rule 2: Event timestamp
    if branch_a.timestamp != branch_b.timestamp:
        return branch_a if branch_a.timestamp < branch_b.timestamp else branch_b
    
    # Rule 3: Hash tie-break
    return branch_a if branch_a.hash < branch_b.hash else branch_b
```

**Properties:**
- **Deterministic:** Same forks → same resolution
- **Verifiable:** Independent parties reach same conclusion
- **Final:** TSA-anchored events cannot be superseded

---

## 8. Agent-to-Agent Protocol

### 8.1 Handshake

```
Agent A                              Agent B
  |                                     |
  |─── identity_proposal ──────────────>|
  |    {agent_id_A, pubkey_A, sig_A}    |
  |                                     |
  |<── identity_response ───────────────|
  |    {agent_id_B, pubkey_B, sig_B,    |
  |     sig_B_over_A_proposal}          |
  |                                     |
  |─── session_confirmation ───────────>|
  |    {session_id,                     |
  |     sig_A_over_B_response}          |
  |                                     |
  |  Both agents record co-signed       |
  |  handshake event in their chains    |
```

### 8.2 Co-Signed Event

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
  "timestamp": 1739395200
}
```

**Properties:**
- Both agents have proof of mutual agreement
- Non-repudiable (both signatures required)
- Recorded in both chains (cross-validation)

---

## 9. Certification Service

### 9.1 Three Tiers

| Tier | Price | Cryptography | Legal Value |
|------|-------|--------------|-------------|
| **Simple** | €9 | PiQrypt CA signature | Internal disputes |
| **Timestamp** | €29 | + RFC 3161 TSA | GDPR, HIPAA compliant |
| **Post-Quantum** | €99 | + Dilithium3 + .pqz | 50+ year archival |

### 9.2 Workflow

```
User export audit → Copy JSON → Stripe checkout → Paste JSON →
Pay → Webhook → Worker certifies → Email bundle (< 5 min)
```

**Automation:**
- Stripe custom field (no upload page needed)
- Flask webhook (Render.com)
- Google Drive storage
- Gmail SMTP delivery

### 9.3 Badge Generation

```svg
<svg width="240" height="80">
  <rect fill="#ff9500" width="240" height="80" rx="8"/>
  <text>✅ Verified by PiQrypt</text>
  <text>Timestamp Certification</text>
  <text>CERT-20260221-A3F7E8</text>
</svg>
```

**Public verification:**
```
V1.6.0
```


---

## 10. Security Analysis

### 10.1 Threat Model

**Assumptions:**
- ✅ Attacker does NOT have agent's private key
- ✅ SHA-256, Ed25519, Dilithium3 are secure
- ⚠️ Attacker MAY control the host system
- ⚠️ Attacker MAY have quantum computer (future)

**Out of scope:**
- ✗ Host compromise (assume encrypted memory or HSM for Pro)
- ✗ Social engineering (separate concern)
- ✗ Correct decision-making (AISS only proves *what* was decided)

### 10.2 Attack Scenarios

**Attack 1: Modify past event**

```
Attacker changes Event 5 payload
  → hash(Event 5) changes
  → Event 6.previous_event_hash mismatch
  → Chain verification FAILS ✅
```

**Attack 2: Backdate event**

```
Attacker creates Event with old timestamp
  → No TSA token (if tier Timestamp)
  → Verification shows "no independent timestamp proof"
  → Court rejects ✅
```

**Attack 3: Repudiate event**

```
Agent: "I never created that event"
Verifier: Checks signature with agent's public key
  → Signature valid = agent DID sign
  → Non-repudiation ✅
```

**Attack 4: Fork attack (create parallel history)**

```
Attacker creates Branch B to hide Event 7
  → Canonical resolution rule selects Branch A (earlier TSA)
  → Branch B marked NON_CANONICAL
  → Fraud detectable ✅
```

**Attack 5: Quantum computer (2035+)**

```
Quantum attacker breaks Ed25519
  → Dilithium3 signature remains valid (hybrid AISS-2)
  → Proof still valid ✅
```

### 10.3 Quantum Resistance

**Timeline:**
- 2026: Ed25519 secure (~15 years until quantum threat)
- 2030-2035: First cryptographically-relevant quantum computers
- 2035+: Ed25519 potentially breakable (Shor's algorithm)

**PiQrypt strategy:**
- **Now:** Ed25519 (fast, small, proven)
- **Pro tier:** Hybrid Ed25519 + Dilithium3
- **2035+:** Dilithium3 ensures 50+ year archival validity


## 10.4 Proof-of-Continuity Protocol (PCP)

PCP defines a measurable continuity model for autonomous systems.

It integrates:

1. Internal continuity
   - Hash chain validity
   - Fork resolution
   - Key rotation traceability

2. Interaction continuity
   - Cross-agent handshake validation
   - Verified interaction ratio
   - Diversity metrics

3. Temporal continuity
   - RFC 3161 timestamp anchoring
   - Anti-replay guarantees
   - Deadline compliance

PCP does not measure morality or correctness.
It measures structural coherence over time and network.
---

## 11. Compliance Mapping

### 11.1 Regulatory Requirements

| Framework | Control | AISS Implementation |
|-----------|---------|---------------------|
| **SOC2** | CC6.1 Identity verification | Agent identity document |
| **SOC2** | CC6.6 Audit trail | Hash chain |
| **ISO 27001** | 5.16 Identity management | Deterministic agent ID |
| **ISO 27001** | 8.15 Logging | Event chain stamping |
| **HIPAA** | §164.312 Audit controls | Immutable event chain |
| **GDPR** | Art. 5.1.f Integrity | Tamper-evident chains |
| **GDPR** | Art. 22 Explanation | Signed decision reasoning |
| **SEC** | Rule 17a-4 7-year retention | Certified exports |
| **SOX** | §404 Internal controls | Signed decision records |

### 11.2 Audit Export Format

```json
{
  "version": "AUDIT-1.0",
  "agent_id": "...",
  "period": {
    "start": "2026-01-01T00:00:00Z",
    "end": "2026-12-31T23:59:59Z"
  },
  "events_count": 125743,
  "chain_hash": "sha256:final...",
  "compliance": {
    "soc2": true,
    "hipaa": true,
    "gdpr": true
  },
  "events": [...]
}
```

---

## 12. Economic Model

### 12.1 Pricing 

**Certification Pay-Per:**
- **€9 Simple:** PiQrypt CA signature
- **€29 Timestamp:** + TSA RFC 3161
- **€99 Post-Quantum:** + Dilithium3 + .pqz

**Subscriptions:**
- **Free:** 3 agents, 1 cert/month
- **Early-Bird Pro:** €290/year (50 agents*, 10 certs/month)
- **Standard Pro:** €390/year (50 agents*, 50 certs/month)
- **Enterprise:** From €10k/year (unlimited, HSM, API)

*Psychological limit; code doesn't enforce (unlimited real)

### 12.2 Unit Economics

**Certification €

**Pro Subscription €
```

### 12.3 Market Sizing

WIP
---

## 13. Implementation

### 13.1 Repository Structure

```
piqrypt/
├── aiss/                 # Core crypto
│   ├── crypto/           # Ed25519, Dilithium3
│   ├── stamp.py          # Event signing
│   ├── chain.py          # Hash chains
│   ├── fork.py           # Fork resolution
│   ├── a2a.py            # A2A protocol [v1.5]
│   ├── certification.py  # Pay-per service [v1.5]
│   └── cert_badges.py    # Badge generation [v1.5]
├── cli/                  # Command-line tool
├── webhook/              # Stripe automation [v1.5]
├── docs/                 # RFC, guides
└── tests/                # 38 tests passing
```

### 13.2 Dependencies

**Python:**
```
cryptography>=41.0.0      # Ed25519, AES-256-GCM
canonicaljson>=2.0.0      # RFC 8785
PyNaCl>=1.5.0             # NaCl library
liboqs-python>=0.9.0      # Dilithium3 (optional)
```

**Infrastructure:**
```
Render.com     # Webhook (free 750h/month)
Google Drive   # Storage (15GB free)
Gmail SMTP     # Email (500/day free)
Stripe         # Payments (2.9% + €0.25)
```

### 13.3 Performance

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Generate identity | 15ms | 66/sec |
| Sign event (Ed25519) | 0.06ms | 16,666/sec |
| Verify signature | 0.15ms | 6,666/sec |
| Store event (Free) | 2ms | 500/sec |
| Store event (Pro, encrypted) | 5ms | 200/sec |
| Export audit (1000 events) | 120ms | 8/sec |

**Overhead:** <10ms per event (meets R7)

---

## 14. Future Work

### 14.1 Roadmap

**v1.6.0 (Q2 2026):**
- Trust scoring dashboard (I/V/D/F metrics)
- Visual badges (custom branding)
- A2A network (DHT peer discovery)

**v1.7.0 (Q3 2026):**
- Witness network (distributed trust)
- HSM integration (hardware security)
- Blockchain anchoring (public ledger)

**v2.0.0 (Q4 2026):**
- ML-KEM-768 key exchange
- Zero-knowledge proofs (selective disclosure)
- Homomorphic encryption (compute on encrypted events)

### 14.2 Research Directions

**Privacy-preserving proofs:**
- Prove "decision was made" without revealing decision content
- Zero-knowledge range proofs (e.g., "price > $100" without revealing exact price)

**Distributed trust:**
- Multi-party witness consensus (Byzantine fault tolerance)
- Threshold signatures (k-of-n approval)

**Formal verification:**
- TLA+ specification of AISS protocol
- Coq proof of chain integrity properties

---

## 15. Conclusion

PiQrypt addresses a critical gap in AI agent infrastructure: **verifiable, tamper-proof decision trails**. By combining:

1. **Open standard** (AISS v1.1, MIT licensed)
2. **Strong cryptography** (Ed25519 + Dilithium3)
3. **Production-ready implementation** (Python/TypeScript)
4. **Compliance-native design** (SOC2, HIPAA, GDPR)
5. **Sustainable economics** (pay-per + subscription)

...PiQrypt enables autonomous agents to operate in regulated environments with legal accountability.

**Key achievements:**
- ✅ <10ms overhead (R7)
- ✅ Post-quantum secure (R5)
- ✅ Compliance-ready (R8)
- ✅ 38/38 tests passing
- ✅ €0 infrastructure cost (MVP)

**Next milestone:** Launch v1.5.0 → 1,000 Pro subscriptions → €290k ARR → Series A.

---

## References

1. RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
2. RFC 8785 — JSON Canonicalization Scheme (JCS)
3. RFC 3161 — Time-Stamp Protocol (TSP)
4. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
5. NIST FIPS 197 — Advanced Encryption Standard (AES)
6. GDPR — General Data Protection Regulation (EU)
7. HIPAA — Health Insurance Portability and Accountability Act (US)
8. SEC Rule 17a-4 — Electronic Storage of Broker-Dealer Records
9. SOC2 — Service Organization Control 2 (AICPA)
10. ISO/IEC 27001:2022 — Information Security Management

---

**For implementation details, see:**
- AISS Specification: https://github.com/piqrypt/aiss-spec
- PiQrypt Core: https://github.com/piqrypt/piqrypt
- MCP Server: https://github.com/piqrypt/piqrypt-mcp-server

---

*PiQrypt Technical Whitepaper v1.5.0*  
*© 2026 PiQrypt Inc. — All Rights Reserved*  
*Patent Pending / e-Soleau DSO2026006483*
