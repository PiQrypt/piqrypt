# PiQrypt Whitepaper v2.0
## Proof of Agent Continuity Infrastructure for Autonomous AI Systems

**Version:** 2.0.0
**Date:** March 2026
**Authors:** PiQrypt
**Status:** Public Release
**IP:** e-Soleau DSO2026006483 + DSO2026009143 (INPI France)
**Contact:** contact@piqrypt.com

---

## Abstract

Autonomous AI agents are rapidly moving from experimental tools to operational actors in finance, healthcare, infrastructure, and digital governance. They execute transactions, coordinate with other agents, and trigger downstream automated actions — often without human review.

Yet the AI ecosystem lacks a fundamental infrastructure primitive: **verifiable continuity of autonomous agents across time, decisions, and interactions.**

PiQrypt introduces the **Proof of Continuity Protocol (PCP)** — a four-layer cryptographic infrastructure enabling autonomous agents to prove:

- **Who they are** — persistent cryptographic identity (AISS)
- **What they did** — tamper-proof signed event chains (PiQrypt Core)
- **Whether their behaviour remained coherent** — real-time risk scoring (Vigil)
- **Whether a human approved it** — policy enforcement and oversight gate (TrustGate)

PiQrypt is not a logging system. It is a **verifiable continuity layer** — records that can be independently verified without access to the original infrastructure, usable in regulatory audits and legal proceedings.

---

## Table of Contents

```
1.  The Agent Continuity Problem
2.  The Proof of Continuity Protocol (PCP)
3.  Layer 1 — AISS: Agent Identity & Security Substrate
4.  Layer 2 — PiQrypt Core: Continuity Engine
5.  Layer 3 — Vigil: Behavioural Monitoring
6.  Layer 4 — TrustGate: Governance & Human Oversight
7.  Cryptographic Foundations
8.  Agent-to-Agent Protocol (A2A)
9.  External Peer Observation
10. Framework Bridges
11. Certification Services
12. Compliance Mapping
13. Security Analysis
14. Economic Model
15. Implementation
16. Future Work
17. Conclusion
```

---

## 1. The Agent Continuity Problem

### 1.1 The Missing Infrastructure Layer

Current AI architecture focuses on:

```
    Model Layer        (GPT-4o, Claude, Gemini, Llama)
         ↓
    Inference APIs     (OpenAI, Anthropic, Ollama)
         ↓
    Agent Frameworks   (LangChain, CrewAI, AutoGen, MCP)
         ↓
    Applications       (trading bots, copilots, robots)
```

**There is no trust infrastructure layer.**

Critical properties are absent from this stack:

- Persistent cryptographic identity per agent
- Tamper-evident decision history
- Verifiable interaction records between agents
- Behavioural stability monitoring over time
- Human oversight gate for critical actions
- Compliance-grade auditability

Without these properties, autonomous agents remain **ephemeral, unverifiable software processes** rather than accountable digital actors.

### 1.2 Four Structural Weaknesses

**Ephemeral Identity.** An agent restarted on another machine is indistinguishable from a new one. There is no persistent cryptographic identity.

**Mutable Logs.** Standard log files can be modified, deleted, reordered, or backdated:
```
[2026-03-01] Trade executed AAPL 100 @ 150.25    ← editable, repudiable
```

**No Behavioural Continuity.** There is no systematic mechanism to detect when an agent begins behaving anomalously — drift, collusion, or sudden reversal.

**No Interaction Accountability.** When agents interact, there is typically no cryptographically verifiable record of what was exchanged, between whom, and when.

### 1.3 Regulatory Convergence

Three major frameworks are converging simultaneously:

| Framework | Key requirements |
|-----------|-----------------|
| **EU AI Act** | Art. 12 (inviolable logs), Art. 14 (human oversight mandatory for high-risk AI), Art. 9 (risk management) |
| **ANSSI 2024** | R25 (dangerous pattern filtering), R29 (audit trail), R30 (clearance-based access) |
| **NIST AI RMF 1.0** | GOVERN 1.2, MANAGE 2.2, MEASURE 2.5, AI 600-1 (agentic AI supervision) |

Traditional logs are not designed for adversarial or legal scrutiny. PiQrypt addresses this gap.

---

## 2. The Proof of Continuity Protocol (PCP)

### 2.1 Core Concept

PCP introduces a foundational concept: **Agent Continuity.**

An autonomous agent must remain a **verifiable, coherent entity** across time, decisions, and interactions. This requires four forms of continuity:

```
              PROOF OF CONTINUITY PROTOCOL

                   Identity Continuity
                          │
                          │
    Memory ────────── [ AGENT ] ────────── Interaction
    Continuity                             Continuity
                          │
                          │
                   Behavioural Continuity
```

**Identity Continuity** — The agent maintains a deterministic cryptographic identity regardless of infrastructure changes, model upgrades, or environment migrations.

**Memory Continuity** — All decisions form a tamper-evident, chronologically ordered chain. Modifications are cryptographically detectable.

**Interaction Continuity** — Agent-to-agent and agent-to-external-service interactions are cryptographically recorded, including with systems not equipped with PiQrypt.

**Behavioural Continuity** — The system monitors drift, anomalies, and collusion patterns continuously, and enforces human oversight when thresholds are exceeded.

Together, these four dimensions produce **Proof of Agent Continuity (PAC)**:

```
PAC = Identity Integrity
    + Event Chain Integrity
    + Interaction Traceability
    + Behavioural Stability
    + Policy Compliance
```

PAC does not verify the *correctness* of decisions. It verifies **who made them, when, how they relate to prior actions, and whether behaviour remained coherent**.

### 2.2 Four-Layer Architecture

PiQrypt implements PCP as a four-layer stack positioned between agent frameworks and storage:

```
    ╔══════════════════════════════════════════════════╗
    ║              TRUSTGATE                           ║
    ║   Human oversight · Policy · Hash-chained audit  ║  Governance
    ╠══════════════════════════════════════════════════╣
    ║              VIGIL                               ║
    ║   Real-time SOC dashboard · VRS · Alerts         ║  Observability
    ╠══════════════════════════════════════════════════╣
    ║              PIQRYPT CORE                        ║
    ║   VRS scoring · .pqz certification · RFC 3161    ║  Risk & Certification
    ╠══════════════════════════════════════════════════╣
    ║              AISS                                ║
    ║   Identity · Signed memory · A2C detection       ║  Foundation (MIT)
    ╚══════════════════════════════════════════════════╝
```

PiQrypt does not replace agent frameworks. It provides the **trust infrastructure** they lack.

### 2.3 Agent Lifecycle Under PCP

```
    Create Identity (AISS)
           │
           ▼
    Agent Initialization
           │
           ▼
    Agent Action / Decision
           │
           ▼
    Event Signing + Hash Chain Linking
           │
           ▼
    Behavioural Monitoring (Vigil VRS)
           │
           ▼
    TrustGate Policy Evaluation
           │
          / \
    ALLOW   DENY / AUDIT
         │
         ▼
    Compliance Storage (.pqz)
```

---

## 3. Layer 1 — AISS: Agent Identity & Security Substrate

AISS (Agent Identity and Signature Standard) is the cryptographic foundation of PCP. It is open-source (MIT) and vendor-neutral.

### 3.1 Deterministic Identity

```python
private_key, public_key = ed25519.generate_keypair()
agent_id = Base58(SHA256(public_key))[:32]
# Example: "5Z8nY7KpL9mN3qR4sT6uV8wX"
```

The identity is:
- **Deterministic** — same keypair → same agent ID
- **Portable** — survives infrastructure changes, model upgrades, environment migrations
- **Independent** — no central authority required

### 3.2 Signed Event Chain

Every agent action produces a signed, hash-linked event:

```
[genesis] ──→ [event 1] ──→ [event 2] ──→ [event 3]
    Ed25519      Ed25519      Ed25519      Ed25519
   prev_hash    prev_hash    prev_hash    prev_hash
```

Event structure:
```json
{
  "version":       "AISS-1.0",
  "agent_id":      "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "timestamp":     1740902400,
  "nonce":         "550e8400-e29b-41d4-a716-446655440000",
  "previous_hash": "sha256:abc123...",
  "payload":       { "event_type": "trade_executed", "symbol": "AAPL", "quantity": 100 },
  "signature":     "base64:...",
  "tsa":           "rfc3161:..."
}
```

If any event is modified: hash mismatch → chain invalid → `InvalidChainError` raised.

### 3.3 Two Signature Tiers

| Tier | Algorithm | Quantum-resistant | Availability |
|------|-----------|:-----------------:|:------------:|
| **STANDARD** | Ed25519 (RFC 8032) | ✗ | All tiers |
| **QUANTUM** | Dilithium3 (NIST FIPS 204) | ✅ | Pro+ |

> Ed25519 (STANDARD) is not post-quantum resistant. For quantum resilience, use `pip install piqrypt[post-quantum]` (Pro tier and above).

### 3.4 A2C Detection — Relational Anomaly Detection

AISS includes the A2C (Agent-to-Context) detector, which evaluates four relational anomaly patterns across agent interactions:

| Pattern | Description |
|---------|-------------|
| **Concentration** | Over-reliance on a single peer (>80% of interactions) |
| **Entropy drop** | Sudden reduction in interaction diversity |
| **Synchronisation** | Multiple agents acting in tight temporal lock-step |
| **Silence break** | Abnormal burst following extended inactivity |

### 3.5 VRS — Vigil Risk Score

Composite real-time risk score [0.0 → 1.0] from four weighted components:

| Component | Weight | What it measures |
|-----------|--------|-----------------|
| Trust Score Instability (TSI) | 30% | Drift in inter-agent relationships |
| Trust Score | 35% | Concentration, volume, frequency anomalies |
| A2C | 20% | 4 patterns: concentration, entropy drop, synchronisation, silence break |
| Chain | 15% | Cryptographic integrity of the identity chain |

States: **SAFE** (VRS < 0.25) · **WATCH** (0.25–0.50) · **ALERT** (0.50–0.75) · **CRITICAL** (> 0.75)

---

## 4. Layer 2 — PiQrypt Core: Continuity Engine

PiQrypt Core provides the operational continuity mechanisms built on top of AISS.

### 4.1 Hash Chain Verification

```python
aiss.verify_chain([event_0, event_1, event_2, ...])
# Raises InvalidChainError on any modification
```

### 4.2 Fork Detection & Resolution

A fork occurs when two events share the same `previous_hash`:

```
Event 0
  ↓
Event 1
  ├─── Event 2a (Branch A)
  └─── Event 2b (Branch B)  ← FORK DETECTED → CRITICAL alert
```

Resolution rule (deterministic):
```python
def resolve_fork(branch_a, branch_b):
    if branch_a.has_tsa and branch_b.has_tsa:
        return min(branch_a, branch_b, key=lambda b: b.tsa_time)
    if branch_a.timestamp != branch_b.timestamp:
        return min(branch_a, branch_b, key=lambda b: b.timestamp)
    return min(branch_a, branch_b, key=lambda b: b.hash)
```

### 4.3 RFC 3161 Timestamping

Events can be anchored to an external, trusted Time Stamping Authority (TSA), producing a legally admissible timestamp independent of PiQrypt infrastructure.

### 4.4 .pqz Certification Format

The `.pqz` format is PiQrypt's portable audit bundle:
- Ed25519 signature (all tiers)
- Dilithium3 post-quantum signature (Pro+)
- RFC 3161 TSA token (Pro+)
- SHA-256 hash of event chain
- Human-readable certificate (Claude Haiku generated, Pro+)

### 4.5 Anti-Replay Protection

```python
detect_replay_attacks(events)
# Flags duplicate nonces — blocks replay attack
```

### 4.6 Encrypted Storage (Pro+)

| Tier | Storage | Key protection |
|------|---------|----------------|
| Free | JSON plaintext | None |
| Pro+ | AES-256-GCM | scrypt N=2¹⁷ + AES-256-GCM (.key.enc, 97 bytes) |

Key derivation scheme:
```
passphrase + salt (32 bytes random)
    ↓ scrypt(N=2¹⁷, r=8, p=1)    # ~400ms — brute-force resistant
    ↓
derived_key (32 bytes)
    ↓ AES-256-GCM(nonce=12 bytes)
    ↓
.key.enc = MAGIC(4) + VERSION(1) + SALT(32) + NONCE(12) + CIPHER(32) + TAG(16)
         = 97 bytes exactly
```

---

## 5. Layer 3 — Vigil: Behavioural Monitoring

Vigil is PiQrypt's real-time monitoring layer — a SOC dashboard for AI agents.

### 5.1 Trust State Index (TSI)

The TSI evaluates behavioural stability over a 24-hour sliding window:

| State | Condition | Action |
|-------|-----------|--------|
| `STABLE` | Score stable, no significant drift | Normal operation |
| `WATCH` | Mild drift detected (Δ24h < -0.08) | Alert logged |
| `UNSTABLE` | Significant deviation (Δ24h < -0.15) | Alert raised |
| `CRITICAL` | UNSTABLE persisting > 48h | High-severity alert, TrustGate triggered |

### 5.2 Network Graph — External Peer Observation

Vigil's network graph displays agent-to-agent and **agent-to-external-service** interactions. External systems (Binance WS, Anthropic API, GitHub webhooks, Bloomberg Terminal, etc.) appear as distinct nodes on an outer ring, connected by live traffic indicators.

This is a key PiQrypt differentiator: **external peers do not need to be equipped with PiQrypt.** Observation is unilateral — PiQrypt records what the monitored agent does, including calls to unregistered external services, with realistic latency and volume profiles per service type:

| Pattern | Examples | Behaviour |
|---------|---------|-----------|
| `burst_open` | Binance WS, Bloomberg | Spikes at market open/close (9h/17h30) |
| `burst` | GitHub webhook, Docker registry | Peaks around push/deploy events |
| `scheduled` | Anthropic API, Instagram API | 3 fixed sessions per day |
| `steady` | Prometheus, Redis | Continuous low-volume flow |

### 5.3 Risk Narrative

Vigil generates human-readable risk narratives for each agent, prioritising the most severe anomaly:

```
⛓ FORK DETECTED — Event chain fork on merge
   → Possible replay attack. Canonical branch resolved by TSA timestamp.
   → Recommend: immediate review of Event #2a vs #2b
```

### 5.4 Dashboard Access

```bash
python -m vigil.vigil_server
# Dashboard  → http://127.0.0.1:18421
# API        → http://127.0.0.1:18421/api/summary
# Alerts     → http://127.0.0.1:18421/api/alerts
# Agent      → http://127.0.0.1:18421/api/agent/<name>
```

---

## 6. Layer 4 — TrustGate: Governance & Human Oversight

TrustGate is the policy enforcement and human oversight gate — the governance layer of PCP. It is the direct implementation of EU AI Act Art. 14 (human oversight mandatory for high-risk AI systems).

### 6.1 Role in the Stack

```
    AI AGENT
        │
        │  action proposed
        ▼
    PIQRYPT CORE   ←── event signed, hash-linked
        │
        │  VRS computed
        ▼
    VIGIL          ←── behavioural monitoring
        │
        │  risk score transmitted
        ▼
    TRUSTGATE      ←── policy evaluation
        │
       / \
    ALLOW   DENY / AUDIT / ESCALATE
```

### 6.2 Policy Evaluation

TrustGate evaluates each action against a configurable policy profile. Supported frameworks:

| Framework | Implementation |
|-----------|---------------|
| EU AI Act | Art. 9 risk management, Art. 12 logging, Art. 14 human oversight |
| NIST AI RMF | GOVERN 1.2, MANAGE 2.2, MEASURE 2.5 |
| ANSSI 2024 | R25 pattern filtering, R29 audit trail, R30 clearance access |
| Custom policies | YAML-configurable rules per agent profile |

Possible outcomes per action:

| Decision | Meaning |
|----------|---------|
| `ALLOW` | Action compliant — logged, stamped, chained |
| `DENY` | Action blocked — incident logged with reason |
| `AUDIT` | Action allowed but flagged for manual review |
| `ESCALATE` | Human operator notified in real-time before execution |

### 6.3 All Decisions Are Hash-Chained

Every TrustGate decision — ALLOW or DENY — is itself a signed event appended to the agent's chain. The governance record is tamper-evident and auditable.

### 6.4 Availability

TrustGate is available in **Pro+ tier** and above. It is the primary differentiator between Free and Pro.

---

## 7. Cryptographic Foundations

### 7.1 Algorithm Stack

| Algorithm | Standard | Purpose | Security Level |
|-----------|----------|---------|----------------|
| **Ed25519** | RFC 8032 | Classical signatures | 128-bit |
| **Dilithium3** | NIST FIPS 204 | Post-quantum signatures | 256-bit PQ |
| **SHA-256** | NIST FIPS 180-4 | Hash chains | 128-bit |
| **AES-256-GCM** | NIST FIPS 197 | Encrypted storage (Pro+) | 256-bit |
| **scrypt** | RFC 7914 | Key derivation | N=2¹⁷, r=8, p=1 |
| **RFC 8785 JCS** | IETF | JSON canonicalization | Deterministic |
| **RFC 3161 TSP** | IETF | Trusted timestamping | External anchor |

### 7.2 Quantum Resistance Timeline

- **2026:** Ed25519 secure (~10 years until credible quantum threat)
- **2030–2035:** First cryptographically-relevant quantum computers expected
- **2035+:** Ed25519 potentially breakable (Shor's algorithm)
- **PiQrypt strategy:** Hybrid Ed25519 + Dilithium3 for Pro+ — archives remain valid post-quantum

### 7.3 Canonicalization (RFC 8785)

JSON is non-deterministic by nature (`{"a":1,"b":2}` ≠ `{"b":2,"a":1}` as byte strings). PiQrypt applies RFC 8785 JSON Canonicalization Scheme before signing: keys sorted lexicographically, no whitespace, UTF-8 encoded. This ensures identical events always produce identical signatures.

---

## 8. Agent-to-Agent Protocol (A2A)

When two PiQrypt-equipped agents interact, they execute a signed handshake:

```
Agent A                                  Agent B

identity_proposal  ──────────────────→
                  ←──────────────────  identity_response
session_confirm    ──────────────────→

Both agents append co-signed handshake event to their own chain.
```

The co-signed event:
```json
{
  "version":    "AISS-1.0",
  "event_type": "a2a_handshake",
  "session_id": "uuid-v4",
  "initiator":  { "agent_id": "...", "signature": "..." },
  "responder":  { "agent_id": "...", "signature": "..." },
  "timestamp":  1740902400
}
```

This produces a **verifiable, bilateral interaction record** — neither party can deny the exchange.

---

## 9. External Peer Observation

A fundamental PiQrypt capability: **monitoring interactions with external systems that are not equipped with PiQrypt.**

When a monitored agent calls `binance_ws`, `anthropic_api`, or `github_webhook`, PiQrypt records:

```python
stamp_event(private_key, agent_id, {
    "event_type":  "order_submitted",
    "peer_id":     "binance_ws",       # external system — no PiQrypt required
    "latency_ms":  7,
    "status":      "200",
    "external":    True
})
```

Binance does not know PiQrypt exists. The observation is **unilateral** — PiQrypt monitors what the agent does, including frequency, volume, latency, and synchronisation with other agents.

This enables detection of:
- Abnormal concentration on a single external service
- Temporal synchronisation between agents calling the same external endpoint
- Anomalous latency patterns suggesting man-in-the-middle
- Interaction bursts deviating from established behavioural baseline

Vigil displays these external peers as distinct nodes in the network graph, connected to monitored agents by live traffic indicators.

---

## 10. Framework Bridges

PiQrypt integrates transparently with major AI agent frameworks via bridges:

| Framework | Bridge | Install |
|-----------|--------|---------|
| LangChain | `bridges/langchain/` | `pip install piqrypt[langchain]` |
| CrewAI | `bridges/crewai/` | `pip install piqrypt[crewai]` |
| AutoGen | `bridges/autogen/` | `pip install piqrypt[autogen]` |
| MCP (Model Context Protocol) | `bridges/mcp/` | `pip install piqrypt[mcp]` |
| Ollama | `bridges/ollama/` | `pip install piqrypt[ollama]` |
| ROS2 | `bridges/ros2/` | `pip install piqrypt[ros2]` |
| Raspberry Pi | `bridges/rpi/` | `pip install piqrypt[rpi]` |
| Session | `bridges/session/` | `pip install piqrypt[session]` |
| OpenClaw | `bridges/openclaw/` | `pip install piqrypt[openclaw]` |
| All bridges | — | `pip install piqrypt[all-bridges]` |

**Integration example (LangChain):**
```python
from langchain.agents import AgentExecutor
from piqrypt.bridges.langchain import PiQryptCallbackHandler

handler = PiQryptCallbackHandler(agent_name="my_agent")
executor = AgentExecutor(agent=agent, callbacks=[handler])
# Every LLM call, tool invocation, and chain step is automatically stamped.
```

---

## 11. Certification Services

PiQrypt offers three certification tiers for producing legally admissible audit bundles:

| Tier | Price | Cryptography | Legal value |
|------|-------|--------------|-------------|
| **Simple** | €9 | PiQrypt CA signature | Internal disputes |
| **Timestamp** | €29 | + RFC 3161 TSA | GDPR, HIPAA compliant |
| **Post-Quantum** | €99 | + Dilithium3 + .pqz | 50+ year archival security |

Certification workflow:
```
User exports audit trail
        ↓
Stripe checkout (€9 / €29 / €99)
        ↓
JSON submitted to certification endpoint
        ↓
Webhook triggers certification worker
        ↓
Worker signs, timestamps, generates PDF certificate (Claude Haiku)
        ↓
Bundle (.pqz + PDF) delivered by email (< 5 min)
        ↓
SHA-256 hash published to public GitHub verification registry
```

Public verification: any third party can verify a certificate hash without access to PiQrypt infrastructure.

---

## 12. Compliance Mapping

| Framework | Control | PiQrypt Implementation |
|-----------|---------|----------------------|
| **EU AI Act** | Art. 12 — Inviolable logging | Hash-chained signed events |
| **EU AI Act** | Art. 14 — Human oversight | TrustGate ESCALATE/DENY |
| **EU AI Act** | Art. 9 — Risk management | VRS composite scoring |
| **SOC2** | CC6.1 Identity verification | AISS deterministic agent ID |
| **SOC2** | CC6.6 Audit trail | Event chain + .pqz export |
| **ISO 27001** | 5.16 Identity management | Ed25519 agent identity |
| **ISO 27001** | 8.15 Logging | Tamper-evident event chain |
| **HIPAA** | §164.312 Audit controls | Immutable event chain |
| **GDPR** | Art. 5.1.f Integrity | Tamper-evident chains |
| **GDPR** | Art. 22 Explanation | Signed decision reasoning |
| **SEC** | Rule 17a-4 7-year retention | .pqz certified exports |
| **SOX** | §404 Internal controls | Signed decision records |
| **NIST AI RMF** | GOVERN 1.2, MANAGE 2.2 | TrustGate policy engine |
| **ANSSI 2024** | R25, R29, R30 | A2C detection, audit trail, access control |

---

## 13. Security Analysis

### 13.1 Threat Model

**In scope:**
- ✅ Post-event log modification → hash chain invalidation
- ✅ Identity repudiation → Ed25519 non-repudiation
- ✅ Timeline alteration → RFC 3161 TSA anchoring
- ✅ Replay attacks → nonce-based deduplication
- ✅ Brute-force key → scrypt N=2¹⁷ (~400ms/attempt)
- ✅ Key in RAM → `_secure_erase()` zeros bytearray after use
- ✅ Path traversal → `_safe_name()` neutralises all separators
- ✅ Quantum attacks (2035+) → Dilithium3 hybrid (Pro+)
- ✅ Unsupervised critical actions → TrustGate ESCALATE/DENY
- ✅ Behavioural anomalies → Vigil VRS + A2C continuous monitoring

**Out of scope:**
- ✗ Compromised private keys (HSM recommended for Level 3)
- ✗ Malicious logic executing *before* stamping
- ✗ Fully compromised host systems
- ✗ Correctness of decisions (PiQrypt proves *what* was decided, not whether it was correct)

### 13.2 Key Attack Scenarios

**Attack: Modify past event**
```
Attacker changes Event 5 payload
  → hash(Event 5) changes
  → Event 6.previous_hash mismatch
  → verify_chain_linkage() raises InvalidChainError ✅
```

**Attack: Brute-force passphrase on .key.enc**
```
Attacker tries 1M passphrases/second
  → scrypt N=2¹⁷ = ~400ms per attempt
  → Effective rate: ~2.5 attempts/second
  → 10⁸ common passphrases → ~4.6 years ✅
```

**Attack: Agent acts without human approval**
```
Agent proposes high-risk action
  → VRS > threshold → TrustGate triggered
  → ESCALATE: human operator notified before execution
  → If no response within TTL → DENY ✅
```

---

## 14. Economic Model

### 14.1 Subscription Tiers

| Tier | Agents | Events/month | Price | Key features |
|------|--------|-------------|-------|-------------|
| **Free** | 3 | 10,000 | Free forever | AISS STANDARD, .pqz memory, Vigil read-only |
| **Pro** | 50 | 500,000 | $79/mo · $790/yr | QUANTUM, TSA RFC 3161, .pqz CERTIFIED, Vigil full, TrustGate manual |
| **Team** | 100 | 1,000,000 | $199/mo · $1,990/yr | All Pro + priority support |
| **Business** | 500 | 10,000,000 | $1,499/mo · $14,990/yr | All Team + TrustGate full, SIEM, multi-org |
| **Enterprise** | Unlimited | Unlimited | On request | All Business + SSO, on-premise, SLA, air-gap |

### 14.2 Certification Pay-Per

- **€9 Simple** — PiQrypt CA signature
- **€29 Timestamp** — + TSA RFC 3161
- **€99 Post-Quantum** — + Dilithium3 + .pqz

### 14.3 Strategic Positioning

PiQrypt occupies a unique position in the infrastructure stack:

| Infrastructure | Purpose |
|---------------|---------|
| PKI | Identity for humans and servers |
| TLS | Secure transport |
| OAuth | Delegated authorisation |
| Blockchain | Distributed transaction consensus |
| **PiQrypt / PCP** | **Agent continuity and accountability** |

---

## 15. Implementation

### 15.1 Quick Start

```bash
pip install piqrypt
```

```python
import piqrypt as aiss

# Create agent identity
private_key, public_key = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(public_key)

# Stamp a signed, hash-linked event
event = aiss.stamp_event(
    private_key,
    agent_id,
    {"action": "recommendation", "asset": "AAPL", "value": "buy"}
)
aiss.store_event(event)

# Verify chain integrity — raises InvalidChainError on any tampering
aiss.verify_chain([event])
```

```bash
# CLI
piqrypt identity create my_agent
piqrypt stamp my_agent --payload '{"action": "trade", "symbol": "AAPL"}'
piqrypt verify my_agent
# ✅ Chain integrity verified — 1 event, 0 anomalies
```

### 15.2 Repository Structure

```
piqrypt/
├── aiss/                      # Core crypto & protocol (MIT)
│   ├── identity.py            # Agent ID derivation
│   ├── stamp.py               # Event signing
│   ├── chain.py               # Hash chain verification
│   ├── fork.py                # Fork detection & resolution
│   ├── a2a.py                 # A2A handshake protocol
│   ├── key_store.py           # scrypt + AES-256-GCM key storage
│   ├── agent_registry.py      # Per-agent directory isolation
│   ├── tsi_engine.py          # Trust State Index
│   ├── a2c_detector.py        # Relational anomaly detection
│   ├── anomaly_monitor.py     # VRS composite scoring
│   ├── memory.py              # Event storage (Free/Pro)
│   ├── exports.py             # Audit trail export
│   └── certification.py      # Pay-per certification
├── vigil/
│   └── vigil_server.py        # HTTP dashboard + REST API
├── trustgate/
│   └── trustgate.py           # Policy engine + human oversight gate
├── bridges/
│   ├── langchain/             # LangChain bridge
│   ├── crewai/                # CrewAI bridge
│   ├── autogen/               # AutoGen bridge
│   ├── mcp/                   # Model Context Protocol bridge
│   ├── ollama/                # Ollama bridge
│   ├── ros2/                  # ROS2 bridge
│   ├── rpi/                   # Raspberry Pi bridge
│   ├── session/               # Session bridge
│   └── openclaw/              # OpenClaw bridge
├── demos/
│   ├── demo_piqrypt_live.py   # 19-agent legacy demo
│   └── demo_families.py       # 9-agent family demo (Nexus/PixelFlow/AlphaCore)
└── tests/                     # 325 passed, 17 known infrastructure failures
```

### 15.3 Performance

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Generate identity | 15ms | 66/sec |
| Sign event (Ed25519) | 0.06ms | 16,666/sec |
| Verify signature | 0.15ms | 6,666/sec |
| Encrypt key (scrypt N=2¹⁷) | ~400ms | intentionally slow |
| Store event (Free) | 2ms | 500/sec |
| Store event (Pro, encrypted) | 5ms | 200/sec |
| Export audit (1,000 events) | 120ms | 8/sec |

Key encryption latency (~400ms) is intentional and occurs only at key creation or passphrase change — never during normal event stamping.

---

## 16. Future Work

### 16.1 v2.1 Roadmap

- **Peer auto-discovery** — `anomaly_monitor` automatically registers observed external peers from events, with latency and trust score computed from observed behaviour (no manual configuration)
- **TrustGate webhook** — real-time human approval interface via Slack/email/mobile
- **Agent reputation layer** — cross-deployment trust score aggregation

### 16.2 v3.0 Research Directions

- **Witness network** — distributed trust consensus, Byzantine fault tolerance
- **Blockchain anchoring** — public ledger anchoring for maximum non-repudiation
- **HSM integration** — hardware security module for Level 3 compliance
- **Zero-knowledge proofs** — prove "decision was made" without revealing content
  - Example: Prove `price > 100` without revealing exact price
- **ML-KEM-768** — post-quantum key exchange
- **Formal verification** — TLA+ specification of PCP protocol

### 16.3 Internet of Agents Vision

At scale, PCP can become the **trust infrastructure for the AI agent ecosystem**:

```
              INTERNET OF AGENTS

    ┌────────────────────────────────────────┐
    │            Applications                │
    │  trading · robots · copilots · IoT     │
    └────────────────────────────────────────┘
                        │
                        ▼
    ┌────────────────────────────────────────┐
    │         Agent Frameworks               │
    │  LangChain · CrewAI · AutoGen · MCP    │
    └────────────────────────────────────────┘
                        │
                        ▼
    ┌────────────────────────────────────────┐
    │         PIQRYPT / PCP LAYER            │
    │  Identity · Memory · Monitoring        │
    │  Interaction · Governance              │
    └────────────────────────────────────────┘
                        │
                        ▼
    ┌────────────────────────────────────────┐
    │        Trust Infrastructure            │
    │  witness network · TSA · compliance    │
    └────────────────────────────────────────┘
```

This enables the emergence of:
- **Agent reputation markets** — agents acquire verifiable trust history
- **Agent-to-agent economies** — contracts between autonomous entities
- **AI governance frameworks** — policy-driven agent supervision at scale
- **Accountable machine decision systems** — legal-grade AI accountability

---

## 17. Conclusion

PiQrypt addresses a critical gap in AI agent infrastructure: **verifiable, tamper-proof decision trails with behavioural continuity monitoring and human oversight.**

By implementing the Proof of Continuity Protocol across four integrated layers — AISS, PiQrypt Core, Vigil, and TrustGate — PiQrypt transforms autonomous agents from ephemeral software processes into **verifiable digital entities**.

**Key capabilities (v2.0.0):**
- ✅ <10ms overhead per event (Ed25519 signing)
- ✅ Post-quantum secure archives (Dilithium3, NIST FIPS 204)
- ✅ Compliance-native (EU AI Act, ANSSI, NIST AI RMF, GDPR, SOC2, HIPAA, SEC)
- ✅ Behavioural drift detection (TSI, A2C, VRS)
- ✅ External peer observation — no PiQrypt required on the observed side
- ✅ Human oversight gate (TrustGate)
- ✅ 9 framework bridges (LangChain, CrewAI, AutoGen, MCP, Ollama, ROS2, RPi, Session, OpenClaw)
- ✅ 325 tests passing

PiQrypt is the **reference implementation of the Proof of Continuity Protocol.**

---

## References

1. RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
2. RFC 8785 — JSON Canonicalization Scheme (JCS)
3. RFC 3161 — Time-Stamp Protocol (TSP)
4. RFC 7914 — The scrypt Password-Based Key Derivation Function
5. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium3)
6. NIST FIPS 197 — Advanced Encryption Standard (AES)
7. NIST AI RMF 1.0 — Artificial Intelligence Risk Management Framework
8. EU AI Act — Regulation (EU) 2024/1689
9. GDPR — General Data Protection Regulation (EU) 2016/679
10. HIPAA — Health Insurance Portability and Accountability Act (US)
11. SEC Rule 17a-4 — Electronic Storage of Broker-Dealer Records
12. SOC2 — Service Organization Control 2 (AICPA)
13. ISO/IEC 27001:2022 — Information Security Management
14. ANSSI — Recommandations pour la sécurité des systèmes d'IA (2024)

---

**For implementation details:**
- GitHub: https://github.com/piqrypt/piqrypt
- Documentation: https://piqrypt.com/docs
- AISS Specification: https://github.com/piqrypt/aiss-spec

---

*PiQrypt Whitepaper v2.0.0 — March 2026*
*© 2026 PiQrypt — All Rights Reserved*
*e-Soleau DSO2026006483 + DSO2026009143 (INPI France)*
*Patent Pending*

*PiQrypt does not change how agents think.*
*It records — verifiably, portably, in compliance with EU AI Act — what they did, how they interacted, and whether a human approved it.*
*The trust layer for autonomous AI agents.*

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
