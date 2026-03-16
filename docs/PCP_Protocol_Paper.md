# PCP — Proof of Continuity Protocol
## Protocol Paper v1.0

```
Status:     Protocol Definition — Public Release
Version:    1.0.0
Date:       March 2026
Authors:    PiQrypt
Reference implementation: https://github.com/piqrypt/piqrypt
Contact:    contact@piqrypt.com
IP:         e-Soleau DSO2026006483 + DSO2026009143 (INPI France)
```

---

## Abstract

Digital infrastructure has been built in layers.

Each layer solved a fundamental problem of its era, and in doing so, made the next layer possible. TCP/IP made communication reliable. TLS made it secure. OAuth made it delegable.

Each protocol introduced a new primitive — a concept so foundational that once established, it became invisible infrastructure.

**A primitive is missing.**

Autonomous AI agents are operating today at scale. They execute financial transactions, coordinate with other agents, and trigger cascading actions across critical systems — often without human review. But there is no protocol that records what they did, in what order, under whose authority, and whether their behaviour remained coherent.

The **Proof of Continuity Protocol (PCP)** introduces this missing primitive: **verifiable continuity**.

PCP enables any autonomous agent to maintain a portable, cryptographically verifiable memory of its decisions, interactions, and governance state — independently auditable by any third party, without access to the original infrastructure.

PiQrypt is the reference implementation of PCP.

---

## Table of Contents

```
1.  The Infrastructure Gap
2.  A Brief History of Protocol Primitives
3.  The Continuity Problem
4.  PCP — Four Primitives
5.  The Four-Layer Stack
6.  Layer 1 — AISS: Identity Continuity
7.  Layer 2 — PiQrypt Core: Memory Continuity
8.  Layer 3 — Vigil: Behavioural Continuity
9.  Layer 4 — TrustGate: Governance Continuity
10. Proof of Agent Continuity (PAC)
11. The Regulatory Imperative
12. Comparison with Existing Approaches
13. Protocol Interoperability
14. Real-World Applications
15. The Internet of Accountable Agents
16. Implementation Status
17. Conclusion
```

---

## 1. The Infrastructure Gap

Something fundamental is missing from the AI stack.

Look at how an autonomous agent operates today:

```
    Model Layer        GPT-4o, Claude, Llama, Mistral
         ↓
    Inference API      OpenAI, Anthropic, Ollama
         ↓
    Agent Framework    LangChain, CrewAI, AutoGen, MCP
         ↓
    Application        trading bot, medical copilot, robot, pipeline
         ↓
    Storage            logs, databases, S3 buckets
```

This stack is capable. It can reason, plan, use tools, coordinate with other agents, and act in the world with increasing sophistication.

But it has no memory in the cryptographic sense. No layer in this stack answers the questions that matter when something goes wrong — or when an auditor, a regulator, or a court asks:

> *Who acted? What did they decide? In what order? Under whose authority? Did their behaviour deviate from the established pattern? Was a human in the loop?*

These are not edge-case questions. They are the minimum required for accountability. And there is no protocol today that addresses them systematically, portably, and in a manner that survives the passage of time.

**This is the infrastructure gap PCP fills.**

---

## 2. A Brief History of Protocol Primitives

Understanding why PCP matters requires understanding how Internet infrastructure has evolved.

Each foundational protocol solved a specific problem that could not be solved by the layers beneath it. And each introduced a new primitive that became the foundation for everything above.

### 2.1 The Protocol Stack

| Era | Protocol | Problem Solved | Primitive Introduced |
|-----|----------|---------------|---------------------|
| 1970s | **TCP/IP** | Machines could not communicate reliably across networks | *Addressable, reliable data transport* |
| 1990s | **HTTP** | There was no standard way to exchange documents on the network | *Stateless document exchange* |
| 1990s | **TLS** | Exchanges were visible and unverifiable in transit | *Encrypted, authenticated transport* |
| 2000s | **SMTP/DKIM** | Email origin could not be verified | *Authenticated message provenance* |
| 2010s | **OAuth 2.0** | Users could not safely delegate access to their resources | *Delegated, scoped authorisation* |
| 2010s | **JWT / OIDC** | Web services could not verify identity without a central authority | *Portable, verifiable identity claims* |
| 2020s | **MCP** | AI models had no standard interface to tools and context | *Structured tool interaction for agents* |
| **2026** | **PCP** | **Autonomous agents have no verifiable, portable decision memory** | ***Verifiable continuity*** |

### 2.2 The Pattern

Every protocol in this table was, at the time of its introduction, solving a problem that seemed niche or premature. TLS was considered overkill for most web traffic in 1995. OAuth seemed over-engineered when most APIs used basic authentication.

In each case, the protocol became essential infrastructure within a decade — because the problem it solved was not niche. It was structural. It would only grow more urgent as the systems above it matured.

PCP occupies the same position today. The problem it solves — *accountability for autonomous agent behaviour* — is structural. It will only grow more urgent as autonomous systems proliferate.

### 2.3 What Makes a Primitive

A protocol primitive has three characteristics:

**It solves a problem no other layer solves.** TLS does not replace TCP. It solves something TCP cannot. Similarly, PCP does not replace OAuth or AISS identity. It solves something they cannot: the continuity of behaviour over time.

**It is independent of the layer above it.** PCP works regardless of which model, which framework, or which application uses it. A LangChain agent and a ROS2 robot can both produce PCP-compliant records. The records are interoperable.

**It becomes invisible when it works.** You do not think about TCP when loading a webpage. You will not think about PCP when an agent executes — but when an auditor or regulator asks for the decision trail, it will be there, intact, independently verifiable.

---

## 3. The Continuity Problem

### 3.1 What Continuity Means

*Identity* answers: **who is this entity?**

*Transactions* answer: **what was exchanged?**

*Continuity* answers: **what did this entity do, in what order, and did it remain coherent throughout?**

This is a different question. It is a question about *behaviour over time* — not about a single moment, but about a trajectory.

Consider what happens when an autonomous trading agent executes a sequence of decisions over eight hours. Each individual decision may be logged. But:

- Are the logs tamper-proof?
- Can anyone verify that no log was deleted or reordered?
- Is there a record of which agent, with which identity, made each decision?
- Is there a record of interactions with other agents or external systems?
- Was there any drift in behaviour — and if so, was it detected?
- Was a human notified before any critical threshold was crossed?

Traditional infrastructure answers none of these questions reliably. PCP answers all of them.

### 3.2 Why Traditional Logs Fail

Standard logging infrastructure was designed for debugging and operations monitoring, not for adversarial scrutiny.

| Limitation | Description | PCP response |
|------------|-------------|-------------|
| **Tampering** | Logs can be modified, deleted, or reordered | Hash-chained signed events — any modification breaks the chain |
| **No identity binding** | Logs record system events, not agent decisions | Every event is signed by the agent's cryptographic private key |
| **No portability** | Logs are siloed in the producing system | `.pqz` bundles are self-contained and independently verifiable |
| **No temporal anchoring** | Log timestamps are internal and unverifiable | RFC 3161 trusted timestamping (TSA) — external, legally admissible |
| **No interaction record** | Inter-agent interactions are not captured jointly | A2A co-signed handshakes — both parties record the same event |
| **No behavioural baseline** | There is no mechanism to detect drift over time | Vigil TSI and VRS — continuous behavioural monitoring |
| **No human oversight trail** | Human approvals are not recorded in the decision chain | TrustGate decisions are signed events in the chain |

### 3.3 The Accountability Vacuum

As autonomous agents take on more consequential roles, the accountability vacuum becomes costly:

- A medical AI recommends a treatment. The outcome is contested. The decision trail cannot be independently verified.
- An algorithmic trading system executes a sequence of orders that contributes to a flash crash. The regulator requests the decision log. It was overwritten.
- Three autonomous agents coordinate on a task. Something goes wrong. No one can determine which agent made which decision, in what order, based on what information.
- A critical infrastructure system acts autonomously. The action triggers a cascade. There is no human-readable, cryptographically verifiable record of what happened.

These are not hypothetical scenarios. They are happening now, with systems that will become far more capable and autonomous within the current decade.

PCP exists to make them impossible to deny and possible to audit.

---

## 4. PCP — Four Primitives

PCP introduces **four new primitives** that together establish verifiable continuity for autonomous agents.

### 4.1 Identity Continuity

> *An agent must remain the same verifiable entity across time, restarts, migrations, and model upgrades.*

An autonomous agent without persistent cryptographic identity is an ephemeral process — indistinguishable from a new instance after each restart. Identity Continuity gives agents a stable anchor: a deterministic identifier derived from a public key, independent of infrastructure.

```
agent_id = BASE58( SHA256(public_key) )[0:32]
```

This identity cannot be claimed by another entity without the corresponding private key. It survives infrastructure changes. It is the foundation on which all continuity is built.

**Implemented by: AISS (Layer 1)**

### 4.2 Memory Continuity

> *An agent's decision history must form a tamper-evident, chronologically ordered, independently verifiable record.*

Every decision produces a signed event. Every event references the hash of the preceding event. The resulting chain has a critical property: if any event is modified, inserted, or deleted, the chain breaks — detectably, irreversibly.

```
[genesis] ──→ [event 1] ──→ [event 2] ──→ [event 3]
  Sign(k)      Sign(k)       Sign(k)       Sign(k)
  h₀           h₁=H(e₀)     h₂=H(e₁)     h₃=H(e₂)
```

This is the agent's memory. It is not a log. It is a cryptographic structure.

**Implemented by: PiQrypt Core (Layer 2)**

### 4.3 Behavioural Continuity

> *An agent's behaviour must be observable over time — and deviations from established patterns must be detectable before they become incidents.*

An agent can have a perfect identity and an intact chain, and still be behaving anomalously. Behavioural Continuity adds a temporal dimension: continuous monitoring of behavioural patterns, with composite risk scoring and anomaly detection.

This is not binary. It is not *"the chain is valid or invalid"*. It is a continuous signal: is this agent behaving consistently with its history? Are there signs of drift, collusion, or coordination with external systems?

**Implemented by: Vigil (Layer 3)**

### 4.4 Governance Continuity

> *Critical agent actions must be subject to policy evaluation, and every governance decision must be recorded as an immutable part of the agent's chain.*

The governance record is not separate from the action record. In PCP, every TrustGate decision — ALLOW, DENY, AUDIT, ESCALATE — is itself a signed event appended to the agent's chain. The governance and the action are cryptographically inseparable.

This means: a DENY that was later overridden leaves a trace. A forced ALLOW outside policy leaves a trace. Governance cannot be silently bypassed.

**Implemented by: TrustGate (Layer 4)**

---

## 5. The Four-Layer Stack

PCP is implemented as a vertical stack. Each layer depends on the one below it, and contributes a distinct form of continuity.

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   TRUSTGATE          Governance Continuity                  │
│   Policy · Human oversight · Signed decisions               │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   VIGIL              Behavioural Continuity                 │
│   TSI · VRS · A2C · Network graph · Risk narrative          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   PIQRYPT CORE       Memory Continuity                      │
│   Hash chains · Fork detection · TSA · .pqz certification   │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   AISS               Identity Continuity                    │
│   Deterministic ID · Ed25519 · Dilithium3 · A2A handshake   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

The stack sits **between** the agent framework and storage:

```
    Agent Frameworks  (LangChain · CrewAI · AutoGen · MCP · ROS2)
              ↓
    ┌─────────────────────┐
    │     PCP STACK       │   ← This layer did not exist before
    └─────────────────────┘
              ↓
    Storage   (local · cloud · encrypted · .pqz)
```

PCP does not replace any existing layer. It adds the trust infrastructure that was missing.

---

## 6. Layer 1 — AISS: Identity Continuity

The Agent Identity and Signature Standard (AISS) is the cryptographic foundation of PCP. It is open-source under the MIT licence.

### 6.1 Deterministic Identity

An agent's identity is derived deterministically from its public key:

```
agent_id = BASE58( SHA256(public_key_bytes) )[0:32]
```

This identity is:

- **Self-sovereign** — no central authority issues or controls it
- **Portable** — survives restarts, migrations, model upgrades
- **Stable** — the same keypair always produces the same identity
- **Cryptographically bound** — impossible to claim without the private key

### 6.2 Two Signature Tiers

AISS defines two signature profiles to accommodate different threat horizons:

| Profile | Algorithm | Quantum-resistant | Use case |
|---------|-----------|:-----------------:|----------|
| **AISS-1** | Ed25519 (RFC 8032) | ✗ | Development, low-risk agents |
| **AISS-2** | ML-DSA-65 + Ed25519 hybrid (NIST FIPS 204) | ✅ | Finance, healthcare, government, high-risk AI |

The quantum threat to Ed25519 is real but not imminent — credible estimates place it at 2035+. AISS-2 provides a hybrid signature that is valid under both classical and post-quantum verification, ensuring archives created today remain valid indefinitely.

### 6.3 Agent-to-Agent Protocol

When two AISS-equipped agents interact, they execute a three-step signed handshake:

```
Agent A                          Agent B
  │
  │── identity_proposal ────────→
  │← identity_response ──────────│
  │── session_confirm ───────────→
  │
  Both agents append co-signed handshake event to their own chains.
  Neither party can deny the interaction occurred.
```

The co-signed event is the bilateral interaction record. It cannot be removed from either chain without breaking chain integrity.

### 6.4 External Peer Observation

A critical PCP capability: when a monitored agent interacts with a system that is not equipped with AISS, PCP records the interaction **unilaterally**. The external system has no knowledge of PiQrypt.

This enables monitoring of real-world production interactions — Binance WebSocket feeds, Anthropic API calls, GitHub webhooks, Bloomberg Terminal — without requiring those systems to adopt PCP.

---

## 7. Layer 2 — PiQrypt Core: Memory Continuity

PiQrypt Core is the continuity engine. It transforms AISS-signed events into a tamper-evident, auditable memory structure.

### 7.1 The Continuity Chain

Every agent action produces a signed event. Every event is linked to the one before it by hash:

```json
{
  "version":       "AISS-1.0",
  "agent_id":      "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "timestamp":     1739382400,
  "nonce":         "550e8400-e29b-41d4-a716-446655440000",
  "previous_hash": "a3f7e8c9d1b2a4f6e8c0d2b4a6f8e0c2",
  "payload":       { "event_type": "trade_executed", "symbol": "AAPL", "quantity": 100 },
  "signature":     "base64:3k9XmL4nP8qR9sT0uV1wX2yZ..."
}
```

The chain property: modifying any event changes its hash, which invalidates the `previous_hash` of every subsequent event. The break is instantaneous and detectable from any point in the chain.

### 7.2 Fork Detection

A fork occurs when two events share the same `previous_hash` — two claimed histories from the same point. This is the signature of a compromise attempt or a synchronisation failure:

```
Event 0 → Event 1 ──┬──→ Event 2a   ← Branch A
                    └──→ Event 2b   ← Branch B — FORK: CRITICAL alert
```

PCP's Canonical History Rule resolves forks deterministically, prioritising TSA-anchored branches, then chronological order, then chain length. All conforming implementations reach the same resolution.

### 7.3 RFC 3161 Timestamping

Events can be anchored to an external Time Stamping Authority (RFC 3161 TSP), producing a legally admissible timestamp independent of PiQrypt infrastructure. This anchoring has two effects:

- It proves the event existed at a specific time, verifiable by any third party
- It finalises the event — a fork after a finalised event is classified as a compromise attempt

### 7.4 The .pqz Bundle

The `.pqz` format is PCP's portable audit artefact — a self-contained, independently verifiable package containing the complete decision trail:

| Component | Content |
|-----------|---------|
| `events.json` | Full signed event chain |
| `identity.json` | Agent identity document |
| `chain_hash.txt` | SHA-256 of the full chain |
| `signature.ed25519` | Ed25519 signature |
| `signature.mldsa65` | ML-DSA-65 signature (Pro+) |
| `tsa_token.tsr` | RFC 3161 TSA token (Pro+) |
| `certificate.pdf` | Human-readable audit certificate (Pro+) |

A `.pqz` bundle can be verified offline, by any third party, without access to PiQrypt infrastructure.

---

## 8. Layer 3 — Vigil: Behavioural Continuity

An intact chain proves the record was not tampered with. It does not prove the agent behaved consistently. Vigil provides the second signal: continuous behavioural monitoring.

### 8.1 The Trust State Index (TSI)

The TSI tracks behavioural stability over a 24-hour sliding window:

| State | Condition | Meaning |
|-------|-----------|---------|
| `STABLE` | No significant drift | Agent behaving consistently |
| `WATCH` | Mild drift detected | Early warning — monitoring increased |
| `UNSTABLE` | Significant deviation | Anomalous — human review recommended |
| `CRITICAL` | Unstable > 48h | High risk — TrustGate escalation triggered |

### 8.2 The Vigil Risk Score (VRS)

The VRS is a composite real-time risk signal in [0.0 → 1.0], recomputed on every event:

```
VRS = 0.30 × TSI_weight
    + 0.35 × (1 − TrustScore)
    + 0.20 × A2C_risk
    + 0.15 × ChainIssueScore
```

| VRS | State | Action |
|-----|-------|--------|
| 0.00 – 0.25 | `SAFE` | Normal operation |
| 0.25 – 0.50 | `WATCH` | Alert logged |
| 0.50 – 0.75 | `ALERT` | High alert · TrustGate AUDIT |
| 0.75 – 1.00 | `CRITICAL` | TrustGate ESCALATE |

### 8.3 A2C — Relational Anomaly Detection

The A2C detector evaluates interactions across the agent network, looking for four structural anomaly patterns:

| Pattern | What it detects |
|---------|----------------|
| **Concentration** | Over-reliance on a single peer (>80% of interactions) |
| **Entropy drop** | Sudden loss of interaction diversity |
| **Synchronisation** | Multiple agents acting in tight temporal lock-step |
| **Silence break** | Abnormal burst following extended inactivity |

A2C evaluates both agent-to-agent interactions and agent-to-external-service interactions — including interactions with systems not equipped with PCP.

### 8.4 The Network Graph

Vigil renders a real-time network graph of agent interactions. Internal agents occupy an inner ring. External systems — Binance, Anthropic API, GitHub, Bloomberg — occupy an outer ring, visible even though they are not PCP-equipped.

This graph is the visual representation of Memory Continuity and Behavioural Continuity together: *who interacted with whom, how often, at what latency, and whether the pattern is anomalous*.

---

## 9. Layer 4 — TrustGate: Governance Continuity

TrustGate is the governance layer — the enforcement point between observation and action.

### 9.1 The Governance Invariant

The defining property of TrustGate in PCP is not the policy evaluation itself — any policy engine can evaluate a rule. The defining property is this:

> **Every TrustGate decision is a signed event in the agent's chain.**

ALLOW, DENY, AUDIT, ESCALATE — each decision is cryptographically appended to the same chain that records the agent's actions. The governance record is not separate from the action record. They are the same structure.

This means governance cannot be silently bypassed. A DENY cannot be removed from the chain. An ESCALATE that timed out and became a DENY is recorded. A human approval is recorded with a timestamp.

### 9.2 The Four Outcomes

| Outcome | Meaning | What gets recorded |
|---------|---------|-------------------|
| `ALLOW` | Policy compliant — proceed | Signed `trustgate_allow` event |
| `DENY` | Policy violation — blocked | Signed `trustgate_deny` event with reason |
| `AUDIT` | Allowed but flagged | Signed `trustgate_audit` event |
| `ESCALATE` | Human must approve before execution | Signed `trustgate_escalate` event; execution paused |

### 9.3 The ESCALATE Mechanism

When VRS exceeds the critical threshold for a given event type, execution pauses:

```
Agent proposes action
        ↓
TrustGate: ESCALATE
        ↓
Signed escalate event appended to chain
        ↓
Human operator notified (Slack / email / webhook)
        ↓
        ├── Human approves → signed trustgate_human_allow → execution resumes
        └── TTL expires (default 300s) → signed trustgate_deny → blocked
```

The default on timeout is DENY. This is the **fail-safe** principle: in the absence of explicit human approval, high-risk actions do not proceed.

### 9.4 Compliance Alignment

TrustGate is the direct technical implementation of human oversight mandates:

| Regulation | Requirement | TrustGate response |
|------------|-------------|-------------------|
| EU AI Act Art. 14 | Human oversight mandatory for high-risk AI systems | ESCALATE with TTL · fail-safe DENY |
| EU AI Act Art. 12 | Inviolable logging of high-risk AI decisions | Every decision is a signed chain event |
| NIST AI RMF GOVERN 1.2 | Governance mechanisms for AI systems | Configurable policy profiles per agent |
| ANSSI 2024 R30 | Clearance-based access control for AI actions | ALLOW/DENY per policy profile |

---

## 10. Proof of Agent Continuity (PAC)

The four layers together establish **Proof of Agent Continuity** — the aggregate property that PCP provides.

```
PAC = Identity Continuity         (AISS)
    + Memory Continuity           (PiQrypt Core)
    + Behavioural Continuity      (Vigil)
    + Governance Continuity       (TrustGate)
```

A valid PAC record answers — for any agent, at any point in time — the five questions that accountability requires:

| Question | Answered by |
|----------|------------|
| **Who acted?** | AISS — deterministic cryptographic identity |
| **What did they decide?** | PiQrypt Core — signed, tamper-evident event chain |
| **In what order?** | PiQrypt Core — hash-chained chronological sequence |
| **Did their behaviour remain coherent?** | Vigil — continuous TSI/VRS/A2C monitoring |
| **Was a human in the loop?** | TrustGate — signed governance decisions in chain |

PAC does not verify the *correctness* of decisions. It verifies their *attributability*, *integrity*, *coherence*, and *governance*. These are the properties required for accountability — and they were previously unavailable as a unified, portable, independently verifiable record.

---

## 11. The Regulatory Imperative

PCP is not a speculative protocol. It addresses obligations that are entering into force now.

### 11.1 EU AI Act — Enforcement Timeline

The EU AI Act (Regulation 2024/1689) is in force. Its high-risk AI provisions — including the logging and human oversight requirements most relevant to PCP — apply from August 2026.

| Article | Requirement | PCP Layer |
|---------|-------------|-----------|
| Art. 9 | Risk management system — documented, monitored, updated | Vigil VRS |
| Art. 12 | Automatic logging — inviolable, tamper-evident, retained | PiQrypt Core |
| Art. 13 | Transparency — decisions explainable to users | Signed payload |
| Art. 14 | Human oversight — ability to intervene, override, stop | TrustGate |
| Art. 17 | Quality management — documented processes and controls | RFC AISS v2.0 |

Operators of high-risk AI systems who cannot produce a compliant audit trail under Art. 12 face penalties of up to €30M or 6% of global annual turnover.

**PCP is compliance infrastructure.**

### 11.2 NIST AI RMF 1.0

The NIST AI Risk Management Framework, widely adopted in the United States and referenced globally, defines four functions: GOVERN, MAP, MEASURE, MANAGE.

| NIST Control | Description | PCP Layer |
|-------------|-------------|-----------|
| GOVERN 1.2 | AI risk governance — policies and accountability mechanisms | TrustGate policy profiles |
| MANAGE 2.2 | Risk treatment — documented responses to identified AI risks | TrustGate DENY/ESCALATE |
| MEASURE 2.5 | Continuous monitoring — metrics for AI system behaviour | Vigil TSI, VRS, A2C |
| AI 600-1 | Agentic AI — supervision mechanisms for autonomous systems | Full PCP stack |

### 11.3 ANSSI 2024

France's national cybersecurity agency (ANSSI) published AI security recommendations in 2024 that directly map to PCP capabilities:

| Recommendation | Requirement | PCP Layer |
|---------------|-------------|-----------|
| R25 | Dangerous pattern filtering before execution | TrustGate DENY |
| R29 | Audit trail — complete, tamper-evident | PiQrypt Core |
| R30 | Clearance-based access control | TrustGate ALLOW/DENY per policy |

### 11.4 The Window

Three major regulatory frameworks are converging simultaneously in 2026. The organisations that deploy PCP now — or build on PCP-compliant infrastructure — will have a compliance artefact that satisfies all three. Those that do not will be retrofitting accountability into systems that were not designed for it.

Retrofitting accountability is harder than building it in. TLS is not retrofitted on top of an insecure protocol. It is the protocol. PCP is the same category of infrastructure.

---

## 12. Comparison with Existing Approaches

### 12.1 What PCP Is Not

It is useful to define what PCP is not, because the space is crowded with partial solutions.

**PCP is not an audit logging system.** Systems like Splunk, Datadog, or CloudWatch record events. They do not sign them. They do not chain them. They cannot prove to a third party that a log was not modified. They have no mechanism to detect drift in agent behaviour over time.

**PCP is not a blockchain.** Blockchain provides distributed consensus for transactions between distrusting parties. PCP provides continuity for the internal decision history of an agent. Blockchains are expensive, slow, and require global consensus for what is fundamentally a local record. PCP runs with <10ms overhead per event, offline, without network access.

**PCP is not an identity system.** PKI, SPIFFE/SPIRE, and OpenID Connect solve identity. PCP extends identity with continuity. An agent can have a valid X.509 certificate and still have no verifiable decision history.

**PCP is not a model governance framework.** MLflow, W&B, and model cards document model lineage and training. PCP documents agent runtime behaviour. These are complementary.

### 12.2 Positioning Matrix

| System | Identity | Event Integrity | Behavioural Monitoring | Human Oversight Trail | Portable Audit |
|--------|:--------:|:---------------:|:---------------------:|:--------------------:|:--------------:|
| PKI/X.509 | ✅ | ✗ | ✗ | ✗ | ✗ |
| Blockchain | Partial | ✅ | ✗ | ✗ | Partial |
| Splunk/Datadog | ✗ | ✗ | Partial | ✗ | ✗ |
| MLflow/W&B | ✗ | Partial | ✗ | ✗ | Partial |
| OpenTelemetry | ✗ | ✗ | Partial | ✗ | ✗ |
| **PCP / PiQrypt** | **✅** | **✅** | **✅** | **✅** | **✅** |

No existing system combines all five properties. PCP is designed specifically to provide all five, in a unified protocol that adds <10ms overhead per event.

---

## 13. Protocol Interoperability

PCP is designed to compose with existing protocols, not replace them.

### 13.1 Relationship to Transport Protocols

PCP is transport-independent. PCP records can be transmitted over any transport layer — HTTP, MQTT, gRPC, stdio — without modification. The cryptographic guarantees are in the record structure, not in the transmission channel.

TLS secures the channel. PCP secures the record. Both are needed.

### 13.2 Relationship to Identity Protocols

AISS identities can coexist with X.509 certificates, SPIFFE SVIDs, or OpenID Connect tokens. An agent can hold both an X.509 certificate (for TLS mutual authentication) and an AISS identity (for continuity chain attribution).

These identities serve different purposes. X.509 proves an agent is authorised to communicate. AISS proves an agent is the one that made specific decisions.

### 13.3 Relationship to MCP

The Model Context Protocol (MCP) defines a standard interface between AI models and tools. PCP's MCP bridge wraps MCP tool calls and records each invocation as a signed PCP event — without modifying the MCP protocol itself.

From MCP's perspective, PiQrypt is invisible. From PCP's perspective, every MCP tool call is a stamped, hash-linked event in the agent's continuity chain.

### 13.4 Relationship to A2A Protocol

Google's A2A (Agent-to-Agent) Protocol defines a communication standard for agents. PCP's A2A layer provides the trust substrate for A2A interactions: co-signed handshakes, bilateral interaction records, and VRS monitoring of interaction patterns.

A2A defines *how* agents communicate. PCP defines *what is provably recorded* from that communication.

---

## 14. Real-World Applications

### 14.1 Finance — Algorithmic Trading

An autonomous trading system executes thousands of decisions per day. Regulators (MiFID II, SEC Rule 17a-4, FINRA) require that decision records be retained for seven years and be producible on demand.

With PCP:
- Every trading signal, order, and justification is signed by the agent's private key
- The decision trail is hash-chained — reordering or deletion is cryptographically detectable
- RFC 3161 timestamps anchor the trail to an external, legally admissible time source
- `.pqz` bundles are self-contained and verifiable without access to the trading system
- Vigil detects unusual coordination between trading agents before orders are submitted

### 14.2 Healthcare — AI Diagnostics

An AI system recommends a treatment. The recommendation is contested. The patient's legal team requests the complete decision trail.

With PCP:
- The model version, input hash, reasoning chain, and recommendation are all signed events
- The trail is independently verifiable without access to the hospital's infrastructure
- The human oversight record (TrustGate ALLOW/ESCALATE) is part of the same chain
- GDPR compliance: only hashes of personal data are stored in the chain; raw data remains in encrypted off-chain storage

### 14.3 Robotics — Autonomous Operations

A ROS2 robot performs an operation on a critical assembly line. An incident occurs. The manufacturer's liability depends on whether the robot behaved within specification.

With PCP:
- Every lifecycle transition (`configure → activate → deactivate → shutdown`) is stamped
- Every sensor reading, decision, and actuator command is a signed chain event
- The trail survives the robot's hardware — it is portable and externally verifiable
- Fork detection identifies any attempt to reconstruct a different history post-incident

### 14.4 AI Infrastructure — Multi-Agent Pipelines

A pipeline of five agents — orchestrator, researcher, writer, reviewer, executor — produces a high-stakes output. One agent's contribution is disputed.

With PCP:
- Each agent maintains its own signed continuity chain
- Agent-to-agent handshakes are co-signed — both parties' chains record the interaction
- Vigil monitors the interaction network for collusion patterns or unexpected coordination
- The complete attribution graph — who instructed whom, when, in what order — is verifiable

---

## 15. The Internet of Accountable Agents

PCP is infrastructure. Infrastructure, by nature, is not the product — it is what makes products possible.

TCP/IP enabled the web, email, streaming, and every internet application that followed — not because it was designed for any of them, but because it established a reliable, universal communication primitive that any application could build on.

PCP establishes a reliable, universal **continuity primitive** that any autonomous agent can build on.

As the ecosystem matures, PCP enables a class of capabilities that are not possible without it:

**Agent reputation markets.** Agents with long, clean, independently verifiable continuity chains can demonstrate trustworthiness over time. This creates a foundation for agent reputation as a first-class asset.

**Agent-to-agent contracts.** When two agents interact with co-signed records in both chains, the interaction is bilaterally verifiable. This is the foundation for autonomous contractual commitments between agents.

**Regulatory-grade AI governance.** Operators of high-risk AI systems can produce, on demand, a complete, tamper-evident, externally verifiable record of every decision made by every agent in their system — without building bespoke audit infrastructure.

**Cross-organisation agent trust.** When organisations operate agents that interact — supply chains, financial networks, healthcare referral systems — PCP provides the shared trust substrate. Each organisation's agents maintain their own chains. Interactions are co-signed. No organisation needs to trust the other's infrastructure.

```
                   INTERNET OF ACCOUNTABLE AGENTS

    ┌──────────────────────────────────────────────────┐
    │              Applications                        │
    │  trading · diagnostics · robots · pipelines      │
    └──────────────────────────────────────────────────┘
                            │
    ┌──────────────────────────────────────────────────┐
    │           Agent Frameworks                       │
    │  LangChain · CrewAI · AutoGen · MCP · ROS2       │
    └──────────────────────────────────────────────────┘
                            │
    ┌──────────────────────────────────────────────────┐
    │          PCP — Trust Infrastructure              │
    │  Identity · Memory · Observation · Governance    │
    └──────────────────────────────────────────────────┘
                            │
    ┌──────────────────────────────────────────────────┐
    │          Network Infrastructure                  │
    │  TLS · TCP/IP · DNS · RFC 3161                   │
    └──────────────────────────────────────────────────┘
```

PCP occupies the same structural position in the AI agent stack that TLS occupies in the web stack. It is not an application. It is not a framework. It is the layer that makes the applications above it trustworthy.

---

## 16. Implementation Status

PCP's reference implementation is **PiQrypt v1.7.1**.

### 16.1 Protocol Coverage

| PCP Component | Status | Reference |
|---------------|--------|-----------|
| AISS-1 (Ed25519 + SHA-256 + RFC 8785) | ✅ Stable | `aiss/` |
| AISS-2 (ML-DSA-65 hybrid) | ✅ Stable (Pro+) | `aiss/` |
| Hash chain + fork detection | ✅ Stable | `aiss/chain.py`, `aiss/fork.py` |
| RFC 3161 TSA integration | ✅ Stable (Pro+) | `aiss/certification.py` |
| A2A handshake protocol | ✅ Stable | `aiss/a2a.py` |
| External peer observation | ✅ Stable | `aiss/anomaly_monitor.py` |
| .pqz certification bundle | ✅ Stable | `aiss/exports.py` |
| Vigil (TSI, VRS, A2C, network graph) | 🚀 Beta | `vigil/` |
| TrustGate (policy engine, ESCALATE) | 🚀 Beta | `trustgate/` |

### 16.2 Framework Bridges

PCP bridges are available for 9 agent frameworks:

| Framework | Bridge |
|-----------|--------|
| LangChain | `pip install piqrypt[langchain]` |
| CrewAI | `pip install piqrypt[crewai]` |
| AutoGen | `pip install piqrypt[autogen]` |
| Model Context Protocol | `pip install piqrypt[mcp]` |
| Ollama | `pip install piqrypt[ollama]` |
| ROS2 | `pip install piqrypt[ros2]` |
| Raspberry Pi | `pip install piqrypt[rpi]` |
| Session | `pip install piqrypt[session]` |
| OpenClaw | `pip install piqrypt[openclaw]` |

### 16.3 Test Coverage

| Category | Tests | Status |
|----------|-------|--------|
| Normative RFC test vectors | 71 | ✅ All passing |
| Security tests | 61 | ✅ All passing |
| Functional AISS | 193 | ✅ All passing |
| Infrastructure-dependent | 17 | ⚠️ Known failures (external cert, live server, Pro-tier) |
| **Total** | **325 + 17** | **325 passed** |

### 16.4 Quick Start

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
    private_key, agent_id,
    {"event_type": "trade_executed", "symbol": "AAPL", "quantity": 100}
)
aiss.store_event(event)

# Verify — raises InvalidChainError on any tampering
aiss.verify_chain([event])
```

Full protocol specification: [RFC AISS v2.0](https://github.com/piqrypt/aiss-spec)

---

## 17. Conclusion

The history of Internet infrastructure is a history of primitives arriving just as they became necessary.

TCP/IP arrived as the network was beginning to scale. TLS arrived as e-commerce was making unauthenticated HTTP untenable. OAuth arrived as the proliferation of web services made credential sharing unsustainable.

Each primitive seemed premature to some at the time of introduction. In retrospect, each arrived barely in time.

Autonomous agents are operating now, at scale, without accountability infrastructure. The EU AI Act's high-risk provisions come into force in August 2026. The NIST AI RMF is being adopted across regulated sectors. ANSSI's recommendations carry weight in European procurement.

The question is not whether accountability infrastructure for autonomous agents will be required. It will. The question is whether the systems being deployed today are building on a foundation that supports it — or whether accountability will need to be retrofitted into systems that were not designed for it.

**PCP is that foundation.**

It introduces a single new primitive — verifiable continuity — and implements it as a four-layer stack that adds under 10ms overhead per event, works offline, integrates with existing frameworks without code changes, produces independently verifiable audit artefacts, and satisfies the logging, monitoring, and human oversight requirements of the major regulatory frameworks simultaneously.

The Internet of Accountable Agents needs infrastructure. PCP is that infrastructure.

---

## References

1. RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
2. RFC 8785 — JSON Canonicalization Scheme (JCS)
3. RFC 3161 — Time-Stamp Protocol (TSP)
4. RFC 7914 — The scrypt Password-Based Key Derivation Function
5. RFC 4122 — A Universally Unique Identifier (UUID) URN Namespace
6. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
7. NIST AI RMF 1.0 — Artificial Intelligence Risk Management Framework
8. NIST AI 600-1 — Artificial Intelligence Risk Management: Generative AI
9. EU AI Act — Regulation (EU) 2024/1689, OJ L 2024/1689
10. ANSSI — Recommandations de sécurité pour les systèmes d'IA (2024)
11. GDPR — General Data Protection Regulation (EU) 2016/679
12. MiFID II — Directive 2014/65/EU (financial instruments)
13. SEC Rule 17a-4 — Electronic Storage of Broker-Dealer Records
14. HIPAA — Health Insurance Portability and Accountability Act (45 CFR Parts 160/164)

---

*PCP Protocol Paper v1.0 — March 2026*
*Reference implementation: https://github.com/piqrypt/piqrypt*
*Protocol specification: https://github.com/piqrypt/aiss-spec*
*© 2026 PiQrypt — e-Soleau DSO2026006483 (INPI France) + Addendum 2026*

---

> *PCP does not change how agents think.*
> *It establishes — cryptographically, portably, independently — what they did.*

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
