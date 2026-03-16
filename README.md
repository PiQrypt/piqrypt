# PiQrypt

**The trust and continuity layer for autonomous AI agents.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt?color=blue&label=PyPI)](https://pypi.org/project/piqrypt/)
[![Downloads](https://img.shields.io/pypi/dm/piqrypt)](https://pypi.org/project/piqrypt/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://pypi.org/project/piqrypt/)
[![License: MIT](https://img.shields.io/badge/AISS%20core-MIT-green)](LICENSE)
[![AISS](https://img.shields.io/badge/AISS-v2.0-orange)](https://aiss.org)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204-red)](https://csrc.nist.gov/pubs/fips/204/final)
[![e-Soleau INPI](https://img.shields.io/badge/e--Soleau-DSO2026006483-lightgrey)](https://www.inpi.fr)
[![AI Act](https://img.shields.io/badge/EU%20AI%20Act-Art.12%2F14-blue)](https://artificialintelligenceact.eu)

*Signed · Hash-chained · Timestamped · Observable · Governable*

---

## What is PiQrypt?

PiQrypt introduces a new primitive for AI systems:

Proof of Continuity.

TCP/IP → communication
TLS → encryption
OAuth → delegation
PCP → continuity

OAuth solved delegated authorization for web apps without sharing credentials.
No one asks why OAuth exists anymore — it is infrastructure.
PCP does the same for AI agent accountability: cryptographic continuity, offline,
cross-framework, legally admissible. The layer that was missing.

PiQrypt is a cryptographic identity, memory, and governance layer for autonomous AI agents.

It answers three questions regulators, auditors, and security teams are asking today:

- **Who acted?** — cryptographic identity per agent (Ed25519 / Dilithium3 NIST FIPS 204)
- **What happened?** — signed, hash-chained, tamper-evident event log
- **Should it have?** — real-time risk scoring (VRS) + governance and audit server (TrustGate)

PiQrypt is not a logging system. It is a **verifiable continuity layer** — records that can be independently verified without access to the original infrastructure, usable in regulatory audits and legal proceedings.

---

## Why this matters

Autonomous agents increasingly execute financial transactions, generate legally relevant content, coordinate with other agents without human review, and trigger downstream automated actions in critical systems.

Three regulatory frameworks are converging simultaneously:

| Framework | Key requirements |
|-----------|-----------------|
| **EU AI Act** | Art.12 (inviolable logs), Art.14 (human oversight mandatory), Art.9 (risk management) |
| **ANSSI 2024** | R25 (dangerous pattern filtering), R29 (audit trail), R30 (clearance-based access) |
| **NIST AI RMF 1.0** | GOVERN 1.2, MANAGE 2.2, MEASURE 2.5, AI 600-1 (agentic AI supervision) |

Autonomous AI agents are making decisions that affect people, money, and legal outcomes —
without any infrastructure to prove who acted, when, and whether it was authorized.
That infrastructure did not exist. Until now.

Traditional logs are not designed for adversarial or legal scrutiny. PiQrypt addresses this gap.

---

## Architecture — Four layers

```
┌──────────────────────────────────────────────────────────┐
│  TrustGate  — Human oversight · Policy · Hash-chained audit │  Governance
├──────────────────────────────────────────────────────────┤
│  Vigil      — Real-time SOC dashboard · VRS · Alerts      │  Observability
├──────────────────────────────────────────────────────────┤
│  PiQrypt    — VRS scoring · .pqz certification · RFC 3161  │  Risk & Certification
├──────────────────────────────────────────────────────────┤
│  AISS       — Identity · Signed memory · A2C detection     │  (MIT) Fondation
└──────────────────────────────────────────────────────────┘
```

### AISS — Agent Identity & Security Substrate

Each agent gets a cryptographic identity and a signed, hash-linked event log.

```
[genesis] → [event 1] → [event 2] → [event 3]
    │           │           │           │
 Ed25519     Ed25519     Ed25519     Ed25519
 prev_hash   prev_hash   prev_hash   prev_hash
```

Two signature tiers:

| Tier | Algorithm | Quantum-resistant | Availability |
|------|-----------|:-----------------:|-------------|
| **STANDARD** (default) | Ed25519 (RFC 8032) | ❌ | All tiers |
| **QUANTUM** | Dilithium3 (NIST FIPS 204) | ✅ | Pro+ |

> Ed25519 (STANDARD) is **not** post-quantum resistant. For quantum resilience,
> use `pip install piqrypt[post-quantum]` (Pro tier and above).

**AISS works with no bridge.** Two lines of Python — `stamp_event()` + `store_event()` — implement the full protocol. Bridges (LangChain, AutoGen, CrewAI, ROS2, RPi) are optional adapters that handle the wiring for your specific framework. The protocol is the same regardless of the framework above it.

### VRS — Vulnerability & Risk Score

Composite real-time risk score [0.0 → 1.0] from four weighted components:

| Component | Weight | What it measures |
|-----------|--------|-----------------|
| TSI | 35% | Trust Score Instability — drift in inter-agent relationships |
| Trust Score | 20% | Concentration, volume, frequency anomalies |
| A2C | 30% | 4 patterns: concentration, entropy drop, synchronisation, silence break |
| Chain | 15% | Cryptographic integrity of the identity chain |

### TrustGate — Governance & Audit

TrustGate evaluates actions and issues authoritative decisions; enforcement is at the application layer.

It is not inline middleware. The AISS bridge always records events unconditionally. Vigil computes the VRS from those events and pushes agent state to TrustGate. TrustGate runs the policy engine and returns a decision. The calling application reads `"blocked": true/false` and acts accordingly.

Key features:

- **Deterministic policy engine** — 10-priority rules, same input → same output. Full compliance mapping: ANSSI R9/R25/R27/R28, EU AI Act Art.14, NIST MANAGE 2.2
- **Six decision outcomes** — `ALLOW`, `ALLOW_WITH_LOG`, `REQUIRE_HUMAN`, `RESTRICTED`, `BLOCK`, `QUARANTINE`
- **REQUIRE_HUMAN queue** — TTL-based decisions, human principal clearance levels (L1–L3), approve/reject with mandatory justification
- **Hash-chained audit journal** — every evaluation is logged, append-only, tamper-evident, verifiable without the live system
- **Proof of disobedience** — if an agent continues acting after a BLOCK decision, two independent signed records (TrustGate audit journal + AISS chain) provide legally admissible evidence of the violation
- **Three compliance profiles** out of the box — `ai_act_high_risk.yaml`, `anssi_strict.yaml`, `nist_balanced.yaml`
- **Simulation mode** — test policy changes before activation (`POST /api/policy/simulate`)

---

## Quick Start

```bash
pip install piqrypt
```

### Launch the stack

```powershell
# Production
.\start_free.ps1          # Free — Vigil dashboard, read+write (agents connect and send events, 2 bridges max)
.\start_pro.ps1           # Pro — Vigil full + exports + certified .pqz
.\start_team.ps1          # Team — Vigil + TrustGate (manual)
.\start_business.ps1      # Business/Enterprise — full stack

# Demos & development
.\demos\start_families.ps1   # Interactive menu — nexus / pixelflow / alphacore
.\demos\start_legacy.ps1     # 10 agents — trading / compliance / rogue
```

### Onboarding in 60 seconds

```
1. .\start_free.ps1                 # dashboard opens automatically
2. Click "+ NEW AGENT" in Vigil
3. Choose your bridge (CrewAI, LangChain, MCP, Ollama…)
4. Copy the generated snippet → paste into your agent code
5. Agent appears live in the network graph
```

### Python API

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

With post-quantum signatures (Pro+):

```bash
pip install piqrypt[post-quantum]
piqrypt license activate pk_pro_...
```

---

## Framework integrations

Bridges are framework-specific adapters. They connect the AISS protocol to your existing stack. The underlying protocol (identity, hash-linked chain, signatures) is identical across all frameworks — and available without any bridge via `aiss.stamp_event()` directly.

```bash
pip install piqrypt[langchain]   # LangChain
pip install piqrypt[crewai]      # CrewAI
pip install piqrypt[autogen]     # AutoGen
pip install piqrypt[mcp]         # Model Context Protocol
pip install piqrypt[ollama]      # Ollama
pip install piqrypt[all-bridges] # All frameworks
```

| Framework | Repo |
|-----------|------|
| LangChain | [piqrypt-langchain-integration](https://github.com/piqrypt/piqrypt-langchain-integration) |
| AutoGen | [piqrypt-autogen-integration](https://github.com/piqrypt/piqrypt-autogen-integration) |
| CrewAI | [piqrypt-crewai-integration](https://github.com/piqrypt/piqrypt-crewai-integration) |
| MCP | [piqrypt-mcp-integration](https://github.com/piqrypt/piqrypt-mcp-integration) |
| Ollama | [bridges/ollama](bridges/ollama/) |

**[→ Integration Guide](INTEGRATION.md)**

---

## Works with any agent — 1 line

> Add a cryptographic audit trail to any AI agent in under 5 minutes.
> One callback. No cloud. No code changes. No raw data stored —
> only signed, hash-chained evidence your auditors and regulators can verify.

| Framework | Minimum integration |
|-----------|---------------------|
| LangChain | `callbacks=[PiQryptCallbackHandler(identity=id)]` — 1 parameter |
| AutoGen | Rename `AssistantAgent` → `AuditedAssistant` — 1 class swap |
| CrewAI | Rename `Agent` → `AuditedAgent` — 1 class swap |
| Ollama | Swap `ollama.Client` → `AuditedOllama` — 1 import |
| Any Python | 2 lines around any decision point |
| REST / CLI | `@audit_endpoint("action_name")` decorator |

**Privacy by design:** raw prompts, model responses, and tool outputs are never stored — only their SHA-256 fingerprints. Structural, not configurable.

**Offline by default:** no third-party server receives any data. The `.pqz` audit archive is verifiable without access to the original infrastructure.

> When two AI agents interact, PiQrypt makes both sign the interaction.
> Cross-framework. Offline. The only system where "Agent B claimed it never talked
> to Agent A" is cryptographically impossible.

> PiQrypt doesn't just log what your agents did — it proves who authorized it,
> who blocked it, and who ignored the block. Deterministic policies. HITL queue.
> Hash-chained evidence. EU AI Act Art.14 compliance out of the box.

---

## Cross-framework trust — AgentSession

When agents from different frameworks collaborate, `AgentSession` records the full interaction as co-signed, independently verifiable chain entries — without a shared server.

```python
from bridges.session import AgentSession
import piqrypt as aiss

# Agents can be from any framework — LangChain, AutoGen, custom Python
# Each has its own independent Ed25519 keypair and AISS chain
planner_key,  planner_pub  = aiss.generate_keypair()  # e.g. a LangChain AgentExecutor
executor_key, executor_pub = aiss.generate_keypair()  # e.g. an AutoGen AssistantAgent
reviewer_key, reviewer_pub = aiss.generate_keypair()  # e.g. a custom Python script

session = AgentSession(agents=[
    {"name": "planner",  "agent_id": aiss.derive_agent_id(planner_pub),
     "private_key": planner_key,  "public_key": planner_pub},
    {"name": "executor", "agent_id": aiss.derive_agent_id(executor_pub),
     "private_key": executor_key, "public_key": executor_pub},
    {"name": "reviewer", "agent_id": aiss.derive_agent_id(reviewer_pub),
     "private_key": reviewer_key, "public_key": reviewer_pub},
])
session.start()
# → 3 co-signed handshakes recorded (N*(N-1)/2 pairs), one in each agent's chain

# Stamp cross-agent interactions — both chains updated simultaneously
session.stamp("planner",  "task_delegation", {"task": "analyze_portfolio"}, peer="executor")
session.stamp("executor", "task_completed",  {"result_hash": "…"},          peer="reviewer")
session.stamp("reviewer", "review_signed",   {"approved": True},            peer="planner")
```

What this produces for each interaction:

- Both agents' chains receive an event with the same `interaction_hash`
- The responder's event embeds the initiator's signature (`peer_signature` field)
- Neither agent can deny the interaction or repudiate their identity
- The full session is auditable cross-framework without a shared server

**[→ A2A Session Guide](docs/A2A_SESSION_GUIDE.md)** for setup, handshake details, and audit export.

---

## Pricing

| Tier | Agents | Events/month | Price (annual) | Key features |
|------|--------|-------------|----------------|-------------|
| **Free** | 3 | 10,000 | Free forever | AISS STANDARD, .pqz memory, Vigil read+write (2 bridges max) |
| **Pro** | 50 | 500,000 | €290–390/year | QUANTUM, TSA RFC 3161, .pqz CERTIFIED, Vigil full, TrustGate manual |
| **Startup** | 50 | 1,000,000 | €990/year | All Pro + team workspace |
| **Team** | 150 | 5,000,000 | €2,990/year | All Startup + priority support |
| **Business** | 500 | 20,000,000 | €14,990/year | All Team + TrustGate full, SIEM, multi-org |
| **Enterprise** | Unlimited | Unlimited | On request | All Business + SSO, on-premise, SLA, air-gap |

**[→ Full pricing & feature comparison](TIERS_PRICING.md)**  
**[→ Certification pricing (.pqz CERTIFIED)](CERTIFICATION_PRICING.md)**

---

## Standards implemented

| Standard | Purpose | Tier |
|----------|---------|------|
| Ed25519 (RFC 8032) | Agent signatures — STANDARD | All |
| Dilithium3 (NIST FIPS 204) | Post-quantum signatures — QUANTUM | Pro+ |
| SHA-256 (NIST FIPS 180-4) | Hash chains | All |
| AES-256-GCM (NIST FIPS 197) | Key encryption at rest | Pro+ |
| scrypt N=2¹⁷ (RFC 7914) | Key derivation | Pro+ |
| RFC 3161 | Trusted timestamps (TSA) | Pro+ |
| RFC 8785 | JSON canonicalization | All |

---

## Threat model

PiQrypt protects against post-event log modification, identity repudiation, timeline alteration (TSA-anchored), behavioural anomalies, and unsupervised critical actions (TrustGate).

PiQrypt does **not** protect against compromised private keys, malicious logic before stamping, or fully compromised hosts. See [SECURITY.md](SECURITY.md) for the complete threat model.

---

## Project status

| Component | Status | Distribution |
|-----------|--------|-------------|
| AISS core | ✅ Stable | `pip install piqrypt` |
| Framework bridges | ✅ Published | `pip install piqrypt[langchain]` etc. |
| Vigil dashboard | 🔶 Beta | Standalone — see [vigil/](vigil/) |
| TrustGate | 🔶 Beta | Standalone — see [trustgate/](trustgate/) |

**Version:** 1.7.1 · **Python:** 3.9–3.12 · **Platforms:** Linux, macOS, Windows

---

## Documentation

| | |
|---|---|
| 🚀 Quick Start | [QUICK-START.md](QUICK-START.md) |
| 🔌 Integration Guide | [INTEGRATION.md](INTEGRATION.md) |
| 💰 Pricing | [TIERS_PRICING.md](TIERS_PRICING.md) |
| 🏅 Certification | [CERTIFICATION_PRICING.md](CERTIFICATION_PRICING.md) |
| 📐 AISS Specification | [docs/RFC_AISS_v2.0.md](docs/RFC_AISS_v2.0.md) |
| 📊 Trust Scoring | [docs/TRUST_SCORING_Technical_v2.1.md](docs/TRUST_SCORING_Technical_v2.1.md) |
| 🤝 A2A Handshake | [docs/A2A_HANDSHAKE_GUIDE.md](docs/A2A_HANDSHAKE_GUIDE.md) |
| 🔗 A2A Session Guide | [docs/A2A_SESSION_GUIDE.md](docs/A2A_SESSION_GUIDE.md) |
| 🔒 Security Policy | [SECURITY.md](SECURITY.md) |
| 🖥️ CLI Reference | `piqrypt --help` |

---

## License

**AISS spec & bridges:** MIT / Apache-2.0 — see [LICENSE](LICENSE)  
**PiQrypt Core, Vigil, TrustGate:** Elastic License 2.0 (ELv2) — see [LICENSE-SCHEMA.md](LICENSE-SCHEMA.md)  
**Commercial use (hosted/managed service):** [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md) — contact@piqrypt.com

**IP:** e-Soleau DSO2026006483 (19/02/2026) · DSO2026009143 (12/03/2026)  
**Contact:** contact@piqrypt.com · **Security:** security@piqrypt.com

---

*PiQrypt does not change how agents think.*  
*It records — verifiably, portably, in compliance with EU AI Act — what they did, how they interacted, and whether a human approved it.*  
*The trust layer for autonomous AI agents.*
