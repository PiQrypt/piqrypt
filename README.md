# PiQrypt

**Verifiable memory for AI agents.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt?color=blue&label=PyPI)](https://pypi.org/project/piqrypt/)
[![Downloads](https://img.shields.io/pypi/dm/piqrypt)](https://pypi.org/project/piqrypt/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://pypi.org/project/piqrypt/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![AISS](https://img.shields.io/badge/AISS-v1.1-orange)](https://github.com/piqrypt/aiss-spec)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204-red)](https://csrc.nist.gov/pubs/fips/204/final)
[![e-Soleau INPI](https://img.shields.io/badge/e--Soleau-DSO2026006483-lightgrey)](https://www.inpi.fr)

*Signed · Hash-chained · Timestamped · Portable*

---

PiQrypt provides a local-first memory layer for autonomous systems.
It records what agents did and how they interacted — in a way that is:

- Verifiable
- Tamper-evident
- Exportable
- Independently checkable

PiQrypt provides verifiable continuity of actions and interactions.
It is not designed to store or manage operational data such as documents, files, images, or datasets.
In most deployments, only structured metadata or content hashes are recorded.

It does not replace your logging system.
It adds a verifiable continuity layer over it.

---

## Why this matters

Autonomous systems are no longer experimental.

They increasingly:

- Execute financial transactions
- Generate legally relevant content
- Interact with customers
- Coordinate with other automated systems
- Trigger downstream automated actions

At the same time, regulatory frameworks are evolving.

Notably:

- AI Act (EU)
- General Data Protection Regulation (Article 22 — automated decision-making)
- U.S. Securities and Exchange Commission recordkeeping rules (e.g., Rule 17a-4)
- Sector-specific audit and traceability obligations

These frameworks increasingly require:

- Traceability of automated decisions
- Evidence of system integrity
- Reconstruction of timelines
- Accountability of system actors

Traditional logs are not designed for adversarial or legal scrutiny.
They can be modified, deleted, rewritten, or disputed.

PiQrypt addresses this gap by providing a verifiable memory layer
for agent actions and interactions.

---

## What PiQrypt provides

For each recorded event:

- Canonicalized representation
- Digital signature bound to agent identity
- Hash-linked continuity
- Optional trusted timestamp

The result is a portable audit history that can be stored locally,
encrypted, transported, submitted for review, and verified independently.

Verification does not require access to the original infrastructure.

---

## Architecture

PiQrypt defines three complementary memory layers.

### 1. Individual Memory

Each agent maintains a signed, hash-linked history of its actions.

```
[genesis] → [event 1] → [event 2] → [event 3]
    │           │           │           │
 signature   signature   signature   signature
 prev_hash   prev_hash   prev_hash   prev_hash
```

This creates tamper-evident continuity.
If an event is modified or removed, verification fails.

### 2. Interaction Memory (A2A)

When two agents interact, both sign the interaction.

```
  Agent A memory                    Agent B memory
  ──────────────────────            ──────────────────────
  a2a_handshake                     a2a_handshake
  peer_id:        B.agent_id        peer_id:        A.agent_id
  peer_signature: B.sig    ←───→   peer_signature: A.sig
  interaction_hash: c7d2            interaction_hash: c7d2
  signature: A.sig                  signature: B.sig
```

Both agents maintain independent but cryptographically correlated records.
Neither side can deny the interaction without cryptographic inconsistency.
This enables later reconstruction of who interacted, what was exchanged,
and in what order.

### 3. Session Memory

For multi-agent workflows, PiQrypt establishes co-signed handshakes
between all agent pairs before any action takes place.

```
  session.start()
      ├── LLM ↔ TradingBot      co-signed ✅
      ├── LLM ↔ OpenClaw        co-signed ✅
      └── TradingBot ↔ OpenClaw co-signed ✅

  During session — each agent keeps its own memory:
  ─────────────────────────────────────────────────
  LLM memory        "recommendation_sent"   interaction_hash: c7d2
  TradingBot memory "recommendation_rcvd"   interaction_hash: c7d2
                                                     ↑
                                           same hash · both signed
```

Session memory provides structural continuity across multiple actors.
Complex pipelines — LLM → Tool → Executor, Agent → Agent → External system —
can be fully reconstructed after the fact.

---

## Quick Start

```bash
pip install piqrypt
```

```bash
# Create an identity
piqrypt identity create agent.json

# Stamp an event
piqrypt stamp agent.json --payload '{"action": "trade", "symbol": "AAPL"}'

# Verify integrity
piqrypt verify audit.json
# ✅ Chain integrity verified
```

Verification runs locally and deterministically.

### Stamp an event — Python

```python
import piqrypt as aiss

private_key, public_key = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(public_key)

event = aiss.stamp_event(
    private_key,
    agent_id,
    {"action": "recommendation", "value": "buy AAPL"}
)

aiss.store_event(event)
```

Every event is signed, hash-linked to the previous one, and stored locally.
Raw values are never stored — only structured metadata and hashes.

---

## Framework support

| Framework | Repo | Install |
|---|---|---|
| LangChain | [piqrypt-langchain](https://github.com/piqrypt/piqrypt-langchain-integration) | `pip install piqrypt-langchain-integration` |
| AutoGen | [piqrypt-autogen](https://github.com/piqrypt/piqrypt-autogen-integration) | `pip install piqrypt-autogen-integration` |
| CrewAI | [piqrypt-crewai](https://github.com/piqrypt/piqrypt-crewai-integration) | `pip install piqrypt-crewai-integration` |
| OpenClaw | [piqrypt-openclaw](https://github.com/piqrypt/piqrypt-openclaw-integration) | `pip install piqrypt-openclaw-integration` |
| Multi-agent | [piqrypt-session](https://github.com/piqrypt/piqrypt-session-integration) | `pip install piqrypt-session-integration` |
| Plain Python | [piqrypt](https://github.com/piqrypt/piqrypt) | `pip install piqrypt` |

**[→ Integration Guide](INTEGRATION.md)**

---

## Portability

A PiQrypt audit bundle can be:

- Archived long-term
- Transmitted securely
- Reviewed by auditors
- Submitted in regulatory contexts
- Verified offline

The verification process does not depend on PiQrypt servers.

---

## Threat model

PiQrypt protects against:

- Post-event log modification
- Silent event deletion
- Identity repudiation
- Timeline alteration (when timestamped)

PiQrypt does not protect against:

- Compromised private keys
- Fully compromised host environments
- Malicious logic before event stamping

PiQrypt guarantees continuity and authenticity of recorded events —
not correctness of decisions.

---

## Design principles

- Local-first
- No mandatory cloud
- Deterministic verification
- Minimal external trust
- Exportable JSON format
- Long-term cryptographic resilience

---

## Standards implemented

| Standard | Purpose |
|---|---|
| Ed25519 (RFC 8032) | Agent signatures |
| Dilithium3 (NIST FIPS 204) | Post-quantum signatures |
| SHA-256 (NIST FIPS 180-4) | Hash chains |
| RFC 3161 | Trusted timestamps |
| RFC 8785 | JSON canonicalization |

PiQrypt serves as the reference implementation of
[AISS](https://github.com/piqrypt/aiss-spec) — Agent Identity & Signature Standard.

---

## Use cases

- AI SaaS audit trails
- Financial automation logging
- Industrial automation traceability
- Multi-agent coordination
- Content authorship timestamping
- Regulatory documentation

For pricing, tier comparison, and deployment options → [PRICING.md](PRICING.md)

For independent audit certification → [CERTIFICATION.md](CERTIFICATION.md)

---

## Project status

Current version: v1.5.x  
Language: Python 3.9+  
License: MIT

Roadmap includes enhanced session graph tooling, hardware security module
integration, and extended verification utilities.

---

## Documentation

| | |
|---|---|
| 🚀 Quick Start | [QUICK-START.md](QUICK-START.md) |
| 🔌 Integration Guide | [INTEGRATION.md](INTEGRATION.md) |
| 💰 Pricing & Tiers | [PRICING.md](PRICING.md) |
| 🏅 Certification | [CERTIFICATION.md](CERTIFICATION.md) |
| 📐 AISS Specification | [docs/RFC.md](docs/RFC.md) |
| 🤝 A2A Handshake | [docs/A2A_GUIDE.md](docs/A2A_GUIDE.md) |
| 🖥️ CLI Reference | `piqrypt --help` |
| 🐛 Issues | [GitHub Issues](https://github.com/piqrypt/piqrypt/issues) |

---

## License

MIT License — see [LICENSE](LICENSE)

**IP:** e-Soleau DSO2026006483 (INPI France — 19/02/2026)

**Contact:** piqrypt@gmail.com

---

*PiQrypt does not change how agents think.*

*It records — in a verifiable, portable way — what they did.*

*Verifiable memory for autonomous systems.*
