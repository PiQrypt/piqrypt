# 🔐 PiQrypt — Cryptographic Proof for AI Agents

<div align="center">

**Your AI acts. PiQrypt proves it. Forever.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt)](https://pypi.org/project/piqrypt/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/piqrypt)](https://pypi.org/project/piqrypt/)
[![PyPI](https://img.shields.io/badge/PyPI-piqrypt-blue)](https://pypi.org/project/piqrypt/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![AISS](https://img.shields.io/badge/AISS-v1.1-orange)](https://github.com/piqrypt/aiss-spec)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204-red)](https://csrc.nist.gov/pubs/fips/204/final)

*Signed · Hash-chained · Post-Quantum Ready · Court-admissible*

</div>

---

```bash
pip install piqrypt   # free forever, no signup, no cloud
```
| 🔌 Integration Guide | [INTEGRATION.md](INTEGRATION.md) |

```
Event created ──▶ SHA-256 hash ──▶ Ed25519 sign ──▶ Chain ──▶ Tamper-proof archive
    2026-02-24T14:32:07Z            ✅ verified        ✅ linked      ✅ portable
```

---

## The problem, in one sentence

> AI agents take decisions that can cost millions, trigger lawsuits, or violate regulations —  
> and most systems log them in **files that anyone can edit**.

```
❌ Without PiQrypt          ✅ With PiQrypt
─────────────────────       ─────────────────────────────────
Log file: editable          Signed event: tamper-proof
No timestamp proof          RFC 3161 TSA timestamp
No identity binding         Unique cryptographic agent ID
Agent trusts nobody         A2A co-signed handshake
Quantum-vulnerable          Dilithium3 (NIST FIPS 204)
"Our AI didn't do that"     Provable. Irrefutable.
```

---

## Start in 2 minutes — free

```bash
# Install
pip install piqrypt

# Create your agent identity
piqrypt identity create my-agent.json

# Sign your first event
piqrypt stamp my-agent.json --payload '{"action": "trade", "symbol": "AAPL", "qty": 100}'

# Verify the chain
piqrypt verify audit.json

# ✅ Done. Signed. Chained. Tamper-proof.
```

> **Free tier:** 3 agents · Ed25519 signatures · Local-first · No account · No cloud · No catch.  
> **[→ Full Quick Start Guide](QUICK-START.md)**

---

## Who is PiQrypt for?

| | 👤 Individual | 🏢 Startup / Dev team | 🏭 SME | 🏦 Enterprise |
|---|---|---|---|---|
| **Agents** | 3 (Free) | 50 (Pro) | 50 (Pro) | Unlimited |
| **Use case** | Prove I created this | Prove our AI said that | Trace the incident | Govern all AI |
| **Key value** | IP protection | Legal non-repudiation | Operational traceability | Global compliance |
| **Tier** | Free | Pro | Pro | Enterprise |

---

## Real-world use cases

<details>
<summary><strong>👤 Digital Creator — Prove prior existence of your work</strong></summary>

**The problem:** You generate an ebook, a script, a design with AI tools. Someone claims they made it first.

```
Your work (PDF, image, code)
         │
         ▼
    SHA-256 hash           ← the document is NEVER stored
         │
         ▼
  Ed25519 signature        ← your cryptographic identity
         │
         ▼
    Hash chain             ← tamper-proof continuity
         │
         ▼
  Portable .pqz archive   ← USB, backup, offline, forever
```

**6 months later, dispute:** recompute the hash → it matches → **proof of prior existence**.

> *"This content existed in this exact form, at this exact time, signed by this identity."*

No content stored. GDPR-friendly. Zero third-party dependency.

**Perfect for:** Freelancers · Content creators · Designers · Trainers · Influencers

</details>

<details>
<summary><strong>🏢 AI SaaS Startup — Prove what your AI said</strong></summary>

**The problem:** Your legal chatbot gives advice. A client disputes a recommendation. Your logs are editable.

```
Client Request
      │
      ▼
  Backend API  ──▶  LLM (GPT / Claude / Mistral)
                          │
                          ▼
              ┌───────────────────────┐
              │     PiQrypt Layer     │
              │  Canonical JSON       │
              │  Ed25519 / ML-DSA     │
              │  Hash chain           │
              │  Fork detection       │
              └───────────────────────┘
                          │
                          ▼
              Signed event store  ──▶  court-admissible export
```

**What you gain:**
- Legal proof in case of dispute
- AI Act compliance (Article 13 — transparency)
- *"We can prove exactly what our AI said."* — commercial differentiator
- Behavioral drift detection when you switch model versions

**Perfect for:** Legal-tech · Fintech · Health-tech · B2B AI SaaS

</details>

<details>
<summary><strong>🏭 Industrial SME — Trace every machine decision</strong></summary>

**The problem:** 4 AI agents run your production line. An incident happens. Who decided what, when?

```
  Robot AI ───┐
              │
 Planner AI ──┼──▶  PiQrypt Core  ──▶  Incident report:
              │     (unique ID           "Quality agent flagged
 Quality AI ──┤      per agent)           anomaly at 14:32:07.
              │                           Logistics re-routed
Logistics AI ─┘                           at 14:32:09. Signed."
```

**What you gain:**
- Full production traceability
- Cryptographic timestamps for insurance claims
- ISO audit support
- Machine drift detection over months

**Perfect for:** Industry 4.0 · Robotics · Supply chain · Automated agri-food

</details>

<details>
<summary><strong>🏦 Large Enterprise — Govern your entire AI ecosystem</strong></summary>

**The problem:** 5 departments, multiple countries, dozens of AI agents. No unified audit layer.

```
Finance AI ──┐
   HR AI ────┤
Support AI ──┼──▶  PiQrypt Node  ──▶  Central Governance
Supply AI ───┤     per entity          (Sentinel Enterprise)
Compliance ──┘          │
                   Authority binding
                   A2A traceability         ──▶  GDPR · AI Act
                   Post-quantum ready       ──▶  HIPAA · SEC
                   Independent verification ──▶  ISO 27001
```

**What you gain:**
- Global AI governance framework
- Multi-country compliance (GDPR, AI Act, HIPAA, SEC/FINRA)
- AI crisis management with full chronological proof
- Post-quantum readiness for the next 50 years

**Perfect for:** Banks · Insurers · Heavy industry · International groups

</details>

---

## The core principle

**PiQrypt stores actions, not documents.**

```
❌ DO NOT store             ✅ PiQrypt stores
──────────────────          ──────────────────────────
Your PDF                    hash(PDF)          → no content leak
Your image                  Timestamp          → RFC 3161, independent
Your patient data           Ed25519 signature  → cryptographic identity
Sensitive API responses     Chain continuity   → tamper-proof history
```

Why this is smarter than storing the document:

| Storing the document | Storing the hash (PiQrypt) |
|---|---|
| GDPR exposure | GDPR-friendly by design |
| Massive storage cost | Negligible footprint |
| Content breach risk | Zero content ever stored |
| Hard to scale | Scales to millions of events |
| Legal liability | Minimal surface |

---
## Verifiable AI Agent Memory — a first

> *"What if every AI agent could prove what it did, when it did it, and with whom?"*

PiQrypt introduces **Verifiable AI Agent Memory** — a cryptographic memory layer for AI agents, from individual actions to multi-agent sessions.

```
Single agent       →  every action signed, chained, tamper-proof
Two agents         →  co-signed interactions, mutual non-repudiation
N agents (session) →  shared session, all pairs handshaked before acting
```

Each agent keeps its own memory — its own view of what happened. Co-signed interactions link the memories cryptographically. No agent can deny what it did. No action can be fabricated or backdated.

**[→ Full story: Verifiable AI Agent Memory](VERIFIABLE_MEMORY.md)**

---
## 3-line integration

```python
import piqrypt as aiss

# That's really it.
event = aiss.stamp_event(private_key, agent_id, {"action": "approved", "amount": 50000})
aiss.store_event(event)
```

**< 10ms per event. Local-first. No network required.**

```python
# More complete example
private_key, public_key = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(public_key)

event = aiss.stamp_event(private_key, agent_id, {
    "event_type": "trade_executed",
    "symbol": "AAPL",
    "quantity": 100,
    "price": 150.25,
    "confidence": 0.95
})

aiss.store_event(event)
aiss.export_audit_chain("audit-q1-2026.json", certified=True)
```

---

## Why PiQrypt — not just a logger

PiQrypt is the reference implementation of **AISS v1.1** (Agent Identity & Signature Standard) and its **Proof of Continuity Protocol (PCP)**.

Unlike structured logging or observability tools, PiQrypt provides:

- **Cryptographic identity** — each agent has a unique, unforgeable ID derived from its keypair
- **Non-repudiation** — a signed event cannot be denied; the agent cannot claim it didn't act
- **Agent-to-agent trust** — A2A handshake co-signs interactions between agents, making multi-agent pipelines fully auditable end-to-end
- **External certification** — export your audit trail and receive a CA-signed certified bundle in minutes, without sharing any content — for legal-grade third-party proof
- **OpenClaw native** — plugs directly into OpenClaw orchestration pipelines with zero workflow changes ([integration guide](docs/OPENCLAW_INTEGRATION.md))
- **Post-quantum readiness** — Dilithium3 (NIST FIPS 204) ensures your proofs remain valid for 50+ years

```
LangChain / AutoGen / OpenClaw  →  produce the decision
              LLM               →  generates the content
           PiQrypt              →  guarantees cryptographic continuity
           Sentinel             →  monitors network stability
```

**Analogy that clicks:**
- Git = versions your **code**
- TLS = secures your **communication**
- Kubernetes = orchestrates your **containers**
- **PiQrypt = proves what your AI decided**

---

## Industry compliance at a glance

| Industry | Regulation | What PiQrypt covers |
|---|---|---|
| **Finance** | SEC Rule 17a-4 | 7-year tamper-proof trade audit |
| **Healthcare** | HIPAA | Immutable AI diagnosis records |
| **HR** | GDPR Art. 22 | Explainable, verifiable hiring decisions |
| **Automotive** | EU AI Act | Black-box with crypto proof |
| **Supply chain** | ISO 27001 | Non-repudiable logistics decisions |

---

## Instant certification — no integration needed

(MARS 2026 for firsts certifications)

Need a one-time certified proof without installing anything?

```
1. piqrypt export audit.json       ← or skip if you have a log
2. Paste JSON at checkout
3. Pay
4. Receive certified bundle by email (< 5 min)
5. piqrypt certify-verify bundle.piqrypt-certified
```

<table>
<tr>
<td width="33%" align="center">

**🔹 Simple · €9**

✅ Cryptographic signature  
✅ Hash verification  
✅ Public badge  
✅ Export bundle  

<a href="https://buy.stripe.com/eVq28k6sIay13yfgN52VG05">
<img src="https://img.shields.io/badge/Certify_Now-€9-blue?style=for-the-badge&logo=stripe&logoColor=white" alt="Simple €9">
</a>

</td>
<td width="33%" align="center">

**🔸 Timestamp · €29**

✅ Everything in Simple  
✅ RFC 3161 TSA timestamp  
✅ Independent time proof  
✅ GDPR/HIPAA ready  

<a href="https://buy.stripe.com/8x214g3gw8pT4Cj68r2VG04">
<img src="https://img.shields.io/badge/Certify_Now-€29-orange?style=for-the-badge&logo=stripe&logoColor=white" alt="Timestamp €29">
</a>

</td>
<td width="33%" align="center">

**🔶 Post-Quantum · €99**

✅ Everything in Timestamp  
✅ Dilithium3 signature  
✅ Encrypted archive  
✅ 50+ year proof  

<a href="https://buy.stripe.com/aFa14g4kA5dH4Cj68r2VG03">
<img src="https://img.shields.io/badge/Certify_Now-€99-gold?style=for-the-badge&logo=stripe&logoColor=white" alt="Post-Quantum €99">
</a>

</td>
</tr>
</table>

---

## Pricing 

### 🆓 Free — forever

3 agents · Ed25519 · JSON storage · 50 exports/month · **1 free Simple certification/month**

```bash
pip install piqrypt   # that's it, free tier is immediate
```

---

### ⚡ Early-Bird Pro — €290/year  *(limited slots)*

For startups, trading bots, compliance-critical workflows.

✅ 50 agents · Ed25519 + Dilithium3 · AES-256-GCM encrypted storage  
✅ Unlimited exports · 10 free Simple certifications/month  
✅ TSA timestamps (RFC 3161) · A2A handshake · Email support (48h)

<a href="https://buy.stripe.com/4gM6oAeZe9tX6KreEX2VG02">
<img src="https://img.shields.io/badge/Get_Early--Bird_Pro-€290/year-blue?style=for-the-badge&logo=stripe&logoColor=white" alt="Early-Bird Pro €290/year">
</a>

---

### 🔥 Standard Pro — €390/year

Everything in Early-Bird · 50 free certifications/month · Trust scoring dashboard *(v1.6)* · Visual badges · Priority support (24h)

<a href="https://buy.stripe.com/00wcMY7wMeOhc4L2Wf2VG01">
<img src="https://img.shields.io/badge/Get_Standard_Pro-€390/year-orange?style=for-the-badge&logo=stripe&logoColor=white" alt="Standard Pro €390/year">
</a>

---

### 🏢 Enterprise — from €10,000/year

HSM integration · REST API + GraphQL · Multi-tenant · SSO (SAML, OAuth) · SLA 99.9% · On-premise · SOC2/ISO 27001 audit support

<a href="mailto:piqrypt@gmail.com?subject=Enterprise Inquiry">
<img src="https://img.shields.io/badge/Contact_Sales-Enterprise-gold?style=for-the-badge&logo=mail.ru&logoColor=white" alt="Enterprise">
</a>

**OSS Exemption:** open-source projects get Pro for free — [apply here](mailto:piqrypt@gmail.com?subject=OSS License Request).

---

## Security

| Algorithm | Standard | Purpose |
|---|---|---|
| **Ed25519** | RFC 8032 | Classical signatures (128-bit security) |
| **Dilithium3** | NIST FIPS 204 | Post-quantum signatures (256-bit PQ) |
| **SHA-256** | NIST FIPS 180-4 | Hash chains |
| **AES-256-GCM** | NIST FIPS 197 | Encrypted storage (Pro) |

✅ Integrity — modification breaks the chain  
✅ Non-repudiation — agent cannot deny its actions  
✅ Authenticity — signatures prove authorship  
✅ Freshness — timestamps prove when  
✅ Post-quantum — Dilithium3 holds for 50+ years

---

## Roadmap

| Version | Target | Features |
|---|---|---|
| **v1.5.0** ✅ | Now | A2A Handshake · AISS v1.1 · MCP Server · Pay-per certification |
| **v1.6.0** | Q2 2026 | Trust Scoring (I/V/D/F) · Visual dashboard · A2A Network (DHT) |
| **v1.7.0** | Q3 2026 | Witness network · HSM integration · Blockchain anchoring |

---

## Documentation

| | |
|---|---|
| 🚀 Quick Start | [QUICK-START.md](QUICK-START.md) |
| 🔌 Integration Guide | [INTEGRATION.md](INTEGRATION.md) |
| 📐 AISS Spec | [docs/RFC.md](docs/RFC.md) |
| 🤝 A2A Handshake | [docs/A2A_GUIDE.md](docs/A2A_GUIDE.md) |
| 🔗 OpenClaw | [docs/OPENCLAW_INTEGRATION.md](docs/OPENCLAW_INTEGRATION.md) |
| 🏷️ Badges | [docs/BADGES.md](docs/BADGES.md) |
| 🖥️ CLI Reference | `piqrypt --help` |
| 🐛 Issues | [GitHub Issues](https://github.com/piqrypt/piqrypt/issues) |

---

## Contributing

PiQrypt is MIT. Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

Found a security issue? See [SECURITY.md](SECURITY.md) for responsible disclosure.

---

## License & Legal

**Core:** MIT License — [LICENSE](LICENSE)

**Intellectual property:** registered e-Soleau DSO2026006483 (INPI, France — 19/02/2026).  
*e-Soleau is a French IP registration system establishing a certified date of creation.*

**Contact:** piqrypt@gmail.com · [GitHub Issues](https://github.com/piqrypt/piqrypt/issues)

---

<div align="center">

**Start free. No account. No cloud.**

```bash
pip install piqrypt
```

*PiQrypt — Cryptographic Proof for AI Agents*

</div>
