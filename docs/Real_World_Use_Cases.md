# 🔐 PiQrypt — Cryptographic Proof for AI Agents

**Prove what your AI did. Cryptographically.**

Signed • Timestamped • Post-Quantum Ready • Tamper-Proof


## 🎯 Real-World Use Cases

### Who uses PiQrypt — and why?

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Who is PiQrypt for?                             │
│                                                                     │
│   👤 INDIVIDUAL          🏢 STARTUP              🏭 ENTERPRISE      │
│   Creators, freelancers  Dev teams, SaaS AI      Banks, Industry    │
│   3 agents (Free)        Up to 50 agents (Pro)   Unlimited          │
└─────────────────────────────────────────────────────────────────────┘
```

---

### 👤 Use Case 1 — Digital Creator (Free)

**The problem:** You create content with AI tools. How do you prove you made it first?

```
Your Creative Workflow
        │
  GPT / Canva / Script
        │
        ▼
  ┌─────────────┐      ┌──────────────────────────────────┐
  │  Your Work  │ ───▶ │         PiQrypt (local)          │
  │  (ebook,    │      │  hash(document) → sign → chain   │
  │   design,   │      └──────────────────────────────────┘
  │   code...)  │                      │
  └─────────────┘                      ▼
                             Portable signed archive
                             (USB, backup, anywhere)
```

**What PiQrypt proves:**

> *"This content existed in this exact form, at this exact time, signed by this identity."*

**Example:** You write an ebook. PiQrypt computes its SHA-256 hash and signs it. 6 months later, if someone claims they wrote it first — you run the hash again. It matches. **Proof of prior existence, no content storage, GDPR-friendly.**

```
Document created
      │
      ▼  SHA-256 hash
      │
      ▼  Ed25519 signature
      │
      ▼  Added to chain
      │
      ▼  Portable archive (.pqz)

→ You own the proof. Stored locally. Zero third-party.
```

**Perfect for:** Freelancers • Content creators • Trainers • Designers • Influencers

---

### 🏢 Use Case 2 — AI SaaS Startup (Pro)

**The problem:** Your legal AI chatbot gives advice. A client disputes a recommendation. Can you prove what your AI said, and when?

```
Client Request
      │
      ▼
  Backend API
      │
      ▼
    LLM (GPT, Claude, etc.)
      │
      ▼
  ┌──────────────────────────────────┐
  │         PiQrypt Layer            │
  │  • Canonical JSON of response    │
  │  • Ed25519 / ML-DSA signature    │
  │  • Hash chain continuity         │
  │  • Fork detection                │
  └──────────────────────────────────┘
      │
      ▼
  Secure Event Store (AES-256-GCM)
      │
      ├──▶  Exportable verified audit → court-admissible
      │
      └──▶  Vigil Server (port 18421)
             Trust State Index (TSI)
             Behavioral drift alerts
```

**What this gives you:**

- ✅ Legal proof in case of dispute
- ✅ AI Act compliance
- ✅ Commercial differentiation: *"We can prove what our AI said."*
- ✅ Behavioral drift detection between model versions (TSI + A2C, 16 scenarios)
- ✅ Real-time Vigil Risk Score (VRS) per agent

**Perfect for:** Legal-tech • Fintech • Health-tech • B2B AI SaaS

---

### 🏭 Use Case 3 — Industrial SME / Robotics (Pro)

**New in v1.7.1:** ROS2 and RPi bridges — every robot action cryptographically signed.

**The problem:** Your factory runs 4 AI agents (robots, planner, quality, logistics). An incident happens on the production line. Who decided what?

```
  Robot ──┐
          │
Planner ──┼──▶  PiQrypt Core  ──▶  Internal Collector
          │         │
Quality ──┤    Unique identity        Continuous audit
          │    per agent              trail per agent
Logistics─┘
                    │
                    ▼
            Incident Report:
            "Quality agent flagged
             anomaly at 14:32:07.
             Logistics agent re-routed
             at 14:32:09. Signed."
```

**What this gives you:**

- ✅ Full production traceability
- ✅ Incident audit with cryptographic timestamps
- ✅ Insurance and ISO certification support
- ✅ Machine drift detection over time (TSI + VRS)

**Perfect for:** Industry 4.0 • Robotics • Supply chain • Automated agri-food

---

### 🏦 Use Case 4 — Large Enterprise (Enterprise)

**The problem:** 5 departments use AI (Finance, HR, Support, Supply Chain, Compliance). You need global governance across entities and countries.

```
  Finance AI ──────┐
                   │
  HR AI ───────────┤
                   │
  Support AI ──────┼──▶  PiQrypt Node     ──▶  Central Governance
                   │     (per entity)            (Vigil Enterprise)
  Supply Chain AI ─┤          │
                   │     Authority binding
  Compliance AI ───┘     A2A traceability
                          Post-quantum ready
                               │
                               ▼
                    Independent verification
                    Multi-country compliance
                    Immutable chronological proof
```

**What this gives you:**

- ✅ Global AI governance framework
- ✅ Multi-country compliance (GDPR, AI Act, HIPAA, SEC...)
- ✅ AI crisis management with full audit trail
- ✅ Post-quantum readiness (50+ year proof, Dilithium3 FIPS 204)

**Perfect for:** Banks • Insurers • Heavy industry • International groups

---

### 🔑 The Core Principle (for all use cases)

**PiQrypt stores actions, not documents.**

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│  ❌ PiQrypt does NOT store:  ✅ PiQrypt DOES store: │
│                                                     │
│   • Your PDF                  • hash(PDF)           │
│   • Your image                • Timestamp           │
│   • Your code                 • Ed25519 signature   │
│   • Sensitive data            • Chain continuity    │
│                                                     │
│  Zero content leak. GDPR-friendly. Portable.        │
└─────────────────────────────────────────────────────┘
```

**Why this is more powerful:**

| Storing the document | Storing the hash (PiQrypt) |
|---------------------|---------------------------|
| GDPR risk | GDPR-friendly |
| Massive storage | Lightweight |
| Legal liability | Minimal exposure |
| Content breach possible | Zero content leaked |
| Hard to scale | Infinitely scalable |

---

### For Businesses

| Industry | Problem | PiQrypt Solution |
|----------|---------|------------------|
| **Finance** | SEC requires 7-year audit trail | Cryptographic trade signatures |
| **Healthcare** | HIPAA compliance for AI decisions | Immutable diagnosis records |
| **HR** | GDPR Art. 22 (explain AI decisions) | Verifiable hiring audit |
| **Autonomous Vehicles** | Legal liability for accidents | Black box with crypto proof |
| **Supply Chain** | Track AI inventory decisions | Non-repudiable logistics trail |

**Compliance:** SOC2 • ISO 27001 • HIPAA • GDPR • SEC/FINRA • NIST PQC (FIPS 204)

---


## 🚀 For Builders: Install & Integrate

**Want full control? Install PiQrypt and integrate into your agent.**

### Installation

```bash
pip install piqrypt
```

**Requirements:** Python 3.9+

### Quick Start

```python
import piqrypt as aiss

# 1. Create identity
private_key, public_key = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(public_key)

# 2. Sign decision
event = aiss.stamp_event(
    private_key,
    agent_id,
    payload={
        "event_type": "trade_decision",
        "action": "buy",
        "symbol": "AAPL",
        "quantity": 100,
        "confidence": 0.95
    }
)

# 3. Store (tamper-proof)
aiss.store_event(event)

# 4. Export for audit
aiss.export_audit_chain("audit-q1-2026.json")
```

**CLI:**

```bash
piqrypt identity create my-agent.json
piqrypt stamp my-agent.json --payload '{"action": "test"}'
piqrypt export audit.json --certified
piqrypt verify audit.json
```

**Full docs:** [Quick Start Guide](QUICK-START.md)


---

**Built with ❤️ for autonomous systems**

*PiQrypt v1.9.0 — Cryptographic Proof for AI Agents*

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
