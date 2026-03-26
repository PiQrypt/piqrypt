# 🔐 PiQrypt — Cryptographic Proof for AI Agents

**Prove what your AI did. Cryptographically.**

Signed • Timestamped • Post-Quantum Ready • Tamper-Proof

[![PyPI](https://img.shields.io/badge/PyPI-piqrypt-blue)](https://pypi.org/project/piqrypt/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![AISS](https://img.shields.io/badge/AISS-v2.0-orange)](https://github.com/piqrypt/aiss-spec)

---

## ⚡ The Problem

AI agents make **critical decisions autonomously**: trades, diagnoses, approvals, actions.

But when something goes wrong:

- **Who did what?**
- **Can it be proven?**
- **Is the log tamper-proof?**
- **Is it quantum-resistant?**

**Most systems rely on editable logs.** Trust is not cryptographic.

```
❌ Traditional Logs
   ├─ Modifiable after the fact
   ├─ No cryptographic proof
   ├─ No legal standing
   └─ Vulnerable to quantum attacks
```

---

## ✅ The Solution

PiQrypt creates **cryptographic audit trails** for autonomous systems.

Every decision is:

✅ **Cryptographically signed** (Ed25519 + Dilithium3)  
✅ **Hash-chained** (tamper-proof, blockchain-like)  
✅ **Timestamped** (RFC 3161 independent proof)  
✅ **Post-quantum secured** (NIST FIPS 204)  
✅ **Court-admissible** (legal standing)

**No blockchain. No token. Just verifiable cryptography.**

```
✅ PiQrypt Audit Trail
   ├─ Cryptographically signed (Ed25519/Dilithium3)
   ├─ Immutable hash chains (tamper-proof)
   ├─ Legal standing (court-admissible)
   └─ Quantum-resistant (50+ year proof)
```

---

## 💡 Why PiQrypt?

PiQrypt is the reference implementation of AISS and its Proof of Continuity Protocol (PCP).

It provides:

- Cryptographic profiles (Classical and Hybrid Post-Quantum)
- Deterministic event validation
- Canonical history enforcement
- Audit-ready certification export

### For Developers

```python
import piqrypt as aiss

# Sign every decision
event = aiss.stamp_event(
    private_key,
    agent_id,
    payload={"action": "buy", "symbol": "AAPL", "quantity": 100}
)

# Tamper-proof storage
aiss.store_event(event)

# Export for auditors
aiss.export_audit_chain("audit.json", certified=True)
```

**<10ms per event. Local-first. No network dependency.**

---

### For Businesses

| Industry | Problem | PiQrypt Solution |
|----------|---------|------------------|
| **Finance** | SEC requires 7-year audit trail | Cryptographic trade signatures |
| **Healthcare** | HIPAA compliance for AI decisions | Immutable diagnosis records |
| **HR** | GDPR Art. 22 (explain AI decisions) | Verifiable hiring audit |
| **Autonomous Vehicles** | Legal liability for accidents | Black box with crypto proof |
| **Supply Chain** | Track AI inventory decisions | Non-repudiable logistics trail |

**Compliance:** SOC2 • ISO 27001 • HIPAA • GDPR • SEC/FINRA • EU AI Act Art.14 • NIST AI RMF • ANSSI 2024

**v1.7.1 — New:** TrustGate governance engine · AgentSession cross-framework sessions · 9 framework bridges (LangChain, CrewAI, AutoGen, OpenClaw, Session, MCP, Ollama, ROS2, RPi)

---

## 🎯 Quick Win: Instant Certification

**Need one-time proof without integration?**

Upload your log → Pay → Get certified bundle instantly.

### Certification Tiers

<table>
<tr>
<td width="33%" align="center">

**🔹 Simple**

**€9**

✅ Cryptographic signature  
✅ Hash verification  
✅ Public badge  
✅ Export bundle  

<a href="https://buy.stripe.com/eVq28k6sIay13yfgN52VG05">
<img src="https://img.shields.io/badge/Certify-€9-blue?style=for-the-badge&logo=stripe&logoColor=white" alt="Simple Certification €9">
</a>

</td>
<td width="33%" align="center">

**🔸 Timestamp**

**€29**

✅ Everything in Simple  
✅ **RFC 3161 TSA timestamp**  
✅ Independent time proof  
✅ GDPR/HIPAA ready  

<a href="https://buy.stripe.com/8x214g3gw8pT4Cj68r2VG04">
<img src="https://img.shields.io/badge/Certify-€29-orange?style=for-the-badge&logo=stripe&logoColor=white" alt="Timestamp Certification €29">
</a>

</td>
<td width="33%" align="center">

**🔶 Post-Quantum**

**€99**

✅ Everything in Timestamp  
✅ **Dilithium3 signature**  
✅ Encrypted archive  
✅ 50+ year proof  

<a href="https://buy.stripe.com/aFa14g4kA5dH4Cj68r2VG03">
<img src="https://img.shields.io/badge/Certify-€99-gold?style=for-the-badge&logo=stripe&logoColor=white" alt="Post-Quantum Bundle €99">
</a>

</td>
</tr>
</table>

**How it works:**

```
1. Export your audit trail:
   piqrypt export audit.json

2. Copy the JSON content:
   cat audit.json  # Copy output (Ctrl+A, Ctrl+C)

3. Click certification tier below

4. Stripe checkout opens → Paste JSON in "Audit Data" field

5. Complete payment

6. Receive certified bundle via email (< 5 minutes)

7. Verify: piqrypt certify-verify bundle.piqrypt-certified
```

**That's it!** No upload page, no complications. Just copy/paste → pay → receive.

**Perfect for:**
- One-time audits
- Proof of concept
- Legal disputes
- Compliance checks

---

## 🚀 For Builders: Install & Integrate

**Want full control? Install PiQrypt and integrate into your agent.**

### Installation

```bash
pip install piqrypt
```

**Requirements:** Python 3.8+

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

## 📊 Pricing: Free → Pro → Enterprise

### 🆓 Free Tier

**Perfect for:**
- Indie developers
- Prototypes
- Testing PiQrypt

**Includes:**
- 3 agents max
- Ed25519 signatures
- JSON storage
- 50 exports/month
- ✅ **A2A handshake** — pairwise agent-to-agent identity
- **1 Simple certification/month FREE** 🔥

```bash
pip install piqrypt
# Free tier active immediately
```

---

### ⚡ Early-Bird Pro — €290/year

**⏰ Limited-time adoption pricing**

Perfect for startups, trading bots, automation workflows.

**Includes:**
- ✅ **50** (vs 3 Free)
- ✅ **Ed25519 + Dilithium3** (post-quantum)
- ✅ **AES-256-GCM** encrypted storage
- ✅ **Unlimited exports**
- ✅ **10 Simple certifications/month FREE**
- ✅ **TSA timestamps** (RFC 3161)
- ✅ **AgentSession** — N-agent cross-framework co-signed sessions
- ✅ **Email support** (48h)

<a href="https://buy.stripe.com/4gM6oAeZe9tX6KreEX2VG02">
<img src="https://img.shields.io/badge/Get_Early--Bird_Pro-€290/year-blue?style=for-the-badge&logo=stripe&logoColor=white" alt="Early-Bird Pro €290/year">
</a>

**⏰ Lock in €290/year before Standard pricing. Limited slots.**

---

### 🔥 Standard Pro — €390/year

**Full premium package**

Perfect for growing startups, fintech, compliance-critical systems.

**Includes:**
- ✅ Everything in Early-Bird Pro
- ✅ **50 certifications/month FREE** (vs 10)
- ✅ **Trust scoring dashboard** (I/V/D/F) *[v1.6]*
- ✅ **Visual badges** (custom branding)
- ✅ **Priority support** (24h vs 48h)

<a href="https://buy.stripe.com/00wcMY7wMeOhc4L2Wf2VG01">
<img src="https://img.shields.io/badge/Get_Standard_Pro-€390/year-orange?style=for-the-badge&logo=stripe&logoColor=white" alt="Standard Pro €390/year">
</a>

---

### 🏢 Enterprise — Custom Pricing

**Infrastructure de confiance**

Perfect for banks, healthcare, government, autonomous vehicles.

**Includes:**
- ✅ Everything in Standard Pro
- ✅ **HSM integration** (hardware security)
- ✅ **REST API + GraphQL**
- ✅ **Multi-tenant** deployment
- ✅ **SSO** (SAML, OAuth)
- ✅ **SLA 99.9%** uptime
- ✅ **Dedicated support** (24h, Slack, Phone)
- ✅ **On-premise** option
- ✅ **SOC2/ISO 27001** audit support

<a href="mailto:contact@piqrypt.com?subject=Enterprise Inquiry">
<img src="https://img.shields.io/badge/Contact_Sales-Enterprise-gold?style=for-the-badge&logo=mail.ru&logoColor=white" alt="Enterprise Contact">
</a>

**Pricing starts at €10,000/year.**

**OSS Exemption:** Open-source projects get Pro for free. [Apply here](mailto:contact@piqrypt.com?subject=OSS License Request).

---

## 🏗️ How It Works

### System Architecture

TRUSTGATE  → Policy / Governance Engine   (Layer 4)
VIGIL      → Behavioural Monitoring         (Layer 3)
PIQRYPT    → Continuity Engine              (Layer 2)
AISS       → Agent Identity Standard        (Layer 1)

PCP → The protocol. PiQrypt → The reference implementation.

```
┌─────────────────────────────────────────────────────────────┐
│            Your AI Agent / Application                      │
│  (Trading Bot, HR AI, Autonomous Vehicle, etc.)             │
└──────────────────────────┬──────────────────────────────────┘
                           ↓
                   Makes Decision
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                 🔐 PIQRYPT LAYER                            │
│  • Canonicalize (RFC 8785)                                  │
│  • Sign (Ed25519 / Dilithium3)                              │
│  • Timestamp (RFC 3161 TSA)                                 │
│  • Chain (SHA-256 hash links)                               │
│  • Store (encrypted if Pro)                                 │
└──────────────────────────┬──────────────────────────────────┘
                           ↓
              Immutable Audit Trail
                           ↓
┌─────────────────────────────────────────────────────────────┐
│              Export for Auditors/Regulators                 │
│  • Certified bundles (.piqrypt-certified)                   │
│  • Court-admissible proof                                   │
│  • Compliance reports (SOC2, HIPAA, SEC)                    │
└─────────────────────────────────────────────────────────────┘
```

**PiQrypt secures decision continuity — it doesn't replace your agent.**

---

## 🌐 AISS Standard

PiQrypt is the **reference implementation** of **AISS v2.0** (Agent Identity & Signature Standard).

**What is AISS?**

A vendor-neutral, open standard (MIT) for cryptographic audit trails of AI agents.

**Repositories:**
- **AISS Spec:** [github.com/piqrypt/aiss-spec](https://github.com/piqrypt/aiss-spec)
- **PiQrypt Core:** [github.com/piqrypt/piqrypt](https://github.com/piqrypt/piqrypt)
- **MCP Server:** [github.com/piqrypt/piqrypt-mcp-server](https://github.com/piqrypt/piqrypt-mcp-server)

**Think:** TLS (standard) vs OpenSSL (implementation)

---

## 🔒 Security

### Cryptography

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| **Ed25519** | RFC 8032 | Classical signatures (128-bit) |
| **Dilithium3** | NIST FIPS 204 | Post-quantum signatures (256-bit PQ) |
| **SHA-256** | NIST FIPS 180-4 | Hash chains |
| **AES-256-GCM** | NIST FIPS 197 | Encryption (Pro) |

### Guarantees

✅ **Integrity:** Modification breaks chain  
✅ **Non-repudiation:** Agent can't deny actions  
✅ **Authenticity:** Signatures prove authorship  
✅ **Freshness:** Timestamps prove when  
✅ **Post-quantum:** Dilithium3 (50+ years)

---

## 🎯 Use Cases

### 1. Trading Bots (SEC Compliance)

```python
# Sign every trade
event = aiss.stamp_event(priv, agent_id, {
    "event_type": "trade_executed",
    "symbol": "AAPL",
    "quantity": 100,
    "price": 150.25
})
```

**Result:** SEC Rule 17a-4 compliant audit trail.

---

### 2. Healthcare AI (HIPAA)

```python
# Sign diagnosis
event = aiss.stamp_event(priv, agent_id, {
    "event_type": "diagnosis",
    "condition": "pneumonia",
    "confidence": 0.94,
    "patient_id_hash": sha256(patient_id)  # HIPAA compliant
})
```

**Result:** Court-admissible proof of AI recommendation.

---

### 3. HR Automation (GDPR Art. 22)

```python
# Sign hiring decision
event = aiss.stamp_event(priv, agent_id, {
    "event_type": "candidate_evaluation",
    "decision": "accept",
    "reasons": ["Relevant experience", "Strong Python"],
    "protected_attributes_used": False  # EEOC
})
```

**Result:** GDPR-compliant audit with explanations.

---

## 📚 Documentation

- **Quick Start:** [QUICK-START.md](QUICK-START.md)
- **AISS Spec:** [docs/RFC.md](docs/RFC.md)
- **A2A Handshake:** [docs/A2A_SESSION_GUIDE.md](docs/A2A_SESSION_GUIDE.md)
- **OpenClaw:** [docs/OPENCLAW_INTEGRATION.md](docs/OPENCLAW_INTEGRATION.md)
- **CLI Reference:** `piqrypt --help`

---

## 🗺️ Roadmap

### v1.7.1 (Current) ✅
- A2A Handshake
- AISS v2.0 separation
- MCP Server
- Pay-per certification

### v1.6.0 ✅
- Trust Scoring (I/V/D/F)
- Visual dashboard
- A2A Network (DHT)

### v1.8.3 ✅
- Witness network
- HSM integration
- Blockchain anchoring

---

### v1.8.3 (Q2 2026)
- OIDC/SSO for Vigil + TrustGate authentication
- Full CMS/PKCS7 TSA token verification
- PostgreSQL event storage backend
- PiQrypt Ambassador Agent (Ollama-based)

## 📧 Contact & Support

- **Email:** contact@piqrypt.com
- **Issues:** [GitHub Issues](https://github.com/piqrypt/piqrypt/issues)
- **Pro Support:** 48h response (Pro tier)
- **Enterprise:** 24h response + Slack

---

## 📄 License

**Core:** MIT License — see [LICENSE](LICENSE)

**e-Soleau:** DSO2026006483 (INPI, 19/02/2026)

---

<div align="center">

### 🚀 Get Started Today

**One-time certification:**

<a href="https://buy.stripe.com/eVq28k6sIay13yfgN52VG05">€9 Simple</a> • 
<a href="https://buy.stripe.com/8x214g3gw8pT4Cj68r2VG04">€29 Timestamp</a> • 
<a href="https://buy.stripe.com/aFa14g4kA5dH4Cj68r2VG03">€99 Post-Quantum</a>

**Pro subscription:**

<a href="https://buy.stripe.com/4gM6oAeZe9tX6KreEX2VG02">Early-Bird €290/year</a> • 
<a href="https://buy.stripe.com/00wcMY7wMeOhc4L2Wf2VG01">Standard €390/year</a>

**Enterprise:**

<a href="mailto:contact@piqrypt.com?subject=Enterprise">Contact Sales</a>

---

**Free tier:**
```bash
pip install piqrypt
```

---

**Built with ❤️ for autonomous systems**

*PiQrypt — Cryptographic Proof for AI Agents*

</div>

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
