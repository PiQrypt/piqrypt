# PiQrypt — Tiers & Pricing

> **Source de vérité unique** — ce fichier est synchronisé avec `aiss/license.py → TIERS{}`
> et `auth_middleware.py → VIGIL_TIER_FEATURES{}`.

---

## Free — forever

For individuals, open-source projects, and evaluation.

**Quotas**
- **3 agents** · **10,000 events/month**

**Core features (local, offline)**
- Ed25519 signatures + hash-linked chains
- Fork detection · A2A handshake
- Plaintext local storage
- `.pqz` memory export (basic)

**Vigil dashboard**
- ✅ Dashboard read + write (agents connect and send events)
- ✅ Live network graph
- ✅ Alerts — CRITICAL severity only
- ✅ PDF audit report (local, non-certified)
- 🔒 Alerts MEDIUM/LOW — Pro+
- 🔒 `.pqz` certified export — Pro+
- 🔒 VRS history > 7 days — Pro+

**Bridges**
- **2 bridge types max** (e.g. LangChain + CrewAI)
- All 9 bridges available to choose from: LangChain, CrewAI, AutoGen, MCP,
  OpenClaw, AgentSession, Ollama, ROS2, RPi

**Support:** Community

```bash
pip install piqrypt   # immediate · no account · no cloud
```

No credit card. No expiry.

---

## Pro — €290/year (Early-Bird) · €390/year (Standard)

For production workloads, freelancers, consultants, and compliance-sensitive environments.

**Quotas**
- **50 agents** · **500,000 events/month**

**Everything in Free, plus:**
- Ed25519 + **Dilithium3** post-quantum signatures (NIST FIPS 204)
- **AES-256-GCM** encrypted local storage (scrypt N=2¹⁷)
- **RFC 3161** trusted timestamps (TSA)
- **AgentSession** — cross-framework co-signed sessions
- All 9 bridges — **unlimited bridge types**

**Vigil — full mode**
- ✅ All alert severities (CRITICAL · HIGH · MEDIUM · LOW)
- ✅ Alert filters (by agent, severity, time range)
- ✅ `.pqz` certified export + memory export
- ✅ PDF audit report
- ✅ VRS history — **90 days**
- ✅ Trust Scoring · TSI · A2C anomaly detection

**TrustGate:** manual mode (REQUIRE_HUMAN flow)

**Certifications included:** 10 × Simple/month *(à la carte available)*

**Support:** Email — 48h response

> **Pro tier — coming soon · contact@piqrypt.com**

---

## Startup — €990/year  *(nouveau)*

For small teams of 2–10 engineers, AI labs, early-stage startups.

**Quotas**
- **50 agents** · **1,000,000 events/month**

**Everything in Pro, plus:**
- Team workspace (shared agent registry)
- Shared Vigil dashboard (multi-user read)
- Collaborative alert policies

**TrustGate:** manual mode

**Certifications included:** 5 × Timestamp/month

**Support:** Priority email — 24h response

---

## Team — €2,990/year

For AI product teams, robotics teams, quant teams.

**Quotas**
- **150 agents** · **5,000,000 events/month**

**Everything in Startup, plus:**
- Org-wide agent registry
- Cross-team monitoring
- Audit history search
- Policy versioning

**TrustGate:** manual mode

**Certifications included:** 10 × Timestamp/month

**Support:** Priority support

---

## Business — €14,990/year

For organizations requiring governance at scale — regulated AI, robotics fleets, finance.

**Quotas**
- **500 agents** · **20,000,000 events/month**

**Everything in Team, plus:**
- **TrustGate full automated mode** (policy-driven, no human approval required)
- Multi-organization support
- SIEM integration
- Compliance reporting (AI Act · GDPR Article 22 · MiFID II)
- Deployment templates
- On-premise deployment (option)

**Certifications included:** 5 × Post-Quantum/month

**Support:** Dedicated support

---

## Enterprise — on demand

For regulated industries, critical infrastructure, large deployments.

**Quotas:** Unlimited agents and events

**Everything in Business, plus:**
- SSO (SAML, OAuth 2.0, OIDC)
- HSM integration · Private signing service
- On-premise deployment (standard)
- SOC2 / ISO 27001 audit support
- Dedicated SLA · Architecture review

**Certifications:** Custom volume

---

## Tiers at a glance

| | Free | Pro | Startup | Team | Business | Enterprise |
|---|---|---|---|---|---|---|
| **Agents** | 3 | 50 | 50 | 150 | 500 | ∞ |
| **Events/month** | 10k | 500k | 1M | 5M | 20M | ∞ |
| **Bridges** | 2 types | ∞ | ∞ | ∞ | ∞ | ∞ |
| **Vigil** | read+write | full | full | full | full | full |
| **Alerts** | CRITICAL | all | all | all | all | all |
| **PDF export** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **.pqz export** | 🔒 | ✅ | ✅ | ✅ | ✅ | ✅ |
| **VRS history** | 7 days | 90 days | 90 days | 90 days | 90 days | ∞ |
| **PQ signatures** | 🔒 | ✅ | ✅ | ✅ | ✅ | ✅ |
| **RFC 3161 TSA** | 🔒 | ✅ | ✅ | ✅ | ✅ | ✅ |
| **TrustGate** | 🔒 | manual | manual | manual | **full auto** | full auto |
| **Multi-org** | 🔒 | 🔒 | 🔒 | 🔒 | ✅ | ✅ |
| **SIEM** | 🔒 | 🔒 | 🔒 | 🔒 | ✅ | ✅ |
| **SSO** | 🔒 | 🔒 | 🔒 | 🔒 | 🔒 | ✅ |
| **HSM** | 🔒 | 🔒 | 🔒 | 🔒 | 🔒 | ✅ |
| **Price/year** | Free | €290–390 | €990 | €2,990 | €14,990 | custom |

---

## Certification Service — à la carte

**Independent third-party certification for PiQrypt audit bundles.**

See full details → [CERTIFICATION_PRICING.md](CERTIFICATION_PRICING.md)

### Certifications included per tier

| Tier | Simple (€9) | Timestamp (€29) | Post-Quantum (€99) |
|---|---|---|---|
| Free | 1 (activation) | — | — |
| Pro (Early-Bird) | 10/month | — | — |
| Pro (Standard) | 10/month | — | — |
| Startup | — | 5/month | — |
| Team | — | 10/month | — |
| Business | — | — | 5/month |
| Enterprise | custom | custom | custom |

Additional certifications available à la carte at any tier.

### Certification levels

| | Simple · €9 | Timestamp · €29 | Post-Quantum · €99 |
|---|---|---|---|
| Independent CA signature | ✅ | ✅ | ✅ |
| Hash chain verification | ✅ | ✅ | ✅ |
| Public verification badge | ✅ | ✅ | ✅ |
| Portable certified bundle | ✅ | ✅ | ✅ |
| RFC 3161 TSA timestamp | — | ✅ | ✅ |
| Dilithium3 (post-quantum) | — | — | ✅ |
| Encrypted archive | — | — | ✅ |
| Valid horizon | now | regulatory | 50+ years |

**Verification — anyone, anywhere, no PiQrypt needed:**
```bash
piqrypt certify-verify bundle.piqrypt-certified
# ✅ Certified by PiQrypt CA — chain intact — 2026-03-13T14:22:00Z
```

---

## Project Badges *(viral growth — earned automatically)*

Badges that appear in your README when your agents meet the criteria.
No purchase required — earned by configuration.

### 🔵 PiQrypt Verified
```
[![PiQrypt Verified](https://img.shields.io/badge/PiQrypt-Verified-blue)](https://piqrypt.com/verify)
```
**Requirements:** AISS-1 compliant · Ed25519 · hash chain · fork detection
**Available:** Free tier and above

---

### 🟠 PiQrypt Production Ready
```
[![PiQrypt Production](https://img.shields.io/badge/PiQrypt-Production_Ready-orange)](https://piqrypt.com/verify)
```
**Requirements:** encrypted keys · Dilithium3 PQ · RFC 3161 · secure storage
**Available:** Pro tier and above

---

### 🥇 PiQrypt Regulated Infrastructure
```
[![PiQrypt Regulated](https://img.shields.io/badge/PiQrypt-Regulated_Infrastructure-gold)](https://piqrypt.com/verify)
```
**Requirements:** HSM · TrustGate full · compliance policies · certified audit export
**Available:** Business tier and above

---

*PiQrypt — Verifiable memory for autonomous systems.*
*ELv2 Open Core — contact@piqrypt.com — https://piqrypt.com*
