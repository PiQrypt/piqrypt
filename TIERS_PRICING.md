# PiQrypt — Pricing & Tiers

**Verifiable memory for AI agents.**

PiQrypt is free to use. Paid tiers unlock additional agents,
encrypted storage, post-quantum signatures, and priority support.

---

## Who is this for?

| Profile | Typical need | Recommended tier |
|---|---|---|
| Independent developer | Prove authorship · personal projects | Free |
| AI startup | Production audit trail · compliance | Pro |
| Trading / fintech | High-volume · encrypted · regulatory | Pro |
| Industrial / IoT | Multi-agent · long-term traceability | Pro |
| Enterprise | Governance · multi-tenant · SLA | Enterprise |

---

## Tiers

### Free — forever

For individuals, open-source projects, and evaluation.

- 3 agents
- Ed25519 signatures
- Plaintext local storage
- 50 exports / month
- 1 free Simple certification / month
- Community support

```bash
pip install piqrypt   # immediate · no account · no cloud
```

No credit card. No expiry.

---

### Pro — €290 / year (Early-Bird) · €390 / year (Standard)

For production workloads, compliance-sensitive environments,
and teams that need more than 3 agents.

- 50 agents
- Ed25519 + Dilithium3 (post-quantum)
- AES-256-GCM encrypted local storage
- Unlimited exports
- 10–50 free Simple certifications / month
- TSA timestamps (RFC 3161)
- A2A session support
- Email support (48h / 24h depending on tier)

<div align="center">

<a href="https://buy.stripe.com/4gM6oAeZe9tX6KreEX2VG02">
<img src="https://img.shields.io/badge/Early--Bird_Pro-€290/year-blue?style=for-the-badge&logo=stripe&logoColor=white" alt="Early-Bird Pro €290/year">
</a>
&nbsp;
<a href="https://buy.stripe.com/00wcMY7wMeOhc4L2Wf2VG01">
<img src="https://img.shields.io/badge/Standard_Pro-€390/year-orange?style=for-the-badge&logo=stripe&logoColor=white" alt="Standard Pro €390/year">
</a>

</div>

---

### Enterprise — from €10,000 / year

For organizations requiring governance at scale,
on-premise deployment, or hardware-level security.

- 50 agents
- HSM integration
- REST API + GraphQL
- Multi-tenant architecture
- SSO (SAML, OAuth)
- SLA 99.9%
- On-premise deployment option
- SOC2 / ISO 27001 audit support
- Dedicated support

<div align="center">

<a href="mailto:piqrypt@gmail.com?subject=Enterprise Inquiry">
<img src="https://img.shields.io/badge/Contact_Sales-Enterprise-gold?style=for-the-badge" alt="Enterprise">
</a>

</div>

---

## Use cases by tier

### Free

**Independent developer — content authorship**

You generate documentation, code, or creative work with AI tools.
A hash-signed, timestamped record proves prior existence
without storing any content.

```bash
piqrypt identity create my-agent.json
piqrypt stamp my-agent.json --payload '{"file": "contract_draft_v1", "hash": "..."}'
```

**Open-source project — contribution traceability**

Each automated commit or release decision is signed by its agent identity.
The audit trail is portable and verifiable by any contributor.

> OSS exemption: open-source projects may apply for Pro at no cost.
> Contact: piqrypt@gmail.com — Subject: OSS License Request

---

### Pro

**AI SaaS — production audit trail**

Your product makes recommendations, decisions, or generates
legally relevant content at scale.

PiQrypt signs every agent action with a cryptographic identity.
Encrypted storage protects sensitive payloads at rest.
Exports are portable and independently verifiable.

This directly supports:
- AI Act Article 13 transparency obligations
- GDPR Article 22 automated decision accountability
- Contractual liability management

**Trading / fintech — regulatory compliance**

Automated trading systems, robo-advisors, and financial automation
require tamper-proof records of every decision.

PiQrypt provides:
- Immutable decision logs bound to agent identity
- RFC 3161 trusted timestamps for legal validity
- Dilithium3 post-quantum signatures for long-term integrity
- Export format compatible with regulatory review

Relevant standards: SEC Rule 17a-4 · MiFID II · FINRA

**Multi-agent coordination — session traceability**

Complex pipelines involving LLMs, tool executors, and downstream
systems require structural continuity across actors.

PiQrypt session memory provides:
- Co-signed handshakes before execution begins
- Correlated interaction hashes across agent boundaries
- Reconstructable timelines for incident analysis

---

### Enterprise

**Regulated industry — governance at scale**

Banks, insurers, healthcare providers, and industrial groups
operating across multiple jurisdictions require:

- Unified audit layer across all AI systems
- Independent verifiability without vendor dependency
- Hardware-level key security (HSM)
- Long-term cryptographic resilience (post-quantum)

PiQrypt Enterprise provides a governance foundation
that scales across departments, subsidiaries, and regulatory contexts.

---

## Tier comparison

| | Free | Pro | Enterprise |
|---|---|---|---|
| Agents | 3 | 50 | 50 |
| Ed25519 signatures | ✅ | ✅ | ✅ |
| Dilithium3 (post-quantum) | — | ✅ | ✅ |
| Encrypted storage | — | ✅ AES-256-GCM | ✅ HSM |
| Exports / month | 50 | Unlimited | Unlimited |
| RFC 3161 timestamps | — | ✅ | ✅ |
| A2A session support | ✅ | ✅ | ✅ |
| Certifications included | 1 Simple/mo | 10–50/mo | Custom |
| Support | Community | Email | Dedicated SLA |
| On-premise | — | — | ✅ |
| SSO / multi-tenant | — | — | ✅ |
| **Price** | **Free** | **€290–390/yr** | **on demand** |

---

## Related

- Independent audit certification → [CERTIFICATION.md](CERTIFICATION.md)
- Integration with your framework → [INTEGRATION.md](INTEGRATION.md)
- Technical architecture → [README.md](README.md)

---

*PiQrypt — Verifiable memory for autonomous systems.*  
*MIT License · piqrypt@gmail.com*
