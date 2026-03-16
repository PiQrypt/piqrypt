# PiQrypt — Certification Service

**Independent third-party certification for PiQrypt audit bundles.**

PiQrypt memory is verifiable locally without any external service.
Certification is an optional step — for contexts where independent,
third-party attestation is required.

---

## What certification adds

Local verification confirms that your audit chain is intact.

Certification adds:

- An independent signature from PiQrypt certification authority
- A verifiable timestamp from a trusted third-party TSA (RFC 3161)
- A portable certified bundle — verifiable by anyone, anywhere
- No dependency on your infrastructure for future verification

The certified bundle can be submitted to regulators, courts,
auditors, or counterparties without sharing any original content.

---

## What is never shared

Certification operates on hashes only.

- Raw agent outputs are never transmitted
- Prompt content is never shared
- Decision payloads are never exposed
- Only the cryptographic structure of your audit chain is processed

This makes certification compatible with GDPR, HIPAA,
and other data minimization requirements.

---

## Certification levels

### Simple · €9

For contractual disputes, IP protection, and general proof of existence.

- Independent cryptographic signature
- Hash verification of your entire chain
- Public verification badge
- Portable export bundle (.piqrypt-certified)

**Verification:**
```bash
piqrypt certify-verify bundle.piqrypt-certified
# ✅ Certified by PiQrypt CA — chain intact
```

<div align="center">

<a href="https://buy.stripe.com/eVq28k6sIay13yfgN52VG05">
<img src="https://img.shields.io/badge/Certify_Now-Simple_€9-blue?style=for-the-badge&logo=stripe&logoColor=white" alt="Simple €9">
</a>

</div>

---

### Timestamp · €29

For regulatory contexts, GDPR compliance, and legal proceedings
where an independently verifiable timestamp is required.

- Everything in Simple
- RFC 3161 trusted timestamp from an accredited TSA
- Independent proof of when the chain existed
- GDPR / HIPAA compatible
- Suitable for regulatory submission

**When to use:**
Automated decision systems subject to GDPR Article 22.
Financial records subject to SEC or MiFID II retention rules.
Any context where "when did this happen" must be independently provable.

<div align="center">

<a href="https://buy.stripe.com/8x214g3gw8pT4Cj68r2VG04">
<img src="https://img.shields.io/badge/Certify_Now-Timestamp_€29-orange?style=for-the-badge&logo=stripe&logoColor=white" alt="Timestamp €29">
</a>

</div>

---

### Post-Quantum · €99

For long-term archival, critical infrastructure,
and contexts where proof must remain valid for decades.

- Everything in Timestamp
- Dilithium3 signature (NIST FIPS 204)
- AES-256-GCM encrypted archive
- Proof designed to remain valid for 50+ years
- Resistant to future quantum computing attacks

**When to use:**
Medical records, industrial certifications, financial archives,
intellectual property requiring long-term legal standing.
Any context where today's proof must be verifiable in 2050.

<div align="center">

<a href="https://buy.stripe.com/aFa14g4kA5dH4Cj68r2VG03">
<img src="https://img.shields.io/badge/Certify_Now-Post--Quantum_€99-gold?style=for-the-badge&logo=stripe&logoColor=white" alt="Post-Quantum €99">
</a>

</div>

---

## Certification levels compared

| | Simple | Timestamp | Post-Quantum |
|---|---|---|---|
| Independent CA signature | ✅ | ✅ | ✅ |
| Hash chain verification | ✅ | ✅ | ✅ |
| Public verification badge | ✅ | ✅ | ✅ |
| Portable certified bundle | ✅ | ✅ | ✅ |
| RFC 3161 TSA timestamp | — | ✅ | ✅ |
| GDPR / HIPAA compatible | ✅ | ✅ | ✅ |
| Dilithium3 (post-quantum) | — | — | ✅ |
| Encrypted archive | — | — | ✅ |
| Valid horizon | Now | Regulatory | 50+ years |
| **Price** | **€9** | **€29** | **€99** |

---

## How it works

```
1. Export your audit chain locally
   piqrypt export audit.json

2. Submit at checkout
   No content shared — hashes only

3. Receive certified bundle by email
   In under 5 minutes

4. Verify anytime, anywhere
   piqrypt certify-verify bundle.piqrypt-certified
   ✅ Certified by PiQrypt CA
```

No integration required. Works with any existing PiQrypt audit chain.
Works without PiQrypt installed — share the bundle directly with auditors.

---

## Who is this for?

### Independent developer / creator

You need to prove that a piece of work existed before a given date.

A Simple or Timestamp certification provides a portable,
independently verifiable proof of prior existence —
without storing any content.

Relevant for: IP disputes · freelance contracts · content authorship

---

### AI SaaS company

A client disputes a recommendation your system made.
A regulator requests evidence of system behavior.

A Timestamp certification provides a court-admissible,
independently verified record of your agent's audit chain
at the time of the disputed event.

Relevant for: legal-tech · fintech · health-tech · HR automation

---

### Compliance officer / legal team

Your organization needs to demonstrate AI system integrity
to a regulator, auditor, or counterparty.

PiQrypt certification provides a portable bundle
that can be submitted without sharing any underlying data.

Relevant for: AI Act compliance · GDPR Article 22 · SEC recordkeeping
· ISO 27001 audit support · contractual due diligence

---

### Long-term archival

You need proof that will remain valid regardless of
future developments in computing — including quantum.

Post-Quantum certification uses Dilithium3 (NIST FIPS 204)
to produce signatures that remain computationally secure
for the foreseeable future.

Relevant for: medical records · industrial certifications
· financial archives · critical IP · government systems

---

## Certification included with paid tiers

| Tier | Certifications included |
|---|---|
| Free | 1 Simple (à l'activation) |
| Pro (Early-Bird €290) | 10 Simple / month |
| Pro (Standard €390) | 50 Simple / month |
| Team | 100 Simple / month |
| Business | Custom volume |
| Enterprise | Custom volume |

Additional certifications available à la carte at the prices above.

---

## Related

- Tier pricing and deployment options → [TIERS_PRICING.md](TIERS_PRICING.md)
- Technical architecture → [README.md](README.md)
- Integration guide → [INTEGRATION.md](INTEGRATION.md)

---

*PiQrypt — Verifiable memory for autonomous systems.*
*MIT License · contact@piqrypt.com*

---

**Intellectual Property Notice**

Primary deposit:  DSO2026006483 — 19 February 2026
Addendum:         DSO2026009143 — 12 March 2026

PCP is an open protocol specification.
PiQrypt is the reference implementation.

© 2026 PiQrypt — contact@piqrypt.com
