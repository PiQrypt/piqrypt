# PiQrypt License System

## Overview

PiQrypt implements a three-tier licensing system designed to support sustainable open-source development while ensuring accessibility for all use cases.

## License Tiers

### 🆓 Free Tier

**Features:**
- ✅ Complete AISS-1 implementation
- ✅ Ed25519 signatures (RFC 8032)
- ✅ Hash-linked event chains
- ✅ Fork detection
- ✅ Anti-replay protection
- ✅ Export audit format
- ✅ Full CLI access
- ✅ Unlimited events
- ✅ No time restrictions

**Ideal For:**
- Individual developers
- Small projects
- Learning and experimentation
- Open source projects (non-commercial)

**License Key:** Not required

---

### 💼 Pro Tier - $390/year

**Everything in Free, plus:**

#### AISS-2 Features
- ✅ **Post-quantum signatures** (Dilithium3)
- ✅ **Hybrid signatures** (Ed25519 + Dilithium3)
- ✅ Future-proof cryptography
- ✅ NIST PQC compliant

#### Professional Features
- ✅ **RFC 3161 Trusted Timestamping**
  - Legal-grade time proofs
  - Third-party attestation
  - Court-admissible evidence

- ✅ **Witness Network**
  - Distributed proof of existence
  - 5+ independent attestors
  - Non-repudiation guarantees

- ✅ **Blockchain Anchoring**
  - Bitcoin/Ethereum anchoring
  - Public proof of existence
  - Immutable timestamps

- ✅ **Priority Support**
  - Direct email support
  - 24-hour response time
  - Video calls available

- ✅ **Commercial Use Rights**
  - Full commercial deployment
  - White-label options
  - Custom integrations

**Ideal For:**
- Regulated industries (finance, healthcare)
- Enterprise deployments
- Mission-critical systems
- Legal/compliance requirements

**License Key:** Required (validated offline)

---

### 🌟 OSS Tier - Free

**All Pro features for qualified open source projects**

**Requirements:**
- ✅ OSI-approved open source license
- ✅ Public repository
- ✅ Active development (3+ commits/month)
- ✅ Clear documentation
- ✅ Proper attribution to PiQrypt

**Application Process:**
1. Submit application at piqrypt.org/oss
2. Provide repository link
3. Receive license key within 48h
4. Renew annually (automatic if requirements met)

**Ideal For:**
- Open source projects
- Academic research
- Non-profit organizations
- Community tools

**License Key:** Required (free, annually renewed)

---

## License Verification

### Offline Validation

PiQrypt validates licenses **entirely offline** using cryptographic signatures:

```python
from piqrypt import verify_license

# License key is signed by PiQrypt
license_info = verify_license("YOUR_LICENSE_KEY")

if license_info.tier == "pro":
    # Enable Pro features
    enable_dilithium()
    enable_witness_network()
    enable_timestamping()
```

### No Phone Home

- ✅ **No internet required** for validation
- ✅ **No tracking** of usage
- ✅ **No telemetry** unless explicitly opted-in
- ✅ **Privacy-first** design

### License Key Format

```
PIQRYPT-v1-PRO-{SIGNATURE}
PIQRYPT-v1-OSS-{SIGNATURE}
```

Keys are:
- Cryptographically signed
- Contain tier information
- Include expiration date (Pro/OSS only)
- Validated using PiQrypt's public key

---

## Feature Matrix

| Feature | Free | Pro | OSS |
|---------|------|-----|-----|
| **AISS-1** |
| Ed25519 signatures | ✅ | ✅ | ✅ |
| Event chains | ✅ | ✅ | ✅ |
| Fork detection | ✅ | ✅ | ✅ |
| Anti-replay | ✅ | ✅ | ✅ |
| Audit export | ✅ | ✅ | ✅ |
| CLI access | ✅ | ✅ | ✅ |
| **AISS-2** |
| Dilithium3 signatures | ❌ | ✅ | ✅ |
| Hybrid signatures | ❌ | ✅ | ✅ |
| Post-quantum ready | ❌ | ✅ | ✅ |
| **Professional** |
| RFC 3161 timestamps | ❌ | ✅ | ✅ |
| Witness network | ❌ | ✅ | ✅ |
| Blockchain anchoring | ❌ | ✅ | ✅ |
| Priority support | ❌ | ✅ | ❌ |
| Commercial use | ⚠️ | ✅ | ❌ |
| White-label | ❌ | ✅ | ❌ |

⚠️ Free tier allows commercial use with attribution

---

## Purchasing Pro License

### Individual License - $1,990/year
- 1 developer
- Unlimited projects
- Commercial use
- Priority support

### Team License - $4,990/year
- Up to 5 developers
- Shared license key
- Unlimited projects
- Priority support
- Quarterly calls

### Enterprise License - Custom
- Unlimited developers
- On-premises deployment
- Custom SLA
- Dedicated support
- Training included

**Purchase at:** https://piqrypt.org/pricing

---

## Applying for OSS License

### Eligibility Criteria

Your project qualifies if it:
1. **Uses OSI-approved license** (MIT, Apache 2.0, GPL, etc.)
2. **Public repository** on GitHub/GitLab/Bitbucket
3. **Active development** (3+ commits in last 30 days)
4. **Clear documentation** (README with usage examples)
5. **Proper attribution** ("Powered by PiQrypt" in README)

### Application Form

```markdown
# OSS License Application

**Project Name:**
**Repository URL:**
**License:** (e.g., MIT)
**Primary Language:**
**Description:** (2-3 sentences)
**Use Case:** How will you use PiQrypt?
**Contributors:** Number of active contributors
```

**Submit to:** oss@piqrypt.org

**Response time:** 48 hours

---

## License Enforcement

### Technical Enforcement

```python
# Pro features are gated
from piqrypt.pro import TrustedTimestamp

try:
    ts = TrustedTimestamp()
except LicenseRequiredError as e:
    print("Pro license required for trusted timestamps")
    print("Upgrade at: https://piqrypt.org/pricing")
```

### Ethical Use Policy

We trust our users. License enforcement is:
- ✅ **Technical** (features gated by license)
- ✅ **Transparent** (clear error messages)
- ❌ **Not invasive** (no phone-home checks)
- ❌ **Not punitive** (graceful degradation)

### Violations

We reserve the right to:
- Revoke license keys for violations
- Request proof of eligibility (OSS tier)
- Audit commercial use (on request)

**However**, we prioritize trust and community over enforcement.

---

## Upgrading Your License

### Free → Pro

```bash
# Add your license key
export PIQRYPT_LICENSE="PIQRYPT-v1-PRO-{YOUR_KEY}"

# Or configure in code
from piqrypt import set_license
set_license("PIQRYPT-v1-PRO-{YOUR_KEY}")

# Pro features now enabled
```

### Free → OSS

After receiving your OSS license key:

```bash
export PIQRYPT_LICENSE="PIQRYPT-v1-OSS-{YOUR_KEY}"
```

### Checking Current License

```bash
piqrypt license info
# License Tier: Free
# Features: AISS-1 (Ed25519)
# Upgrade: https://piqrypt.org/pricing

piqrypt license info
# License Tier: Pro
# Expires: 2026-02-16
# Features: AISS-1, AISS-2, Timestamping, Witness Network
```

---

## FAQ

### Why not fully free?

PiQrypt is a complex cryptographic library requiring:
- Ongoing security audits ($$$)
- Maintenance and bug fixes
- Feature development
- Infrastructure (witness network, etc.)

**Free tier ensures accessibility. Pro tier ensures sustainability.**

### Can I use Free commercially?

**Yes!** Free tier allows commercial use with attribution:
- Add "Powered by PiQrypt" to your README
- Link to https://piqrypt.org
- No revenue sharing required

### What if I can't afford Pro?

Apply for **OSS license** if your project is open source.
Otherwise, Free tier is very capable for most use cases.

### Can I try Pro before buying?

**Yes!** 30-day free trial:
```bash
piqrypt license trial --email your@email.com
```

### Is the license key secure?

Yes:
- Cryptographically signed (Ed25519)
- Cannot be forged
- Validated offline
- Contains expiration date
- Specific to license tier

### What happens when license expires?

**Pro/OSS licenses:**
- Graceful degradation to Free tier
- No data loss
- Existing signatures remain valid
- New Pro features disabled
- 30-day grace period for renewal

---

## Support

### Free Tier
- GitHub Issues
- Community Discussions
- Documentation

### Pro Tier
- support@piqrypt.org
- 24-hour response time
- Video calls available

### OSS Tier
- oss@piqrypt.org
- Best-effort support
- Community priority

---

## License Philosophy

> "We believe cryptographic identity should be accessible to everyone, while advanced features fund sustainable development."

**Our commitments:**
- ✅ Core features always free
- ✅ No vendor lock-in (MIT license)
- ✅ Open source forever
- ✅ Privacy-first (no tracking)
- ✅ Transparent pricing
- ✅ Support open source community

---

**Last Updated:** February 16, 2025
**Version:** 1.1.0
