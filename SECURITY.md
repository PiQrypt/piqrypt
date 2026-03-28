# Security Policy — PiQrypt

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 1.7.1 | ✅ Current stable | AISS-1 + AISS-2, VRS, TSI, A2C, Vigil, TrustGate, 9 bridges |
| 1.7.x | ✅ Security patches only | |
| 1.6.x | ✅ Security patches only | |
| 1.5.x | ⚠️ End of support | Upgrade recommended |
| < 1.5 | ❌ Not supported | |

---

## Reporting a Vulnerability

PiQrypt handles cryptographic identities and audit chains for autonomous AI agents.
Any vulnerability in these areas has potential legal and operational impact for our users.

**Email:** security@piqrypt.com
**Subject:** `[SECURITY] Vulnerability Report`
**PGP:** Available on request at security@piqrypt.com

**Include in your report:**
- Affected version and component (aiss, rfc3161, key_store, chain, vigil, trustgate…)
- Steps to reproduce
- Potential impact
- Suggested fix if any

**Please do NOT:**
- Open a public GitHub issue before coordinated disclosure
- Disclose publicly before a fix is available
- Test against third-party production systems

---

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | 48 hours |
| Initial assessment | 5 business days |
| Fix or workaround | 15 business days |
| Public disclosure | After fix + 30 days |

---

## Cryptographic Primitives

| Component | Algorithm | Standard | Quantum-resistant |
|-----------|-----------|----------|:-----------------:|
| Agent signatures (AISS-1, default) | Ed25519 | RFC 8032 | ❌ |
| Agent signatures (AISS-2, Pro+) | Dilithium3 | NIST FIPS 204 | ✅ |
| Key encryption at rest | AES-256-GCM | NIST FIPS 197 | — |
| Key derivation | scrypt N=2¹⁷ | RFC 7914 | — |
| Hash chain | SHA-256 | NIST FIPS 180-4 | — |
| Trusted timestamps | RFC 3161 | IETF | — |
| JSON canonicalization | RFC 8785 | IETF | — |
| Licence JWT | Ed25519 | RFC 8032 | — |

> **Note on post-quantum:** AISS-1 (Free/Pro default) uses Ed25519 which is **not**
> quantum-resistant. AISS-2 (Pro+, `pip install piqrypt[post-quantum]`) adds
> Dilithium3 for post-quantum signatures.

---

## Threat Model

### What PiQrypt protects against
- Post-event log modification or deletion
- Identity repudiation between agents (Ed25519 / Dilithium3 signatures)
- Timeline alteration when TSA RFC 3161 timestamps are used
- Behavioural anomalies: concentration, entropy drop, synchronisation, silence break
- Unsupervised critical agent actions (TrustGate — Pro+)

### What PiQrypt does NOT protect against
- Compromised private keys — if the host is compromised before stamping, all bets are off
- Malicious logic executing before the event is stamped
- Fully compromised host environments
- Vulnerabilities in underlying libraries (PyNaCl, cryptography)
- Network attacks against TSA servers (graceful degradation applies)

---

## Key Storage

| Tier | Storage | Protection |
|------|---------|-----------|
| Free | `private.key.json` plaintext | OS file permissions only |
| Pro+ | `private.key.enc` encrypted | AES-256-GCM + scrypt N=2¹⁷ (~128 MB RAM/attempt) |
| Enterprise | HSM integration available | Contact sales@piqrypt.com |

**CRITICAL:** Never commit `private.key.json` or `private.key.enc` to version control.
The provided `.gitignore` excludes all key files — verify before every push.

---

## Known Limitations (v1.7.1)

| Limitation | Impact | Planned fix |
|-----------|--------|-------------|
| `verify_tsa_token()` checks DER structure only — does not verify TSA signature (CMS/PKCS7) | A forged token could pass as "verified" | v1.8.4 — full CMS verification |
| JSON flat-file event storage — not designed for >100k events/agent | High-frequency agents (>10 events/s) will degrade | v2.0 — PostgreSQL backend |
| Vigil/TrustGate use static `VIGIL_TOKEN`/`TRUSTGATE_TOKEN` env var | No per-user auth | v1.8.4 — OIDC/SSO |
| `license.py` HMAC validation (Free) is client-side | Motivated developer can bypass | By design for Free tier — Pro+ uses Ed25519 JWT |

---

## Licence Security Model

- **Free tier:** HMAC local token — offline, no server calls, bypassable by a motivated developer. Acceptable for a free tier — no payment data at risk.
- **Pro+ tiers:** Ed25519 JWT signed by PiQrypt's private key (never leaves `api.piqrypt.com`). Verification is 100% offline using the embedded public key. Cannot be forged without the private key.
- **Network calls:** Only at renewal time (monthly/annual). Zero heartbeat, zero telemetry, zero data about your agents leaves your infrastructure.

---

## Responsible Disclosure

We appreciate responsible security research.
Researchers who report valid vulnerabilities will be credited in our changelog (with permission).

**Contact:** security@piqrypt.com

**PiQrypt Inc.**
e-Soleau primary deposit: DSO2026006483 — 19 February 2026
e-Soleau addendum:        DSO2026009143 — 12 March 2026

---

**Intellectual Property Notice**

Core protocol concepts described in this document were deposited
via e-Soleau with the French National Institute of Industrial Property (INPI):

Primary deposit:  DSO2026006483 — 19 February 2026
Addendum:         DSO2026009143 — 12 March 2026

PCP (Proof of Continuity Protocol) is an open protocol specification.
It may be implemented independently by any compliant system.
PiQrypt is the reference implementation.

© 2026 PiQrypt — contact@piqrypt.com
