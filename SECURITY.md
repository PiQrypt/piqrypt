# Security Policy

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 1.10.x | Yes, current | AISS-1, AISS-2.0 (verification) and AISS-2.1, RFC 3161 verification, Signer interface |
| 1.9.x | Critical security fixes only | Upgrade to 1.10 recommended |
| < 1.9 | No | |

---

## Reporting a Vulnerability

PiQrypt handles cryptographic identities and audit chains for autonomous AI agents.
A vulnerability in these areas can have operational and legal consequences for the people who rely on it.

**Email:** security@piqrypt.com
**Subject:** `[SECURITY] Vulnerability Report`
**PGP:** Available on request at security@piqrypt.com

**Include in your report:**
- Affected version and component (aiss, rfc3161, key_store, chain, vigil, trustgate, ...)
- Steps to reproduce
- Potential impact
- Suggested fix if any

**Please do NOT:**
- Open a public GitHub issue before coordinated disclosure
- Disclose publicly before a fix is available
- Test against third-party production systems

A statement in our documentation that the code does not support is also a defect. Report it the same way.

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

| Component | Algorithm | Reference | Quantum-resistant |
|-----------|-----------|-----------|:-----------------:|
| Event signatures, AISS-1 | Ed25519 | RFC 8032 | No |
| Event signatures, AISS-2.1 | Ed25519 and ML-DSA-65, both required | RFC 8032, NIST FIPS 204 | Yes |
| Event signatures, AISS-2.0 (legacy, verification) | Ed25519 and ML-DSA-65, both required | RFC 8032, NIST FIPS 204 | Yes |
| Chain hash, AISS-1 and AISS-2.0 | SHA-256 | NIST FIPS 180-4 | n/a |
| Chain hash, AISS-2.1 | SHA-512 | NIST FIPS 180-4 | n/a |
| Canonical JSON, AISS-2.1 | JCS | RFC 8785 | n/a |
| Key encryption at rest | AES-256-GCM, key derived with scrypt (N = 2^17, r = 8, p = 1 by default) | NIST SP 800-38D, RFC 7914 | n/a |
| Trusted timestamps | RFC 3161, verified only with the optional `timestamp` extra and a trust root you configure | RFC 3161 | n/a |
| Licence token (Pro and above) | Ed25519 (JWT, EdDSA) | RFC 8032 | No |

"Reference" names the specification being implemented. No component of PiQrypt has been validated
under a NIST validation programme.

> **Post-quantum note.** AISS-1 uses Ed25519 only, which a sufficiently large quantum computer
> could break. AISS-2.1 accepts an event only if both its Ed25519 and its ML-DSA-65 signatures
> verify. Install `piqrypt[post-quantum]` (liboqs-python, Python 3.10 or later) for signing. The
> pure-Python fallback (dilithium-py) is not constant time and its authors say it is not meant for
> cryptographic use.

For the full list of what is and is not claimed, see
[docs/LIMITS_AND_POSTURE.md](docs/LIMITS_AND_POSTURE.md).

---

## Threat Model

### What PiQrypt helps with
- Detecting after-the-fact modification, reordering or removal of events inside a hash chain
  (it does not prevent them, and removing the last events of a chain is not detectable without an
  external anchor)
- Letting a third party check which key signed an event, offline
- Showing that an event existed before a given time, when a timestamp token has been verified
  against a trust root you configured
- Flagging statistical anomalies in agent behaviour (Vigil). This is a monitoring aid, not a
  guarantee.
- Requiring a human decision before critical agent actions (TrustGate)

### What PiQrypt does NOT protect against
- Compromised private keys. If the host is compromised before an event is stamped, the event is
  signed anyway.
- Malicious logic that runs before an event is stamped, or events that describe actions falsely
- A local attacker who can read a plaintext key file, process memory or swap
- Side-channel attacks against the pure-Python ML-DSA-65 fallback
- Binding a key to a real-world person or organisation
- Vulnerabilities in underlying libraries (PyNaCl, cryptography, liboqs, dilithium-py,
  rfc3161-client)
- A TSA that lies about the time, or a TSA certificate that was revoked (revocation is not checked)

---

## Key Storage

| Key | File | Protection |
|-----|------|-----------|
| Ed25519, passphrase given | `private.key.enc` (format v1) | AES-256-GCM, scrypt (about 128 MB of memory per attempt at the default cost) |
| Ed25519, no passphrase (API only) | `private.key.json` | Plaintext, operating system file permissions only |
| ML-DSA-65 (hybrid identities) | `private_pq.key.enc` (format v2) | AES-256-GCM with authenticated header, scrypt, passphrase mandatory (8 characters minimum) |
| Hardware module or KMS | Signer interface | Interface only. No hardware module has been tested. |

File permissions 0o600 are applied on POSIX systems only. Erasure of key material in memory is
best effort and does not remove the exposure window.

**Never commit key files to version control.** The provided `.gitignore` excludes them; check it
before every push.

Keys encrypted by versions before 1.10 are read as before. A `private.key.json.bak` left by an
earlier version of `identity secure` is not removed automatically; delete it yourself once you
have checked that the encrypted key opens.

---

## Known Limitations (v1.10.0)

| Limitation | Impact | Status |
|-----------|--------|--------|
| dilithium-py fallback is not constant time | Signing with it may leak key information to a local observer | Use liboqs for signing |
| liboqs and dilithium-py interoperability workflow has never been run | No recorded evidence that the two backends agree on PiQrypt messages | Run the manual workflow, then publish the result |
| No revocation check on TSA certificates; no trust root shipped | A revoked TSA certificate is not detected; you must configure roots | Documented in `docs/TIMESTAMPS.md` |
| DigiCert and Entrust tokens verify as `invalid` | Fails closed. The parser (rfc3161-client 1.0.9) cannot read them. | Upstream limitation |
| Attestations read by `piqrypt certify-verify` hold no hash of the audit data | The command cannot link an attestation to the data in the same file | Planned |
| Vigil and TrustGate use one static token from the environment, over plain HTTP | No per-user authentication, no TLS | Bind to 127.0.0.1 or put a reverse proxy in front |
| The Free-tier token is checked with a local HMAC | Can be bypassed by a motivated developer | By design for the Free tier |
| `verify_chain` does not require a genesis event; forks are found by comparing two logs | A chain with a cut head can verify | To settle in the AISS-2.1 text |
| TrustGate HTTP approvals are not authenticated per person | The approve and reject endpoints build the session from the principal name in the request and sign it with a constant secret that is in the source. A holder of the TrustGate token can record an approval under any registered principal | Do not treat an HTTP approval as proof of who approved. Planned for 1.10.1 |
| The TrustGate journal protects only part of each entry | The hash covers 12 fields; `agent_name`, `approved_by`, `approval_timestamp` and `state` can be edited undetected. Entries are unsigned and not anchored, so removing the last entries is not detected, and `verify_chain` fails after `purge_old` removes the oldest file | Treat it as an operational log and keep copies elsewhere. Planned for 1.10.1 |
| `get_scope_assessment` matches keywords inside words | "phi" matches "sophisticated" and "test" matches "latest". It is a heuristic, not a determination | Do not use it for a decision. Whole-word matching planned |

---

## Licence Security Model

- **Free tier:** local HMAC token, no network call, bypassable by a motivated developer.
  Acceptable for a free tier: no payment data is at risk.
- **Pro and above:** Ed25519 JWT (EdDSA) verified offline with the public key embedded in the
  package.
- Verification of chains and attestations is never gated by a licence.
- For what the software sends over the network, see [docs/TELEMETRY.md](docs/TELEMETRY.md).

---

## Responsible Disclosure

We appreciate responsible security research.
Researchers who report valid vulnerabilities will be credited in our changelog (with permission).

**Contact:** security@piqrypt.com

**PiQrypt Inc.**
e-Soleau primary deposit: DSO2026006483 (19 February 2026)
e-Soleau addendum: DSO2026009143 (12 March 2026)

---

**Intellectual Property Notice**

Core protocol concepts described in this document were deposited via e-Soleau with the French
National Institute of Industrial Property (INPI):

Primary deposit: DSO2026006483 (19 February 2026)
Addendum: DSO2026009143 (12 March 2026)

PCP (Proof of Continuity Protocol) is an open protocol specification.
It may be implemented independently by anyone.
PiQrypt is the reference implementation.

(c) 2026 PiQrypt, contact@piqrypt.com
