# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.4.x   | :white_check_mark: |
| 1.3.x   | :white_check_mark: |
| 1.2.x   | :white_check_mark: |
| < 1.2   | :x:                |

---

## Reporting a Vulnerability

**We take security seriously.** If you discover a security vulnerability, please report it responsibly.

### 🔒 Private Disclosure

**Email:** piqrypt@gmail.com  
**Subject:** `[SECURITY] Vulnerability Report`

**Include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Please DO NOT:**
- ❌ Open a public GitHub issue
- ❌ Disclose publicly before we've had a chance to fix
- ❌ Exploit the vulnerability

---

## Response Timeline

| Step | Timeline |
|------|----------|
| **Acknowledgment** | Within 24 hours |
| **Initial assessment** | Within 3 business days |
| **Fix & patch** | Within 14 days (critical), 30 days (medium) |
| **Public disclosure** | After patch release |

---

## Security Guarantees

### Cryptography

**Algorithms:**
- Ed25519 (AISS-1.0): 128-bit security, NIST approved
- Dilithium3 (AISS-2.0): 256-bit PQ security, NIST FIPS 204
- SHA-256: Collision resistance 2^128
- AES-256-GCM: Authenticated encryption, NIST approved

**Key Management:**
- Private keys: 0600 permissions (Unix), encrypted at rest (Pro)
- Master key: PBKDF2-SHA256 (100k iterations)
- No keys transmitted over network
- No keys logged

### Audit Trail

**Guarantees:**
- Hash chain: Any modification detectable (SHA-256 collision resistance)
- Signatures: Non-repudiation (Ed25519/Dilithium3)
- Fork detection: Double-spend temporal attempts detected
- Canonical history: Deterministic resolution (RFC §6)

**No guarantees against:**
- ❌ Compromise of private key (user responsibility)
- ❌ Physical access to unlocked memory (Pro)
- ❌ Side-channel attacks (timing, power analysis)

---

## Known Limitations

### Free Tier

- **Plaintext storage:** Events stored unencrypted in `~/.piqrypt/events/plain/`
  - **Mitigation:** Use Pro tier for AES-256-GCM encryption
  
- **Limited replay protection:** Local nonce tracking only
  - **Mitigation:** Use Pro + A2A network (v1.6) for network-wide detection

### Pro Tier

- **Passphrase security:** Master key strength = passphrase strength
  - **Mitigation:** Use strong passphrase (min 16 chars, high entropy)
  
- **Memory unlocked session:** Master key in RAM while unlocked
  - **Mitigation:** Lock session when not in use (`piqrypt memory lock`)

### All Tiers

- **Quantum attacks (Ed25519):** AISS-1.0 vulnerable to Shor's algorithm
  - **Mitigation:** Migrate to AISS-2.0 (Dilithium3 hybrid)
  
- **Trusted timestamp attacks:** TSA compromise could forge timestamps
  - **Mitigation:** Use multiple TSAs (future), cross-verify

---

## Security Best Practices

### For Users

1. **Protect private keys**
   - 0600 permissions on identity files
   - Never commit to git
   - Backup securely (offline, encrypted)

2. **Use strong passphrases (Pro)**
   - Min 16 characters
   - High entropy (mix uppercase, lowercase, numbers, symbols)
   - Use password manager

3. **Lock memory when idle (Pro)**
   ```bash
   piqrypt memory lock
   ```

4. **Verify exports**
   ```bash
   piqrypt verify-export audit.json audit.json.cert
   ```

5. **Enable 2FA** (future: account management)

### For Developers

1. **Validate inputs**
   - Sanitize payloads before signing
   - Check event structure (JSON schema)

2. **Handle errors gracefully**
   - Don't leak private keys in error messages
   - Don't log sensitive data

3. **Use authority chains**
   - Delegate minimal scope
   - Short validity periods (days, not years)
   - Revoke compromised delegations

4. **Monitor for forks**
   - Alert on fork detection
   - Investigate immediately

---

## Compliance

**PiQrypt helps meet:**
- SOC2 Type 2 (audit controls)
- ISO 27001 (event logging)
- HIPAA (audit trail, encryption)
- GDPR (transparency, integrity)
- NIST PQC (post-quantum readiness)

**Certifications:**
- ⏳ SOC2 Type 2 (in progress, Q3 2026)
- ⏳ ISO 27001 (planned, Q4 2026)

---

## Responsible Disclosure Hall of Fame

*Thank you to the following researchers for responsible disclosure:*

(None yet — be the first!)

---

## Contact

**Security issues:** piqrypt@gmail.com  
**General support:** piqrypt@gmail.com  
**GitHub:** https://github.com/piqrypt/piqrypt/security

---

**Last updated:** 2026-02-19
