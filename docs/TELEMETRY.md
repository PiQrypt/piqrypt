# Telemetry System

**Version:** 1.7.1
**Date:** 2026-03-12
**Status:** Current

---

## Overview

PiQrypt includes **optional, privacy-first telemetry** to help improve the product while respecting user privacy.

## Core Principles

1. **Opt-in only** — Disabled by default
2. **Anonymous** — No personal data
3. **Transparent** — See exactly what's sent
4. **Minimal** — Only usage statistics
5. **Respectful** — Easy to disable anytime

---

## Quick Start

### Enable Telemetry

```bash
piqrypt telemetry enable
```

### Disable Telemetry

```bash
piqrypt telemetry disable
```

### Check Status

```bash
piqrypt telemetry status
# Telemetry: Disabled
# Last sent: Never
```

---

## What Data is Collected

### ✅ Collected (Anonymous)

**Usage Statistics:**
- Feature usage counts (e.g., "stamped 100 events")
- Command frequency
- License tier (Free, Pro, OSS)
- Python version
- PiQrypt version
- Operating system
- Timestamp (UTC)

**Performance Metrics:**
- Average operation duration
- Event chain lengths
- Error counts (no error details)

**Example payload:**
```json
{
  "version": "1.8.3",
  "python": "3.10",
  "os": "linux",
  "license_tier": "free",
  "timestamp": "2026-03-02T14:30:00Z",
  "metrics": {
    "events_stamped": 1000,
    "chains_verified": 50,
    "forks_detected": 2,
    "avg_stamp_duration_ms": 2.3,
    "commands": {
      "stamp": 1000,
      "verify": 500,
      "audit": 50
    }
  }
}
```

### ❌ Never Collected

- ❌ Personal information (names, emails, IPs)
- ❌ Agent IDs
- ❌ Private keys or passphrases
- ❌ KeyStore files or contents
- ❌ Payloads or data content
- ❌ Signatures
- ❌ Hostnames or machine IDs
- ❌ File paths
- ❌ Geographic location

---

## How It Works

### Transmission

- **Frequency:** Once per day (00:00 UTC)
- **Method:** HTTPS POST to telemetry.piqrypt.org
- **Async:** Non-blocking
- **Retry:** 3 attempts, then discard
- **Timeout:** 5 seconds max
- **Failure:** Silently ignored — never breaks your app

### Storage (Local)

All telemetry stored locally first:
```
~/.piqrypt/telemetry.json
```

Inspect anytime:
```bash
cat ~/.piqrypt/telemetry.json
```

---

## Privacy Guarantees

**No way to identify users:**
- No unique IDs sent
- No IP addresses logged
- No fingerprinting
- No session correlation

```
We know: "Someone used stamp_event 1000 times"
We DON'T know: "User X used stamp_event"
```

**Compliance:**
- **GDPR:** No personal data = no consent needed
- **CCPA:** No data sold
- **HIPAA:** No PHI collected

---

## Configuration

### Basic

```python
from piqrypt import configure_telemetry

configure_telemetry(
    enabled=True,
    frequency="daily",
    endpoint="https://telemetry.piqrypt.org"
)
```

### Environment Variables

```bash
export PIQRYPT_TELEMETRY=false
export PIQRYPT_TELEMETRY=true
export PIQRYPT_TELEMETRY_ENDPOINT=https://your-server.com
```

---

## Metrics Collected

### Usage Metrics

```python
{
  "events_stamped": 1234,
  "events_verified": 567,
  "chains_validated": 89,
  "identities_created": 12,
  "key_rotations": 3,
  "forks_detected": 2,
  "replay_attacks_blocked": 5,
  "audit_exports": 10,
  "keystore_created": 3,     # v1.8.3
  "agents_registered": 5     # v1.8.3
}
```

### Performance Metrics

```python
{
  "avg_stamp_duration_ms": 2.3,
  "avg_verify_duration_ms": 1.2,
  "avg_chain_validation_ms": 45.6,
  "avg_keystore_load_ms": 420.0    # v1.8.3 — scrypt expected ~400ms
}
```

### Feature Usage

```python
{
  "cli_commands": {
    "stamp": 1000,
    "verify": 500,
    "audit": 50,
    "identity_create": 12,
    "vigil_start": 8           # v1.5.0+
  },
  "behavioral_monitoring": {
    "tsi_computed": 200,       # v1.5.0+
    "a2c_scans": 150,          # v1.5.0+
    "vrs_computed": 200        # v1.5.0+
  }
}
```

### Error Metrics

```python
{
  "errors": {
    "InvalidSignatureError": 5,
    "ForkDetected": 2,
    "ReplayAttackDetected": 5,
    "LicenseRequiredError": 3,
    "KeyStoreAuthError": 1       # v1.8.3
  }
}
```

---

## CLI Commands

### Status

```bash
piqrypt telemetry status
# Telemetry: Enabled
# Frequency: Daily
# Last sent: 2026-03-02 00:00:00 UTC
# Next scheduled: 2026-03-03 00:00:00 UTC
# Events pending: 1,234
```

### Send Now

```bash
piqrypt telemetry send

# Dry run — see what would be sent
piqrypt telemetry send --dry-run
```

### View Pending Data

```bash
piqrypt telemetry show
```

### Clear Data

```bash
piqrypt telemetry clear
```

---

## Opt-Out Best Practices

### For Organizations

```bash
# Ansible
- name: Disable PiQrypt telemetry
  command: piqrypt telemetry disable

# Or via environment
- name: Set telemetry environment variable
  lineinfile:
    path: /etc/environment
    line: 'PIQRYPT_TELEMETRY=false'
```

---

## Transparency

### View Source Code

```
piqrypt/telemetry.py
```

### Data Retention

- **Raw data:** None (only aggregates received)
- **Aggregated stats:** 90 days
- **Reports:** Anonymous summaries

---

## FAQ

**Why is telemetry disabled by default?** Respect for privacy. We want explicit consent.

**Can telemetry identify me?** No. No IDs, IPs, or fingerprints.

**Does it slow down PiQrypt?** No. Async, batched, <1KB payload, sent once daily.

**Can I audit what's sent?** Yes: `piqrypt telemetry show`

**Can I use PiQrypt offline?** Yes. Telemetry fails silently if offline.

**Can I host my own telemetry server?** Yes. Set `PIQRYPT_TELEMETRY_ENDPOINT=https://your-server.com`.

**How do I know you're not lying?** Code is open source: `cat piqrypt/telemetry.py`

---

## Support Telemetry

If you find PiQrypt useful, consider enabling telemetry:

```bash
piqrypt telemetry enable
```

It helps us improve the product, fix bugs faster, and prioritize features — while respecting your privacy 100%.

**Alternative ways to help:**
- ⭐ Star on GitHub
- 🐛 Report bugs via issues
- 💡 Request features
- 🤝 Contribute code (PRs welcome)

---

## Technical Details

### Payload Schema

```json
{
  "schema_version": "1.1",
  "piqrypt_version": "1.8.3",
  "python_version": "3.10.4",
  "os": "linux",
  "license_tier": "free",
  "timestamp": "2026-03-02T14:30:00Z",
  "metrics": {
    "usage": {},
    "performance": {},
    "features": {},
    "errors": {}
  }
}
```

### Security

- ✅ HTTPS only (TLS 1.3)
- ✅ No authentication (anonymous)
- ✅ Rate limited
- ✅ DDoS protection

---

**Last Updated:** 2026-03-12
**Version:** 1.7.1

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
