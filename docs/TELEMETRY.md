# Telemetry System

**Version:** 1.5.0  
**Date:** 2026-02-21  
**Status:** Current

---


## Overview

PiQrypt v1.1.0 includes **optional, privacy-first telemetry** to help improve the product while respecting user privacy.

## Core Principles

1. **Opt-in only** - Disabled by default
2. **Anonymous** - No personal data
3. **Transparent** - See exactly what's sent
4. **Minimal** - Only usage statistics
5. **Respectful** - Easy to disable anytime

---

## Quick Start

### Enable Telemetry

```bash
# CLI
piqrypt telemetry enable

# Or in code
from piqrypt import enable_telemetry
enable_telemetry()
```

### Disable Telemetry

```bash
# CLI
piqrypt telemetry disable

# Or in code
from piqrypt import disable_telemetry
disable_telemetry()
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
- Command frequency (e.g., "verify called 50 times")
- License tier (Free, Pro, OSS)
- Python version
- PiQrypt version
- Operating system (Linux, macOS, Windows)
- Timestamp (UTC)

**Performance Metrics:**
- Average operation duration
- Event chain lengths
- Error counts (no error details)

**Example payload:**
```json
{
  "version": "1.1.0",
  "python": "3.10",
  "os": "linux",
  "license_tier": "free",
  "timestamp": "2025-02-16T14:30:00Z",
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

- ❌ **Personal information** (names, emails, IPs)
- ❌ **Agent IDs**
- ❌ **Private keys** (obviously!)
- ❌ **Payloads** or data content
- ❌ **Signatures**
- ❌ **Hostnames** or machine IDs
- ❌ **File paths**
- ❌ **Network information**
- ❌ **Geographic location**

---

## Why Telemetry?

### Benefits to Users

**Better Product:**
- Identify most-used features → prioritize development
- Find performance bottlenecks → optimize
- Discover bugs → fix quickly
- Understand usage patterns → improve UX

**Better Documentation:**
- See where users struggle → improve docs
- Know which features need examples
- Understand common workflows

**Better Roadmap:**
- Data-driven feature priorities
- Focus on what matters most
- Avoid building unused features

### Benefits to PiQrypt

- Measure product-market fit
- Justify continued development
- Demonstrate value to sponsors
- Make informed decisions

---

## How It Works

### Collection

```python
from piqrypt import stamp_event

# Telemetry enabled
event = stamp_event(priv, agent_id, payload)
# → Increments internal counter: events_stamped++

# Periodically (daily), anonymous stats sent
# → No blocking, no slowdown
# → Batched and aggregated
```

### Transmission

- **Frequency:** Once per day (00:00 UTC)
- **Method:** HTTPS POST to telemetry.piqrypt.org
- **Async:** Non-blocking, doesn't slow operations
- **Retry:** 3 attempts, then discard (no queueing)
- **Timeout:** 5 seconds max
- **Failure:** Silently ignored (never breaks your app)

### Storage

- Aggregated statistics only
- No raw events stored
- 90-day retention
- GDPR compliant
- SOC 2 Type II certified endpoint

---

## Privacy Guarantees

### Anonymous by Design

**No way to identify users:**
- No unique IDs sent
- No IP addresses logged
- No fingerprinting
- No tracking cookies
- No session correlation

**Example:**
```
We know: "Someone used stamp_event 1000 times"
We DON'T know: "User X used stamp_event"
```

### Local Control

**All telemetry stored locally first:**
```
~/.piqrypt/telemetry.json
```

You can inspect it anytime:
```bash
cat ~/.piqrypt/telemetry.json
```

**You control when it's sent:**
```bash
# Send now (if enabled)
piqrypt telemetry send

# Or never (if disabled)
piqrypt telemetry disable
```

### Compliance

- **GDPR:** No personal data = no consent needed
- **CCPA:** No selling of data (we don't even collect it)
- **HIPAA:** No PHI collected
- **SOC 2:** Secure transmission and storage

---

## Configuration

### Basic Configuration

```python
from piqrypt import configure_telemetry

configure_telemetry(
    enabled=True,
    frequency="daily",  # daily, weekly, manual
    endpoint="https://telemetry.piqrypt.org"
)
```

### Advanced Configuration

```python
configure_telemetry(
    enabled=True,
    frequency="weekly",
    endpoint="https://telemetry.piqrypt.org",
    timeout=5,  # seconds
    retry_count=3,
    min_interval=86400,  # seconds (1 day)
    proxy=None,  # or "http://proxy:8080"
    verify_ssl=True,
    include_performance=True,
    include_errors=True,
    custom_tags={
        "deployment": "production",
        "region": "eu"
    }
)
```

### Environment Variables

```bash
# Disable via environment
export PIQRYPT_TELEMETRY=false

# Or enable
export PIQRYPT_TELEMETRY=true

# Custom endpoint (for self-hosted)
export PIQRYPT_TELEMETRY_ENDPOINT=https://your-server.com
```

---

## Self-Hosted Telemetry

For enterprises wanting insights without external dependencies:

### Run Your Own Server

```bash
# Docker
docker run -p 8080:8080 piqrypt/telemetry-server

# Or Python
pip install piqrypt-telemetry-server
piqrypt-telemetry-server --port 8080
```

### Configure Clients

```python
configure_telemetry(
    enabled=True,
    endpoint="https://telemetry.yourcompany.com"
)
```

### Dashboard

Access at `http://localhost:8080/dashboard`

Shows:
- Total events stamped
- Active installations
- Feature usage
- Error rates
- Performance metrics

---

## CLI Commands

### Status

```bash
piqrypt telemetry status
# Telemetry: Enabled
# Frequency: Daily
# Last sent: 2025-02-16 00:00:00 UTC
# Next scheduled: 2025-02-17 00:00:00 UTC
# Events pending: 1,234
```

### Enable

```bash
piqrypt telemetry enable

# With options
piqrypt telemetry enable --frequency weekly
```

### Disable

```bash
piqrypt telemetry disable

# Clears pending data
piqrypt telemetry disable --clear
```

### Send Now

```bash
# Send pending telemetry immediately
piqrypt telemetry send

# Dry run (see what would be sent)
piqrypt telemetry send --dry-run
```

### View Pending Data

```bash
# See what will be sent
piqrypt telemetry show

# Output:
{
  "version": "1.1.0",
  "metrics": {
    "events_stamped": 1234,
    "chains_verified": 56
  }
}
```

### Clear Data

```bash
# Clear pending telemetry (doesn't disable)
piqrypt telemetry clear
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
  "audit_exports": 10
}
```

### Performance Metrics

```python
{
  "avg_stamp_duration_ms": 2.3,
  "avg_verify_duration_ms": 1.2,
  "avg_chain_validation_ms": 45.6,
  "p95_stamp_duration_ms": 5.1,
  "p99_stamp_duration_ms": 8.7
}
```

### Feature Usage

```python
{
  "cli_commands": {
    "stamp": 1000,
    "verify": 500,
    "audit": 50,
    "identity_create": 12
  },
  "api_calls": {
    "stamp_event": 1000,
    "verify_signature": 500,
    "verify_chain": 50
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
    "LicenseRequiredError": 3
  }
}
```

### AISS-2 Metrics (Pro/OSS)

```python
{
  "dilithium_signatures": 234,
  "hybrid_signatures": 456,
  "trusted_timestamps": 78,
  "witness_attestations": 90,
  "blockchain_anchors": 12
}
```

---

## Opt-Out Best Practices

### For Users

**Telemetry is opt-in by default.** You don't need to do anything.

If you explicitly enable it and change your mind:
```bash
piqrypt telemetry disable
```

### For Organizations

**Disable for all users** via configuration management:

```bash
# Ansible
- name: Disable PiQrypt telemetry
  command: piqrypt telemetry disable
  become_user: "{{ item }}"
  with_items: "{{ users }}"

# Or via environment
- name: Set telemetry environment variable
  lineinfile:
    path: /etc/environment
    line: 'PIQRYPT_TELEMETRY=false'
```

### For Packages

If you're packaging PiQrypt, **respect user choice:**
```bash
# Don't enable telemetry in post-install scripts
# Let users opt-in themselves
```

---

## Transparency

### View Source Code

Telemetry implementation is open source:
```
piqrypt/telemetry.py
```

See exactly what's collected and sent.

### Audit Transmission

```bash
# See what's about to be sent
piqrypt telemetry send --dry-run

# Or inspect local data
cat ~/.piqrypt/telemetry.json
```

### Data Retention

- **Raw data:** None (we only receive aggregates)
- **Aggregated stats:** 90 days
- **Reports:** Indefinite (anonymous summaries)

### Data Access

- Only PiQrypt core team
- Never sold or shared
- Never used for marketing
- Never used to identify users

---

## FAQ

### Why is telemetry disabled by default?

**Respect for privacy.** We want explicit consent.

### Can telemetry identify me?

**No.** It's designed to be anonymous. No IDs, IPs, or fingerprints.

### Does it slow down PiQrypt?

**No.** Telemetry is:
- Async (non-blocking)
- Batched (not per-operation)
- Lightweight (<1KB payload)
- Cached locally (sent once daily)

### Can I audit what's sent?

**Yes!** 
```bash
piqrypt telemetry show
```

### Can I use PiQrypt offline?

**Yes!** Telemetry fails silently if offline. No errors, no delays.

### What if I'm behind a firewall?

Telemetry will fail to send (silently) and be discarded after 3 retries. Your app continues working normally.

### Does Free tier have telemetry?

**Only if you enable it.** All tiers respect your choice.

### Can I host my own telemetry server?

**Yes!** See "Self-Hosted Telemetry" section above.

### How do I know you're not lying?

**Code is open source.** Audit it:
```bash
cat piqrypt/telemetry.py
```

### What happens to Pro users?

**Same rules apply.** Telemetry is opt-in for everyone.

---

## Support Telemetry

If you find PiQrypt useful, **consider enabling telemetry**:

```bash
piqrypt telemetry enable
```

It helps us:
- ✅ Improve the product
- ✅ Fix bugs faster
- ✅ Prioritize features
- ✅ Justify continued development

**While respecting your privacy 100%.**

---

## Alternative Ways to Help

Don't want to enable telemetry? You can still help:

1. **Star on GitHub** ⭐
2. **Report bugs** (manually)
3. **Request features** (via issues)
4. **Contribute code** (PRs welcome)
5. **Sponsor development** (GitHub Sponsors)
6. **Spread the word** (Twitter, Reddit, etc.)

---

## Technical Details

### Payload Schema

```json
{
  "schema_version": "1.0",
  "piqrypt_version": "1.1.0",
  "python_version": "3.10.4",
  "os": "linux",
  "architecture": "x86_64",
  "license_tier": "free",
  "timestamp": "2025-02-16T14:30:00Z",
  "session_duration_seconds": 3600,
  "metrics": {
    "usage": { /* ... */ },
    "performance": { /* ... */ },
    "features": { /* ... */ },
    "errors": { /* ... */ }
  },
  "custom_tags": { /* optional */ }
}
```

### Endpoint

```
POST https://telemetry.piqrypt.org/v1/collect
Content-Type: application/json
User-Agent: PiQrypt/1.1.0 Python/3.10.4

{
  // payload
}
```

### Response

```
200 OK
{"status": "received", "id": "anon_12345"}
```

Note: `id` is generated server-side, not sent by client.

### Security

- ✅ HTTPS only (TLS 1.3)
- ✅ Certificate pinning
- ✅ No authentication (anonymous)
- ✅ Rate limited (100 req/day per IP)
- ✅ DDoS protection

---

## Roadmap

Future telemetry improvements (all opt-in):

- **v1.2:** Crash reports (if opted-in)
- **v1.3:** Performance profiling (sampling)
- **v2.0:** Usage heatmaps (CLI commands)

**All future additions will:**
- ✅ Remain opt-in
- ✅ Be announced clearly
- ✅ Preserve anonymity
- ✅ Be auditable

---

## Contact

Questions about telemetry?

- **Technical:** telemetry@piqrypt.org
- **Privacy:** privacy@piqrypt.org
- **General:** contact@piqrypt.org

---

**Last Updated:** February 16, 2025
**Version:** 1.1.0
