# PiQrypt Logging Guide

## Overview

PiQrypt provides structured logging for developers to debug and monitor agent operations.

**Logs are:**
- ✅ Human-readable (timestamped messages)
- ✅ Machine-parseable (JSON format)
- ✅ Privacy-conscious (agent IDs truncated)
- ✅ Opt-in verbosity (via environment variables)

---

## Log Levels

```bash
# Set log level via environment variable
export PIQRYPT_LOG_LEVEL=DEBUG  # Options: DEBUG, INFO, WARNING, ERROR

# Default: INFO
```

### Level Descriptions

| Level | When to Use |
|-------|-------------|
| **DEBUG** | Development, troubleshooting (verbose) |
| **INFO** | Normal operations (default) |
| **WARNING** | Anomalies detected (forks, TSI drift, VRS alert) |
| **ERROR** | Failures (replay attacks, invalid signatures, KeyStore auth failure) |

---

## Log Format

### Console Output (Human-Readable)

```
[2026-03-02 15:30:45] INFO: {"timestamp": "2026-03-02T15:30:45Z", "event_type": "identity_created", "message": "Agent identity created", "agent_id": "5Z8nY7KpL9mN3qR4...", "data": {"algorithm": "Ed25519"}}
```

### Parsed JSON

```json
{
  "timestamp": "2026-03-02T15:30:45Z",
  "event_type": "identity_created",
  "message": "Agent identity created",
  "agent_id": "5Z8nY7KpL9mN3qR4...",
  "data": {
    "algorithm": "Ed25519"
  }
}
```

---

## Logged Events

### Identity Operations

```
event_type: identity_created
  - algorithm: "Ed25519" | "ML-DSA-65"

event_type: identity_rotated
  - old_agent_id: "..."
  - new_agent_id: "..."
```

### KeyStore Operations (v1.7.0)

```
event_type: keystore_created
  - scrypt_n: 131072
  - file: "agent.key.enc"

event_type: keystore_loaded
  - agent_id: "5Z8n...A2z"

event_type: keystore_auth_failed
  - reason: "wrong passphrase" | "magic bytes invalid" | "truncated file"

event_type: key_erased_from_ram
  - agent_id: "5Z8n...A2z"
```

### AgentRegistry Operations (v1.7.0)

```
event_type: agent_registered
  - name: "trading_bot"
  - agent_id: "5Z8n...A2z"

event_type: path_traversal_blocked
  - name: "../etc/passwd"
  - reason: "name contains path separator"
```

### Event Signing

```
event_type: event_signed
  - event_type: User-defined event type
  - nonce: "550e8400-e29b-..."

event_type: event_verified
  - event_hash: "a3f7e8c9..."
```

### Chain Operations

```
event_type: chain_verified
  - events: 100
  - chain_hash: "b4f8e0c2..."
```

### Security Events

```
event_type: fork_detected (WARNING)
  - hash: "c5g9f1d3..."
  - branches: 2

event_type: replay_detected (ERROR)
  - nonce: "550e8400-e29b-..."

event_type: signature_invalid (ERROR)
  - agent_id: "5Z8n...A2z"
```

### Behavioral Monitoring Events (v1.5.0+)

```
event_type: tsi_state_changed (WARNING if UNSTABLE/CRITICAL)
  - agent_id: "5Z8n...A2z"
  - old_state: "STABLE"
  - new_state: "WATCH"
  - delta_24h: -0.09

event_type: a2c_anomaly_detected (WARNING/ERROR)
  - agent_id: "5Z8n...A2z"
  - scenario: "concentration_soudaine" | "chute_entropie" | ...
  - risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

event_type: vrs_threshold_crossed (WARNING)
  - agent_id: "5Z8n...A2z"
  - vrs: 0.51
  - state: "ALERT"
```

### License & Telemetry

```
event_type: license_activated
  - tier: "pro" | "oss" | "enterprise"
  - license_id: "a3f29b4c..."

event_type: telemetry_enabled
event_type: telemetry_disabled
```

---

## Usage Examples

### Python API

```python
from aiss.logger import (
    log_identity_created,
    log_event_signed,
    log_chain_verified,
    log_fork_detected
)

# Identity created
log_identity_created(agent_id, "Ed25519")
# [2026-03-02 15:30:45] INFO: {"event_type": "identity_created", ...}

# Event signed
log_event_signed(agent_id, "trade_completed", nonce)
# [2026-03-02 15:30:50] INFO: {"event_type": "event_signed", ...}

# Chain verified
log_chain_verified(agent_id, event_count=100, chain_hash="abc123...")
# [2026-03-02 15:31:00] INFO: {"event_type": "chain_verified", ...}

# Fork detected (warning)
log_fork_detected(agent_id, fork_hash="def456...", branches=2)
# [2026-03-02 15:31:05] WARNING: {"event_type": "fork_detected", ...}
```

### CLI Logging

Logs appear automatically when using CLI:

```bash
$ piqrypt identity create --output agent.json
[2026-03-02 15:30:45] INFO: {"event_type": "identity_created", ...}
✓ Agent ID: 5Z8nY7KpL9mN3qR4...

$ piqrypt stamp agent.json --payload payload.json
[2026-03-02 15:30:50] INFO: {"event_type": "event_signed", ...}
✓ Event stamped

$ piqrypt audit chain.json
[2026-03-02 15:31:00] INFO: {"event_type": "chain_verified", ...}
✓ Chain integrity confirmed
```

---

## Filtering & Parsing Logs

### Grep for Specific Events

```bash
# Show only errors
piqrypt audit chain.json 2>&1 | grep ERROR

# Show only warnings (forks, TSI drift)
piqrypt audit chain.json 2>&1 | grep WARNING

# Show only behavioral monitoring events
piqrypt audit chain.json 2>&1 | grep -E "tsi_state|a2c_anomaly|vrs_threshold"
```

### Parse with jq

```bash
# Extract event types
piqrypt audit chain.json 2>&1 | grep '^\[' | sed 's/.*: //' | jq -r '.event_type'

# Count events by type
piqrypt audit chain.json 2>&1 | grep '^\[' | sed 's/.*: //' | jq -r '.event_type' | sort | uniq -c
```

### Redirect to File

```bash
# Save logs to file
piqrypt audit chain.json 2>&1 | tee piqrypt.log

# JSON-only logs
piqrypt audit chain.json 2>&1 | grep '^\[' | sed 's/.*: //' > events.jsonl
```

---

## Privacy

**Agent IDs are automatically truncated:**

```
Full agent ID:  5Z8nY7KpL9mN3qR4sT6uV8wX1yA2z (32 chars)
Logged as:      5Z8nY7KpL9mN3qR4... (16 chars + ...)
```

**Never logged:**
- ❌ Private keys
- ❌ KeyStore passphrases
- ❌ Full agent IDs
- ❌ Event payloads (user data)
- ❌ License keys (only license_id)

---

## Production Recommendations

### 1. Log to File

```bash
# Systemd service
ExecStart=/usr/bin/piqrypt-agent --config /etc/piqrypt/config.json 2>&1 | tee -a /var/log/piqrypt.log
```

### 2. Rotate Logs

```bash
# /etc/logrotate.d/piqrypt
/var/log/piqrypt.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
```

### 3. Ship to Monitoring

```bash
# Fluentd, Logstash, etc.
tail -f /var/log/piqrypt.log | grep '^\[' | sed 's/.*: //' | your-log-shipper
```

---

## Troubleshooting

### No Logs Appearing

```bash
export PIQRYPT_LOG_LEVEL=DEBUG
piqrypt identity create
# Should see verbose output
```

### Too Verbose

```bash
export PIQRYPT_LOG_LEVEL=WARNING
piqrypt audit chain.json
# Only shows warnings and errors
```

### Disable Logging

```bash
export PIQRYPT_LOG_LEVEL=ERROR

# Or redirect to /dev/null
piqrypt audit chain.json 2>/dev/null
```

---

## Log Schema Reference

```typescript
type LogEntry = {
  timestamp: string;               // ISO 8601 UTC
  event_type: string;              // Event identifier
  message: string;                 // Human-readable description
  agent_id?: string;               // Truncated to 16 chars
  data?: Record<string, any>;      // Event-specific data
}
```

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
