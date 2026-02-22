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
| **WARNING** | Anomalies detected (forks, etc.) |
| **ERROR** | Failures (replay attacks, invalid signatures) |

---

## Log Format

### Console Output (Human-Readable)

```
[2026-02-11 15:30:45] INFO: {"timestamp": "2026-02-11T15:30:45Z", "event_type": "identity_created", "message": "Agent identity created", "agent_id": "5Z8nY7KpL9mN3qR4...", "data": {"algorithm": "Ed25519"}}
```

### Parsed JSON

```json
{
  "timestamp": "2026-02-11T15:30:45Z",
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
# [2026-02-11 15:30:45] INFO: {"event_type": "identity_created", ...}

# Event signed
log_event_signed(agent_id, "trade_completed", nonce)
# [2026-02-11 15:30:50] INFO: {"event_type": "event_signed", ...}

# Chain verified
log_chain_verified(agent_id, event_count=100, chain_hash="abc123...")
# [2026-02-11 15:31:00] INFO: {"event_type": "chain_verified", ...}

# Fork detected (warning)
log_fork_detected(agent_id, fork_hash="def456...", branches=2)
# [2026-02-11 15:31:05] WARNING: {"event_type": "fork_detected", ...}
```

### CLI Logging

Logs appear automatically when using CLI:

```bash
$ piqrypt identity create --output agent.json
[2026-02-11 15:30:45] INFO: {"event_type": "identity_created", ...}
✓ Agent ID: 5Z8nY7KpL9mN3qR4...

$ piqrypt stamp agent.json --payload payload.json
[2026-02-11 15:30:50] INFO: {"event_type": "event_signed", ...}
✓ Event stamped

$ piqrypt audit chain.json
[2026-02-11 15:31:00] INFO: {"event_type": "chain_verified", ...}
✓ Chain integrity confirmed
```

---

## Filtering & Parsing Logs

### Grep for Specific Events

```bash
# Show only errors
piqrypt audit chain.json 2>&1 | grep ERROR

# Show only warnings (forks)
piqrypt audit chain.json 2>&1 | grep WARNING

# Show only identity operations
piqrypt identity create 2>&1 | grep identity_created
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
- ❌ Full agent IDs
- ❌ Event payloads (user data)
- ❌ Passphrases
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
# Check log level
export PIQRYPT_LOG_LEVEL=DEBUG
piqrypt identity create

# Should see verbose output
```

### Too Verbose

```bash
# Reduce to WARNING only
export PIQRYPT_LOG_LEVEL=WARNING
piqrypt audit chain.json

# Only shows warnings and errors
```

### Disable Logging

```bash
# Set to ERROR (only critical)
export PIQRYPT_LOG_LEVEL=ERROR

# Or redirect to /dev/null
piqrypt audit chain.json 2>/dev/null
```

---

## Log Schema Reference

```typescript
type LogEntry = {
  timestamp: string;        // ISO 8601 UTC
  event_type: string;       // Event identifier
  message: string;          // Human-readable description
  agent_id?: string;        // Truncated to 16 chars
  data?: Record<string, any>;  // Event-specific data
}
```

---

## Support

- **GitHub Issues:** Report logging issues
- **Documentation:** https://docs.piqrypt.com/logging
- **Examples:** See `tests/` for usage patterns

---

**Last Updated:** 2026-02-11  
**Version:** 1.1.0
