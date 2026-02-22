# PiQrypt Logging System

## Overview

PiQrypt v1.1.0 introduces structured, privacy-conscious logging designed for production systems, debugging, and compliance.

## Design Principles

1. **Structured** - JSON parseable for automation
2. **Human-readable** - Easy to understand at a glance
3. **Privacy-conscious** - Truncates sensitive IDs
4. **Configurable** - Multiple log levels and outputs
5. **Performance-aware** - Minimal overhead

---

## Quick Start

### Basic Usage

```python
from piqrypt import configure_logging

# Simple configuration
configure_logging(level="INFO")

# Create agent and log automatically
from piqrypt import generate_keypair, stamp_event

priv, pub = generate_keypair()
# LOG: [INFO] Generated Ed25519 keypair

event = stamp_event(priv, agent_id, {"action": "test"})
# LOG: [INFO] Event stamped | agent=5Z8n...A2z | nonce=550e...0000
```

### Advanced Configuration

```python
from piqrypt import configure_logging

configure_logging(
    level="DEBUG",
    format="json",
    output="file",
    filepath="/var/log/piqrypt/events.log",
    privacy_mode=True,  # Truncate IDs (default)
    include_stacktrace=True  # For errors
)
```

---

## Log Levels

### CRITICAL
System failures, security violations

```
[CRITICAL] Signature verification failed | agent=5Z8n...A2z | hash=a3f7...8c9d
[CRITICAL] Fork detected | agent=5Z8n...A2z | branches=2
```

### ERROR
Operation failures, invalid inputs

```
[ERROR] Invalid event structure | missing_field=timestamp
[ERROR] License verification failed | key=invalid
```

### WARNING
Potential issues, degraded performance

```
[WARNING] Nonce reuse detected | nonce=550e...0000
[WARNING] License expiring soon | days_remaining=7
```

### INFO (Default)
Normal operations, key events

```
[INFO] Event stamped | agent=5Z8n...A2z | nonce=550e...0000
[INFO] Chain verified | events=100 | duration=0.45s
[INFO] License activated | tier=pro | expires=2026-02-16
```

### DEBUG
Detailed operations, troubleshooting

```
[DEBUG] Computing canonical hash | payload_size=234
[DEBUG] Verifying signature | algorithm=Ed25519
[DEBUG] Nonce store lookup | nonce=550e...0000 | found=false
```

---

## Log Formats

### Human-Readable (Default)

Easy to read in terminals:

```
[2025-02-16 14:30:45] [INFO] Event stamped
  agent: 5Z8nY7Kp...A2z (truncated)
  nonce: 550e8400...0000
  timestamp: 1739382645
  payload_hash: a3f7e8c9...d4e5

[2025-02-16 14:30:46] [INFO] Chain verified
  events: 100
  duration: 0.45s
  integrity_hash: b4c8f9d0...e5f6
```

### JSON Format

Machine-parseable for automation:

```json
{
  "timestamp": "2025-02-16T14:30:45.123Z",
  "level": "INFO",
  "event": "event_stamped",
  "data": {
    "agent_id": "5Z8nY7Kp...A2z",
    "nonce": "550e8400...0000",
    "timestamp": 1739382645,
    "payload_hash": "a3f7e8c9...d4e5"
  }
}
```

### Structured Text

Best of both worlds:

```
timestamp=2025-02-16T14:30:45.123Z level=INFO event=event_stamped agent=5Z8nY7Kp...A2z nonce=550e8400...0000 duration=0.002s
```

---

## Privacy Mode

**Enabled by default** to protect sensitive data.

### What Gets Truncated

```python
# Full IDs (privacy_mode=False)
agent_id: "5Z8nY7KpL9mN3qR4sT6uV8wX1yA2z"
nonce: "550e8400-e29b-41d4-a716-446655440000"
signature: "3k9XmL4nP8qR..."  # 64 chars

# Truncated (privacy_mode=True, default)
agent_id: "5Z8n...A2z"
nonce: "550e...0000"
signature: "3k9X...R..."
```

### What Stays Full

- Timestamps
- Event counts
- Performance metrics
- Error messages
- Algorithm names

### Disable for Debugging

```python
configure_logging(privacy_mode=False)  # Full IDs in logs
```

---

## Output Destinations

### Console (Default)

```python
configure_logging(output="console")
# Logs to stdout (INFO+) and stderr (ERROR+)
```

### File

```python
configure_logging(
    output="file",
    filepath="/var/log/piqrypt/events.log",
    rotation="daily",  # daily, weekly, size
    max_size="100MB",  # for size rotation
    backup_count=7     # keep 7 old files
)
```

### Syslog

```python
configure_logging(
    output="syslog",
    facility="local0",
    address=("localhost", 514)
)
```

### Custom Handler

```python
import logging

class MyHandler(logging.Handler):
    def emit(self, record):
        # Send to monitoring system
        send_to_datadog(record)

configure_logging(
    output="custom",
    handler=MyHandler()
)
```

---

## Log Rotation

### Daily Rotation

```python
configure_logging(
    output="file",
    filepath="/var/log/piqrypt/events.log",
    rotation="daily",
    backup_count=30  # Keep 30 days
)
```

Creates files:
```
events.log          # Current
events.log.2025-02-16
events.log.2025-02-15
...
```

### Size-Based Rotation

```python
configure_logging(
    output="file",
    filepath="/var/log/piqrypt/events.log",
    rotation="size",
    max_size="100MB",
    backup_count=5
)
```

Creates files:
```
events.log          # Current
events.log.1
events.log.2
...
```

---

## Performance Considerations

### Overhead

```
Format          | Overhead per log
----------------|------------------
Console         | ~0.1ms
File            | ~0.2ms
JSON            | ~0.3ms
Syslog (local)  | ~0.5ms
Syslog (remote) | ~5-10ms
```

### High-Performance Mode

```python
configure_logging(
    level="WARNING",  # Only warnings+
    async_logging=True,  # Non-blocking
    buffer_size=1000     # Batch writes
)
```

### Sampling

For very high-volume scenarios:

```python
configure_logging(
    sampling_rate=0.1  # Log 10% of events
)
```

---

## Log Event Types

### Agent Operations

```
event_type=keypair_generated algorithm=Ed25519
event_type=agent_id_derived agent=5Z8n...A2z
event_type=identity_exported agent=5Z8n...A2z
event_type=key_rotated old_agent=5Z8n...A2z new_agent=9K3m...B7x
```

### Event Operations

```
event_type=event_stamped agent=5Z8n...A2z nonce=550e...0000
event_type=signature_verified agent=5Z8n...A2z valid=true
event_type=chain_validated events=100 duration=0.45s
```

### Security Events

```
event_type=fork_detected agent=5Z8n...A2z branches=2
event_type=replay_detected nonce=550e...0000
event_type=signature_invalid agent=5Z8n...A2z
event_type=tampering_detected event_hash=a3f7...8c9d
```

### License Events

```
event_type=license_verified tier=pro expires=2026-02-16
event_type=license_expired tier=pro expired_on=2025-12-31
event_type=license_invalid key_format=invalid
event_type=feature_blocked feature=dilithium requires=pro
```

### AISS-2 Events

```
event_type=dilithium_keypair_generated
event_type=hybrid_signature_created algorithms=Ed25519+Dilithium3
event_type=trusted_timestamp_obtained authority=freetsa.org
event_type=witness_attestation_received witnesses=5
event_type=blockchain_anchor_created chain=bitcoin txid=abc123...
```

---

## Integration Examples

### With Monitoring Systems

#### Datadog

```python
from datadog import initialize, statsd

def log_event_to_datadog(event_type, data):
    statsd.increment(f'piqrypt.{event_type}')
    statsd.histogram('piqrypt.duration', data.get('duration', 0))
    
configure_logging(
    output="custom",
    handler=DatadogHandler()
)
```

#### Prometheus

```python
from prometheus_client import Counter, Histogram

events_total = Counter('piqrypt_events_total', 'Total events', ['type'])
duration = Histogram('piqrypt_duration_seconds', 'Operation duration')

@duration.time()
def stamp_with_metrics(priv, agent_id, payload):
    event = stamp_event(priv, agent_id, payload)
    events_total.labels(type='stamped').inc()
    return event
```

### With ELK Stack

```python
configure_logging(
    format="json",
    output="file",
    filepath="/var/log/piqrypt/events.log"
)
```

Logstash config:
```
input {
  file {
    path => "/var/log/piqrypt/events.log"
    codec => json
  }
}

filter {
  if [event] == "fork_detected" {
    mutate { add_tag => ["security_alert"] }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "piqrypt-%{+YYYY.MM.dd}"
  }
}
```

---

## Security Considerations

### Sensitive Data

**Never logged** (even with privacy_mode=False):
- ❌ Private keys
- ❌ Full payloads (only hashes)
- ❌ Plaintext passwords
- ❌ API keys

**Truncated** (with privacy_mode=True):
- ✅ Agent IDs (first 4 + last 3 chars)
- ✅ Nonces (first 4 + last 4 chars)
- ✅ Signatures (first 4 + last 4 chars)
- ✅ Hashes (first 8 + last 8 chars)

### Log File Permissions

```bash
# Restrict log file access
chmod 600 /var/log/piqrypt/events.log
chown piqrypt:piqrypt /var/log/piqrypt/events.log
```

### Compliance

Logs are designed to support:
- **GDPR** - No PII without explicit consent
- **HIPAA** - Healthcare data privacy
- **SOC 2** - Audit trails
- **PCI DSS** - Transaction logging

---

## CLI Usage

### View Logs

```bash
# Tail logs
piqrypt logs tail

# Follow logs
piqrypt logs follow

# Search logs
piqrypt logs search "fork_detected"

# Filter by level
piqrypt logs filter --level ERROR

# Export logs
piqrypt logs export --start 2025-02-01 --end 2025-02-16 --format json
```

### Configure Logging

```bash
# Set log level
piqrypt config set log_level DEBUG

# Set output
piqrypt config set log_output file
piqrypt config set log_filepath /var/log/piqrypt/events.log

# Enable/disable privacy mode
piqrypt config set log_privacy_mode true
```

---

## Troubleshooting

### No Logs Appearing

```python
import piqrypt
print(piqrypt.get_log_config())
# Shows current configuration

# Force logging
configure_logging(level="DEBUG", output="console")
```

### Logs Too Verbose

```python
# Reduce verbosity
configure_logging(level="WARNING")

# Or filter specific events
configure_logging(
    level="INFO",
    exclude_events=["nonce_check", "hash_computed"]
)
```

### Performance Issues

```python
# Enable async logging
configure_logging(async_logging=True)

# Reduce sampling
configure_logging(sampling_rate=0.1)

# Use faster format
configure_logging(format="structured")  # Faster than JSON
```

---

## Best Practices

### Development

```python
configure_logging(
    level="DEBUG",
    output="console",
    privacy_mode=False  # See full IDs
)
```

### Production

```python
configure_logging(
    level="INFO",
    output="file",
    filepath="/var/log/piqrypt/events.log",
    rotation="daily",
    backup_count=30,
    privacy_mode=True,  # Protect IDs
    async_logging=True  # Better performance
)
```

### High-Security

```python
configure_logging(
    level="WARNING",  # Only issues
    output="syslog",
    facility="auth",
    privacy_mode=True,
    include_stacktrace=False  # No code paths
)
```

---

## API Reference

### configure_logging()

```python
def configure_logging(
    level: str = "INFO",           # DEBUG, INFO, WARNING, ERROR, CRITICAL
    format: str = "human",          # human, json, structured
    output: str = "console",        # console, file, syslog, custom
    filepath: str = None,           # For file output
    rotation: str = None,           # daily, weekly, size
    max_size: str = "100MB",        # For size rotation
    backup_count: int = 7,          # Number of backups
    privacy_mode: bool = True,      # Truncate IDs
    async_logging: bool = False,    # Non-blocking
    buffer_size: int = 1000,        # For async
    sampling_rate: float = 1.0,     # 0.0-1.0
    exclude_events: list = None,    # Event types to skip
    include_stacktrace: bool = True # For errors
) -> None:
    """Configure PiQrypt logging system"""
```

---

**Last Updated:** February 16, 2025
**Version:** 1.1.0
