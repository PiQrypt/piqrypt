# PiQrypt Logging System

## Overview

PiQrypt provides structured, privacy-conscious logging designed for production systems, debugging, and compliance.

## Design Principles

1. **Structured** — JSON parseable for automation
2. **Human-readable** — Easy to understand at a glance
3. **Privacy-conscious** — Truncates sensitive IDs
4. **Configurable** — Multiple log levels and outputs
5. **Performance-aware** — Minimal overhead

---

## Quick Start

### Basic Usage

```python
from piqrypt import configure_logging

# Simple configuration
configure_logging(level="INFO")

# Create agent and log automatically
from aiss import stamp_event
from aiss.crypto import ed25519
from aiss.identity import derive_agent_id

priv, pub = ed25519.generate_keypair()
agent_id = derive_agent_id(pub)
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
[CRITICAL] KeyStore magic bytes invalid | file=agent.key.enc
```

### ERROR
Operation failures, invalid inputs

```
[ERROR] Invalid event structure | missing_field=timestamp
[ERROR] License verification failed | key=invalid
[ERROR] Path traversal attempt blocked | name=../etc/passwd
```

### WARNING
Potential issues, degraded performance

```
[WARNING] Nonce reuse detected | nonce=550e...0000
[WARNING] License expiring soon | days_remaining=7
[WARNING] TSI drift detected | agent=5Z8n...A2z | delta_24h=-0.16
[WARNING] VRS elevated | agent=5Z8n...A2z | vrs=0.52 | state=ALERT
```

### INFO (Default)
Normal operations, key events

```
[INFO] Event stamped | agent=5Z8n...A2z | nonce=550e...0000
[INFO] Chain verified | events=100 | duration=0.45s
[INFO] License activated | tier=pro | expires=2027-03-02
[INFO] KeyStore loaded | agent=5Z8n...A2z | scrypt_n=131072
[INFO] Vigil Server started | port=18421
```

### DEBUG
Detailed operations, troubleshooting

```
[DEBUG] Computing canonical hash | payload_size=234
[DEBUG] Verifying signature | algorithm=Ed25519
[DEBUG] Nonce store lookup | nonce=550e...0000 | found=false
[DEBUG] scrypt key derivation | n=131072 | r=8 | p=1
[DEBUG] RAM erasure complete | agent=5Z8n...A2z
```

---

## Log Formats

### Human-Readable (Default)

```
[2026-03-02 14:30:45] [INFO] Event stamped
  agent: 5Z8nY7Kp...A2z (truncated)
  nonce: 550e8400...0000
  timestamp: 1740902400
  payload_hash: a3f7e8c9...d4e5

[2026-03-02 14:30:46] [INFO] Chain verified
  events: 100
  duration: 0.45s
  integrity_hash: b4c8f9d0...e5f6
```

### JSON Format

```json
{
  "timestamp": "2026-03-02T14:30:45.123Z",
  "level": "INFO",
  "event": "event_stamped",
  "data": {
    "agent_id": "5Z8nY7Kp...A2z",
    "nonce": "550e8400...0000",
    "timestamp": 1740902400,
    "payload_hash": "a3f7e8c9...d4e5"
  }
}
```

### Structured Text

```
timestamp=2026-03-02T14:30:45.123Z level=INFO event=event_stamped agent=5Z8nY7Kp...A2z nonce=550e8400...0000 duration=0.002s
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
    rotation="daily",
    max_size="100MB",
    backup_count=7
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
        send_to_datadog(record)

configure_logging(
    output="custom",
    handler=MyHandler()
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
event_type=keystore_created agent=5Z8n...A2z scrypt_n=131072
event_type=keystore_loaded agent=5Z8n...A2z
event_type=key_erased_from_ram agent=5Z8n...A2z
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
event_type=path_traversal_blocked name=../etc/passwd
event_type=keystore_magic_invalid file=agent.key.enc
event_type=keystore_auth_failed agent=5Z8n...A2z
```

### Behavioral Monitoring Events

```
event_type=tsi_state_changed agent=5Z8n...A2z old=STABLE new=WATCH delta_24h=-0.09
event_type=tsi_state_changed agent=5Z8n...A2z old=WATCH new=UNSTABLE delta_24h=-0.16
event_type=a2c_anomaly_detected agent=5Z8n...A2z scenario=concentration_soudaine risk=HIGH
event_type=vrs_threshold_crossed agent=5Z8n...A2z vrs=0.51 state=ALERT
event_type=vigil_alert_raised agent=5Z8n...A2z severity=HIGH type=trust_drift
```

### License Events

```
event_type=license_verified tier=pro expires=2027-03-02
event_type=license_expired tier=pro expired_on=2026-12-31
event_type=feature_blocked feature=dilithium requires=pro
```

### AISS-2 Events (Pro)

```
event_type=dilithium_keypair_generated
event_type=hybrid_signature_created algorithms=Ed25519+Dilithium3
event_type=trusted_timestamp_obtained authority=freetsa.org
```

---

## Integration Examples

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
  if [event] == "tsi_state_changed" {
    mutate { add_tag => ["behavioral_alert"] }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "piqrypt-%{+YYYY.MM.dd}"
  }
}
```

### With Prometheus

```python
from prometheus_client import Counter, Histogram

events_total = Counter('piqrypt_events_total', 'Total events', ['type'])
duration = Histogram('piqrypt_duration_seconds', 'Operation duration')

@duration.time()
def stamp_with_metrics(priv, agent_id, payload):
    from aiss import stamp_event
    event = stamp_event(priv, agent_id, payload)
    events_total.labels(type='stamped').inc()
    return event
```

---

## Security Considerations

### Sensitive Data

**Never logged** (even with privacy_mode=False):
- ❌ Private keys
- ❌ KeyStore passphrases
- ❌ Full payloads (only hashes)
- ❌ API keys

**Truncated** (with privacy_mode=True):
- ✅ Agent IDs (first 4 + last 3 chars)
- ✅ Nonces (first 4 + last 4 chars)
- ✅ Signatures (first 4 + last 4 chars)
- ✅ Hashes (first 8 + last 8 chars)

### Log File Permissions

```bash
chmod 600 /var/log/piqrypt/events.log
chown piqrypt:piqrypt /var/log/piqrypt/events.log
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
    privacy_mode=True,
    async_logging=True
)
```

### High-Security

```python
configure_logging(
    level="WARNING",
    output="syslog",
    facility="auth",
    privacy_mode=True,
    include_stacktrace=False  # No code paths in logs
)
```

---

## API Reference

### configure_logging()

```python
def configure_logging(
    level: str = "INFO",            # DEBUG, INFO, WARNING, ERROR, CRITICAL
    format: str = "human",          # human, json, structured
    output: str = "console",        # console, file, syslog, custom
    filepath: str = None,
    rotation: str = None,           # daily, weekly, size
    max_size: str = "100MB",
    backup_count: int = 7,
    privacy_mode: bool = True,
    async_logging: bool = False,
    buffer_size: int = 1000,
    sampling_rate: float = 1.0,
    exclude_events: list = None,
    include_stacktrace: bool = True
) -> None
```

---

**Last Updated:** 2026-03-12
**Version:** 1.8.6

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
