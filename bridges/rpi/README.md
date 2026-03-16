# piqrypt-rpi

**Cryptographic audit trail for Raspberry Pi edge agents.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-rpi)](https://pypi.org/project/piqrypt-rpi/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-00C8E0)](https://piqrypt.com)

Every GPIO operation, sensor reading, actuator command, and AI decision —
signed Ed25519, hash-chained, tamper-proof. From the edge device all the way
to the cloud audit trail.

---

## Install

```bash
pip install piqrypt[rpi]
# Requires: Raspberry Pi OS (or compatible), RPi.GPIO
```

---

## Quickstart

```python
from piqrypt_rpi import AuditedGPIO, AuditedPiAgent

# ── GPIO layer — low-level I/O audit ──────────────────────────────────────
gpio = AuditedGPIO(identity_file="~/.piqrypt/rpi.json")

gpio.setup(18, gpio.OUT)
gpio.output(18, gpio.HIGH)   # ← signed: pin, value, timestamp
val = gpio.input(24)         # ← signed: pin, value_hash

gpio.cleanup()               # ← signed: cleanup event

# ── Agent layer — high-level AI decisions ─────────────────────────────────
agent = AuditedPiAgent(identity_file="~/.piqrypt/rpi.json")

# Sensor readings — value hashed for privacy
agent.stamp_sensor("temperature", 25.3, "celsius")
agent.stamp_sensor("pressure", 1013.25, "hPa")
agent.stamp_sensor_hashed("heart_rate", 72, "bpm")  # extra-sensitive: SHA-256 only

# AI decision made on this Pi
agent.stamp_decision("activate_cooling", {
    "trigger": "temp > 28",
    "temperature_reading": "~25.3C",  # can be approximate
})

# Physical action taken
agent.stamp_actuator("fan_relay", "ON", {"channel": 18, "speed": 75})

# System metrics snapshot
agent.stamp_system_metrics()  # CPU, RAM, temperature — all hashed

# Export audit trail
agent.export_audit("edge_audit.json")
```

---

## What gets stamped

| Event | Stamped data |
|-------|-------------|
| `gpio_setup` | pin, mode, timestamp |
| `gpio_output` | pin, value, timestamp |
| `gpio_input` | pin, value (or value_hash for sensitive) |
| `gpio_event_detected` | pin, edge_type, timestamp |
| `gpio_cleanup` | pins_cleaned, timestamp |
| `sensor_reading` | sensor_name, unit, value (raw or hashed) |
| `ai_decision` | decision_name, inputs_hash, action |
| `actuator_command` | actuator_name, state, params_hash |
| `system_metrics` | cpu_hash, ram_hash, temp_hash |
| `network_event` | event_type, payload_hash |
| `error` | error_type, message_hash |

---

## AuditedGPIO

Drop-in replacement for `RPi.GPIO`:

```python
from piqrypt_rpi import AuditedGPIO
import RPi.GPIO as GPIO  # original, for constants

gpio = AuditedGPIO(identity_file="~/.piqrypt/rpi.json")
gpio.setmode(GPIO.BCM)

# All standard GPIO operations — signed
gpio.setup(18, GPIO.OUT)
gpio.setup(24, GPIO.IN, pull_up_down=GPIO.PUD_UP)

gpio.output(18, GPIO.HIGH)
state = gpio.input(24)

# Edge detection — callback wrapped automatically
def on_button(channel):
    print(f"Button pressed on {channel}")

gpio.add_event_detect(24, GPIO.FALLING, callback=on_button)
# Every trigger: signed event with pin, edge_type, timestamp

gpio.cleanup()
```

## AuditedPiAgent

High-level agent for IoT/edge AI:

```python
from piqrypt_rpi import AuditedPiAgent

agent = AuditedPiAgent(
    agent_name="factory_sensor_01",
    identity_file="~/.piqrypt/factory_01.json",
)

# Medical example — raw value never stored
agent.stamp_sensor_hashed("blood_pressure_systolic", 120, "mmHg")
agent.stamp_sensor_hashed("blood_pressure_diastolic", 80, "mmHg")

# Industrial example — decision audit trail
agent.stamp_decision("emergency_shutdown", {
    "trigger": "pressure_anomaly",
    "pressure_threshold_exceeded": True,
    "timestamp_iso": "2026-03-09T10:00:00Z",
})
agent.stamp_actuator("main_valve", "CLOSED", {"force": "emergency"})

# Network event — hash only
agent.stamp_network_event("mqtt_alert_sent", {
    "broker_hash": sha256("mqtt://broker.example.com"),
    "topic_hash": sha256("/factory/alerts"),
})

print(agent.piqrypt_id)       # AGENT_...
print(agent.event_count)      # 12
print(agent.last_event_hash)  # sha256...
```

## @stamp_loop — audit control loops

```python
from piqrypt_rpi import stamp_loop

@stamp_loop("control_loop_10hz", identity_file="~/.piqrypt/rpi.json")
def control_loop():
    temp = read_temperature()
    humidity = read_humidity()
    if temp > 28:
        activate_fan()
    return {"temp": round(temp, 1), "humidity": round(humidity, 1)}

# Call at 10Hz — every iteration stamped: inputs_hash, result_hash
while True:
    control_loop()
    time.sleep(0.1)
```

---

## Cross-framework: RPi + LLM orchestrator

The powerful pattern: an LLM agent in the cloud sends commands to a RPi at the edge.
Every command is cryptographically co-signed — in the LLM's memory AND in the RPi's memory.

```python
from piqrypt_rpi import AuditedPiAgent
from piqrypt_session import AgentSession
import json, hashlib

# Session: links cloud LLM ↔ edge RPi
session = AgentSession([
    {"name": "crewai_orchestrator", "identity_file": "~/.piqrypt/cloud.json"},
    {"name": "rpi_actuator",        "identity_file": "~/.piqrypt/rpi.json"},
])
session.start()

# Cloud LLM sends command to RPi — co-signed in both memories
command = {"action": "activate_relay", "channel": 18, "duration_ms": 500}
payload_hash = hashlib.sha256(json.dumps(command, sort_keys=True).encode()).hexdigest()

session.stamp("crewai_orchestrator", "command_sent", {
    "payload_hash": payload_hash,
    "command": "activate_relay",
}, peer="rpi_actuator")

# RPi receives and executes — stamped locally
agent = AuditedPiAgent(identity_file="~/.piqrypt/rpi.json")

agent.stamp("command_received", {
    "payload_hash": payload_hash,   # SAME hash as in cloud memory
    "peer": "crewai_orchestrator",
})

agent.stamp_actuator("relay_1", "ON", {"channel": 18, "duration_ms": 500})

# Confirmation back to cloud — co-signed
session.stamp("rpi_actuator", "execution_confirmed", {
    "payload_hash": payload_hash,
    "status": "SUCCESS",
    "duration_actual_ms": 503,
}, peer="crewai_orchestrator")

# Two independent audit trails, cryptographically linked:
session.export("cloud_audit.json")     # Cloud LLM memory
agent.export_audit("edge_audit.json")  # Edge RPi memory
```

**What this proves:**
- The LLM issued this exact command (its Ed25519 signature, cloud)
- The RPi received the exact same command (same `payload_hash`, its signature)
- The physical actuator was activated as a result (causal chain on RPi)
- The execution time was confirmed back (co-signed return path)

---

## Use cases

**Medical IoT (IEC 62304 / FDA 21 CFR Part 11)**
Vital sign monitor with AI-assisted alerting. Every sensor reading hashed —
raw patient data never leaves the device. Every alert decision signed.
Cryptographic proof of what the AI measured and decided.

**Industrial control (IEC 61511 / IEC 62443)**
Safety PLC backup with AI anomaly detection. Every sensor reading, every
shutdown command, every valve activation — signed and timestamped.
Impossible to alter the incident log after the fact.

**Smart agriculture**
LLM-coordinated irrigation: soil sensors on RPi, decisions in cloud.
Every watering command co-signed: AI decision + physical execution.

**Autonomous retail (GDPR / PCI-DSS)**
Smart shelf with computer vision. Every inventory event signed.
Customer data hashed at source — never stored on-device or in audit trail.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Part of [PiQrypt](https://piqrypt.com) — Trust infrastructure for autonomous AI agents.  
IP: e-Soleau DSO2026006483 (INPI France — 19/02/2026)
