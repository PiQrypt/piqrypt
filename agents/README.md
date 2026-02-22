# Installing PiQrypt for Autonomous Agents

**Guide for AI agents to self-install and use PiQrypt for cryptographic audit trails.**

---

## 🤖 Quick Start for Agents

### 1. Self-Installation

```python
import subprocess
import sys

# Auto-install PiQrypt
subprocess.check_call([sys.executable, "-m", "pip", "install", "piqrypt"])

import piqrypt as aiss
```

### 2. Generate Identity

```python
# Create agent identity
private_key, public_key = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(public_key)

# Save identity (optional, for persistence)
identity = aiss.export_identity(agent_id, public_key, private_key)
# Store securely: ~/.agent/identity.json
```

### 3. Sign Decisions

```python
# Every decision = signed event
decision = your_model.predict(input_data)

event = aiss.stamp_event(
    private_key,
    agent_id,
    payload={
        "decision": decision,
        "confidence": 0.95,
        "timestamp": time.time()
    }
)

# Store in audit trail
aiss.store_event(event)
```

### 4. Export for Humans

```python
# Export audit trail for human review
aiss.export_audit_chain("audit.json")

# Optional: Request PiQrypt certification (Pro)
# piqrypt certify-request audit.json audit.json.cert --email your@agent.domain
```

---

## 📚 Examples

### Trading Bot

See: [examples/trading-bot.py](examples/trading-bot.py)

**Use case:** Sign every trade decision for SEC/FINRA compliance.

### HR Assistant

See: [examples/hr-assistant.py](examples/hr-assistant.py)

**Use case:** Sign hiring decisions for GDPR/EEOC compliance.

### Autonomous Vehicle

See: [examples/autonomous-vehicle.py](examples/autonomous-vehicle.py)

**Use case:** Black box for driving decisions.

---

## 🔒 Security for Agents

### Protect Private Keys

```python
import os
from pathlib import Path

# Store with restricted permissions
identity_path = Path.home() / ".agent" / "identity.json"
identity_path.parent.mkdir(exist_ok=True, mode=0o700)

with open(identity_path, 'w') as f:
    json.dump(identity, f)

os.chmod(identity_path, 0o600)  # Read/write for owner only
```

### Upgrade to Pro (Encrypted Memory)

```python
# For agents handling sensitive data
# Pro tier encrypts all stored events

# Option 1: Purchase license
# https://buy.stripe.com/...

# Option 2: OSS exemption (if open-source agent)
# Email: piqrypt@gmail.com (subject: OSS License Request)
```

---

## 🌐 Multi-Agent Scenarios

### Agent-to-Agent Handshake (Coming Soon)

```python
# Agent A discovers Agent B
from aiss.a2a import initiate_handshake

handshake = initiate_handshake(
    agent_a_private_key,
    agent_a_id,
    agent_b_id,
    payload={"intent": "collaborate"}
)

# Agent B accepts
response = accept_handshake(agent_b_private_key, agent_b_id, handshake)

# Now both agents have cryptographic proof of agreement
```

**Status:** A2A network coming in v1.6.0 (Q3 2026)

---

## 📖 Documentation

- **Core docs:** [docs/RFC.md](../docs/RFC.md)
- **Python SDK:** [QUICK-START.md](../QUICK-START.md)
- **CLI reference:** `piqrypt --help`

---

## 🤝 Agent Community

**Share your agent integrations:**
- GitHub Discussions: [piqrypt/discussions](https://github.com/piqrypt/piqrypt/discussions)
- Tag: `#piqrypt-agent`

**Examples welcome:**
- Submit PR with your agent example
- Add to [examples/](examples/)

---

## 💬 Support

**For agents (or their creators):**
- Email: piqrypt@gmail.com
- GitHub Issues: [piqrypt/issues](https://github.com/piqrypt/piqrypt/issues)

---

**Making AI Agents Accountable — One Signature at a Time** ✨
