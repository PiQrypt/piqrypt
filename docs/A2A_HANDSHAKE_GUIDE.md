# Agent-to-Agent Handshake Protocol

**Version:** 1.5.0  
**Date:** 2026-02-21  
**Status:** Current

---


**Enable autonomous agents to discover and collaborate with cryptographic proof.**

---

## 🤝 What is A2A?

The A2A protocol allows agents to:
- **Discover** other agents (via registry or direct)
- **Authenticate** each other (mutual signatures)
- **Collaborate** with cryptographic proof
- **Audit** all interactions (stored in both audit trails)

---

## 🚀 Quick Start

### Basic Handshake

```python
from aiss.a2a import initiate_handshake, accept_handshake, verify_handshake
from aiss.crypto import ed25519
from aiss.identity import derive_agent_id

# Agent A setup
priv_a, pub_a = ed25519.generate_keypair()
agent_a = derive_agent_id(pub_a)

# Agent B setup
priv_b, pub_b = ed25519.generate_keypair()
agent_b = derive_agent_id(pub_b)

# 1. Agent A initiates handshake
handshake = initiate_handshake(
    priv_a,
    agent_a,
    agent_b,
    payload={
        "intent": "data_sharing",
        "scope": "market_analysis",
        "terms": "50/50 split"
    }
)

# 2. Send handshake to Agent B (network/file/API)
# ... transmission ...

# 3. Agent B accepts
response = accept_handshake(
    priv_b,
    agent_b,
    handshake,
    counter_payload={
        "agreed": True,
        "conditions": "Data encrypted in transit"
    }
)

# 4. Verify (both agents can do this)
is_valid = verify_handshake(response, {
    agent_a: pub_a,
    agent_b: pub_b
})

print(f"Handshake valid: {is_valid}")
# → Handshake valid: True
```

---

## 🔍 Peer Discovery

### Using PeerRegistry

```python
from aiss.a2a import PeerRegistry

# Create registry (shared or distributed)
registry = PeerRegistry()

# Agent A registers
registry.register(
    agent_a,
    pub_a,
    metadata={
        "role": "trading_bot",
        "capabilities": ["market_data", "execution"],
        "endpoint": "https://agent-a.example.com"
    }
)

# Agent B registers
registry.register(
    agent_b,
    pub_b,
    metadata={
        "role": "analysis_bot",
        "capabilities": ["ML_prediction", "risk_assessment"]
    }
)

# Agent A discovers peers with specific capability
peers = registry.discover()
for peer in peers:
    if "ML_prediction" in peer["metadata"]["capabilities"]:
        print(f"Found ML agent: {peer['agent_id']}")
        # Initiate handshake...
```

---

## 📋 Handshake States

### State Machine

```
pending → accepted → verified
       ↘ rejected
```

**States:**
- `pending` : Handshake initiated, awaiting response
- `accepted` : Responder accepted, both signed
- `rejected` : Responder rejected
- `verified` : External party verified signatures

---

## 🔒 Security

### Mutual Authentication

Both agents sign the handshake:

1. **Initiator signs** proposal
2. **Responder signs** acceptance (includes initiator signature)
3. **Verification** checks both signatures

**Property:** Neither agent can deny participation.

### Expiration

Handshakes expire after configurable time (default: 1 hour):

```python
handshake = initiate_handshake(
    priv_a,
    agent_a,
    agent_b,
    expires_in=300  # 5 minutes
)
```

**Why:** Prevent replay attacks from old handshakes.

### Nonce Anti-Replay

Each handshake includes:
- `nonce_initiator` (UUID v4)
- `nonce_responder` (UUID v4)

**Property:** Each handshake unique, cannot be replayed.

---

## 📊 Use Cases

### 1. Data Sharing Agreement

```python
handshake = initiate_handshake(
    priv_a,
    agent_a,
    agent_b,
    payload={
        "intent": "data_sharing",
        "data_types": ["market_prices", "order_flow"],
        "duration": "30 days",
        "compensation": "API credits"
    }
)
```

### 2. Task Delegation

```python
handshake = initiate_handshake(
    priv_manager,
    manager_id,
    worker_id,
    payload={
        "intent": "task_delegation",
        "task": "analyze_Q4_sales",
        "deadline": "2026-03-01",
        "compensation": "$500"
    }
)
```

### 3. Multi-Agent Coordination

```python
# Trading bot + Risk bot collaboration
handshake = initiate_handshake(
    trading_priv,
    trading_id,
    risk_id,
    payload={
        "intent": "risk_check",
        "trade": {"symbol": "AAPL", "quantity": 1000, "side": "buy"},
        "max_risk": 0.05
    }
)

# Risk bot accepts with risk assessment
response = accept_handshake(
    risk_priv,
    risk_id,
    handshake,
    counter_payload={
        "risk_score": 0.03,
        "approved": True,
        "conditions": ["Stop loss at $145"]
    }
)
```

---

## 🛠️ Advanced Features

### Rejection with Reason

```python
response = reject_handshake(
    priv_b,
    agent_b,
    handshake,
    reason="Insufficient capacity - try again in 1 hour"
)

print(response["status"])  # → "rejected"
print(response["rejection_reason"])  # → "Insufficient capacity..."
```

### Store in Audit Trail

```python
from aiss.a2a import handshake_to_event
from aiss import store_event

# Convert handshake to AISS event
event = handshake_to_event(response, agent_a)

# Store in Agent A's audit trail
store_event(event)

# Now handshake is part of immutable audit trail
```

### Network-Wide Registry (Production)

For production, use distributed registry:

```python
# Example with Redis
import redis

class DistributedRegistry:
    def __init__(self):
        self.redis = redis.Redis(host='registry.example.com')
    
    def register(self, agent_id, public_key, metadata):
        self.redis.hset(f"agent:{agent_id}", mapping={
            "public_key": ed25519.encode_base64(public_key),
            "metadata": json.dumps(metadata),
            "registered_at": int(time.time())
        })
    
    def discover(self, agent_id=None):
        if agent_id:
            return self.redis.hgetall(f"agent:{agent_id}")
        
        # Scan all agents
        agents = []
        for key in self.redis.scan_iter("agent:*"):
            agents.append(self.redis.hgetall(key))
        return agents
```

---

## 📈 Monitoring

### Track Handshakes

```python
from aiss import search_events

# Find all A2A handshakes
handshakes = search_events(event_type="a2a_handshake")

# Analyze
total = len(handshakes)
accepted = len([h for h in handshakes if h["payload"]["status"] == "accepted"])
rejected = len([h for h in handshakes if h["payload"]["status"] == "rejected"])

print(f"Total: {total}, Accepted: {accepted}, Rejected: {rejected}")
print(f"Acceptance rate: {accepted/total*100:.1f}%")
```

---

## 🚀 Roadmap (v1.6.0)

**Coming features:**

### DHT Discovery
- Distributed Hash Table for peer discovery
- No central registry required
- Kademlia-based routing

### Cross-Chain Verification
- Agent A verifies Agent B's entire audit trail
- Mutual audit before collaboration
- Trust scoring based on history

### Network-Wide Nonce Registry
- Prevent replay across entire network
- Shared nonce database
- Real-time verification

### Witness Protocol
- Third-party witnesses for handshakes
- Multi-signature approval (2-of-3, 3-of-5)
- Enhanced trust for high-value agreements

---

## 🐛 Troubleshooting

### "Handshake not for this agent"

**Problem:** Wrong responder agent ID

**Solution:**
```python
# Check responder_agent_id matches
print(f"Expected: {agent_b}")
print(f"Got: {handshake['responder_agent_id']}")
```

### "Handshake expired"

**Problem:** Took too long to respond

**Solution:**
```python
# Increase expiration time
handshake = initiate_handshake(
    priv_a, agent_a, agent_b,
    expires_in=3600  # 1 hour instead of default
)
```

### "Signature verification failed"

**Problem:** Wrong public key or tampered handshake

**Solution:**
```python
# Verify public keys match agent IDs
derived_id = derive_agent_id(pub_a)
assert derived_id == agent_a, "Public key mismatch"
```

---

## 📚 API Reference

### `initiate_handshake()`

```python
def initiate_handshake(
    initiator_private_key: bytes,
    initiator_agent_id: str,
    responder_agent_id: str,
    payload: Optional[Dict[str, Any]] = None,
    expires_in: int = 3600
) -> Dict[str, Any]
```

### `accept_handshake()`

```python
def accept_handshake(
    responder_private_key: bytes,
    responder_agent_id: str,
    handshake: Dict[str, Any],
    counter_payload: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]
```

### `reject_handshake()`

```python
def reject_handshake(
    responder_private_key: bytes,
    responder_agent_id: str,
    handshake: Dict[str, Any],
    reason: str
) -> Dict[str, Any]
```

### `verify_handshake()`

```python
def verify_handshake(
    handshake: Dict[str, Any],
    public_keys: Dict[str, bytes]
) -> bool
```

---

## 💡 Best Practices

1. **Always verify handshakes** before acting on them
2. **Store handshakes in audit trail** for accountability
3. **Use short expiration times** for sensitive operations
4. **Include detailed intent** in payload for transparency
5. **Register in discovery** if you want to be found
6. **Reject gracefully** with helpful error messages

---

**Questions?** piqrypt@gmail.com

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
