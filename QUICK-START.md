# PiQrypt Quick Start Guide

**Get started with PiQrypt in 5 minutes.**

---

## Installation

```bash
pip install piqrypt
```

**Requirements:** Python 3.8+

---

## 1. Create Agent Identity

```bash
# Generate keypair
piqrypt identity create my-agent.json

# View identity
cat my-agent.json
```

**Output:**
```json
{
  "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "public_key": "base64:...",
  "private_key": "base64:...",
  "algorithm": "Ed25519",
  "created_at": "2026-02-19T00:00:00Z"
}
```

⚠️ **Keep `private_key` secret!** Store in secure location (0600 permissions).

---

## 2. Sign Your First Event

```bash
piqrypt stamp my-agent.json --payload '{"action": "hello_world", "status": "active"}'
```

**Output:**
```json
{
  "version": "AISS-1.0",
  "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "timestamp": 1739395200,
  "nonce": "uuid-12345678",
  "payload": {
    "action": "hello_world",
    "status": "active"
  },
  "previous_hash": "genesis",
  "signature": "base64:..."
}
```

---

## 3. Create Event Chain

```python
import piqrypt as aiss

# Load identity
identity = aiss.load_identity("my-agent.json")
private_key = identity["private_key_bytes"]
agent_id = identity["agent_id"]

# Sign multiple events (chain)
previous_hash = "genesis"

for i in range(5):
    event = aiss.stamp_event(
        private_key,
        agent_id,
        payload={"action": f"task_{i}", "step": i},
        previous_hash=previous_hash
    )
    
    # Store event
    aiss.store_event(event)
    
    # Update chain
    previous_hash = aiss.compute_event_hash(event)
    
    print(f"✓ Event {i+1} signed")
```

---

## 4. Search & Verify

```bash
# Search recent events
piqrypt search --limit 10

# Search by type
piqrypt search --type task

# Verify chain integrity
piqrypt verify chain.json
```

---

## 5. Export Audit Trail

### Free Tier (Plaintext)

```bash
# Export to JSON
piqrypt export chain.json audit.json

# Verify export
cat audit.json | jq '.events | length'
```

### Pro Tier (Certified)

```bash
# Activate Pro license
piqrypt license activate pk_pro_XXXXXXXXXXXX_XXXXXXXX

# Create certified export
piqrypt export chain.json audit.json --certified --identity my-agent.json

# Files created:
# - audit.json (audit trail)
# - audit.json.cert (cryptographic certificate)

# Verify
piqrypt verify-export audit.json audit.json.cert
```

---

## 6. Request External Certification (Pro)

```bash
# Create certification request
piqrypt certify-request audit.json audit.json.cert --email you@company.com

# Output: certification-request-CERT-XXXXX.zip

# Email to: piqrypt@gmail.com
# Subject: Certification Request
```

**You'll receive:**
- `audit-CERT-XXXXX.piqrypt-certified` (certified by PiQrypt Inc.)

**Verify:**
```bash
piqrypt certify-verify audit-CERT-XXXXX.piqrypt-certified
```

---

## 7. Upgrade to Pro

### Option 1: Stripe (Credit Card)

Visit: https://buy.stripe.com/XXXXXXXX

Or use embedded button:
```html
<script async src="https://js.stripe.com/v3/buy-button.js"></script>
<stripe-buy-button
  buy-button-id="buy_btn_1T2YDA2dXxVwyOAsPvmzFb3i"
  publishable-key="pk_live_51T2XZu2dXxVwyOAsGo1UrCTTbSk6vFHqxj23Q4VqPpUMI5J9EeRWn37ONCy0eDs4VWfQnqs2r6FRaKvz28f6vRmP00DSrwvY8F">
</stripe-buy-button>
```

### Option 2: Email Invoice

Email: piqrypt@gmail.com  
Subject: Pro License Request  
Include: Company name, billing email

---

## 8. Encrypt Memory (Pro)

```bash
# Unlock Pro features
piqrypt memory encrypt

# Enter passphrase (min 12 chars)
# Passphrase: ****************

# Verify encryption
ls ~/.piqrypt/events/encrypted/
# → 2025-02.enc (AES-256-GCM encrypted)
```

---

## 9. Use with AI Agents

### Claude Desktop (MCP)

**Install MCP Server:**
```bash
npm install -g @piqrypt/mcp-server
```

**Configure Claude Desktop:**
```json
{
  "mcpServers": {
    "piqrypt": {
      "command": "piqrypt-mcp-server"
    }
  }
}
```

**Usage in Claude:**
```
User: "Sign this decision with PiQrypt"
Claude: [calls piqrypt_stamp_event MCP tool]
```

### n8n Workflow

**Install n8n node:**
```bash
npm install n8n-nodes-piqrypt
```

**Workflow:**
```
[Webhook] → [AI Decision] → [PiQrypt Stamp] → [Execute Action]
```

---

## 10. Python SDK

```python
import piqrypt as aiss

# Generate identity
priv, pub = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(pub)

# Sign event
event = aiss.stamp_event(priv, agent_id, {"action": "test"})

# Store
aiss.store_event(event)

# Search
events = aiss.search_events(event_type="test", limit=10)

# Verify chain
result = aiss.verify_chain(events)
print(result["valid"])  # True
```

---

## Next Steps

- 📚 **Full docs:** [docs/RFC.md](docs/RFC.md)
- 🔧 **CLI reference:** `piqrypt --help`
- 💡 **Examples:** [examples/](examples/)
- 🤝 **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)
- 📧 **Support:** piqrypt@gmail.com

---

**Questions?** Email piqrypt@gmail.com or open a [GitHub Issue](https://github.com/piqrypt/piqrypt/issues).
