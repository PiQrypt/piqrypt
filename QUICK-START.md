# PiQrypt Quick Start Guide

**PiQrypt v1.8.8 — AISS v2.0 Reference Implementation**

Get started in 5 minutes.

---

## Launch the stack

```powershell
# Production — choisir selon votre tier
.\start_free.ps1          # Free  — Vigil dashboard, lecture seule
.\start_pro.ps1           # Pro   — Vigil complet, exports, .pqz certifiés
.\start_team.ps1          # Team  — Vigil + TrustGate manuel
.\start_business.ps1      # Business/Enterprise — stack complet

# Démos & développement
.\demos\start_families.ps1   # Menu interactif — nexus / pixelflow / alphacore
.\demos\start_legacy.ps1     # 10 agents — trading / compliance / rogue
```

**Onboarding en 60 secondes :**

```
1. .\start_free.ps1                 ← dashboard s'ouvre automatiquement
2. Clic "+ NEW AGENT" dans Vigil
3. Choisir un bridge (CrewAI, LangChain, MCP, Ollama…)
4. Copier le snippet généré → coller dans votre code agent
5. L'agent apparaît en temps réel dans le network graph
```

---

## Installation
```bash
pip install piqrypt
```

**Requirements:** Python 3.9+

---

## 1. Create Agent Identity
```bash
piqrypt identity create my-agent.json
```

**Output:**
```json
{
  "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "public_key": "base64:...",
  "algorithm": "Ed25519",
  "created_at": "2026-03-02T00:00:00Z"
}
```

⚠️ **Keep your private key secret.** Store with 0600 permissions. Never commit to git.

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
  "timestamp": 1741824000,
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "payload": {"action": "hello_world", "status": "active"},
  "previous_hash": "0000...0000",
  "signature": "base64:..."
}
```

---

## 3. Create Event Chain — Python API
```python
from aiss import stamp_event, stamp_genesis_event, derive_agent_id
from aiss.chain import compute_event_hash
from aiss.crypto import ed25519

# Generate keypair and agent identity
private_key, public_key = ed25519.generate_keypair()
agent_id = derive_agent_id(public_key)

# Genesis event
genesis = stamp_genesis_event(private_key, public_key, agent_id, {"init": True})
previous_hash = compute_event_hash(genesis)

# Chain of events
for i in range(5):
    event = stamp_event(
        private_key,
        agent_id,
        payload={"action": f"task_{i}", "step": i},
        previous_hash=previous_hash
    )
    previous_hash = compute_event_hash(event)
    print(f"✓ Event {i+1} signed — hash: {previous_hash[:16]}...")
```

---

## 4. Verify Chain Integrity
```bash
piqrypt verify audit.json
# ✅ Chain integrity verified — 5 events, 0 forks, 0 replays
```
```python
from aiss.chain import verify_chain_linkage
from aiss.fork import find_forks
from aiss.replay import detect_replay_attacks

# Verify linkage
ok = verify_chain_linkage(events)  # True

# Detect attacks
forks = find_forks(events)         # []
replays = detect_replay_attacks(events)  # []
```

---

## 5. Behavioral Monitoring (v1.5+)
```python
from aiss.tsi_engine import compute_tsi
from aiss.anomaly_monitor import compute_vrs

# Trust State Index — STABLE / WATCH / UNSTABLE / CRITICAL
result = compute_tsi(agent_id, current_score=0.85)
print(result["tsi"])      # "STABLE"
print(result["tsi_state"])  # "STABLE"

# Vigil Risk Score — composite behavioral score
vrs = compute_vrs(agent_id)
print(vrs["state"])       # "SAFE"
print(vrs["vrs"])         # 0.09
```

### Launch the Vigil Dashboard
```bash
# Recommended — via launcher (token auto-géré)
.\start_free.ps1

# Or directly
$env:VIGIL_TOKEN="your_token"
python piqrypt_start.py --vigil
# Dashboard → http://127.0.0.1:8421/?token=your_token
# API       → http://127.0.0.1:8421/api/summary
# API       → http://127.0.0.1:8421/api/alerts
```

---

## 6. Export Audit Trail

### Free Tier (Plaintext)
```bash
piqrypt export chain.json audit.json
```

### Pro Tier (Certified)
```bash
# Activate Pro license
piqrypt license activate <jwt_token_received_by_email>

# Create certified export
piqrypt export chain.json audit.json --certified --identity my-agent.json

# Verify
piqrypt verify-export audit.json audit.json.cert
```

---

## 7. Request External Certification (Pro)
```bash
# Create certification request
piqrypt certify-request audit.json audit.json.cert --email you@company.com
# Output: certification-request-CERT-XXXXX.zip
# Email to: piqrypt@gmail.com

# Verify received certificate
piqrypt certify-verify audit-CERT-XXXXX.piqrypt-certified
```

---

## 8. Agent Registry & Isolation
```python
from aiss.agent_registry import AgentRegistry
from pathlib import Path

# Create isolated registry
registry = AgentRegistry(Path("my_registry.json"))
registry.register("trading_bot", {"tier": "pro"})
registry.register("hr_agent", {"tier": "free"})

# List agents
agents = registry.list()

# Get specific agent
bot = registry.get("trading_bot")
```

---

## 9. Encrypt Private Key at Rest (Pro)
```bash
piqrypt memory encrypt
# Enter passphrase (min 16 chars): ****************
# ✅ Key encrypted — scrypt N=2¹⁷ + AES-256-GCM
```
```python
from aiss.identity_session import IdentitySession

# Open session (prompts for passphrase)
with IdentitySession.open("my_agent") as session:
    event = session.sign(payload_bytes)
# Private key automatically zeroed after with block
```

---

## 10. Use with AI Agents

### Claude Desktop (MCP)
```bash
npm install -g @piqrypt/mcp-server
```
```json
{
  "mcpServers": {
    "piqrypt": {
      "command": "piqrypt-mcp-server"
    }
  }
}
```

### n8n Workflow
```bash
npm install n8n-nodes-piqrypt
```
```
[Webhook] → [AI Decision] → [PiQrypt Stamp] → [Execute Action]
```

---

## 11. Key Rotation
```bash
# Rotate identity keys (preserves chain continuity)
piqrypt identity rotate my-agent.json

# View full history across rotation boundaries
piqrypt history 
piqrypt history  --chain    # identity chain only
piqrypt history  --summary  # statistics
```

---

## Next Steps

| | |
|---|---|
| 📐 AISS Specification | [docs/RFC_AISS_v2.0.md](docs/RFC_AISS_v2.0.md) |
| 📊 Implementation Status | [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) |
| 🔒 Security Policy | [SECURITY.md](SECURITY.md) |
| 🔌 Integration Guide | [INTEGRATION.md](INTEGRATION.md) |
| 🤝 A2A Handshake | [docs/A2A_HANDSHAKE_GUIDE.md](docs/A2A_HANDSHAKE_GUIDE.md) |
| 🖥️ CLI Reference | `piqrypt --help` |
| 🐛 Issues | [GitHub Issues](https://github.com/piqrypt/piqrypt/issues) |

---

**Questions?** Email piqrypt@gmail.com or open a [GitHub Issue](https://github.com/piqrypt/piqrypt/issues).

---

**Intellectual Property Notice**

Primary deposit:  DSO2026006483 — 19 February 2026
Addendum:         DSO2026009143 — 12 March 2026

PCP is an open protocol specification.
PiQrypt is the reference implementation.

© 2026 PiQrypt — contact@piqrypt.com
