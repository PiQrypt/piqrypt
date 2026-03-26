# PiQrypt — Developer Documentation

**Version:** 1.7.1 | **Last updated:** 2026-03-12 | **License:** MIT + Apache-2.0 (bridges)

> **PiQrypt** is the reference implementation of the [Proof of Continuity Protocol (PCP)](https://piqrypt.com/pcp) — trust infrastructure for autonomous AI agents. Every agent action is Ed25519-signed, hash-chained, and independently verifiable.

---

## Table of Contents

1. [Installation](#1-installation)
2. [Core Concepts in 5 Minutes](#2-core-concepts-in-5-minutes)
3. [AISS-1 — Single Agent Quickstart](#3-aiss-1--single-agent-quickstart)
4. [Identity & Key Management](#4-identity--key-management)
5. [Stamping Events](#5-stamping-events)
6. [Chain Verification](#6-chain-verification)
7. [Memory — Storage & Search](#7-memory--storage--search)
8. [A2A — Agent-to-Agent Handshake](#8-a2a--agent-to-agent-handshake)
9. [AgentSession — Cross-Framework Audit Trails](#9-agentsession--cross-framework-audit-trails)
10. [Vigil — Behavioural Monitoring](#10-vigil--behavioural-monitoring)
11. [TrustGate — Governance Engine](#11-trustgate--governance-engine)
12. [Framework Bridges](#12-framework-bridges)
13. [Export & Audit](#13-export--audit)
14. [AISS-2 — Post-Quantum & TSA](#14-aiss-2--post-quantum--tsa)
15. [CLI Reference](#15-cli-reference)
16. [Configuration Reference](#16-configuration-reference)
17. [Security Considerations](#17-security-considerations)
18. [Compliance Reference](#18-compliance-reference)
19. [Troubleshooting](#19-troubleshooting)

---

## 1. Installation

### Requirements

- Python 3.9+
- pip 23+
- OS: Linux, macOS, Windows (PowerShell)

### Base Install

```bash
pip install piqrypt
```

### Optional Extras

```bash
pip install piqrypt[session]        # Multi-agent AgentSession bridge
pip install piqrypt[post-quantum]   # AISS-2 — ML-DSA-65 (Dilithium3)
pip install piqrypt[all]            # Everything
```

### Framework Bridges (separate packages)

```bash
pip install piqrypt-langchain       # LangChain / LangGraph
pip install piqrypt-crewai          # CrewAI
pip install piqrypt-autogen         # Microsoft AutoGen
pip install piqrypt-openclaw        # OpenClaw
pip install piqrypt-ollama          # Ollama local LLMs
pip install piqrypt-ros             # ROS2 (requires ROS2 Humble+)
pip install piqrypt-rpi             # Raspberry Pi edge agents
```

### Verify installation

```bash
python -c "import piqrypt; print(piqrypt.__version__)"
# → 1.7.1

python quickstart_dev.py            # Full demo in ~5 seconds
```

---

## 2. Core Concepts in 5 Minutes

### The four layers of PiQrypt

```
┌─────────────────────────────────────────────────────┐
│  TRUSTGATE   Policy / Governance Engine              │  Layer 4
│              EU AI Act · NIST · ANSSI · Compliance   │
├─────────────────────────────────────────────────────┤
│  VIGIL       Behavioural Monitoring                  │  Layer 3
│              TSI · VRS · A2C · Anomaly Detection     │
├─────────────────────────────────────────────────────┤
│  PIQRYPT     Continuity Engine                       │  Layer 2
│              Event chains · Signatures · TSA · A2A   │
├─────────────────────────────────────────────────────┤
│  AISS        Agent Identity Standard                 │  Layer 1
│              Ed25519 · ML-DSA-65 · Key model         │
└─────────────────────────────────────────────────────┘
```

You can use any layer independently. Most integrations start at Layer 1 (AISS) and add layers progressively.

### What is an event?

An **event** is a signed JSON record that captures one agent action:

```json
{
  "version": "AISS-1.0",
  "agent_id": "PIQR1abc123...",
  "timestamp": 1741776000,
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "payload": { "event_type": "trade_executed", "symbol": "AAPL" },
  "previous_hash": "sha256_of_previous_event",
  "signature": "ed25519_base64..."
}
```

- `agent_id` — derived deterministically from the public key. No central registry.
- `nonce` — UUIDv4, prevents replay attacks.
- `previous_hash` — links this event to the prior one. Changing any event breaks all subsequent hashes.
- `signature` — Ed25519 over the canonical JSON (RFC 8785). Non-repudiable.

### What is a chain?

A **chain** is a sequence of events where each event references the hash of the previous one. Modifying any event breaks the chain at that point — detectable by any verifier holding the public key.

```
Genesis ─→ Event 1 ─→ Event 2 ─→ Event 3 ─→ ...
  hash_0     hash_1     hash_2     hash_3
             prev=0     prev=1     prev=2
```

---

## 3. AISS-1 — Single Agent Quickstart

The minimal integration: generate an identity, stamp events, verify the chain.

```python
import piqrypt as aiss

# 1. Generate Ed25519 keypair
private_key, public_key = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(public_key)

print(f"Agent ID: {agent_id}")
# → PIQR1AbCd3f...  (deterministic, derived from public key)

# 2. Stamp the genesis event (first event in the chain)
genesis = aiss.stamp_genesis_event(
    private_key, public_key, agent_id,
    payload={"event_type": "agent_initialized", "version": "1.0"}
)

# 3. Stamp subsequent events
event1 = aiss.stamp_event(
    private_key,
    agent_id,
    payload={"event_type": "trade_decision", "symbol": "AAPL", "action": "buy"},
    previous_hash=aiss.compute_event_hash(genesis),
)

event2 = aiss.stamp_event(
    private_key,
    agent_id,
    payload={"event_type": "trade_executed", "order_id": "ORD-001", "status": "filled"},
    previous_hash=aiss.compute_event_hash(event1),
)

# 4. Store events locally
aiss.store_event(genesis)
aiss.store_event(event1)
aiss.store_event(event2)

# 5. Verify the chain
chain = [genesis, event1, event2]
aiss.verify_chain(chain, public_key)  # raises on failure
print("Chain valid ✓")

# 6. Export audit trail
identity = aiss.export_identity(agent_id, public_key)
audit = aiss.export_audit_chain(identity, chain)

import json
with open("audit.json", "w") as f:
    json.dump(audit, f, indent=2)

print("Audit exported → audit.json")
```

**Run the full demo:**

```bash
python quickstart_dev.py
# → 7-step walkthrough with tamper detection demo
```

---

## 4. Identity & Key Management

### 4.1 Generating a keypair

```python
import piqrypt as aiss

# AISS-1 — Ed25519 (default, Free tier)
private_key, public_key = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(public_key)

# AISS-2 — ML-DSA-65 post-quantum (Pro+ — pip install piqrypt[post-quantum])
from aiss.crypto import dilithium
pq_priv, pq_pub = dilithium.generate_keypair()
```

### 4.2 IdentitySession — secure key handling

`IdentitySession` is the recommended way to hold a private key in production. The key is stored as a `bytearray` and zeroed from RAM when the session closes — even on exception.

```python
from aiss.identity_session import IdentitySession

# Recommended: context manager guarantees RAM erasure
with IdentitySession.open("my_agent", passphrase="my-strong-passphrase") as session:
    event = aiss.stamp_event(session.private_key, session.agent_id, payload)
    aiss.store_event(event)
# Key zeroed here — even if an exception occurred inside

# For Docker / Kubernetes / IoT — from environment variables
# export PIQRYPT_AGENT_NAME=my_agent
# export PIQRYPT_PASSPHRASE=my-strong-passphrase
with IdentitySession.from_env() as session:
    event = aiss.stamp_event(session.private_key, session.agent_id, payload)
```

### 4.3 Encrypted key storage (Pro tier)

```bash
# Encrypt an existing plaintext key
piqrypt identity secure my_agent

# Create a new agent with encrypted key from the start
piqrypt identity create my_agent --encrypt
```

Encrypted keys use `scrypt(N=2¹⁷) + AES-256-GCM` — approximately 400ms per decryption attempt on modern hardware, making brute-force impractical.

**Key file format (97 bytes):**

```
[4 bytes]  magic bytes: "PQKY"
[1 byte]   version: 0x01
[32 bytes] scrypt salt (random per key)
[12 bytes] AES-GCM nonce
[48 bytes] ciphertext (32B key + 16B GCM auth tag)
```

### 4.4 Agent Registry

```python
from aiss.agent_registry import register_agent, list_agents, get_agent_info

# Register an agent after creating its identity
register_agent("trading_bot", agent_id, tier="pro", metadata={"env": "prod"})

# List all agents on this installation
agents = list_agents()
for agent in agents:
    print(agent["name"], agent["agent_id"])

# Get info for a specific agent
info = get_agent_info("trading_bot")
# → {"name": "trading_bot", "agent_id": "PIQR1...", "tier": "pro", ...}
```

Agent directories are created under `~/.piqrypt/agents/<name>/` with `chmod 700`. Agent names are sanitized to prevent path traversal: `../`, backslashes, and null bytes are neutralized.

### 4.5 Key Rotation

When an agent rotates its keys, its `agent_id` changes. PiQrypt maintains continuity across rotations via a rotation attestation:

```python
from aiss.identity import create_rotation_attestation, create_rotation_pcp_event

# Generate new keypair
new_priv, new_pub = aiss.generate_keypair()
new_agent_id = aiss.derive_agent_id(new_pub)

# Create signed attestation linking old → new identity
attestation = create_rotation_attestation(
    old_private_key, old_agent_id,
    new_agent_id,
    reason="scheduled_rotation"
)

# Stamp rotation event in the chain (signed by OLD key)
rotation_event = create_rotation_pcp_event(
    old_private_key, old_agent_id,
    new_agent_id, attestation,
    previous_hash=aiss.compute_event_hash(last_event)
)
aiss.store_event(rotation_event)

# Load complete history across rotation boundary
from aiss.memory import load_full_history
full_history = load_full_history(new_agent_id)
# → events from both identities, in chronological order
```

---

## 5. Stamping Events

### 5.1 Basic stamp

```python
event = aiss.stamp_event(
    private_key,
    agent_id,
    payload={"event_type": "action_taken", "details": "..."},
    previous_hash=aiss.compute_event_hash(previous_event),
)
```

### 5.2 Genesis event

The genesis event is the first event in a chain. Its `previous_hash` is the string `"genesis"`.

```python
genesis = aiss.stamp_genesis_event(
    private_key, public_key, agent_id,
    payload={"event_type": "agent_initialized"}
)
```

### 5.3 Event payload conventions

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | `str` | Machine-readable action label (required) |
| Any other fields | `any` | Domain-specific payload |

**Privacy guidance:** Never store raw PII in event payloads. Use SHA-256 hashes of sensitive values:

```python
import hashlib

def h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

event = aiss.stamp_event(private_key, agent_id, payload={
    "event_type": "patient_diagnosis",
    "patient_hash": h("patient_id:P2026-441"),   # PII hashed
    "diagnosis_hash": h("ICD10:I21.4"),           # diagnosis hashed
    "confidence": 0.91,                           # non-PII: stored as-is
})
```

### 5.4 Chaining events correctly

```python
events = []

genesis = aiss.stamp_genesis_event(private_key, public_key, agent_id, {"event_type": "init"})
events.append(genesis)

for action in ["step_1", "step_2", "step_3"]:
    prev_hash = aiss.compute_event_hash(events[-1])
    event = aiss.stamp_event(private_key, agent_id,
                              payload={"event_type": action},
                              previous_hash=prev_hash)
    events.append(event)
    aiss.store_event(event)
```

### 5.5 AISS-2 — timestamped events (RFC 3161 TSA)

```python
# Pro+ tier — requires pip install piqrypt[post-quantum]
from aiss.tsa import stamp_with_tsa

event = aiss.stamp_event(private_key, agent_id, payload, previous_hash)
event_with_tsa = stamp_with_tsa(event)
# → adds "trusted_timestamp": { "token": "...", "tsa_url": "...", "verified": true }
```

TSA tokens create externally verifiable timestamps. A `FORK_AFTER_FINALIZATION` is detectable when a branch diverges after a TSA-anchored event.

---

## 6. Chain Verification

### 6.1 Full chain verification

```python
# Raises InvalidChainError, InvalidSignatureError, or ReplayAttackDetected on failure
aiss.verify_chain(events, public_key)
print("Chain valid ✓")
```

### 6.2 Individual checks

```python
from aiss.chain import verify_chain_linkage, verify_monotonic_timestamps
from aiss.replay import detect_replay_attacks

# Hash chain linkage
verify_chain_linkage(events)       # raises InvalidChainError on break

# Monotonic timestamps
verify_monotonic_timestamps(events)  # raises InvalidChainError if ts goes backward

# Replay attack detection
replays = detect_replay_attacks(events)  # returns list of duplicate nonces
if replays:
    raise Exception(f"Replay detected: {replays}")

# Individual event signature
aiss.verify_event(event)           # raises InvalidSignatureError on bad sig
aiss.verify_signature(event, public_key)
```

### 6.3 Tamper detection example

```python
import copy

# Attacker modifies Event 2
tampered_chain = copy.deepcopy(events)
tampered_chain[2]["payload"]["amount"] = 999999

try:
    verify_chain_linkage(tampered_chain)
except InvalidChainError as e:
    print(f"Tamper detected at event index: {e.event_index}")
    # → Tamper detected at event index: 3
    # (Event 3's previous_hash no longer matches the modified Event 2)
```

### 6.4 Fork detection

```python
from aiss.fork import find_forks

forks = find_forks(events)
if forks:
    for fork in forks:
        print(f"Fork at hash: {fork.hash[:16]}... — {len(fork.branches)} branches")
```

---

## 7. Memory — Storage & Search

### 7.1 Store and load events

```python
# Store (persists to ~/.piqrypt/agents/<name>/)
aiss.store_event(event, agent_name="my_agent")

# Load all events for an agent
events = aiss.load_events(agent_id=agent_id, agent_name="my_agent")

# Load complete history including key rotations
from aiss.memory import load_full_history
full_history = load_full_history(agent_id)
```

### 7.2 Search

```python
results = aiss.search_events(
    agent_id=agent_id,
    event_type="trade_executed",      # filter by type
    after=1741776000,                 # Unix timestamp
    before=1741862400,
    limit=50,
)

# Search by session (multi-agent session_id)
results = aiss.search_events(session_id="sess_a3f29b4c...")

# Follow key rotation chain automatically
results = aiss.search_events(agent_id=new_agent_id, follow_rotation=True)
```

### 7.3 Memory stats

```python
stats = aiss.get_memory_stats()
# → {"total_events": 1243, "agents": 5, "size_bytes": 284920,
#    "sessions_count": 7, "rotations_count": 2}
```

### 7.4 Encrypted memory (Pro tier)

```python
# Unlock encrypted memory with passphrase
aiss.unlock("my_agent", passphrase="my-strong-passphrase")

events = aiss.load_events(agent_id=agent_id)

# Always lock when done
aiss.lock("my_agent")

# Or use context manager
from aiss.memory import MemorySession
with MemorySession("my_agent", passphrase="...") as mem:
    events = mem.load_events(agent_id)
```

---

## 8. A2A — Agent-to-Agent Handshake

A2A establishes mutual cryptographic identity between two agents before any interaction. The co-signed handshake event is recorded in **both** agents' chains.

### 8.1 Basic handshake

```python
from aiss.a2a import (
    create_identity_proposal,
    create_identity_response,
    build_cosigned_handshake_event,
)

# Agent A creates a proposal
proposal = create_identity_proposal(
    agent_a_private_key, agent_a_public_key, agent_a_id,
    capabilities=["stamp", "verify", "a2a"],
    metadata={"role": "orchestrator"},
)

# Agent B responds (typically on the other side of a network call)
response = create_identity_response(
    agent_b_private_key, agent_b_public_key, agent_b_id,
    proposal,
    capabilities=["stamp", "verify", "a2a"],
)

# Both agents build a co-signed handshake event for their own chain
event_a = build_cosigned_handshake_event(
    agent_a_private_key, agent_a_id,
    proposal, response,
    previous_hash=aiss.compute_event_hash(last_event_a),
)
aiss.store_event(event_a)

event_b = build_cosigned_handshake_event(
    agent_b_private_key, agent_b_id,
    proposal, response,
    previous_hash=aiss.compute_event_hash(last_event_b),
)
aiss.store_event(event_b)
```

The co-signed handshake event is signed by **both** agents over the same payload. Modifying the `capabilities_agreed` field after signing invalidates both signatures simultaneously — the agreed profile cannot be downgraded post-handshake.

---

## 9. AgentSession — Cross-Framework Audit Trails

`AgentSession` is the first tool to provide cryptographic co-signatures across framework boundaries. Every cross-agent interaction is co-signed in **both** agents' memories with the **same `interaction_hash`** — tampering is detectable regardless of which framework each agent uses.

**The key property:** LangSmith traces LangChain only. CrewAI logs CrewAI only. PiQrypt Session produces a provable causal chain across all frameworks simultaneously.

### 9.1 Quickstart

```python
from piqrypt_session import AgentSession

# 1. Declare all agents in the pipeline
session = AgentSession([
    {"name": "claude",    "identity_file": "~/.piqrypt/claude.json"},
    {"name": "langgraph", "identity_file": "~/.piqrypt/langgraph.json"},
    {"name": "crewai",    "identity_file": "~/.piqrypt/crewai.json"},
])

# 2. Start — performs pairwise Ed25519 handshakes (3 agents = 3 pairs)
session.start()
# → [handshake] claude ↔ langgraph  co-signed ✓
# → [handshake] claude ↔ crewai     co-signed ✓
# → [handshake] langgraph ↔ crewai  co-signed ✓

# 3. Co-signed cross-agent interaction
session.stamp("claude", "instruction_sent", {
    "task": "analyse portfolio",
    "context_hash": hashlib.sha256(portfolio_data).hexdigest(),
}, peer="langgraph")
# → stamps "instruction_sent"          in claude's memory
# → stamps "instruction_sent_received" in langgraph's memory
# → same interaction_hash in both

# 4. Unilateral action (no peer)
session.stamp("crewai", "trade_executed", {
    "symbol": "AAPL", "action": "BUY", "qty": 100
})

# 5. Export full cross-framework audit trail
session.export("audit_session.json")
```

**Run the multi-framework demo:**

```bash
python quickstart_session.py                     # trading pipeline
python quickstart_session.py --scenario healthcare  # EU AI Act Art.22
python quickstart_session.py --scenario robotics    # IEC 62443
python quickstart_session.py --scenario all         # all three
```

### 9.2 Why the same `interaction_hash` matters

```python
session.stamp("claude", "recommendation", {"action": "BUY"}, peer="crewai")

# In Claude's memory:
# { event_type: "recommendation",
#   interaction_hash: "a3f29b4c...",
#   peer_agent_id: "<crewai_id>",
#   signature: <claude_sig> }

# In CrewAI's memory:
# { event_type: "recommendation_received",
#   interaction_hash: "a3f29b4c...",     ← IDENTICAL
#   peer_agent_id: "<claude_id>",
#   signature: <crewai_sig> }

# To falsify what Claude sent, an attacker must:
# 1. Modify Claude's event (breaking Claude's chain)
# 2. Modify CrewAI's event (breaking CrewAI's chain)
# 3. Keep both interaction_hashes identical (impossible without both private keys)
```

### 9.3 Privacy — raw data never stored

`AgentSession.stamp()` automatically hashes all payload values that don't already end in `_hash` or `_id`:

```python
session.stamp("agent", "patient_visit", {
    "patient_id": "P2026-441",              # kept as-is (ends in _id)
    "diagnosis": "NSTEMI",                  # → stored as diagnosis_hash: sha256("NSTEMI")
    "confidence": 0.91,                     # → stored as confidence_hash: sha256("0.91")
})
# Raw diagnosis never persisted. RGPD-compliant by design.
```

### 9.4 AgentSession API reference

```python
AgentSession(agents: list[dict])
# agents: [{"name": str, "identity_file": str}, ...]

session.start() -> AgentSession              # pairwise handshakes
session.end() -> dict                        # stamp session_end in all memories
session.stamp(
    agent_name: str,
    event_type: str,
    payload: dict,
    peer: str | None = None,
) -> tuple[event, interaction_hash | None]

session.export(path: str) -> str             # export full audit
session.summary() -> dict                    # metadata + event counts
session.session_id -> str
session.agents -> dict[str, AgentMember]
session.get_agent(name: str) -> AgentMember

# AgentMember
member.name -> str
member.agent_id -> str
member.event_count -> int
member.events -> list[dict]
```

---

## 10. Vigil — Behavioural Monitoring

Vigil computes a **Vigil Risk Score (VRS)** for each agent by aggregating four independent signals:

```
VRS = 0.35 × (1 − Trust Score)
    + 0.30 × TSI weight
    + 0.20 × A2C risk
    + 0.15 × Chain anomaly score
```

| State | VRS Range | Meaning |
|-------|-----------|---------|
| `SAFE` | 0.00 – 0.25 | Normal behaviour |
| `WATCH` | 0.25 – 0.50 | Weak signal — log and observe |
| `ALERT` | 0.50 – 0.75 | Significant anomaly — investigate |
| `CRITICAL` | 0.75 – 1.00 | Immediate action required |

### 10.1 Start Vigil

```bash
# Start Vigil dashboard (port 8421, localhost only)
python piqrypt_start.py --vigil

# Or directly
python -m vigil.vigil_server
python -m vigil.vigil_server --port 9000 --host 0.0.0.0   # external access
```

Open `http://localhost:8421` to see the real-time dashboard.

### 10.2 Compute VRS programmatically

```python
from aiss.anomaly_monitor import compute_vrs, get_installation_summary

# VRS for a single agent
result = compute_vrs("my_agent", agent_id=agent_id, events=events)

print(result["vrs"])       # 0.12 — float [0, 1]
print(result["state"])     # "SAFE"
print(result["components"]["trust_score"]["score"])  # 0.94
print(result["components"]["tsi"]["state"])          # "STABLE"
print(result["components"]["a2c"]["risk"])           # 0.02
print(result["alerts"])    # [] — list of active alerts

# Installation-wide summary (all agents)
summary = get_installation_summary()
print(summary["installation_state"])   # "SAFE"
print(summary["global_vrs"])           # 0.08
print(summary["critical_count"])       # 0
```

### 10.3 TSI — Trust Stability Index

TSI measures the **stability over time** of an agent's trust score, not just its current value. An agent that fluctuates between 0.9 and 0.3 over 24 hours is more concerning than one that holds steady at 0.7.

| State | Meaning |
|-------|---------|
| `STABLE` | Baseline behaviour |
| `WATCH` | Weak drift signal |
| `UNSTABLE` | Significant drift — 24h delta triggers |
| `CRITICAL` | Critical drift — TrustGate escalation |

```python
from aiss.tsi_engine import compute_tsi

result = compute_tsi(agent_id, current_score=0.87)
print(result["tsi_state"])    # "STABLE"
print(result["delta_24h"])    # -0.02  (small negative drift)
print(result["z_score"])      # 0.31   (well within 2σ baseline)
```

### 10.4 A2C — Agent-to-Agent Collusion Detector

A2C detects suspicious coordination patterns between agents:

| Detector | Signal | Threshold |
|----------|--------|-----------|
| Concentration | >70% of interactions with one peer | configurable |
| Entropy drop | Shannon diversity of peers drops >0.4 in 48h | configurable |
| Synchronisation | Cross-correlation of event timing | ±5s window |
| Silence break | Dormant agent resumes, correlated with active peer | >7 days silence |

```python
from aiss.a2c_detector import compute_a2c_risk

result = compute_a2c_risk(
    agent_id,
    events=events,
    peer_events_map={"peer_id": peer_events},  # optional
)
print(result["a2c_risk"])    # 0.0 — float [0, 1]
print(result["severity"])    # "NONE"
print(result["indicators"])  # {"concentration": 0.0, "entropy_drop": 0.0, ...}
```

### 10.5 Vigil REST API

```
GET  /health                     → {"status": "ok"}
GET  /api/summary                → installation-wide VRS summary
GET  /api/alerts                 → all active alerts
GET  /api/agent/<name>           → per-agent VRS details
GET  /api/agent/<name>/alerts    → alert journal for agent
POST /api/agent/<name>/record    → inject external event for monitoring
GET  /api/agent/<name>/export/pqz-cert    → certified export
GET  /api/agent/<name>/export/pdf         → PDF report
```

**Authentication:** `Authorization: Bearer $VIGIL_TOKEN` (set `VIGIL_TOKEN` env var).

---

## 11. TrustGate — Governance Engine

TrustGate intercepts agent actions **before execution** and applies deterministic governance rules. Every decision is signed and recorded in a hash-chained audit journal.

**Design principle:** Zero AI, zero heuristics. Same input → same output, always.

### 11.1 Start TrustGate

```bash
# Pro+ tier required
python piqrypt_start.py --trustgate

# Or directly
python -m trustgate.trustgate_server
```

### 11.2 Evaluate an action

```python
from trustgate.decision import EvaluationContext
from trustgate.policy_loader import load_policy
from trustgate.policy_engine import evaluate

# Load and hash-verify policy
policy = load_policy("~/.piqrypt/trustgate/policy.yaml")

# Build evaluation context
ctx = EvaluationContext(
    agent_id=agent_id,
    agent_name="trading_bot",
    action="execute_trade",
    payload={"symbol": "AAPL", "qty": 100},
    role="operator",
    vrs=0.18,                    # from Vigil
    tsi_state="STABLE",          # from Vigil
    target_domain="nyse.com",
)

# Evaluate — deterministic, no side effects
decision = evaluate(ctx, policy)

print(decision.outcome)   # "ALLOW" | "BLOCK" | "REQUIRE_HUMAN" | ...
print(decision.reason)    # "VRS 0.18 < block threshold 0.85"
print(decision.policy_hash)  # SHA-256 of policy at decision time

if decision.outcome == "BLOCK":
    raise PermissionError(f"TrustGate BLOCK: {decision.reason}")
elif decision.outcome == "REQUIRE_HUMAN":
    # Send to human approval queue — see section 11.4
    pass
```

### 11.3 Policy profiles

Three built-in profiles are included:

| Profile | Use Case | VRS Block | External Calls |
|---------|----------|-----------|----------------|
| `ai_act_high_risk.yaml` | EU AI Act high-risk AI | 0.70 | Blocked |
| `nist_balanced.yaml` | US enterprise, moderate risk | 0.85 | Allowed with log |
| `anssi_strict.yaml` | French critical infrastructure | 0.65 | Blocked |

Load a profile:

```bash
piqrypt trustgate activate-policy profiles/ai_act_high_risk.yaml \
  --comment "Activated for EU AI Act compliance audit"
```

Custom policy YAML:

```yaml
version: "1.0"
name: "my_policy"

thresholds:
  vrs_require_human: 0.60
  vrs_block: 0.85
  tsi_critical_action: "BLOCK"

roles:
  operator:
    allowed_tools: [read_db, write_db, http_get, http_post]
    blocked_tools: [shell, admin, delete]
  read_only:
    allowed_tools: [read_db, list_files, search]
    blocked_tools: ["*_write", admin, delete]

dangerous_patterns:
  - "rm\\s+-rf"
  - "DROP\\s+TABLE"
  - "/etc/(passwd|shadow)"
  - "financial_transfer"

network:
  block_external: false
  log_external_calls: true

notification:
  timeout_seconds: 300
  on_timeout: "DENY"     # or "ESCALATE"

escalation:
  max_watch_events: 5
  auto_restrict_after: 8
```

### 11.4 Human oversight — REQUIRE_HUMAN flow

```python
# TrustGate returns REQUIRE_HUMAN for high-VRS actions
decision = evaluate(ctx, policy)

if decision.outcome == "REQUIRE_HUMAN":
    # Notify human — via email, Slack, webhook (configurable)
    # Decision expires after timeout_seconds (default 300s)
    print(f"Decision ID: {decision.id}")
    print(f"Expires: {decision.expires_at}")

    # Human approves via API or CLI
    # POST /api/decisions/<id>/approve
    # → piqrypt trustgate approve <decision_id> --by "Dr. Dupont"

    # Or check programmatically
    approved = wait_for_human_decision(decision.id, timeout=300)
    if not approved:
        # Timeout → automatic DENY (signed chain event)
        raise PermissionError("Human approval timeout — action denied")
```

**CLI approval:**

```bash
piqrypt trustgate pending                    # list pending decisions
piqrypt trustgate approve <decision_id>      # approve
piqrypt trustgate reject <decision_id> --reason "Risk too high"
```

### 11.5 Policy versioning and audit

```python
from trustgate.policy_versioning import PolicyVersioning

pv = PolicyVersioning()

# View policy history
history = pv.get_history()
for version in history:
    print(version.version_id, version.activated_at, version.activated_by)

# Diff two versions
diff = pv.diff(version_id_1, version_id_2)
print(diff)  # human-readable diff of what changed

# Verify a version hasn't been tampered with
pv.verify(version_id)  # raises PolicyIntegrityError if hash mismatch
```

### 11.6 TrustGate REST API

```
GET  /api/status
GET  /api/policy                   → current policy + hash
POST /api/policy/simulate          → dry-run evaluation (no side effects)
POST /api/evaluate                 → evaluate an action
GET  /api/decisions                → all decisions
GET  /api/decisions/<id>
POST /api/decisions/<id>/approve
POST /api/decisions/<id>/reject
GET  /api/principals               → registered human principals
POST /api/principals
GET  /api/audit                    → audit journal
GET  /api/audit/export             → export journal
POST /api/vigil/agent-state        → receive VRS from Vigil
```

---

## 12. Framework Bridges

Each bridge provides a drop-in wrapper that signs every agent action into the AISS chain without modifying application logic.

### 12.1 LangChain

```python
from piqrypt_langchain import PiQryptCallbackHandler, AuditedAgentExecutor

# Option 1: Callback handler (most powerful — attaches to any component)
handler = PiQryptCallbackHandler(identity_file="~/.piqrypt/my_agent.json")

# Attach to any LangChain component
llm_with_audit = llm.with_config(callbacks=[handler])
chain_with_audit = my_chain.with_config(callbacks=[handler])

# Option 2: Audited executor
executor = AuditedAgentExecutor(
    agent=agent,
    tools=tools,
    identity_file="~/.piqrypt/my_agent.json",
)
result = executor.invoke({"input": "analyse this portfolio"})
# → every LLM call, tool call, and step signed automatically
```

### 12.2 CrewAI

```python
from piqrypt_crewai import AuditedAgent, AuditedCrew

researcher = AuditedAgent(
    role="Researcher",
    goal="Research market trends",
    backstory="Expert analyst",
    identity_file="~/.piqrypt/researcher.json",
)

trader = AuditedAgent(
    role="Trader",
    goal="Execute optimal trades",
    backstory="Algorithmic trader",
    identity_file="~/.piqrypt/trader.json",
)

crew = AuditedCrew(
    agents=[researcher, trader],
    tasks=[research_task, trade_task],
)
result = crew.kickoff()
# → every task execution signed in each agent's chain
```

### 12.3 AutoGen

```python
from piqrypt_autogen import AuditedConversableAgent, AuditedGroupChat

assistant = AuditedConversableAgent(
    name="assistant",
    identity_file="~/.piqrypt/assistant.json",
    system_message="You are a helpful assistant.",
    llm_config={"model": "gpt-4"},
)

user = AuditedConversableAgent(
    name="user_proxy",
    identity_file="~/.piqrypt/user_proxy.json",
    human_input_mode="NEVER",
)

chat = AuditedGroupChat(agents=[assistant, user], messages=[])
# → every message exchange co-signed
```

### 12.4 ROS2

```python
from piqrypt_ros import AuditedNode
from std_msgs.msg import String

class MyRobot(AuditedNode):
    def __init__(self):
        super().__init__(
            node_name="my_robot",
            identity_file="~/.piqrypt/my_robot.json",
        )
        # Audited publisher — every publish() call is signed automatically
        self.pub = self.create_audited_publisher(String, "/cmd", 10)

        # Audited subscription — every received message is signed
        self.sub = self.create_audited_subscription(String, "/sensor", 10)

    def on_sensor(self, msg):
        # msg is automatically stamped on receipt
        response = String(data=f"processed: {msg.data}")
        self.pub.publish(response)  # stamped automatically
```

### 12.5 Raspberry Pi

```python
from piqrypt_rpi import AuditedRPiAgent

agent = AuditedRPiAgent(
    name="temperature_sensor",
    identity_file="~/.piqrypt/rpi_sensor.json",
)

# Stamp a sensor reading
agent.stamp_reading("temperature", {"celsius": 23.4, "humidity": 61})

# Stamp a command execution
agent.stamp_command("fan_on", {"speed": 80, "reason": "overheating"})
```

### 12.6 Bridge compatibility matrix

| Bridge | Works with Session | Works with Vigil | Works with TrustGate |
|--------|-------------------|-----------------|---------------------|
| LangChain | ✅ | ✅ | ✅ |
| CrewAI | ✅ | ✅ | ✅ |
| AutoGen | ✅ | ✅ | ✅ |
| OpenClaw | ✅ | ✅ | ✅ |
| Session | — | ✅ | ✅ |
| MCP | ✅ | ✅ | ✅ |
| Ollama | ✅ | ✅ | ⚠ planned |
| ROS2 | ✅ | ✅ | ✅ |
| RPi | ✅ | ✅ | ⚠ planned |

---

## 13. Export & Audit

### 13.1 Export audit chain

```python
identity = aiss.export_identity(agent_id, public_key)
audit = aiss.export_audit_chain(identity, events)

import json
with open("audit.json", "w") as f:
    json.dump(audit, f, indent=2)
```

The exported JSON contains:
- Agent identity document (public key, agent_id, creation timestamp)
- Full event chain with signatures
- Chain hash (SHA-256 over all event hashes)
- AISS version and conformance level

### 13.2 Export formats (Vigil)

| Format | Description | Legal standing |
|--------|-------------|---------------|
| `.pqz CERTIFIED` | Ed25519 signed + RFC 3161 TSA timestamp | eIDAS Art.26 advanced electronic signature |
| `.pqz MEMORY` | Full history, portable, auto-extractible | Internal audit use |
| `PDF REPORT` | Human-readable report | Internal audit — not certified |

```bash
# Via Vigil API
curl http://localhost:8421/api/agent/my_agent/export/pqz-cert \
  -H "Authorization: Bearer $VIGIL_TOKEN" \
  -o my_agent_certified.pqz

# Via CLI
piqrypt export my_agent --format certified --output my_agent.pqz
```

### 13.3 Verify an export

```bash
piqrypt verify audit.json             # verifies chain + all signatures
piqrypt verify my_agent.pqz           # verifies .pqz archive
piqrypt session-verify session_audit.json  # verifies cross-framework consistency
```

```python
# Programmatic verification
from aiss.exports import verify_audit_export

result = verify_audit_export("audit.json")
print(result["valid"])          # True
print(result["event_count"])    # 47
print(result["chain_hash"])     # sha256...
```

### 13.4 Public verification registry

PiQrypt-issued certifications are registered in a public GitHub-based verification registry (SHA-256 / HMAC, RGPD-compliant). Anyone can verify a certificate without contacting PiQrypt:

```bash
piqrypt verify-public <certificate_hash>
# → Checks against https://github.com/piqrypt/registry
```

---

## 14. AISS-2 — Post-Quantum & TSA

AISS-2 adds post-quantum resistance and mandatory trusted timestamps to the AISS-1 baseline.

### 14.1 Requirements

```bash
pip install piqrypt[post-quantum]   # adds liboqs-python (ML-DSA-65 / Dilithium3)
```

AISS-2 requires a Pro+ license (`piqrypt activate-license <key>`).

### 14.2 Generate AISS-2 identity

```python
from aiss.crypto import dilithium
from aiss.identity_aiss2 import generate_aiss2_identity

# Generate hybrid keypair: Ed25519 (AISS-1) + ML-DSA-65 (post-quantum)
identity = generate_aiss2_identity(agent_name="my_pq_agent", passphrase="...")
# → identity["aiss1"]["private_key"]  — Ed25519
# → identity["aiss2"]["private_key"]  — ML-DSA-65
# → identity["agent_id"]              — same derivation as AISS-1
```

### 14.3 Stamp with post-quantum signature + TSA

```python
from aiss.stamp_aiss2 import stamp_event_aiss2

event = stamp_event_aiss2(
    ed25519_private_key=identity["aiss1"]["private_key"],
    dilithium_private_key=identity["aiss2"]["private_key"],
    agent_id=identity["agent_id"],
    payload={"event_type": "critical_action"},
    previous_hash=prev_hash,
    tsa=True,   # request RFC 3161 timestamp from configured TSA
)

# event["signatures"]["post_quantum"]["algorithm"] → "ML-DSA-65"
# event["trusted_timestamp"]["token"]              → RFC 3161 DER token
# event["version"]                                 → "AISS-2.0"
```

### 14.4 TSA Fallback policy

If the TSA server is unreachable, AISS-2 implementations must:

1. Stamp the event with AISS-1 guarantees only
2. Mark `"tsa_status": "pending"` in the event payload
3. Retry anchoring within 24 hours
4. Raise a `tsa_failure` Vigil alert if anchoring cannot be completed

```python
from aiss.tsa import stamp_with_tsa, TSAUnavailableError

try:
    event = stamp_with_tsa(event)
except TSAUnavailableError:
    event["payload"]["tsa_status"] = "pending"
    tsa_retry_queue.append(event)
    # FORK_AFTER_FINALIZATION detection suspended until anchoring completes
```

### 14.5 Profile downgrade protection

Receiving implementations **MUST** reject events claiming `version: "AISS-2.0"` without the required fields:

```python
from aiss.verify_aiss2 import verify_aiss2_conformance

try:
    verify_aiss2_conformance(event)
except ProfileMismatchError as e:
    # "AISS-2.0 event missing ML-DSA-65 signature"
    # Event rejected — not silently downgraded to AISS-1
    raise
```

---

## 15. CLI Reference

```bash
# Identity
piqrypt identity create <name>               # create new agent identity
piqrypt identity create <name> --encrypt     # create with encrypted key
piqrypt identity secure <name>               # encrypt existing plaintext key
piqrypt identity list                        # list all agents
piqrypt identity info <name>                 # agent details

# Chain
piqrypt verify <file>                        # verify audit chain
piqrypt verify-public <cert_hash>            # verify against public registry

# Memory
piqrypt memory stats                         # storage statistics
piqrypt memory search --type trade_executed  # search events
piqrypt memory search --session <session_id>
piqrypt history <agent_id>                   # full history with rotation markers
piqrypt history <agent_id> --follow-rotation

# Export
piqrypt export <agent_name>                  # export audit chain
piqrypt export <agent_name> --format certified
piqrypt export <agent_name> --format pdf

# Vigil
piqrypt vigil start                          # start Vigil server
piqrypt vigil status                         # current VRS for all agents
piqrypt vigil alerts                         # active alerts

# TrustGate (Pro+)
piqrypt trustgate start                      # start TrustGate server
piqrypt trustgate activate-policy <file>     # activate policy
piqrypt trustgate pending                    # pending REQUIRE_HUMAN decisions
piqrypt trustgate approve <decision_id>
piqrypt trustgate reject <decision_id>
piqrypt trustgate audit                      # audit journal

# License
piqrypt activate-license <key>
piqrypt license info

# Session
piqrypt session-verify <session_audit.json>  # verify cross-framework audit
```

---

## 16. Configuration Reference

### 16.1 Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PIQRYPT_HOME` | `~/.piqrypt` | Root data directory |
| `PIQRYPT_AGENT_NAME` | — | Agent name for `IdentitySession.from_env()` |
| `PIQRYPT_PASSPHRASE` | — | Passphrase for `IdentitySession.from_env()` |
| `VIGIL_TOKEN` | — | Bearer token for Vigil API (required) |
| `VIGIL_PORT` | `8421` | Vigil server port |
| `VIGIL_HOST` | `127.0.0.1` | Vigil server host |
| `TRUSTGATE_TOKEN` | — | Bearer token for TrustGate API (required) |
| `TRUSTGATE_PORT` | `8422` | TrustGate server port |
| `TRUSTGATE_HOST` | `127.0.0.1` | TrustGate server host |
| `VIGIL_NO_BROWSER` | `0` | Set to `1` to suppress browser auto-open |
| `VIGIL_DEV_DELETE` | `0` | Set to `1` to enable agent deletion (dev only) |

### 16.2 Directory layout

```
~/.piqrypt/
├── agents/
│   └── <agent_name>/
│       ├── identity.json          # agent_id + public key
│       ├── private.key.enc        # encrypted private key (Pro)
│       ├── private.key.json       # plaintext key (Free — dev only)
│       └── vigil/
│           ├── alerts.json        # Vigil alert journal
│           └── vrs_history.json   # 30-day VRS history
├── events/                        # Free tier flat-file storage
├── trustgate/
│   ├── journal/                   # hash-chained governance decisions
│   ├── policy_versions/           # immutable policy history
│   └── policy.yaml                # active policy
└── index.db                       # SQLite event index
```

---

## 17. Security Considerations

### 17.1 Private key security

- **Never commit key files to version control.** The provided `.gitignore` excludes `*.key.enc` and `*.key.json` — verify before every push.
- **Use encrypted keys in production** (`piqrypt identity secure`). Free-tier plaintext keys are acceptable only for development.
- **Use HSM for Enterprise/critical deployments** — contact sales@piqrypt.com.
- `IdentitySession` guarantees RAM erasure via `_secure_erase()` — prefer it over holding `private_key` in a plain variable.

### 17.2 Threat model summary

| Attack | Coverage | Mechanism |
|--------|----------|-----------|
| Retroactive event modification | ✅ | Hash chain break |
| Identity repudiation | ✅ | Ed25519 / ML-DSA-65 |
| Replay attack | ✅ | UUIDv4 nonce deduplication |
| Brute-force key | ✅ | scrypt N=2¹⁷ (~400ms/attempt) |
| Agent impersonation | ✅ | Public key binding |
| Fork after finalization | ✅ | TSA anchor + Vigil |
| Semantic evasion (payload manipulation) | ✅ | TrustGate `dangerous_patterns` on full payload |
| Insider threat (valid key) | ⚠ | TSA + Vigil baseline + TrustGate role policy |
| Protocol downgrade (AISS-1↔2) | ✅ | `PROFILE_MISMATCH` — no silent downgrade |
| Quantum attack (2035+) | ✅ | ML-DSA-65 (AISS-2) |

Full threat model: see [RFC AISS v2.0 §21](https://docs.piqrypt.com/rfc/security).

### 17.3 Known limitations (v1.7.1)

| Limitation | Impact | Planned fix |
|-----------|--------|-------------|
| `verify_tsa_token()` checks DER structure only — no full CMS/PKCS7 verification | A crafted TSA token could pass as verified | v1.8.2 |
| Vigil/TrustGate use static `VIGIL_TOKEN` env var | No per-user auth | v1.8.2 OIDC/SSO |
| Flat-file event storage | Degrades >100k events/agent | v2.0 PostgreSQL |

### 17.4 Responsible disclosure

Security vulnerabilities: **security@piqrypt.com** — 48h acknowledgement, 15-day fix target. Do not open public GitHub issues before coordinated disclosure. PGP key available on request.

---

## 18. Compliance Reference

| Regulation | Article | PiQrypt Coverage |
|-----------|---------|-----------------|
| EU AI Act | Art.9 | Risk management — TrustGate policy versioning |
| EU AI Act | Art.12 | Automatic logging — TrustGate audit journal |
| EU AI Act | Art.13 | Transparency — agent identity + chain export |
| EU AI Act | Art.14 | Human oversight — REQUIRE_HUMAN flow + TTL |
| EU AI Act | Art.22 | High-risk AI — `ai_act_high_risk.yaml` profile |
| NIST AI RMF | GOVERN 1.2 | Role-based access — TrustGate roles |
| NIST AI RMF | MANAGE 1.3 | Risk prioritization — VRS thresholds |
| NIST AI RMF | MEASURE 2.5 | TSI monitoring — Vigil |
| ANSSI | R9 | No automated critical action — REQUIRE_HUMAN |
| ANSSI | R25 | Dangerous input filtering — `dangerous_patterns` |
| ANSSI | R26/R30 | Least privilege — role-action binding |
| ANSSI | R35 | Policy integrity — SHA-256 on load |
| MiFID II | Art.17 | Algorithmic trading records — chain export |
| RGPD | — | Raw data never stored — payload hashing by default |
| eIDAS | Art.26 | Advanced electronic signature — certified `.pqz` |
| IEC 62443 | — | Industrial robot audit — ROS2 bridge |

---

## 19. Troubleshooting

### ImportError: No module named 'piqrypt'

```bash
pip install piqrypt
# If in a virtualenv, ensure it is activated
```

### AgentNotFoundError: Agent 'X' not found

The agent directory does not exist. Create it:

```bash
piqrypt identity create X
# or
piqrypt identity create X --encrypt   # Pro tier
```

### InvalidPassphraseError

The passphrase does not match the stored encrypted key. Reset is not possible (by design). If you have the plaintext key, re-encrypt it:

```bash
piqrypt identity secure <name>   # prompts for new passphrase
```

### InvalidChainError: Chain broken at event index N

An event was modified after signing, or events were loaded out of order. Verify:

```python
from aiss.chain import verify_chain_linkage
try:
    verify_chain_linkage(events)
except InvalidChainError as e:
    print(f"Break at index {e.event_index}")
    print(f"Expected: {e.expected_hash[:16]}...")
    print(f"Got:      {e.actual_hash[:16]}...")
```

### Vigil shows CRITICAL but no chain anomaly

This is typically a TSI drift signal. The agent's Trust Score changed significantly in 24h. Check:

```python
from aiss.tsi_engine import compute_tsi
result = compute_tsi(agent_id, current_score)
print(result["drift_reasons"])   # human-readable drift explanation
```

### TrustGate returns BLOCK on every action

Check whether the VRS exceeds `vrs_block` in the active policy:

```bash
piqrypt vigil status                      # check VRS
piqrypt trustgate policy simulate \       # dry-run your action
  --agent my_agent --action execute_trade
```

If VRS is elevated due to a false positive (new agent with no history), the trust score baseline needs time to stabilise. You can temporarily adjust the policy threshold while the agent builds history:

```yaml
thresholds:
  vrs_block: 0.95   # temporarily higher during agent warmup
```

### Vigil API returns 401 Unauthorized

Set the `VIGIL_TOKEN` environment variable:

```bash
export VIGIL_TOKEN=your_token_here
# Or generate a new one:
python piqrypt_start.py --gen-tokens
```

---

## Contact & Resources

| Resource | URL |
|----------|-----|
| Documentation | https://docs.piqrypt.com |
| GitHub | https://github.com/piqrypt/piqrypt |
| PyPI | https://pypi.org/project/piqrypt |
| Security | security@piqrypt.com |
| Support | piqrypt@gmail.com |
| PCP Protocol Paper | https://piqrypt.com/pcp |
| RFC AISS v2.0 | https://docs.piqrypt.com/rfc |

**IP:** e-Soleau DSO2026006483 + DSO2026009143 (INPI France)
**License:** MIT (core) + Apache-2.0 (bridges)  
**Python:** 3.9+ | **PiQrypt:** 1.7.1

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
