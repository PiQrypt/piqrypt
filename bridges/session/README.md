# piqrypt-session

**Cross-framework A2A co-signed audit trail for multi-agent pipelines.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-session)](https://pypi.org/project/piqrypt-session/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-00C8E0)](https://piqrypt.com)

Every cross-agent interaction — signed by **both** agents, in **both** memories,  
with the **same payload hash**. Tamper-proof. Framework-agnostic.

---

## The problem no other tool solves

You use Claude + LangGraph + CrewAI in the same pipeline.

LangSmith traces LangChain. CrewAI has its own logs. But **nobody produces a
cryptographic proof that links all three** — where each agent co-signs every
interaction with its peer, in its own independent memory.

If something goes wrong — a bad trade, a wrong diagnosis, a harmful action —
you cannot prove *who decided what, in what order, based on what input*,
across framework boundaries.

**PiQrypt Session solves exactly this.**

---

## How it works

```
Claude           →  "analyse portfolio"    →  LangGraph
LangGraph        →  "graph result"         →  CrewAI
CrewAI (crew)    →  "execute trade AAPL"   →  system

Audit result:
  ✅ Claude signed the instruction          (Ed25519, Claude's memory)
  ✅ LangGraph received AND forwarded it    (Ed25519, LangGraph's memory)
  ✅ CrewAI executed on that exact basis    (Ed25519, CrewAI's memory)
  ✅ All three share the same session_id
  ✅ Each interaction has the same payload_hash in BOTH memories
  ✅ Chain of causality: cryptographically provable end-to-end
```

Each agent keeps its **own independent memory**. They are never merged.  
But every cross-agent interaction is **co-signed** — both agents stamp the same
`payload_hash` with their own key, in their own chain.

This means: **you cannot falsify one side without breaking the other.**

---

## Install

```bash
pip install piqrypt[session]
```

---

## Quickstart — Claude + LangGraph + CrewAI

```python
from piqrypt_session import AgentSession

# 1. Declare all agents in the pipeline
session = AgentSession([
    {"name": "claude",    "identity_file": "~/.piqrypt/claude.json"},
    {"name": "langgraph", "identity_file": "~/.piqrypt/langgraph.json"},
    {"name": "crewai",    "identity_file": "~/.piqrypt/crewai.json"},
])

# 2. Start — performs pairwise Ed25519 handshakes (3 pairs = 6 handshakes)
session.start()

# 3. Stamp cross-agent interactions
# Claude sends an instruction to LangGraph — co-signed in both memories
session.stamp("claude", "instruction_sent", {
    "task": "analyse portfolio",
    "context_hash": sha256(portfolio_data),   # raw data never stored
}, peer="langgraph")

# LangGraph forwards result to CrewAI
session.stamp("langgraph", "graph_result_sent", {
    "nodes_executed": 7,
    "recommendation_hash": sha256("BUY AAPL 100"),
}, peer="crewai")

# CrewAI executes (no peer — internal decision)
session.stamp("crewai", "trade_executed", {
    "symbol": "AAPL",
    "action": "BUY",
    "qty": 100,
})

# 4. Export full cross-framework audit trail
session.export("audit_session.json")

# 5. Inspect
print(session.summary())
# {
#   "session_id": "sess_a3f29b4c...",
#   "agent_count": 3,
#   "total_events": 12,
#   "started_at": "2026-03-09T10:00:00Z"
# }
```

---

## What gets stamped

| Event | When | Payload |
|-------|------|---------|
| `session_start` | `session.start()` | session_id, agent_count, timestamp |
| `a2a_handshake` | pairwise at start | peer_id, session_id, sig |
| `{event_type}` | `session.stamp(...)` | event_type, payload_hash, session_id |
| `{event_type}_received` | peer side of stamp | payload_hash, peer_id, session_id |

**Privacy by design:** raw payloads are never stored. Only SHA-256 hashes.  
GDPR-compliant out of the box.

---

## What makes it unique

### Same payload_hash in both memories

```python
session.stamp("claude", "recommendation", {"action": "BUY"}, peer="crewai")

# In Claude's memory:
# { event_type: "recommendation", payload_hash: "a3f2...", peer: "crewai", sig: <claude_sig> }

# In CrewAI's memory:
# { event_type: "recommendation_received", payload_hash: "a3f2...", peer: "claude", sig: <crewai_sig> }

# payload_hash is IDENTICAL in both. Signatures are INDEPENDENT.
# You cannot modify one side without detection.
```

### Works with any framework combination

```python
# Any combination works — the session doesn't care about the underlying framework
AgentSession([
    {"name": "claude"},        # Anthropic API
    {"name": "autogen_agent"}, # Microsoft AutoGen
    {"name": "crewai_crew"},   # CrewAI
    {"name": "ros2_node"},     # ROS2 robot
    {"name": "rpi_sensor"},    # Raspberry Pi edge agent
])
```

### Verifiable chain of causality

Because each agent's memory is an independent hash-chain, and because
cross-agent interactions reference the same `payload_hash`, you can
reconstruct the exact causal chain of any decision:

```bash
piqrypt verify claude.json        # ✅ Claude's chain intact
piqrypt verify langgraph.json     # ✅ LangGraph's chain intact  
piqrypt verify crewai.json        # ✅ CrewAI's chain intact
piqrypt session-verify audit_session.json  # ✅ Cross-chain consistency
```

---

## Real-world use cases

### Regulated finance: MiFID II / SEC Rule 17a-4

A trading pipeline where Claude analyses, LangGraph builds the decision graph,
and CrewAI executes. Each step is co-signed. In case of regulatory audit,
the full causal chain is reproductible by an independent third party.

### Healthcare: EU AI Act Article 22

A diagnostic pipeline where one LLM suggests, another validates, a human
principal approves (via TrustGate). Every handoff is co-signed. The AI
decision trail is provable before a judge.

### Industrial robotics: IEC 62443

A multi-agent system controlling physical equipment. Each command from the
orchestrator to the ROS2 node is co-signed. In case of incident, the cryptographic
timeline distinguishes a software fault from an external modification.

---

## AgentSession API

```python
# Create
session = AgentSession(agents: list[dict])
# agents: [{"name": str, "identity_file": str | None}, ...]
# identity_file is optional — ephemeral key generated if absent

# Start (performs handshakes)
session.start() -> None

# Stamp an interaction
session.stamp(
    agent_name: str,       # name of the acting agent
    event_type: str,       # your event label
    payload: dict,         # data to hash (never stored raw)
    peer: str | None,      # if set, co-signs in peer's memory too
) -> str                   # returns payload_hash

# Export full audit trail
session.export(path: str) -> str

# Session info
session.session_id -> str
session.summary() -> dict
session.agents -> list[AgentMember]

# AgentMember
member.name -> str
member.agent_id -> str
member.event_count -> int
member.last_event_hash -> str
```

---

## Integration with other PiQrypt bridges

Session works alongside — not instead of — individual framework bridges:

```python
from piqrypt_crewai import AuditedAgent, AuditedCrew
from piqrypt_session import AgentSession

# Each agent has its own framework-level audit (CrewAI bridge)
researcher = AuditedAgent(
    role="Researcher", goal="Research", backstory="Expert",
    identity_file="~/.piqrypt/researcher.json"
)
trader = AuditedAgent(
    role="Trader", goal="Trade", backstory="Algo trader",
    identity_file="~/.piqrypt/trader.json"
)

# AND the session adds cross-agent co-signatures on top
session = AgentSession([
    {"name": "researcher", "identity_file": "~/.piqrypt/researcher.json"},
    {"name": "trader",     "identity_file": "~/.piqrypt/trader.json"},
    {"name": "claude",     "identity_file": "~/.piqrypt/claude.json"},
])
session.start()

# CrewAI-level audit: every task execution signed
crew = AuditedCrew(agents=[researcher, trader], tasks=[...])
result = crew.kickoff()

# Session-level audit: cross-agent handoffs co-signed
session.stamp("claude", "instruction", {"task_hash": sha256(task)}, peer="researcher")
session.stamp("researcher", "findings_sent", {"findings_hash": sha256(result)}, peer="trader")
session.stamp("trader", "trade_executed", {"symbol": "AAPL", "action": "BUY"})
```

Two layers of proof:
- **Framework layer**: what each agent did internally (CrewAI bridge)
- **Session layer**: what passed between agents (Session bridge)

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Part of [PiQrypt](https://piqrypt.com) — Trust infrastructure for autonomous AI agents.  
IP: e-Soleau DSO2026006483 (INPI France — 19/02/2026)
