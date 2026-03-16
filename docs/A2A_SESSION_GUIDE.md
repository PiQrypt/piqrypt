# A2A Session Guide — Cross-framework Multi-Agent Trust

*PiQrypt v1.7.1 — AISS v2.0*

---

## Overview

`AgentSession` establishes a cryptographically verifiable interaction record across N agents
from different frameworks. Each agent retains an independent keypair and AISS chain. The
session layer adds a co-signed overlay: every handshake and every interaction produces
entries in **both** agents' chains simultaneously, with each entry embedding the peer's
signature.

This guide covers:

1. [Prerequisites](#prerequisites)
2. [Three-agent setup](#three-agent-setup-langchain--autogen--custom-python)
3. [The handshake protocol](#the-handshake-protocol)
4. [Stamping cross-agent interactions](#stamping-cross-agent-interactions)
5. [What each chain contains](#what-each-chain-contains)
6. [Ending a session](#ending-a-session)
7. [Exporting the audit record](#exporting-the-audit-record)
8. [Handling non-PiQrypt peers](#handling-non-piqrypt-peers)
9. [API reference](#api-reference)

---

## Prerequisites

```bash
pip install piqrypt[all-bridges]
# or selectively:
pip install piqrypt[langchain]
pip install piqrypt[autogen]
```

Each agent needs a keypair. Keypairs are generated once and persisted. The `agent_id`
is deterministically derived from the public key — it is stable across restarts.

```python
import piqrypt as aiss

# Generate and persist (Pro+: encrypted at rest with AES-256-GCM)
private_key, public_key = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(public_key)
# agent_id = BASE58(SHA256(public_key))[0:32] — deterministic, non-falsifiable
```

---

## Three-agent setup: LangChain + AutoGen + custom Python

This example connects three agents from three different frameworks into a single
co-signed session.

```python
import piqrypt as aiss
from bridges.session import AgentSession

# ── Agent 1: LangChain planner ────────────────────────────────────────────────
# In production, load from aiss.key_store (Pro+: encrypted at rest)
planner_key, planner_pub = aiss.generate_keypair()
planner_id = aiss.derive_agent_id(planner_pub)

# Attach PiQrypt to the LangChain agent via callback
from bridges.langchain import PiQryptCallbackHandler
planner_identity = {"agent_id": planner_id, "private_key": planner_key, "public_key": planner_pub}
lc_handler = PiQryptCallbackHandler(identity=planner_identity)
# → attach to your LangChain executor: AgentExecutor(..., callbacks=[lc_handler])

# ── Agent 2: AutoGen executor ─────────────────────────────────────────────────
executor_key, executor_pub = aiss.generate_keypair()
executor_id = aiss.derive_agent_id(executor_pub)

from bridges.autogen import AuditedAssistant
# AuditedAssistant is a drop-in for autogen.AssistantAgent
# executor = AuditedAssistant("executor", identity=executor_identity, llm_config=...)

# ── Agent 3: Custom Python reviewer ──────────────────────────────────────────
reviewer_key, reviewer_pub = aiss.generate_keypair()
reviewer_id = aiss.derive_agent_id(reviewer_pub)
# Any Python process — uses aiss.stamp_event() directly

# ── Session setup ─────────────────────────────────────────────────────────────
session = AgentSession(agents=[
    {
        "name":        "planner",
        "agent_id":    planner_id,
        "private_key": planner_key,
        "public_key":  planner_pub,
    },
    {
        "name":        "executor",
        "agent_id":    executor_id,
        "private_key": executor_key,
        "public_key":  executor_pub,
    },
    {
        "name":        "reviewer",
        "agent_id":    reviewer_id,
        "private_key": reviewer_key,
        "public_key":  reviewer_pub,
    },
])

session.start()
# → 3 pairwise handshakes executed: (planner, executor), (planner, reviewer), (executor, reviewer)
# → 6 co-signed chain events stored (2 per pair — one in each agent's chain)
```

---

## The handshake protocol

When `session.start()` is called, `N*(N-1)/2` pairwise handshakes are executed.
For 3 agents: 3 handshakes. For 5 agents: 10 handshakes.

Each handshake is a 4-step protocol from `aiss/a2a.py`:

```
Step 1 — Agent A creates a proposal
         Signed document: agent_id, public_key, capabilities, session_nonce (UUID4), timestamp
         Signed with A's Ed25519 private key over RFC 8785 canonical JSON

Step 2 — Agent B creates a response
         Verifies A's signature and checks that A's agent_id derives from A's public_key
         Response echoes session_nonce and includes proposal_hash = SHA256(canonical(proposal))
         This binding proves B received exactly this proposal — not a replay or substitution

Step 3 — build_cosigned_handshake_event() runs twice
         Event for A's chain: role=initiator, peer_signature=B's response signature
         Event for B's chain: role=responder, peer_signature=A's proposal signature
         Each event is signed by the recording agent's own key

Step 4 — Both events stored via store_event()
         Each event contains: session_id, my_role, peer_agent_id, peer_signature,
         capabilities_agreed, participants[]
```

After `start()`, neither agent can deny that the session was established, nor claim
the counterpart had a different identity.

---

## Stamping cross-agent interactions

Once the session is started, use `session.stamp()` for every interaction between agents:

```python
# Task delegation: planner → executor
session.stamp(
    "planner",                          # agent performing the action
    "task_delegation",                  # event type
    {"task": "analyze_portfolio",
     "deadline": "2026-03-16"},         # payload — values auto-hashed if raw
    peer="executor"                     # counterpart agent
)

# Task completion: executor reports back to reviewer
session.stamp(
    "executor",
    "task_completed",
    {"result_hash": "a3f4b2…",          # already a hash — not double-hashed
     "duration_ms": 1240},
    peer="reviewer"
)

# Review sign-off: reviewer → planner
session.stamp(
    "reviewer",
    "review_signed",
    {"approved": True, "note": "portfolio analysis validated"},
    peer="planner"
)
```

**What `session.stamp(..., peer=...)` does internally:**

1. Generates `interaction_hash = SHA256(f"{initiator_id}:{responder_id}:{timestamp}")`
2. Creates event for `initiator` chain: `role=initiator`, `interaction_hash`, `peer_agent_id`
3. Calls `initiator.stamp()` → signs and stores in initiator's chain
4. Creates event for `peer` chain: `role=responder`, same `interaction_hash`,
   `peer_signature = initiator_event["signature"]`
5. Calls `peer.stamp()` → signs and stores in peer's chain

The same `interaction_hash` in both chains is the cross-reference an auditor uses
to match the two sides of any interaction.

**Payload auto-hashing:** any value whose key does not end in `_hash` or `_id` is
automatically replaced with `SHA256(str(value))`. Raw sensitive content never enters
the chain.

---

## What each chain contains

After the example session above, each agent's AISS chain holds:

**planner's chain:**
```
[genesis]
  → session_start         (session_id, participants)
  → a2a_handshake         (role=initiator, peer=executor,  peer_signature=executor's sig)
  → a2a_handshake         (role=initiator, peer=reviewer,  peer_signature=reviewer's sig)
  → task_delegation       (role=initiator, peer=executor,  interaction_hash=H1,
                           task_hash=SHA256("analyze_portfolio"), peer_signature=None*)
  → review_signed         (role=responder, peer=reviewer,  interaction_hash=H3,
                           peer_signature=reviewer's sig)
```

**executor's chain:**
```
[genesis]
  → session_start
  → a2a_handshake         (role=responder, peer=planner,   peer_signature=planner's sig)
  → a2a_handshake         (role=initiator, peer=reviewer,  peer_signature=reviewer's sig)
  → task_delegation       (role=responder, peer=planner,   interaction_hash=H1,
                           peer_signature=planner's sig)
  → task_completed        (role=initiator, peer=reviewer,  interaction_hash=H2)
```

**reviewer's chain:**
```
[genesis]
  → session_start
  → a2a_handshake         (role=responder, peer=planner,   peer_signature=planner's sig)
  → a2a_handshake         (role=responder, peer=executor,  peer_signature=executor's sig)
  → task_completed        (role=responder, peer=executor,  interaction_hash=H2,
                           peer_signature=executor's sig)
  → review_signed         (role=initiator, peer=planner,   interaction_hash=H3)
```

*`peer_signature` is `None` for the initiator side when the peer event is stamped
independently; the responder side always carries the initiator's signature.

Every event in every chain is:
- Signed by the recording agent's Ed25519 key
- Linked to the previous event via `previous_hash` (SHA-256)
- RFC 8785 canonicalized before signing
- UUID4-nonce protected against replay

---

## Ending a session

```python
session.end()
# → stamps session_end event in each agent's chain
# → records final event count and session duration
```

---

## Exporting the audit record

**Single agent chain (Free+):**
```python
from aiss.exports import export_chain_json

chain = export_chain_json(agent_id=planner_id)
# → list of all events, each with signature, previous_hash, payload
```

**Certified .pqz archive (Pro+):**
```python
from aiss.certification import certify_agent

archive = certify_agent(
    agent_id=planner_id,
    private_key=planner_key,
    include_tsa=True      # RFC 3161 trusted timestamp (Pro+)
)
# → writes planner_id.pqz
# → verifiable without access to the original infrastructure
```

**CLI:**
```bash
piqrypt certify planner_agent --output planner_audit.pqz
piqrypt verify  planner_audit.pqz
# ✅ Chain integrity verified — 6 events, 0 anomalies, TSA timestamp valid
```

The `.pqz` archive is self-contained: it carries the full event chain, agent identity
metadata, certification signature, and (Pro+) a RFC 3161 TSA timestamp. It is
verifiable by any party without access to the PiQrypt server that produced it.

---

## Handling non-PiQrypt peers

If one agent in a multi-agent pipeline does not have PiQrypt installed, use
`record_external_interaction()` from `aiss.a2a`:

```python
from aiss.a2a import record_external_interaction

# Record interaction with a non-AISS peer — unilateral proof
event = record_external_interaction(
    private_key=planner_key,
    agent_id=planner_id,
    peer_identifier="external_gpt4o_agent",
    interaction_data={"prompt_hash": "…", "response_hash": "…"},
)
# → event stored in planner's chain with piqrypt_available=False
# → interaction_data is hashed — raw content never stored
```

The resulting event explicitly marks the peer as non-AISS and records a hash of the
interaction. It provides unilateral proof that the interaction occurred, at the cost
of not having the peer's co-signature.

---

## API reference

### `AgentSession`

```python
class AgentSession:
    def __init__(self, agents: List[Dict[str, str]])
    # agents: list of {"name", "agent_id", "private_key", "public_key"}
    # minimum 2 agents required

    def start(self) -> "AgentSession"
    # Stamps session_start + performs N*(N-1)/2 handshakes

    def stamp(
        self,
        agent_name: str,
        event_type: str,
        payload: Dict,
        peer: Optional[str] = None
    ) -> Optional[Dict]
    # peer=None → single-agent stamp (no cross-signing)
    # peer=name → dual-agent stamp with interaction_hash + peer_signature

    def end(self) -> None
    # Stamps session_end in each agent's chain
```

### `aiss/a2a.py` — low-level A2A protocol

| Function | Description |
|----------|-------------|
| `create_identity_proposal(private_key, public_key, agent_id, capabilities)` | Step 1: signed proposal from initiator |
| `create_identity_response(private_key, public_key, agent_id, proposal)` | Step 2: signed response from responder |
| `verify_identity_proposal(proposal)` | Verifies signature + agent_id derivation |
| `verify_identity_response(response, original_proposal)` | Verifies sig + nonce echo + proposal_hash binding |
| `build_cosigned_handshake_event(my_private_key, my_agent_id, proposal, response)` | Builds one co-signed PCP event |
| `perform_handshake(my_private_key, my_public_key, my_agent_id, peer_proposal)` | Full orchestration from B's perspective |
| `record_external_interaction(private_key, agent_id, peer_identifier, data)` | Unilateral record for non-AISS peers |
| `compute_trust_score(agent_id, events)` | Trust Score T ∈ [0,1] with 5 components |

---

## See also

- [INTEGRATION.md](../INTEGRATION.md) — full integration guide (all frameworks)
- [docs/A2A_HANDSHAKE_GUIDE.md](A2A_HANDSHAKE_GUIDE.md) — protocol specification detail
- [docs/RFC_AISS_v2.0.md](RFC_AISS_v2.0.md) — AISS v2.0 specification
- [bridges/session/](../bridges/session/) — source code

---

*e-Soleau: DSO2026006483 (19/02/2026) — DSO2026009143 (12/03/2026)*
