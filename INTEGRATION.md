# PiQrypt Integration Guide

**How to add cryptographic accountability to your existing agent — whatever stack you use.**

This guide answers the question the Quick Start doesn't: *"I already have an agent running. Where exactly do I add PiQrypt?"*

---

## Pick your stack

| I use... | Go to |
|---|---|
| A Python script or class | [→ Python script](#1-python-script--class) |
| OpenAI / Anthropic / Mistral API directly | [→ LLM API wrapper](#2-llm-api-wrapper-openai--anthropic--mistral) |
| LangChain | [→ LangChain](#3-langchain) |
| AutoGen | [→ AutoGen](#4-autogen) |
| CrewAI | [→ CrewAI](#5-crewai) |
| n8n or Make.com | [→ No-code](#6-n8n--makecom-no-code) |
| A REST API / webhook | [→ REST / webhook](#7-rest-api--webhook) |
| Something else | [→ Universal pattern](#8-universal-pattern) |

---

## The core idea — before any example

PiQrypt hooks into **two moments** in your agent's lifecycle:

```
Your agent flow (before PiQrypt)        Your agent flow (with PiQrypt)
──────────────────────────────          ──────────────────────────────
1. Receive input                        1. Receive input
2. Process / decide                     2. Process / decide
3. Act                                  3. ── stamp_event() ──  ← ADD THIS
                                        4. Act
                                        5. ── store_event() ── ← AND THIS
```

That's it. You don't change your logic. You add two lines around your decision point.

**The minimal diff:**

```python
# BEFORE
result = my_agent.decide(input_data)
execute(result)

# AFTER
result = my_agent.decide(input_data)
event = aiss.stamp_event(private_key, agent_id, {
    "action": "decision",
    "input_hash": hashlib.sha256(str(input_data).encode()).hexdigest(),
    "result": result
})
aiss.store_event(event)
execute(result)
```

---

## Setup — common to all patterns

```python
# Run once — persist private_key and agent_id securely
import piqrypt as aiss

private_key, public_key = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(public_key)

# Or load from file (recommended for production)
# piqrypt identity create my-agent.json
identity = aiss.load_identity("my-agent.json")
private_key = identity["private_key_bytes"]
agent_id = identity["agent_id"]
```

⚠️ Generate identity **once**. Persist it. If you regenerate on every run, you lose chain continuity.

---

## 1. Python script / class

**Your situation:** you have a Python function or class that makes decisions.

**Before:**

```python
def my_agent(input_data):
    decision = process(input_data)
    return decision
```

**After — minimal change:**

```python
import hashlib
import piqrypt as aiss

# Load once at startup
identity = aiss.load_identity("my-agent.json")
private_key = identity["private_key_bytes"]
agent_id = identity["agent_id"]

def my_agent(input_data):
    decision = process(input_data)

    # ── PiQrypt: 3 lines ──────────────────────────────
    event = aiss.stamp_event(private_key, agent_id, {
        "action": "decision",
        "input_hash": hashlib.sha256(str(input_data).encode()).hexdigest(),
        "decision": str(decision),
    })
    aiss.store_event(event)
    # ─────────────────────────────────────────────────

    return decision
```

**Class version — add PiQrypt in `__init__`:**

```python
import hashlib
import piqrypt as aiss

class MyAgent:
    def __init__(self):
        self.your_existing_setup()

        # ── PiQrypt: add to __init__ ──────────────────
        identity = aiss.load_identity("my-agent.json")
        self._pq_key = identity["private_key_bytes"]
        self._pq_id = identity["agent_id"]
        # ─────────────────────────────────────────────

    def decide(self, input_data):
        decision = self.your_logic(input_data)

        # ── PiQrypt: stamp after each decision ────────
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "action": "decide",
            "input_hash": hashlib.sha256(str(input_data).encode()).hexdigest(),
            "decision": str(decision),
        }))
        # ─────────────────────────────────────────────

        return decision
```

---

## 2. LLM API wrapper (OpenAI / Anthropic / Mistral)

**Your situation:** you call an LLM API directly and use the response to drive actions.

**Before:**

```python
from openai import OpenAI
client = OpenAI()

def ask_agent(prompt):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content
```

**After — wrap the call:**

```python
import hashlib
import piqrypt as aiss
from openai import OpenAI

client = OpenAI()

identity = aiss.load_identity("my-agent.json")
private_key = identity["private_key_bytes"]
agent_id = identity["agent_id"]

def ask_agent(prompt):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )
    reply = response.choices[0].message.content

    # ── PiQrypt: anchor prompt + response ─────────────
    aiss.store_event(aiss.stamp_event(private_key, agent_id, {
        "action": "llm_call",
        "model": "gpt-4o",
        "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest(),
        "response_hash": hashlib.sha256(reply.encode()).hexdigest(),
        # prompt and reply are never stored — only their hashes
    }))
    # ─────────────────────────────────────────────────

    return reply
```

**Same pattern for Anthropic:**

```python
import anthropic
client = anthropic.Anthropic()

def ask_claude(prompt):
    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    reply = message.content[0].text

    aiss.store_event(aiss.stamp_event(private_key, agent_id, {
        "action": "llm_call",
        "model": "claude-opus-4-5",
        "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest(),
        "response_hash": hashlib.sha256(reply.encode()).hexdigest(),
    }))

    return reply
```

---

## 3. LangChain

**Your situation:** you have a LangChain agent with tools.

**Two integration points — choose what fits:**

### Option A — wrap individual tools (recommended)

```python
import hashlib
import piqrypt as aiss
from langchain.tools import tool

identity = aiss.load_identity("my-agent.json")
private_key = identity["private_key_bytes"]
agent_id = identity["agent_id"]

def piqrypt_tool(func):
    """Decorator: wrap any LangChain tool with cryptographic proof."""
    def wrapper(input_str):
        result = func(input_str)

        aiss.store_event(aiss.stamp_event(private_key, agent_id, {
            "action": "tool_call",
            "tool": func.__name__,
            "input_hash": hashlib.sha256(str(input_str).encode()).hexdigest(),
            "output_hash": hashlib.sha256(str(result).encode()).hexdigest(),
        }))

        return result
    wrapper.__name__ = func.__name__
    return wrapper

# Apply to your existing tools
@tool
@piqrypt_tool
def search_web(query: str) -> str:
    """Search the web."""
    return your_search_logic(query)

@tool
@piqrypt_tool
def send_email(content: str) -> str:
    """Send an email."""
    return your_email_logic(content)
```

### Option B — wrap the agent executor

```python
from langchain.agents import AgentExecutor

class AuditedAgentExecutor(AgentExecutor):
    """AgentExecutor with PiQrypt audit trail."""

    def __init__(self, *args, pq_key, pq_id, **kwargs):
        super().__init__(*args, **kwargs)
        self._pq_key = pq_key
        self._pq_id = pq_id

    def invoke(self, input, **kwargs):
        result = super().invoke(input, **kwargs)

        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "action": "agent_invoke",
            "input_hash": hashlib.sha256(str(input).encode()).hexdigest(),
            "output_hash": hashlib.sha256(str(result).encode()).hexdigest(),
        }))

        return result

# Replace AgentExecutor with AuditedAgentExecutor
agent = AuditedAgentExecutor(
    agent=your_agent,
    tools=your_tools,
    pq_key=private_key,
    pq_id=agent_id
)
```

---

## 4. AutoGen

**Your situation:** you have one or more AutoGen agents in a conversation.

**Subclass `AssistantAgent` — minimal change:**

```python
import hashlib
import autogen
import piqrypt as aiss

identity = aiss.load_identity("my-agent.json")
private_key = identity["private_key_bytes"]
agent_id = identity["agent_id"]

class AuditedAssistant(autogen.AssistantAgent):
    """AssistantAgent with PiQrypt audit trail."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pq_key = private_key
        self._pq_id = agent_id

    def generate_reply(self, messages=None, sender=None, **kwargs):
        reply = super().generate_reply(messages=messages, sender=sender, **kwargs)

        # ── PiQrypt ───────────────────────────────────
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "action": "generate_reply",
            "agent_name": self.name,
            "message_count": len(messages) if messages else 0,
            "reply_hash": hashlib.sha256(str(reply).encode()).hexdigest(),
            "sender": sender.name if sender else None,
        }))
        # ─────────────────────────────────────────────

        return reply

# Use AuditedAssistant instead of AssistantAgent
assistant = AuditedAssistant(
    name="assistant",
    llm_config={"model": "gpt-4o"}
)
```

**For multi-agent pipelines — each agent gets its own identity:**

```python
identity_a = aiss.load_identity("agent-a.json")
identity_b = aiss.load_identity("agent-b.json")

agent_a = AuditedAssistant(name="planner", ...)
agent_b = AuditedAssistant(name="executor", ...)

# Each agent signs its own decisions independently
# A2A handshake available for cross-agent trust (Pro)
```

---

## 5. CrewAI

**Your situation:** you have a CrewAI crew with agents and tasks.

**Decorator approach — zero change to existing code:**

```python
import hashlib
import functools
import piqrypt as aiss
from crewai import Agent, Task, Crew

identity = aiss.load_identity("my-agent.json")
private_key = identity["private_key_bytes"]
agent_id = identity["agent_id"]

def stamp_task(task_name: str):
    """Decorator: stamp any CrewAI task execution."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            aiss.store_event(aiss.stamp_event(private_key, agent_id, {
                "action": "task_executed",
                "task": task_name,
                "result_hash": hashlib.sha256(str(result).encode()).hexdigest(),
            }))

            return result
        return wrapper
    return decorator

# Apply to your task functions
@stamp_task("research")
def research_task(topic: str) -> str:
    return your_research_logic(topic)

@stamp_task("write_report")
def write_report(research: str) -> str:
    return your_writing_logic(research)
```

**Or hook into the Crew at task completion:**

```python
class AuditedCrew(Crew):
    def kickoff(self, inputs=None):
        result = super().kickoff(inputs=inputs)

        aiss.store_event(aiss.stamp_event(private_key, agent_id, {
            "action": "crew_kickoff",
            "crew": self.id if hasattr(self, 'id') else "crew",
            "result_hash": hashlib.sha256(str(result).encode()).hexdigest(),
        }))

        return result
```

---

## 6. n8n / Make.com (no-code)

**Your situation:** your agent is a workflow in n8n or Make.com.

### n8n

Install the PiQrypt node:

```bash
npm install n8n-nodes-piqrypt
```

Add these nodes to your workflow **around every decision point**:

```
[Trigger]
    ↓
[Your AI node (GPT, Claude, etc.)]
    ↓
[PiQrypt: Stamp Event]          ← ADD THIS
    │   • action: "ai_decision"
    │   • payload: {{ $json.response_hash }}
    ↓
[Your action node (email, DB, API...)]
    ↓
[PiQrypt: Store Event]          ← AND THIS
```

**Minimal workflow config for the Stamp node:**

```json
{
  "action": "stamp_event",
  "identity_file": "/home/user/.piqrypt/my-agent.json",
  "payload": {
    "action": "{{ $node['AI'].json.action_type }}",
    "result_hash": "{{ $node['AI'].json.result_hash }}"
  }
}
```

### Make.com

Use the **HTTP module** to call PiQrypt via its CLI wrapper:

```
[Webhook trigger]
    ↓
[Your AI module]
    ↓
[HTTP: POST /piqrypt/stamp]     ← ADD THIS
    │   Body: { "action": "...", "result_hash": "..." }
    ↓
[Your action module]
```

Or use the **Run a command** module with:

```bash
piqrypt stamp my-agent.json --payload '{"action":"{{action}}", "result_hash":"{{hash}}"}'
```

---

## 7. REST API / webhook

**Your situation:** your agent is a service that receives requests and returns responses.

**Add PiQrypt middleware to your FastAPI / Flask app:**

### FastAPI

```python
import hashlib
import piqrypt as aiss
from fastapi import FastAPI, Request
from functools import wraps

app = FastAPI()

identity = aiss.load_identity("my-agent.json")
private_key = identity["private_key_bytes"]
agent_id = identity["agent_id"]

def audit_endpoint(action_name: str):
    """Decorator: audit any FastAPI endpoint."""
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            body = await request.body()
            result = await func(request, *args, **kwargs)

            aiss.store_event(aiss.stamp_event(private_key, agent_id, {
                "action": action_name,
                "endpoint": str(request.url),
                "request_hash": hashlib.sha256(body).hexdigest(),
                "response_hash": hashlib.sha256(str(result).encode()).hexdigest(),
            }))

            return result
        return wrapper
    return decorator

# Apply to your endpoints
@app.post("/decide")
@audit_endpoint("api_decision")
async def decide(request: Request):
    body = await request.json()
    result = your_decision_logic(body)
    return result
```

### Flask

```python
import hashlib
import piqrypt as aiss
from flask import Flask, request, g
from functools import wraps

app = Flask(__name__)

identity = aiss.load_identity("my-agent.json")
private_key = identity["private_key_bytes"]
agent_id = identity["agent_id"]

def audit_route(action_name: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            aiss.store_event(aiss.stamp_event(private_key, agent_id, {
                "action": action_name,
                "endpoint": request.path,
                "request_hash": hashlib.sha256(request.get_data()).hexdigest(),
                "response_hash": hashlib.sha256(str(result).encode()).hexdigest(),
            }))

            return result
        return wrapper
    return decorator

@app.route("/decide", methods=["POST"])
@audit_route("api_decision")
def decide():
    return your_decision_logic(request.json)
```

---

## 8. Universal pattern

**Your situation:** none of the above match exactly.

Every agent, regardless of framework, does the same thing:

```
receive input → process → produce output → act
```

PiQrypt always hooks at the same place:

```python
import hashlib
import piqrypt as aiss

identity = aiss.load_identity("my-agent.json")
private_key = identity["private_key_bytes"]
agent_id = identity["agent_id"]

def stamp(action: str, **kwargs):
    """Universal stamp helper — call after any significant decision."""
    payload = {"action": action, "aiss_profile": "AISS-1"}

    for key, value in kwargs.items():
        if key.endswith("_hash"):
            payload[key] = value                              # already a hash
        else:
            payload[key] = hashlib.sha256(                   # hash everything else
                str(value).encode()
            ).hexdigest()

    aiss.store_event(aiss.stamp_event(private_key, agent_id, payload))

# Then use anywhere in your code:
stamp("my_decision", input=raw_input, output=raw_output)
stamp("file_created", path=file_path)
stamp("api_called", endpoint=url, response=response_body)
stamp("model_output", prompt=prompt_text, reply=reply_text)
```

---

## Export and verify — same for all patterns

```bash
# Export your full audit trail
piqrypt export audit.json

# Verify chain integrity
piqrypt verify audit.json

# Search events
piqrypt search --type my_decision --limit 20

# Request external certification if needed (Pro)
piqrypt certify-request audit.json audit.json.cert --email you@company.com
```

---

## Scope reminder

| Your environment | AISS profile | Notes |
|---|---|---|
| Development / PoC | AISS-1 (Free) | All patterns above |
| Non-critical production | AISS-1 (Free) | All patterns above |
| Regulated production (finance, health) | AISS-2 (Pro) | Add Dilithium3 + RFC 3161 |
| Legal admissibility required | AISS-2 (Pro) | Consult legal counsel |

Upgrade path is seamless — same API, same patterns, stronger crypto.

---

## Next steps

| | |
|---|---|
| 🚀 Quick Start | [QUICK-START.md](QUICK-START.md) |
| 🤖 Agent self-install | [agents/AGENT_PROMPT.md](agents/AGENT_PROMPT.md) |
| 🤝 A2A between agents | [docs/A2A_GUIDE.md](docs/A2A_GUIDE.md) |
| 🔗 OpenClaw pipeline | [docs/OPENCLAW_INTEGRATION.md](docs/OPENCLAW_INTEGRATION.md) |
| 📐 AISS specification | [docs/RFC.md](docs/RFC.md) |
| 🐛 Issues / questions | [GitHub Issues](https://github.com/piqrypt/piqrypt/issues) |
| 📧 Support | piqrypt@gmail.com |

---

*PiQrypt v1.5.0 — AISS v1.1 Reference Implementation*
