# piqrypt-autogen

**Cryptographic audit trail for Microsoft AutoGen agents.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-autogen)](https://pypi.org/project/piqrypt-autogen/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-00C8E0)](https://piqrypt.com)

Every message, reply, and group chat turn — signed Ed25519, hash-chained,
tamper-proof. Drop-in replacement for `AssistantAgent` and `UserProxyAgent`.

---

## Install

```bash
pip install piqrypt[autogen]
```

---

## Quickstart — one line change

```python
# Before
from autogen import AssistantAgent, UserProxyAgent

# After
from piqrypt_autogen import AuditedAssistant, AuditedUserProxy

assistant = AuditedAssistant(
    name="analyst",
    system_message="You are a financial analyst.",
    llm_config={"model": "gpt-4o"},
    identity_file="~/.piqrypt/analyst.json",  # ← only addition
)

user_proxy = AuditedUserProxy(
    name="user",
    identity_file="~/.piqrypt/user.json",
)

# Every message exchange is now signed and hash-chained
user_proxy.initiate_chat(
    assistant,
    message="Analyse AAPL risk for Q4 2025",
)
```

---

## What gets stamped

| Event | Stamped data |
|-------|-------------|
| `message_sent` | `message_hash`, sender, recipient, turn |
| `reply_generated` | `reply_hash`, model, token count |
| `tool_call` | tool name, `args_hash` |
| `tool_result` | `result_hash`, success/failure |
| `conversation_end` | total turns, `final_reply_hash` |

**Privacy:** message content is never stored — only SHA-256 hashes.

---

## Multi-agent group chat

```python
from piqrypt_autogen import AuditedAssistant, AuditedUserProxy, AuditedGroupChat
import autogen

researcher = AuditedAssistant(
    name="researcher",
    system_message="Research and gather data.",
    llm_config=llm_config,
    identity_file="~/.piqrypt/researcher.json",
)

analyst = AuditedAssistant(
    name="analyst",
    system_message="Analyse data and produce recommendations.",
    llm_config=llm_config,
    identity_file="~/.piqrypt/analyst.json",
)

user_proxy = AuditedUserProxy(
    name="user",
    identity_file="~/.piqrypt/user.json",
    human_input_mode="TERMINATE",
)

# AuditedGroupChat: every turn stamped per agent
group_chat = AuditedGroupChat(
    agents=[researcher, analyst, user_proxy],
    messages=[],
    max_round=10,
)

manager = autogen.GroupChatManager(groupchat=group_chat, llm_config=llm_config)
user_proxy.initiate_chat(manager, message="Build an investment thesis for AAPL")

# Export per-agent audit trails
researcher.export_audit("researcher_audit.json")
analyst.export_audit("analyst_audit.json")
```

---

## Cross-framework: AutoGen + CrewAI + Claude

```python
from piqrypt_autogen import AuditedAssistant
from piqrypt_crewai import AuditedAgent, AuditedCrew
from piqrypt_session import AgentSession

# Cross-framework session
session = AgentSession([
    {"name": "autogen_researcher", "identity_file": "~/.piqrypt/researcher.json"},
    {"name": "crewai_executor",    "identity_file": "~/.piqrypt/executor.json"},
    {"name": "claude",             "identity_file": "~/.piqrypt/claude.json"},
])
session.start()

# AutoGen researcher produces a recommendation
researcher = AuditedAssistant(
    name="researcher",
    llm_config=llm_config,
    identity_file="~/.piqrypt/researcher.json",
)
# ... initiate_chat, get recommendation ...

# Handoff to CrewAI executor — co-signed in both memories
session.stamp("autogen_researcher", "recommendation_sent", {
    "recommendation_hash": sha256(recommendation),
    "symbol": "AAPL",
}, peer="crewai_executor")

# CrewAI executes — its own framework-level audit
executor = AuditedAgent(
    role="Executor", goal="Execute", backstory="...",
    identity_file="~/.piqrypt/executor.json",
)
crew = AuditedCrew(agents=[executor], tasks=[exec_task])
crew.kickoff()

# Full cross-framework audit
session.export("cross_framework_audit.json")
```

---

## API

```python
# AuditedAssistant / AuditedUserProxy
agent.piqrypt_id          # str — Ed25519 agent ID
agent.audit_event_count   # int — total stamped events
agent.last_event_hash     # str — sha256 of last event
agent.export_audit(path)  # export this agent's memory

# AuditedGroupChat
chat.export_all_audits(prefix)  # export one file per agent

# @stamp_reply — audit any reply function
from piqrypt_autogen import stamp_reply

@stamp_reply("my_model", identity_file="~/.piqrypt/agent.json")
def generate_reply(messages, **kwargs):
    return "My reply"

# @stamp_conversation — audit a full conversation function
from piqrypt_autogen import stamp_conversation

@stamp_conversation("research_session", identity_file="~/.piqrypt/agent.json")
def run_conversation(topic):
    # ... your multi-turn logic
    return result
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Part of [PiQrypt](https://piqrypt.com) — Trust infrastructure for autonomous AI agents.  
IP: e-Soleau DSO2026006483 (INPI France — 19/02/2026)
