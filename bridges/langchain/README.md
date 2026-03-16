# piqrypt-langchain

**Verifiable AI Agent Memory for LangChain.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-langchain)](https://pypi.org/project/piqrypt-langchain/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-00C8E0)](https://piqrypt.com)

Every LLM call, tool execution, chain run, and agent action — signed Ed25519,
hash-chained, tamper-proof. Zero raw data stored. GDPR-compliant.

---

## Install

```bash
pip install piqrypt[langchain]
```

---

## Quickstart — 3 lines

```python
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor
from piqrypt_langchain import PiQryptCallbackHandler

# Attach to any LangChain LLM, chain, or agent executor
handler = PiQryptCallbackHandler(identity_file="~/.piqrypt/my_agent.json")

llm = ChatOpenAI(model="gpt-4o", callbacks=[handler])

# Every LLM call is now signed and hash-chained
response = llm.invoke("Analyse the portfolio risk for AAPL")
```

---

## What gets stamped

| Event | Stamped data |
|-------|-------------|
| LLM call start | `prompt_hash`, model name, timestamp |
| LLM call end | `response_hash`, token count |
| LLM error | error type (message hashed) |
| Tool start | tool name, `input_hash` |
| Tool end | `output_hash` |
| Tool error | error type |
| Chain start | chain type, `input_hash` |
| Chain end | `output_hash` |
| Agent finish | `output_hash`, return values hash |

**Privacy by design:** prompts and responses are never stored — only their
SHA-256 hash. GDPR Article 22 compliant.

---

## PiQryptCallbackHandler

Attaches to any LangChain component via the standard `callbacks=` parameter.

```python
from piqrypt_langchain import PiQryptCallbackHandler

handler = PiQryptCallbackHandler(
    identity_file="~/.piqrypt/analyst.json",  # persistent identity
    # or auto-generate ephemeral identity:
    # agent_name="analyst"
)

# Works with any LangChain component
llm = ChatOpenAI(callbacks=[handler])
chain = my_chain.with_config(callbacks=[handler])
executor = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])

# Inspect
print(handler.piqrypt_id)         # AGENT_a3f29b4c...
print(handler.audit_event_count)  # 42
print(handler.last_event_hash)    # sha256...

# Export
handler.export_audit("audit.json")
```

## AuditedAgentExecutor

Drop-in wrapper for `AgentExecutor`:

```python
from langchain.agents import AgentExecutor
from piqrypt_langchain import AuditedAgentExecutor

base_executor = AgentExecutor(agent=agent, tools=tools)
executor = AuditedAgentExecutor(
    executor=base_executor,
    identity_file="~/.piqrypt/executor.json",
)

# invoke() and run() are automatically audited
result = executor.invoke({"input": "Research AAPL earnings"})
```

## @piqrypt_tool — audit any tool

```python
from piqrypt_langchain import piqrypt_tool

@piqrypt_tool("web_search", identity_file="~/.piqrypt/agent.json")
def search(query: str) -> str:
    return requests.get(f"https://api.search.com?q={query}").json()

# Every call is now signed: tool_name, input_hash, result_hash
result = search("AAPL earnings Q4 2025")
```

## @stamp_chain — audit any function as a chain

```python
from piqrypt_langchain import stamp_chain

@stamp_chain("risk_analysis", identity_file="~/.piqrypt/agent.json")
def analyse_risk(portfolio: dict) -> dict:
    # ... your logic
    return {"risk_score": 0.42, "recommendation": "HOLD"}

result = analyse_risk({"AAPL": 100, "MSFT": 50})
# Stamped: chain_start, chain_complete (with result_hash)
```

---

## Cross-framework: LangChain → CrewAI

The real power comes when you combine bridges with an AgentSession.
A LangChain analyst and a CrewAI trader, with cryptographic proof
of every handoff between them:

```python
from piqrypt_langchain import PiQryptCallbackHandler
from piqrypt_crewai import AuditedAgent, AuditedCrew
from piqrypt_session import AgentSession

# Session: co-signs cross-agent interactions
session = AgentSession([
    {"name": "langchain_analyst", "identity_file": "~/.piqrypt/analyst.json"},
    {"name": "crewai_trader",     "identity_file": "~/.piqrypt/trader.json"},
])
session.start()

# LangChain analyst — framework-level audit
handler = PiQryptCallbackHandler(identity_file="~/.piqrypt/analyst.json")
llm = ChatOpenAI(callbacks=[handler])
recommendation = llm.invoke("Should we buy AAPL?")

# Send recommendation to CrewAI trader — co-signed in both memories
session.stamp("langchain_analyst", "recommendation_sent", {
    "recommendation_hash": sha256(recommendation.content),
    "symbol": "AAPL",
}, peer="crewai_trader")

# CrewAI trader — framework-level audit
trader = AuditedAgent(
    role="Trader", goal="Execute trades", backstory="Algo trader",
    identity_file="~/.piqrypt/trader.json"
)
crew = AuditedCrew(agents=[trader], tasks=[trade_task])
crew.kickoff()

# Session-level: execution co-signed
session.stamp("crewai_trader", "trade_executed", {
    "symbol": "AAPL", "action": "BUY", "qty": 100
})

# Two independent audit trails, cryptographically linked
handler.export_audit("langchain_audit.json")   # LangChain memory
session.export("session_audit.json")           # Cross-agent co-signatures
```

**Result:** if the trade is ever disputed, you can prove:
- The LangChain analyst produced this recommendation (its signature)
- The CrewAI trader received exactly this payload (same hash, its signature)
- The execution followed from that recommendation (causal chain)

---

## Use cases

**Regulated finance (MiFID II / SEC Rule 17a-4)**
Every LLM-generated trading signal is signed, hash-chained, and timestamped RFC 3161.
Reproducible audit for any regulator.

**Healthcare (EU AI Act Art. 13 / HIPAA)**
Every diagnostic suggestion stamped — model version, input hash, output hash.
Never stores patient data. Cryptographic proof of what the AI recommended.

**Legal & compliance**
Every contract analysis, risk assessment, or compliance check — signed by the
agent that produced it, at the exact moment it was produced.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Part of [PiQrypt](https://piqrypt.com) — Trust infrastructure for autonomous AI agents.  
IP: e-Soleau DSO2026006483 (INPI France — 19/02/2026)
