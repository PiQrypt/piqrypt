# piqrypt-crewai

**Cryptographic audit trail for CrewAI agents and crews.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-crewai)](https://pypi.org/project/piqrypt-crewai/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-00C8E0)](https://piqrypt.com)

Every agent decision, task execution, and crew result — signed Ed25519,
hash-chained, tamper-proof. Drop-in replacement — one line change.

---

## Install

```bash
pip install piqrypt[crewai]
```

---

## Quickstart — one line change

```python
# Before
from crewai import Agent, Crew

# After — everything else stays identical
from piqrypt_crewai import AuditedAgent, AuditedCrew

researcher = AuditedAgent(
    role="Researcher",
    goal="Find accurate information",
    backstory="Senior research analyst with 10 years experience",
    identity_file="~/.piqrypt/researcher.json",  # ← only addition
)

writer = AuditedAgent(
    role="Writer",
    goal="Write clear technical reports",
    backstory="Technical writer specialized in AI",
    identity_file="~/.piqrypt/writer.json",
)

crew = AuditedCrew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    crew_name="research_crew",                   # ← only addition
)

result = crew.kickoff()
# Every task execution is now signed, every crew result hash-chained
```

---

## What gets stamped

| Event | When | Stamped data |
|-------|------|-------------|
| `task_start` | `execute_task()` begins | task description hash, agent_id, timestamp |
| `task_complete` | `execute_task()` ends | result_hash, duration_ms |
| `task_error` | `execute_task()` fails | error type, task hash |
| `crew_start` | `kickoff()` begins | agent_count, task_count, session context |
| `crew_complete` | `kickoff()` ends | result_hash, total_duration_ms |
| `crew_error` | `kickoff()` fails | error type |

**Privacy:** task descriptions and results are never stored — only their SHA-256 hash.

---

## AuditedAgent

Drop-in for `crewai.Agent`. Every `execute_task()` call is signed.

```python
from piqrypt_crewai import AuditedAgent

agent = AuditedAgent(
    role="Financial Analyst",
    goal="Analyse market data",
    backstory="CFA with 15 years experience in equity research",
    llm=my_llm,
    tools=[search_tool, calculator_tool],
    identity_file="~/.piqrypt/analyst.json",  # persistent identity
    # or ephemeral:
    # agent_name="analyst"                     # auto-generates keypair
)

# Inspect
print(agent.piqrypt_id)         # AGENT_a3f29b4c...
print(agent.audit_event_count)  # 7
print(agent.last_event_hash)    # sha256...

# Export this agent's memory
agent.export_audit("analyst_audit.json")
```

## AuditedCrew

Drop-in for `crewai.Crew`. `kickoff()` is signed with agent count and result hash.

```python
from piqrypt_crewai import AuditedCrew

crew = AuditedCrew(
    agents=[researcher, trader],
    tasks=[research_task, trade_task],
    verbose=True,
    crew_name="trading_crew",
)

result = crew.kickoff()
crew.export_audit("crew_audit.json")
```

## @stamp_task — audit any function as a task

```python
from piqrypt_crewai import stamp_task

@stamp_task("market_analysis", identity_file="~/.piqrypt/agent.json")
def analyse_market(symbol: str, period: str) -> dict:
    # ... your logic
    return {"signal": "BUY", "confidence": 0.87}

result = analyse_market("AAPL", "1M")
# Stamped: task_start (input_hash), task_complete (result_hash)
```

---

## Cross-framework: CrewAI + LangChain + Claude

The most powerful pattern: a multi-framework pipeline where every handoff
between agents is cryptographically co-signed.

```python
from piqrypt_crewai import AuditedAgent, AuditedCrew
from piqrypt_langchain import PiQryptCallbackHandler
from piqrypt_session import AgentSession

# 1. Cross-framework session — co-signs all inter-agent handoffs
session = AgentSession([
    {"name": "claude",      "identity_file": "~/.piqrypt/claude.json"},
    {"name": "lc_analyst",  "identity_file": "~/.piqrypt/analyst.json"},
    {"name": "crew_trader", "identity_file": "~/.piqrypt/trader.json"},
])
session.start()

# 2. Claude + LangChain analyst — framework-level audit
lc_handler = PiQryptCallbackHandler(identity_file="~/.piqrypt/analyst.json")
llm = ChatOpenAI(callbacks=[lc_handler])
analysis = llm.invoke("Should we buy AAPL? Current price: $195")

# 3. Handoff: LangChain → CrewAI — co-signed in both memories
session.stamp("lc_analyst", "recommendation_sent", {
    "symbol": "AAPL",
    "signal_hash": sha256(analysis.content),
    "confidence": 0.87,
}, peer="crew_trader")

# 4. CrewAI trader executes — framework-level audit
trader = AuditedAgent(
    role="Algo Trader",
    goal="Execute trades based on analyst recommendations",
    backstory="Systematic trader, risk-managed",
    identity_file="~/.piqrypt/trader.json",
)
crew = AuditedCrew(agents=[trader], tasks=[execute_task])
trade_result = crew.kickoff()

# 5. Execution stamped in session — co-signed
session.stamp("crew_trader", "trade_executed", {
    "symbol": "AAPL", "action": "BUY", "qty": 100,
    "execution_hash": sha256(str(trade_result)),
})

# Two independent, cryptographically linked audit trails:
lc_handler.export_audit("langchain_audit.json")  # LangChain memory
trader.export_audit("crewai_audit.json")         # CrewAI memory
session.export("session_audit.json")             # Cross-agent co-signatures
```

**What this proves:**
- The LangChain analyst produced recommendation X (its Ed25519 signature)
- The CrewAI trader received exactly recommendation X (same hash, its signature)
- The trade execution followed from that specific recommendation
- No one can alter any step without breaking the cryptographic chain

---

## Use cases

**Autonomous trading (MiFID II / SEC)**
Multi-agent pipeline: research crew → analysis crew → execution crew.
Every inter-crew handoff co-signed. Full causal chain for regulatory audit.

**Healthcare coordination (EU AI Act / HIPAA)**
Diagnostic crew + treatment recommendation crew + validation agent.
Every recommendation co-signed between crews. No raw patient data stored.

**Legal document processing**
Review agent + summary agent + compliance checker.
Every document hash, every recommendation, every approval — signed and chained.

**Content moderation at scale**
Classification agent + review agent + action agent.
Every decision traceable to the specific input that triggered it.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Part of [PiQrypt](https://piqrypt.com) — Trust infrastructure for autonomous AI agents.  
IP: e-Soleau DSO2026006483 (INPI France — 19/02/2026)
