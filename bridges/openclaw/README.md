# piqrypt-openclaw

**Cryptographic audit trail for OpenClaw code execution.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-openclaw)](https://pypi.org/project/piqrypt-openclaw/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-00C8E0)](https://piqrypt.com)

Every code execution, tool invocation, and file operation — signed Ed25519,
hash-chained, tamper-proof. Know exactly what code your AI agents ran,
when, and what it returned.

---

## Install

```bash
pip install piqrypt[openclaw]
```

---

## Quickstart

```python
from piqrypt_openclaw import AuditableOpenClaw

claw = AuditableOpenClaw(identity_file="~/.piqrypt/executor.json")

# Every execution is signed: code_hash, result_hash, timestamp
result = claw.run("python", "print('hello')")
result = claw.run("bash",   "ls -la /tmp")
result = claw.run("node",   "console.log(process.version)")

# Export audit trail
claw.export_audit("execution_audit.json")
```

---

## What gets stamped

| Event | Stamped data |
|-------|-------------|
| `execution_start` | language, `code_hash`, timestamp |
| `execution_complete` | `result_hash`, exit_code, duration_ms |
| `execution_error` | error type, `code_hash` |
| `file_read` | `path_hash`, `content_hash` |
| `file_write` | `path_hash`, `content_hash` |
| `tool_action` | tool name, `input_hash`, `output_hash` |

**Privacy:** source code and outputs are never stored — only SHA-256 hashes.

---

## @stamp_action — audit any action

```python
from piqrypt_openclaw import stamp_action

@stamp_action("data_processing", identity_file="~/.piqrypt/agent.json")
def process_data(df):
    # ... pandas, numpy, etc.
    return df.describe()

result = process_data(my_dataframe)
# Stamped: action_start (input_hash), action_complete (result_hash)
```

---

## Cross-framework: OpenClaw + CrewAI

```python
from piqrypt_crewai import AuditedAgent, AuditedCrew
from piqrypt_openclaw import AuditableOpenClaw
from piqrypt_session import AgentSession

session = AgentSession([
    {"name": "crewai_analyst", "identity_file": "~/.piqrypt/analyst.json"},
    {"name": "openclaw_exec",  "identity_file": "~/.piqrypt/executor.json"},
])
session.start()

# CrewAI analyst produces a script
analyst = AuditedAgent(
    role="Data Analyst", goal="Produce analysis scripts",
    backstory="Expert data scientist",
    identity_file="~/.piqrypt/analyst.json",
)

# OpenClaw executes the script — audited separately
claw = AuditableOpenClaw(identity_file="~/.piqrypt/executor.json")

# Handoff: CrewAI → OpenClaw, co-signed
session.stamp("crewai_analyst", "script_sent", {
    "script_hash": sha256(generated_script),
    "language": "python",
}, peer="openclaw_exec")

result = claw.run("python", generated_script)

session.stamp("openclaw_exec", "execution_complete", {
    "result_hash": sha256(result.stdout),
    "exit_code": result.returncode,
})

session.export("execution_pipeline_audit.json")
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Part of [PiQrypt](https://piqrypt.com) — Trust infrastructure for autonomous AI agents.  
IP: e-Soleau DSO2026006483 (INPI France — 19/02/2026)
