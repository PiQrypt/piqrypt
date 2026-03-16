# piqrypt-mcp

**Cryptographic audit trail for Model Context Protocol (MCP).**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-mcp)](https://pypi.org/project/piqrypt-mcp/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-00C8E0)](https://piqrypt.com)

Every MCP tool call, resource read, and prompt invocation — signed Ed25519,
hash-chained, tamper-proof. Audit what your MCP-connected AI agents
actually did with the tools and resources they accessed.

---

## Install

```bash
pip install piqrypt[mcp]
```

---

## Quickstart

```python
from piqrypt_mcp import AuditedMCPClient

client = AuditedMCPClient(
    server_url="http://localhost:8000",
    identity_file="~/.piqrypt/my_agent.json",
)

async with client:
    # Every tool call stamped: tool_name, args_hash, result_hash
    result = await client.call_tool("search", {"query": "AAPL earnings"})
    
    # Every resource read stamped: uri_hash, content_hash
    doc = await client.read_resource("file:///reports/q4.pdf")
    
    # Every prompt stamped: prompt_name, args_hash, messages_hash
    messages = await client.get_prompt("analyst", {"symbol": "AAPL"})

client.export_audit("mcp_audit.json")
```

---

## What gets stamped

| Event | Stamped data |
|-------|-------------|
| `mcp_tool_call` | tool name, `args_hash`, timestamp |
| `mcp_tool_result` | `result_hash`, duration_ms |
| `mcp_tool_error` | tool name, error type |
| `mcp_resource_read` | `uri_hash`, `content_hash` |
| `mcp_prompt_get` | prompt name, `args_hash`, `messages_hash` |
| `mcp_session_start` | server_url hash, capabilities |
| `mcp_session_end` | total calls, total_duration_ms |

---

## Cross-framework: MCP + LangChain

```python
from piqrypt_mcp import AuditedMCPClient
from piqrypt_langchain import PiQryptCallbackHandler
from piqrypt_session import AgentSession

session = AgentSession([
    {"name": "langchain_agent", "identity_file": "~/.piqrypt/agent.json"},
    {"name": "mcp_tools",       "identity_file": "~/.piqrypt/mcp.json"},
])
session.start()

# LangChain agent — framework-level audit
handler = PiQryptCallbackHandler(identity_file="~/.piqrypt/agent.json")
llm = ChatOpenAI(callbacks=[handler])

# MCP client — tool-level audit
mcp = AuditedMCPClient(identity_file="~/.piqrypt/mcp.json")

async with mcp:
    # Tool call result sent back to LangChain — co-signed
    search_result = await mcp.call_tool("search", {"query": "AAPL"})
    
    session.stamp("mcp_tools", "result_sent", {
        "result_hash": sha256(str(search_result)),
        "tool": "search",
    }, peer="langchain_agent")
    
    response = llm.invoke(f"Based on: {search_result}\nGive investment advice.")

session.export("mcp_langchain_audit.json")
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Part of [PiQrypt](https://piqrypt.com) — Trust infrastructure for autonomous AI agents.  
IP: e-Soleau DSO2026006483 (INPI France — 19/02/2026)
