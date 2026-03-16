# piqrypt-ollama

PiQrypt cryptographic audit trail bridge for **Ollama**.

Every `generate()` and `chat()` call is signed with Ed25519, hash-chained,
and stored as a tamper-proof local audit trail — compatible with AISS v1.1.

## Install

```bash
pip install piqrypt piqrypt-ollama
```

Requires Ollama running locally: https://ollama.ai

## Quickstart

```python
from piqrypt_ollama import AuditedOllama

# With PiQrypt identity (Pro tier — TSA anchoring, Vigil monitoring)
llm = AuditedOllama(
    model="llama3.2",
    identity_file="my_agent.json",
    agent_name="my_agent",
    tier="pro",
)

# generate — stamped automatically
response = llm.generate("What is the capital of France?")
print(response["response"])

# chat — each turn stamped and chained
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user",   "content": "Hello!"},
]
response = llm.chat(messages)
print(response["message"]["content"])

# streaming — fully audited
for chunk in llm.generate("Tell me a story", stream=True):
    print(chunk["response"], end="", flush=True)

# export audit trail
llm.export_audit("my_agent_audit.json")
```

## With Vigil live monitoring

```python
llm = AuditedOllama(
    model="mistral",
    identity_file="agent.json",
    vigil_endpoint="http://localhost:8421",   # forward events to Vigil
)
```

## Tool use with audit

```python
tools = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get weather for a city",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string"}
                },
                "required": ["city"],
            },
        },
    }
]

def dispatcher(name, args):
    if name == "get_weather":
        return f"Sunny, 22C in {args['city']}"
    return "Unknown tool"

response = llm.chat_with_tools(
    messages=[{"role": "user", "content": "What's the weather in Paris?"}],
    tools=tools,
    tool_dispatcher=dispatcher,
)
```

## Decorator

```python
from piqrypt_ollama import stamp_ollama
import ollama

@stamp_ollama("summarize", identity_file="agent.json")
def summarize(text: str) -> str:
    r = ollama.generate(model="llama3.2", prompt=f"Summarize: {text}")
    return r["response"]
```

## What is stamped

| Event | Stamped fields |
|-------|----------------|
| `agent_initialized` | model, tier, host |
| `ollama_generate_start` | prompt_hash, model, stream |
| `ollama_generate_complete` | response_hash, elapsed_ms, tokens |
| `ollama_chat_start` | messages_hash, message_count |
| `ollama_chat_complete` | response_hash, elapsed_ms |
| `ollama_tool_call` | tool_name, args_hash, round |
| `ollama_tool_result` | tool_name, result_hash, round |

All hashes are SHA-256. No raw content is ever stored.

## Audit chain

```
agent_initialized
    ↓ (previous_event_hash)
ollama_generate_start
    ↓
ollama_generate_complete
    ↓
ollama_chat_start
    ↓
ollama_chat_complete
    ...
```

Each event references the hash of the previous one — tamper-evident.

## Part of PiQrypt ecosystem

```
piqrypt          # core AISS identity
piqrypt-ollama   # this package
piqrypt-crewai   # CrewAI bridge
piqrypt-autogen  # AutoGen bridge
piqrypt-langchain # LangChain bridge
piqrypt-mcp      # MCP bridge
piqrypt-ros      # ROS2 bridge
piqrypt-rpi      # Raspberry Pi bridge
```

---

MIT License — PiQrypt Contributors
