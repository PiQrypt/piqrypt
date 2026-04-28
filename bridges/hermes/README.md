# piqrypt-hermes

**PiQrypt cryptographic audit trail plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent)**

Every tool call Hermes makes — `bash`, `web_search`, `file_read`, and all others — is stamped with an Ed25519 signature and linked into a tamper-evident hash chain. The full audit trail is stored locally and visualized in Vigil (`localhost:8421`).

---

## What it does

| Hook | Event stamped |
|------|--------------|
| `on_session_start` | `agent_initialized` |
| `pre_tool_call` | `tool_intent` (params hashed, never stored raw) |
| `post_tool_call` | `tool_result` (result hashed, chained to intent) |
| `pre_llm_call` | Injects recent PiQrypt memory context into the LLM turn |
| `on_session_end` | `session_end` with total event count |

All events are signed with Ed25519, hash-chained (each event includes the hash of the previous one), and stored locally under `~/.piqrypt/`.

---

## Installation

```bash
pip install piqrypt piqrypt-hermes
hermes plugins enable piqrypt-audit
```

Or from the PiQrypt source repo:

```bash
cp -r bridges/hermes ~/.hermes/plugins/piqrypt-audit
hermes plugins enable piqrypt-audit
```

---

## Identity setup

PiQrypt needs to know which agent identity to use for signing. Three options:

**Option 1 — Named agent (recommended)**
```bash
piqrypt init          # creates an identity if you don't have one
export PIQRYPT_AGENT_NAME=hermes
```

**Option 2 — Identity file**
```bash
export PIQRYPT_IDENTITY_FILE=~/.piqrypt/agents/hermes/identity.json
```

**Option 3 — Ephemeral (default)**
No configuration needed. A new keypair is generated each session.
The audit trail is still valid, but not linkable across sessions.

---

## Monitoring with Vigil

```bash
piqrypt vigil          # opens the dashboard at localhost:8421
```

Vigil shows:
- VRS (Verification and Risk Score) per agent — real-time trust indicator
- Chain health — any hash break is immediately flagged CRITICAL
- Full signed event history, searchable and exportable

---

## Memory injection

On every LLM turn, the plugin injects the agent's recent signed event history
into the user message context. This gives Hermes cryptographically verifiable
recall of its own past actions — not just text summaries, but signed evidence.

The injected context looks like:
```
[PiQrypt memory — last 10 events]
2026-04-28T10:23:11  tool_intent    bash  params_hash=a3f2...
2026-04-28T10:23:12  tool_result    bash  result_hash=8c1d...  chain=ok
...
```

---

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `PIQRYPT_IDENTITY_FILE` | — | Path to a saved identity `.json` |
| `PIQRYPT_AGENT_NAME` | `hermes` | Agent name in `~/.piqrypt/agents/` |
| `PIQRYPT_MEMORY_DEPTH` | `10` | Number of recent events to inject per turn |

---

## Security properties

- **Non-repudiation** — every tool call is signed; Hermes cannot deny it happened
- **Tamper-evidence** — any retroactive modification breaks the hash chain
- **Privacy** — raw params and results are never stored; only their SHA-256 hashes
- **Local-first** — nothing leaves your machine; no server, no account required
- **Post-quantum ready** — upgrade to ML-DSA-65 with `pip install piqrypt[post-quantum]`

---

## EU AI Act

PiQrypt implements the logging requirements of EU AI Act Art. 12 (inviolable logs)
and Art. 14 (human oversight) for high-risk AI systems.
See [piqrypt.com/eu-ai-act](https://piqrypt.com/eu-ai-act) for the compliance mapping.

---

## Links

- [PiQrypt](https://piqrypt.com) — main project
- [AISS Standard](https://aiss-standard.org) — the underlying protocol (MIT)
- [Vigil dashboard](https://piqrypt.com/docs/vigil)
- [GitHub](https://github.com/piqrypt/piqrypt)
- [PyPI](https://pypi.org/project/piqrypt/)

---

## License

Apache-2.0 — see [LICENSE](../../LICENSE)

Copyright (c) 2026 PiQrypt Inc.  
IP protected by e-Soleau INPI DSO2026006483 and DSO2026009143.
