# OpenClaw Integration Guide

**Version:** 1.7.1
**Date:** 2026-03-12
**Status:** Current

---

**Integrate PiQrypt audit trail into OpenClaw autonomous agents.**

---

## 🤖 What is OpenClaw?

**OpenClaw** is an autonomous AI agent framework based on:
- **Llama 3.2** (3B parameter model)
- **Computer Use** (OS-level control)
- **Tool calling** (file operations, bash, Python)

**Challenge:** How to ensure OpenClaw decisions are auditable and trustworthy?

**Solution:** PiQrypt cryptographic audit trail + behavioral monitoring.

---

## 🔗 Integration Architecture

```
┌──────────────────────────────────────────┐
│  User Request                            │
│  "Analyze sales data and create report"  │
│  ↓                                       │
├──────────────────────────────────────────┤
│  OpenClaw (Llama 3.2)                    │
│  1. Reasoning: What steps needed?        │
│  2. Planning: Read CSV → Analyze → PDF   │
│  ↓                                       │
├──────────────────────────────────────────┤
│  PiQrypt Audit Layer                     │
│  • Sign each decision (Ed25519)          │
│  • Link decisions in hash chain          │
│  • Store cryptographic proof             │
│  • Trust State Index (TSI)               │
│  • VRS composite risk score              │
│  ↓                                       │
├──────────────────────────────────────────┤
│  Execution                               │
│  • Read sales.csv                        │
│  • Run analysis                          │
│  • Generate report.pdf                   │
└──────────────────────────────────────────┘
```

---

## 📦 Installation

### 1. Install PiQrypt

```bash
pip install piqrypt
```

**Requirements:** Python 3.9+

### 2. Install OpenClaw

```bash
git clone https://github.com/openclaw/openclaw
cd openclaw
pip install -e .
```

### 3. Configure Integration

Create `openclaw_config.yaml`:

```yaml
agent:
  name: openclaw_assistant
  model: llama-3.2-3b

audit:
  enabled: true
  provider: piqrypt
  tier: pro  # recommended for production

tools:
  - file_operations
  - bash_executor
  - python_executor
```

---

## 💻 Code Integration

### Basic Integration

```python
import piqrypt as aiss
from aiss.agent_registry import AgentRegistry
from aiss.key_store import KeyStore
from openclaw import Agent, Task

class AuditableOpenClaw(Agent):
    """OpenClaw with PiQrypt audit trail."""

    def __init__(self, config):
        super().__init__(config)

        # Initialize PiQrypt with encrypted key storage
        registry = AgentRegistry()
        registry.register_agent("openclaw_main")

        key_store = KeyStore(agent_name="openclaw_main")
        key_store.generate_and_save(passphrase="your-secure-passphrase")

        self.piqrypt_key = key_store.load(passphrase="your-secure-passphrase")
        from aiss.crypto import ed25519
        pub = ed25519.get_public_key(self.piqrypt_key)
        from aiss.identity import derive_agent_id
        self.piqrypt_id = derive_agent_id(pub)

        print(f"🔐 PiQrypt audit enabled")
        print(f"   Agent ID: {self.piqrypt_id}")

    def execute_task(self, task: Task):
        """Execute task with audit trail."""

        # 1. Llama reasoning
        plan = self.llama_model.plan(task.description)

        # 2. Sign reasoning with PiQrypt
        reasoning_event = aiss.stamp_event(
            self.piqrypt_key,
            self.piqrypt_id,
            payload={
                "event_type": "task_reasoning",
                "task": task.description,
                "plan": plan.steps,
                "confidence": plan.confidence,
                "model": "llama-3.2-3b"
            }
        )
        aiss.store_event(reasoning_event)

        # 3. Execute each step
        results = []
        previous_hash = aiss.compute_event_hash(reasoning_event)

        for step in plan.steps:
            result = self.execute_step(step)

            execution_event = aiss.stamp_event(
                self.piqrypt_key,
                self.piqrypt_id,
                payload={
                    "event_type": "step_execution",
                    "step": step.description,
                    "tool": step.tool,
                    "result": result.summary,
                    "success": result.success
                },
                previous_hash=previous_hash
            )
            aiss.store_event(execution_event)

            results.append(result)
            previous_hash = aiss.compute_event_hash(execution_event)

        return results

    def export_audit_trail(self, output_path="openclaw-audit.json"):
        """Export audit for human review."""
        events = aiss.load_events()
        from aiss.identity import export_identity
        from aiss.crypto import ed25519
        pub = ed25519.get_public_key(self.piqrypt_key)
        identity = export_identity(self.piqrypt_id, pub)
        audit = aiss.export_audit_chain(identity, events)

        import json
        with open(output_path, 'w') as f:
            json.dump(audit, f, indent=2)

        print(f"📋 Audit trail exported: {output_path}")
```

### Usage Example

```python
# Initialize OpenClaw with PiQrypt
agent = AuditableOpenClaw(config)

# Execute task
task = Task("Analyze Q4 sales data and create executive summary")
results = agent.execute_task(task)

# Export audit trail
agent.export_audit_trail("q4-sales-audit.json")

# Verify (for human reviewer)
# $ piqrypt verify q4-sales-audit.json
```

---

## 🔍 What Gets Audited?

**Every OpenClaw decision is signed:**

1. **Task Understanding** — What did OpenClaw understand? When?
2. **Reasoning Process** — What steps planned? Confidence level?
3. **Tool Executions** — bash, Python, file operations + results
4. **Failures & Retries** — What failed? How did it recover?

**Chain of Evidence:**
```
[Task] → [Reasoning] → [Step 1] → [Step 2] → [Step 3] → [Result]
   ↓         ↓            ↓          ↓          ↓          ↓
 Sign      Sign        Sign       Sign       Sign       Sign
```

---

## 📊 Behavioral Monitoring

### Vigil Server for OpenClaw

```bash
python -m vigil.vigil_server
# Dashboard → http://127.0.0.1:18421
# API       → http://127.0.0.1:18421/api/summary
```

Monitors in real-time:
- **Trust State Index (TSI):** STABLE / WATCH / UNSTABLE / CRITICAL
- **A2C anomaly detection:** 16 relational scenarios
- **VRS score:** composite behavioral risk per agent

### Example: Malicious Behavior Detection

```python
from aiss import search_events

suspicious_events = search_events(event_type="step_execution")

for event in suspicious_events:
    payload = event["payload"]
    if payload.get("tool") == "bash":
        if any(cmd in payload["step"] for cmd in ["rm -rf", "curl | bash", "chmod 777"]):
            print(f"⚠️ Suspicious command detected:")
            print(f"   Event: {aiss.compute_event_hash(event)}")
            print(f"   Command: {payload['step']}")
            print(f"   Timestamp: {event['timestamp']}")
```

---

## 🛡️ Trust & Safety

### Why PiQrypt for OpenClaw?

**Problem:** OpenClaw has OS-level access — dangerous if compromised.

**PiQrypt guarantees:**
1. **Non-repudiation** — OpenClaw cannot deny actions
2. **Tamper-proof** — Cannot modify history after execution
3. **Auditability** — Humans can verify what happened
4. **Accountability** — Legal proof of agent behavior
5. **Behavioral drift** — TSI/A2C detect anomalous patterns over time

---

## 🔐 Pro Features

### Encrypted Memory (Recommended for Production)

The `KeyStore` (v1.8.1) provides scrypt N=2¹⁷ + AES-256-GCM encryption for the private key at rest. See example above.

```bash
# All OpenClaw decisions encrypted at rest
# .key.enc = 97 bytes, magic bytes PQKY, fixed structure
```

**Benefits:**
- ✅ Brute-force resistant (>400ms per attempt)
- ✅ AES-GCM authentication tag (any tampering detected)
- ✅ Private key zeroed from RAM after use
- ✅ GDPR, HIPAA compatible

### External Certification

```bash
# Export and certify audit trail
piqrypt export openclaw-chain.json audit.json

# Request certification
piqrypt certify-request audit.json audit.json.cert --email compliance@company.com

# Verify
piqrypt certify-verify audit-CERT-XXXXX.piqrypt-certified
# ✅ Certified by PiQrypt Inc.
```

---

## 🚀 Multi-OpenClaw Collaboration

```python
# OpenClaw A and OpenClaw B collaborate on task
from aiss.a2a import initiate_handshake, accept_handshake

handshake = initiate_handshake(
    openclaw_a.piqrypt_key,
    openclaw_a.piqrypt_id,
    openclaw_b.piqrypt_id,
    payload={"task": "joint_analysis", "split": "50/50"}
)

response = accept_handshake(
    openclaw_b.piqrypt_key,
    openclaw_b.piqrypt_id,
    handshake
)

# Both agents have cryptographic proof of agreement
# Audit trail shows: A and B collaborated on task X
```

---

## 📝 Best Practices

1. **Sign Before Execution** — sign reasoning BEFORE tool execution
2. **Granular Events** — one event per step, not per entire task
3. **Include Context** — task description, confidence, tool details
4. **Use KeyStore** — never store private keys in plaintext
5. **Monitor with Vigil** — catch behavioral drift early
6. **Regular Exports** — daily/weekly audit trail export
7. **Human Review** — periodic review of VRS alerts

---

## 🆘 Troubleshooting

### OpenClaw Can't Sign Events

**Error:** `LicenseError: Free tier limited to 3 agents`

```bash
piqrypt status
piqrypt identity deactivate old-agent.json
# Or upgrade to Pro (50 agents)
```

### Audit Trail Too Large

```bash
# Fast indexed search
piqrypt search --type step_execution

# Archive old events
piqrypt archive create openclaw-q4.pqz --from 2026-01-01 --to 2026-03-31
```

---

## 📞 Support

**OpenClaw + PiQrypt questions:**
- Email: piqrypt@gmail.com
- GitHub: [piqrypt/discussions](https://github.com/piqrypt/piqrypt/discussions)
- Tag: `#openclaw-integration`

---

**Making OpenClaw Trustworthy with Cryptographic Proof** 🔐✨

---

**Intellectual Property Notice**

Core protocol concepts described in this document were deposited
via e-Soleau with the French National Institute of Industrial Property (INPI):

Primary deposit:  DSO2026006483 — 19 February 2026
Addendum:         DSO2026009143 — 12 March 2026

These deposits establish proof of authorship and prior art
for the PCP protocol specification and PiQrypt reference implementation.

PCP (Proof of Continuity Protocol) is an open protocol specification.
It may be implemented independently by any compliant system.
PiQrypt is the reference implementation.

© 2026 PiQrypt — contact@piqrypt.com
