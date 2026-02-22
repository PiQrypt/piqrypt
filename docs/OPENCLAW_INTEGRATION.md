# OpenClaw Integration Guide

**Version:** 1.5.0  
**Date:** 2026-02-21  
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

**Solution:** PiQrypt cryptographic audit trail.

---

## 🔗 Integration Architecture

```
┌──────────────────────────────────────────┐
│  User Request                            │
│  "Analyze sales data and create report" │
│  ↓                                       │
├──────────────────────────────────────────┤
│  OpenClaw (Llama 3.2)                   │
│  1. Reasoning: What steps needed?       │
│  2. Planning: Read CSV → Analyze → PDF  │
│  ↓                                       │
├──────────────────────────────────────────┤
│  PiQrypt Audit Layer                    │
│  • Sign each decision                    │
│  • Link decisions in chain               │
│  • Store cryptographic proof             │
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

### 2. Install OpenClaw

```bash
# Clone OpenClaw (example - adjust for real repo)
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
  tier: free  # or pro
  
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
from openclaw import Agent, Task

class AuditableOpenClaw(Agent):
    """OpenClaw with PiQrypt audit trail."""
    
    def __init__(self, config):
        super().__init__(config)
        
        # Initialize PiQrypt
        self.piqrypt_key, self.piqrypt_pub = aiss.generate_keypair()
        self.piqrypt_id = aiss.derive_agent_id(self.piqrypt_pub)
        
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
            # Execute step
            result = self.execute_step(step)
            
            # Sign execution
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
        identity = aiss.export_identity(self.piqrypt_id, self.piqrypt_pub)
        
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

1. **Task Understanding**
   - What did OpenClaw understand from the request?
   - Timestamp: When?

2. **Reasoning Process**
   - What steps did it plan?
   - What was the confidence level?

3. **Tool Executions**
   - What tools were used? (bash, Python, file ops)
   - What were the results?

4. **Failures & Retries**
   - Did anything fail?
   - How did it recover?

**Chain of Evidence:**
```
[Task] → [Reasoning] → [Step 1] → [Step 2] → [Step 3] → [Result]
   ↓         ↓            ↓          ↓          ↓          ↓
 Sign      Sign        Sign       Sign       Sign       Sign
```

---

## 🛡️ Trust & Safety

### Why PiQrypt for OpenClaw?

**Problem:** OpenClaw has OS-level access (dangerous if compromised)

**PiQrypt guarantees:**
1. **Non-repudiation:** OpenClaw cannot deny actions
2. **Tamper-proof:** Cannot modify history after execution
3. **Auditability:** Humans can verify what happened
4. **Accountability:** Legal proof of agent behavior

### Example: Malicious Behavior Detection

```python
# Search for suspicious bash commands
suspicious_events = aiss.search_events(event_type="step_execution")

for event in suspicious_events:
    payload = event["payload"]
    
    if payload.get("tool") == "bash":
        # Check for dangerous commands
        if any(cmd in payload["step"] for cmd in ["rm -rf", "curl | bash", "chmod 777"]):
            print(f"⚠️ Suspicious command detected:")
            print(f"   Event: {aiss.compute_event_hash(event)}")
            print(f"   Command: {payload['step']}")
            print(f"   Timestamp: {event['timestamp']}")
```

---

## 📊 Monitoring Dashboard

### Real-Time Monitoring

```python
# Watch OpenClaw decisions in real-time
from piqrypt import watch_events

def on_new_event(event):
    if event["payload"]["event_type"] == "step_execution":
        print(f"⚙️ OpenClaw executing: {event['payload']['tool']}")

watch_events(callback=on_new_event, filters={"agent_id": agent.piqrypt_id})
```

### Daily Summary

```python
# Generate daily report
from datetime import datetime, timedelta

today = datetime.now().timestamp()
yesterday = (datetime.now() - timedelta(days=1)).timestamp()

events = aiss.search_events(
    after=yesterday,
    before=today,
    agent_id=agent.piqrypt_id
)

print(f"📈 OpenClaw Activity (last 24h)")
print(f"   Total events: {len(events)}")
print(f"   Tasks completed: {len([e for e in events if e['payload']['event_type'] == 'task_reasoning'])}")
print(f"   Tools used: {set(e['payload'].get('tool') for e in events if 'tool' in e['payload'])}")
```

---

## 🔐 Pro Features

### Encrypted Memory (Recommended for Production)

```bash
# Upgrade to Pro
piqrypt license activate pk_pro_XXXXXXXXXXXX_XXXXXXXX

# Encrypt OpenClaw's audit trail
piqrypt memory encrypt
# Enter passphrase: ****************

# Now all OpenClaw decisions are encrypted at rest
```

**Benefits:**
- ✅ AES-256-GCM encryption
- ✅ Protects sensitive task details
- ✅ Compliance (GDPR, HIPAA)

### External Certification

```bash
# For legal compliance (e.g., automated trading)
piqrypt export openclaw-chain.json audit.json --certified

# Request PiQrypt Inc. certification
piqrypt certify-request audit.json audit.json.cert --email compliance@company.com

# After receiving .piqrypt-certified file
piqrypt certify-verify audit-CERT-XXXXX.piqrypt-certified
# ✅ Certified by PiQrypt Inc. (legal standing++)
```

---

## 🚀 Advanced: Multi-OpenClaw Collaboration

### Agent-to-Agent Handshake (Coming v1.6)

```python
# OpenClaw A and OpenClaw B collaborate on task
from aiss.a2a import initiate_handshake

# OpenClaw A initiates
handshake = initiate_handshake(
    openclaw_a.piqrypt_key,
    openclaw_a.piqrypt_id,
    openclaw_b.piqrypt_id,
    payload={"task": "joint_analysis", "split": "50/50"}
)

# OpenClaw B accepts
response = accept_handshake(
    openclaw_b.piqrypt_key,
    openclaw_b.piqrypt_id,
    handshake
)

# Now both have cryptographic proof of agreement
# Audit trail shows: A and B collaborated on task X
```

**Use case:** Two OpenClaw instances splitting complex task.

---

## 📝 Best Practices

1. **Sign Before Execution**
   - Always sign reasoning BEFORE tool execution
   - Creates temporal proof

2. **Granular Events**
   - One event per step (not per entire task)
   - Better auditability

3. **Include Context**
   - Task description
   - Confidence levels
   - Tool details

4. **Regular Exports**
   - Export audit trail daily/weekly
   - Store securely (Pro: encrypted)

5. **Human Review**
   - Periodic review of audit trails
   - Flag suspicious patterns

---

## 🆘 Troubleshooting

### OpenClaw Can't Sign Events

**Error:** `LicenseError: Free tier limited to 3 agents`

**Solution:**
```bash
# Check active agents
piqrypt status

# Deactivate old agents
piqrypt identity deactivate old-agent.json

# Or upgrade to Pro (unlimited agents)
```

### Audit Trail Too Large

**Problem:** 100k+ events, slow search

**Solution:**
```bash
# Use SQLite index (automatic in v1.4+)
piqrypt search --type step_execution  # Fast (indexed)

# Or export to archive
piqrypt archive create openclaw-q4.pqz --from 2025-10-01 --to 2025-12-31
```

---

## 📞 Support

**OpenClaw + PiQrypt questions:**
- Email: piqrypt@gmail.com
- GitHub: [piqrypt/discussions](https://github.com/piqrypt/piqrypt/discussions)
- Tag: `#openclaw-integration`

---

**Making OpenClaw Trustworthy with Cryptographic Proof** 🔐✨
