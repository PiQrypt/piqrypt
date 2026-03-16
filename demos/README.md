# PiQrypt — Demos

Live simulations of the full PiQrypt stack.
No API key required — everything runs locally.

---

## Quick start

Run from the **repo root**:

```powershell
cd C:\Users\julie\Documents\Papa\Github\piqrypt

# Multi-agent family simulation (interactive menu)
.\demos\start_families.ps1

# Full live stack — Trading / Compliance / Rogue agents
.\demos\start_legacy.ps1
```

---

## start_families.ps1

Launches a multi-agent simulation organized by agent family.

**Interactive menu** (no argument):
```powershell
.\demos\start_families.ps1

  PiQrypt -- Choisissez votre profil
  ------------------------------------
  [1]  Nexus Labs   -- DevOps / Infra    (Ollama + LangGraph)
  [2]  PixelFlow    -- Createur digital  (CrewAI + Claude Haiku)
  [3]  AlphaCore    -- Quant / Trading   (AutoGen + GPT-4o)

  Votre choix [1/2/3] :
```

**Direct launch** (with argument):
```powershell
.\demos\start_families.ps1 nexus        # Nexus Labs  — DevOps / Infra
.\demos\start_families.ps1 pixelflow    # PixelFlow   — Digital creator
.\demos\start_families.ps1 alphacore    # AlphaCore   — Quant trading
```

**What it does:**
- Resets local `.piqrypt` data
- Starts the full stack (`piqrypt_start.py --all`)
- Waits 10s for stack readiness
- Launches `demo_families.py` for the selected family
- Opens Vigil dashboard → http://localhost:8421

---

## start_legacy.ps1

Launches the full PiQrypt live stack with 10 agents across
trading, compliance, rogue, and shadow profiles.

```powershell
.\demos\start_legacy.ps1
```

**What it does:**
- Resets local `.piqrypt` data
- Starts the full stack (`piqrypt_start.py --all`)
- Waits 10s for stack readiness
- Launches `demo_piqrypt_live.py` in loop mode
- Opens Vigil dashboard → http://localhost:8421

---

## demo_trustgate_flow.py

Focused simulation of the TrustGate decision engine.
Run directly:

```powershell
python demos\demo_trustgate_flow.py
```

**What it demonstrates:**
- Policy loading and versioning
- REQUIRE_HUMAN trigger flow
- Automated governance decisions
- Audit journal generation

---

## Stack architecture

```
  ┌─────────────────────────────────────────────────────┐
  │  TrustGate  — Governance & Policy enforcement       │
  ├─────────────────────────────────────────────────────┤
  │  Vigil      — Behavioral monitoring                 │
  │               http://localhost:8421                 │
  ├─────────────────────────────────────────────────────┤
  │  PiQrypt    — Continuity engine                     │
  │               event chains · stamps · TSA · A2A     │
  ├─────────────────────────────────────────────────────┤
  │  AISS       — Agent identity (Ed25519 · Dilithium)  │
  └─────────────────────────────────────────────────────┘
```

---

## Requirements

```powershell
# From repo root
pip install -e ".[dev]"
```

---

> For production deployment see [QUICK-START.md](../QUICK-START.md)
> For full documentation see [docs/](../docs/)

© 2026 PiQrypt — contact@piqrypt.com
