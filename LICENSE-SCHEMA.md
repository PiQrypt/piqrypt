# PiQrypt — License Schema

**Version:** 1.7.1
**Last Updated:** 2026-03-12

---

## Overview

PiQrypt uses the **Open Core** dual-license model — the same strategy
used by Elastic, Grafana, GitLab, and Confluent.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     PiQrypt License Architecture                    │
├──────────────────────┬─────────────────┬────────────────────────────┤
│ Layer                │ License         │ Objective                  │
├──────────────────────┼─────────────────┼────────────────────────────┤
│ AISS spec + RFC      │ MIT             │ Adoption — open standard   │
│ tests/, demos/,      │ MIT             │ Open contribution          │
│ agents/, examples/,  │                 │                            │
│ scripts racine       │                 │                            │
│ bridges/             │ Apache-2.0      │ Adoption — no friction     │
├──────────────────────┼─────────────────┼────────────────────────────┤
│ CLI + SDK            │ Apache-2.0      │ Developer community        │
├──────────────────────┼─────────────────┼────────────────────────────┤
│ Core engine (aiss/)  │ ELv2            │ Protection + revenue       │
│ Vigil                │ ELv2            │ Enterprise upsell          │
│ TrustGate (infra)    │ ELv2            │ Enterprise upsell          │
├──────────────────────┼─────────────────┼────────────────────────────┤
│ Trust Score + TSI    │ ELv2 + Comm.    │ Proprietary IP (e-Soleau)  │
│ A2C + Anomaly        │ ELv2 + Comm.    │ Proprietary IP (e-Soleau)  │
│ TrustGate (engine)   │ ELv2 + Comm.    │ Proprietary IP (e-Soleau)  │
├──────────────────────┼─────────────────┼────────────────────────────┤
│ Commercial license   │ On demand       │ SaaS / cloud / OEM         │
└──────────────────────┴─────────────────┴────────────────────────────┘
```

---

## Why this model

Three growth engines, one architecture:

```
  FREE DISTRIBUTION          TECHNICAL LOCK-IN         ENTERPRISE UPSELL
  ─────────────────          ─────────────────         ─────────────────
  MIT/Apache on the          Once an org uses          Individuals use
  protocol + bridges         AISS protocol,            Free.
  = automatic marketing.     .pqz format, and          Teams buy Pro.
                             chain identity,           Enterprises need
  GitHub becomes:            migration cost            Vigil + TrustGate
  · user acquisition         is high.                  + SLA — that is
  · dev adoption                                       where revenue is.
  · technical credibility    Lock-in through
                             data inertia,
                             not contracts.
```

---

## License details

### MIT — AISS specification + RFC

```
  ✅  Use in any project — commercial or open source
  ✅  Modify and redistribute freely
  ✅  Implement AISS independently in any language or framework
  ✅  No obligation to open your code
  ⚠️  Attribution required (include copyright notice)
```

The AISS protocol and PCP specification are intentionally MIT.
Any agent framework, any organization, any language can implement
AISS without legal friction — this is what makes it a credible
open standard and drives adoption.

---

### MIT — Tests, demos, examples, root scripts

```
  ✅  tests/             — Full test suite
  ✅  demos/             — Demo scenarios
  ✅  agents/            — Agent examples
  ✅  examples/          — Usage examples
  ✅  Root scripts       — piqrypt_start.py, smoke_test*.py, generate_*.py, etc.
```

These directories contain no proprietary algorithms. They are released under MIT
to allow contribution, forking, and independent testing without restriction.

---

### Apache-2.0 — Bridges + CLI + SDK

```
  ✅  Use commercially without restrictions
  ✅  Modify and distribute
  ✅  Patent grant included
  ✅  No obligation to open your code
  ⚠️  Include NOTICE file when distributing
  ⚠️  State significant changes made
```

All 9 framework bridges (LangChain, CrewAI, AutoGen, OpenClaw,
Session, MCP, Ollama, ROS2, RPi) are Apache-2.0. Any developer
can integrate them into any proprietary or open-source project
with zero friction.

---

### ELv2 (Elastic License 2.0) — Core engine, Vigil, TrustGate

```
  ✅  Personal projects — free
  ✅  Internal business deployment — free (no external users)
  ✅  Open-source projects — free
  ✅  Full evaluation rights (dev / test / staging)
  ✅  Modify and study the source
  ❌  Providing the software to third parties as a hosted
      or managed service — requires commercial license
  ❌  Removing or bypassing license key enforcement
```

**Why ELv2 and not AGPL-3.0?**

```
  AGPL-3.0                          ELv2
  ────────────────────────────────  ────────────────────────────────
  Network clause triggers only      "Hosted or managed service"
  if you MODIFY the code.           prohibition applies regardless
                                    of whether you modified it.
  A cloud provider can WRAP
  the software unmodified and       No interpretation required.
  argue AGPL does not apply.        No wrapper loophole.

  Requires legal interpretation.    Readable by a lawyer in 30s.
```

ELv2 closes the "AWS wrapper" loophole explicitly.
This is the enforcement advantage over AGPL.

---

### ELv2 + Commercial — Proprietary methods (e-Soleau protected)

```
  ✅  Same rights as ELv2 above for open/internal use
  ✅  Additional IP protection via e-Soleau deposits
  ❌  SaaS / managed service deployment — commercial license required
  ❌  Embedding in proprietary products — commercial license required
  ❌  OEM or white-label use — commercial license required
```

Files covered:
```
  aiss/trust_score.py      Trust Scoring — 5-component weighted method
  aiss/tsi_engine.py       Trust State Index — 4 statistical indicators
  aiss/a2c_detector.py     A2C — 16 relational anomaly scenarios
  aiss/anomaly_monitor.py  Behavioral anomaly monitoring
  trustgate/policy_engine.py     Policy evaluation engine
  trustgate/policy_loader.py     Policy loading and parsing
  trustgate/policy_versioning.py Policy versioning system
  trustgate/decision.py          Decision logic
```

These files contain original algorithmic methods deposited via
e-Soleau (DSO2026006483 + DSO2026009143) — independently inventive
methods that did not exist prior to this work.

---

### Commercial License — on demand

For organizations that cannot comply with ELv2:

```
  ✅  Deploy core / Vigil / TrustGate as SaaS or managed service
  ✅  Keep all modifications private — zero open-source obligation
  ✅  Sub-license and OEM rights available
  ✅  White-label rights available
  ✅  Patent grant + license audit protection
```

Full details → [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)

---

## Decision tree

```
  Are you using only bridges / CLI / AISS spec?
  │
  └── YES ──► MIT / Apache-2.0
              No restrictions. No action needed.

  Are you using aiss/ / vigil/ / trustgate/?
  │
  ├── Internal use only (no external users)?
  │   └── YES ──► ELv2 — Free. No action needed.
  │
  ├── Open-source project?
  │   └── YES ──► ELv2 — Free.
  │               Apply for OSS Pro license if needed:
  │               contact@piqrypt.com
  │
  └── SaaS / managed service / cloud for external users?
      └── YES ──► Commercial license required.
                  contact@piqrypt.com
                  Subject: Commercial License Inquiry
```

---

## License files in this repository

```
  piqrypt/
  ├── LICENSE                   MIT + ELv2 overview (root default)
  ├── LICENSE-SCHEMA.md         This file
  ├── COMMERCIAL-LICENSE.md     Commercial license tiers and terms
  ├── aiss/
  │   └── LICENSE               ELv2
  ├── vigil/
  │   └── LICENSE               ELv2
  ├── trustgate/
  │   └── LICENSE               ELv2
  ├── cli/
  │   └── LICENSE               Apache-2.0
  └── bridges/
      └── LICENSE               Apache-2.0
```

> If a component directory does not contain its own LICENSE file,
> the root MIT license applies.

---

**Intellectual Property Notice**

Primary deposit : DSO2026006483 — 19 February 2026
Addendum        : DSO2026009143 — 12 March 2026

PCP (Proof of Continuity Protocol) is an open protocol specification.
It may be implemented independently by any compliant system.
PiQrypt is the reference implementation.

© 2026 PiQrypt — contact@piqrypt.com
