# PiQrypt License System

**Version:** 1.10.0
**Last Updated:** 2026-10-26

---

## Overview

PiQrypt uses a six-tier licensing system (Free, Pro, Startup, Team, Business, Enterprise). The core AISS-1 protocol is free forever. Paid tiers unlock additional agents, encrypted storage, post-quantum signatures, behavioral monitoring, governance, and professional support.

License validation is **local-first** — no internet required after activation. Free tier requires no license key at all.

---

## Tiers

### 🆓 Free — forever

**Quotas:** 3 agents · 10,000 events/month

**Features:**
- ✅ Complete AISS-1 (Ed25519, SHA-256, RFC 8785, anti-replay)
- ✅ Fork detection + Canonical History Rule
- ✅ Audit export (.pqz memory format)
- ✅ Full CLI access
- ✅ A2A handshake (Ed25519 co-signed)
- ✅ All 9 framework bridges (LangChain, CrewAI, AutoGen, OpenClaw, Session, MCP, Ollama, ROS2, RPi)
- ✅ Vigil — read-only (dashboard view)
- ⚠️ TrustGate - demo mode (real policy engine and approval queue with demo operators; the queue and journal are reset at each start)

**License key:** Not required.

---

### 💼 Pro — €390/year

**Quotas:** 50 agents · 500,000 events/month · 1,000 API req/hour

**Everything in Free, plus:**
- ✅ AISS-2 — Dilithium3 post-quantum signatures (NIST FIPS 204)
- ✅ AISS-2 — Hybrid signatures (Ed25519 + Dilithium3)
- ✅ RFC 3161 trusted timestamps (TSA integration)
- ✅ Encrypted key storage (scrypt N=2¹⁷ + AES-256-GCM)
- ✅ Certified export (.pqz certified: Ed25519 signed archive with RFC 3161 timestamp token)
- ✅ AgentSession — cross-framework co-signed sessions (N agents)
- ✅ TrustGate — manual mode (REQUIRE_HUMAN flow, policy evaluation)
- ✅ Vigil — full mode (write API, event injection)
- ✅ Trust Scoring (TS) — 5-component weighted score
- ✅ Trust State Index (TSI) — 4 statistical stability indicators
- ✅ A2C relational anomaly detection (16 scenarios)
- ✅ VRS — Vigil Risk Score (composite 4-dimension score)
- ✅ Email support — 48h response

**License key:** Required — JWT Ed25519, offline validation.

---

### 🚀 Startup — €990/year

**Quotas:** 50 agents · 1,000,000 events/month · 5,000 API req/hour

Everything in Pro, plus a team workspace (shared agent registry) and a shared Vigil dashboard. Email support, 24h response.

---

### 👥 Team — on request

**Quotas:** 150 agents · 5,000,000 events/month · 10,000 API req/hour

Everything in Pro. Designed for shared team deployments.

---

### 🏢 Business — on request

**Quotas:** 500 agents · 20,000,000 events/month · 100,000 API req/hour

**Everything in Team, plus:**
- ✅ TrustGate — **full automated mode** (no human approval required)
- ✅ Multi-organization support
- ✅ SIEM integration
- ✅ On-premise deployment (option)
- ✅ Priority support

---

### 🌟 Enterprise — on demand

**Quotas:** Unlimited agents · unlimited events · unlimited API

**Everything in Business, plus:**
- ✅ SSO (SAML, OAuth 2.0, OIDC)
- ✅ HSM integration
- ✅ On-premise deployment
- ✅ SOC2 / ISO 27001 audit support
- ✅ Dedicated SLA + support

**Contact:** piqrypt@gmail.com — Subject: Enterprise Inquiry

---

### 🌱 OSS — Free (Pro features for qualified open-source projects)

All Pro features at no cost. Requirements: OSI-approved license · public repo · active development (3+ commits/month) · attribution in README.

**Apply:** piqrypt@gmail.com — Subject: OSS License Request

---

## Feature Matrix

| Feature | Free | Pro | Team | Business | Enterprise |
|---------|:----:|:---:|:----:|:--------:|:----------:|
| **Quotas** | | | | | |
| Agents | 3 | 50 | 150 | 500 | ∞ |
| Events / month | 10k | 500k | 5M | 20M | ∞ |
| API req / hour | 100 | 1k | 10k | 100k | ∞ |
| **AISS-1** | | | | | |
| Ed25519 · chains · fork · anti-replay | ✅ | ✅ | ✅ | ✅ | ✅ |
| A2A handshake | ✅ | ✅ | ✅ | ✅ | ✅ |
| All 9 framework bridges | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AISS-2** | | | | | |
| Dilithium3 (post-quantum) | — | ✅ | ✅ | ✅ | ✅ |
| Hybrid signatures Ed25519 + Dilithium3 | — | ✅ | ✅ | ✅ | ✅ |
| RFC 3161 trusted timestamps | — | ✅ | ✅ | ✅ | ✅ |
| **Storage** | | | | | |
| Plaintext local storage | ✅ | ✅ | ✅ | ✅ | ✅ |
| AES-256-GCM encrypted storage | — | ✅ | ✅ | ✅ | ✅ |
| HSM integration | — | — | — | option | ✅ |
| **Export** | | | | | |
| .pqz memory export | ✅ | ✅ | ✅ | ✅ | ✅ |
| .pqz certified (Ed25519 + RFC 3161 token) | — | ✅ | ✅ | ✅ | ✅ |
| **Vigil** | | | | | |
| Dashboard read-only | ✅ | ✅ | ✅ | ✅ | ✅ |
| Vigil full mode (write API) | — | ✅ | ✅ | ✅ | ✅ |
| Trust Scoring (TS) | — | ✅ | ✅ | ✅ | ✅ |
| TSI — stability index (4 indicators) | — | ✅ | ✅ | ✅ | ✅ |
| A2C anomaly detection (16 scenarios) | — | ✅ | ✅ | ✅ | ✅ |
| VRS composite score | — | ✅ | ✅ | ✅ | ✅ |
| **TrustGate** | | | | | |
| Manual mode (policy eval + REQUIRE_HUMAN) | demo | ✅ | ✅ | ✅ | ✅ |
| Full automated enforcement | — | — | — | ✅ | ✅ |
| **Enterprise** | | | | | |
| AgentSession cross-framework | — | ✅ | ✅ | ✅ | ✅ |
| Multi-organization | — | — | — | ✅ | ✅ |
| SIEM integration | — | — | — | ✅ | ✅ |
| SSO | — | — | — | — | ✅ |
| On-premise | — | — | — | option | ✅ |
| **Support** | Community | Email 48h | Priority | Dedicated | Dedicated SLA |
| **Price** | **Free** | **€390/yr** | **on request** | **on request** | **on request** |

Free: TrustGate runs in demo mode (real policy engine and approval queue, demo operators, queue and journal reset at each start). Manual mode with a persistent journal starts at Pro; full automated mode starts at Business.

Startup (€990/year) is Pro plus a team workspace and a shared Vigil dashboard; it is not a separate column in this table. See TIERS_PRICING.md for the full comparison.

---

## License Verification

### Architecture

```
Free    →  HMAC local (free.<id>.<hmac8>)         — aucun appel réseau pour la licence
Pro+    →  JWT Ed25519 — vérifié offline           — réseau au renouvellement seulement
                                                     Grace period 72h si réseau absent
```

### Validation mechanism

- **Free tier:** HMAC-SHA256 local, aucune dépendance réseau
- **Pro+ tiers:** JWT signé Ed25519 (clé publique embarquée dans le binaire). Aucun appel réseau pour valider — la clé privée ne quitte jamais `api.piqrypt.com`.
- **Grace period:** 72 heures après expiration avant dégradation vers Free. Jamais de blocage brutal.
- **Dégradation gracieuse:** expiration → Free tier automatiquement. Zéro perte de données. Les signatures existantes restent valides.

### Réseau et licence

- ✅ Validation offline complète après activation
- ✅ Aucune vérification de licence côté serveur à l'usage
- ✅ Télémétrie anonyme activée par défaut, désactivable (voir docs/TELEMETRY.md)
- ✅ Free tier : aucun appel réseau pour la licence

---

## Activation

### Vérifier la licence actuelle

```bash
piqrypt license status
# ==================================================
#   PiQrypt License Status
# ==================================================
#
#   Tier    : FREE
#
#   Features:
#     (one line per feature, with a check mark when it is available)
#
#   Upgrade to Pro:
#     piqrypt.com/pricing  -  EUR 390/year
```

### Activer une licence Pro

```bash
# Variable d'environnement (recommandé — Docker, CI/CD, Kubernetes)
export PIQRYPT_LICENSE_KEY="<jwt_token>"

# Ou écriture dans ~/.piqrypt/license.jwt
piqrypt license activate <jwt_token>
```

```python
from piqrypt import activate_license
activate_license("<jwt_token>")
```

### Vérifier les features dans le code

```python
from aiss.license import get_license, require, FeatureNotAvailableError

lic = get_license()

# Tier et quotas
print(lic.tier)              # "free" | "pro" | "startup" | "team" | "business" | "enterprise"
print(lic.agents_max)        # 3 | 50 | 50 | 150 | 500 | None (Enterprise = illimité)
print(lic.events_month)      # 10000 | 500000 | ... | None

# Vérifier une feature
print(lic.has_feature("quantum"))           # False (Free) | True (Pro+)
print(lic.has_feature("tsa_rfc3161"))       # False (Free) | True (Pro+)
print(lic.get_feature_level("trustgate"))   # None | "manual" | "full"
print(lic.get_feature_level("vigil"))       # "readonly" | "full"

# Lever une exception si feature absente
try:
    require("quantum")
except FeatureNotAvailableError as e:
    print(e)
    # 'quantum' requires tier 'pro' or higher.
    # Current tier: 'free'
    # Upgrade: https://piqrypt.com/pricing

# TrustGate — vérifier le niveau
lic.require_trustgate(level="manual")   # OK sur Pro+
lic.require_trustgate(level="full")     # lève si < Business

# Vérifier un quota
from aiss.license import check_quota, QuotaExceededError
try:
    check_quota("agents", current_count=45)   # alerte à 80%, bloque à 100%
except QuotaExceededError as e:
    print(e)
    # Quota exceeded: agents (50/50 used, tier 'pro').
```

### Décorateur `@require_pro`

```python
from aiss.license import require_pro

@require_pro("Trusted timestamps")
def stamp_with_tsa(event):
    # accessible Pro+ uniquement
    ...
```

---

## Purchasing

### Pro

<div align="center">

[![Pro €390/year](https://img.shields.io/badge/Pro-€390/year-orange?style=for-the-badge&logo=stripe)](https://piqrypt.com/pricing)

</div>

Après paiement, le JWT de licence est envoyé par email. Activation :

```bash
piqrypt license activate <token>
```

### Enterprise

**piqrypt@gmail.com** — Subject: Enterprise Inquiry

### OSS (open-source projects)

**piqrypt@gmail.com** — Subject: OSS License Request

---

## FAQ

**Les 9 bridges sont-ils gratuits ?**
Oui. LangChain, CrewAI, AutoGen, OpenClaw, Session, MCP, Ollama, ROS2, RPi — tous MIT/Apache-2.0, disponibles sur tous les tiers.

**AgentSession est-il gratuit ?**
Non. AgentSession (co-signature cross-framework entre N agents) requiert Pro+.

**TrustGate est-il disponible en Free ?**
En mode démo, pour l'évaluation : le moteur de politiques et la file d'approbation sont les vrais, avec deux opérateurs de démonstration, et la file et le journal sont remis à zéro à chaque démarrage. Le mode manuel avec journal persistant commence à Pro ; le mode automatique complet commence à Business.

**Que se passe-t-il à l'expiration ?**
Grace period de 72h, puis dégradation gracieuse vers Free. Zéro perte de données. Les signatures existantes restent valides indéfiniment.

**Puis-je utiliser Free en production commerciale ?**
Oui, avec attribution ("Powered by PiQrypt" + lien vers piqrypt.com).

**Le token JWT est-il sécurisé ?**
Stocké dans `~/.piqrypt/license.jwt` (chmod 600). La clé privée de signature ne quitte jamais `api.piqrypt.com`. Validation locale via clé publique Ed25519 embarquée.

---

## Philosophy

> Core cryptographic identity should be accessible to everyone.
> Advanced features fund sustainable development.

- ✅ AISS-1 core — gratuit, toujours, sans régression
- ✅ Pas de vérification de licence en ligne
- ✅ Local-first — pas de dépendance cloud forcée
- ✅ Grace period — jamais de blocage brutal
- ✅ Open-source program pour les projets OSS

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
