# Trust Scoring & Sentinel — Technical Specification

**Version:** 2.1  
**Date:** 2026-03-02  
**Standard:** AISS v1.1 (Agent Identity and Signature Standard)  
**Status:** ✅ Fully implemented — v1.8.4

---

## Abstract

Le Trust Scoring dans PiQrypt n'est pas un score moral.

Il est un **indicateur structurel de cohérence, stabilité et continuité cryptographique** d'un agent autonome.

**Sentinel** est un moteur local de détection de dérive comportementale et structurelle, pleinement opérationnel depuis v1.8.4.

Le système complet est :

- **Explicable** — chaque composante est traçable à des événements cryptographiques concrets
- **Déterministe** — même inputs → même outputs, toujours
- **Audit-able** — tous les calculs reproductibles par un tiers indépendant
- **Non-bloquant** — jamais de gate automatique, l'humain décide
- **Local-first** — aucune dépendance à un service central

---

## Table des matières
```
1.  Architecture cible
2.  Trust Score (TS) — État structurel
3.  TSI — Trust Stability Index — Dynamique
4.  A2C Detection Layer
5.  Anomaly Monitor & VRS
6.  Vigil Server
7.  Handshake Signal Extension
8.  Contraintes d'implémentation
9.  Historique d'implémentation
10. CTO Defensibility Matrix
11. Limitations & Future Work
12. Références
```

---

## 1. Architecture cible
```
Agent
 ├── PiQrypt Core
 │    ├── aiss/
 │    │    ├── trust_score.py      ← TS computation       ✅ v1.5.0
 │    │    ├── tsi_engine.py       ← TSI dynamics          ✅ v1.5.0
 │    │    ├── a2c_detector.py     ← Relational drift      ✅ v1.5.0
 │    │    ├── anomaly_monitor.py  ← Event hub + VRS       ✅ v1.5.0
 │    │    ├── key_store.py        ← Encrypted key storage ✅ v1.8.4
 │    │    └── agent_registry.py   ← Agent isolation       ✅ v1.8.4
 │    ├── history.py               ← Rotation chain        ✅ v1.6.0
 │    ├── index.py                 ← SQLite index          ✅ v1.6.0
 │    └── memory.py
 │
 └── Vigil Server                  ✅ v1.5.0
      └── vigil/vigil_server.py
           ├── HTTP dashboard (port 18421)
           ├── /api/summary — VRS par agent
           └── /api/alerts  — alertes actives
```

**Principe de séparation des responsabilités :**
```
PiQrypt Core    → prouve la continuité cryptographique
Trust Score     → mesure la cohérence structurelle (état)
TSI             → mesure la stabilité du score (dynamique)
A2C Detector    → mesure la dérive relationnelle        ✅ v1.5.0
Anomaly Monitor → centralise les alertes + calcule VRS  ✅ v1.5.0
Vigil Server    → dashboard HTTP + REST API             ✅ v1.5.0
L'humain        → décide
```

---

## 2. Trust Score (TS) — État structurel

### 2.1 Définition

Le Trust Score est un **score instantané normalisé entre 0 et 1**, calculé à partir des événements cryptographiques d'un agent.

Il mesure 5 dimensions :

| Composante | Nom | Poids recommandé |
|-----------|-----|-----------------|
| **I** | Integrity | 0.30 |
| **V_t** | Verified Interactions (time-weighted) | 0.25 |
| **D_t** | Diversity (Shannon entropy) | 0.15 |
| **F** | Finalization Reliability | 0.15 |
| **R** | Rotation Health | 0.15 |

**Formule globale :**
```
TS = w_I×I + w_V×V_t + w_D×D_t + w_F×F + w_R×R

Avec : w_I + w_V + w_D + w_F + w_R = 1.0
TS ∈ [0, 1]
```

Les poids sont **configurables par déploiement**.

---

### 2.2 I — Integrity Score

**Définition :** Continuité cryptographique de la chaîne d'événements.
```python
I = (
    hash_chain_valid    × 0.30 +
    no_unresolved_forks × 0.25 +
    signatures_valid    × 0.25 +
    key_rotation_valid  × 0.20
)
```

| Score I | Signification |
|---------|--------------|
| 1.00 | Continuité cryptographique parfaite |
| 0.80–0.99 | Issues mineures (fork résolu, attestation ancienne) |
| 0.50–0.79 | Concerns modérés (forks multiples, rotation incomplète) |
| < 0.50 | Compromis sévère (rupture de chaîne, clé révoquée) |

> ⚠️ **Limitation :** `I` mesure la *continuité*, pas la *sécurité*. Une clé privée volée utilisée pour signer des événements valides donne I = 1.0. Défenses complémentaires requises : HSM, révocation, attestation matérielle.

---

### 2.3 V_t — Verified Interaction Ratio (time-weighted)

**Pondération temporelle — décroissance exponentielle :**
```python
def temporal_weight(event_timestamp, current_time):
    import math
    LAMBDA = math.log(2) / (30 * 86400)  # demi-vie 30 jours
    age = current_time - event_timestamp
    return math.exp(-LAMBDA * age)
```
```
Événement d'aujourd'hui : w ≈ 1.0
Événement à 30 jours    : w = 0.50
Événement à 60 jours    : w = 0.25
Événement à 90 jours    : w = 0.125
```

---

### 2.4 D_t — Diversity Factor (Shannon Entropy)

**Définition :** Entropie de la distribution des partenaires d'interaction.
```python
def compute_D_t(interactions, current_time, window=30*86400):
    from math import log2
    from collections import Counter
    recent = [i for i in interactions
              if current_time - i["timestamp"] < window]
    if not recent:
        return 1.0
    peer_counts = Counter(i["peer_id"] for i in recent)
    total = len(recent)
    entropy = -sum((c/total) * log2(c/total) for c in peer_counts.values())
    max_entropy = log2(len(peer_counts)) if len(peer_counts) > 1 else 1.0
    return entropy / max_entropy if max_entropy > 0 else 0.0
```

| D_t | Pattern |
|-----|---------|
| 0.9–1.0 | Haute diversité |
| 0.5–0.8 | Clustering modéré |
| < 0.5 | Cluster fermé |

---

### 2.5 F — Finalization Reliability
```python
def compute_F(events):
    eligible = [e for e in events
                if e.get("payload", {}).get("event_type")
                not in ("key_rotation", "genesis")]
    if not eligible:
        return 1.0
    finalized = sum(1 for e in eligible
                    if e.get("tsa_token") or e.get("rfc3161_token"))
    return finalized / len(eligible)
```

---

### 2.6 R — Rotation Health

Évalue la cohérence des rotations de clés via `history.py` (v1.6.0).

Pénalités :
- Rotation sans attestation : `-0.60`
- Rotation trop rapide (< 7 jours) : `-0.30`

---

### 2.7 Tiers du Trust Score global

| TS | Tier | Signification |
|----|------|--------------|
| > 0.95 | **Elite** | Continuité cryptographique irréprochable |
| 0.90–0.95 | **A+** | Très haute confiance |
| 0.80–0.89 | **A** | Haute confiance |
| 0.70–0.79 | **B** | Confiance modérée — surveiller |
| < 0.70 | **At Risk** | Anomalies détectées — investiguer |

---

## 3. TSI — Trust Stability Index

### 3.1 Définition

Le TS est un **état**.
Le TSI est une **dynamique**.

**Fichier :** `aiss/tsi_engine.py` — ✅ implémenté v1.5.0, 7/7 tests

### 3.2 Baseline dynamique
```python
class TSIBaseline:
    window_days: int = 30
    scores: List[Tuple[int, float]]  # [(timestamp, score), ...]
```

Stockée dans `~/.piqrypt/tsi/<agent_id>.json`.

### 3.3 Détection de dérive
```python
def detect_drift(current_score, baseline):
    # Condition 1 : z-score > 3σ
    if baseline.std > 0:
        z_score = abs(current_score - baseline.mean) / baseline.std
        if z_score > 3.0:
            return True, f"Z-score={z_score:.2f} > 3σ"
    # Condition 2 : chute rapide sur 24h
    delta_24h = current_score - baseline.score_at_24h_ago()
    if delta_24h < -0.15:
        return True, f"Δ24h={delta_24h:.3f} < -0.15"
    # Condition 3 : variance anormale
    if baseline.std > baseline.dynamic_variance_threshold():
        return True, f"Variance={baseline.std:.4f} > seuil"
    return False, None
```

### 3.4 États TSI
```
STABLE    → Score dans la normale, variance faible
WATCH     → Légère dérive détectée, surveillance renforcée
UNSTABLE  → Dérive significative (Δ24h < -0.15), alerte générée
CRITICAL  → UNSTABLE persistant > 48h, action recommandée
```

**Transitions :**
```
STABLE   ──(Δ24h < -0.08)──→ WATCH
WATCH    ──(Δ24h < -0.15)──→ UNSTABLE
WATCH    ──(z-score > 3σ)──→ UNSTABLE
UNSTABLE ──(persistance > 48h)──→ CRITICAL
*        ──(retour normale)──→ STABLE
```

### 3.5 Sortie TSI
```python
{
    "agent_id": "pq_abc123...",
    "tsi_state": "WATCH",
    "tsi": "WATCH",           # alias court
    "current_score": 0.81,
    "baseline_mean": 0.89,
    "baseline_std": 0.03,
    "delta_24h": -0.08,
    "delta_7d": -0.12,
    "z_score": 2.67,
    "computed_at": 1740902400,
    "window_days": 30,
    "drift_reasons": ["Δ24h proche seuil", "V_t en baisse"]
}
```

---

## 4. A2C Detection Layer ✅

**Fichier :** `aiss/a2c_detector.py`  
**Statut :** ✅ Implémenté v1.5.0 — 16 scénarios — 16/16 tests

### 4.1 Principe

Le A2C Detector analyse uniquement :
- Métadonnées d'interactions
- Identifiants agents (jamais les clés privées)
- Timestamps et fréquences
- Patterns relationnels

Il ne regarde **jamais le contenu** des messages.

### 4.2 Les 16 scénarios d'anomalies relationnelles

Organisés en 4 catégories :

**Concentration & Isolation**
1. Concentration soudaine (top_partner_ratio > 0.8)
2. Chute d'entropie (D_t < baseline - 2σ)
3. Isolation progressive (réduction du réseau de pairs)
4. Cluster fermé (groupe d'agents en boucle fermée)

**Fréquence & Timing**
5. Synchronisation anormale (patterns périodiques stricts)
6. Silence prolongé (absence > seuil adaptatif)
7. Burst soudain (pic de fréquence non justifié)
8. Inversion jour/nuit (activité hors baseline temporelle)

**Identité & Rotation**
9. Rotation suspecte (rotation < 7j après précédente)
10. Reset brutal (rotation sans attestation)
11. Usurpation de contexte (agent_id instable)
12. Chaîne brisée post-rotation

**Relations & Réseau**
13. Nouveau pair dominant (inconnu + ratio élevé immédiat)
14. Disparition de pairs historiques
15. Ratio non-vérifiés croissant
16. Corrélation cross-agents suspecte

### 4.3 Score A2C Risk
```python
a2c_risk = weighted_sum(
    concentration_score,
    entropy_drop_score,
    frequency_variance_score,
    identity_stability_score
)
# Normalisé [0, 1]
# Severity: NONE | LOW | MEDIUM | HIGH | CRITICAL
```

---

## 5. Anomaly Monitor & VRS ✅

**Fichier :** `aiss/anomaly_monitor.py`  
**Statut :** ✅ Implémenté v1.5.0 — 7/7 tests

### 5.1 Vigil Risk Score (VRS)

Le VRS est le score composite agrégeant toutes les dimensions :
```
VRS = w1·(1 - TrustScore) + w2·TSI_weight + w3·A2C_risk + w4·chain_issues

États :
  SAFE     → VRS < 0.25
  WATCH    → 0.25 ≤ VRS < 0.50
  ALERT    → 0.50 ≤ VRS < 0.75
  CRITICAL → VRS ≥ 0.75
```

### 5.2 Format d'événement d'anomalie
```python
{
    "type": "trust_drift",         # trust_drift | entropy_drop |
                                   # concentration_risk | identity_drift |
                                   # fork_spike
    "severity": "MEDIUM",          # LOW | MEDIUM | HIGH | CRITICAL
    "agent_id": "pq_abc123...",
    "metrics_impacted": ["V_t", "D_t"],
    "delta": -0.12,
    "baseline_reference": 0.89,
    "current_value": 0.77,
    "timestamp": 1740902400,
    "drift_reasons": ["V_t en baisse depuis 48h"],
    "recommended_action": "Vérifier les interactions récentes"
}
```

**Principe :** Aucune décision automatique. Tous les événements sont loggés, exportables, consultables.

---

## 6. Vigil Server ✅

**Fichier :** `vigil/vigil_server.py`  
**Statut :** ✅ Implémenté v1.5.0 — 7/7 tests
```bash
python -m vigil.vigil_server

# Dashboard → http://127.0.0.1:18421
# API       → http://127.0.0.1:18421/api/summary
# API       → http://127.0.0.1:18421/api/alerts
# API       → http://127.0.0.1:18421/health
```

**Réponse `/api/summary` :**
```json
{
  "agents": 6,
  "global_vrs": 0.240,
  "agents_detail": [
    {"name": "trading_bot_B", "vrs": 0.392, "state": "WATCH"},
    {"name": "sentinel_alpha", "vrs": 0.367, "state": "WATCH"},
    {"name": "mirror_clone",   "vrs": 0.203, "state": "SAFE"}
  ],
  "alerts_count": 14
}
```

---

## 7. Handshake Signal Extension

Lors d'un échange A2A, un agent peut partager son Trust Signal :
```python
{
    "trust_score": 0.87,
    "tsi_state": "WATCH",
    "tsi": "WATCH",
    "delta_24h": -0.06,
    "a2c_risk": "LOW",
    "vrs": 0.18,
    "timestamp": 1740902400,
    "signature": "..."
}
```

**Règles :**
- Signal **informatif uniquement** — jamais bloquant
- L'agent receveur peut recalculer localement sans faire confiance au signal
- Tous les champs sont ✅ disponibles depuis v1.8.4

---

## 8. Contraintes d'implémentation

| Contrainte | Détail |
|-----------|--------|
| ❌ Pas de ML opaque | Uniquement statistiques déterministes |
| ❌ Pas de dépendance externe | Calcul 100% local |
| ✅ Calcul déterministe | Mêmes inputs → mêmes outputs |
| ✅ Complexité faible | O(n) sur les événements |
| ✅ Mémoire maîtrisée | Fenêtre glissante 30j |
| ❌ Pas d'analyse de contenu | Uniquement métadonnées et primitives crypto |
| ✅ Graceful degradation | Modules indépendants, dégradation partielle possible |

---

## 9. Historique d'implémentation

### v1.5.0 — Trust Score + TSI + A2C + Sentinel
```
aiss/trust_score.py      ✅  compute_trust_score(), I, V_t, D_t, F, R
aiss/tsi_engine.py       ✅  TSIBaseline, compute_tsi(), detect_drift()
aiss/a2c_detector.py     ✅  compute_a2c_risk(), 16 scénarios
aiss/anomaly_monitor.py  ✅  AnomalyMonitor, compute_vrs()
vigil/vigil_server.py    ✅  HTTP dashboard, /api/summary, /api/alerts
```

### v1.6.0 — Key Rotation Chain
```
aiss/history.py          ✅  load_full_history(), get_history_summary()
aiss/index.py            ✅  successor_agent_id, session_id, migration
```

### v1.8.4 — Security Hardening & API Stabilization
```
aiss/key_store.py        ✅  scrypt N=2¹⁷ + AES-256-GCM, magic bytes, RAM erasure
aiss/agent_registry.py   ✅  AgentRegistry class, path traversal protection
aiss/tsi_engine.py       ✅  alias "tsi" ajouté dans compute_tsi() output
aiss/identity.py         ✅  base_dir support
aiss/memory.py           ✅  agent_name isolation
aiss/migration.py        ✅  migrate_agent() alias
tests/                   ✅  45 tests sécurité + 14 RFC vectors
```

### v2.0.0 — Planifié
```
Witness network          🔲  Distributed trust
HSM integration          🔲  Level 3 compliance
Blockchain anchoring     🔲  Public ledger
ZK proofs                🔲  Selective disclosure
```

---

## 10. CTO Defensibility Matrix

| Question | Réponse |
|----------|---------|
| **"Attaque Sybil → score gonflé ?"** | `D_t` entropie + fenêtre temporelle limite l'impact. Détectable via A2C scénario #4. |
| **"Clé compromise → manipulation ?"** | `I` mesure la *continuité*, pas la *sécurité*. Défenses complémentaires : HSM, révocation. scrypt N=2¹⁷ rend le brute-force de la passphrase économiquement infaisable. |
| **"Pourquoi pas PageRank ?"** | Simplicité, auditabilité, performance. Graphes complexes = opaque, difficile à débugger. |
| **"Bootstrap d'un nouvel agent ?"** | `I` = 1.0 dès que la chaîne est valide. `V_t`, `D_t`, `F` croissent graduellement. |
| **"Score bas = opérations bloquées ?"** | **Jamais.** Score = indicateur uniquement. Les opérateurs fixent les seuils. |
| **"Post-quantum = garantie de confiance ?"** | **Non.** PQC = résilience cryptographique. Trust = continuité observable. Concepts orthogonaux. |
| **"Faux positifs ?"** | Attendus pour nouveaux agents, déploiements isolés. Seuils ajustables. |
| **"Sentinel prend des décisions ?"** | **Jamais.** Sentinel alerte. L'humain décide. Toujours. |
| **"RAM disclosure ?"** | `_secure_erase()` — clé privée mise à zéro en mémoire après usage. Testé dans `test_security_keystore.py`. |

---

## 11. Limitations & Future Work

### Ce que le système ne fait PAS

- ❌ Garantir la **sécurité** de l'agent (uniquement la continuité)
- ❌ Détecter les **attaques sémantiques** (model poisoning, prompt injection)
- ❌ Vérifier l'**intégrité du code** (code signing = couche séparée)
- ❌ Prouver la **sécurité matérielle** (TPM, TEE = couche séparée)
- ❌ Remplacer le **jugement humain**

### Directions de recherche (v2.0+)

- Poids adaptatifs par vertical (finance, santé, industrie)
- Zero-knowledge proofs pour divulgation sélective
- Scoring fédéré (privacy-preserving)
- Intégration SIEM (Splunk, ELK, Datadog)
- Standardisation (NIST, ISO working groups)

---

## 12. Références

- **RFC 8032** — EdDSA
- **RFC 8785** — JSON Canonicalization Scheme
- **RFC 3161** — Time-Stamp Protocol
- **NIST FIPS 204** — ML-DSA (Dilithium3)
- **NIST FIPS 197** — AES-256-GCM
- **scrypt** — Colin Percival, 2009
- **AISS v1.1** — Agent Identity and Signature Standard (PiQrypt)
- **SOC2** — AICPA Trust Service Criteria
- **GDPR Article 22** — Automated Decision-Making
- **OWASP LLM Top 10** — 2023

---

## Appendix A — Formula Reference Card
```python
# Trust Score global
TS = 0.30×I + 0.25×V_t + 0.15×D_t + 0.15×F + 0.15×R

# I — Integrity
I = 0.30×hash_chain + 0.25×no_forks + 0.25×signatures + 0.20×rotation_valid

# V_t — Verified Interactions (time-weighted)
w(t) = e^(-λ·age)   avec λ = ln(2) / (30 × 86400)
V_t = Σ(verified × w(t)) / Σ(total × w(t))

# D_t — Diversity (Shannon)
H = -Σ p_i × log2(p_i)
D_t = H / log2(nb_peers_uniques)

# F — Finalization
F = events_with_TSA / events_eligible

# R — Rotation Health
R = mean(score_par_rotation)

# TSI — Drift Detection
z_score = |TS_current - mean| / std   → drift si > 3σ
Δ24h = TS_now - TS_24h_ago            → drift si < -0.15

# VRS — Vigil Risk Score
VRS = w1·(1-TS) + w2·TSI_weight + w3·A2C_risk + w4·chain_issues
```

---

## Appendix B — CLI Output Examples
```bash
# Trust Score instantané
$ piqrypt trust-score compute pq_abc123...
Trust Score : 0.87  [A+]
  I  (Integrity)           : 1.00  ✅
  V_t (Verified, weighted) : 0.82  ✅
  D_t (Diversity)          : 0.71  ⚠️
  F   (Finalization)       : 0.95  ✅
  R   (Rotation Health)    : 0.90  ✅
  A2C Risk                 : 0.08  LOW ✅

# Historique 30 jours
$ piqrypt trust-score history --days 30
Date         TS     I     V_t   D_t   F     R     TSI       A2C
2026-01-27   0.91  1.00  0.88  0.82  0.96  1.00  STABLE    LOW
2026-02-03   0.89  1.00  0.85  0.78  0.95  0.90  STABLE    LOW
2026-02-10   0.87  1.00  0.82  0.71  0.95  0.90  WATCH     LOW
2026-02-17   0.85  0.98  0.80  0.68  0.94  0.90  WATCH     MEDIUM

# Sentinel status (v1.8.4)
$ piqrypt sentinel status pq_abc123...
Sentinel Status : pq_abc123...
  Trust Score  : 0.87  [A+]
  TSI State    : WATCH
  Δ 24h        : -0.04
  Δ 7j         : -0.06
  Z-score      : 1.8
  A2C Risk     : LOW (0.08)
  VRS          : 0.18  SAFE
  Alertes      : 0 actives
```

---

*Trust Scoring & Sentinel v2.1 — PiQrypt Technical Specification*  
*© 2026 PiQrypt Inc. — MIT License*

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
