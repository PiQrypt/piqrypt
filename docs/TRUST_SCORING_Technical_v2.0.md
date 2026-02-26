# Trust Scoring & Sentinel — Technical Specification

**Version:** 2.0  
**Date:** 2026-02-26  
**Standard:** AISS v1.1 (Agent Identity and Signature Standard)  
**Status:** v1.6.0 — Trust Score + TSI | v1.7.0+ — A2C + Sentinel

---

## Abstract

Le Trust Scoring dans PiQrypt n'est pas un score moral.

Il est un **indicateur structurel de cohérence, stabilité et continuité cryptographique** d'un agent autonome.

**Sentinel** (v1.7.0+) est un moteur local de détection de dérive comportementale et structurelle.

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
4.  A2C Detection Layer — Dérive relationnelle  [v1.7.0]
5.  Anomaly Monitor                              [v1.7.0]
6.  Handshake Signal Extension
7.  Contraintes d'implémentation
8.  Roadmap d'implémentation
9.  CTO Defensibility Matrix
10. Limitations & Future Work
11. Références
```

---

## 1. Architecture cible

```
Agent
 ├── PiQrypt Core
 │    ├── aiss/
 │    │    ├── trust_score.py      ← TS computation (v1.6.0)
 │    │    ├── tsi_engine.py       ← TSI dynamics    (v1.6.0)
 │    │    ├── a2c_detector.py     ← Relational drift [v1.7.0]
 │    │    └── anomaly_monitor.py  ← Event hub        [v1.7.0]
 │    ├── history.py               ← Rotation chain (v1.6.0)
 │    ├── index.py                 ← SQLite index   (v1.6.0)
 │    └── memory.py
 │
 └── Sentinel                      [v1.7.0]
      └── (orchestrates a2c_detector + anomaly_monitor)
```

**Principe de séparation des responsabilités :**

```
PiQrypt Core   → prouve la continuité cryptographique
Trust Score    → mesure la cohérence structurelle (état)
TSI            → mesure la stabilité du score (dynamique)
A2C Detector   → mesure la dérive relationnelle [v1.7.0]
Anomaly Monitor → centralise les alertes         [v1.7.0]
Sentinel       → orchestre, alerte               [v1.7.0]
L'humain       → décide
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

Les poids sont **configurables par déploiement** (finance peut augmenter F, recherche peut augmenter D_t).

---

### 2.2 I — Integrity Score

**Définition :** Continuité cryptographique de la chaîne d'événements.

**Composantes :**

```python
I = (
    hash_chain_valid    × 0.30 +
    no_unresolved_forks × 0.25 +
    signatures_valid    × 0.25 +
    key_rotation_valid  × 0.20
)
```

**Détail de chaque sous-composante :**

```python
# 1. Hash chain valid (0.30)
def compute_hash_chain_score(events):
    """Vérifie la continuité des previous_hash."""
    from aiss.chain import verify_chain_linkage
    return 1.0 if verify_chain_linkage(events) else 0.0

# 2. No unresolved forks (0.25)
def compute_fork_score(events):
    """Détecte les forks non résolus."""
    from aiss.fork import find_forks
    forks = find_forks(events)
    unresolved = [f for f in forks if not getattr(f, 'resolved', False)]
    return max(0.0, 1.0 - len(unresolved) / 5)  # 5+ forks → 0

# 3. Signatures valid (0.25)
def compute_signature_score(events):
    """Ratio d'événements avec signature valide."""
    if not events:
        return 1.0
    signed = sum(1 for e in events if e.get("signature"))
    return signed / len(events)

# 4. Key rotation valid (0.20)
# S'appuie sur history.py v1.6.0
def compute_rotation_score(events):
    """Rotations correctement enchaînées via attestation."""
    rotations = [e for e in events
                 if e.get("payload", {}).get("event_type") == "key_rotation"]
    if not rotations:
        return 1.0
    valid = sum(1 for r in rotations
                if r.get("payload", {}).get("rotation_attestation"))
    return valid / len(rotations)
```

**Tiers Integrity :**

| Score I | Signification |
|---------|--------------|
| 1.00 | Continuité cryptographique parfaite |
| 0.80–0.99 | Issues mineures (fork résolu, attestation ancienne) |
| 0.50–0.79 | Concerns modérés (forks multiples, rotation incomplète) |
| < 0.50 | Compromis sévère (rupture de chaîne, clé révoquée) |

> ⚠️ **Limitation importante :** `I` mesure la *continuité*, pas la *sécurité*. Une clé privée volée utilisée pour signer des événements valides donne I = 1.0. Défenses complémentaires requises : HSM, révocation, attestation matérielle.

---

### 2.3 V_t — Verified Interaction Ratio (time-weighted)

**Définition :** Proportion d'interactions avec des pairs cryptographiquement vérifiés, **pondérée temporellement**.

**Pondération temporelle — décroissance exponentielle :**

```python
def temporal_weight(event_timestamp, current_time):
    """
    Demi-vie 30 jours.
    w(t) = e^(-λ·age)  avec λ = ln(2)/30
    """
    import math
    LAMBDA = math.log(2) / (30 * 86400)  # 30 jours
    age = current_time - event_timestamp
    return math.exp(-LAMBDA * age)
```

**Propriétés :**

```
Événement d'aujourd'hui : w ≈ 1.0
Événement à 30 jours    : w = 0.50
Événement à 60 jours    : w = 0.25
Événement à 90 jours    : w = 0.125
```

**Formule V_t :**

```python
def compute_V_t(interactions, current_time):
    numerator = 0.0
    denominator = 0.0
    for interaction in interactions:
        w = temporal_weight(interaction["timestamp"], current_time)
        denominator += w
        if interaction.get("peer_verified"):  # Handshake A2A complété
            numerator += w
    return numerator / denominator if denominator > 0 else 0.0
```

**Propriétés importantes :**

- **Non-discriminatoire :** les interactions avec des agents non-PiQrypt réduisent le ratio mais ne sont pas pénalisées
- **Anti-gaming :** les anciennes vérifications en masse ont un impact décroissant
- **Bootstrap graduel :** un nouvel agent part de V_t ≈ 0 et croît naturellement avec le réseau

---

### 2.4 D_t — Diversity Factor (Shannon Entropy)

**Définition :** Entropie de la distribution des partenaires d'interaction, mesure la résistance aux clusters et attaques Sybil.

**Formule :**

```python
def compute_D_t(interactions, current_time, window=30*86400):
    from math import log2
    from collections import Counter

    recent = [i for i in interactions
              if current_time - i["timestamp"] < window]

    if not recent:
        return 1.0  # Pas d'interactions récentes = pas de risque cluster

    peer_counts = Counter(i["peer_id"] for i in recent)
    total = len(recent)

    # Entropie de Shannon
    entropy = -sum(
        (count / total) * log2(count / total)
        for count in peer_counts.values()
    )

    # Normalisation [0, 1]
    max_entropy = log2(len(peer_counts)) if len(peer_counts) > 1 else 1.0
    return entropy / max_entropy if max_entropy > 0 else 0.0
```

**Interprétation :**

| D_t | Pattern |
|-----|---------|
| 0.9–1.0 | Haute diversité (nombreux pairs uniques) |
| 0.5–0.8 | Clustering modéré (quelques pairs répétés) |
| < 0.5 | Cluster fermé (peu de pairs uniques, forte répétition) |

> **Note :** Un D_t bas n'est pas nécessairement malveillant — un agent spécialisé ou en phase de bootstrap aura naturellement un D_t faible. C'est un **signal**, jamais un verdict.

> **Hook Sentinel :** Un D_t qui chute brutalement sous la baseline sera capturé par le A2C Detector (v1.7.0).

---

### 2.5 F — Finalization Reliability

**Définition :** Taux d'événements finalisés avec preuve cryptographique externe (TSA / ancrage RFC 3161).

```python
def compute_F(events):
    """
    F = événements avec token TSA / événements éligibles
    """
    if not events:
        return 1.0

    eligible = [e for e in events
                if e.get("payload", {}).get("event_type") not in
                ("key_rotation", "genesis")]

    if not eligible:
        return 1.0

    finalized = sum(
        1 for e in eligible
        if e.get("tsa_token") or
           e.get("payload", {}).get("tsa_token") or
           e.get("rfc3161_token")
    )

    return finalized / len(eligible)
```

**Interprétation :**

| F | Signification |
|---|--------------|
| > 0.95 | Très fiable (conforme au protocole) |
| 0.80–0.95 | Fiable avec délais occasionnels |
| 0.50–0.80 | Issues opérationnelles (à investiguer) |
| < 0.50 | Non-fiabilité sévère |

---

### 2.6 R — Rotation Health

**Définition :** Cohérence et santé des rotations de clés.

**S'appuie sur `history.py` v1.6.0** — la chaîne d'identités est disponible.

```python
def compute_R(events, agent_id, current_time):
    """
    Évalue la santé des rotations de clés.

    Seuils recommandés (configurables) :
    - Rotation < 7 jours après la précédente  → suspecte
    - Rotation > 365 jours sans rotation      → overdue (si rotation attendue)
    - Reset brutal (sans attestation)          → pénalité forte
    """
    rotations = sorted(
        [e for e in events
         if e.get("payload", {}).get("event_type") == "key_rotation"],
        key=lambda e: e.get("timestamp", 0)
    )

    if not rotations:
        return 1.0  # Aucune rotation = pas de risque rotation

    scores = []
    prev_ts = None

    for rotation in rotations:
        ts = rotation.get("timestamp", 0)
        payload = rotation.get("payload", {})
        score = 1.0

        # Pénalité : rotation sans attestation (reset brutal)
        if not payload.get("rotation_attestation"):
            score -= 0.60

        # Pénalité : rotation trop rapide (< 7 jours)
        if prev_ts and (ts - prev_ts) < 7 * 86400:
            score -= 0.30

        scores.append(max(0.0, score))
        prev_ts = ts

    return sum(scores) / len(scores) if scores else 1.0
```

> **Intégration v1.6.0 :** `compute_R()` bénéficie directement de `load_full_history()` et `get_history_summary()` pour accéder à la chaîne complète de rotations.

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

Il mesure :

- Δ court terme (24h)
- Δ moyen terme (7j)
- Variance sur fenêtre glissante
- Z-score par rapport à la baseline de l'agent

**Fichier :** `aiss/tsi_engine.py`

---

### 3.2 Baseline dynamique

Chaque agent maintient une baseline glissante stockée dans l'index mémoire :

```python
class TSIBaseline:
    """
    Fenêtre glissante 30 jours des Trust Scores historiques.
    Stockée dans ~/.piqrypt/tsi_baseline.json
    """
    window_days: int = 30
    scores: List[Tuple[int, float]]  # [(timestamp, score), ...]

    @property
    def mean(self) -> float:
        return statistics.mean(s for _, s in self.scores)

    @property
    def std(self) -> float:
        return statistics.stdev(s for _, s in self.scores) if len(self.scores) > 1 else 0.0
```

---

### 3.3 Détection de dérive

**Trois conditions de déclenchement :**

```python
def detect_drift(current_score, baseline):
    """
    Retourne True si une dérive est détectée.
    """
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

---

### 3.4 États TSI

```
STABLE    → Score dans la normale, variance faible
WATCH     → Légère dérive détectée, surveillance renforcée
UNSTABLE  → Dérive significative, alerte générée
CRITICAL  → Dérive sévère ou chute brutale, action recommandée
```

**Transitions :**

```
STABLE ──(Δ24h < -0.08)──→ WATCH
WATCH  ──(Δ24h < -0.15)──→ UNSTABLE
WATCH  ──(z-score > 3σ)──→ UNSTABLE
UNSTABLE ─(persistance)──→ CRITICAL
* ────(retour normale)────→ STABLE
```

---

### 3.5 Sortie TSI

```python
{
    "agent_id": "pq_abc123...",
    "tsi_state": "WATCH",           # STABLE | WATCH | UNSTABLE | CRITICAL
    "current_score": 0.81,
    "baseline_mean": 0.89,
    "baseline_std": 0.03,
    "delta_24h": -0.08,
    "delta_7d": -0.12,
    "z_score": 2.67,
    "computed_at": 1700000000,
    "window_days": 30,
    "drift_reasons": ["Δ24h proche seuil", "V_t en baisse"]
}
```

> **Hook Sentinel (v1.7.0) :** Quand `tsi_state` passe à `UNSTABLE` ou `CRITICAL`, l'`anomaly_monitor` reçoit un événement `trust_drift` avec le détail des métriques impactées. Aucune décision automatique.

---

## 4. A2C Detection Layer [v1.7.0]

> **Statut :** Spécification complète — implémentation reportée à v1.7.0.
> L'architecture de `trust_score.py` et `tsi_engine.py` est conçue pour accueillir ce module sans modification.

### 4.1 Principe

Le A2C Detector ne regarde **jamais le contenu** des messages.

Il analyse uniquement :

- Métadonnées d'interactions
- Identifiants agents (pas les clés)
- Timestamps et fréquences
- Patterns relationnels

### 4.2 Les 4 indicateurs

**1. Concentration soudaine**
```
Si : top_partner_ratio > 0.8
ET  : baseline_historique < 0.4
→ Alerte concentration
```

**2. Chute d'entropie**
```
Si : D_t_current < baseline_mean - 2σ
→ Alerte entropy_drop
```

**3. Synchronisation anormale**
```
Si : pattern d'interactions périodiques strictes apparaît (nouveau)
→ Alerte abnormal_sync
```

**4. Silence prolongé**
```
Si : absence totale d'activité > seuil_adaptatif
→ Alerte prolonged_silence
```

### 4.3 Score A2C Risk

```python
a2c_risk = weighted_sum(
    concentration_score,
    entropy_drop_score,
    variance_score,
    abnormal_frequency_score
)
# Normalisé [0, 1] → LOW | ELEVATED | HIGH
```

### 4.4 Fichier cible

`aiss/a2c_detector.py` — Interface préparée dans `trust_score.py` v1.6.0 :

```python
# Hook prévu dans trust_score.py
def get_a2c_risk(agent_id: str) -> Optional[Dict]:
    """
    v1.6.0 : retourne None (A2C non implémenté)
    v1.7.0 : retourne le score A2C complet
    """
    try:
        from aiss.a2c_detector import compute_a2c_risk
        return compute_a2c_risk(agent_id)
    except ImportError:
        return None  # Graceful degradation
```

---

## 5. Anomaly Monitor [v1.7.0]

> **Statut :** Spécification — implémentation v1.7.0.

Centralise tous les événements d'anomalie en provenance de TS, TSI, A2C.

**Format d'événement standardisé :**

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
    "timestamp": 1700000000,
    "drift_reasons": ["V_t en baisse depuis 48h"],
    "recommended_action": "Vérifier les interactions récentes"
}
```

**Principe :** Aucune décision automatique. Tous les événements sont loggés, exportables, consultables via CLI.

---

## 6. Handshake Signal Extension

Lors d'un échange A2A, un agent peut partager son Trust Signal :

```python
{
    "trust_score": 0.87,
    "tsi_state": "WATCH",
    "delta_24h": -0.06,
    "a2c_risk": "ELEVATED",    # None en v1.6.0, disponible en v1.7.0
    "timestamp": 1700000000,
    "signature": "..."
}
```

**Règles importantes :**

- Ce signal est **informatif uniquement** — jamais bloquant
- L'agent receveur **peut recalculer localement** sans faire confiance au signal
- Le champ `a2c_risk` est `null` en v1.6.0, exploitable en v1.7.0

---

## 7. Contraintes d'implémentation

| Contrainte | Détail |
|-----------|--------|
| ❌ Pas de ML opaque | Uniquement statistiques déterministes |
| ❌ Pas de dépendance externe | Calcul 100% local |
| ✅ Calcul déterministe | Mêmes inputs → mêmes outputs |
| ✅ Complexité faible | O(n) sur les événements |
| ✅ Mémoire maîtrisée | Fenêtre glissante 30j, pas d'accumulation infinie |
| ❌ Pas d'analyse de contenu | Uniquement métadonnées et primitives crypto |
| ✅ Graceful degradation | TSI sans A2C = OK, A2C sans Sentinel = OK |

---

## 8. Roadmap d'implémentation

### v1.6.0 — Trust Score + TSI (maintenant)

```
aiss/trust_score.py
    compute_I()           ← I : hash chain + forks + signatures + rotation
    compute_V_t()         ← V_t : interactions vérifiées, time-weighted
    compute_D_t()         ← D_t : entropie Shannon
    compute_F()           ← F : taux TSA
    compute_R()           ← R : rotation health (s'appuie sur history.py)
    compute_trust_score() ← Score agrégé + tiers
    get_a2c_risk()        ← Hook v1.7.0 (retourne None)

aiss/tsi_engine.py
    TSIBaseline           ← Fenêtre glissante 30j
    compute_tsi()         ← États STABLE/WATCH/UNSTABLE/CRITICAL
    detect_drift()        ← z-score + Δ24h + variance

CLI :
    piqrypt trust-score compute <agent_id>
    piqrypt trust-score history --days 30
    piqrypt trust-score compare AGENT_A AGENT_B
    piqrypt sentinel status <agent_id>   ← affiche TS + TSI (A2C = N/A)
```

### v1.7.0 — A2C + Sentinel (future)

```
aiss/a2c_detector.py
    compute_a2c_risk()    ← 4 indicateurs relationnels

aiss/anomaly_monitor.py
    AnomalyMonitor        ← Hub événements TS + TSI + A2C

Sentinel
    orchestration complète
    export dashboard entreprise
    mode "policy hooks"
```

---

## 9. CTO Defensibility Matrix

| Question | Réponse |
|----------|---------|
| **"Attaque Sybil → score gonflé ?"** | `D_t` entropie + fenêtre temporelle limite l'impact. Cluster coordonné détectable via faible diversité. |
| **"Clé compromise → manipulation ?"** | `I` mesure la *continuité*, pas la *sécurité*. Défenses complémentaires : HSM, révocation, attestation matérielle. |
| **"Pourquoi pas PageRank ?"** | Simplicité, auditabilité, performance. Graphes complexes = opaque, difficile à débugger, coût calcul élevé. |
| **"Bootstrap d'un nouvel agent ?"** | `I` = 1.0 dès que la chaîne est valide. `V_t`, `D_t`, `F` croissent graduellement. Grace period configurable. |
| **"Score bas = opérations bloquées ?"** | **Jamais.** Score = indicateur uniquement. Les opérateurs fixent les seuils (s'ils le souhaitent). |
| **"Post-quantum = garantie de confiance ?"** | **Non.** PQC = résilience cryptographique. Trust = continuité observable. Concepts orthogonaux. |
| **"Faux positifs ?"** | Attendus pour nouveaux agents, déploiements isolés. Seuils ajustables par déploiement. |
| **"Sentinel prend des décisions ?"** | **Jamais.** Sentinel alerte. L'humain décide. Toujours. |

---

## 10. Limitations & Future Work

### Ce que le système ne fait PAS

- ❌ Garantir la **sécurité** de l'agent (uniquement la continuité)
- ❌ Détecter les **attaques sémantiques** (model poisoning, prompt injection)
- ❌ Vérifier l'**intégrité du code** (code signing = couche séparée)
- ❌ Prouver la **sécurité matérielle** (TPM, TEE = couche séparée)
- ❌ Remplacer le **jugement humain**

### Directions de recherche (v2.0+)

- Poids adaptatifs par vertical (finance, santé, industrie)
- Zero-knowledge proofs pour divulgation sélective des composantes
- Scoring fédéré (privacy-preserving)
- Intégration SIEM (Splunk, ELK, Datadog)
- Standardisation (NIST, ISO working groups)

---

## 11. Références

### Standards
- **RFC 8032** — Edwards-Curve Digital Signature Algorithm (EdDSA)
- **RFC 8785** — JSON Canonicalization Scheme (JCS)
- **RFC 3161** — Time-Stamp Protocol (TSP)
- **NIST FIPS 186-5** — Digital Signature Standard

### Industry
- **AISS v1.1** — Agent Identity and Signature Standard (PiQrypt)
- **SOC2 Trust Service Criteria** — AICPA
- **GDPR Article 22** — Automated Decision-Making
- **OWASP Top 10 for LLM Applications** (2023)

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
  score = 1.0 - pénalité_sans_attestation - pénalité_rotation_rapide

# TSI — Drift Detection
z_score = |TS_current - mean| / std   → drift si > 3σ
Δ24h = TS_now - TS_24h_ago            → drift si < -0.15

# Temporal weight
w(age) = e^(-ln(2)/30j × age_jours)
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
  A2C Risk                 : N/A   (disponible v1.7.0)

# Historique 30 jours
$ piqrypt trust-score history --days 30
Date         TS     I     V_t   D_t   F     R     TSI
2026-01-27   0.91  1.00  0.88  0.82  0.96  1.00  STABLE
2026-02-03   0.89  1.00  0.85  0.78  0.95  0.90  STABLE
2026-02-10   0.87  1.00  0.82  0.71  0.95  0.90  WATCH
2026-02-17   0.85  0.98  0.80  0.68  0.94  0.90  WATCH

# Comparaison agents
$ piqrypt trust-score compare AGENT_A AGENT_B
Métrique     Agent A   Agent B   Δ
TS           0.87      0.71      +0.16
I            1.00      0.85      +0.15
V_t          0.82      0.62      +0.20
D_t          0.71      0.55      +0.16
F            0.95      0.88      +0.07
R            0.90      0.70      +0.20
TSI          WATCH     UNSTABLE  —

# Sentinel status (v1.6.0 — A2C non disponible)
$ piqrypt sentinel status pq_abc123...
Sentinel Status : pq_abc123...
  Trust Score  : 0.87  [A+]
  TSI State    : WATCH
  Δ 24h        : -0.04
  Δ 7j         : -0.06
  Z-score      : 1.8
  A2C Risk     : N/A (v1.7.0)
  Alertes      : 0 actives
```

---

*Trust Scoring & Sentinel v2.0 — PiQrypt Technical Specification*
*© 2026 PiQrypt — MIT License*
