# TSI — Trust Stability Index

**Module :** `aiss/tsi_engine.py`  
**Version :** PiQrypt v1.8.1  
**Dépendances :** `aiss.trust_score`, `aiss.agent_registry`

---

## 1. Objectif

Un Trust Score élevé à un instant *t* ne garantit pas la fiabilité d'un agent sur la durée. Un agent peut présenter un score de confiance fort mais instable — oscillant, en dérive progressive, ou soudainement volatil. Ces patterns sont des signaux de risque distincts du score ponctuel.

Le TSI (Trust Stability Index) quantifie la **stabilité temporelle** du Trust Score. Il répond à une question distincte du Trust Score :

> "Cet agent est-il fiable maintenant ?" → **Trust Score**  
> "Cet agent est-il stable dans le temps ?" → **TSI**

---

## 2. Modèle statistique

### 2.1 Fenêtre d'observation

Le TSI est calculé sur une **fenêtre glissante de 30 jours**. Chaque point est un Trust Score horodaté, stocké dans l'historique TSI de l'agent (`~/.piqrypt/agents/<nom>/tsi/`). La résolution minimale est 1 point par appel à `compute_tsi()`.

Les snapshots antérieurs à 30 jours sont purgés automatiquement à chaque calcul.

### 2.2 Quatre indicateurs

#### Z-score de dérive

Mesure la distance statistique (en écarts-types) entre le score actuel et la distribution historique sur 30 jours. Un z-score élevé indique que le score actuel est anormalement éloigné de la baseline — signal de dérive même si la valeur absolue reste acceptable.

#### Variation 24h (Δ24h)

Dérivée temporelle du Trust Score sur les 24 dernières heures. Détecte les chutes ou remontées abruptes indépendamment de la position absolue du score.

#### Volatilité (σ7j)

Écart-type glissant sur 7 jours. Mesure le bruit intrinsèque du comportement de l'agent, indépendamment de la tendance. Une volatilité élevée même autour d'un score moyen acceptable est un signal à surveiller.

#### Tendance (régression linéaire 30j)

Pente de la droite de régression sur 30 jours, exprimée en points par jour. Une tendance négative persistante même à partir d'un score élevé est un prédicteur de dégradation future.

### 2.3 États TSI

Les quatre indicateurs sont combinés par une règle de priorité décroissante. Une condition suffisante sur l'un des indicateurs prime sur les autres.

| État | Interprétation | Déclencheur Vigil |
|---|---|---|
| `STABLE` | Comportement nominal | — |
| `WATCH` | Signal faible détecté | Log INFO |
| `UNSTABLE` | Dérive significative | Alerte WATCH |
| `CRITICAL` | Dérive critique | Alerte CRITICAL |

### 2.4 Intégration dans le VRS

Le TSI est l'une des 4 composantes du Vigil Risk Score (VRS) :

```
VRS = 0.35 × (1 - Trust Score)
    + 0.30 × TSI_weight          ← TSI
    + 0.20 × A2C_risk
    + 0.15 × chain_risk
```

Le poids de **0.30** fait du TSI la deuxième composante la plus importante après le Trust Score (0.35), reflétant que la stabilité temporelle est un prédicteur de risque aussi important que le niveau absolu de confiance.

---

## 3. Implémentation

### 3.1 API principale

```python
from aiss.tsi_engine import (
    compute_tsi,
    get_tsi_history,
    get_tsi_summary,
    reset_tsi_baseline,
    TSI_STATES,
)

# Calcul TSI
result = compute_tsi(agent_id, current_score=0.87)
print(result["tsi_state"])   # "STABLE" | "WATCH" | "UNSTABLE" | "CRITICAL"
print(result["metrics"])     # z_score, delta_24h, delta_7d, ...

# Historique
history = get_tsi_history(agent_id)
# → [{"timestamp": ..., "score": ..., "tsi_state": ...}, ...]

# Résumé
summary = get_tsi_summary(agent_id)
# → {"current_state": ..., "snapshots_count": ..., "window_days": 30, ...}

# Réinitialiser la baseline (après refonte comportementale volontaire)
reset_tsi_baseline(agent_id)
```

### 3.2 États disponibles

```python
from aiss.tsi_engine import TSI_STATES

print(TSI_STATES)  # ("STABLE", "WATCH", "UNSTABLE", "CRITICAL")
```

### 3.3 Mode persist

Par défaut, chaque appel à `compute_tsi()` persiste le snapshot dans `~/.piqrypt/agents/<nom>/tsi/`. Pour un calcul one-shot sans persistance :

```python
result = compute_tsi(agent_id, current_score=0.87, persist=False)
```

### 3.4 Hook temps réel dans Vigil

Le hook TSI s'active automatiquement au démarrage de `vigil_server.py` via `activate_tsi_hook()`. Il reçoit les événements de finalisation AISS, recalcule le TSI à chaque mise à jour du Trust Score, et déclenche une alerte Vigil si l'état change.

```python
# Dans vigil_server.py — activé automatiquement
from aiss.anomaly_monitor import activate_tsi_hook
activate_tsi_hook()
```

---

## 4. Risk Narrative — TSI dans Vigil

Lorsque le TSI d'un agent passe en `WATCH`, `UNSTABLE` ou `CRITICAL`, Vigil génère automatiquement un Risk Narrative explicatif visible dans le dashboard Overview et dans le drill-down de l'agent.

**Exemple — agent en UNSTABLE :**
```
⚠ WHY IS VRS 0.62?

TSI UNSTABLE — Drift detected (HIGH)
  z-score: 2.4σ above 30d baseline
  Δ24h: -0.08 (sharp drop)
  Volatility σ7j: 0.12 (elevated)

Trust Score: 0.71 (MEDIUM)
A2C: 0.18 (LOW)
Chain: intact
```

---

## 5. Utilisation dans un agent autonome

```python
from aiss.identity import generate_keypair, derive_agent_id
from aiss.stamp import stamp_genesis_event, stamp_event
from aiss.chain import compute_event_hash
from aiss.memory import store_event_free
from aiss.trust_score import compute_trust_score
from aiss.tsi_engine import compute_tsi

priv, pub = generate_keypair()
agent_id = derive_agent_id(pub)

# Après chaque cycle d'activité
events = load_events_free(agent_name="mon_agent")
ts_result = compute_trust_score(agent_id, events=events)
trust_score = ts_result["trust_score"]

# Calcul TSI (persiste automatiquement le snapshot)
tsi_result = compute_tsi(agent_id, current_score=trust_score)
state = tsi_result["tsi_state"]

if state in ("UNSTABLE", "CRITICAL"):
    # Alerte ou action corrective
    print(f"⚠ TSI {state} — métriques : {tsi_result['metrics']}")
```

---

## 6. Limites & perspectives

### 6.1 Limites actuelles

- **Minimum 7 jours de données** pour un calcul fiable du z-score. En dessous, le TSI est retourné en mode dégradé (`STABLE` avec indicateurs partiels).
- La **fenêtre fixe de 30 jours** peut manquer des dérives très lentes (> 30 jours).
- Pas de saisonnalité modélisée : un agent avec un comportement légitime cyclique (weekend inactif, pic mensuel) peut générer des faux positifs sur la volatilité.

### 6.2 Perspectives v1.8

- Modèle ARIMA pour la **prédiction de dérive** — alerte préventive avant l'état UNSTABLE
- **Fenêtre adaptative** selon la maturité de l'agent (plus courte en phase d'apprentissage initial)
- **Corrélation TSI cross-agents** pour la détection de dérives systémiques coordonnées

---

*PiQrypt v1.8.1 — MIT License*

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
