# PiQrypt TrustGate — Guide de configuration des politiques

> Applicable aux tiers **Business** et **Enterprise** uniquement.
> TrustGate en mode automatique prend des décisions sans intervention humaine
> selon les règles définies dans `policy.yaml`.

---

## Emplacement du fichier

```
~/.piqrypt/trustgate/policy.yaml
```

TrustGate recharge la policy au démarrage. Pour appliquer une modification :
relancer le stack ou appeler `POST /api/policy` avec le nouveau contenu.

---

## Modes de fonctionnement

### Mode automatique (Business / Enterprise — défaut)
```powershell
.\start_business.ps1
```
TrustGate applique les règles et prend les décisions seul.
Toutes les décisions sont auditées dans `~/.piqrypt/trustgate/journal/`.

### Mode manuel (optionnel)
```powershell
.\start_business.ps1 -Manual
```
TrustGate met les décisions en file d'attente — un humain valide via le dashboard.
Utile pour la phase de calibration ou les environnements réglementés stricts.

---

## Structure complète de policy.yaml

```yaml
# ── Métadonnées ────────────────────────────────────────────────
version: "1.0"
name: "ma-politique"
profile: "custom"          # anssi_strict | nist_balanced | ai_act_high_risk | custom
author: "equipe-securite"

# ── Seuils VRS et TSI ─────────────────────────────────────────
thresholds:
  vrs_require_human: 0.60  # VRS >= ce seuil -> REQUIRE_HUMAN
  vrs_block:         0.85  # VRS >= ce seuil -> BLOCK  (doit etre > vrs_require_human)
  tsi_unstable_action: REQUIRE_HUMAN   # ALLOW | REQUIRE_HUMAN | BLOCK | RESTRICTED
  tsi_critical_action: BLOCK           # ALLOW | REQUIRE_HUMAN | BLOCK | RESTRICTED

# ── Roles et permissions ──────────────────────────────────────
roles:
  operator:
    allowed_tools: ["*"]           # tous les outils autorises
    blocked_tools: []
  analyst:
    allowed_tools: ["read", "report", "export"]
    blocked_tools: ["*"]           # tout bloque sauf la liste allowed
  restricted:
    allowed_tools: []
    blocked_tools: ["*"]           # aucun outil autorise

# ── Escalade progressive ──────────────────────────────────────
escalation:
  max_watch_events:          3     # alertes WATCH avant restriction
  auto_restrict_after:       5     # incidents avant restriction automatique
  restrict_duration_minutes: 60    # duree de restriction en minutes

# ── Reseau (Zero Trust) ───────────────────────────────────────
network:
  block_external:      true        # bloquer les domaines non listes
  log_external_calls:  true        # logger tous les appels externes
  allowed_domains:                 # domaines autorises
    - "api.anthropic.com"
    - "api.openai.com"
    - "api.github.com"

# ── Patterns dangereux ────────────────────────────────────────
dangerous_patterns:
  - "rm -rf"
  - "DROP TABLE"
  - "exec\\("
  - "eval\\("

# ── Notifications ─────────────────────────────────────────────
notification:
  timeout_seconds:       300       # delai avant action automatique
  on_timeout:            REJECT    # REJECT | BLOCK | ESCALATE
  require_justification: false     # exiger une justification de l'humain
  principals:
    - "admin@monentreprise.com"
```

---

## Logique de décision — ordre de priorité

TrustGate est **déterministe** : même entrée → même sortie, toujours.

| Priorité | Condition | Décision | Référence |
|---|---|---|---|
| 1 | VRS >= `vrs_block` | **BLOCK** | ANSSI R9, NIST MANAGE 1.3 |
| 2 | Pattern dangereux détecté | **BLOCK** | ANSSI R25, NIST MAP 5.1 |
| 3 | Action interdite pour ce rôle | **BLOCK** | ANSSI R26/R30 |
| 4 | TSI = CRITICAL | **BLOCK** *(configurable)* | NIST MEASURE 2.5, AI Act Art.9 |
| 5 | Domaine réseau non autorisé | **BLOCK** | ANSSI R28 Zero Trust |
| 6 | VRS >= `vrs_require_human` | **REQUIRE_HUMAN** | ANSSI R9, AI Act Art.14 |
| 7 | TSI = UNSTABLE | **REQUIRE_HUMAN** *(configurable)* | NIST MEASURE 2.5 |
| 8 | Seuil d'escalade atteint | **RESTRICTED** | ANSSI R27 |
| 9 | TSI = WATCH | **ALLOW_WITH_LOG** | — |
| 10 | Aucune règle déclenchée | **ALLOW** | — |

---

## Comprendre le VRS (Verifiable Risk Score)

Le VRS est calculé par Vigil pour chaque agent. Il combine :
- **Trust Score (TS)** — cohérence des événements signés
- **TSI** — dérive temporelle du score (Stable / Unstable / Critical)
- **A2C** — anomalies de concentration et synchronisation inter-agents
- **Hash chain** — intégrité de la chaîne d'événements

**Valeurs indicatives :**

| VRS | Etat | Signification |
|---|---|---|
| 0.85 – 1.00 | SAFE | Agent fiable, comportement normal |
| 0.60 – 0.85 | WATCH | Dérive légère, surveillance renforcée |
| 0.30 – 0.60 | ALERT | Anomalie significative, intervention conseillée |
| 0.00 – 0.30 | CRITICAL | Comportement anormal grave |

---

## Profils prédéfinis

### Recommandé pour commencer — `nist_balanced`
```yaml
profile: nist_balanced
thresholds:
  vrs_require_human: 0.60
  vrs_block:         0.85
  tsi_unstable_action: REQUIRE_HUMAN
  tsi_critical_action: BLOCK
```
Équilibre entre sécurité et fluidité opérationnelle.

---

### Finance / Trading — `ai_act_high_risk`
```yaml
profile: ai_act_high_risk
thresholds:
  vrs_require_human: 0.50   # seuil plus bas = plus de controle humain
  vrs_block:         0.75
  tsi_unstable_action: REQUIRE_HUMAN
  tsi_critical_action: BLOCK
escalation:
  max_watch_events:          2
  auto_restrict_after:       3
  restrict_duration_minutes: 120
notification:
  timeout_seconds:       180
  on_timeout:            BLOCK    # timeout = blocage automatique
  require_justification: true
```

---

### DevOps / Infra — permissif avec audit
```yaml
profile: custom
thresholds:
  vrs_require_human: 0.75   # seuil plus haut = moins d'interruptions
  vrs_block:         0.90
  tsi_unstable_action: ALLOW_WITH_LOG
  tsi_critical_action: REQUIRE_HUMAN
network:
  block_external: false       # agents peuvent appeler l'exterieur
  log_external_calls: true    # mais tout est logue
```

---

### Strict — `anssi_strict`
```yaml
profile: anssi_strict
thresholds:
  vrs_require_human: 0.40
  vrs_block:         0.70
  tsi_unstable_action: BLOCK
  tsi_critical_action: BLOCK
network:
  block_external: true
  allowed_domains: []          # aucun domaine externe autorise
escalation:
  max_watch_events:          1
  auto_restrict_after:       2
  restrict_duration_minutes: 480
```

---

## Démarrage sans policy.yaml

Si `~/.piqrypt/trustgate/policy.yaml` est absent, TrustGate démarre avec
les valeurs par défaut (`nist_balanced`) et log un avertissement.

Pour créer la policy par défaut :
```powershell
python -c "
from trustgate.policy_loader import Policy
import yaml, pathlib
p = pathlib.Path.home() / '.piqrypt' / 'trustgate'
p.mkdir(parents=True, exist_ok=True)
print('Policy par defaut OK -- editez', p / 'policy.yaml')
"
```

---

## Vérifier la policy active

```powershell
# Via l'API TrustGate
Invoke-RestMethod -Uri "http://localhost:8422/api/policy" `
    -Headers @{ Authorization = "Bearer $TOKEN" }
```

---

## Bonnes pratiques

- Commencer avec `nist_balanced` et ajuster selon les alertes observées
- Ne jamais mettre `vrs_require_human >= vrs_block` (erreur de validation)
- Tester les changements en mode `-Manual` avant de repasser en automatique
- Garder `log_external_calls: true` en production
- Versionner `policy.yaml` dans votre repo (sans les tokens)

---

*PiQrypt TrustGate — Deterministic governance for autonomous agents.*
*AI Act Art.9/14 · ANSSI R9/R25/R26/R27/R28 · NIST AI RMF*
