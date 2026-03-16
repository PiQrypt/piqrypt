# Vigil — Monitoring Continu

**Module :** `vigil/vigil_server.py`  
**Version :** PiQrypt v1.7.1  
**Port :** 8421 (défaut)  
**Dépendances :** `aiss.anomaly_monitor`, `aiss.a2c_detector`, `aiss.tsi_engine`

---

## 1. Objectif

Vigil est la couche de surveillance continue de PiQrypt. Son rôle est de transformer un flux de preuves cryptographiques (événements AISS signés, Trust Scores, TSI, A2C) en intelligence opérationnelle immédiatement exploitable — pour un CTO, une équipe SOC, ou un responsable compliance.

> "Parmi tous mes agents IA en production, lequel pose un problème maintenant — et pourquoi ?"

---

## 2. Architecture

### 2.1 Stack technique

Vigil est intentionnellement léger :

- **Dashboard** — fichier HTML autonome servi par `vigil_server.py`, zéro dépendance JS externe, zéro CDN requis
- **Serveur** — Python stdlib uniquement (`http.server`), aucune dépendance tierce
- **Backend** — branché en live sur `anomaly_monitor.py`, `a2c_detector.py` et `tsi_engine.py`
- **Mode DEMO** — activé automatiquement si le backend n'est pas disponible (données synthétiques)

### 2.2 Intégration TrustGate

Vigil expose le VRS calculé à TrustGate via `POST /api/vigil/agent-state`. TrustGate utilise le VRS et l'état TSI pour ses décisions de politique — voir `trustgate/policy_engine.py`. Les deux services communiquent en localhost uniquement.

### 2.3 API REST

| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/health` | Santé du serveur |
| GET | `/api/summary` | Résumé installation (tous agents) |
| GET | `/api/alerts` | Journal d'alertes (filtrable) |
| GET | `/api/agent/<n>` | VRS + historique d'un agent |
| GET | `/api/agent/<n>/export/pqz-cert` | Archive .pqz certifiée |
| GET | `/api/agent/<n>/export/pqz-memory` | Archive .pqz mémoire |
| GET | `/api/agent/<n>/export/pdf` | Rapport PDF local |
| POST | `/api/agent/<n>/record` | Injection d'événement (bridges) |

---

## 3. Lancement

```bash
# Depuis piqrypt/
python -m vigil.vigil_server

# Avec options
python -m vigil.vigil_server --port 9000 --host 0.0.0.0

# Vérification
curl http://localhost:8421/health
# → {"status": "ok", "backend": true, "demo_mode": false, ...}
```

Ouvrir le dashboard : **http://127.0.0.1:8421**

---

## 4. Fonctionnalités du dashboard

### 4.1 Overview — Vue CTO

Lecture immédiate de l'état de l'installation en un coup d'œil.

- **Jauge VRS globale** — arc animé avec code couleur SAFE / WATCH / ALERT / CRITICAL
- **Compteurs** — nombre d'agents par état
- **Risk Narrative auto-généré** — "WHY IS VRS X.XX?" avec causes racines classées HIGH / MEDIUM / LOW / OK et chiffres précis
- **Chain Integrity** — badge AISS par agent : ✔ CANONICAL CHAIN / ✖ FORKED IDENTITY / ⚠ ROTATION INCONSISTENT
- **Grille A2C** — état du détecteur de collusion visible directement (non enterré dans le drill-down)
- **Sparklines 30 jours** — tendance VRS de chaque agent
- **Alertes actives** — liste priorisée

### 4.2 Agent Network — Vue étoile

Visualisation Canvas interactive des relations inter-agents.

- Chaque agent est un **nœud coloré** par état de risque (SAFE=vert, WATCH=jaune, ALERT=orange, CRITICAL=rouge)
- Les **arêtes** représentent les corrélations A2C — épaisseur proportionnelle au score de corrélation, pointillées si corrélation > 0.5
- **Clic sur un nœud** → centrage de l'agent, les autres en orbite avec score de corrélation affiché
- **Selector** pour choisir l'agent central
- Cartes récapitulatives par agent sous le graphe

### 4.3 All Agents — Table complète

Table de tous les agents enregistrés avec drill-down par agent :

- Trust Score détaillé (I, V_t, D_t, F)
- A2C Detail (concentration, entropy_drop, synchronization, silence_break)
- Timeline événementielle
- Export

### 4.4 SOC Timeline

Timeline événementielle par agent avec marqueurs de rupture. Événements positionnés sur un axe temporel :

| Marqueur | Événement |
|---|---|
| 🔴 diamant rouge | Fork d'identité détecté |
| 🟠 spike pointillé | Rotation anomaly |
| 🟡 diamant orange | Peer cluster spike (A2C) |
| ● vert | État stable |

### 4.5 Export

Recherche par nom d'agent, type d'export et tier. Trois formats distincts :

| Format | Contenu | Portée légale |
|---|---|---|
| `.pqz CERTIFIED` | Archive signée Ed25519 + horodatage TSA RFC 3161, chaîne de hachage vérifiable | Valeur probante légale (eIDAS Art.26) |
| `.pqz MEMORY` | Historique complet auto-extractible, portable | Audit interne, migration système |
| `PDF REPORT` | Rapport lisible local | Communication interne uniquement — mention "Export local — non certifié PiQrypt" |

### 4.6 Wizard New Agent

Onboarding guidé en 3 étapes :
1. Nom de l'agent + tier (Free / Pro)
2. Choix du bridge parmi les intégrations disponibles
3. Snippet de code auto-généré + commande `pip install` copiable

---

## 5. VRS — Vigil Risk Score

### 5.1 Formule

```
VRS = 0.35 × (1 - Trust Score)
    + 0.30 × TSI_weight
    + 0.20 × A2C_risk
    + 0.15 × chain_risk
```

### 5.2 Seuils d'état

| État | VRS | Description |
|---|---|---|
| `SAFE` | [0.00, 0.25[ | Comportement nominal |
| `WATCH` | [0.25, 0.50[ | Signal faible, surveillance renforcée |
| `ALERT` | [0.50, 0.75[ | Anomalie significative |
| `CRITICAL` | [0.75, 1.00] | Action requise |

### 5.3 Risk Narrative

Pour chaque agent en état WATCH ou supérieur, Vigil génère automatiquement un narratif explicatif structuré — titre de l'état, causes classées par sévérité, chiffres précis. Visible dans l'Overview et dans le drill-down de l'agent.

---

## 6. Cas d'usage — exemples concrets

### 6.1 Détection de fork d'identité

Un fork d'identité se produit quand deux instances d'un agent partagent la même clé ou que la continuité de chaîne est rompue. Vigil détecte le fork immédiatement via la vérification AISS et affiche le badge **"FORKED IDENTITY"** en rouge clignotant avec alerte prioritaire CRITICAL.

### 6.2 Détection de collusion A2C

Exemple réel : `trading_bot_A` / `sentiment_bot`.

- 81% du trafic de `trading_bot_A` est dirigé vers `sentiment_bot` → détecteur de **concentration** déclenché
- Synchronisation temporelle de 0.94 entre les deux agents → détecteur de **synchronisation** déclenché

Ces deux signaux indépendants convergent vers une alerte de collusion potentielle, visible dans la vue étoile (arête épaisse entre les deux agents) et dans le Risk Narrative.

### 6.3 Détection de dérive TSI

Un agent dont le Trust Score chute progressivement sur 30 jours sans événement de fork visible sera détecté par le TSI **5 à 10 jours avant** que le seuil d'alerte absolu du Trust Score ne soit franchi. Le z-score signale la dérive bien avant que la valeur absolue ne devienne critique.

---

## 7. Intégration programmatique

### 7.1 Lire le résumé depuis l'API

```python
import urllib.request, json

with urllib.request.urlopen("http://localhost:8421/api/summary") as r:
    summary = json.loads(r.read())

print(f"{summary['total_agents']} agents")
print(f"VRS global : {summary['global_vrs']:.2f}")
for agent in summary['agents']:
    print(f"  {agent['name']} → {agent['state']} (VRS={agent['vrs']:.2f})")
```

### 7.2 Injecter un événement depuis un bridge

Les 9 bridges (LangChain, CrewAI, AutoGen, OpenClaw, Session, MCP, Ollama, ROS2, RPi) utilisent tous `POST /api/agent/<n>/record` pour injecter des événements dans Vigil.


```python
import urllib.request, json

event = {...}  # événement AISS signé

data = json.dumps(event).encode()
req = urllib.request.Request(
    "http://localhost:8421/api/agent/mon_agent/record",
    data=data,
    method="POST",
    headers={"Content-Type": "application/json"},
)
urllib.request.urlopen(req)
```

### 7.3 VIGILServer en Python

```python
from vigil.vigil_server import VIGILServer
import threading

srv = VIGILServer(host="127.0.0.1", port=8421)
thread = threading.Thread(target=srv.start, daemon=True)
thread.start()

# ... utilisation ...

srv.stop()
```

---

## 8. Alertes

Vigil maintient un journal d'alertes avec déduplication et priorisation.

- **Déduplication** : 1 heure entre deux alertes identiques (10 minutes pour CRITICAL)
- **Niveaux** : INFO (silencieux), WATCH, ALERT, CRITICAL
- **CRITICAL non noyable** : toujours en tête du journal

```bash
curl http://localhost:8421/api/alerts
# → {"alerts": [...], "total": N, "critical": K}
```

---

*PiQrypt v1.7.1 — MIT License*

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
