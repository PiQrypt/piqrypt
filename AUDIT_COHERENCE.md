# PiQrypt — Audit de cohérence globale
**Version auditée :** 1.7.1 (local) · PyPI v1.6.0
**Date d'audit :** 2026-03-14
**Périmètre :** Code source complet, documentation, licences, configuration, tiers
**Statut :** Rapport uniquement — aucune modification effectuée

---

## 1. Compréhension du projet

PiQrypt est une **infrastructure de confiance cryptographique pour agents IA autonomes**. Le projet répond à un problème structurel réel : l'écosystème IA (modèles → APIs → frameworks → applications) est dépourvu de couche d'infrastructure de confiance vérifiable. Les agents redémarrés perdent leur identité, les logs sont modifiables, et aucune traçabilité inter-agents n'est standardisée.

La réponse de PiQrypt s'articule autour de quatre couches empilées :

- **AISS** (fondation) : identité cryptographique par agent via paire Ed25519 avec dérivation déterministe de l'`agent_id`, chaîne d'événements hash-liée append-only, canonicalisation RFC 8785, anti-replay UUID4, détection de fork.
- **PiQrypt Core** : scoring de risque (VRS), certification `.pqz`, horodatage TSA RFC 3161, support post-quantique Dilithium3 NIST FIPS 204.
- **Vigil** : dashboard SOC HTTP temps réel (port 8421), API REST, visualisation réseau d'agents, export PDF/`.pqz`.
- **TrustGate** : moteur de gouvernance déterministe (10 priorités), file d'attente de supervision humaine (REQUIRE_HUMAN), politiques YAML hash-vérifiées, journal d'audit hash-chaîné propre à TrustGate.

Le protocole central **PCP (Proof of Continuity Protocol)** est déposé via e-Soleau (INPI France) — deux dépôts : DSO2026006483 (19/02/2026) et DSO2026009143 (12/03/2026). PiQrypt en est l'implémentation de référence.

Le modèle commercial est un **Open Core** à six tiers (Free → Enterprise), avec trois licences distinctes (MIT pour les primitives AISS, Apache-2.0 pour CLI et bridges, Elastic-2.0 pour le core, Vigil et TrustGate). La monétisation combine des abonnements annuels et un service de certification à la carte via Stripe.

Le positionnement réglementaire est clairement articulé autour de l'EU AI Act (Art. 12, 14, 9), de l'ANSSI 2024 (R25, R29, R30), et du NIST AI RMF 1.0. Le projet dispose d'une suite de tests de 325 tests (v1.7.1), d'une RFC AISS v2.0 de 1790 lignes, et d'un whitepaper v2.0.

---

## 2. Cohérence technique

### Ce qui est bien implémenté

L'implémentation technique est solide sur ses fondamentaux. La chaîne AISS est correctement construite : canonicalisation RFC 8785 dans `canonical.py`, signature Ed25519 via PyNaCl avec fallback `cryptography`, hash SHA-256 calculé sur le document canonique sans le champ `signature`, événement genesis avec `previous_hash = "genesis"`, nonces UUID4. Le `key_store.py` implémente scrypt N=2¹⁷ + AES-256-GCM + magic bytes `PQKY` + effacement mémoire (`_secure_erase`). L'`AgentRegistry` protège contre le path traversal. Le TrustGate est déterministe (zéro IA, même input → même output). Le journal d'audit TrustGate est lui-même hash-chaîné — cohérent avec la philosophie du projet.

### Incohérence majeure : poids VRS (documentation ≠ code)

Le README, le CLAUDE.md et la description dans l'en-tête du docstring d'`anomaly_monitor.py` présentent tous les poids VRS de la façon suivante :

```
TSI    30%  · Trust Score  35%  · A2C  20%  · Chain  15%
```

Mais les **constantes réelles** dans le code sont :

```python
VRS_WEIGHT_TS     = 0.20   # Trust Score  → 20% (README dit 35%)
VRS_WEIGHT_TSI    = 0.35   # TSI          → 35% (README dit 30%)
VRS_WEIGHT_A2C    = 0.30   # A2C          → 30% (README dit 20%)
VRS_WEIGHT_CHAIN  = 0.15   # Chain        → 15% (cohérent)
```

L'inversion TS/TSI et l'écart A2C (20% vs 30%) sont significatifs. Le docstring en tête d'`anomaly_monitor.py` documente lui-même les mauvais poids (il reflète l'ancienne version). Le code est la référence opérationnelle — la documentation externe (README, CLAUDE.md, docstring) décrit une ancienne version des poids.

### Incohérence mineure : numéro de version dans `aiss/__init__.py`

```python
__version__ = "1.6.0"   # aiss/__init__.py
version = "1.7.1"        # pyproject.toml
```

Le `__init__.py` n'a pas été mis à jour lors du passage en 1.7.1. Toute vérification programmatique de `aiss.__version__` retournera une valeur incorrecte.

### Incohérence mineure : port Vigil dans le CHANGELOG

Le CHANGELOG v1.5.0 mentionne "HTTP dashboard on port 18421". Partout ailleurs dans le projet (code, docs, CLAUDE.md, DEVELOPER_DOCS, démos), le port correct est **8421**. Il s'agit d'une faute de frappe dans la seule entrée du CHANGELOG v1.5.0.

### Conformité RFC AISS v2.0

La matrice de conformité dans `docs/IMPLEMENTATION_STATUS.md` est très complète. L'implémentation couvre Level 1 (§5–12, free) et Level 2 (§5–16, pro). Le Level 3 (HSM) est explicitement planifié pour v2.0.0. Aucune section RFC n'est revendiquée sans implémentation identifiable.

### Limitation documentée et correcte

Le CHANGELOG v1.7.1 documente explicitement que `verify_tsa_token()` vérifie la structure DER uniquement, sans vérification CMS/PKCS7 complète. C'est une limitation honnêtement déclarée, planifiée pour v1.8.0.

---

## 3. Cohérence des licences

### Mapping SPDX présent et cohérent

Les fichiers disposant de headers SPDX sont correctement taggués :

- `aiss/identity.py`, `stamp.py`, `verify.py`, `chain.py`, `fork.py`, `replay.py`, `canonical.py`, `exceptions.py`, `a2a.py`, `__init__.py`, `stamp_aiss2.py` → **MIT** ✅
- `aiss/agent_registry.py`, `memory.py`, `tsi_engine.py`, `trust_score.py`, `a2c_detector.py`, `key_store.py`, `identity_session.py`, `archive.py`, `history.py`, `certification.py`, `exports.py`, `badges.py`, `cert_badges.py`, `authority.py`, `anomaly_monitor.py`, `agent_context.py`, `logger.py`, `migration.py`, `telemetry.py`, `rfc3161.py`, `external_cert.py`, `index.py` → **Elastic-2.0** ✅
- `trustgate/*.py` (hors tests) → **Elastic-2.0** ✅
- `bridges/*/\_\_init\_\_.py` + `bridges/ros/piqrypt_ros.py` + `bridges/rpi/piqrypt_rpi.py` → **Apache-2.0** ✅
- `cli/__init__.py` et `cli/main.py` → **Apache-2.0** ✅ (confirmé par présence fichier `cli/LICENSE`)

Le mapping dans `LICENSE-SCHEMA.md` est cohérent avec les headers SPDX présents, et cohérent avec `pyproject.toml` qui déclare `MIT AND Apache-2.0 AND Elastic-2.0`.

### Fichiers sans header SPDX (67 fichiers)

67 fichiers `.py` n'ont pas encore de header SPDX (inventoriés dans la session précédente). Parmi eux :

**Priorité haute — fichiers avec licence attendue claire :**
- `auth_middleware.py` (racine) → devrait être **Elastic-2.0** (documenté dans LICENSE-SCHEMA.md)
- `vigil/vigil_server.py` → devrait être **Elastic-2.0** (confirmé par `vigil/LICENSE`)
- `trustgate/smoke_test_trustgate.py`, `trustgate/tests/*.py` → licence à définir
- `aiss/license.py` → devrait être **Elastic-2.0** (c'est un module business-critical)
- `aiss/crypto/__init__.py`, `aiss/crypto/dilithium_liboqs.py`, `aiss/crypto/ed25519.py` → probablement **MIT** (primitives cryptographiques)
- `aiss/templates/decrypt.py` → à définir selon usage

**Priorité basse — fichiers annexes :**
- `tests/`, `demos/`, `agents/examples/`, fichiers racine (`piqrypt_start.py`, `smoke_test.py`, etc.) → aucune licence assignée dans le mapping actuel.

**Question ouverte :** `tests/`, `demos/`, `agents/examples/` et les scripts racine ne sont pas couverts par le mapping de LICENSE-SCHEMA.md. La règle de fallback ("si pas de LICENSE dans le dossier, la licence MIT racine s'applique") les couvre théoriquement, mais sans header explicite, c'est ambigu dans un contexte légal.

---

## 4. Cohérence des tiers

### Incohérence majeure : tier Team — nombre d'agents

| Source | Agents Team |
|--------|------------|
| `aiss/license.py` TIERS dict | **150** |
| `aiss/license.py` docstring (lignes 19) | **100** |
| `README.md` tableau pricing | **100** |
| `TIERS_PRICING.md` (source de vérité déclarée) | **150** |
| `auth_middleware.py` (hérite de license.py) | **150** (via TIERS) |
| `CLAUDE.md` | **150** |

Le `TIERS` dict dans `license.py` (qui est la source opérationnelle) dit **150**, ce qui est cohérent avec `TIERS_PRICING.md` et `CLAUDE.md`. Le README et le docstring de `license.py` sont à corriger (ils disent 100).

### Incohérence majeure : devise et fréquence de facturation

Le README.md affiche les prix en **USD mensuel** (`$79/mo · $790/yr`, `$199/mo`, `$1,499/mo`). Le TIERS_PRICING.md affiche les prix en **EUR annuel** uniquement (`€290–390/year`, `€2,990/year`, `€14,990/year`). Ces deux représentations ne sont ni équivalentes ni converties — elles décrivent deux structures de prix différentes. Le README n'a pas été mis à jour lors du passage au modèle annuel en EUR.

### Incohérence notable : certifications incluses tier Free

| Source | Certifications Free |
|--------|-------------------|
| `CERTIFICATION_PRICING.md` | **1 Simple / mois** |
| `TIERS_PRICING.md` | **Aucune** (tableau ne montre pas de Simple pour Free) |
| `aiss/license.py` TIERS dict | `cert_simple_month: 0` (aucune) |

Le fichier `CERTIFICATION_PRICING.md` promet 1 Simple/mois en Free, ce que ni le code ni TIERS_PRICING.md ne reflètent. C'est une promesse commerciale non implémentée.

### Incohérence mineure : événements/mois tier Team

| Source | Events/mois Team |
|--------|----------------|
| `aiss/license.py` TIERS dict | 5,000,000 |
| `TIERS_PRICING.md` | 5,000,000 ✅ |
| `README.md` | 1,000,000 ✗ (ancienne valeur) |
| `aiss/license.py` docstring | 1M (ancienne valeur) ✗ |

Le `README.md` et le docstring de `license.py` montrent l'ancienne valeur de 1M events pour Team. Le code et TIERS_PRICING.md sont alignés sur 5M.

### Ce qui est cohérent

Les structures de features dans `VIGIL_TIER_FEATURES` (auth_middleware.py) et `TIERS` (license.py) sont cohérentes entre elles : même logique de gating, même hiérarchie. Le `TRUSTGATE_TIER_LEVEL` reflète correctement None/manual/full. Les quotas Enterprise (None = illimité) sont correctement gérés dans toute la pile.

---

## 5. Cohérence philosophique et produit

### Le positionnement réglementaire est soutenu par l'implémentation

La revendication EU AI Act Art. 14 (supervision humaine obligatoire) est concrètement implémentée : le flow REQUIRE_HUMAN dans TrustGate, la file de décisions avec TTL configurable, l'approbation/rejet par `HumanPrincipal`. Ce n'est pas un marketing vide — le code existe et est testé.

La revendication ANSSI R25 (filtrage de patterns dangereux) est implémentée via les `dangerous_patterns` en regex dans les fichiers de politique YAML, évalués en priorité 2 dans le `policy_engine.py`. ANSSI R29 (piste d'audit) est couvert par l'`audit_journal.py` hash-chaîné.

La revendication NIST AI RMF GOVERN 1.2 et MANAGE 2.2 est soutenue par la combinaison TrustGate + politiques configurables + journal immuable.

### Principe "non-bloquant" cohérent

Le VRS est clairement non-bloquant dans tout le projet : le score est calculé et exposé, mais aucune décision automatique de blocage n'est déclenchée par lui seul. C'est TrustGate, contrôlé par l'humain ou par politique explicite, qui décide. Ce principe est consistant entre la documentation, le CLAUDE.md et le code.

### Cas d'usage vs capacités techniques

Les quatre cas d'usage principaux décrits (créateur digital, SaaS AI startup, industrie/robotique, grande entreprise) sont couverts par des bridges existants (MCP pour créateurs, LangChain/CrewAI pour SaaS, ROS2/RPi pour robotique, TrustGate+SSO pour Enterprise). La couverture est réelle.

### Limite honnêtement documentée : storage flat-file

Le CHANGELOG v1.7.1 reconnaît que le stockage JSON en fichiers plats "degrade au-delà de 100k events/agent" et planifie PostgreSQL pour v2.0. Cette limite est réelle mais son impact est correctement borné pour la clientèle cible des tiers inférieurs.

### Tension : "production permanente" vs backend absent

Le CLAUDE.md liste parmi les priorités v1.7.1 : "créer le backend, fonctionnel, sur Render". Or le modèle commercial (certifications à la carte via Stripe, activation de licences Pro+, renouvellement annuel) présuppose l'existence de `api.piqrypt.com`. La clé publique embarquée dans `license.py` est explicitement marquée "Remplacer par la vraie clé publique avant production". Ce backend n'est pas encore en production, ce qui signifie que le tier Pro+ n'est pas réellement activable par un client externe aujourd'hui.

---

## 6. Points forts

**Architecture cryptographique rigoureuse.** La chaîne AISS respecte strictement RFC 8785, RFC 8032, RFC 3161, NIST FIPS 204. Les invariants (append-only, nonce unique, signature sur tout sauf elle-même) sont corrects et documentés. Le KeyStore avec scrypt N=2¹⁷ et effacement mémoire est de qualité production.

**Déterminisme du TrustGate.** Le principe "zéro IA, même input → même output" est fondamental pour l'auditabilité réglementaire. Son implémentation via 10 règles ordonnées explicites, avec références de compliance dans chaque règle, est un vrai différenciateur.

**Modèle de licence cohérent et bien raisonné.** Le choix ELv2 vs AGPL (fermer le "loophole AWS") est justifié, documenté, et le mapping fichier-par-fichier est précis. La stratégie Open Core (MIT pour attirer, ELv2 pour protéger, Apache pour les bridges) est une bonne pratique industrielle.

**Documentation technique de haute qualité.** La RFC AISS v2.0, le whitepaper, les guides d'intégration et `IMPLEMENTATION_STATUS.md` forment un corpus solide. L'auto-référencement entre documents est cohérent.

**Tests de sécurité sérieux.** 61 tests dédiés à la sécurité (timing, path traversal, forgery, replay, RAM erasure) indiquent une conscience sécurité au-delà du minimum. La présence de test vectors canoniques (`test_vectors/`) est une bonne pratique pour la conformité RFC.

**Propriété intellectuelle protégée.** Les dépôts e-Soleau sont récents (février et mars 2026), couvrent le PCP et l'implémentation de référence, et sont correctement référencés dans les fichiers sensibles.

---

## 7. Points faibles ou incohérences

### Incohérences à corriger avant la release GitHub publique

**W1 — Poids VRS incorrects dans la documentation (impact : crédibilité)**
README.md, docstring d'`anomaly_monitor.py` et CLAUDE.md décrivent les poids TSI=30%/TS=35%/A2C=20%. Le code réel est TS=20%/TSI=35%/A2C=30%. La documentation externe décrit une version périmée de la formule VRS. À corriger dans : README.md (tableau VRS), CLAUDE.md (section VRS), en-tête docstring d'`anomaly_monitor.py`.

**W2 — `aiss/__init__.py` version = "1.6.0" (impact : tooling, PyPI)**
La version dans `aiss/__init__.py` n'a pas été mise à jour lors du passage à v1.7.1. Toute vérification de `import aiss; aiss.__version__` retourne "1.6.0". À synchroniser avec pyproject.toml.

**W3 — README.md : pricing USD mensuel vs réalité EUR annuel (impact : commercial)**
Le tableau de pricing dans README.md affiche des prix en USD mensuel (`$79/mo`, `$199/mo`, `$1,499/mo`) qui ne correspondent pas au modèle actuel en EUR annuel. C'est la première chose visible par un prospect GitHub — un écart de devise et de modèle de facturation est préjudiciable.

**W4 — README.md : Team = 100 agents, 1M events (impact : informationnel)**
Le README affiche Team = 100 agents / 1M events, alors que la valeur opérationnelle est 150 agents / 5M events. Identique dans le docstring de `license.py`.

**W5 — CERTIFICATION_PRICING.md : Free inclut 1 Simple/mois non implémenté (impact : commercial)**
Ce fichier promet 1 certification Simple offerte par mois en tier Free. Ni `TIERS_PRICING.md`, ni `aiss/license.py` ne reflètent cela (`cert_simple_month: 0` pour Free). C'est une promesse non tenue visible publiquement.

**W6 — CHANGELOG v1.5.0 : port Vigil "18421" (impact : documentation)**
Une seule occurrence, ligne 344 du CHANGELOG. Le port correct est 8421. Faute de frappe mineure mais visible.

**W7 — Backend `api.piqrypt.com` absent (impact : fonctionnel Pro+)**
La clé publique embarquée dans `license.py` est marquée "à remplacer avant production". Sans backend, le tier Pro+ ne peut pas être vendu ni activé. Les liens Stripe dans `TIERS_PRICING.md` et `CERTIFICATION_PRICING.md` existent, mais l'infrastructure de fulfillment (émission de JWT de licence, traitement des certifications) n'est pas déployée.

### Observations secondaires

**O1 — 67 fichiers sans header SPDX.** La priorité immédiate concerne `auth_middleware.py`, `vigil/vigil_server.py`, `aiss/license.py`, `aiss/crypto/*.py`. Les tests et démos sont moins urgents mais créent une ambiguïté légale.

**O2 — Vigil Free tier : "read-only" dans README vs "read+write" dans TIERS_PRICING.**
Le README dit `start_free.ps1` ouvre "Vigil dashboard, read-only" et le tableau montre "Vigil read-only". TIERS_PRICING.md dit "Dashboard read + write (agents connect and send events)". Le code dans `auth_middleware.py` dit `"record": True` pour Free (les bridges peuvent envoyer des événements). La réalité opérationnelle est read+write — le README est en retard sur cette décision.

**O3 — Terme "VRS" vs "Vigil Risk Score" vs "Vulnerability & Risk Score".**
Le README utilise "Vulnerability & Risk Score", CLAUDE.md aussi. Le code (`anomaly_monitor.py`) utilise "Vigil Risk Score" en commentaire. Les deux sont utilisés. Mineure, mais une terminologie unique serait préférable dans les documents publics.

**O4 — `piqrypt@gmail.com` vs `contact@piqrypt.com`.**
TIERS_PRICING.md et CERTIFICATION_PRICING.md terminent avec `piqrypt@gmail.com`. README.md, SECURITY.md et CHANGELOG utilisent `contact@piqrypt.com`. Deux adresses différentes pour le même projet dans des documents publics.

---

## 8. Questions ouvertes

**Q1 — Poids VRS : quelle version est correcte ?**
README/CLAUDE.md : TSI=30%, TS=35%, A2C=20%. Code : TS=20%, TSI=35%, A2C=30%. Le code est la réalité opérationnelle, mais les documents décrivent-ils un état antérieur délibérément changé ? Ou le code a-t-il été modifié sans mise à jour de la documentation ?

**Q2 — Team tier : 100 ou 150 agents ?**
Le dict `TIERS` dans le code (150) et TIERS_PRICING.md (150) sont alignés, mais README et docstring license.py disent 100. La valeur correcte pour la release publique est-elle bien 150 ?

**Q3 — Certifications Free tier : 1 Simple/mois ou 0 ?**
CERTIFICATION_PRICING.md promet 1 Simple/mois. Le code dit 0. Quelle est la décision commerciale à retenir ?

**Q4 — Vigil Free : read+write ou read-only ?**
La décision a changé à v1.7.1 (le commentaire `"# Vigil fully functional (v1.7.1)"` dans license.py en témoigne). Le README n'a pas été mis à jour. Confirmation attendue : le Free tier est bien read+write (bridges fonctionnels) ?

**Q5 — Licence `tests/`, `demos/`, scripts racine (`piqrypt_start.py`, etc.) ?**
Ces fichiers ne sont couverts par aucune entrée dans le mapping de LICENSE-SCHEMA.md. La règle de fallback ("MIT racine") les couvre formellement, mais leur statut est ambigu. Faut-il leur assigner une licence explicite (MIT ? Apache-2.0 ?) ou les exclure de la distribution PyPI (ce que fait déjà `pyproject.toml` via `exclude = ["tests*", "docs*"]`) ?

**Q6 — Email de contact public : `piqrypt@gmail.com` ou `contact@piqrypt.com` ?**
Deux adresses différentes coexistent dans les documents publics. Laquelle est l'adresse canonique ?

**Q7 — Backends Stripe et `api.piqrypt.com` : calendrier de déploiement ?**
Les liens Stripe sont présents dans les documents publics. Sans backend, le flux d'activation Post-achat ne fonctionne pas. La release GitHub publique est-elle prévue avant ou après le déploiement du backend ?

---

*Audit produit sur la base du code et des documents disponibles dans le repo local v1.7.1.*
*Aucune modification n'a été effectuée dans le cadre de cet audit.*
