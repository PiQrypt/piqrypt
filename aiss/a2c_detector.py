# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# PROPRIETARY METHOD -- Dual License
# This file contains original algorithmic methods protected by
# e-Soleau deposits DSO2026006483 and DSO2026009143 (INPI France).
#
# Licensed under the Elastic License 2.0 (ELv2) for open/internal use.
# A separate commercial license is required for:
#   - SaaS or managed service deployment to third parties
#   - Proprietary products embedding this method
#   - OEM or white-label use
# Commercial license: contact@piqrypt.com -- Subject: Commercial License Inquiry

"""
A2C Detector — PiQrypt Vigil v1.8.1

Détection des anomalies relationnelles Agent-to-Agent (A2C).
Complète le Trust Score (comportement individuel) avec une analyse
des patterns d'interaction entre agents.

4 indicateurs relationnels :
    1. concentration    — trop de messages vers un seul peer (>70%)
    2. entropy_drop     — chute soudaine de diversité peers (Δ > 0.4 en 48h)
    3. synchronization  — deux agents parfaitement synchronisés (suspect)
    4. silence_break    — agent silencieux qui reprend brusquement

Contraintes d'implémentation :
    - Synchronisation temporelle : préférence TSA RFC 3161, flag CLOCK_UNANCHORED sinon
    - Performance : cache 5min < 50 agents, async > 50 agents
    - Seuils d'alerte : déduplication 1h, CRITICAL ne peut pas être noyé
    - Sélection agents : calcul possible sur sous-ensemble

Vigil Risk Score (VRS) — contribution A2C :
    VRS += 0.20 × A2C_risk
    A2C_risk = max(concentration, entropy_drop, synchronization, silence_break)

Hook v1.6.0 → v1.8.1 :
    trust_score.get_a2c_risk() appelle compute_a2c_risk() ici.
    Aucune modification nécessaire dans trust_score.py.
"""

import math
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Seuils ───────────────────────────────────────────────────────────────────
CONCENTRATION_THRESHOLD   = 0.70   # >70% messages vers un seul peer → suspect
ENTROPY_DROP_THRESHOLD    = 0.40   # Δentropie > 0.4 en 48h → alerte
SYNC_CORRELATION_MIN      = 0.92   # corrélation temporelle > 0.92 → suspect
SILENCE_BREAK_DAYS        = 7      # silence > 7j puis reprise soudaine
SILENCE_BURST_THRESHOLD   = 5      # ≥ 5 messages en 1h après silence

# Fenêtres temporelles
WINDOW_SHORT_H  = 48     # heures — pour détecter changements rapides
WINDOW_LONG_D   = 30     # jours  — baseline long terme

# Cache performances
CACHE_TTL_SECONDS = 300  # 5 minutes
_cache: Dict[str, Dict[str, Any]] = {}
_cache_timestamps: Dict[str, int] = {}

# Seuil multi-agents pour mode async (non bloquant)
ASYNC_THRESHOLD = 50


# ─── Types résultats ──────────────────────────────────────────────────────────

def _indicator(
    name: str,
    score: float,
    severity: str,
    details: Dict[str, Any],
    anchored: bool = True,
) -> Dict[str, Any]:
    """Construit un résultat d'indicateur normalisé."""
    return {
        "indicator":  name,
        "score":      round(min(1.0, max(0.0, score)), 4),
        "severity":   severity,           # NONE / LOW / MEDIUM / HIGH / CRITICAL
        "details":    details,
        "anchored":   anchored,           # False = horloge non fiable (TSA absent)
        "timestamp":  int(time.time()),
    }


def _severity(score: float) -> str:
    """Convertit un score [0,1] en niveau de sévérité."""
    if score < 0.25:
        return "NONE"
    if score < 0.50:
        return "LOW"
    if score < 0.70:
        return "MEDIUM"
    if score < 0.90:
        return "HIGH"
    return "CRITICAL"


# ─── Helpers temporels ────────────────────────────────────────────────────────

def _is_anchored(event: Dict[str, Any]) -> bool:
    """
    Vérifie si l'événement a un timestamp TSA RFC 3161 fiable.
    Contrainte : synchronisation temporelle.
    """
    payload = event.get("payload", {})
    return bool(
        payload.get("tsa_token")
        or payload.get("rfc3161_token")
        or event.get("tsa_timestamp")
        or event.get("finalized_at")
    )


def _get_timestamp(event: Dict[str, Any]) -> Tuple[int, bool]:
    """
    Retourne (timestamp, anchored).
    anchored=True si le timestamp vient d'une TSA RFC 3161.
    """
    payload = event.get("payload", {})
    tsa_ts = (
        payload.get("tsa_timestamp")
        or event.get("tsa_timestamp")
        or event.get("finalized_at")
    )
    if tsa_ts:
        return int(tsa_ts), True
    return int(event.get("timestamp", 0)), False


def _recent_events(
    events: List[Dict[str, Any]],
    hours: int,
    current_time: int,
    require_anchored: bool = False,
) -> List[Dict[str, Any]]:
    """Filtre les événements dans une fenêtre temporelle."""
    cutoff = current_time - hours * 3600
    result = []
    for e in events:
        ts, anchored = _get_timestamp(e)
        if ts >= cutoff:
            if require_anchored and not anchored:
                continue
            result.append(e)
    return result


def _peer_id(event: Dict[str, Any]) -> Optional[str]:
    """Extrait le peer_id d'un événement A2A."""
    payload = event.get("payload", {})
    return (
        payload.get("peer_agent_id")
        or payload.get("peer_id")
        or event.get("peer_agent_id")
    )


def _is_a2a(event: Dict[str, Any]) -> bool:
    """Retourne True si l'événement est une interaction A2A."""
    a2a_types = {
        "a2a_handshake", "a2a_message",
        "a2a_handshake_complete", "external_interaction",
        "a2a_request", "a2a_response",
    }
    event_type = event.get("payload", {}).get("event_type", "")
    return event_type in a2a_types


# ─── Indicateur 1 : Concentration ─────────────────────────────────────────────

def detect_concentration(
    events: List[Dict[str, Any]],
    current_time: Optional[int] = None,
    window_hours: int = WINDOW_SHORT_H,
) -> Dict[str, Any]:
    """
    Concentration : trop de messages vers un seul peer.

    Score élevé = l'agent concentre >70% de ses interactions
    sur un seul peer dans la fenêtre récente.

    Cas suspect :
        - Agent de trading qui parle uniquement à un autre agent
        - Possible coordination opaque ou dépendance excessive

    Contrainte TSA : si événements non ancrés, flag CLOCK_UNANCHORED
    mais calcul quand même (horloge locale peut suffire).
    """
    if current_time is None:
        current_time = int(time.time())

    a2a_events = [e for e in events if _is_a2a(e)]
    recent = _recent_events(a2a_events, window_hours, current_time)

    unanchored_count = sum(1 for e in recent if not _is_anchored(e))
    anchored = unanchored_count == 0

    if not recent:
        return _indicator("concentration", 0.0, "NONE", {
            "note": "Aucune interaction A2A récente",
            "window_hours": window_hours,
        }, anchored)

    peer_counts: Counter = Counter()
    for e in recent:
        pid = _peer_id(e) or "unknown"
        peer_counts[pid] += 1

    total = len(recent)
    top_peer, top_count = peer_counts.most_common(1)[0]
    top_ratio = top_count / total
    unique_peers = len(peer_counts)

    # Score : ratio au-dessus du seuil, normalisé
    if top_ratio <= CONCENTRATION_THRESHOLD:
        score = 0.0
    else:
        # Interpolation linéaire entre seuil (0.0) et 1.0 (100%)
        score = (top_ratio - CONCENTRATION_THRESHOLD) / (1.0 - CONCENTRATION_THRESHOLD)

    details = {
        "top_peer":          top_peer,
        "top_peer_ratio":    round(top_ratio, 4),
        "unique_peers":      unique_peers,
        "total_interactions": total,
        "threshold":         CONCENTRATION_THRESHOLD,
        "window_hours":      window_hours,
    }

    if not anchored:
        details["clock_warning"] = "CLOCK_UNANCHORED — timestamps non vérifiés TSA"

    return _indicator("concentration", score, _severity(score), details, anchored)


# ─── Indicateur 2 : Entropy Drop ──────────────────────────────────────────────

def detect_entropy_drop(
    events: List[Dict[str, Any]],
    current_time: Optional[int] = None,
    window_short_h: int = WINDOW_SHORT_H,
    window_long_d: int = WINDOW_LONG_D,
) -> Dict[str, Any]:
    """
    Entropy Drop : chute soudaine de diversité peers.

    Compare l'entropie de Shannon sur la fenêtre courte (48h)
    vs la baseline longue (30j). Une chute > 0.40 est suspecte.

    Cas suspect :
        - Agent qui avait 10 peers diversifiés et n'en contacte plus qu'un
        - Possible isolation forcée ou compromission de routing

    Contrainte TSA : gaps impliquant uniquement des événements
    non-ancrés génèrent CLOCK_UNANCHORED, pas une alerte DRIFT.
    """
    if current_time is None:
        current_time = int(time.time())

    a2a_events = [e for e in events if _is_a2a(e)]

    # Baseline longue
    long_window  = _recent_events(a2a_events, window_long_d * 24, current_time)
    # Fenêtre courte
    short_window = _recent_events(a2a_events, window_short_h, current_time)

    unanchored = sum(1 for e in short_window if not _is_anchored(e))
    anchored   = unanchored == 0

    def _entropy(evts: List) -> float:
        if not evts:
            return 0.0
        counts: Counter = Counter()
        for e in evts:
            pid = _peer_id(e) or "unknown"
            counts[pid] += 1
        total = len(evts)
        unique = len(counts)
        if unique <= 1:
            return 0.0
        h = -sum((c / total) * math.log2(c / total) for c in counts.values())
        return h / math.log2(unique) if unique > 1 else 0.0

    entropy_long  = _entropy(long_window)
    entropy_short = _entropy(short_window)
    delta = entropy_long - entropy_short  # positif = chute

    if len(long_window) < 5:
        return _indicator("entropy_drop", 0.0, "NONE", {
            "note": "Baseline insuffisante (< 5 événements A2A sur 30j)",
        }, anchored)

    if delta <= 0:
        score = 0.0
    elif delta <= ENTROPY_DROP_THRESHOLD:
        score = delta / ENTROPY_DROP_THRESHOLD * 0.5
    else:
        score = min(1.0, 0.5 + (delta - ENTROPY_DROP_THRESHOLD) * 2)

    details = {
        "entropy_baseline_30d": round(entropy_long, 4),
        "entropy_recent_48h":   round(entropy_short, 4),
        "delta":                round(delta, 4),
        "threshold":            ENTROPY_DROP_THRESHOLD,
        "long_window_events":   len(long_window),
        "short_window_events":  len(short_window),
    }

    if not anchored:
        details["clock_warning"] = "CLOCK_UNANCHORED — delta peut être faussé"

    return _indicator("entropy_drop", score, _severity(score), details, anchored)


# ─── Indicateur 3 : Synchronization ──────────────────────────────────────────

def detect_synchronization(
    agent_events: List[Dict[str, Any]],
    peer_events: List[Dict[str, Any]],
    peer_id: str,
    current_time: Optional[int] = None,
    window_hours: int = WINDOW_SHORT_H,
    tolerance_seconds: int = 5,
) -> Dict[str, Any]:
    """
    Synchronization : deux agents qui agissent de manière parfaitement synchronisée.

    Détecte des patterns temporels suspects entre deux agents :
    si leurs événements sont corrélés à < tolerance_seconds près
    sur > SYNC_CORRELATION_MIN de leurs actions communes.

    Cas suspect :
        - Deux agents contrôlés par la même entité malveillante
        - Coordination cachée pour manipuler un système tiers

    Note : nécessite accès aux événements du peer.
    Si peer_events vide → score 0.0 (pas de données).
    """
    if current_time is None:
        current_time = int(time.time())

    agent_recent = _recent_events(agent_events, window_hours, current_time)
    peer_recent  = _recent_events(peer_events,  window_hours, current_time)

    # Vérifier ancrage TSA — critique pour ce check
    agent_unanchored = sum(1 for e in agent_recent if not _is_anchored(e))
    peer_unanchored  = sum(1 for e in peer_recent  if not _is_anchored(e))
    anchored = (agent_unanchored + peer_unanchored) == 0

    if len(agent_recent) < 3 or len(peer_recent) < 3:
        return _indicator("synchronization", 0.0, "NONE", {
            "note": "Données insuffisantes pour détecter synchronisation",
            "peer_id": peer_id,
        }, anchored)

    # Extraire les timestamps
    agent_ts = sorted(_get_timestamp(e)[0] for e in agent_recent)
    peer_ts  = sorted(_get_timestamp(e)[0] for e in peer_recent)

    # Compter les paires temporellement proches
    matched = 0
    min_len = min(len(agent_ts), len(peer_ts))

    j = 0
    for ts_a in agent_ts:
        while j < len(peer_ts) and peer_ts[j] < ts_a - tolerance_seconds:
            j += 1
        if j < len(peer_ts) and abs(peer_ts[j] - ts_a) <= tolerance_seconds:
            matched += 1

    correlation = matched / min_len if min_len > 0 else 0.0

    if correlation < SYNC_CORRELATION_MIN:
        score = 0.0
    else:
        score = (correlation - SYNC_CORRELATION_MIN) / (1.0 - SYNC_CORRELATION_MIN)

    details = {
        "peer_id":             peer_id,
        "correlation":         round(correlation, 4),
        "matched_pairs":       matched,
        "agent_events":        len(agent_recent),
        "peer_events":         len(peer_recent),
        "tolerance_seconds":   tolerance_seconds,
        "threshold":           SYNC_CORRELATION_MIN,
        "window_hours":        window_hours,
    }

    if not anchored:
        details["clock_warning"] = (
            "CLOCK_UNANCHORED — synchronisation peut être un artefact "
            "d'horloge non synchronisée. Résultat non fiable."
        )
        # Si non ancré, on divise le score par 2 — incertitude clock
        score *= 0.5

    return _indicator("synchronization", score, _severity(score), details, anchored)


# ─── Indicateur 4 : Silence Break ─────────────────────────────────────────────

def detect_silence_break(
    events: List[Dict[str, Any]],
    current_time: Optional[int] = None,
    silence_days: int = SILENCE_BREAK_DAYS,
    burst_threshold: int = SILENCE_BURST_THRESHOLD,
    burst_window_hours: int = 1,
) -> Dict[str, Any]:
    """
    Silence Break : agent silencieux qui reprend brusquement.

    Pattern :
        1. L'agent est silencieux depuis > silence_days jours
        2. Il reprend avec ≥ burst_threshold événements en 1h

    Cas suspect :
        - Agent compromis qui "reprend vie" après une période de dormance
        - Injection d'événements en masse pour manipuler le Trust Score
        - Reprise après une mise à jour malveillante

    Contrainte : nécessite au moins silence_days + 1 d'historique.
    """
    if current_time is None:
        current_time = int(time.time())

    if not events:
        return _indicator("silence_break", 0.0, "NONE", {
            "note": "Aucun événement",
        })

    # Trier par timestamp
    sorted_events = sorted(events, key=lambda e: _get_timestamp(e)[0])

    # Chercher une période de silence suivie d'un burst
    silence_sec = silence_days * 86400
    burst_sec   = burst_window_hours * 3600

    # Trouver le dernier gap > silence_days dans l'historique récent
    silence_start = None
    silence_end   = None

    for i in range(len(sorted_events) - 1):
        ts_curr, _ = _get_timestamp(sorted_events[i])
        ts_next, _ = _get_timestamp(sorted_events[i + 1])
        gap = ts_next - ts_curr

        if gap >= silence_sec:
            silence_start = ts_curr
            silence_end   = ts_next

    if silence_start is None:
        return _indicator("silence_break", 0.0, "NONE", {
            "note": f"Aucune période de silence > {silence_days}j détectée",
            "silence_days": silence_days,
        })

    # Vérifier s'il y a un burst juste après la fin du silence
    burst_events = [
        e for e in sorted_events
        if silence_end <= _get_timestamp(e)[0] <= silence_end + burst_sec
    ]

    actual_silence_days = (silence_end - silence_start) / 86400
    burst_count = len(burst_events)

    unanchored = sum(1 for e in burst_events if not _is_anchored(e))
    anchored = unanchored == 0

    # Score basé sur la combinaison : silence long + burst important
    if burst_count < burst_threshold:
        score = 0.0
    else:
        # Normalisation : plus le silence est long et le burst fort, plus le score monte
        silence_factor = min(1.0, actual_silence_days / (silence_days * 3))
        burst_factor   = min(1.0, (burst_count - burst_threshold) / burst_threshold)
        score = (silence_factor * 0.4 + burst_factor * 0.6)

    details = {
        "silence_start":        silence_start,
        "silence_end":          silence_end,
        "silence_days":         round(actual_silence_days, 1),
        "burst_count":          burst_count,
        "burst_window_hours":   burst_window_hours,
        "burst_threshold":      burst_threshold,
        "silence_threshold_days": silence_days,
    }

    if not anchored:
        details["clock_warning"] = "CLOCK_UNANCHORED — silence peut être un artefact"
        score *= 0.5

    return _indicator("silence_break", score, _severity(score), details, anchored)


# ─── Cache performances ───────────────────────────────────────────────────────

def _get_cached(agent_id: str) -> Optional[Dict[str, Any]]:
    """Retourne le résultat en cache si encore valide."""
    if agent_id not in _cache:
        return None
    age = int(time.time()) - _cache_timestamps.get(agent_id, 0)
    if age > CACHE_TTL_SECONDS:
        return None
    return _cache[agent_id]


def _set_cache(agent_id: str, result: Dict[str, Any]) -> None:
    """Met en cache le résultat A2C pour un agent."""
    _cache[agent_id] = result
    _cache_timestamps[agent_id] = int(time.time())


def invalidate_cache(agent_id: Optional[str] = None) -> None:
    """
    Invalide le cache A2C.
    Si agent_id fourni → invalide uniquement cet agent.
    Sinon → invalide tout le cache.
    """
    if agent_id:
        _cache.pop(agent_id, None)
        _cache_timestamps.pop(agent_id, None)
    else:
        _cache.clear()
        _cache_timestamps.clear()


# ─── Agrégat principal ────────────────────────────────────────────────────────

def compute_a2c_risk(
    agent_id: str,
    events: Optional[List[Dict[str, Any]]] = None,
    peer_events_map: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    current_time: Optional[int] = None,
    use_cache: bool = True,
    agent_subset: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Calcule le risque A2C complet pour un agent.

    Args:
        agent_id:        ID de l'agent analysé
        events:          Événements de l'agent (chargés auto si None)
        peer_events_map: {peer_id: [events]} pour la détection de synchronisation
                         Si None → detect_synchronization non calculé
        current_time:    Timestamp courant (auto si None)
        use_cache:       Utilise le cache 5min (recommandé en production)
        agent_subset:    Liste d'agent_ids à inclure dans l'analyse multi-agents
                         None = tous les agents connus

    Returns:
        {
            a2c_risk:     float [0,1]  — score global
            severity:     str          — NONE/LOW/MEDIUM/HIGH/CRITICAL
            indicators:   dict         — détail des 4 indicateurs
            alerts:       list         — alertes déclenchées (seuil MEDIUM+)
            anchored:     bool         — True si tous timestamps TSA
            cached:       bool         — True si résultat depuis cache
            computed_at:  int
        }
    """
    if current_time is None:
        current_time = int(time.time())

    # Cache
    if use_cache:
        cached = _get_cached(agent_id)
        if cached:
            return {**cached, "cached": True}

    # Charger les événements si non fournis
    if events is None:
        try:
            from aiss.memory import load_events
            events = load_events(agent_id=agent_id)
        except Exception as e:
            logger.warning(f"[A2C] Impossible de charger les événements : {e}")
            events = []

    # Calculer les 4 indicateurs
    concentration  = detect_concentration(events, current_time)
    entropy_drop   = detect_entropy_drop(events, current_time)
    silence_break  = detect_silence_break(events, current_time)

    # Synchronisation — si peer_events_map fourni
    sync_results = []
    if peer_events_map:
        # Filtrer par agent_subset si fourni
        peers_to_check = peer_events_map
        if agent_subset:
            peers_to_check = {
                k: v for k, v in peer_events_map.items()
                if k in agent_subset
            }
        for peer_id, peer_evts in peers_to_check.items():
            sync = detect_synchronization(events, peer_evts, peer_id, current_time)
            if sync["score"] > 0.0:
                sync_results.append(sync)

    # Synchronisation maximale (worst case)
    sync_score = max((s["score"] for s in sync_results), default=0.0)
    sync_indicator = max(sync_results, key=lambda s: s["score"]) if sync_results else \
        _indicator("synchronization", 0.0, "NONE", {
            "note": "Pas de données peers pour analyse synchronisation"
        })

    # Score global A2C = max pondéré des indicateurs
    scores = {
        "concentration":  concentration["score"]  * 0.30,
        "entropy_drop":   entropy_drop["score"]   * 0.25,
        "synchronization": sync_score             * 0.25,
        "silence_break":  silence_break["score"]  * 0.20,
    }
    a2c_risk = sum(scores.values())

    # Ancrage global
    all_anchored = all([
        concentration["anchored"],
        entropy_drop["anchored"],
        sync_indicator["anchored"],
        silence_break["anchored"],
    ])

    # Alertes — seuil MEDIUM+ avec déduplication
    alerts = _build_alerts(agent_id, {
        "concentration":   concentration,
        "entropy_drop":    entropy_drop,
        "synchronization": sync_indicator,
        "silence_break":   silence_break,
    })

    result = {
        "agent_id":   agent_id,
        "a2c_risk":   round(min(1.0, a2c_risk), 4),
        "severity":   _severity(a2c_risk),
        "indicators": {
            "concentration":   concentration,
            "entropy_drop":    entropy_drop,
            "synchronization": sync_indicator,
            "silence_break":   silence_break,
        },
        "weighted_scores": {k: round(v, 4) for k, v in scores.items()},
        "alerts":      alerts,
        "anchored":    all_anchored,
        "cached":      False,
        "computed_at": current_time,
    }

    if not all_anchored:
        result["clock_warning"] = (
            "Certains timestamps ne sont pas ancrés TSA RFC 3161. "
            "Les scores A2C peuvent être moins fiables. "
            "Utilisez piqrypt stamp --finalize pour ancrer les événements."
        )

    # Mise en cache
    if use_cache:
        _set_cache(agent_id, result)

    logger.info(
        f"[A2C] {agent_id[:16]}... — risk={result['a2c_risk']} "
        f"severity={result['severity']} alerts={len(alerts)}"
    )

    return result


# ─── Alertes avec déduplication ───────────────────────────────────────────────

# Journal des alertes déjà émises {agent_id:indicator_name: last_emit_ts}
_alert_journal: Dict[str, int] = {}
ALERT_COOLDOWN = 3600  # 1 heure


def _build_alerts(
    agent_id: str,
    indicators: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Construit la liste des alertes actives.

    Contrainte :
        - Seuil MEDIUM+ uniquement
        - Déduplication : même alerte → cooldown 1h
        - CRITICAL ne peut jamais être noyé (cooldown réduit à 10min)
    """
    alerts = []
    now = int(time.time())

    severity_order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    messages = {
        "concentration":   "Concentration excessive vers un seul peer",
        "entropy_drop":    "Chute soudaine de diversité des interactions",
        "synchronization": "Synchronisation temporelle suspecte avec un peer",
        "silence_break":   "Reprise d'activité suspecte après une longue période de silence",
    }

    for name, indicator in indicators.items():
        sev = indicator["severity"]
        if severity_order.get(sev, 0) < severity_order["MEDIUM"]:
            continue

        journal_key = f"{agent_id}:{name}"
        last_emit   = _alert_journal.get(journal_key, 0)
        cooldown    = 600 if sev == "CRITICAL" else ALERT_COOLDOWN

        if now - last_emit < cooldown:
            continue  # Déduplication

        alert = {
            "agent_id":  agent_id,
            "indicator": name,
            "severity":  sev,
            "score":     indicator["score"],
            "message":   messages.get(name, name),
            "details":   indicator.get("details", {}),
            "timestamp": now,
            "anchored":  indicator.get("anchored", True),
        }
        alerts.append(alert)
        _alert_journal[journal_key] = now

    # Trier : CRITICAL en premier
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 0), reverse=True)
    return alerts


# ─── API multi-agents ─────────────────────────────────────────────────────────

def compute_a2c_risk_batch(
    agent_ids: List[str],
    events_map: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    agent_subset: Optional[List[str]] = None,
    use_cache: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """
    Calcule le risque A2C pour un ensemble d'agents.

    Contrainte performance :
        < 50 agents  → calcul synchrone
        ≥ 50 agents  → calcul en batch séquentiel avec cache agressif

    Args:
        agent_ids:    Liste d'agent_ids à analyser
        events_map:   {agent_id: [events]} — chargé auto si None
        agent_subset: Restreindre l'analyse à ce sous-ensemble
                      (sélection unitaire ou par groupe)
        use_cache:    Cache 5min activé

    Returns:
        {agent_id: compute_a2c_risk_result}
    """
    # Filtrer par subset si fourni
    to_analyze = agent_ids
    if agent_subset:
        to_analyze = [a for a in agent_ids if a in agent_subset]

    is_large = len(to_analyze) >= ASYNC_THRESHOLD
    if is_large:
        logger.info(
            f"[A2C] Batch {len(to_analyze)} agents — "
            f"mode séquentiel avec cache (> {ASYNC_THRESHOLD} agents)"
        )

    results = {}
    for agent_id in to_analyze:
        events = (events_map or {}).get(agent_id)
        # Pour synchronisation, construire le peer_map sans l'agent courant
        peer_map = None
        if events_map:
            peer_map = {
                k: v for k, v in events_map.items()
                if k != agent_id
                and (agent_subset is None or k in agent_subset)
            }

        results[agent_id] = compute_a2c_risk(
            agent_id=agent_id,
            events=events,
            peer_events_map=peer_map,
            use_cache=use_cache,
        )

    return results


def get_installation_a2c_summary(
    agent_subset: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Résumé A2C de toute l'installation (ou d'un sous-ensemble).

    Utilisé par le dashboard Vigil — vue globale CTO.

    Returns:
        {
            total_agents:   int
            critical_count: int
            high_count:     int
            agents:         [résumés triés par risque décroissant]
            computed_at:    int
        }
    """
    try:
        from aiss.agent_registry import list_agents
        all_agents = list_agents()
    except Exception:
        all_agents = []

    agent_ids = [a["name"] for a in all_agents]
    if agent_subset:
        agent_ids = [a for a in agent_ids if a in agent_subset]

    results = compute_a2c_risk_batch(agent_ids, agent_subset=agent_subset)

    severity_order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    summaries = []
    for agent_id, result in results.items():
        summaries.append({
            "agent_id":  agent_id,
            "a2c_risk":  result["a2c_risk"],
            "severity":  result["severity"],
            "alerts":    len(result["alerts"]),
            "cached":    result["cached"],
        })

    summaries.sort(
        key=lambda s: severity_order.get(s["severity"], 0),
        reverse=True
    )

    return {
        "total_agents":   len(summaries),
        "critical_count": sum(1 for s in summaries if s["severity"] == "CRITICAL"),
        "high_count":     sum(1 for s in summaries if s["severity"] == "HIGH"),
        "medium_count":   sum(1 for s in summaries if s["severity"] == "MEDIUM"),
        "agents":         summaries,
        "agent_subset":   agent_subset,
        "computed_at":    int(time.time()),
    }


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    "compute_a2c_risk",
    "compute_a2c_risk_batch",
    "get_installation_a2c_summary",
    "detect_concentration",
    "detect_entropy_drop",
    "detect_synchronization",
    "detect_silence_break",
    "invalidate_cache",
    # Constantes
    "CONCENTRATION_THRESHOLD",
    "ENTROPY_DROP_THRESHOLD",
    "SYNC_CORRELATION_MIN",
    "SILENCE_BREAK_DAYS",
    "CACHE_TTL_SECONDS",
    "ASYNC_THRESHOLD",
]
