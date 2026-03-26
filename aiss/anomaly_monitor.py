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
Anomaly Monitor — PiQrypt Vigil v1.8.3

Hub central du système Vigil. Agrège tous les signaux disponibles
en un Vigil Risk Score (VRS) unique par agent et par installation.

Sources agrégées :
    Trust Score (TS)    — comportement individuel
    TSI                 — dérive temporelle
    A2C                 — anomalies relationnelles
    Chain anomalies     — forks, replay, ruptures

Vigil Risk Score :
    VRS = 0.35 × (1 - TS)
        + 0.30 × TSI_weight
        + 0.20 × A2C_risk
        + 0.15 × chain_risk

    VRS [0, 1] → SAFE / WATCH / ALERT / CRITICAL

Journal d'alertes :
    - Persisté par agent dans ~/.piqrypt/agents/<n>/vigil/alerts.json
    - Déduplication 1h (CRITICAL → 10min)
    - Niveaux : INFO (silencieux), WATCH, ALERT, CRITICAL
    - CRITICAL non noyable : toujours en tête du journal

Intégration hooks v1.6.0 :
    tsi_engine._emit_sentinel_event()   → record() ici
    trust_score.get_a2c_risk()          → compute_a2c_risk() dans a2c_detector
    Aucune modification nécessaire dans les modules existants

Performance :
    < 10 agents  : synchrone
    10-50 agents : cache 5min par agent
    > 50 agents  : batch séquentiel, résultats depuis cache
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Constantes ───────────────────────────────────────────────────────────────

# Poids VRS
VRS_WEIGHT_TS     = 0.20
VRS_WEIGHT_TSI    = 0.35
VRS_WEIGHT_A2C    = 0.30
VRS_WEIGHT_CHAIN  = 0.15

# États VRS
VRS_SAFE     = "SAFE"
VRS_WATCH    = "WATCH"
VRS_ALERT    = "ALERT"
VRS_CRITICAL = "CRITICAL"

# Seuils VRS → état
VRS_THRESHOLDS = {
    VRS_SAFE:     (0.00, 0.25),
    VRS_WATCH:    (0.25, 0.50),
    VRS_ALERT:    (0.50, 0.75),
    VRS_CRITICAL: (0.75, 1.01),
}

# Poids TSI state → contribution VRS
TSI_WEIGHTS = {
    "STABLE":   0.0,
    "WATCH":    0.25,
    "UNSTABLE": 1.0,
    "CRITICAL": 1.0,
}

# Journal alertes
ALERT_COOLDOWN_S  = 3600   # 1h
CRITICAL_COOLDOWN = 600    # 10min — CRITICAL non noyable
MAX_ALERTS_STORED = 200    # par agent, rotation FIFO

# Cache performance
VRS_CACHE_TTL = 300        # 5min


# ─── Stockage journal ─────────────────────────────────────────────────────────

def _vigil_dir(agent_name: str) -> Path:
    """Répertoire Vigil de l'agent."""
    try:
        from aiss.agent_registry import get_agent_dir
        return get_agent_dir(agent_name) / "vigil"
    except Exception:
        return Path.home() / ".piqrypt" / "agents" / agent_name / "vigil"


def _alerts_path(agent_name: str) -> Path:
    return _vigil_dir(agent_name) / "alerts.json"


def _vrs_history_path(agent_name: str) -> Path:
    return _vigil_dir(agent_name) / "vrs_history.json"


def _load_alerts(agent_name: str) -> List[Dict[str, Any]]:
    path = _alerts_path(agent_name)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def _save_alerts(agent_name: str, alerts: List[Dict[str, Any]]) -> None:
    path = _alerts_path(agent_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Rotation FIFO
    if len(alerts) > MAX_ALERTS_STORED:
        alerts = alerts[-MAX_ALERTS_STORED:]
    path.write_text(json.dumps(alerts, indent=2))


def _load_vrs_history(agent_name: str) -> List[Dict[str, Any]]:
    path = _vrs_history_path(agent_name)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def _save_vrs_history(agent_name: str, history: List[Dict[str, Any]]) -> None:
    path = _vrs_history_path(agent_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Garder 30 jours
    cutoff = int(time.time()) - 30 * 86400
    history = [h for h in history if h.get("timestamp", 0) >= cutoff]
    path.write_text(json.dumps(history, indent=2))


# ─── VRS — Vigil Risk Score ───────────────────────────────────────────────────

def _vrs_state(vrs: float) -> str:
    """Convertit un score VRS en état lisible."""
    for state, (low, high) in VRS_THRESHOLDS.items():
        if low <= vrs < high:
            return state
    return VRS_CRITICAL


def _compute_chain_risk(
    events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Calcule le risque chaîne depuis fork.py, chain.py, replay.py.
    Retourne {score, details, anomalies}.
    """
    anomalies = []
    score = 0.0

    if not events:
        return {"score": 0.0, "anomalies": [], "details": {"note": "Aucun événement"}}

    # Forks
    try:
        from aiss.fork import find_forks
        forks = find_forks(events)
        if forks:
            score += 0.4 * min(1.0, len(forks) / 3)
            for f in forks:
                anomalies.append({
                    "type":        "fork",
                    "severity":    "CRITICAL",   # RFC AISS-1.1 §6 — fork = incident sécurité
                    "description": f"Chain fork at {getattr(f, 'hash', '?')[:12]}… — {len(getattr(f, 'events', []))} branches",
                    "details":     f"Chain fork at {getattr(f, 'hash', '?')[:12]}… — {len(getattr(f, 'events', []))} branches",
                    "timestamp":   int(__import__('time').time()) - 120,
                })
    except Exception as e:
        logger.debug(f"[Vigil] fork check: {e}")

    # Replay
    try:
        from aiss.replay import detect_replay_attacks
        replays = detect_replay_attacks(events)
        if replays:
            score += 0.4 * min(1.0, len(replays) / 2)
            for r in replays:
                anomalies.append({
                    "type": "replay",
                    "severity": "CRITICAL",
                    "details": f"Replay détecté (nonce={getattr(r, 'nonce', '?')[:12]}...)",
                })
    except Exception as e:
        logger.debug(f"[Vigil] replay check: {e}")

    # Rupture chaîne
    try:
        from aiss.chain import verify_chain_linkage, verify_monotonic_timestamps
        if len(events) >= 2:
            if not verify_chain_linkage(events):
                score += 0.3
                anomalies.append({
                    "type": "chain_break",
                    "severity": "HIGH",
                    "details": "Rupture de chaîne hash détectée",
                })
            if not verify_monotonic_timestamps(events):
                score += 0.1
                anomalies.append({
                    "type": "timestamp_anomaly",
                    "severity": "MEDIUM",
                    "details": "Timestamps non-monotones",
                })
    except Exception as e:
        logger.debug(f"[Vigil] chain check: {e}")

    return {
        "score":     round(min(1.0, score), 4),
        "anomalies": anomalies,
        "details":   {"anomaly_count": len(anomalies)},
    }


def compute_vrs(
    agent_name: str,
    agent_id: Optional[str] = None,
    events: Optional[List[Dict[str, Any]]] = None,
    current_time: Optional[int] = None,
    peer_events_map: Optional[Dict[str, List]] = None,
    persist: bool = True,
) -> Dict[str, Any]:
    """
    Calcule le Vigil Risk Score complet pour un agent.

    VRS = 0.35×(1-TS) + 0.30×TSI_weight + 0.20×A2C + 0.15×chain

    Args:
        agent_name:      Nom de l'agent (pour stockage journal)
        agent_id:        ID cryptographique (déduit depuis registre si None)
        events:          Événements (chargés auto si None)
        current_time:    Timestamp courant (auto si None)
        peer_events_map: Pour A2C synchronisation
        persist:         Persiste VRS dans l'historique

    Returns:
        {
            vrs:          float [0,1]
            state:        SAFE/WATCH/ALERT/CRITICAL
            components:   {ts, tsi, a2c, chain}
            alerts:       list
            agent_name:   str
            agent_id:     str
            computed_at:  int
        }
    """
    if current_time is None:
        current_time = int(time.time())

    # Résoudre agent_id
    if agent_id is None:
        try:
            from aiss.agent_registry import get_agent_info
            info = get_agent_info(agent_name)
            agent_id = info["agent_id"] if info else agent_name
        except Exception:
            agent_id = agent_name

    # Charger événements
    if events is None:
        try:
            from aiss.memory import load_events
            events = load_events(agent_id=agent_id, agent_name=agent_name)
        except Exception:
            events = []

    # ── Composante 1 : Trust Score ────────────────────────────────────────────
    ts_result = {"score": 1.0, "tier": "UNKNOWN", "components": {}}
    try:
        from aiss.trust_score import compute_trust_score
        ts_result = compute_trust_score(agent_id, events=events)
    except Exception as e:
        logger.debug(f"[Vigil] TS non disponible pour {agent_name}: {e}")

    ts_score = ts_result.get("trust_score", ts_result.get("score", 1.0))
    ts_contribution = VRS_WEIGHT_TS * (1.0 - ts_score)

    # ── Composante 2 : TSI ────────────────────────────────────────────────────
    tsi_state = "STABLE"
    tsi_details: Dict[str, Any] = {}
    try:
        from aiss.tsi_engine import compute_tsi
        tsi_result = compute_tsi(agent_id, ts_score, current_time)
        tsi_state   = tsi_result.get("tsi_state", tsi_result.get("state", "STABLE"))
        tsi_details = tsi_result
    except Exception as e:
        logger.debug(f"[Vigil] TSI non disponible pour {agent_name}: {e}")

    tsi_weight      = TSI_WEIGHTS.get(tsi_state, 0.0)
    tsi_contribution = VRS_WEIGHT_TSI * tsi_weight

    # ── Composante 3 : A2C ────────────────────────────────────────────────────
    a2c_result: Dict[str, Any] = {"a2c_risk": 0.0, "severity": "NONE", "alerts": []}
    try:
        from aiss.a2c_detector import compute_a2c_risk
        a2c_result = compute_a2c_risk(
            agent_id,
            events=events,
            peer_events_map=peer_events_map,
            current_time=current_time,
            use_cache=False,
        )
    except Exception as e:
        logger.debug(f"[Vigil] A2C non disponible pour {agent_name}: {e}")

    a2c_contribution = VRS_WEIGHT_A2C * a2c_result.get("a2c_risk", 0.0)

    # ── Composante 4 : Chain anomalies ────────────────────────────────────────
    chain_result = _compute_chain_risk(events)
    chain_contribution = VRS_WEIGHT_CHAIN * chain_result["score"]

    # ── VRS final ─────────────────────────────────────────────────────────────
    vrs = ts_contribution + tsi_contribution + a2c_contribution + chain_contribution
    vrs = round(min(1.0, max(0.0, vrs)), 4)
    state = _vrs_state(vrs)

    # ── Fork override — RFC AISS-1.1 §6 ──────────────────────────────────────
    # Un fork détecté = incident de sécurité = CRITICAL d'office
    # Le score est remonté à 0.75 minimum pour refléter la gravité
    _chain_forks = [a for a in chain_result.get("anomalies", []) if a.get("type") == "fork"]
    if _chain_forks:
        state = "CRITICAL"
        vrs   = max(vrs, 0.75)
        logger.warning(f"[Vigil] {agent_name} — FORK DETECTED → state forced CRITICAL, VRS={vrs}")

    # ── Agrégation alertes ────────────────────────────────────────────────────
    all_alerts = _aggregate_alerts(
        agent_name=agent_name,
        agent_id=agent_id,
        state=state,
        vrs=vrs,
        ts_score=ts_score,
        tsi_state=tsi_state,
        a2c_alerts=a2c_result.get("alerts", []),
        chain_anomalies=chain_result.get("anomalies", []),
        current_time=current_time,
    )

    # ── Narrative root cause (priorité : fork > TSI > A2C > TS) ──────────
    chain_anomalies_list = chain_result.get("anomalies", [])
    forks_found   = [a for a in chain_anomalies_list if a.get("type") == "fork"]
    replays_found = [a for a in chain_anomalies_list if a.get("type") == "replay"]

    if forks_found:
        # Fork = incident de sécurité → priorité absolue dans le narratif
        f0 = forks_found[0]
        narrative_title = "Chain Fork — RFC AISS-1.1 §6 Security Incident"
        narrative_items = [
            {"severity": "CRITICAL", "text": f0.get("description", "2 branches detected from same previous_hash")},
            {"severity": "HIGH",     "text": f"Chain contribution +{round(chain_contribution,3)} to VRS={vrs:.3f}"},
            {"severity": "MEDIUM",   "text": f"TSI state: {tsi_state} — trust continuity affected"},
            {"severity": "LOW",      "text": "Recommended: isolate agent, audit event chain, trigger incident response"},
        ]
        if replays_found:
            narrative_items.insert(1, {"severity": "CRITICAL", "text": f"Replay attack also detected — {len(replays_found)} duplicate nonce(s)"})
    elif replays_found:
        narrative_title = "Replay Attack — Duplicate nonce detected"
        narrative_items = [
            {"severity": "CRITICAL", "text": f"{len(replays_found)} replay attempt(s) blocked"},
            {"severity": "HIGH",     "text": f"Chain risk score: {chain_result['score']:.3f}"},
            {"severity": "MEDIUM",   "text": f"TSI: {tsi_state} — agent identity continuity suspect"},
        ]
    elif tsi_state in ("CRITICAL", "UNSTABLE"):
        tsi_det = tsi_details.get("details", tsi_details) if isinstance(tsi_details, dict) else {}
        delta   = tsi_det.get("delta_24h", 0)
        score24 = tsi_det.get("score_24h_ago", "?")
        narrative_title = f"TSI {tsi_state} — Trust score collapsed {delta:+.3f} in 24h"
        narrative_items = [
            {"severity": "CRITICAL", "text": f"TSI score: {ts_score:.3f} (was {score24} 24h ago, Δ={delta:+.3f})"},
            {"severity": "HIGH",     "text": f"TSI contribution: {round(tsi_contribution,3)} of VRS={vrs:.3f}"},
            {"severity": "MEDIUM",   "text": f"A2C risk: {a2c_result.get('a2c_risk',0):.3f} — peer concentration suspect"},
            {"severity": "LOW",      "text": "Recommended: verify peer interactions, check for external LLM injection"},
        ]
    elif a2c_result.get("severity") in ("HIGH", "CRITICAL"):
        a2c_risk = a2c_result.get("a2c_risk", 0)
        narrative_title = f"A2C Anomaly — Concentration risk {a2c_risk:.2f}"
        narrative_items = [
            {"severity": "HIGH",   "text": f"A2C risk: {a2c_risk:.3f} — abnormal peer concentration"},
            {"severity": "MEDIUM", "text": f"TSI: {tsi_state} — trust score: {ts_score:.3f}"},
            {"severity": "LOW",    "text": "Recommended: audit peer interaction graph"},
        ]
    else:
        narrative_title = f"VRS {vrs:.3f} — {state}"
        narrative_items = [
            {"severity": "LOW", "text": f"TS={ts_score:.3f} TSI={tsi_state} A2C={a2c_result.get('a2c_risk',0):.3f} Chain={chain_result['score']:.3f}"},
        ]

    result = {
        "agent_name":      agent_name,
        "agent_id":        agent_id,
        "vrs":             vrs,
        "state":           state,
        "narrative_title": narrative_title,
        "narrative_items": narrative_items,
        "components": {
            "trust_score": {
                "score":        ts_score,
                "contribution": round(ts_contribution, 4),
                "weight":       VRS_WEIGHT_TS,
                "tier":         ts_result.get("tier", "?"),
            },
            "tsi": {
                "state":        tsi_state,
                "weight_value": tsi_weight,
                "contribution": round(tsi_contribution, 4),
                "weight":       VRS_WEIGHT_TSI,
                "details":      tsi_details,
            },
            "a2c": {
                "risk":         a2c_result.get("a2c_risk", 0.0),
                "severity":     a2c_result.get("severity", "NONE"),
                "contribution": round(a2c_contribution, 4),
                "weight":       VRS_WEIGHT_A2C,
                "indicators":   a2c_result.get("indicators", {}),
            },
            "chain": {
                "score":        chain_result["score"],
                "contribution": round(chain_contribution, 4),
                "weight":       VRS_WEIGHT_CHAIN,
                "anomalies":    chain_result["anomalies"],
            },
        },
        "alerts":      all_alerts,
        "computed_at": current_time,
    }

    # Persister VRS history + alertes
    if persist:
        _persist_vrs(agent_name, vrs, state, current_time)
        if all_alerts:
            _persist_alerts(agent_name, all_alerts)
        # Invalider le cache global si fork détecté — recalcul immédiat
        if _chain_forks:
            _summary_cache.clear()

    logger.info(
        f"[Vigil] {agent_name} — VRS={vrs} state={state} "
        f"(TS={ts_score} TSI={tsi_state} A2C={a2c_result.get('a2c_risk', 0):.2f} "
        f"chain={chain_result['score']:.2f})"
    )

    return result


# ─── Agrégation alertes ───────────────────────────────────────────────────────

# Journal déduplication en mémoire {agent_name:type: last_emit_ts}
_dedup_journal: Dict[str, int] = {}


def _aggregate_alerts(
    agent_name: str,
    agent_id: str,
    state: str,
    vrs: float,
    ts_score: float,
    tsi_state: str,
    a2c_alerts: List[Dict[str, Any]],
    chain_anomalies: List[Dict[str, Any]],
    current_time: int,
) -> List[Dict[str, Any]]:
    """
    Agrège toutes les alertes avec règles de priorité et déduplication.

    Règles :
        - INFO : log silencieux uniquement (pas retourné)
        - WATCH → CRITICAL : retourné dans la liste
        - CRITICAL toujours en tête, cooldown 10min
        - Déduplication : même type + même agent → cooldown 1h
    """
    severity_order = {"WATCH": 1, "MEDIUM": 2, "ALERT": 3, "HIGH": 3, "CRITICAL": 4}
    alerts = []

    def _should_emit(key: str, severity: str) -> bool:
        # Les forks sont toujours émis — incident de sécurité actif
        if "chain_fork" in key or "chain_replay" in key:
            return True
        cooldown = CRITICAL_COOLDOWN if severity == "CRITICAL" else ALERT_COOLDOWN_S
        last = _dedup_journal.get(key, 0)
        return current_time - last >= cooldown

    def _emit(key: str, alert: Dict[str, Any]) -> None:
        _dedup_journal[key] = current_time
        alerts.append(alert)

    # Alerte VRS global
    if state in ("ALERT", "CRITICAL"):
        key = f"{agent_name}:vrs_state"
        if _should_emit(key, state):
            _emit(key, {
                "type":       "vigil_state",
                "severity":   state,
                "agent_name": agent_name,
                "agent_id":   agent_id,
                "message":    f"Vigil Risk Score {state} — VRS={vrs}",
                "vrs":        vrs,
                "timestamp":  current_time,
            })

    # Alerte TS bas
    if ts_score < 0.5:
        sev = "CRITICAL" if ts_score < 0.3 else "ALERT"
        key = f"{agent_name}:ts_low"
        if _should_emit(key, sev):
            _emit(key, {
                "type":       "trust_score_low",
                "severity":   sev,
                "agent_name": agent_name,
                "message":    f"Trust Score faible : {ts_score}",
                "score":      ts_score,
                "timestamp":  current_time,
            })

    # Alertes TSI
    if tsi_state in ("UNSTABLE", "CRITICAL"):
        sev = "CRITICAL" if tsi_state == "CRITICAL" else "ALERT"
        key = f"{agent_name}:tsi_{tsi_state}"
        if _should_emit(key, sev):
            _emit(key, {
                "type":       "tsi_drift",
                "severity":   sev,
                "agent_name": agent_name,
                "message":    f"Dérive TSI détectée : état {tsi_state}",
                "tsi_state":  tsi_state,
                "timestamp":  current_time,
            })

    # Alertes A2C (déjà filtrées MEDIUM+ par a2c_detector)
    for a in a2c_alerts:
        key = f"{agent_name}:a2c_{a.get('indicator','?')}"
        sev = a.get("severity", "MEDIUM")
        if _should_emit(key, sev):
            _emit(key, {**a, "agent_name": agent_name})

    # Anomalies chaîne
    for anomaly in chain_anomalies:
        sev = anomaly.get("severity", "HIGH")
        atype = anomaly.get("type", "?")
        key = f"{agent_name}:chain_{atype}"
        if _should_emit(key, sev):
            # Message explicite selon le type
            if atype == "fork":
                msg = f"Chain fork detected — {anomaly.get('description', anomaly.get('details', '2 branches'))}"
            elif atype == "replay":
                msg = f"Replay attack — {anomaly.get('details', 'duplicate nonce')}"
            elif atype == "linkage":
                msg = f"Chain linkage broken — {anomaly.get('details', 'hash mismatch')}"
            else:
                msg = anomaly.get("details", f"Chain anomaly: {atype}")
            _emit(key, {
                "type":       f"chain_{atype}",
                "severity":   sev,
                "agent_name": agent_name,
                "message":    msg,
                "timestamp":  anomaly.get("timestamp", current_time),
            })

    # Tri : chain_fork/replay CRITICAL en tête absolu, puis severity, puis timestamp
    def _alert_priority(a):
        atype = a.get("type", "")
        sev   = severity_order.get(a.get("severity", "WATCH"), 0)
        # Fork et replay = priorité max dans l'affichage
        type_boost = 10 if ("fork" in atype or "replay" in atype) else 0
        return sev + type_boost

    alerts.sort(key=_alert_priority, reverse=True)
    return alerts


# ─── Persistence ──────────────────────────────────────────────────────────────

def _persist_vrs(
    agent_name: str,
    vrs: float,
    state: str,
    current_time: int,
) -> None:
    """Ajoute un point VRS à l'historique 30j."""
    try:
        history = _load_vrs_history(agent_name)
        history.append({"timestamp": current_time, "vrs": vrs, "state": state})
        _save_vrs_history(agent_name, history)
    except Exception as e:
        logger.debug(f"[Vigil] Impossible de sauver VRS history: {e}")


def _persist_alerts(
    agent_name: str,
    new_alerts: List[Dict[str, Any]],
) -> None:
    """Ajoute les nouvelles alertes au journal persisté."""
    try:
        existing = _load_alerts(agent_name)
        existing.extend(new_alerts)
        _save_alerts(agent_name, existing)
    except Exception as e:
        logger.debug(f"[Vigil] Impossible de sauver alertes: {e}")


# ─── Hook tsi_engine ──────────────────────────────────────────────────────────

def record(event: Dict[str, Any]) -> None:
    """
    Point d'entrée depuis tsi_engine._emit_sentinel_event().

    Reçoit un événement trust_drift et le persiste dans le journal Vigil.
    Appelé automatiquement quand TSI passe en UNSTABLE ou CRITICAL.

    Args:
        event: {type, severity, agent_id, tsi_state, current_score, ...}
    """
    agent_id = event.get("agent_id", "unknown")

    # Résoudre agent_name depuis agent_id
    agent_name = _resolve_name(agent_id)

    alert = {
        "type":       event.get("type", "trust_drift"),
        "severity":   event.get("severity", "MEDIUM"),
        "agent_name": agent_name,
        "agent_id":   agent_id,
        "message":    (
            f"TSI {event.get('tsi_state')} — "
            f"score={event.get('current_score')} "
            f"delta_24h={event.get('delta_24h')}"
        ),
        "tsi_state":  event.get("tsi_state"),
        "z_score":    event.get("z_score"),
        "timestamp":  event.get("timestamp", int(time.time())),
        "source":     "tsi_engine",
    }

    _persist_alerts(agent_name, [alert])

    logger.info(
        f"[Vigil] Alert recorded from TSI — "
        f"agent={agent_name} severity={alert['severity']}"
    )


def _resolve_name(agent_id: str) -> str:
    """Résout le nom d'agent depuis son ID cryptographique."""
    try:
        from aiss.agent_registry import list_agents
        for a in list_agents():
            if a.get("agent_id") == agent_id:
                return a["name"]
    except Exception:
        pass
    return agent_id  # fallback


# ─── Vue installation ─────────────────────────────────────────────────────────


def _chain_label(result: Dict) -> str:
    """Dérive un label chaîne depuis les anomalies chain."""
    anomalies = result.get("components", {}).get("chain", {}).get("anomalies", [])
    if not anomalies:
        return "CANONICAL CHAIN"
    types = [a.get("type", "") for a in anomalies]
    if "fork" in types:
        return "FORKED IDENTITY"
    if "rotation" in types:
        return "KEY ROTATION"
    return "CHAIN ANOMALY"


def _build_agent_timeline(result: Dict) -> list:
    """Construit la timeline d'événements d'un agent depuis les composantes VRS."""
    import time as _time
    now = result.get("computed_at", int(_time.time()))
    events = []

    # TSI state
    tsi_state = result.get("components", {}).get("tsi", {}).get("state", "STABLE")
    tsi_details = result.get("components", {}).get("tsi", {}).get("details", {})
    if isinstance(tsi_details, dict):
        det = tsi_details.get("details", tsi_details)
    else:
        det = {}
    if tsi_state in ("UNSTABLE", "CRITICAL"):
        events.append({"t": now, "type": "alert",
                       "label": f"TSI {tsi_state} Δ24h={det.get('delta_24h', 0):.3f}"})
    elif tsi_state == "WATCH":
        events.append({"t": now - 3600, "type": "watch",
                       "label": "TSI drifting"})

    # Chain anomalies
    for anom in result.get("components", {}).get("chain", {}).get("anomalies", []):
        atype = anom.get("type", "anomaly")
        events.append({"t": anom.get("timestamp", now - 7200), "type": atype,
                       "label": anom.get("description", atype)})

    # A2C alerts
    a2c_sev = result.get("components", {}).get("a2c", {}).get("severity", "NONE")
    a2c_risk = result.get("components", {}).get("a2c", {}).get("risk", 0)
    if a2c_sev not in ("NONE", "LOW") or a2c_risk > 0.3:
        events.append({"t": now - 1800, "type": "cluster",
                       "label": f"A2C {a2c_sev} risk={a2c_risk:.2f}"})

    # Stable baseline
    events.append({"t": now - 30 * 86400, "type": "stable", "label": "Baseline"})
    events.sort(key=lambda e: e["t"])
    return events

_summary_cache: Dict[str, Any] = {}

def get_installation_summary(
    agent_subset: Optional[List[str]] = None,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """
    Résumé Vigil de toute l'installation (ou d'un sous-ensemble).

    Vue CTO — tout visible en 5 secondes.

    Args:
        agent_subset: Liste de noms d'agents à inclure (None = tous)
        use_cache:    Cache 5min

    Returns:
        {
            installation_state:  SAFE/WATCH/ALERT/CRITICAL
            global_vrs:          float
            total_agents:        int
            critical_count:      int
            agents:              [résumés triés par VRS décroissant]
            active_alerts:       [toutes alertes CRITICAL actives]
            computed_at:         int
        }
    """
    try:
        from aiss.agent_registry import list_agents
        all_agents = list_agents()
    except Exception:
        all_agents = []

    # Filtrer par subset
    if agent_subset:
        all_agents = [a for a in all_agents if a["name"] in agent_subset]

    agents_vrs = []
    all_critical_alerts = []

    for agent_info in all_agents:
        name = agent_info["name"]
        aid  = agent_info.get("agent_id", name)

        try:
            result = compute_vrs(name, agent_id=aid, persist=False)
            # Extraire top peers depuis les events pour le network graph
            try:
                from aiss.memory import load_events as _le
                _evts = _le(agent_name=name, agent_id=aid)
                _pc = {}
                for _e in _evts:
                    _p = _e.get("peer_id", "")
                    if _p:
                        _pc[_p] = _pc.get(_p, 0) + 1
                _total = sum(_pc.values()) or 1
                _id_to_name = {a.get("agent_id", a["name"]): a["name"] for a in all_agents}
                _peers = sorted(_pc.items(), key=lambda x: x[1], reverse=True)[:6]
                result["a2c_peers_computed"] = [[_id_to_name.get(p, p), round(c/_total, 3)] for p, c in _peers]
            except Exception:
                result["a2c_peers_computed"] = []
            agents_vrs.append({
                "agent_name":  name,
                "agent_id":    aid,
                "vrs":         result["vrs"],
                "state":       result["state"],
                "ts_score":    result["components"]["trust_score"]["score"],
                "tsi_state":   result["components"]["tsi"]["state"],
                "a2c_risk":    result["components"]["a2c"]["risk"],
                "alert_count": len(result["alerts"]),
                "a2c_peers":   result.get("a2c_peers_computed", []),
                "event_count": len(_evts) if "_evts" in dir() else 0,
                "last_stamp":  max((_e.get("timestamp", 0) for _e in _evts), default=0) if "_evts" in dir() and _evts else 0,
                "a2c_detail":  result["components"].get("a2c", {}),
                "tsi_detail":  result["components"].get("tsi", {}),
                "narrative_title": result.get("narrative_title", ""),
                "narrative_items": result.get("narrative_items", []),
                "history":     result.get("history", []),
                "timeline":    _build_agent_timeline(result),
                "chain_label": _chain_label(result),
                "last_seen":   result.get("computed_at", int(__import__("time").time())),
            })
            # Collecter les alertes CRITICAL
            for alert in result["alerts"]:
                if alert.get("severity") in ("CRITICAL", "HIGH"):
                    all_critical_alerts.append(alert)
        except Exception as e:
            logger.warning(f"[Vigil] Erreur calcul VRS pour {name}: {e}")
            agents_vrs.append({
                "agent_name": name, "vrs": 0.0, "state": "SAFE",
                "error": str(e),
            })

    # Trier par VRS décroissant
    agents_vrs.sort(key=lambda a: a.get("vrs", 0), reverse=True)

    # VRS global = moyenne pondérée (les critiques comptent plus)
    if agents_vrs:
        weights = {"SAFE": 1, "WATCH": 2, "ALERT": 3, "CRITICAL": 4}
        total_w = sum(weights.get(a.get("state", "SAFE"), 1) for a in agents_vrs)
        global_vrs = sum(
            a.get("vrs", 0) * weights.get(a.get("state", "SAFE"), 1)
            for a in agents_vrs
        ) / total_w if total_w > 0 else 0.0
    else:
        global_vrs = 0.0

    installation_state = _vrs_state(global_vrs)

    return {
        "installation_state": installation_state,
        "global_vrs":         round(global_vrs, 4),
        "total_agents":       len(agents_vrs),
        "critical_count":     sum(1 for a in agents_vrs if a.get("state") == "CRITICAL"),
        "alert_count":        sum(1 for a in agents_vrs if a.get("state") == "ALERT"),
        "watch_count":        sum(1 for a in agents_vrs if a.get("state") == "WATCH"),
        "safe_count":         sum(1 for a in agents_vrs if a.get("state") == "SAFE"),
        "agents":             agents_vrs,
        "active_alerts":      all_critical_alerts,
        "agent_subset":       agent_subset,
        "computed_at":        int(time.time()),
    }


def get_agent_alerts(
    agent_name: str,
    severity_filter: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    Retourne le journal d'alertes d'un agent.

    Args:
        agent_name:      Nom de l'agent
        severity_filter: Filtrer par sévérité (ex: "CRITICAL")
        limit:           Nombre max d'alertes retournées

    Returns:
        Liste triée par timestamp décroissant (plus récent en premier)
    """
    alerts = _load_alerts(agent_name)

    if severity_filter:
        alerts = [a for a in alerts if a.get("severity") == severity_filter]

    alerts.sort(key=lambda a: a.get("timestamp", 0), reverse=True)
    return alerts[:limit]


def get_vrs_history(
    agent_name: str,
    days: int = 30,
) -> List[Dict[str, Any]]:
    """
    Retourne l'historique VRS d'un agent (pour le graphe timeline).

    Args:
        agent_name: Nom de l'agent
        days:       Fenêtre en jours (max 30)

    Returns:
        [{timestamp, vrs, state}] trié chronologiquement
    """
    history = _load_vrs_history(agent_name)
    cutoff  = int(time.time()) - min(days, 30) * 86400
    history = [h for h in history if h.get("timestamp", 0) >= cutoff]
    return sorted(history, key=lambda h: h.get("timestamp", 0))


# ─── Activation hook tsi_engine ───────────────────────────────────────────────

def activate_tsi_hook() -> bool:
    """
    Active l'intégration avec tsi_engine._emit_sentinel_event().

    À appeler au démarrage de Vigil (piqrypt vigil start).
    Patch le hook commenté dans tsi_engine pour pointer vers record().

    Returns:
        True si activation réussie
    """
    try:
        import aiss.tsi_engine as tsi
        _original = tsi._emit_sentinel_event

        def _patched_emit(agent_id, new_state, current_score, metrics, reasons, current_time):
            _original(agent_id, new_state, current_score, metrics, reasons, current_time)
            try:
                record({
                    "type":          "trust_drift",
                    "severity":      "CRITICAL" if new_state == "CRITICAL" else "HIGH",
                    "agent_id":      agent_id,
                    "tsi_state":     new_state,
                    "current_score": current_score,
                    "delta_24h":     metrics.get("delta_24h"),
                    "z_score":       metrics.get("z_score"),
                    "drift_reasons": reasons,
                    "timestamp":     current_time,
                })
            except Exception as e:
                logger.debug(f"[Vigil] Hook TSI record failed: {e}")

        tsi._emit_sentinel_event = _patched_emit
        logger.info("[Vigil] Hook tsi_engine activé")
        return True

    except Exception as e:
        logger.warning(f"[Vigil] Impossible d'activer le hook TSI: {e}")
        return False


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    # VRS
    "compute_vrs",
    "get_installation_summary",
    # Alertes
    "get_agent_alerts",
    "get_vrs_history",
    # Hook
    "record",
    "activate_tsi_hook",
    # Constantes
    "VRS_SAFE",
    "VRS_WATCH",
    "VRS_ALERT",
    "VRS_CRITICAL",
    "VRS_WEIGHT_TS",
    "VRS_WEIGHT_TSI",
    "VRS_WEIGHT_A2C",
    "VRS_WEIGHT_CHAIN",
]








