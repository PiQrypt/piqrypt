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
TSI — Trust Stability Index — PiQrypt v1.6.0

Le TS est un état.
Le TSI est une dynamique.

Mesure :
    - Δ court terme (24h)
    - Δ moyen terme (7j)
    - Variance sur fenêtre glissante 30j
    - Z-score par rapport à la baseline de l'agent

États :
    STABLE    → Score dans la normale
    WATCH     → Légère dérive, surveillance renforcée
    UNSTABLE  → Dérive significative, alerte
    CRITICAL  → Dérive sévère ou chute brutale, action recommandée

Transitions :
    STABLE   ──(Δ24h < -0.08)──→ WATCH
    WATCH    ──(Δ24h < -0.15)──→ UNSTABLE
    WATCH    ──(z-score > 3σ)──→ UNSTABLE
    UNSTABLE ─(persistance)───→ CRITICAL
    *        ──(retour norme)──→ STABLE

Stockage :
    ~/.piqrypt/tsi/<agent_id>.json
    Format : liste de snapshots {timestamp, score}
    Fenêtre glissante : 30 jours (anciens snapshots purgés)

Hook Sentinel v1.7.0 :
    Quand tsi_state → UNSTABLE ou CRITICAL,
    anomaly_monitor reçoit un événement trust_drift.
    En v1.6.0 : l'événement est loggé localement (prêt pour v1.7.0).
"""

import json
import time
import statistics
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Constantes ───────────────────────────────────────────────────────────────
PIQRYPT_DIR = Path.home() / ".piqrypt"
TSI_DIR = PIQRYPT_DIR / "tsi"

WINDOW_DAYS = 30              # Fenêtre glissante baseline
DRIFT_Z_THRESHOLD = 3.0       # z-score > 3σ → drift
DRIFT_DELTA_24H_WATCH = -0.08   # Δ24h < -0.08 → WATCH
DRIFT_DELTA_24H_UNSTABLE = -0.15  # Δ24h < -0.15 → UNSTABLE
DRIFT_VARIANCE_MULTIPLIER = 2.5   # std > 2.5 × historical_std → variance alert
CRITICAL_PERSISTENCE_HOURS = 48   # UNSTABLE depuis > 48h → CRITICAL

TSI_STATES = ("STABLE", "WATCH", "UNSTABLE", "CRITICAL")


# ─── Stockage baseline ────────────────────────────────────────────────────────

def _tsi_path(agent_id: str) -> Path:
    """Chemin du fichier TSI pour un agent."""
    safe_id = agent_id.replace("/", "_").replace("\\", "_")[:64]
    return TSI_DIR / f"{safe_id}.json"


def _load_baseline(agent_id: str) -> Dict[str, Any]:
    """Charge la baseline TSI d'un agent."""
    path = _tsi_path(agent_id)
    if not path.exists():
        return {"snapshots": [], "last_state": "STABLE", "unstable_since": None}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {"snapshots": [], "last_state": "STABLE", "unstable_since": None}


def _save_baseline(agent_id: str, data: Dict[str, Any]) -> None:
    """Sauvegarde la baseline TSI d'un agent."""
    TSI_DIR.mkdir(parents=True, exist_ok=True)
    path = _tsi_path(agent_id)
    try:
        path.write_text(json.dumps(data, indent=2))
        path.chmod(0o600)
    except Exception as e:
        logger.warning(f"[TSI] Cannot save baseline for {agent_id}: {e}")


def _purge_old_snapshots(
    snapshots: List[Dict[str, Any]],
    current_time: int,
    window_days: int = WINDOW_DAYS,
) -> List[Dict[str, Any]]:
    """Supprime les snapshots hors de la fenêtre glissante."""
    cutoff = current_time - window_days * 86400
    return [s for s in snapshots if s["timestamp"] >= cutoff]


# ─── Statistiques baseline ────────────────────────────────────────────────────

def _baseline_stats(
    snapshots: List[Dict[str, Any]],
) -> Tuple[Optional[float], Optional[float]]:
    """
    Retourne (mean, std) des scores dans la baseline.
    (None, None) si moins de 2 snapshots.
    """
    scores = [s["score"] for s in snapshots]
    if len(scores) < 2:
        return (scores[0] if scores else None), None
    return statistics.mean(scores), statistics.stdev(scores)


def _score_at_age(
    snapshots: List[Dict[str, Any]],
    current_time: int,
    max_age_seconds: int,
) -> Optional[float]:
    """
    Retourne le score le plus récent qui date d'au moins max_age_seconds.
    Utilisé pour calculer Δ24h et Δ7j.
    """
    target = current_time - max_age_seconds
    candidates = [s for s in snapshots if s["timestamp"] <= target]
    if not candidates:
        return None
    # Le plus proche du target dans le passé
    closest = max(candidates, key=lambda s: s["timestamp"])
    return closest["score"]


# ─── Détection de dérive ──────────────────────────────────────────────────────

def _detect_drift(
    current_score: float,
    snapshots: List[Dict[str, Any]],
    current_time: int,
    last_state: str,
    unstable_since: Optional[int],
) -> Tuple[str, List[str], Dict[str, Any]]:
    """
    Détermine l'état TSI et les raisons de dérive.

    Returns:
        (new_state, reasons, metrics_dict)
    """
    reasons = []
    metrics: Dict[str, Any] = {}

    mean, std = _baseline_stats(snapshots)
    delta_24h = None
    delta_7d = None
    z_score = None

    # Δ24h
    score_24h_ago = _score_at_age(snapshots, current_time, 86400)
    if score_24h_ago is not None:
        delta_24h = round(current_score - score_24h_ago, 4)
        metrics["delta_24h"] = delta_24h

    # Δ7j
    score_7d_ago = _score_at_age(snapshots, current_time, 7 * 86400)
    if score_7d_ago is not None:
        delta_7d = round(current_score - score_7d_ago, 4)
        metrics["delta_7d"] = delta_7d

    # Z-score
    if mean is not None and std is not None and std > 0:
        z_score = round(abs(current_score - mean) / std, 4)
        metrics["z_score"] = z_score
        if z_score > DRIFT_Z_THRESHOLD:
            reasons.append(f"Z-score={z_score:.2f} > {DRIFT_Z_THRESHOLD}σ")

    metrics["baseline_mean"] = round(mean, 4) if mean is not None else None
    metrics["baseline_std"]  = round(std, 4) if std is not None else None

    # Détermination de l'état
    # CRITICAL : UNSTABLE depuis trop longtemps
    if (last_state == "UNSTABLE" and unstable_since is not None
            and (current_time - unstable_since) > CRITICAL_PERSISTENCE_HOURS * 3600):
        reasons.append(
            f"UNSTABLE depuis {(current_time - unstable_since) // 3600}h "
            f"> {CRITICAL_PERSISTENCE_HOURS}h"
        )
        return "CRITICAL", reasons, metrics

    # UNSTABLE : chute rapide 24h ou z-score fort
    if (delta_24h is not None and delta_24h < DRIFT_DELTA_24H_UNSTABLE):
        reasons.append(f"Δ24h={delta_24h:.3f} < {DRIFT_DELTA_24H_UNSTABLE}")
        return "UNSTABLE", reasons, metrics

    if z_score is not None and z_score > DRIFT_Z_THRESHOLD:
        return "UNSTABLE", reasons, metrics

    # WATCH : dérive légère
    if delta_24h is not None and delta_24h < DRIFT_DELTA_24H_WATCH:
        reasons.append(f"Δ24h={delta_24h:.3f} < {DRIFT_DELTA_24H_WATCH}")
        return "WATCH", reasons, metrics

    if (z_score is not None and z_score > DRIFT_Z_THRESHOLD * 0.6):
        reasons.append(f"Z-score={z_score:.2f} elevated")
        return "WATCH", reasons, metrics

    return "STABLE", reasons, metrics


# ─── Hook Sentinel v1.7.0 ─────────────────────────────────────────────────────

def _emit_sentinel_event(
    agent_id: str,
    new_state: str,
    current_score: float,
    metrics: Dict[str, Any],
    reasons: List[str],
    current_time: int,
) -> None:
    """
    Hook pour Sentinel v1.7.0.

    v1.6.0 : log local uniquement.
    v1.7.0 : anomaly_monitor.record() sera appelé ici.

    L'interface est déjà prête — aucune modification nécessaire en v1.7.0,
    il suffira d'importer anomaly_monitor.
    """
    if new_state not in ("UNSTABLE", "CRITICAL"):
        return

    severity_map = {"UNSTABLE": "MEDIUM", "CRITICAL": "HIGH"}

    _ = {
        "type":               "trust_drift",
        "severity":           severity_map.get(new_state, "MEDIUM"),
        "agent_id":           agent_id,
        "tsi_state":          new_state,
        "current_score":      current_score,
        "baseline_mean":      metrics.get("baseline_mean"),
        "delta_24h":          metrics.get("delta_24h"),
        "z_score":            metrics.get("z_score"),
        "drift_reasons":      reasons,
        "timestamp":          current_time,
        "recommended_action": "Vérifier les interactions et événements récents",
    }

    # v1.6.0 : log local
    logger.warning(
        f"[TSI] {new_state} — agent={agent_id} "
        f"score={current_score} delta_24h={metrics.get('delta_24h')} "
        f"reasons={reasons}"
    )

    # Hook v1.7.0 — décommenter quand anomaly_monitor disponible :
    # try:
    #     from aiss.anomaly_monitor import AnomalyMonitor
    #     AnomalyMonitor.record(event)
    # except ImportError:
    #     pass


# ─── Compute TSI — API principale ─────────────────────────────────────────────

def compute_tsi(
    agent_id: str,
    current_score: Optional[float] = None,
    persist: bool = True,
    current_time: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Calcule le TSI (Trust Stability Index) pour un agent.

    Charge ou calcule le TS courant, compare à la baseline historique,
    détermine l'état de dérive, met à jour la baseline.

    Args:
        agent_id:      ID de l'agent
        current_score: TS courant (calcule via trust_score si None)
        persist:       Sauvegarder le snapshot dans la baseline
        current_time:  Unix timestamp courant

    Returns:
        Dict complet avec tsi_state, métriques, baseline_stats

    Example:
        >>> tsi = compute_tsi("pq_abc123...")
        >>> print(tsi["tsi_state"], tsi["delta_24h"])
        WATCH -0.08
    """
    if current_time is None:
        current_time = int(time.time())

    # Calculer le TS courant si non fourni
    if current_score is None:
        try:
            from aiss.trust_score import compute_trust_score
            ts_result = compute_trust_score(agent_id, current_time=current_time)
            current_score = ts_result["trust_score"]
        except Exception as e:
            logger.warning(f"[TSI] Cannot compute TS for {agent_id}: {e}")
            current_score = 1.0

    # Charger baseline
    data = _load_baseline(agent_id)
    snapshots = _purge_old_snapshots(
        data.get("snapshots", []), current_time
    )
    last_state = data.get("last_state", "STABLE")
    unstable_since = data.get("unstable_since")

    # Détecter la dérive
    new_state, reasons, metrics = _detect_drift(
        current_score, snapshots, current_time, last_state, unstable_since
    )

    # Gérer unstable_since
    if new_state in ("UNSTABLE", "CRITICAL") and last_state == "STABLE":
        unstable_since = current_time
    elif new_state == "STABLE":
        unstable_since = None

    # Émettre l'événement Sentinel si nécessaire
    if new_state != last_state and new_state in ("UNSTABLE", "CRITICAL"):
        _emit_sentinel_event(
            agent_id, new_state, current_score, metrics, reasons, current_time
        )

    # Ajouter le snapshot courant
    new_snapshot = {"timestamp": current_time, "score": current_score}
    snapshots.append(new_snapshot)

    # Persister
    if persist:
        _save_baseline(agent_id, {
            "snapshots":      snapshots,
            "last_state":     new_state,
            "unstable_since": unstable_since,
            "last_updated":   current_time,
        })

    mean, std = _baseline_stats(snapshots)

    return {
        "agent_id":        agent_id,
        "tsi_state":       new_state,
        "tsi":             new_state,   # alias court pour compat tests et consumers
        "current_score":   current_score,
        "baseline_mean":   round(mean, 4) if mean is not None else None,
        "baseline_std":    round(std, 4) if std is not None else None,
        "delta_24h":       metrics.get("delta_24h"),
        "delta_7d":        metrics.get("delta_7d"),
        "z_score":         metrics.get("z_score"),
        "drift_reasons":   reasons,
        "snapshot_count":  len(snapshots),
        "window_days":     WINDOW_DAYS,
        "computed_at":     current_time,
        "unstable_since":  unstable_since,
    }


# ─── Historique TSI ───────────────────────────────────────────────────────────

def get_tsi_history(
    agent_id: str,
    days: int = 30,
    current_time: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Retourne l'historique des snapshots TSI d'un agent.

    Args:
        agent_id: ID de l'agent
        days:     Nombre de jours d'historique (défaut 30)

    Returns:
        Liste de snapshots triés chronologiquement
        [{timestamp, score, date_str}, ...]
    """
    if current_time is None:
        current_time = int(time.time())

    data = _load_baseline(agent_id)
    snapshots = _purge_old_snapshots(
        data.get("snapshots", []), current_time, window_days=days
    )

    # Enrichir avec date lisible
    result = []
    for s in sorted(snapshots, key=lambda x: x["timestamp"]):
        import datetime
        dt = datetime.datetime.fromtimestamp(
            s["timestamp"], tz=datetime.timezone.utc
        )
        result.append({
            "timestamp": s["timestamp"],
            "score":     s["score"],
            "date":      dt.strftime("%Y-%m-%d"),
        })

    return result


def get_tsi_summary(agent_id: str) -> Dict[str, Any]:
    """
    Résumé TSI compact — utile pour le CLI et le handshake signal.
    """
    data = _load_baseline(agent_id)
    snapshots = _purge_old_snapshots(
        data.get("snapshots", []), int(time.time())
    )
    mean, std = _baseline_stats(snapshots)
    last_state = data.get("last_state", "STABLE")
    unstable_since = data.get("unstable_since")

    return {
        "agent_id":       agent_id,
        "last_state":     last_state,
        "baseline_mean":  round(mean, 4) if mean is not None else None,
        "baseline_std":   round(std, 4) if std is not None else None,
        "snapshot_count": len(snapshots),
        "unstable_since": unstable_since,
    }


def reset_tsi_baseline(agent_id: str) -> None:
    """
    Réinitialise la baseline TSI d'un agent.
    À utiliser après une migration ou une rotation planifiée majeure.
    """
    path = _tsi_path(agent_id)
    if path.exists():
        path.unlink()
    logger.info(f"[TSI] Baseline réinitialisée pour {agent_id}")


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    "compute_tsi",
    "get_tsi_history",
    "get_tsi_summary",
    "reset_tsi_baseline",
    "TSI_STATES",
    "WINDOW_DAYS",
    "DRIFT_Z_THRESHOLD",
    "DRIFT_DELTA_24H_WATCH",
    "DRIFT_DELTA_24H_UNSTABLE",
]
