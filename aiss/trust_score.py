"""
Trust Score (TS) — PiQrypt v1.6.0

Indicateur structurel de cohérence, stabilité et continuité cryptographique
d'un agent autonome. Score normalisé [0, 1].

Formule :
    TS = w_I×I + w_V×V_t + w_D×D_t + w_F×F + w_R×R

Composantes :
    I   — Integrity          : continuité cryptographique de la chaîne
    V_t — Verified Interactions : ratio interactions vérifiées, time-weighted
    D_t — Diversity          : entropie Shannon des partenaires
    F   — Finalization       : taux TSA / RFC 3161
    R   — Rotation Health    : cohérence des rotations de clés

Philosophie :
    - Score = indicateur, jamais un gate
    - Déterministe : mêmes inputs → mêmes outputs
    - Audit-able : chaque composante traçable à des événements concrets
    - Local-first : aucune dépendance réseau

Hooks Sentinel (v1.7.0) :
    - get_a2c_risk() → None en v1.6.0, peuplé en v1.7.0
    - D_t.top_peer_ratio disponible pour a2c_detector.concentration_score
    - V_t.weighted_ratio disponible pour a2c_detector.entropy_drop
"""

import math
import time
from collections import Counter
from typing import Any, Dict, List, Optional

from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Poids par défaut ─────────────────────────────────────────────────────────
DEFAULT_WEIGHTS: Dict[str, float] = {
    "w_I": 0.30,
    "w_V": 0.25,
    "w_D": 0.15,
    "w_F": 0.15,
    "w_R": 0.15,
}

# ─── Seuils rotation (configurables) ─────────────────────────────────────────
ROTATION_MIN_INTERVAL = 7 * 86400    # < 7j = suspecte
ROTATION_MAX_INTERVAL = 365 * 86400  # > 365j = overdue

# ─── Demi-vie temporelle : 30 jours ───────────────────────────────────────────
_LAMBDA = math.log(2) / (30 * 86400)

# ─── Tiers ────────────────────────────────────────────────────────────────────
TIERS = [(0.95, "Elite"), (0.90, "A+"), (0.80, "A"), (0.70, "B"), (0.0, "At Risk")]


def _tier(score: float) -> str:
    for threshold, label in TIERS:
        if score >= threshold:
            return label
    return "At Risk"


# ─── Pondération temporelle ───────────────────────────────────────────────────

def temporal_weight(event_timestamp: int, current_time: int) -> float:
    """
    Décroissance exponentielle — demi-vie 30 jours.
        w(t) = e^(-λ × age)   λ = ln(2) / (30 × 86400)
    Exemples :
        aujourd'hui → 1.0  |  30j → 0.5  |  60j → 0.25  |  90j → 0.125
    """
    age = max(0, current_time - event_timestamp)
    return math.exp(-_LAMBDA * age)


# ─── I — Integrity ────────────────────────────────────────────────────────────

def compute_I(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Continuité cryptographique de la chaîne.

    I = 0.30 × hash_chain_valid
      + 0.25 × no_unresolved_forks
      + 0.25 × signatures_valid
      + 0.20 × key_rotation_valid
    """
    if not events:
        return {"score": 1.0, "components": {
            "hash_chain": 1.0, "no_forks": 1.0,
            "signatures": 1.0, "rotations": 1.0,
        }, "details": {"note": "Nouvel agent"}}

    # 1. Hash chain (0.30)
    try:
        from aiss.chain import verify_chain_linkage
        hash_chain_score = 1.0 if verify_chain_linkage(events) else 0.0
    except Exception:
        hash_chain_score = 0.5

    # 2. Forks non résolus (0.25)
    unresolved_count = 0
    try:
        from aiss.fork import find_forks
        forks = find_forks(events)
        unresolved_count = sum(1 for f in forks if not getattr(f, "resolved", False))
        fork_score = max(0.0, 1.0 - unresolved_count / 5.0)
    except Exception:
        fork_score = 1.0

    # 3. Signatures (0.25)
    total = len(events)
    signed = sum(1 for e in events if e.get("signature"))
    sig_score = signed / total if total else 1.0

    # 4. Rotations de clés attestées (0.20)
    rotations = [e for e in events
                 if e.get("payload", {}).get("event_type") == "key_rotation"]
    if not rotations:
        rotation_score = 1.0
        valid_rot = 0
    else:
        valid_rot = sum(
            1 for r in rotations
            if r.get("payload", {}).get("rotation_attestation")
            or r.get("payload", {}).get("attestation")
            or r.get("payload", {}).get("prev_agent_signature")
        )
        rotation_score = valid_rot / len(rotations)

    I_score = round(min(1.0, max(0.0,
        hash_chain_score * 0.30 + fork_score * 0.25
        + sig_score * 0.25 + rotation_score * 0.20
    )), 4)

    return {
        "score": I_score,
        "components": {
            "hash_chain": round(hash_chain_score, 4),
            "no_forks":   round(fork_score, 4),
            "signatures": round(sig_score, 4),
            "rotations":  round(rotation_score, 4),
        },
        "details": {
            "total_events":     total,
            "signed_events":    signed,
            "unresolved_forks": unresolved_count,
            "rotations_total":  len(rotations),
            "rotations_valid":  valid_rot,
        },
    }


# ─── V_t — Verified Interaction Ratio ────────────────────────────────────────

def compute_V_t(
    events: List[Dict[str, Any]],
    current_time: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Ratio interactions vérifiées, pondéré temporellement.

    V_t = Σ(verified × w(t)) / Σ(total_interactions × w(t))

    Non-discriminatoire : agents non-PiQrypt réduisent le ratio,
    ne sont pas pénalisés.
    """
    if current_time is None:
        current_time = int(time.time())

    a2a_types = {
        "a2a_handshake", "a2a_message",
        "a2a_handshake_complete", "external_interaction",
    }
    interactions = [e for e in events
                    if e.get("payload", {}).get("event_type") in a2a_types]

    if not interactions:
        return {"score": 1.0, "details": {
            "total_interactions": 0, "verified_interactions": 0,
            "note": "Aucune interaction A2A",
        }}

    numerator = denominator = 0.0
    verified_count = 0

    for e in interactions:
        w = temporal_weight(e.get("timestamp", current_time), current_time)
        denominator += w
        payload = e.get("payload", {})
        if (payload.get("peer_signature") or payload.get("verified")
                or payload.get("handshake_complete")):
            numerator += w
            verified_count += 1

    V_t = numerator / denominator if denominator > 0 else 1.0

    return {
        "score": round(min(1.0, max(0.0, V_t)), 4),
        "details": {
            "total_interactions":    len(interactions),
            "verified_interactions": verified_count,
            "weighted_ratio":        round(V_t, 4),
        },
    }


# ─── D_t — Diversity (Shannon Entropy) ───────────────────────────────────────

def compute_D_t(
    events: List[Dict[str, Any]],
    current_time: Optional[int] = None,
    window_days: int = 30,
) -> Dict[str, Any]:
    """
    Diversité des partenaires — entropie de Shannon normalisée.

    D_t = H / H_max

    Hook A2C v1.7.0 : top_peer_ratio disponible pour
    a2c_detector.concentration_score().
    """
    if current_time is None:
        current_time = int(time.time())

    window_sec = window_days * 86400
    a2a_types = {
        "a2a_handshake", "a2a_message",
        "a2a_handshake_complete", "external_interaction",
    }

    recent = [
        e for e in events
        if e.get("payload", {}).get("event_type") in a2a_types
        and current_time - e.get("timestamp", 0) < window_sec
    ]

    if not recent:
        return {"score": 1.0, "details": {
            "unique_peers": 0, "total_recent": 0,
            "entropy": 0.0, "top_peer_ratio": 0.0,
            "note": f"Aucune interaction dans les {window_days}j",
        }}

    peer_counts: Counter = Counter()
    for e in recent:
        payload = e.get("payload", {})
        peer_id = (payload.get("peer_agent_id")
                   or payload.get("peer_id")
                   or e.get("peer_agent_id", "unknown"))
        peer_counts[peer_id] += 1

    total = len(recent)
    unique = len(peer_counts)
    top_ratio = max(peer_counts.values()) / total

    if unique <= 1:
        return {"score": 0.0, "details": {
            "unique_peers": unique, "total_recent": total,
            "entropy": 0.0, "top_peer_ratio": top_ratio,
        }}

    entropy = -sum((c / total) * math.log2(c / total)
                   for c in peer_counts.values())
    max_entropy = math.log2(unique)
    D_t = entropy / max_entropy if max_entropy > 0 else 0.0

    return {
        "score": round(min(1.0, max(0.0, D_t)), 4),
        "details": {
            "unique_peers":   unique,
            "total_recent":   total,
            "entropy":        round(entropy, 4),
            "max_entropy":    round(max_entropy, 4),
            "top_peer_ratio": round(top_ratio, 4),  # Hook A2C v1.7.0
            "window_days":    window_days,
        },
    }


# ─── F — Finalization Reliability ────────────────────────────────────────────

def compute_F(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Taux d'événements finalisés avec preuve cryptographique externe (TSA / RFC 3161).

    F = finalized / eligible
    """
    if not events:
        return {"score": 1.0, "details": {"note": "Aucun événement"}}

    non_eligible = {"key_rotation", "genesis", "identity_created"}
    eligible = [e for e in events
                if e.get("payload", {}).get("event_type") not in non_eligible]

    if not eligible:
        return {"score": 1.0, "details": {
            "eligible_events": 0, "note": "Aucun événement éligible TSA",
        }}

    finalized = sum(
        1 for e in eligible
        if (e.get("tsa_token") or e.get("rfc3161_token")
            or e.get("payload", {}).get("tsa_token")
            or e.get("payload", {}).get("rfc3161_timestamp")
            or e.get("payload", {}).get("tsa_timestamp"))
    )
    F = finalized / len(eligible)

    return {
        "score": round(min(1.0, max(0.0, F)), 4),
        "details": {
            "eligible_events":  len(eligible),
            "finalized_events": finalized,
            "pending_events":   len(eligible) - finalized,
        },
    }


# ─── R — Rotation Health ──────────────────────────────────────────────────────

def compute_R(
    events: List[Dict[str, Any]],
    agent_id: str = "",
    current_time: Optional[int] = None,
    min_interval: int = ROTATION_MIN_INTERVAL,
) -> Dict[str, Any]:
    """
    Santé des rotations de clés.

    Pénalités par rotation :
        - Sans attestation (reset brutal) : -0.60
        - Intervalle < 7 jours            : -0.30

    Utilise history.py v1.6.0 pour la chaîne complète si disponible.
    """
    if current_time is None:
        current_time = int(time.time())

    rotations = sorted(
        [e for e in events
         if e.get("payload", {}).get("event_type") == "key_rotation"],
        key=lambda e: e.get("timestamp", 0),
    )

    if not rotations:
        return {"score": 1.0, "details": {
            "rotation_count": 0, "note": "Aucune rotation",
        }}

    scores = []
    details_list = []
    prev_ts = None

    for rot in rotations:
        ts = rot.get("timestamp", 0)
        payload = rot.get("payload", {})
        score = 1.0
        reasons = []

        # Pénalité 1 : pas d'attestation
        has_attestation = bool(
            payload.get("rotation_attestation")
            or payload.get("attestation")
            or payload.get("prev_agent_signature")
        )
        if not has_attestation:
            score -= 0.60
            reasons.append("Pas d'attestation")

        # Pénalité 2 : rotation trop rapide
        if prev_ts is not None and (ts - prev_ts) < min_interval:
            score -= 0.30
            reasons.append(f"Rotation rapide ({(ts - prev_ts) // 86400}j)")

        score = max(0.0, score)
        scores.append(score)
        details_list.append({
            "timestamp": ts, "score": round(score, 4), "reasons": reasons,
        })
        prev_ts = ts

    R = sum(scores) / len(scores)

    return {
        "score": round(min(1.0, max(0.0, R)), 4),
        "details": {
            "rotation_count": len(rotations),
            "rotations":      details_list,
        },
    }


# ─── Hook Sentinel v1.7.0 ─────────────────────────────────────────────────────

def get_a2c_risk(agent_id: str) -> Optional[Dict[str, Any]]:
    """
    Hook A2C Detection Layer.
    v1.6.0 → None (graceful degradation)
    v1.7.0 → score de risque relationnel complet
    """
    try:
        from aiss.a2c_detector import compute_a2c_risk
        return compute_a2c_risk(agent_id)
    except ImportError:
        return None


# ─── Agrégat principal ────────────────────────────────────────────────────────

def compute_trust_score(
    agent_id: str,
    events: Optional[List[Dict[str, Any]]] = None,
    weights: Optional[Dict[str, float]] = None,
    current_time: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Calcule le Trust Score complet d'un agent.

    TS = w_I×I + w_V×V_t + w_D×D_t + w_F×F + w_R×R

    Args:
        agent_id:     ID de l'agent
        events:       Événements (charge depuis memory si None)
        weights:      Poids personnalisés (utilise DEFAULT_WEIGHTS si None)
        current_time: Unix timestamp courant

    Returns:
        Dict avec trust_score, tier, components, component_details,
        event_count, computed_at, a2c_risk

    Example:
        >>> result = compute_trust_score("pq_abc123...")
        >>> print(f"{result['trust_score']}  [{result['tier']}]")
        0.87  [A+]
    """
    if current_time is None:
        current_time = int(time.time())

    w = (weights or DEFAULT_WEIGHTS).copy()
    total_w = sum(w.values())
    if abs(total_w - 1.0) > 0.001:
        w = {k: v / total_w for k, v in w.items()}

    # Chargement des événements
    if events is None:
        try:
            # v1.6.0 : historique complet (traverse les rotations)
            try:
                from aiss.history import load_full_history
                events = load_full_history(agent_id, include_markers=False)
            except Exception:
                from aiss.memory import load_events
                events = load_events(agent_id=agent_id)
        except Exception as e:
            logger.warning(f"[TS] Cannot load events for {agent_id}: {e}")
            events = []

    if not events:
        return {
            "agent_id":    agent_id,
            "trust_score": 1.0,
            "tier":        "Elite",
            "components":  {},
            "weights":     w,
            "event_count": 0,
            "computed_at": current_time,
            "a2c_risk":    None,
            "note":        "Nouvel agent — score neutre",
        }

    # Calcul des composantes
    I_r  = compute_I(events)
    Vt_r = compute_V_t(events, current_time)
    Dt_r = compute_D_t(events, current_time)
    F_r  = compute_F(events)
    R_r  = compute_R(events, agent_id, current_time)

    I_score = I_r["score"]
    V_t = Vt_r["score"]
    D_t = Dt_r["score"]
    F   = F_r["score"]
    R   = R_r["score"]

    TS = round(min(1.0, max(0.0,
        w["w_I"] * I_score + w["w_V"] * V_t + w["w_D"] * D_t
        + w["w_F"] * F + w["w_R"] * R
    )), 4)

    return {
        "agent_id":    agent_id,
        "trust_score": TS,
        "tier":        _tier(TS),
        "components": {
            "I": I_score, "V_t": V_t, "D_t": D_t, "F": F, "R": R,
        },
        "component_details": {
            "I":   I_r["details"],
            "V_t": Vt_r["details"],
            "D_t": Dt_r["details"],
            "F":   F_r["details"],
            "R":   R_r["details"],
        },
        "weights":     w,
        "event_count": len(events),
        "computed_at": current_time,
        "a2c_risk":    get_a2c_risk(agent_id),
    }


# ─── Handshake Signal ─────────────────────────────────────────────────────────

def build_trust_signal(
    agent_id: str,
    private_key: bytes,
    tsi_state: Optional[str] = None,
    delta_24h: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Construit le signal de trust partageable lors d'un handshake A2A.

    Informatif uniquement — jamais bloquant.
    Le receveur peut recalculer localement.
    """
    result = compute_trust_score(agent_id)
    current_time = int(time.time())

    signal: Dict[str, Any] = {
        "trust_score": result["trust_score"],
        "tier":        result["tier"],
        "tsi_state":   tsi_state or "UNKNOWN",
        "delta_24h":   delta_24h,
        "a2c_risk":    result.get("a2c_risk"),
        "timestamp":   current_time,
    }

    try:
        from aiss.canonical import canonicalize
        from aiss.crypto import ed25519
        sig = ed25519.sign(private_key, canonicalize(signal))
        signal["signature"] = sig.hex() if isinstance(sig, bytes) else sig
    except Exception as e:
        logger.warning(f"[TS] Cannot sign trust signal: {e}")

    return signal


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    "compute_I", "compute_V_t", "compute_D_t", "compute_F", "compute_R",
    "compute_trust_score",
    "temporal_weight", "build_trust_signal", "get_a2c_risk",
    "DEFAULT_WEIGHTS", "TIERS",
]
