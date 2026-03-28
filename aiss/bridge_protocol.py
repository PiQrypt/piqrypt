# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute — see root LICENSE for details.

from __future__ import annotations

"""
aiss/bridge_protocol.py — Contrat d'interface pour les bridges PiQrypt

Définit le protocole que tout bridge doit implémenter pour accéder
aux trois capacités du moteur :

    1. Mémoire injectée    — historique agent avant inférence
    2. Historique peer     — mémoire relationnelle A2A
    3. Gate TrustGate      — arrêt obligatoire avant action

Les bridges restent dans bridges/ avec leur licence Apache-2.0.
Ce fichier est MIT — il est le seul point de contact entre le moteur
AISS et les bridges externes.

Usage dans un bridge :
    from aiss.bridge_protocol import BridgeProtocol, BridgeAction

    class PiQryptCallbackHandler(BaseCallbackHandler, BridgeProtocol):

        def __init__(self, agent_name, ...):
            BridgeProtocol.__init__(self, agent_name)
            ...
            # Injection mémoire au démarrage
            memory_ctx = self.on_session_start()
            # → injecter memory_ctx dans le system prompt

        def on_tool_start(self, serialized, input_str, **kwargs):
            action = BridgeAction(
                name=serialized.get("name", "unknown"),
                payload={"input_hash": _h(input_str)},
            )
            if not self.on_action_gate(action):
                raise RuntimeError(
                    f"[PiQrypt] Action '{action.name}' bloquée par TrustGate"
                )
            # Stamp l'event comme d'habitude
            ...
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Chemin policy TrustGate par défaut ───────────────────────────────────────
_DEFAULT_POLICY_PATH = Path.home() / ".piqrypt" / "trustgate" / "policy.yaml"

# ── Nombre d'events récents injectés par défaut ───────────────────────────────
_DEFAULT_MEMORY_DEPTH = 10


# ─── BridgeAction ────────────────────────────────────────────────────────────

@dataclass
class BridgeAction:
    """
    Représente une action que l'agent s'apprête à exécuter.
    Passé à on_action_gate() pour évaluation TrustGate.

    Attributes:
        name:    Nom de l'action (tool name, event type, etc.)
        payload: Données associées — ne jamais mettre de données sensibles brutes
        role:    Rôle de l'agent dans la policy (défaut: "operator")
        domain:  Domaine cible si appel réseau (ex: "api.openai.com")
    """
    name:    str
    payload: Dict[str, Any] = field(default_factory=dict)
    role:    str = "operator"
    domain:  Optional[str] = None


# ─── BridgeProtocol ──────────────────────────────────────────────────────────

class BridgeProtocol:
    """
    Contrat minimal que tout bridge PiQrypt doit implémenter.

    Fournit les trois capacités du moteur aux bridges :
        1. on_session_start()  — mémoire injectée avant inférence
        2. on_peer_contact()   — historique A2A pour un peer connu
        3. on_action_gate()    — gate TrustGate avant chaque action

    Chaque méthode a un fallback gracieux :
        - TrustGate absent (Free tier) → ALLOW
        - Mémoire vide                 → chaîne vide, pas d'erreur
        - Peer inconnu                 → dict vide, pas d'erreur

    Args:
        agent_name:    Nom de l'agent (utilisé pour load_events)
        memory_depth:  Nombre d'events récents à injecter (défaut: 10)
        policy_path:   Chemin vers policy.yaml TrustGate (défaut: ~/.piqrypt/trustgate/policy.yaml)
        vrs:           VRS courant de l'agent (mis à jour par Vigil si disponible)
        tsi_state:     État TSI courant ("STABLE", "WATCH", "UNSTABLE", "CRITICAL")
    """

    def __init__(
        self,
        agent_name: str,
        memory_depth: int = _DEFAULT_MEMORY_DEPTH,
        policy_path: Optional[Path] = None,
        vrs: float = 0.0,
        tsi_state: str = "STABLE",
    ) -> None:
        self._agent_name   = agent_name
        self._memory_depth = memory_depth
        self._policy_path  = policy_path or _DEFAULT_POLICY_PATH
        self._vrs          = vrs
        self._tsi_state    = tsi_state

        # Cache policy pour éviter les rechargements répétitifs
        self._policy        = None
        self._policy_loaded = False

        # Timestamp de la dernière injection mémoire (pour injection delta)
        self._last_injection_ts: int = 0

    # ── 1. Mémoire injectée ──────────────────────────────────────────────────

    def on_session_start(self) -> str:
        """
        Charge les N derniers events de l'agent et retourne un bloc
        texte prêt à être injecté dans le system prompt du LLM.

        Doit être appelé dans __init__ du bridge, avant la première inférence.

        Returns:
            Bloc mémoire formaté (chaîne vide si aucun historique).

        Example:
            memory_ctx = self.on_session_start()
            system_prompt = BASE_PROMPT + "\\n\\nTon historique récent :\\n" + memory_ctx
        """
        events = self._load_recent_events()
        if not events:
            logger.debug(
                "[BridgeProtocol] %s — aucun historique disponible",
                self._agent_name,
            )
            return ""

        self._last_injection_ts = int(time.time())
        block = self._format_memory_block(events)

        logger.info(
            "[BridgeProtocol] %s — %d events injectés au démarrage",
            self._agent_name, len(events),
        )
        return block

    def on_session_update(self) -> str:
        """
        Charge uniquement les events postérieurs à la dernière injection
        (delta). À appeler périodiquement sur les longues sessions.

        Returns:
            Bloc mémoire delta (chaîne vide si aucun nouvel event).
        """
        events = self._load_recent_events()
        new_events = [
            e for e in events
            if e.get("timestamp", 0) > self._last_injection_ts
        ]
        if not new_events:
            return ""

        self._last_injection_ts = int(time.time())
        block = self._format_memory_block(new_events, label="Mise à jour mémoire")

        logger.info(
            "[BridgeProtocol] %s — delta: %d nouveaux events injectés",
            self._agent_name, len(new_events),
        )
        return block

    # ── 2. Historique peer A2A ───────────────────────────────────────────────

    def on_peer_contact(self, peer_id: str) -> Dict[str, Any]:
        """
        Retourne l'historique partagé avec un peer connu, avant contact.

        Doit être appelé dans le bridge quand un peer est détecté
        (ex: on_chain_start avec un peer_agent_id connu).

        Args:
            peer_id: agent_id du peer

        Returns:
            Dict avec :
                known          (bool)   — peer déjà rencontré
                first_seen     (int)    — timestamp première rencontre
                interaction_count (int) — nombre de sessions passées
                last_session_hash (str) — hash du dernier co-signed event
                summary        (str)    — bloc texte injectabe dans le prompt
        """
        try:
            from aiss.a2a import get_peer
            peer_data = get_peer(peer_id)
        except Exception as e:
            logger.debug("[BridgeProtocol] get_peer failed: %s", e)
            peer_data = None

        if not peer_data:
            return {
                "known": False,
                "first_seen": None,
                "interaction_count": 0,
                "last_session_hash": None,
                "summary": "",
            }

        # Récupérer le dernier co-signed event partagé avec ce peer
        last_hash = self._last_shared_event_hash(peer_id)

        summary = (
            f"[PiQrypt] Peer connu : {peer_id[:16]}...\n"
            f"  Première rencontre : {peer_data.get('first_seen', '?')}\n"
            f"  Sessions passées   : {peer_data.get('interaction_count', 0)}\n"
            f"  Trust score        : {peer_data.get('trust_score', 1.0):.2f}\n"
            + (f"  Dernier event co-signé : {last_hash[:16]}...\n" if last_hash else "")
        )

        logger.info(
            "[BridgeProtocol] %s — peer connu %s (%d interactions)",
            self._agent_name,
            peer_id[:16],
            peer_data.get("interaction_count", 0),
        )

        return {
            "known": True,
            "first_seen": peer_data.get("first_seen"),
            "interaction_count": peer_data.get("interaction_count", 0),
            "last_session_hash": last_hash,
            "summary": summary,
        }

    # ── 3. Gate TrustGate ────────────────────────────────────────────────────

    def on_action_gate(self, action: BridgeAction) -> bool:
        """
        Évalue une action auprès de TrustGate avant exécution.

        Appel direct à trustgate.policy_engine.evaluate() — pas HTTP.
        Fallback ALLOW si TrustGate non installé (Free tier).

        Args:
            action: BridgeAction décrivant l'action à évaluer

        Returns:
            True  → continuer (ALLOW / ALLOW_WITH_LOG)
            False → bloquer  (BLOCK / RESTRICTED)

        Note:
            REQUIRE_HUMAN est traité comme BLOCK dans le bridge —
            l'opérateur doit approuver via le dashboard TrustGate.
        """
        policy = self._load_policy()
        if policy is None:
            # TrustGate absent ou policy non configurée — ALLOW par défaut
            return True

        try:
            from trustgate.policy_engine import evaluate
            from trustgate.decision import EvaluationContext, Outcome

            ctx = EvaluationContext(
                agent_id    = self._agent_name,
                agent_name  = self._agent_name,
                action      = action.name,
                payload     = action.payload,
                role        = action.role,
                vrs         = self._vrs,
                tsi_state   = self._tsi_state,
                target_domain = action.domain,
            )

            decision = evaluate(ctx, policy)
            outcome  = decision.outcome

            # Normaliser outcome (peut être Outcome enum ou string)
            outcome_str = (
                outcome.value if hasattr(outcome, "value") else str(outcome)
            )

            blocking = outcome_str in ("BLOCK", "RESTRICTED", "REQUIRE_HUMAN")

            if blocking:
                logger.warning(
                    "[BridgeProtocol] %s — action '%s' bloquée : %s (%s)",
                    self._agent_name, action.name,
                    outcome_str, decision.reason,
                )
            elif outcome_str == "ALLOW_WITH_LOG":
                logger.info(
                    "[BridgeProtocol] %s — action '%s' autorisée avec log",
                    self._agent_name, action.name,
                )

            return not blocking

        except ImportError:
            # TrustGate non installé — Free tier, ALLOW silencieux
            logger.debug(
                "[BridgeProtocol] TrustGate non disponible — ALLOW par défaut"
            )
            return True

        except Exception as e:
            # Ne jamais bloquer à cause d'une erreur interne du gate
            logger.error(
                "[BridgeProtocol] Erreur gate TrustGate : %s — ALLOW par défaut",
                e,
            )
            return True

    # ── Mise à jour VRS/TSI (appelée par Vigil si disponible) ───────────────

    def update_trust_state(self, vrs: float, tsi_state: str) -> None:
        """
        Met à jour le VRS et TSI state courants.
        Appelé par le bridge quand Vigil pousse une mise à jour.

        Args:
            vrs:       Score VRS (0.0 = safe, 1.0 = compromis)
            tsi_state: "STABLE" | "WATCH" | "UNSTABLE" | "CRITICAL"
        """
        self._vrs       = vrs
        self._tsi_state = tsi_state
        logger.debug(
            "[BridgeProtocol] %s — trust state mis à jour : VRS=%.3f TSI=%s",
            self._agent_name, vrs, tsi_state,
        )

    # ── Helpers privés ───────────────────────────────────────────────────────

    def _load_recent_events(self) -> List[Dict[str, Any]]:
        """Charge les N derniers events de l'agent depuis la mémoire."""
        try:
            from aiss.memory import load_events
            events = load_events(agent_name=self._agent_name)
            return events[-self._memory_depth:] if events else []
        except Exception as e:
            logger.debug("[BridgeProtocol] load_events failed: %s", e)
            return []

    def _format_memory_block(
        self,
        events: List[Dict[str, Any]],
        label: str = "Historique récent",
    ) -> str:
        """
        Formate une liste d'events en bloc texte injectable dans un prompt.

        Format volontairement compact — chaque ligne = un event significatif.
        Le genesis est ignoré (pas d'action à montrer à l'agent).
        """
        lines = [f"[PiQrypt — {label}]"]

        for e in events:
            payload = e.get("payload", {})

            # Ignorer le genesis (pas d'action métier)
            if e.get("version") == "AISS-1.0" and not payload.get("action") and not payload.get("event_type"):
                continue

            ts     = e.get("timestamp", 0)
            action = (
                payload.get("action")
                or payload.get("event_type")
                or "event"
            )
            result = (
                payload.get("result")
                or payload.get("status")
                or payload.get("error")
                or ""
            )
            line = f"  [{ts}] {action}"
            if result:
                line += f" → {result}"
            lines.append(line)

        if len(lines) == 1:
            # Aucun event significatif après filtrage
            return ""

        return "\n".join(lines)

    def _last_shared_event_hash(self, peer_id: str) -> Optional[str]:
        """
        Retourne le hash du dernier event co-signé avec ce peer.
        Cherche dans la mémoire de l'agent les events A2A avec peer_agent_id == peer_id.
        """
        try:
            from aiss.memory import load_events
            events = load_events(agent_name=self._agent_name)
            a2a_events = [
                e for e in events
                if e.get("payload", {}).get("peer_agent_id") == peer_id
            ]
            if not a2a_events:
                return None
            from aiss.chain import compute_event_hash
            return compute_event_hash(a2a_events[-1])
        except Exception as e:
            logger.debug(
                "[BridgeProtocol] _last_shared_event_hash failed: %s", e
            )
            return None

    def _load_policy(self):
        """
        Charge la policy TrustGate une seule fois (cache en mémoire).
        Retourne None si TrustGate non disponible ou policy absente.
        """
        if self._policy_loaded:
            return self._policy

        self._policy_loaded = True  # Ne pas réessayer en cas d'échec

        try:
            from trustgate.policy_loader import load_policy
            if self._policy_path.exists():
                self._policy = load_policy(self._policy_path)
                logger.info(
                    "[BridgeProtocol] Policy TrustGate chargée : %s",
                    self._policy_path,
                )
            else:
                logger.debug(
                    "[BridgeProtocol] Policy absente : %s — TrustGate désactivé",
                    self._policy_path,
                )
        except ImportError:
            logger.debug(
                "[BridgeProtocol] trustgate non installé — gate désactivé"
            )
        except Exception as e:
            logger.warning(
                "[BridgeProtocol] Impossible de charger la policy : %s", e
            )

        return self._policy
