# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-session — Multi-agent cryptographic session bridge

v1.1.0 — BridgeProtocol intégré :
    - AgentMember charge sa mémoire au démarrage (on_session_start)
    - _handshake_pair consulte l'historique A2A avant chaque handshake
      (on_peer_contact) — "je me souviens de toi"
    - stamp() avec peer passe par le gate TrustGate si activé

Usage:
    from piqrypt_session import AgentSession

    session = AgentSession([
        {"name": "analyst",  "identity_file": "analyst.json"},
        {"name": "executor", "identity_file": "executor.json"},
    ])
    session.start()
    session.stamp("analyst", "recommendation_sent", {...}, peer="executor")
    session.end()
"""

__version__ = "1.1.0"
__author__  = "PiQrypt Contributors"
__license__ = "Apache-2.0"

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional

try:
    import piqrypt as aiss
except ImportError:
    raise ImportError(
        "piqrypt is required. Install with: pip install piqrypt"
    )

try:
    from aiss.a2a import (
        create_identity_proposal,
        create_identity_response,
        build_cosigned_handshake_event,
    )
except ImportError:
    raise ImportError(
        "aiss A2A module not found. Install with: pip install piqrypt"
    )

# ── BridgeProtocol — contrat moteur AISS ──────────────────────────────────────
try:
    from aiss.bridge_protocol import BridgeProtocol, BridgeAction
    _BRIDGE_PROTOCOL_AVAILABLE = True
except ImportError:
    BridgeProtocol = object
    BridgeAction = None
    _BRIDGE_PROTOCOL_AVAILABLE = False


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _h(value: Any) -> str:
    """SHA-256 hash of any value. Never stores raw content."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


# ─── AgentMember ─────────────────────────────────────────────────────────────

class AgentMember(BridgeProtocol):
    """
    Represents one agent participant in a session.

    v1.1.0 — BridgeProtocol intégré :
        - Charge sa mémoire au démarrage (on_session_start)
        - Expose memory_context pour injection dans le system prompt
        - Met à jour le delta mémoire après chaque stamp

    Holds its PiQrypt identity and tracks its own event chain
    within the session.
    """

    def __init__(
        self,
        name: str,
        identity_file: str,
        inject_memory: bool = True,
        memory_depth: int = 10,
        enable_gate: bool = True,
    ):
        self.name = name
        identity = aiss.load_identity(identity_file)
        self.private_key: bytes = identity["private_key_bytes"]
        self.public_key: bytes  = identity["public_key_bytes"]
        self.agent_id: str      = identity["agent_id"]
        self.previous_hash: Optional[str] = None
        self._events: List[Dict] = []
        self._enable_gate = enable_gate

        # ── BridgeProtocol ────────────────────────────────────────────────────
        if _BRIDGE_PROTOCOL_AVAILABLE:
            BridgeProtocol.__init__(
                self,
                agent_name=name,
                memory_depth=memory_depth,
            )

        # ── Injection mémoire au démarrage ────────────────────────────────────
        # Disponible via member.memory_context pour injection dans system prompt
        self.memory_context: str = ""
        if inject_memory and _BRIDGE_PROTOCOL_AVAILABLE:
            self.memory_context = self.on_session_start()

    def stamp(
        self,
        event_type: str,
        payload: Dict[str, Any],
        session_id: str,
        peer_id: Optional[str] = None,
        peer_signature: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Stamp an event into this agent's memory, linked to the session."""
        full_payload = {
            **payload,
            "event_type":  event_type,
            "session_id":  session_id,
            "aiss_profile": "AISS-1",
        }
        if peer_id:
            full_payload["peer_agent_id"] = peer_id
        if peer_signature:
            full_payload["peer_signature"] = peer_signature

        event = aiss.stamp_event(
            self.private_key,
            self.agent_id,
            payload=full_payload,
            previous_hash=self.previous_hash or "genesis",
        )
        aiss.store_event(event)
        self.previous_hash = aiss.compute_event_hash(event)
        self._events.append(event)

        # Delta mémoire après chaque stamp
        if _BRIDGE_PROTOCOL_AVAILABLE:
            delta = self.on_session_update()
            if delta:
                self.memory_context = delta

        return event

    @property
    def events(self) -> List[Dict]:
        return self._events.copy()

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def last_event_hash(self) -> Optional[str]:
        return self.previous_hash


# ─── AgentSession ─────────────────────────────────────────────────────────────

class AgentSession:
    """
    Multi-agent cryptographic session.

    v1.1.0 — BridgeProtocol intégré :
        - Chaque AgentMember charge sa mémoire au démarrage
        - _handshake_pair consulte l'historique A2A partagé avant handshake
          → l'agent peut dire "je me souviens de toi, voici notre historique"
        - stamp() avec peer passe par le gate TrustGate si activé

    Usage:
        session = AgentSession([
            {"name": "analyst",  "identity_file": "analyst.json"},
            {"name": "executor", "identity_file": "executor.json"},
        ])
        session.start()
        # Voir la mémoire de chaque agent :
        print(session.agents["analyst"].memory_context)
    """

    def __init__(
        self,
        agents: List[Dict[str, str]],
        enable_gate: bool = True,
        memory_depth: int = 10,
    ):
        if len(agents) < 2:
            raise ValueError(
                "AgentSession requires at least 2 agents. "
                "For single-agent use, use aiss.stamp_event() directly."
            )

        self.session_id: str = f"sess_{uuid.uuid4().hex[:16]}"
        self.started_at: Optional[int] = None
        self.started: bool = False
        self._enable_gate = enable_gate

        # Build agent registry — chaque membre charge sa mémoire au démarrage
        self._agents: Dict[str, AgentMember] = {}
        for agent_def in agents:
            name = agent_def["name"]
            identity_file = agent_def.get("identity_file", "")
            self._agents[name] = AgentMember(
                name=name,
                identity_file=identity_file,
                memory_depth=memory_depth,
                enable_gate=enable_gate,
            )

        self._handshakes: List[Dict] = []

    def start(self) -> "AgentSession":
        """
        Start the session — perform all pairwise A2A handshakes.

        v1.1.0 : avant chaque handshake, consulte l'historique partagé
        via on_peer_contact(). Si les agents se connaissent déjà, le
        contexte est enrichi dans le payload du handshake.
        """
        if self.started:
            raise RuntimeError(
                f"Session {self.session_id} already started."
            )

        self.started_at = int(time.time())
        agent_list = list(self._agents.values())
        pair_count = 0

        # Stamp session_start dans la mémoire de chaque agent
        for agent in agent_list:
            agent.stamp(
                event_type="session_start",
                payload={
                    "session_id":        self.session_id,
                    "participants":      [a.agent_id for a in agent_list],
                    "participant_names": list(self._agents.keys()),
                    "agent_count":       len(agent_list),
                },
                session_id=self.session_id,
            )

        # Handshakes pairwise — avec consultation mémoire relationnelle
        for i in range(len(agent_list)):
            for j in range(i + 1, len(agent_list)):
                handshake = self._handshake_pair(agent_list[i], agent_list[j])
                self._handshakes.append(handshake)
                pair_count += 1

        self.started = True

        print(f"[PiQrypt Session] ✅ Session started: {self.session_id}")
        print(f"  Agents    : {', '.join(self._agents.keys())}")
        print(f"  Handshakes: {pair_count} co-signed")
        print(f"  Timestamp : {self.started_at}")

        return self

    def _handshake_pair(
        self,
        agent_a: AgentMember,
        agent_b: AgentMember,
    ) -> Dict[str, Any]:
        """
        Perform A2A handshake between agent_a and agent_b.

        v1.1.0 : consulte on_peer_contact() avant de créer la proposal.
        Si les agents se sont déjà rencontrés, le payload du handshake
        inclut l'historique partagé — "je me souviens de toi".
        """
        # ── Consultation mémoire relationnelle ────────────────────────────────
        prior_context_a = {}
        prior_context_b = {}

        if _BRIDGE_PROTOCOL_AVAILABLE:
            peer_ctx_a = agent_a.on_peer_contact(agent_b.agent_id)
            peer_ctx_b = agent_b.on_peer_contact(agent_a.agent_id)

            if peer_ctx_a["known"]:
                prior_context_a = {
                    "prior_interactions": peer_ctx_a["interaction_count"],
                    "first_seen":         peer_ctx_a["first_seen"],
                    "last_session_hash":  peer_ctx_a["last_session_hash"],
                }
                print(
                    f"  [memory] {agent_a.name} se souvient de {agent_b.name} "
                    f"({peer_ctx_a['interaction_count']} interaction(s))"
                )
            if peer_ctx_b["known"]:
                prior_context_b = {
                    "prior_interactions": peer_ctx_b["interaction_count"],
                    "first_seen":         peer_ctx_b["first_seen"],
                    "last_session_hash":  peer_ctx_b["last_session_hash"],
                }

        # ── Handshake (inchangé) ──────────────────────────────────────────────
        proposal = create_identity_proposal(
            agent_a.private_key,
            agent_a.public_key,
            agent_a.agent_id,
            capabilities=["stamp", "verify", "a2a", "session"],
            metadata={
                "session_id": self.session_id,
                "name":       agent_a.name,
                **prior_context_a,   # enrichi avec la mémoire relationnelle
            },
        )

        response = create_identity_response(
            agent_b.private_key,
            agent_b.public_key,
            agent_b.agent_id,
            proposal,
            capabilities=["stamp", "verify", "a2a", "session"],
        )

        # Co-signed event pour A
        event_a = build_cosigned_handshake_event(
            agent_a.private_key,
            agent_a.agent_id,
            proposal,
            response,
            previous_hash=agent_a.previous_hash or "genesis",
        )
        event_a["payload"]["session_id"] = self.session_id
        event_a["payload"]["peer_name"]  = agent_b.name
        if prior_context_a:
            event_a["payload"]["prior_context"] = prior_context_a
        aiss.store_event(event_a)
        agent_a.previous_hash = aiss.compute_event_hash(event_a)
        agent_a._events.append(event_a)

        # Co-signed event pour B
        event_b = build_cosigned_handshake_event(
            agent_b.private_key,
            agent_b.agent_id,
            proposal,
            response,
            previous_hash=agent_b.previous_hash or "genesis",
        )
        event_b["payload"]["session_id"] = self.session_id
        event_b["payload"]["peer_name"]  = agent_a.name
        if prior_context_b:
            event_b["payload"]["prior_context"] = prior_context_b
        aiss.store_event(event_b)
        agent_b.previous_hash = aiss.compute_event_hash(event_b)
        agent_b._events.append(event_b)

        print(f"  [handshake] {agent_a.name} ↔ {agent_b.name} co-signed ✅")

        return {
            "agent_a":      agent_a.name,
            "agent_b":      agent_b.name,
            "agent_a_id":   agent_a.agent_id,
            "agent_b_id":   agent_b.agent_id,
            "session_id":   self.session_id,
            "event_a_hash": aiss.compute_event_hash(event_a),
            "event_b_hash": aiss.compute_event_hash(event_b),
            "timestamp":    int(time.time()),
            "prior_known":  bool(prior_context_a),  # les agents se connaissaient
        }

    def stamp(
        self,
        agent_name: str,
        event_type: str,
        payload: Dict[str, Any],
        peer: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Stamp an event in an agent's memory, linked to this session.

        v1.1.0 : si peer est fourni et gate activé, l'action passe par
        TrustGate avant d'être co-signée.
        """
        self._require_started()
        agent = self._get_agent(agent_name)

        # Hash raw values automatically
        safe_payload = {}
        for key, value in payload.items():
            if key.endswith("_hash") or key.endswith("_id") or key == "session_id":
                safe_payload[key] = value
            else:
                safe_payload[f"{key}_hash"] = _h(value)

        if peer:
            peer_agent = self._get_agent(peer)

            # ── Gate TrustGate sur les interactions co-signées ────────────────
            if self._enable_gate and _BRIDGE_PROTOCOL_AVAILABLE:
                action = BridgeAction(
                    name=event_type,
                    payload={"peer": peer, **safe_payload},
                )
                if not agent.on_action_gate(action):
                    agent.stamp(
                        event_type=f"{event_type}_blocked",
                        payload={"peer": peer, "reason": "trustgate"},
                        session_id=self.session_id,
                    )
                    raise RuntimeError(
                        f"[PiQrypt TrustGate] '{event_type}' bloqué pour "
                        f"'{agent_name}'. Consultez le dashboard (port 8422)."
                    )

            # ── Co-signature (inchangé) ───────────────────────────────────────
            interaction_hash = _h(
                f"{agent.agent_id}:{peer_agent.agent_id}:{time.time()}"
            )

            event_agent = agent.stamp(
                event_type=event_type,
                payload={
                    **safe_payload,
                    "interaction_hash": interaction_hash,
                    "my_role": "initiator",
                },
                session_id=self.session_id,
                peer_id=peer_agent.agent_id,
            )

            peer_agent.stamp(
                event_type=f"{event_type}_received",
                payload={
                    **safe_payload,
                    "interaction_hash": interaction_hash,
                    "my_role": "responder",
                },
                session_id=self.session_id,
                peer_id=agent.agent_id,
                peer_signature=event_agent.get("signature"),
            )

            return event_agent

        else:
            return agent.stamp(
                event_type=event_type,
                payload=safe_payload,
                session_id=self.session_id,
            )

    def end(self) -> Dict[str, Any]:
        """End the session — stamp session_end in all agents' memories."""
        self._require_started()
        summary = self.summary()
        for agent in self._agents.values():
            agent.stamp(
                event_type="session_end",
                payload={
                    "session_id":  self.session_id,
                    "duration_s":  int(time.time()) - (self.started_at or 0),
                    "event_count": agent.event_count,
                },
                session_id=self.session_id,
            )
        self.started = False
        return summary

    def export(self, output_path: str = "session_audit.json") -> str:
        """Export full session audit trail to JSON."""
        aiss.export_audit_chain(output_path)
        return output_path

    def summary(self) -> Dict[str, Any]:
        return {
            "session_id":   self.session_id,
            "started_at":   self.started_at,
            "agents":       {
                name: {
                    "agent_id":    m.agent_id,
                    "event_count": m.event_count,
                }
                for name, m in self._agents.items()
            },
            "handshakes":   len(self._handshakes),
        }

    @property
    def agents(self) -> Dict[str, AgentMember]:
        return self._agents

    def get_agent(self, name: str) -> AgentMember:
        return self._get_agent(name)

    def _get_agent(self, name: str) -> AgentMember:
        if name not in self._agents:
            raise KeyError(
                f"Agent '{name}' not in session. "
                f"Known agents: {list(self._agents.keys())}"
            )
        return self._agents[name]

    def _require_started(self) -> None:
        if not self.started:
            raise RuntimeError(
                "Session not started. Call session.start() first."
            )


__all__ = ["AgentSession", "AgentMember"]
