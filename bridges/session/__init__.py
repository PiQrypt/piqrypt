# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-session — Multi-agent cryptographic session for PiQrypt

Establishes a cryptographically co-signed session between N agents,
regardless of their framework (LangChain, AutoGen, CrewAI, OpenClaw...).

Each agent keeps its own memory. Every interaction references the shared
session_id. Co-signed handshakes prove mutual identification before
any action takes place.

Install:
    pip install piqrypt-session

Usage:
    from piqrypt_session import AgentSession

    session = AgentSession([
        {"name": "llm",          "identity_file": "llm.json"},
        {"name": "trading_bot",  "identity_file": "trading-bot.json"},
        {"name": "openclaw",     "identity_file": "openclaw.json"},
    ])

    session.start()
    # → all agents co-sign handshakes with each other
    # → session_id shared across all memories

    session.stamp("llm", "recommendation_sent", {
        "symbol": "AAPL",
        "action": "buy",
        "confidence": 0.87,
    }, peer="trading_bot")

    session.export("trading-session-audit.json")
"""

__version__ = "1.0.0"
__author__ = "PiQrypt Contributors"
__license__ = "Apache-2.0"

import uuid
import time
import json
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import piqrypt as aiss
    from aiss.a2a import (
        create_identity_proposal,
        perform_handshake,
        build_cosigned_handshake_event,
        create_identity_response,
        verify_identity_proposal,
    )
    from aiss.crypto import ed25519
except ImportError:
    raise ImportError(
        "piqrypt is required. Install with: pip install piqrypt"
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _h(value: Any) -> str:
    """SHA-256 hash of any value. Never stores raw content."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


# ─── AgentMember ──────────────────────────────────────────────────────────────

class AgentMember:
    """
    Represents one agent participant in a session.

    Holds its PiQrypt identity and tracks its own event chain
    within the session.
    """

    def __init__(self, name: str, identity_file: str):
        self.name = name
        identity = aiss.load_identity(identity_file)
        self.private_key: bytes = identity["private_key_bytes"]
        self.public_key: bytes = identity["public_key_bytes"]
        self.agent_id: str = identity["agent_id"]
        self.previous_hash: Optional[str] = None  # chain continuity
        self._events: List[Dict] = []

    def stamp(
        self,
        event_type: str,
        payload: Dict[str, Any],
        session_id: str,
        peer_id: Optional[str] = None,
        peer_signature: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Stamp an event into this agent's memory, linked to the session.

        Args:
            event_type:     Event type string
            payload:        Event payload (will be merged with session metadata)
            session_id:     Shared session identifier
            peer_id:        Peer agent_id if this is an interaction
            peer_signature: Peer's signature if co-signed

        Returns:
            Signed event dict
        """
        full_payload = {
            **payload,
            "event_type": event_type,
            "session_id": session_id,
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

        return event

    @property
    def events(self) -> List[Dict]:
        return self._events.copy()


# ─── AgentSession ─────────────────────────────────────────────────────────────

class AgentSession:
    """
    Multi-agent cryptographic session.

    Establishes co-signed A2A handshakes between all agent pairs,
    then provides a shared session context for stamping interactions.

    Each agent maintains its own memory (its own PiQrypt chain).
    Every event references the shared session_id.
    Co-signed interactions embed both agents' signatures.

    Usage:
        session = AgentSession([
            {"name": "llm",         "identity_file": "llm.json"},
            {"name": "trading_bot", "identity_file": "trading-bot.json"},
            {"name": "openclaw",    "identity_file": "openclaw.json"},
        ])

        session.start()

        # Stamp a unilateral action
        session.stamp("trading_bot", "trade_decision", {
            "symbol": "AAPL",
            "action": "buy",
            "price_hash": _h("182.50"),
        })

        # Stamp a co-signed interaction between two agents
        session.stamp("llm", "recommendation_sent", {
            "symbol": "AAPL",
            "confidence_hash": _h("0.87"),
        }, peer="trading_bot")

        session.export("audit.json")
    """

    def __init__(self, agents: List[Dict[str, str]]):
        """
        Initialize session with agent definitions.

        Args:
            agents: List of dicts with keys:
                    - name: human-readable agent name
                    - identity_file: path to PiQrypt identity JSON
        """
        if len(agents) < 2:
            raise ValueError(
                "AgentSession requires at least 2 agents. "
                "For single-agent use, use aiss.stamp_event() directly."
            )

        self.session_id: str = f"sess_{uuid.uuid4().hex[:16]}"
        self.started_at: Optional[int] = None
        self.started: bool = False

        # Build agent registry
        self._agents: Dict[str, AgentMember] = {}
        for agent_def in agents:
            name = agent_def["name"]
            identity_file = agent_def["identity_file"]
            self._agents[name] = AgentMember(name, identity_file)

        # Track handshakes
        self._handshakes: List[Dict] = []

    def start(self) -> "AgentSession":
        """
        Start the session — perform all pairwise A2A handshakes.

        For N agents, performs N*(N-1)/2 handshakes.
        Each handshake produces a co-signed event in BOTH agents' memories.

        Example with 3 agents (LLM, TradingBot, OpenClaw):
            LLM ↔ TradingBot    → co-signed event in both memories
            LLM ↔ OpenClaw      → co-signed event in both memories
            TradingBot ↔ OpenClaw → co-signed event in both memories

        Returns:
            self (chainable)

        Raises:
            RuntimeError: If session already started
        """
        if self.started:
            raise RuntimeError(
                f"Session {self.session_id} already started. "
                "Create a new AgentSession to start a new session."
            )

        self.started_at = int(time.time())
        agent_list = list(self._agents.values())
        pair_count = 0

        # Stamp session_start in each agent's memory
        for agent in agent_list:
            agent.stamp(
                event_type="session_start",
                payload={
                    "session_id": self.session_id,
                    "participants": [a.agent_id for a in agent_list],
                    "participant_names": list(self._agents.keys()),
                    "agent_count": len(agent_list),
                },
                session_id=self.session_id,
            )

        # Perform all pairwise handshakes
        for i in range(len(agent_list)):
            for j in range(i + 1, len(agent_list)):
                agent_a = agent_list[i]
                agent_b = agent_list[j]

                handshake = self._handshake_pair(agent_a, agent_b)
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
        Perform A2A handshake between agent_a (initiator) and agent_b (responder).

        Both agents get a co-signed event in their respective memories.
        The event in each memory contains:
        - My own signature
        - The peer's signature (embedded)
        - The shared session_id
        - The peer's agent_id

        Returns:
            Handshake result dict
        """
        # Step 1 — Agent A creates proposal
        proposal = create_identity_proposal(
            agent_a.private_key,
            agent_a.public_key,
            agent_a.agent_id,
            capabilities=["stamp", "verify", "a2a", "session"],
            metadata={"session_id": self.session_id, "name": agent_a.name},
        )

        # Step 2 — Agent B responds
        response = create_identity_response(
            agent_b.private_key,
            agent_b.public_key,
            agent_b.agent_id,
            proposal,
            capabilities=["stamp", "verify", "a2a", "session"],
        )

        # Step 3 — Build co-signed event for Agent A's memory
        event_a = build_cosigned_handshake_event(
            agent_a.private_key,
            agent_a.agent_id,
            proposal,
            response,
            previous_hash=agent_a.previous_hash or "genesis",
        )
        # Inject session_id into the event payload
        event_a["payload"]["session_id"] = self.session_id
        event_a["payload"]["peer_name"] = agent_b.name
        aiss.store_event(event_a)
        agent_a.previous_hash = aiss.compute_event_hash(event_a)
        agent_a._events.append(event_a)

        # Step 4 — Build co-signed event for Agent B's memory
        event_b = build_cosigned_handshake_event(
            agent_b.private_key,
            agent_b.agent_id,
            proposal,
            response,
            previous_hash=agent_b.previous_hash or "genesis",
        )
        event_b["payload"]["session_id"] = self.session_id
        event_b["payload"]["peer_name"] = agent_a.name
        aiss.store_event(event_b)
        agent_b.previous_hash = aiss.compute_event_hash(event_b)
        agent_b._events.append(event_b)

        print(
            f"  [handshake] {agent_a.name} ↔ {agent_b.name} "
            f"co-signed ✅"
        )

        return {
            "agent_a": agent_a.name,
            "agent_b": agent_b.name,
            "agent_a_id": agent_a.agent_id,
            "agent_b_id": agent_b.agent_id,
            "session_id": self.session_id,
            "event_a_hash": aiss.compute_event_hash(event_a),
            "event_b_hash": aiss.compute_event_hash(event_b),
            "timestamp": int(time.time()),
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

        If peer is provided, the event is co-signed:
        - Agent stamps the event with the peer's agent_id
        - Peer stamps a corresponding event with the agent's agent_id
        - Both events reference the same interaction_hash

        Args:
            agent_name:  Name of the acting agent
            event_type:  Event type string
            payload:     Event data (values are hashed automatically
                         unless key ends with '_hash' or '_id')
            peer:        Optional peer agent name for co-signed interaction

        Returns:
            Stamped event dict (acting agent's event)

        Raises:
            RuntimeError: If session not started
            KeyError: If agent_name or peer not in session
        """
        self._require_started()
        agent = self._get_agent(agent_name)

        # Hash raw values automatically — only keep pre-hashed fields as-is
        safe_payload = {}
        for key, value in payload.items():
            if key.endswith("_hash") or key.endswith("_id") or key == "session_id":
                safe_payload[key] = value
            else:
                safe_payload[f"{key}_hash"] = _h(value)

        if peer:
            peer_agent = self._get_agent(peer)

            # Compute a shared interaction_hash — same in both memories
            interaction_hash = _h(f"{agent.agent_id}:{peer_agent.agent_id}:{time.time()}")

            # Agent stamps its side
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

            # Peer stamps its side — same interaction_hash, different perspective
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
            # Unilateral action — agent stamps alone
            return agent.stamp(
                event_type=event_type,
                payload=safe_payload,
                session_id=self.session_id,
            )

    def end(self) -> Dict[str, Any]:
        """
        End the session — stamp session_end in all agents' memories.

        Returns:
            Session summary dict
        """
        self._require_started()

        ended_at = int(time.time())
        duration = ended_at - self.started_at
        total_events = sum(len(a.events) for a in self._agents.values())

        for agent in self._agents.values():
            agent.stamp(
                event_type="session_end",
                payload={
                    "session_id": self.session_id,
                    "duration_seconds": duration,
                    "total_events": total_events,
                },
                session_id=self.session_id,
            )

        summary = self.summary()
        print(f"\n[PiQrypt Session] Session ended: {self.session_id}")
        print(f"  Duration : {duration}s")
        print(f"  Events   : {total_events}")

        return summary

    def summary(self) -> Dict[str, Any]:
        """
        Return session summary — event counts, handshakes, agent IDs.

        Returns:
            Dict with full session metadata
        """
        return {
            "session_id": self.session_id,
            "started_at": self.started_at,
            "agents": {
                name: {
                    "agent_id": agent.agent_id,
                    "event_count": len(agent.events),
                    "last_hash": agent.previous_hash,
                }
                for name, agent in self._agents.items()
            },
            "handshakes": self._handshakes,
            "handshake_count": len(self._handshakes),
            "total_events": sum(
                len(a.events) for a in self._agents.values()
            ),
        }

    def export(self, output_path: str = "session-audit.json") -> str:
        """
        Export the full session audit — all agents, all events, all handshakes.

        The export contains:
        - Session metadata (id, participants, handshakes)
        - Each agent's full event chain
        - Cross-references between agent memories

        Args:
            output_path: Path to output JSON file

        Returns:
            output_path
        """
        self._require_started()

        export_data = {
            "session": self.summary(),
            "agents": {},
        }

        for name, agent in self._agents.items():
            export_data["agents"][name] = {
                "agent_id": agent.agent_id,
                "event_count": len(agent.events),
                "events": agent.events,
            }

        Path(output_path).write_text(
            json.dumps(export_data, indent=2)
        )

        print(f"\n[PiQrypt Session] Audit exported: {output_path}")
        print(f"  Verify with: piqrypt verify {output_path}")

        return output_path

    def get_agent(self, name: str) -> AgentMember:
        """Return AgentMember by name for direct access."""
        return self._get_agent(name)

    @property
    def id(self) -> str:
        """Session ID."""
        return self.session_id

    @property
    def agents(self) -> Dict[str, AgentMember]:
        """All agent members."""
        return self._agents.copy()

    def _require_started(self) -> None:
        if not self.started:
            raise RuntimeError(
                "Session not started. Call session.start() first."
            )

    def _get_agent(self, name: str) -> AgentMember:
        if name not in self._agents:
            raise KeyError(
                f"Agent '{name}' not in session. "
                f"Available: {list(self._agents.keys())}"
            )
        return self._agents[name]


# ─── Public API ───────────────────────────────────────────────────────────────

__all__ = [
    "AgentSession",
    "AgentMember",
]
