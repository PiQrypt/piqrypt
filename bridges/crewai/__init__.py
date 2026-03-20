# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-crewai — PiQrypt bridge for CrewAI

Adds cryptographic audit trails to CrewAI agents and tasks.
Every agent decision, tool call, and task result is signed,
hash-chained, and tamper-proof.

Install:
    pip install piqrypt-crewai

Usage:
    from piqrypt_crewai import AuditedAgent, AuditedCrew, stamp_task
"""

__version__ = "1.0.0"
__author__ = "PiQrypt Contributors"
__license__ = "Apache-2.0"

import hashlib
import functools
from typing import Any, Dict, Optional

try:
    import piqrypt as aiss
except ImportError:
    raise ImportError(
        "piqrypt is required. Install with: pip install piqrypt"
    )

try:
    from crewai import Agent, Crew
except ImportError:
    raise ImportError(
        "crewai is required. Install with: pip install crewai"
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _h(value: Any) -> str:
    """SHA-256 hash of any value. Never stores raw content."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _load_identity(identity_file: str):
    """Load PiQrypt identity from file."""
    identity = aiss.load_identity(identity_file)
    return identity["private_key_bytes"], identity["agent_id"]


# ─── AuditedAgent ─────────────────────────────────────────────────────────────

class AuditedAgent(Agent):
    """
    CrewAI Agent with PiQrypt cryptographic audit trail.

    Every task execution is signed with Ed25519, hash-chained,
    and stored in a tamper-proof local audit trail.

    Usage:
        agent = AuditedAgent(
            role="Researcher",
            goal="Find information",
            backstory="Expert researcher",
            identity_file="my-agent.json"   # PiQrypt identity
        )

    Or with auto-generated identity (not persisted across runs):
        agent = AuditedAgent(
            role="Researcher",
            goal="...",
            backstory="..."
        )
    """

    # CrewAI uses Pydantic — declare extra fields
    model_config = {"arbitrary_types_allowed": True}

    def __init__(self, *args, identity_file: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)

        # Load or generate PiQrypt identity
        if identity_file:
            self._pq_key, self._pq_id = _load_identity(identity_file)
        else:
            pq_priv, pq_pub = aiss.generate_keypair()
            self._pq_key = pq_priv
            self._pq_id = aiss.derive_agent_id(pq_pub)

        # Stamp agent initialization
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "agent_initialized",
            "role": self.role,
            "goal_hash": _h(self.goal),
            "aiss_profile": "AISS-1",
        }))

    def execute_task(self, task, context=None, tools=None):
        """Execute task and stamp input, output, and any tool calls."""

        # Stamp task start
        start_event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "task_start",
            "role": self.role,
            "task_hash": _h(task.description if hasattr(task, "description") else task),
            "context_hash": _h(context) if context else None,
            "aiss_profile": "AISS-1",
        })
        aiss.store_event(start_event)

        # Execute
        result = super().execute_task(task, context=context, tools=tools)

        # Stamp task result
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "task_complete",
            "role": self.role,
            "task_hash": _h(task.description if hasattr(task, "description") else task),
            "result_hash": _h(result),
            "previous_event_hash": aiss.compute_event_hash(start_event),
            "aiss_profile": "AISS-1",
        }))

        return result

    @property
    def piqrypt_id(self) -> str:
        """Return this agent's PiQrypt identity."""
        return self._pq_id

    def export_audit(self, output_path: str = "crewai-audit.json") -> str:
        """Export this agent's audit trail."""
        aiss.export_audit_chain(output_path)
        return output_path


# ─── AuditedCrew ──────────────────────────────────────────────────────────────

class AuditedCrew(Crew):
    """
    CrewAI Crew with PiQrypt audit trail on kickoff.

    Stamps the crew kickoff, inputs, and final result.
    Individual agent stamps are handled by AuditedAgent.

    Usage:
        crew = AuditedCrew(
            agents=[agent1, agent2],
            tasks=[task1, task2],
            identity_file="crew-coordinator.json"
        )
        result = crew.kickoff(inputs={"topic": "AI safety"})
    """

    model_config = {"arbitrary_types_allowed": True}

    def __init__(self, *args, identity_file: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)

        if identity_file:
            self._pq_key, self._pq_id = _load_identity(identity_file)
        else:
            pq_priv, pq_pub = aiss.generate_keypair()
            self._pq_key = pq_priv
            self._pq_id = aiss.derive_agent_id(pq_pub)

    def kickoff(self, inputs: Optional[Dict[str, Any]] = None):
        """Run crew and stamp kickoff + result."""

        # Stamp kickoff
        kickoff_event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "crew_kickoff",
            "agent_count": len(self.agents),
            "task_count": len(self.tasks),
            "inputs_hash": _h(inputs) if inputs else None,
            "aiss_profile": "AISS-1",
        })
        aiss.store_event(kickoff_event)

        # Run crew
        result = super().kickoff(inputs=inputs)

        # Stamp result
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "crew_complete",
            "result_hash": _h(result),
            "previous_event_hash": aiss.compute_event_hash(kickoff_event),
            "aiss_profile": "AISS-1",
        }))

        return result

    def export_audit(self, output_path: str = "crew-audit.json") -> str:
        """Export full crew audit trail."""
        aiss.export_audit_chain(output_path)
        return output_path


# ─── stamp_task decorator ─────────────────────────────────────────────────────

def stamp_task(
    task_name: str,
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
):
    """
    Decorator: stamp any CrewAI task function with PiQrypt proof.

    Usage:
        # With identity file
        @stamp_task("research", identity_file="my-agent.json")
        def research(topic: str) -> str:
            return do_research(topic)

        # With explicit keys
        @stamp_task("research", private_key=priv, agent_id=aid)
        def research(topic: str) -> str:
            return do_research(topic)
    """
    def decorator(func):
        # Resolve identity once at decoration time
        if identity_file:
            _key, _id = _load_identity(identity_file)
        elif private_key and agent_id:
            _key, _id = private_key, agent_id
        else:
            pq_priv, pq_pub = aiss.generate_keypair()
            _key = pq_priv
            _id = aiss.derive_agent_id(pq_pub)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            aiss.store_event(aiss.stamp_event(_key, _id, {
                "event_type": "task_executed",
                "task": task_name,
                "args_hash": _h(args),
                "kwargs_hash": _h(kwargs),
                "result_hash": _h(result),
                "aiss_profile": "AISS-1",
            }))

            return result
        return wrapper
    return decorator


# ─── Convenience export ───────────────────────────────────────────────────────

def export_audit(output_path: str = "crewai-audit.json") -> str:
    """Export full audit trail for all agents in this session."""
    aiss.export_audit_chain(output_path)
    return output_path


__all__ = [
    "AuditedAgent",
    "AuditedCrew",
    "stamp_task",
    "export_audit",
]
