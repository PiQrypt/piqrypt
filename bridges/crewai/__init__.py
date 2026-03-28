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

__version__ = "1.1.0"
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


def _load_identity(identity_file: str):
    """Load PiQrypt identity from file."""
    identity = aiss.load_identity(identity_file)
    return identity["private_key_bytes"], identity["agent_id"]


# ─── AuditedAgent ─────────────────────────────────────────────────────────────

class AuditedAgent(Agent, BridgeProtocol):
    """
    CrewAI Agent with PiQrypt cryptographic audit trail.

    v1.1.0 — BridgeProtocol intégré :
        - Injection mémoire au démarrage
        - Gate TrustGate avant chaque execute_task()
        - Mémoire delta après chaque tâche complétée

    Usage:
        agent = AuditedAgent(
            role="Researcher",
            goal="Find information",
            backstory="Expert researcher",
            identity_file="~/.piqrypt/researcher.json",
            agent_name="researcher",
            inject_memory=True,
        )
        # Bloc mémoire disponible pour injection dans le system prompt :
        system_context = agent.memory_context
    """

    model_config = {"arbitrary_types_allowed": True}

    def __init__(
        self,
        *args,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        inject_memory: bool = True,
        memory_depth: int = 10,
        enable_gate: bool = True,
        **kwargs,
    ):
        # ── Identité cryptographique (inchangé) ──────────────────────────────
        Agent.__init__(self, *args, **kwargs)

        if identity_file:
            self._pq_key, self._pq_id = _load_identity(identity_file)
        elif private_key and agent_id:
            self._pq_key, self._pq_id = private_key, agent_id
        else:
            pq_priv, pq_pub = aiss.generate_keypair()
            self._pq_key = pq_priv
            self._pq_id = aiss.derive_agent_id(pq_pub)

        # ── Résolution nom agent ──────────────────────────────────────────────
        # Priorité : agent_name explicite > role CrewAI > agent_id
        self._agent_name = (
            agent_name
            or getattr(self, "role", None)
            or self._pq_id[:16]
        )
        self._enable_gate = enable_gate
        self._event_count = 0

        # ── BridgeProtocol ────────────────────────────────────────────────────
        if _BRIDGE_PROTOCOL_AVAILABLE:
            BridgeProtocol.__init__(
                self,
                agent_name=self._agent_name,
                memory_depth=memory_depth,
            )

        # ── Injection mémoire au démarrage ────────────────────────────────────
        self.memory_context: str = ""
        if inject_memory and _BRIDGE_PROTOCOL_AVAILABLE:
            self.memory_context = self.on_session_start()

        # ── Event de démarrage (inchangé) ─────────────────────────────────────
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "agent_initialized",
            "role": getattr(self, "role", "unknown"),
            "agent_name": self._agent_name,
            "framework": "crewai",
            "memory_injected": bool(self.memory_context),
            "aiss_profile": "AISS-1",
        }))

    def execute_task(self, task, context=None, tools=None):
        """
        Execute a CrewAI task with PiQrypt audit trail.

        v1.1.0 : gate TrustGate avant l'exécution.
        Lève RuntimeError si bloqué — arrêt obligatoire.
        """
        task_description = getattr(task, "description", str(task))

        # ── Gate TrustGate ────────────────────────────────────────────────────
        if self._enable_gate and _BRIDGE_PROTOCOL_AVAILABLE:
            action = BridgeAction(
                name="execute_task",
                payload={"task_hash": _h(task_description)},
            )
            allowed = self.on_action_gate(action)
            if not allowed:
                aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
                    "event_type": "task_blocked_by_trustgate",
                    "task_hash": _h(task_description),
                    "aiss_profile": "AISS-1",
                }))
                raise RuntimeError(
                    f"[PiQrypt TrustGate] Tâche bloquée pour '{self._agent_name}'. "
                    f"Consultez le dashboard TrustGate (port 8422)."
                )

        # ── Stamp démarrage tâche (inchangé) ──────────────────────────────────
        start_event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "task_start",
            "task_hash": _h(task_description),
            "context_hash": _h(context) if context else None,
            "aiss_profile": "AISS-1",
        })
        aiss.store_event(start_event)
        self._event_count += 1

        # ── Exécution (inchangé) ──────────────────────────────────────────────
        result = super().execute_task(task, context=context, tools=tools)

        # ── Stamp résultat (inchangé) ─────────────────────────────────────────
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "task_complete",
            "result_hash": _h(result),
            "previous_event_hash": aiss.compute_event_hash(start_event),
            "aiss_profile": "AISS-1",
        }))
        self._event_count += 1

        # ── Delta mémoire après tâche ─────────────────────────────────────────
        if _BRIDGE_PROTOCOL_AVAILABLE:
            delta = self.on_session_update()
            if delta:
                self.memory_context = delta

        return result

    @property
    def piqrypt_id(self) -> str:
        return self._pq_id

    @property
    def audit_event_count(self) -> int:
        return self._event_count

    def export_audit(self, output_path: str = "crewai-audit.json") -> str:
        """Export this agent's audit trail."""
        aiss.export_audit_chain(output_path)
        return output_path


# ─── AuditedCrew (inchangé — pas de gate nécessaire à ce niveau) ─────────────

class AuditedCrew(Crew):
    """
    CrewAI Crew with PiQrypt audit trail on kickoff.

    Le gate TrustGate opère au niveau de chaque AuditedAgent.execute_task().
    AuditedCrew se concentre sur la traçabilité du kickoff et du résultat global.
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
        kickoff_event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "crew_kickoff",
            "agent_count": len(self.agents),
            "task_count": len(self.tasks),
            "inputs_hash": _h(inputs) if inputs else None,
            "aiss_profile": "AISS-1",
        })
        aiss.store_event(kickoff_event)

        result = super().kickoff(inputs=inputs)

        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "crew_complete",
            "result_hash": _h(result),
            "previous_event_hash": aiss.compute_event_hash(kickoff_event),
            "aiss_profile": "AISS-1",
        }))

        return result

    def export_audit(self, output_path: str = "crew-audit.json") -> str:
        aiss.export_audit_chain(output_path)
        return output_path


# ─── stamp_task decorator (inchangé) ─────────────────────────────────────────

def stamp_task(
    task_name: str,
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
):
    """Decorator: stamp any CrewAI task function with PiQrypt proof."""
    def decorator(func):
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
            try:
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
            except Exception as e:
                aiss.store_event(aiss.stamp_event(_key, _id, {
                    "event_type": "task_error",
                    "task": task_name,
                    "error_hash": _h(str(e)),
                    "aiss_profile": "AISS-1",
                }))
                raise
        return wrapper
    return decorator


# ─── Convenience export (inchangé) ───────────────────────────────────────────

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
