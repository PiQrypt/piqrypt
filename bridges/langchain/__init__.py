# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-langchain — PiQrypt bridge for LangChain

Adds Verifiable AI Agent Memory to LangChain agents, tools, and chains.
Every tool call, chain execution, and agent action is signed,
hash-chained, and tamper-proof.

Install:
    pip install piqrypt-langchain

Usage:
    from piqrypt_langchain import AuditedAgentExecutor, piqrypt_tool, stamp_chain
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
    from langchain.agents import AgentExecutor
    from langchain.callbacks.base import BaseCallbackHandler
    from langchain.schema import LLMResult
except ImportError:
    raise ImportError(
        "langchain is required. Install with: pip install langchain"
    )

# ── BridgeProtocol — contrat moteur AISS ──────────────────────────────────────
try:
    from aiss.bridge_protocol import BridgeProtocol, BridgeAction
    _BRIDGE_PROTOCOL_AVAILABLE = True
except ImportError:
    # Compatibilité ascendante si bridge_protocol.py pas encore déployé
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


def _resolve_identity(identity_file, private_key, agent_id):
    """Resolve PiQrypt identity from file or explicit keys."""
    if identity_file:
        return _load_identity(identity_file)
    elif private_key and agent_id:
        return private_key, agent_id
    else:
        pq_priv, pq_pub = aiss.generate_keypair()
        return pq_priv, aiss.derive_agent_id(pq_pub)


def _resolve_agent_name(identity_file, agent_id, agent_name):
    """
    Résout le nom lisible de l'agent pour BridgeProtocol.
    Priorité : agent_name explicite > agent_id > 'default'
    """
    if agent_name:
        return agent_name
    if agent_id:
        return agent_id
    return "default"


# ─── PiQryptCallbackHandler ───────────────────────────────────────────────────

class PiQryptCallbackHandler(BaseCallbackHandler, BridgeProtocol):
    """
    LangChain callback handler que stamps every LLM call,
    tool call, and chain event with PiQrypt cryptographic proof.

    v1.1.0 — BridgeProtocol intégré :
        - Injection mémoire au démarrage (on_session_start)
        - Gate TrustGate avant chaque tool call (on_action_gate)
        - Historique peer A2A sur on_chain_start si peer_agent_id détecté

    Usage:
        handler = PiQryptCallbackHandler(
            identity_file="my-agent.json",
            agent_name="trading_bot",       # nom pour la mémoire
            inject_memory=True,             # injecter mémoire au démarrage
        )
        # Récupérer le bloc mémoire pour l'injecter dans le system prompt :
        system_prompt = BASE_PROMPT + handler.memory_context

        llm = ChatOpenAI(callbacks=[handler])
        agent = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])
    """

    def __init__(
        self,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        inject_memory: bool = True,
        memory_depth: int = 10,
        enable_gate: bool = True,
    ):
        # ── Identité cryptographique (inchangé) ──────────────────────────────
        BaseCallbackHandler.__init__(self)
        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )

        # ── Résolution nom agent pour mémoire ────────────────────────────────
        self._agent_name = _resolve_agent_name(identity_file, agent_id, agent_name)
        self._enable_gate = enable_gate

        # ── BridgeProtocol — accès mémoire + gate ────────────────────────────
        if _BRIDGE_PROTOCOL_AVAILABLE:
            BridgeProtocol.__init__(
                self,
                agent_name=self._agent_name,
                memory_depth=memory_depth,
            )

        # ── Compteur events (inchangé) ────────────────────────────────────────
        self._event_count = 0
        self._last_event_hash: Optional[str] = None

        # ── Injection mémoire au démarrage ────────────────────────────────────
        # Le bloc est disponible via handler.memory_context pour injection
        # dans le system prompt avant la première inférence.
        self.memory_context: str = ""
        if inject_memory and _BRIDGE_PROTOCOL_AVAILABLE:
            self.memory_context = self.on_session_start()

        # ── Event de démarrage (inchangé) ─────────────────────────────────────
        self._stamp({
            "event_type": "callback_handler_initialized",
            "framework": "langchain",
            "agent_name": self._agent_name,
            "memory_injected": bool(self.memory_context),
            "aiss_profile": "AISS-1",
        })

    # ── Stamp helper interne ──────────────────────────────────────────────────

    def _stamp(self, payload: Dict) -> None:
        """Stamp + store un event, met à jour le compteur et le dernier hash."""
        event = aiss.stamp_event(self._pq_key, self._pq_id, payload)
        aiss.store_event(event)
        self._event_count += 1
        self._last_event_hash = aiss.compute_event_hash(event)

    # ── LLM events (inchangés) ────────────────────────────────────────────────

    def on_llm_start(self, serialized: Dict, prompts, **kwargs) -> None:
        """Stamp every LLM call start."""
        self._stamp({
            "event_type": "llm_start",
            "model": serialized.get("name", "unknown"),
            "prompt_hash": _h(prompts),
            "aiss_profile": "AISS-1",
        })

    def on_llm_end(self, response: LLMResult, **kwargs) -> None:
        """Stamp every LLM response."""
        self._stamp({
            "event_type": "llm_response",
            "response_hash": _h(response),
            "generation_count": len(response.generations),
            "aiss_profile": "AISS-1",
        })

    def on_llm_error(self, error: Exception, **kwargs) -> None:
        """Stamp LLM errors."""
        self._stamp({
            "event_type": "llm_error",
            "error_hash": _h(str(error)),
            "aiss_profile": "AISS-1",
        })

    # ── Tool events — GATE TRUSTGATE ─────────────────────────────────────────

    def on_tool_start(self, serialized: Dict, input_str: str, **kwargs) -> None:
        """
        Stamp every tool call start.
        v1.1.0 : gate TrustGate avant l'exécution si enable_gate=True.
        Lève RuntimeError si l'action est bloquée — arrêt obligatoire.
        """
        tool_name = serialized.get("name", "unknown")

        # ── Gate TrustGate ────────────────────────────────────────────────────
        if self._enable_gate and _BRIDGE_PROTOCOL_AVAILABLE:
            action = BridgeAction(
                name=tool_name,
                payload={"input_hash": _h(input_str)},
            )
            allowed = self.on_action_gate(action)
            if not allowed:
                # Stamp le blocage avant de lever l'exception
                self._stamp({
                    "event_type": "tool_blocked_by_trustgate",
                    "tool_name": tool_name,
                    "input_hash": _h(input_str),
                    "aiss_profile": "AISS-1",
                })
                raise RuntimeError(
                    f"[PiQrypt TrustGate] Action '{tool_name}' bloquée. "
                    f"Consultez le dashboard TrustGate (port 8422)."
                )

        # ── Stamp normal ──────────────────────────────────────────────────────
        self._stamp({
            "event_type": "tool_start",
            "tool_name": tool_name,
            "input_hash": _h(input_str),
            "aiss_profile": "AISS-1",
        })

    def on_tool_end(self, output: str, **kwargs) -> None:
        """Stamp every tool call result."""
        self._stamp({
            "event_type": "tool_end",
            "output_hash": _h(output),
            "aiss_profile": "AISS-1",
        })

    def on_tool_error(self, error: Exception, **kwargs) -> None:
        """Stamp tool errors — important for audit."""
        self._stamp({
            "event_type": "tool_error",
            "error_hash": _h(str(error)),
            "aiss_profile": "AISS-1",
        })

    # ── Chain events — PEER CONTACT + DELTA MEMOIRE ──────────────────────────

    def on_chain_start(self, serialized: Dict, inputs: Dict, **kwargs) -> None:
        """
        Stamp chain start.
        v1.1.0 : si un peer_agent_id est détecté dans les inputs,
        charge l'historique A2A partagé (on_peer_contact).
        """
        peer_id = inputs.get("peer_agent_id") if isinstance(inputs, dict) else None

        peer_summary = ""
        if peer_id and _BRIDGE_PROTOCOL_AVAILABLE:
            peer_ctx = self.on_peer_contact(peer_id)
            peer_summary = peer_ctx.get("summary", "")

        self._stamp({
            "event_type": "chain_start",
            "chain_name": serialized.get("name", "unknown"),
            "inputs_hash": _h(inputs),
            "peer_agent_id": peer_id or "",
            "peer_known": bool(peer_summary),
            "aiss_profile": "AISS-1",
        })

        # Le peer_summary est disponible pour injection dans le prochain prompt
        # via handler.peer_context (accessible depuis l'application)
        self.peer_context: str = peer_summary

    def on_chain_end(self, outputs: Dict, **kwargs) -> None:
        """
        Stamp chain completion.
        v1.1.0 : injection delta mémoire si la session est longue.
        """
        self._stamp({
            "event_type": "chain_end",
            "outputs_hash": _h(outputs),
            "aiss_profile": "AISS-1",
        })

        # Delta mémoire disponible après chaque chain — pour longues sessions
        if _BRIDGE_PROTOCOL_AVAILABLE:
            delta = self.on_session_update()
            if delta:
                self.memory_context = delta  # Le handler expose le delta

    def on_chain_error(self, error: Exception, **kwargs) -> None:
        """Stamp chain errors."""
        self._stamp({
            "event_type": "chain_error",
            "error_hash": _h(str(error)),
            "aiss_profile": "AISS-1",
        })

    # ── Agent events (inchangés) ──────────────────────────────────────────────

    def on_agent_action(self, action, **kwargs) -> None:
        """Stamp every agent action decision."""
        self._stamp({
            "event_type": "agent_action",
            "tool": action.tool,
            "tool_input_hash": _h(action.tool_input),
            "log_hash": _h(action.log),
            "aiss_profile": "AISS-1",
        })

    def on_agent_finish(self, finish, **kwargs) -> None:
        """Stamp agent completion."""
        self._stamp({
            "event_type": "agent_finish",
            "output_hash": _h(finish.return_values),
            "aiss_profile": "AISS-1",
        })

    # ── Propriétés publiques ──────────────────────────────────────────────────

    @property
    def piqrypt_id(self) -> str:
        return self._pq_id

    @property
    def audit_event_count(self) -> int:
        return self._event_count

    @property
    def last_event_hash(self) -> Optional[str]:
        return self._last_event_hash

    def export_audit(self, output_path: str = "langchain-audit.json") -> str:
        aiss.export_audit_chain(output_path)
        return output_path


# ─── AuditedAgentExecutor (inchangé) ─────────────────────────────────────────

class AuditedAgentExecutor(AgentExecutor):
    """
    LangChain AgentExecutor with PiQrypt audit trail.
    Drop-in replacement for AgentExecutor.
    """

    model_config = {"arbitrary_types_allowed": True}

    def __init__(
        self,
        *args,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )
        self._agent_name = _resolve_agent_name(identity_file, agent_id, agent_name)

    def invoke(self, input: Dict, **kwargs) -> Dict:
        """Invoke agent and stamp input + output."""
        start_event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "executor_invoke",
            "input_hash": _h(input),
            "aiss_profile": "AISS-1",
        })
        aiss.store_event(start_event)

        result = super().invoke(input, **kwargs)

        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "executor_complete",
            "output_hash": _h(result),
            "previous_event_hash": aiss.compute_event_hash(start_event),
            "aiss_profile": "AISS-1",
        }))

        return result

    def export_audit(self, output_path: str = "langchain-audit.json") -> str:
        aiss.export_audit_chain(output_path)
        return output_path

    @property
    def piqrypt_id(self) -> str:
        return self._pq_id


# ─── piqrypt_tool decorator (inchangé) ────────────────────────────────────────

def piqrypt_tool(
    tool_name: Optional[str] = None,
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
):
    """Decorator: wrap any LangChain tool function with PiQrypt proof."""
    def decorator(func):
        _key, _id = _resolve_identity(identity_file, private_key, agent_id)
        _name = tool_name or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                aiss.store_event(aiss.stamp_event(_key, _id, {
                    "event_type": "tool_complete",
                    "tool": _name,
                    "args_hash": _h(args),
                    "result_hash": _h(result),
                    "aiss_profile": "AISS-1",
                }))
                return result
            except Exception as e:
                aiss.store_event(aiss.stamp_event(_key, _id, {
                    "event_type": "tool_error",
                    "tool": _name,
                    "error_hash": _h(str(e)),
                    "aiss_profile": "AISS-1",
                }))
                raise
        return wrapper
    return decorator


# ─── stamp_chain decorator (inchangé) ────────────────────────────────────────

def stamp_chain(
    chain_name: str,
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
):
    """Decorator: stamp any chain invocation with PiQrypt proof."""
    def decorator(func):
        _key, _id = _resolve_identity(identity_file, private_key, agent_id)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            aiss.store_event(aiss.stamp_event(_key, _id, {
                "event_type": "chain_start",
                "chain": chain_name,
                "args_hash": _h(args),
                "aiss_profile": "AISS-1",
            }))
            result = func(*args, **kwargs)
            aiss.store_event(aiss.stamp_event(_key, _id, {
                "event_type": "chain_executed",
                "chain": chain_name,
                "result_hash": _h(result),
                "aiss_profile": "AISS-1",
            }))
            return result
        return wrapper
    return decorator


# ─── Convenience export (inchangé) ───────────────────────────────────────────

def export_audit(output_path: str = "langchain-audit.json") -> str:
    """Export full audit trail for this session."""
    aiss.export_audit_chain(output_path)
    return output_path


__all__ = [
    "PiQryptCallbackHandler",
    "AuditedAgentExecutor",
    "piqrypt_tool",
    "stamp_chain",
    "export_audit",
]
