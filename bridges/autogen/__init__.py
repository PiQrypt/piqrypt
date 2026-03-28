# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-autogen — PiQrypt bridge for AutoGen

Adds cryptographic audit trails to AutoGen agents and conversations.
Every message exchange, code execution, and group chat turn is signed,
hash-chained, and tamper-proof.

Install:
    pip install piqrypt-autogen

Usage:
    from piqrypt_autogen import AuditedAssistant, AuditedUserProxy, AuditedGroupChat
"""

__version__ = "1.1.0"
__author__ = "PiQrypt Contributors"
__license__ = "Apache-2.0"

import hashlib
import functools
from typing import Any, Dict, List, Optional, Union

try:
    import piqrypt as aiss
except ImportError:
    raise ImportError(
        "piqrypt is required. Install with: pip install piqrypt"
    )

try:
    from autogen import AssistantAgent, UserProxyAgent, GroupChat, GroupChatManager
    ConversableAgent = AssistantAgent.__bases__[0]
except ImportError:
    raise ImportError(
        "autogen is required. Install with: pip install pyautogen"
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


def _resolve_identity(identity_file, private_key, agent_id):
    if identity_file:
        identity = aiss.load_identity(identity_file)
        return identity["private_key_bytes"], identity["agent_id"]
    elif private_key and agent_id:
        return private_key, agent_id
    else:
        pq_priv, pq_pub = aiss.generate_keypair()
        return pq_priv, aiss.derive_agent_id(pq_pub)


# ─── Mixin commun ─────────────────────────────────────────────────────────────

class _PiQryptMixin(BridgeProtocol):
    """
    Mixin partagé entre AuditedAssistant et AuditedUserProxy.
    Centralise l'initialisation BridgeProtocol et les helpers communs.
    """

    def _piqrypt_init(
        self,
        identity_file=None,
        private_key=None,
        agent_id=None,
        agent_name=None,
        inject_memory=True,
        memory_depth=10,
        enable_gate=True,
    ):
        """Appelé depuis __init__ de chaque sous-classe après super().__init__()."""
        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )
        # Priorité : agent_name > name AutoGen > agent_id[:16]
        self._agent_name = (
            agent_name
            or getattr(self, "name", None)
            or self._pq_id[:16]
        )
        self._enable_gate = enable_gate
        self._event_count = 0
        self._last_event_hash: Optional[str] = None

        if _BRIDGE_PROTOCOL_AVAILABLE:
            BridgeProtocol.__init__(
                self,
                agent_name=self._agent_name,
                memory_depth=memory_depth,
            )

        # Injection mémoire au démarrage
        self.memory_context: str = ""
        if inject_memory and _BRIDGE_PROTOCOL_AVAILABLE:
            self.memory_context = self.on_session_start()

    def _stamp(self, payload: Dict) -> None:
        event = aiss.stamp_event(self._pq_key, self._pq_id, payload)
        aiss.store_event(event)
        self._event_count += 1
        self._last_event_hash = aiss.compute_event_hash(event)

    def _gate(self, action_name: str, payload: Dict) -> bool:
        """
        Gate TrustGate. Retourne True = continuer, False = bloquer.
        Stamp un event tool_blocked si bloqué.
        """
        if not self._enable_gate or not _BRIDGE_PROTOCOL_AVAILABLE:
            return True
        action = BridgeAction(name=action_name, payload=payload)
        allowed = self.on_action_gate(action)
        if not allowed:
            self._stamp({
                "event_type": "reply_blocked_by_trustgate",
                "action": action_name,
                "agent_name": self._agent_name,
                "aiss_profile": "AISS-1",
            })
        return allowed

    @property
    def piqrypt_id(self) -> str:
        return self._pq_id

    @property
    def audit_event_count(self) -> int:
        return self._event_count

    @property
    def last_event_hash(self) -> Optional[str]:
        return self._last_event_hash

    def export_audit(self, output_path: str = "autogen-audit.json") -> str:
        aiss.export_audit_chain(output_path)
        return output_path


# ─── AuditedAssistant ─────────────────────────────────────────────────────────

class AuditedAssistant(AssistantAgent, _PiQryptMixin):
    """
    AutoGen AssistantAgent with PiQrypt cryptographic audit trail.

    v1.1.0 — BridgeProtocol intégré :
        - Injection mémoire au démarrage
        - Gate TrustGate avant generate_reply()
        - Delta mémoire après chaque reply

    Usage:
        assistant = AuditedAssistant(
            name="analyst",
            system_message="You are a financial analyst.",
            identity_file="~/.piqrypt/analyst.json",
            agent_name="analyst",
            inject_memory=True,
        )
        # Bloc mémoire disponible pour injection dans system_message :
        assistant.system_message += "\\n" + assistant.memory_context
    """

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
        AssistantAgent.__init__(self, *args, **kwargs)
        self._piqrypt_init(
            identity_file=identity_file,
            private_key=private_key,
            agent_id=agent_id,
            agent_name=agent_name,
            inject_memory=inject_memory,
            memory_depth=memory_depth,
            enable_gate=enable_gate,
        )
        self._stamp({
            "event_type": "assistant_initialized",
            "agent_name": self._agent_name,
            "autogen_name": getattr(self, "name", "unknown"),
            "framework": "autogen",
            "memory_injected": bool(self.memory_context),
            "aiss_profile": "AISS-1",
        })

    def generate_reply(
        self,
        messages: Optional[List[Dict]] = None,
        sender: Optional[Any] = None,
        **kwargs,
    ) -> Union[str, Dict, None]:
        """
        Generate reply with PiQrypt audit trail.

        v1.1.0 : gate TrustGate avant génération.
        Si bloqué, retourne None (AutoGen interpréte None comme fin de conversation).
        """
        sender_name = sender.name if sender and hasattr(sender, "name") else "unknown"

        # ── Gate TrustGate ────────────────────────────────────────────────────
        # AutoGen : bloquer = retourner None, pas lever une exception
        # (lever une exception casserait le groupe chat)
        if not self._gate(
            action_name="generate_reply",
            payload={
                "message_count": len(messages) if messages else 0,
                "sender": sender_name,
            },
        ):
            return None

        # ── Génération (inchangé) ─────────────────────────────────────────────
        reply = super().generate_reply(messages=messages, sender=sender, **kwargs)

        if reply is not None:
            self._stamp({
                "event_type": "assistant_reply",
                "agent_name": self._agent_name,
                "sender": sender_name,
                "message_count": len(messages) if messages else 0,
                "reply_hash": _h(reply),
                "aiss_profile": "AISS-1",
            })

            # ── Delta mémoire après reply ─────────────────────────────────────
            if _BRIDGE_PROTOCOL_AVAILABLE:
                delta = self.on_session_update()
                if delta:
                    self.memory_context = delta

        return reply


# ─── AuditedUserProxy ─────────────────────────────────────────────────────────

class AuditedUserProxy(UserProxyAgent, _PiQryptMixin):
    """
    AutoGen UserProxyAgent with PiQrypt cryptographic audit trail.

    v1.1.0 — BridgeProtocol intégré.
    Le gate opère sur generate_reply() et execute_code_blocks().
    """

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
        UserProxyAgent.__init__(self, *args, **kwargs)
        self._piqrypt_init(
            identity_file=identity_file,
            private_key=private_key,
            agent_id=agent_id,
            agent_name=agent_name,
            inject_memory=inject_memory,
            memory_depth=memory_depth,
            enable_gate=enable_gate,
        )
        self._stamp({
            "event_type": "proxy_initialized",
            "agent_name": self._agent_name,
            "autogen_name": getattr(self, "name", "unknown"),
            "human_input_mode": getattr(self, "human_input_mode", "unknown"),
            "framework": "autogen",
            "memory_injected": bool(self.memory_context),
            "aiss_profile": "AISS-1",
        })

    def execute_code_blocks(self, code_blocks, **kwargs):
        """
        Execute code blocks with gate TrustGate.
        v1.1.0 : le gate s'applique avant toute exécution de code.
        """
        # Gate sur l'exécution de code — action sensible par définition
        if not self._gate(
            action_name="execute_code",
            payload={"block_count": len(code_blocks) if code_blocks else 0},
        ):
            raise RuntimeError(
                f"[PiQrypt TrustGate] Exécution de code bloquée pour '{self._agent_name}'. "
                f"Consultez le dashboard TrustGate (port 8422)."
            )

        results = super().execute_code_blocks(code_blocks, **kwargs)

        for i, (lang, code) in enumerate(code_blocks):
            self._stamp({
                "event_type": "code_executed",
                "agent_name": self._agent_name,
                "language": lang,
                "code_hash": _h(code),
                "result_hash": _h(results),
                "block_index": i,
                "aiss_profile": "AISS-1",
            })

        return results

    def generate_reply(
        self,
        messages: Optional[List[Dict]] = None,
        sender: Optional[Any] = None,
        **kwargs,
    ) -> Union[str, Dict, None]:
        """Generate proxy reply with audit trail."""
        reply = super().generate_reply(messages=messages, sender=sender, **kwargs)

        if reply is not None:
            self._stamp({
                "event_type": "proxy_reply",
                "agent_name": self._agent_name,
                "sender": sender.name if sender and hasattr(sender, "name") else None,
                "reply_hash": _h(reply),
                "aiss_profile": "AISS-1",
            })

        return reply


# ─── AuditedGroupChat (inchangé — gate au niveau des agents) ─────────────────

class AuditedGroupChat(GroupChatManager):
    """
    AutoGen GroupChatManager with PiQrypt audit trail.

    Le gate TrustGate opère au niveau de chaque AuditedAssistant/UserProxy.
    AuditedGroupChat se concentre sur la traçabilité de la session globale.
    """

    def __init__(
        self,
        *args,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )

        gc = self.groupchat if hasattr(self, "groupchat") else None
        agent_names = [a.name for a in gc.agents] if gc else []

        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "groupchat_initialized",
            "agent_names": agent_names,
            "agent_count": len(agent_names),
            "framework": "autogen",
            "aiss_profile": "AISS-1",
        }))

    def run_chat(self, messages=None, sender=None, config=None):
        """Run group chat and stamp start + completion."""
        start_event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "groupchat_start",
            "message_count": len(messages) if messages else 0,
            "initial_message_hash": _h(messages[-1]) if messages else None,
            "aiss_profile": "AISS-1",
        })
        aiss.store_event(start_event)

        result = super().run_chat(messages=messages, sender=sender, config=config)

        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "groupchat_complete",
            "previous_event_hash": aiss.compute_event_hash(start_event),
            "aiss_profile": "AISS-1",
        }))

        return result

    def export_audit(self, output_path: str = "groupchat-audit.json") -> str:
        aiss.export_audit_chain(output_path)
        return output_path

    @property
    def piqrypt_id(self) -> str:
        return self._pq_id


# ─── stamp_reply decorator (inchangé) ────────────────────────────────────────

def stamp_reply(
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
):
    """Decorator: stamp any generate_reply method with PiQrypt proof."""
    def decorator(func):
        _key, _id = _resolve_identity(identity_file, private_key, agent_id)

        @functools.wraps(func)
        def wrapper(messages=None, sender=None, **kwargs):
            reply = func(messages=messages, sender=sender, **kwargs)
            if reply is not None:
                aiss.store_event(aiss.stamp_event(_key, _id, {
                    "event_type": "reply_generated",
                    "message_count": len(messages) if messages else 0,
                    "reply_hash": _h(reply),
                    "aiss_profile": "AISS-1",
                }))
            return reply
        return wrapper
    return decorator


# ─── stamp_conversation (inchangé) ───────────────────────────────────────────

def stamp_conversation(
    messages: List[Dict],
    private_key: bytes,
    agent_id: str,
    conversation_id: Optional[str] = None,
) -> str:
    """Stamp a complete AutoGen conversation as a single event."""
    event = aiss.stamp_event(private_key, agent_id, {
        "event_type": "conversation_stamped",
        "conversation_id": conversation_id,
        "message_count": len(messages),
        "conversation_hash": _h(messages),
        "speakers": list({m.get("name", "unknown") for m in messages}),
        "aiss_profile": "AISS-1",
    })
    aiss.store_event(event)
    return aiss.compute_event_hash(event)


# ─── Convenience export (inchangé) ───────────────────────────────────────────

def export_audit(output_path: str = "autogen-audit.json") -> str:
    """Export full audit trail for this session."""
    aiss.export_audit_chain(output_path)
    return output_path


__all__ = [
    "AuditedAssistant",
    "AuditedUserProxy",
    "AuditedGroupChat",
    "stamp_reply",
    "stamp_conversation",
    "export_audit",
]
