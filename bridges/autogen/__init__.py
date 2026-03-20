# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-autogen — PiQrypt bridge for Microsoft AutoGen

Adds cryptographic audit trails to AutoGen agents and conversations.
Every reply, tool call, and agent interaction is signed,
hash-chained, and tamper-proof.

Install:
    pip install piqrypt-autogen

Usage:
    from piqrypt_autogen import AuditedAssistant, AuditedUserProxy, AuditedGroupChat
"""

__version__ = "1.0.0"
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
    from autogen import AssistantAgent, UserProxyAgent, GroupChatManager
except ImportError:
    raise ImportError(
        "pyautogen is required. Install with: pip install pyautogen"
    )


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


# ─── AuditedAssistant ─────────────────────────────────────────────────────────

class AuditedAssistant(AssistantAgent):
    """
    AutoGen AssistantAgent with PiQrypt cryptographic audit trail.

    Drop-in replacement for AssistantAgent.
    Every reply is Ed25519-signed and hash-chained.

    Usage:
        assistant = AuditedAssistant(
            name="assistant",
            llm_config={"model": "gpt-4o"},
            identity_file="assistant.json"
        )
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

        # Stamp initialization
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "agent_initialized",
            "agent_name": self.name,
            "framework": "autogen",
            "aiss_profile": "AISS-1",
        }))

    def generate_reply(
        self,
        messages: Optional[List[Dict]] = None,
        sender: Optional[Any] = None,
        **kwargs,
    ) -> Union[str, Dict, None]:
        """Generate reply and stamp it cryptographically."""

        reply = super().generate_reply(messages=messages, sender=sender, **kwargs)

        # Stamp the reply
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "reply_generated",
            "agent_name": self.name,
            "sender": sender.name if sender and hasattr(sender, "name") else None,
            "message_count": len(messages) if messages else 0,
            "last_message_hash": _h(messages[-1]) if messages else None,
            "reply_hash": _h(reply),
            "aiss_profile": "AISS-1",
        }))

        return reply

    @property
    def piqrypt_id(self) -> str:
        return self._pq_id

    def export_audit(self, output_path: str = "autogen-audit.json") -> str:
        aiss.export_audit_chain(output_path)
        return output_path


# ─── AuditedUserProxy ─────────────────────────────────────────────────────────

class AuditedUserProxy(UserProxyAgent):
    """
    AutoGen UserProxyAgent with PiQrypt audit trail.

    Stamps every human input, code execution, and tool call.

    Usage:
        user_proxy = AuditedUserProxy(
            name="user_proxy",
            human_input_mode="NEVER",
            identity_file="proxy.json"
        )
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

        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "proxy_initialized",
            "agent_name": self.name,
            "human_input_mode": self.human_input_mode,
            "framework": "autogen",
            "aiss_profile": "AISS-1",
        }))

    def execute_code_blocks(self, code_blocks, **kwargs):
        """Execute code blocks and stamp each execution."""

        results = super().execute_code_blocks(code_blocks, **kwargs)

        # Stamp code execution
        for i, (lang, code) in enumerate(code_blocks):
            aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
                "event_type": "code_executed",
                "agent_name": self.name,
                "language": lang,
                "code_hash": _h(code),      # never store raw code
                "result_hash": _h(results),
                "block_index": i,
                "aiss_profile": "AISS-1",
            }))

        return results

    def generate_reply(
        self,
        messages: Optional[List[Dict]] = None,
        sender: Optional[Any] = None,
        **kwargs,
    ) -> Union[str, Dict, None]:
        """Generate proxy reply and stamp it."""

        reply = super().generate_reply(messages=messages, sender=sender, **kwargs)

        if reply is not None:
            aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
                "event_type": "proxy_reply",
                "agent_name": self.name,
                "sender": sender.name if sender and hasattr(sender, "name") else None,
                "reply_hash": _h(reply),
                "aiss_profile": "AISS-1",
            }))

        return reply

    @property
    def piqrypt_id(self) -> str:
        return self._pq_id


# ─── AuditedGroupChat ─────────────────────────────────────────────────────────

class AuditedGroupChat(GroupChatManager):
    """
    AutoGen GroupChatManager with PiQrypt audit trail.

    Stamps every speaker selection and message in the group chat.
    Each agent in the group should also be an AuditedAssistant
    for full end-to-end auditability.

    Usage:
        group_chat = GroupChat(
            agents=[agent1, agent2, agent3],
            messages=[],
            max_round=10
        )
        manager = AuditedGroupChat(
            groupchat=group_chat,
            llm_config={"model": "gpt-4o"},
            identity_file="group-manager.json"
        )
        user_proxy.initiate_chat(manager, message="Start the analysis")
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

        # Stamp group chat initialization
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


# ─── stamp_reply decorator ────────────────────────────────────────────────────

def stamp_reply(
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
):
    """
    Decorator: stamp any generate_reply method with PiQrypt proof.

    Useful when you cannot subclass (e.g. third-party agent classes).

    Usage:
        agent = SomeThirdPartyAgent(...)
        agent.generate_reply = stamp_reply(
            identity_file="my-agent.json"
        )(agent.generate_reply)
    """
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


# ─── Conversation audit helper ────────────────────────────────────────────────

def stamp_conversation(
    messages: List[Dict],
    private_key: bytes,
    agent_id: str,
    conversation_id: Optional[str] = None,
) -> str:
    """
    Stamp a complete AutoGen conversation as a single event.

    Useful for post-hoc auditing of an entire conversation.

    Args:
        messages: Full conversation message list
        private_key: PiQrypt private key
        agent_id: PiQrypt agent ID
        conversation_id: Optional conversation identifier

    Returns:
        Hash of the conversation event
    """
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


# ─── Convenience export ───────────────────────────────────────────────────────

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
