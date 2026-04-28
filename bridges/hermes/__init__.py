# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) â€” DSO2026009143 (12/03/2026)

"""
piqrypt-hermes â€” PiQrypt plugin for Hermes Agent  v1.0.0

Hermes plugin that adds a cryptographic audit trail to every tool call.

How it works:
    - on_session_start  â†’ stamps agent_initialized, loads memory context
    - pre_tool_call     â†’ stamps tool_intent (before execution)
    - post_tool_call    â†’ stamps tool_result (after execution, chained)
    - pre_llm_call      â†’ injects recent PiQrypt memory into the LLM turn
    - on_session_end    â†’ stamps session_end

Installation (pip):
    pip install piqrypt-hermes
    hermes plugins enable piqrypt-audit

Installation (directory):
    cp -r bridges/hermes ~/.hermes/plugins/piqrypt-audit
    hermes plugins enable piqrypt-audit

The agent identity is resolved in this order:
    1. PIQRYPT_IDENTITY_FILE env var (path to a .json identity file)
    2. PIQRYPT_AGENT_NAME env var  (uses PiQrypt default agent dir)
    3. Auto-generated ephemeral keypair (keys NOT persisted)
"""

__version__ = "1.0.0"
__author__  = "PiQrypt Contributors"
__license__ = "Apache-2.0"

import hashlib
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("piqrypt.hermes")

# â”€â”€ piqrypt import â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

try:
    import piqrypt as aiss
    _PIQRYPT_AVAILABLE = True
except ImportError:
    _PIQRYPT_AVAILABLE = False
    logger.warning(
        "[piqrypt-hermes] piqrypt not installed â€” audit trail disabled. "
        "Run: pip install piqrypt"
    )

# â”€â”€ BridgeProtocol (optional â€” graceful degradation) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

try:
    from aiss.bridge_protocol import BridgeProtocol
    _BRIDGE_PROTOCOL_AVAILABLE = True
except ImportError:
    BridgeProtocol = object
    _BRIDGE_PROTOCOL_AVAILABLE = False


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _h(value: Any) -> str:
    """SHA-256 of any value â€” never stores raw content."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _resolve_identity():
    """
    Resolve PiQrypt identity from environment or generate an ephemeral one.

    Priority:
        1. PIQRYPT_IDENTITY_FILE  â€” path to a saved .json identity
        2. PIQRYPT_AGENT_NAME     â€” name of an agent in the default PiQrypt dir
        3. Ephemeral keypair      â€” logged as WARNING (keys lost on restart)
    """
    if not _PIQRYPT_AVAILABLE:
        return None, None

    identity_file = os.environ.get("PIQRYPT_IDENTITY_FILE")
    agent_name    = os.environ.get("PIQRYPT_AGENT_NAME")

    try:
        if identity_file:
            identity = aiss.load_identity(identity_file)
            logger.info("[piqrypt-hermes] Identity loaded from %s", identity_file)
            return identity["private_key_bytes"], identity["agent_id"]

        if agent_name:
            identity = aiss.load_identity(agent_name=agent_name)
            logger.info("[piqrypt-hermes] Identity loaded for agent '%s'", agent_name)
            return identity["private_key_bytes"], identity["agent_id"]

        # Ephemeral fallback
        priv, pub = aiss.generate_keypair()
        agent_id  = aiss.derive_agent_id(pub)
        logger.warning(
            "[piqrypt-hermes] No identity configured â€” using ephemeral keypair. "
            "Set PIQRYPT_IDENTITY_FILE or PIQRYPT_AGENT_NAME for persistent identity."
        )
        return priv, agent_id

    except Exception as exc:
        logger.error("[piqrypt-hermes] Identity resolution failed: %s", exc)
        priv, pub = aiss.generate_keypair()
        return priv, aiss.derive_agent_id(pub)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PiQryptAuditPlugin
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _PiQryptAuditPlugin(BridgeProtocol if _BRIDGE_PROTOCOL_AVAILABLE else object):
    """
    Internal plugin state. One instance per Hermes session.

    Not exposed publicly â€” the Hermes plugin API uses the module-level
    register() function.
    """

    def __init__(self):
        self._pq_key, self._pq_id = _resolve_identity()
        self._last_hash: Optional[str]  = None
        self._event_count: int          = 0
        self._memory_context: str       = ""
        self._session_id: Optional[str] = None

        agent_name = (
            os.environ.get("PIQRYPT_AGENT_NAME")
            or "hermes"
        )

        if _BRIDGE_PROTOCOL_AVAILABLE and _PIQRYPT_AVAILABLE:
            BridgeProtocol.__init__(
                self,
                agent_name=agent_name,
                memory_depth=int(os.environ.get("PIQRYPT_MEMORY_DEPTH", "10")),
            )
            self._memory_context = self.on_session_start()

        self._stamp("agent_initialized", {
            "framework":       "hermes",
            "agent_name":      agent_name,
            "memory_injected": bool(self._memory_context),
            "aiss_profile":    "AISS-1",
        })

    # â”€â”€ Internal stamp â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _stamp(self, event_type: str, payload: Dict) -> Optional[Dict]:
        """Sign, chain and store one audit event. Noop if piqrypt unavailable."""
        if not _PIQRYPT_AVAILABLE or self._pq_key is None:
            return None

        full_payload = {"event_type": event_type, **payload}
        try:
            event = aiss.stamp_event(self._pq_key, self._pq_id, full_payload)
            aiss.store_event(event)
            self._event_count += 1
            self._last_hash = aiss.compute_event_hash(event)
            return event
        except Exception as exc:
            logger.error("[piqrypt-hermes] stamp failed (%s): %s", event_type, exc)
            return None

    # â”€â”€ Hook handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def handle_session_start(self, session_id: str, **kwargs):
        self._session_id = session_id
        self._stamp("session_start", {
            "session_id":    session_id,
            "aiss_profile":  "AISS-1",
        })

    def handle_pre_llm_call(
        self,
        session_id: str,
        model: str,
        is_first_turn: bool,
        user_message: Optional[str] = None,
        **kwargs,
    ) -> Optional[Dict[str, str]]:
        """
        Inject recent PiQrypt memory into the current LLM turn.

        Hermes appends the returned 'context' string to the user message.
        On first turn: inject full memory block.
        On subsequent turns: inject delta only (events since last injection).
        """
        if not _PIQRYPT_AVAILABLE or not _BRIDGE_PROTOCOL_AVAILABLE:
            return None

        try:
            if is_first_turn:
                context = self._memory_context
            else:
                context = self.on_session_update()

            if context:
                return {"context": context}
        except Exception as exc:
            logger.debug("[piqrypt-hermes] memory injection skipped: %s", exc)

        return None

    def handle_pre_tool_call(self, tool_name: str, params: Dict, **kwargs):
        """Stamp tool intent before execution."""
        self._stamp("tool_intent", {
            "tool_name":   tool_name,
            "params_hash": _h(params),
            "session_id":  self._session_id,
            "aiss_profile": "AISS-1",
        })

    def handle_post_tool_call(self, tool_name: str, params: Dict, result: Any, **kwargs):
        """Stamp tool result after execution, chained to the intent event."""
        self._stamp("tool_result", {
            "tool_name":    tool_name,
            "params_hash":  _h(params),
            "result_hash":  _h(result),
            "session_id":   self._session_id,
            "event_count":  self._event_count,
            "aiss_profile": "AISS-1",
        })

    def handle_session_end(self, session_id: str, **kwargs):
        self._stamp("session_end", {
            "session_id":  session_id,
            "total_events": self._event_count,
            "aiss_profile": "AISS-1",
        })


# â”€â”€ Singleton â€” one plugin instance per process â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_plugin: Optional[_PiQryptAuditPlugin] = None


def _get_plugin() -> Optional[_PiQryptAuditPlugin]:
    global _plugin
    if _plugin is None and _PIQRYPT_AVAILABLE:
        try:
            _plugin = _PiQryptAuditPlugin()
        except Exception as exc:
            logger.error("[piqrypt-hermes] Plugin init failed: %s", exc)
    return _plugin


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Hermes plugin entry point
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def register(ctx):
    """
    Hermes plugin registration function.

    Called once by Hermes at startup when the plugin is enabled.
    Registers hooks that stamp every tool call and inject PiQrypt
    memory context into every LLM turn.
    """
    if not _PIQRYPT_AVAILABLE:
        # Surface the missing dependency as a Hermes tool warning, not a crash
        logger.warning(
            "[piqrypt-hermes] piqrypt not available â€” "
            "install with: pip install piqrypt"
        )
        return

    plugin = _get_plugin()
    if plugin is None:
        return

    ctx.register_hook("on_session_start", plugin.handle_session_start)
    ctx.register_hook("pre_llm_call",     plugin.handle_pre_llm_call)
    ctx.register_hook("pre_tool_call",    plugin.handle_pre_tool_call)
    ctx.register_hook("post_tool_call",   plugin.handle_post_tool_call)
    ctx.register_hook("on_session_end",   plugin.handle_session_end)

    logger.info(
        "[piqrypt-hermes] PiQrypt audit trail active â€” agent_id=%s",
        plugin._pq_id,
    )
