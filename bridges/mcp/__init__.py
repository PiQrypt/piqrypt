# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-mcp — PiQrypt bridge for Model Context Protocol (MCP)

Adds cryptographic audit trail to MCP tool calls, resource reads,
and prompt invocations. Every interaction is signed Ed25519,
hash-chained, and tamper-proof.

Install:
    pip install piqrypt[mcp]

Usage:
    from piqrypt_mcp import AuditedMCPClient
"""

__version__ = "1.1.0"
__author__  = "PiQrypt Contributors"
__license__ = "Apache-2.0"

import hashlib
import time
from typing import Any, Dict, Optional

try:
    import piqrypt as aiss
except ImportError:
    raise ImportError("piqrypt is required. Install with: pip install piqrypt")

# ── BridgeProtocol — contrat moteur AISS ──────────────────────────────────────
try:
    from aiss.bridge_protocol import BridgeProtocol, BridgeAction
    _BRIDGE_PROTOCOL_AVAILABLE = True
except ImportError:
    BridgeProtocol = object
    BridgeAction = None
    _BRIDGE_PROTOCOL_AVAILABLE = False


def _h(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _resolve_identity(identity_file, agent_name):
    if identity_file:
        identity = aiss.load_identity(identity_file)
        return identity["private_key_bytes"], identity["agent_id"]
    pq_priv, pq_pub = aiss.generate_keypair()
    return pq_priv, aiss.derive_agent_id(pq_pub)


class AuditedMCPClient(BridgeProtocol):
    """
    MCP client with PiQrypt cryptographic audit trail.

    v1.1.0 — BridgeProtocol intégré :
        - Injection mémoire au démarrage (__aenter__)
        - Gate TrustGate avant call_tool()
        - read_resource() et get_prompt() : pas de gate (lecture seule)

    Usage:
        client = AuditedMCPClient(
            server_url="http://localhost:8000",
            identity_file="~/.piqrypt/agent.json",
            agent_name="mcp_agent",
        )
        async with client:
            # Bloc mémoire disponible après __aenter__ :
            print(client.memory_context)
            result = await client.call_tool("search", {"query": "AAPL"})
    """

    def __init__(
        self,
        server_url: str = "http://localhost:8000",
        identity_file: Optional[str] = None,
        agent_name: Optional[str] = None,
        memory_depth: int = 10,
        enable_gate: bool = True,
    ):
        self.server_url  = server_url
        self._priv, self.piqrypt_id = _resolve_identity(identity_file, agent_name)
        self._last_hash: Optional[str] = None
        self._event_count = 0
        self._enable_gate = enable_gate

        # Résolution nom agent
        self._agent_name = agent_name or self.piqrypt_id[:16]

        # BridgeProtocol
        if _BRIDGE_PROTOCOL_AVAILABLE:
            BridgeProtocol.__init__(
                self,
                agent_name=self._agent_name,
                memory_depth=memory_depth,
            )

        # Bloc mémoire — chargé dans __aenter__ (contexte async)
        self.memory_context: str = ""

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self):
        # Injection mémoire au démarrage de la session MCP
        if _BRIDGE_PROTOCOL_AVAILABLE:
            self.memory_context = self.on_session_start()

        self._stamp("mcp_session_start", {
            "server_hash":     _h(self.server_url),
            "memory_injected": bool(self.memory_context),
        })
        return self

    async def __aexit__(self, *args):
        self._stamp("mcp_session_end", {
            "total_calls": self._event_count,
        })

    # ── Core stamping ─────────────────────────────────────────────────────────

    def _stamp(self, event_type: str, payload: Dict[str, Any]) -> str:
        event = {
            "event_type": event_type,
            "agent_id":   self.piqrypt_id,
            **payload,
        }
        if self._last_hash:
            event["previous_event_hash"] = self._last_hash

        stamped = aiss.stamp_event(self._priv, self.piqrypt_id, event)
        aiss.store_event(stamped)
        self._last_hash = aiss.compute_event_hash(stamped)
        self._event_count += 1
        return self._last_hash

    # ── MCP operations ────────────────────────────────────────────────────────

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """
        Call an MCP tool with PiQrypt audit trail.

        v1.1.0 : gate TrustGate avant l'appel.
        Les tool calls sont des actions — elles passent par le gate.
        Lève RuntimeError si bloqué.
        """
        # ── Gate TrustGate ────────────────────────────────────────────────────
        if self._enable_gate and _BRIDGE_PROTOCOL_AVAILABLE:
            action = BridgeAction(
                name=tool_name,
                payload={"args_hash": _h(arguments)},
            )
            allowed = self.on_action_gate(action)
            if not allowed:
                self._stamp("mcp_tool_blocked", {
                    "tool_name": tool_name,
                    "args_hash": _h(arguments),
                })
                raise RuntimeError(
                    f"[PiQrypt TrustGate] Tool '{tool_name}' bloqué. "
                    f"Consultez le dashboard TrustGate (port 8422)."
                )

        # ── Appel (inchangé) ──────────────────────────────────────────────────
        self._stamp("mcp_tool_call", {
            "tool_name": tool_name,
            "args_hash": _h(arguments),
            "ts":        time.time(),
        })
        try:
            result = await self._do_call_tool(tool_name, arguments)
            self._stamp("mcp_tool_result", {
                "tool_name":   tool_name,
                "result_hash": _h(result),
            })

            # Delta mémoire après chaque tool call réussi
            if _BRIDGE_PROTOCOL_AVAILABLE:
                delta = self.on_session_update()
                if delta:
                    self.memory_context = delta

            return result
        except RuntimeError:
            # Re-raise sans stamp supplémentaire (déjà stamped)
            raise
        except Exception as e:
            self._stamp("mcp_tool_error", {
                "tool_name":  tool_name,
                "error_type": type(e).__name__,
                "error_hash": _h(str(e)),
            })
            raise

    async def read_resource(self, uri: str) -> Any:
        """
        Read an MCP resource.
        Pas de gate — lecture seule, pas d'action irréversible.
        """
        self._stamp("mcp_resource_read_start", {
            "uri_hash": _h(uri),
            "ts":       time.time(),
        })
        result = await self._do_read_resource(uri)
        self._stamp("mcp_resource_read_complete", {
            "uri_hash":     _h(uri),
            "content_hash": _h(result),
        })
        return result

    async def get_prompt(self, name: str, arguments: Optional[Dict] = None) -> Any:
        """
        Get an MCP prompt.
        Pas de gate — récupération de template, pas d'action.
        """
        self._stamp("mcp_prompt_get", {
            "prompt_name": name,
            "args_hash":   _h(arguments or {}),
        })
        result = await self._do_get_prompt(name, arguments)
        self._stamp("mcp_prompt_result", {
            "prompt_name":   name,
            "messages_hash": _h(result),
        })
        return result

    # ── Override ces méthodes dans les sous-classes ───────────────────────────

    async def _do_call_tool(self, tool_name: str, arguments: Dict) -> Any:
        raise NotImplementedError(
            "Inject a real MCP client via subclass or composition"
        )

    async def _do_read_resource(self, uri: str) -> Any:
        raise NotImplementedError(
            "Inject a real MCP client via subclass or composition"
        )

    async def _do_get_prompt(self, name: str, arguments: Optional[Dict]) -> Any:
        raise NotImplementedError(
            "Inject a real MCP client via subclass or composition"
        )

    # ── Inspection / export ───────────────────────────────────────────────────

    @property
    def audit_event_count(self) -> int:
        return self._event_count

    @property
    def last_event_hash(self) -> Optional[str]:
        return self._last_hash

    def export_audit(self, path: str) -> str:
        aiss.export_audit_chain(path)
        return path

    def __repr__(self):
        return (
            f"AuditedMCPClient("
            f"server={self.server_url!r}, "
            f"id={self.piqrypt_id[:16]}...)"
        )


def export_audit(path: str) -> str:
    """Export the full MCP audit trail to a JSON file."""
    aiss.export_audit_chain(path)
    return path


__all__ = [
    "AuditedMCPClient",
    "export_audit",
]
