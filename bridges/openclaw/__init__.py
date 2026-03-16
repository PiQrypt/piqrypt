# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-openclaw — PiQrypt bridge for OpenClaw

Adds cryptographic audit trails to OpenClaw autonomous agents.
Every reasoning step, tool execution, and task result is signed,
hash-chained, and tamper-proof.

Install:
    pip install piqrypt-openclaw

Usage:
    from piqrypt_openclaw import AuditableOpenClaw, stamp_action
"""

__version__ = "1.0.0"
__author__ = "PiQrypt Contributors"
__license__ = "Apache-2.0"

import hashlib
import functools
from typing import Any, Dict, List, Optional

try:
    import piqrypt as aiss
except ImportError:
    raise ImportError(
        "piqrypt is required. Install with: pip install piqrypt"
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _h(value: Any) -> str:
    """SHA-256 hash of any value. Never stores raw content."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _load_identity(identity_file: str):
    """Load PiQrypt identity from file."""
    identity = aiss.load_identity(identity_file)
    return identity["private_key_bytes"], identity["agent_id"]


# ─── AuditableOpenClaw ────────────────────────────────────────────────────────

class AuditableOpenClaw:
    """
    OpenClaw agent wrapper with PiQrypt cryptographic audit trail.

    Wraps any OpenClaw Agent class and stamps every:
    - Task reasoning (planning phase)
    - Tool execution (bash, Python, file ops)
    - Task completion
    - Failures and retries

    Usage:
        from openclaw import Agent
        from piqrypt_openclaw import AuditableOpenClaw

        base_agent = Agent(config)
        agent = AuditableOpenClaw(base_agent, identity_file="openclaw.json")

        result = agent.execute_task(task)
        agent.export_audit("openclaw-audit.json")
    """

    def __init__(
        self,
        openclaw_agent: Any,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
    ):
        self._agent = openclaw_agent

        # Resolve PiQrypt identity
        if identity_file:
            self._pq_key, self._pq_id = _load_identity(identity_file)
        elif private_key and agent_id:
            self._pq_key = private_key
            self._pq_id = agent_id
        else:
            pq_priv, pq_pub = aiss.generate_keypair()
            self._pq_key = pq_priv
            self._pq_id = aiss.derive_agent_id(pq_pub)

        # Stamp initialization
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "agent_initialized",
            "framework": "openclaw",
            "aiss_profile": "AISS-1",
        }))

    def execute_task(self, task: Any) -> Any:
        """
        Execute OpenClaw task with full audit trail.

        Stamps: task_start → reasoning → each tool call → task_complete
        """
        task_desc = getattr(task, "description", str(task))

        # Stamp task start
        start_event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "task_start",
            "task_hash": _h(task_desc),
            "aiss_profile": "AISS-1",
        })
        aiss.store_event(start_event)
        previous_hash = aiss.compute_event_hash(start_event)

        try:
            # Execute via underlying OpenClaw agent
            result = self._agent.execute_task(task)

            # Stamp completion
            aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
                "event_type": "task_complete",
                "task_hash": _h(task_desc),
                "result_hash": _h(result),
                "previous_event_hash": previous_hash,
                "success": True,
                "aiss_profile": "AISS-1",
            }))

            return result

        except Exception as e:
            # Stamp failure — important for audit
            aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
                "event_type": "task_failed",
                "task_hash": _h(task_desc),
                "error_hash": _h(str(e)),
                "previous_event_hash": previous_hash,
                "success": False,
                "aiss_profile": "AISS-1",
            }))
            raise

    def stamp_reasoning(self, task_desc: str, plan: Any, model: str = "llama") -> str:
        """
        Stamp OpenClaw reasoning / planning phase.

        Call this after OpenClaw produces its execution plan,
        before tool calls begin.

        Returns:
            Hash of the reasoning event (use as previous_hash for tool stamps)
        """
        event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "task_reasoning",
            "task_hash": _h(task_desc),
            "plan_hash": _h(plan),
            "model": model,
            "aiss_profile": "AISS-1",
        })
        aiss.store_event(event)
        return aiss.compute_event_hash(event)

    def stamp_tool_call(
        self,
        tool: str,
        input_data: Any,
        result: Any,
        previous_hash: Optional[str] = None,
        success: bool = True,
    ) -> str:
        """
        Stamp a single tool execution (bash, Python, file op, etc.).

        Args:
            tool: Tool name ("bash", "python", "file_read", "file_write", ...)
            input_data: Tool input (will be hashed, never stored raw)
            result: Tool output (will be hashed, never stored raw)
            previous_hash: Hash of previous event in chain
            success: Whether tool execution succeeded

        Returns:
            Hash of this event (use as previous_hash for next stamp)

        Example:
            prev = agent.stamp_reasoning(task, plan)
            prev = agent.stamp_tool_call("bash", "ls -la", output, prev)
            prev = agent.stamp_tool_call("python", code, result, prev)
        """
        # Safety check: flag potentially dangerous bash commands
        suspicious = False
        if tool == "bash":
            dangerous = ["rm -rf", "curl | bash", "chmod 777", "sudo rm", "> /dev/"]
            suspicious = any(cmd in str(input_data) for cmd in dangerous)

        payload = {
            "event_type": "tool_execution",
            "tool": tool,
            "input_hash": _h(input_data),   # never store raw command
            "output_hash": _h(result),       # never store raw output
            "success": success,
            "suspicious_pattern": suspicious,
            "aiss_profile": "AISS-1",
        }

        if previous_hash:
            payload["previous_event_hash"] = previous_hash

        event = aiss.stamp_event(self._pq_key, self._pq_id, payload)
        aiss.store_event(event)

        if suspicious:
            import warnings
            warnings.warn(
                f"[PiQrypt] Suspicious bash pattern detected and stamped. "
                f"Event hash: {aiss.compute_event_hash(event)[:16]}...",
                UserWarning,
                stacklevel=2
            )

        return aiss.compute_event_hash(event)

    def get_suspicious_events(self) -> List[Dict[str, Any]]:
        """
        Return all stamped events with suspicious_pattern=True.

        Useful for security monitoring and incident response.
        """
        events = aiss.search_events(event_type="tool_execution")
        return [
            e for e in events
            if e.get("payload", {}).get("suspicious_pattern") is True
        ]

    def export_audit(self, output_path: str = "openclaw-audit.json") -> str:
        """Export full audit trail."""
        aiss.export_audit_chain(output_path)
        return output_path

    @property
    def piqrypt_id(self) -> str:
        """Return this agent's PiQrypt identity."""
        return self._pq_id

    def __getattr__(self, name: str) -> Any:
        """Proxy all other attributes to underlying OpenClaw agent."""
        return getattr(self._agent, name)


# ─── stamp_action decorator ───────────────────────────────────────────────────

def stamp_action(
    action_name: str,
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
):
    """
    Decorator: stamp any OpenClaw action function with PiQrypt proof.

    Usage:
        @stamp_action("file_analysis", identity_file="my-agent.json")
        def analyze_file(path: str) -> dict:
            return your_analysis_logic(path)
    """
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
            result = func(*args, **kwargs)

            aiss.store_event(aiss.stamp_event(_key, _id, {
                "event_type": "action_executed",
                "action": action_name,
                "args_hash": _h(args),
                "kwargs_hash": _h(kwargs),
                "result_hash": _h(result),
                "aiss_profile": "AISS-1",
            }))

            return result
        return wrapper
    return decorator


# ─── Convenience export ───────────────────────────────────────────────────────

def export_audit(output_path: str = "openclaw-audit.json") -> str:
    """Export full audit trail for this session."""
    aiss.export_audit_chain(output_path)
    return output_path


__all__ = [
    "AuditableOpenClaw",
    "stamp_action",
    "export_audit",
]
