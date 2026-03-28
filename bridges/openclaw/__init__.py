# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)

"""
piqrypt-openclaw — PiQrypt bridge for OpenClaw  v1.1.0

BridgeProtocol intégré :
    - Injection mémoire au démarrage
    - Gate TrustGate sur execute_task() et run()
    - stamp_reasoning() et stamp_tool_call() sans gate (observation)
    - Delta mémoire après chaque exécution
"""

__version__ = "1.1.0"
__author__  = "PiQrypt Contributors"
__license__ = "Apache-2.0"

import hashlib
import functools
import time
from typing import Any, Dict, List, Optional

try:
    import piqrypt as aiss
except ImportError:
    raise ImportError("piqrypt is required. Install with: pip install piqrypt")

# ── BridgeProtocol ────────────────────────────────────────────────────────────
try:
    from aiss.bridge_protocol import BridgeProtocol, BridgeAction
    _BRIDGE_PROTOCOL_AVAILABLE = True
except ImportError:
    BridgeProtocol = object
    BridgeAction = None
    _BRIDGE_PROTOCOL_AVAILABLE = False


def _h(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

def _load_identity(identity_file: str):
    identity = aiss.load_identity(identity_file)
    return identity["private_key_bytes"], identity["agent_id"]


# ══════════════════════════════════════════════════════════════════════════════
# AuditableOpenClaw
# ══════════════════════════════════════════════════════════════════════════════

class AuditableOpenClaw(BridgeProtocol):
    """
    OpenClaw agent wrapper avec audit trail PiQrypt.

    v1.1.0 — BridgeProtocol intégré :
        - Injection mémoire au démarrage
        - Gate TrustGate sur execute_task() et run()
        - stamp_reasoning() et stamp_tool_call() sans gate

    Usage:
        from openclaw import Agent
        from piqrypt_openclaw import AuditableOpenClaw

        base_agent = Agent(config)
        claw = AuditableOpenClaw(
            base_agent,
            identity_file="executor.json",
            agent_name="executor",
            inject_memory=True,
        )
        # Mémoire disponible :
        print(claw.memory_context)

        result = claw.execute_task(task)
    """

    def __init__(
        self,
        openclaw_agent: Any = None,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        inject_memory: bool = True,
        memory_depth: int = 10,
        enable_gate: bool = True,
    ):
        self._agent = openclaw_agent
        self._enable_gate = enable_gate
        self._last_hash: Optional[str] = None
        self._event_count = 0

        # ── Identité ──────────────────────────────────────────────────────────
        if identity_file:
            self._pq_key, self._pq_id = _load_identity(identity_file)
        elif private_key and agent_id:
            self._pq_key = private_key
            self._pq_id  = agent_id
        else:
            pq_priv, pq_pub = aiss.generate_keypair()
            self._pq_key = pq_priv
            self._pq_id  = aiss.derive_agent_id(pq_pub)

        # ── Résolution nom agent ──────────────────────────────────────────────
        self._agent_name = (
            agent_name
            or getattr(openclaw_agent, "name", None)
            or self._pq_id[:16]
        )

        # ── BridgeProtocol ────────────────────────────────────────────────────
        if _BRIDGE_PROTOCOL_AVAILABLE:
            BridgeProtocol.__init__(
                self,
                agent_name=self._agent_name,
                memory_depth=memory_depth,
            )

        # ── Injection mémoire ─────────────────────────────────────────────────
        self.memory_context: str = ""
        if inject_memory and _BRIDGE_PROTOCOL_AVAILABLE:
            self.memory_context = self.on_session_start()

        # ── Event de démarrage ────────────────────────────────────────────────
        self._stamp("agent_initialized", {
            "agent_name":      self._agent_name,
            "framework":       "openclaw",
            "memory_injected": bool(self.memory_context),
            "aiss_profile":    "AISS-1",
        })

    # ── Internal stamp ────────────────────────────────────────────────────────

    def _stamp(self, event_type: str, payload: Dict) -> Dict:
        if self._last_hash:
            payload["previous_event_hash"] = self._last_hash
        event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": event_type,
            "aiss_profile": "AISS-1",
            **payload,
        })
        aiss.store_event(event)
        self._last_hash = aiss.compute_event_hash(event)
        self._event_count += 1
        return event

    # ── execute_task() — gate TrustGate ───────────────────────────────────────

    def execute_task(self, task: Any) -> Any:
        """Execute OpenClaw task avec gate TrustGate avant exécution."""
        task_desc = getattr(task, "description", str(task))

        # ── Gate ─────────────────────────────────────────────────────────────
        if self._enable_gate and _BRIDGE_PROTOCOL_AVAILABLE:
            action = BridgeAction(
                name="openclaw_execute_task",
                payload={"task_hash": _h(task_desc)},
            )
            if not self.on_action_gate(action):
                self._stamp("task_blocked_by_trustgate", {"task_hash": _h(task_desc)})
                raise RuntimeError(
                    f"[PiQrypt TrustGate] execute_task bloqué pour '{self._agent_name}'. "
                    f"Consultez le dashboard TrustGate (port 8422)."
                )

        # ── Exécution (inchangée) ─────────────────────────────────────────────
        start_event = self._stamp("task_start", {"task_hash": _h(task_desc)})
        previous_hash = aiss.compute_event_hash(start_event)

        try:
            result = self._agent.execute_task(task)
            self._stamp("task_complete", {
                "task_hash":           _h(task_desc),
                "result_hash":         _h(result),
                "previous_event_hash": previous_hash,
                "success":             True,
            })
            # Delta mémoire après exécution
            if _BRIDGE_PROTOCOL_AVAILABLE:
                delta = self.on_session_update()
                if delta:
                    self.memory_context = delta
            return result

        except RuntimeError:
            raise
        except Exception as e:
            self._stamp("task_failed", {
                "task_hash":           _h(task_desc),
                "error_hash":          _h(str(e)),
                "previous_event_hash": previous_hash,
                "success":             False,
            })
            raise

    # ── run() — gate TrustGate ────────────────────────────────────────────────

    def run(self, language: str, code: str) -> Any:
        """
        Execute code directement — gate TrustGate avant exécution.
        Équivalent de execute_task pour du code raw.
        """
        if self._enable_gate and _BRIDGE_PROTOCOL_AVAILABLE:
            action = BridgeAction(
                name=f"openclaw_run_{language}",
                payload={"code_hash": _h(code), "language": language},
            )
            if not self.on_action_gate(action):
                self._stamp("run_blocked_by_trustgate", {
                    "code_hash": _h(code), "language": language,
                })
                raise RuntimeError(
                    f"[PiQrypt TrustGate] run({language}) bloqué pour '{self._agent_name}'."
                )

        start_event = self._stamp("execution_start", {
            "language":  language,
            "code_hash": _h(code),
        })
        previous_hash = aiss.compute_event_hash(start_event)

        try:
            result = self._agent.run(language, code)
            self._stamp("execution_complete", {
                "language":            language,
                "result_hash":         _h(str(result)),
                "previous_event_hash": previous_hash,
            })
            return result
        except RuntimeError:
            raise
        except Exception as e:
            self._stamp("execution_error", {
                "language":   language,
                "code_hash":  _h(code),
                "error_hash": _h(str(e)),
            })
            raise

    # ── Méthodes d'observation — sans gate ────────────────────────────────────

    def stamp_reasoning(self, task_desc: str, plan: Any = None,
                        model: str = "unknown") -> str:
        """Stamp reasoning/planning phase — sans gate (observation)."""
        event = self._stamp("task_reasoning", {
            "task_hash": _h(task_desc),
            "plan_hash": _h(plan) if plan else "",
            "model":     model,
        })
        return aiss.compute_event_hash(event)

    def stamp_tool_call(self, tool: str, input_data: Any, result: Any,
                        previous_hash: Optional[str] = None,
                        success: bool = True) -> str:
        """Stamp tool call — sans gate (observation)."""
        payload: Dict = {
            "tool_name":    tool,
            "input_hash":   _h(input_data),
            "result_hash":  _h(result),
            "success":      success,
        }
        if previous_hash:
            payload["previous_event_hash"] = previous_hash
        event = self._stamp("tool_call", payload)
        return aiss.compute_event_hash(event)

    def stamp_event(self, event_type: str, payload: Optional[Dict] = None) -> Dict:
        return self._stamp(event_type, payload or {})

    def export_audit(self, output_path: str = "openclaw-audit.json") -> str:
        aiss.export_audit_chain(output_path)
        return output_path

    @property
    def piqrypt_id(self) -> str: return self._pq_id

    @property
    def event_count(self) -> int: return self._event_count

    @property
    def last_event_hash(self) -> Optional[str]: return self._last_hash

    def __getattr__(self, name: str) -> Any:
        if self._agent is not None:
            return getattr(self._agent, name)
        raise AttributeError(name)


# ── stamp_action decorator (inchangé) ────────────────────────────────────────

def stamp_action(action_name: str, identity_file=None,
                 private_key=None, agent_id=None):
    """Decorator — stamp any OpenClaw action function with PiQrypt proof."""
    def decorator(func):
        if identity_file:
            _key, _id = _load_identity(identity_file)
        elif private_key and agent_id:
            _key, _id = private_key, agent_id
        else:
            pq_priv, pq_pub = aiss.generate_keypair()
            _key = pq_priv
            _id  = aiss.derive_agent_id(pq_pub)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            aiss.store_event(aiss.stamp_event(_key, _id, {
                "event_type":  "action_executed",
                "action":      action_name,
                "args_hash":   _h(args),
                "kwargs_hash": _h(kwargs),
                "result_hash": _h(result),
                "aiss_profile": "AISS-1",
            }))
            return result
        return wrapper
    return decorator


def export_audit(output_path: str = "openclaw-audit.json") -> str:
    aiss.export_audit_chain(output_path)
    return output_path

__all__ = ["AuditableOpenClaw", "stamp_action", "export_audit"]
