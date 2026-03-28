# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)

"""
piqrypt-rpi — PiQrypt bridge for Raspberry Pi  v1.1.0

BridgeProtocol intégré :
    - Injection mémoire au démarrage
    - Gate TrustGate sur stamp_actuator() et stamp_decision()
      (actions physiques irréversibles)
    - stamp_sensor() et stamp_system_metrics() sans gate (lectures)
    - Delta mémoire après chaque action gated
"""

from __future__ import annotations

__version__ = "1.1.0"
__author__  = "PiQrypt Inc."
__license__ = "Apache-2.0"

import hashlib
import json
import platform
import time
import threading
import functools
from typing import Any, Callable, Dict, List, Optional, Union

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

def _get_system_info() -> Dict:
    info: Dict = {"platform": platform.system(), "python": platform.python_version()}
    try:
        import subprocess
        r = subprocess.run(["vcgencmd", "measure_temp"], capture_output=True, text=True, timeout=2)
        if r.returncode == 0:
            info["rpi_model"] = "raspberry_pi"
    except Exception:
        pass
    return info

def _resolve_identity(identity_file, private_key, agent_id):
    if identity_file:
        identity = aiss.load_identity(identity_file)
        return identity["private_key_bytes"], identity["agent_id"]
    elif private_key and agent_id:
        return private_key, agent_id
    else:
        pq_priv, pq_pub = aiss.generate_keypair()
        return pq_priv, aiss.derive_agent_id(pq_pub)


# ══════════════════════════════════════════════════════════════════════════════
# AUDITED GPIO
# ══════════════════════════════════════════════════════════════════════════════

class AuditedGPIO:
    """GPIO wrapper qui stampe chaque opération. Inchangé en v1.1.0."""

    RISING  = "RISING"
    FALLING = "FALLING"
    BOTH    = "BOTH"
    IN      = "IN"
    OUT     = "OUT"
    HIGH    = True
    LOW     = False

    def __init__(self, agent: "AuditedPiAgent"):
        self._agent  = agent
        self._backend = "mock"
        self._pins: Dict[int, str] = {}
        try:
            import RPi.GPIO as _gpio
            self._gpio    = _gpio
            self._backend = "rpigpio"
            _gpio.setmode(_gpio.BCM)
        except ImportError:
            pass

    def setup(self, pin, direction, **kwargs):
        self._pins[pin] = direction
        if self._backend == "rpigpio":
            mode = self._gpio.OUT if direction == self.OUT else self._gpio.IN
            self._gpio.setup(pin, mode, **kwargs)
        self._agent._stamp_event("rpi_gpio_setup", {"pin": pin, "direction": direction})

    def output(self, pin, value):
        if self._backend == "rpigpio":
            self._gpio.output(pin, self._gpio.HIGH if value else self._gpio.LOW)
        self._agent._stamp_event("rpi_gpio_output", {
            "pin": pin, "value": value, "level": "HIGH" if value else "LOW",
        })

    def input(self, pin):
        value = False
        if self._backend == "rpigpio":
            value = bool(self._gpio.input(pin))
        self._agent._stamp_event("rpi_gpio_input", {
            "pin": pin, "value": value, "level": "HIGH" if value else "LOW",
        })
        return value

    def add_event_detect(self, pin, edge, callback=None, bouncetime=200):
        def _audited_cb(ch):
            self._agent._stamp_event("rpi_gpio_interrupt", {"pin": ch, "edge": edge})
            if callback:
                callback(ch)
        if self._backend == "rpigpio":
            gpio_edge = {"RISING": self._gpio.RISING, "FALLING": self._gpio.FALLING,
                         "BOTH": self._gpio.BOTH}.get(edge, self._gpio.BOTH)
            self._gpio.add_event_detect(pin, gpio_edge, callback=_audited_cb,
                                         bouncetime=bouncetime)
        self._agent._stamp_event("rpi_gpio_interrupt_registered", {"pin": pin, "edge": edge})

    def cleanup(self, pins=None):
        if self._backend == "rpigpio":
            self._gpio.cleanup(pins) if pins else self._gpio.cleanup()
        self._agent._stamp_event("rpi_gpio_cleanup", {
            "pins": pins or list(self._pins.keys()), "backend": self._backend,
        })
        self._pins.clear()


# ══════════════════════════════════════════════════════════════════════════════
# AUDITED PI AGENT
# ══════════════════════════════════════════════════════════════════════════════

class AuditedPiAgent(BridgeProtocol):
    """
    Raspberry Pi agent avec audit trail PiQrypt.

    v1.1.0 — BridgeProtocol intégré :
        - Injection mémoire au démarrage
        - Gate TrustGate sur stamp_actuator() et stamp_decision()
        - stamp_sensor() et stamp_system_metrics() sans gate (lectures)
    """

    def __init__(
        self,
        name: str = "pi_agent",
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        vigil_endpoint: Optional[str] = None,
        heartbeat_sec: Optional[float] = None,
        inject_memory: bool = True,
        memory_depth: int = 10,
        enable_gate: bool = True,
        # Compat ancienne signature
        agent_name: Optional[str] = None,
    ):
        self.name       = agent_name or name
        self._vigil     = vigil_endpoint.rstrip("/") if vigil_endpoint else None
        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )
        self._last_hash: Optional[str] = None
        self._event_count = 0
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._running = True
        self._enable_gate = enable_gate

        # ── BridgeProtocol ────────────────────────────────────────────────────
        if _BRIDGE_PROTOCOL_AVAILABLE:
            BridgeProtocol.__init__(
                self,
                agent_name=self.name,
                memory_depth=memory_depth,
            )

        # ── Injection mémoire ─────────────────────────────────────────────────
        self.memory_context: str = ""
        if inject_memory and _BRIDGE_PROTOCOL_AVAILABLE:
            self.memory_context = self.on_session_start()

        # ── Event de démarrage ────────────────────────────────────────────────
        sys_info = _get_system_info()
        self._stamp_event("rpi_agent_init", {
            "agent_name":      self.name,
            "framework":       "raspberry_pi",
            "memory_injected": bool(self.memory_context),
            "aiss_profile":    "AISS-1",
            **sys_info,
        })

        if heartbeat_sec:
            self._start_heartbeat(heartbeat_sec)

    # ── Internal stamp (inchangé) ─────────────────────────────────────────────

    def _stamp_event(self, event_type: str, payload: Dict) -> Dict:
        full = {"event_type": event_type, "agent_name": self.name,
                "aiss_profile": "AISS-1", **payload}
        if self._last_hash:
            full["previous_event_hash"] = self._last_hash
        event = aiss.stamp_event(self._pq_key, self._pq_id, full)
        aiss.store_event(event)
        self._last_hash = aiss.compute_event_hash(event)
        self._event_count += 1
        if self._vigil:
            self._forward_vigil(event)
        return event

    def _forward_vigil(self, event: Dict) -> None:
        try:
            import urllib.request
            body = json.dumps(event, default=str).encode()
            req  = urllib.request.Request(
                f"{self._vigil}/api/agent/{self.name}/record",
                data=body, headers={"Content-Type": "application/json"}, method="POST",
            )
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass

    # ── Lectures — sans gate ──────────────────────────────────────────────────

    def stamp_sensor(self, sensor_name: str, value: Any, unit: str = "") -> Dict:
        """Stamp sensor reading — pas de gate (lecture)."""
        return self._stamp_event("rpi_sensor_reading", {
            "sensor":       sensor_name,
            "value_hash":   _h(str(value)),
            "unit":         unit,
        })

    def stamp_system_metrics(self) -> Dict:
        """Stamp system metrics snapshot — pas de gate (lecture)."""
        metrics: Dict = {}
        try:
            import psutil
            metrics = {
                "cpu_percent_hash":  _h(str(psutil.cpu_percent())),
                "ram_percent_hash":  _h(str(psutil.virtual_memory().percent)),
                "disk_percent_hash": _h(str(psutil.disk_usage("/").percent)),
            }
        except ImportError:
            metrics = {"psutil": "not_available"}
        return self._stamp_event("rpi_system_metrics", metrics)

    def stamp_network_event(self, event_type: str, payload: Optional[Dict] = None) -> Dict:
        """Stamp network event — pas de gate."""
        return self._stamp_event(f"rpi_network_{event_type}", payload or {})

    def stamp_error(self, error_type: str, message: str) -> Dict:
        """Stamp error event — pas de gate."""
        return self._stamp_event("rpi_error", {
            "error_type":    error_type,
            "message_hash":  _h(message),
        })

    # ── Actions — avec gate TrustGate ─────────────────────────────────────────

    def stamp_actuator(self, actuator_name: str, state: str,
                       metadata: Optional[Dict] = None) -> Dict:
        """
        Stamp physical actuator command — gate TrustGate avant action.
        Actions physiques irréversibles : relay, motor, valve, etc.
        """
        if self._enable_gate and _BRIDGE_PROTOCOL_AVAILABLE:
            action = BridgeAction(
                name=f"actuator_{actuator_name}",
                payload={"state": state, "actuator": actuator_name},
            )
            if not self.on_action_gate(action):
                self._stamp_event("rpi_actuator_blocked", {
                    "actuator": actuator_name, "state": state,
                })
                raise RuntimeError(
                    f"[PiQrypt TrustGate] Actuator '{actuator_name}' bloqué. "
                    f"Consultez le dashboard TrustGate (port 8422)."
                )

        event = self._stamp_event("rpi_actuator_command", {
            "actuator":      actuator_name,
            "state":         state,
            "metadata_hash": _h(str(metadata or {})),
        })

        # Delta mémoire après action physique
        if _BRIDGE_PROTOCOL_AVAILABLE:
            delta = self.on_session_update()
            if delta:
                self.memory_context = delta

        return event

    def stamp_decision(self, decision: str, context: Optional[Dict] = None) -> Dict:
        """
        Stamp AI decision — gate TrustGate avant exécution.
        Décisions qui engagent une action physique.
        """
        if self._enable_gate and _BRIDGE_PROTOCOL_AVAILABLE:
            action = BridgeAction(
                name=f"decision_{decision}",
                payload={"decision": decision},
            )
            if not self.on_action_gate(action):
                self._stamp_event("rpi_decision_blocked", {"decision": decision})
                raise RuntimeError(
                    f"[PiQrypt TrustGate] Décision '{decision}' bloquée. "
                    f"Consultez le dashboard TrustGate (port 8422)."
                )

        event = self._stamp_event("rpi_decision", {
            "decision":     decision,
            "context_hash": _h(str(context or {})),
        })

        if _BRIDGE_PROTOCOL_AVAILABLE:
            delta = self.on_session_update()
            if delta:
                self.memory_context = delta

        return event

    # ── Stamp générique ───────────────────────────────────────────────────────

    def stamp(self, event_type: str, payload: Optional[Dict] = None) -> Dict:
        return self._stamp_event(event_type, payload or {})

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def _start_heartbeat(self, interval_sec: float) -> None:
        def _hb():
            while self._running:
                time.sleep(interval_sec)
                if self._running:
                    self._stamp_event("rpi_heartbeat", {"interval_sec": interval_sec})
        self._heartbeat_thread = threading.Thread(target=_hb, daemon=True)
        self._heartbeat_thread.start()

    def stop(self) -> None:
        self._running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2)

    def export_audit(self, output_path: str = "rpi_audit.json") -> str:
        aiss.export_audit_chain(output_path)
        return output_path

    @property
    def piqrypt_id(self) -> str: return self._pq_id

    @property
    def event_count(self) -> int: return self._event_count

    @property
    def last_event_hash(self) -> Optional[str]: return self._last_hash


def export_audit(output_path: str = "rpi_audit.json") -> str:
    aiss.export_audit_chain(output_path)
    return output_path

__all__ = ["AuditedPiAgent", "AuditedGPIO", "export_audit"]
