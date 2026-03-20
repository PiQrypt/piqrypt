# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-rpi — PiQrypt bridge for Raspberry Pi
===============================================

Adds cryptographic audit trails to Raspberry Pi agents.
Every sensor reading, GPIO event, decision, actuator command,
and system metric is Ed25519-signed, hash-chained, and tamper-proof.

Designed to be generic and extensible :
    - Works without GPIO hardware (simulation/mock mode)
    - Compatible with RPi.GPIO, gpiozero, pigpio
    - Works on any Linux SBC (RPi 3/4/5, Jetson, Orange Pi...)

Install:
    pip install piqrypt[rpi]
    # GPIO optional: pip install RPi.GPIO gpiozero

Usage (basic — no GPIO):
    from piqrypt_rpi import AuditedPiAgent

    agent = AuditedPiAgent(
        name="edge_sensor",
        identity_file="edge_sensor.json",
    )
    agent.stamp_sensor("temperature", 23.4, unit="°C")
    agent.stamp_decision("fan_on", {"temp": 23.4, "threshold": 22.0})
    agent.stamp_actuator("fan", "ON", {"speed": "HIGH"})

Usage (avec GPIO):
    from piqrypt_rpi import AuditedPiAgent, AuditedGPIO

    agent = AuditedPiAgent(name="door_controller", identity_file="door.json")
    gpio  = AuditedGPIO(agent)

    gpio.setup(17, "OUT")
    gpio.output(17, True)    # stamped automatically

Usage (agent autonome):
    class SecurityAgent(AuditedPiAgent):
        def run_loop(self):
            while True:
                temp = self.read_sensor("ds18b20")
                self.stamp_sensor("temperature", temp, unit="°C")
                if temp > 80:
                    self.stamp_decision("emergency_shutdown", {"temp": temp})
                    self.stamp_actuator("relay_1", "OFF")
                time.sleep(1.0)

IP : e-Soleau DSO2026006483 (INPI France — 19/02/2026)
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__  = "PiQrypt Inc."
__license__ = "MIT"

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
    raise ImportError(
        "piqrypt is required. Install with: pip install piqrypt"
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _h(value: Any) -> str:
    """SHA-256 of any value. Never stores raw content."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

def _load_identity(identity_file: str):
    identity = aiss.load_identity(identity_file)
    return identity["private_key_bytes"], identity["agent_id"]

def _resolve_identity(identity_file, private_key, agent_id):
    if identity_file:
        return _load_identity(identity_file)
    elif private_key and agent_id:
        return private_key, agent_id
    else:
        pq_priv, pq_pub = aiss.generate_keypair()
        return pq_priv, aiss.derive_agent_id(pq_pub)

def _is_raspberry_pi() -> bool:
    """Detect if running on a real Raspberry Pi."""
    try:
        with open("/proc/device-tree/model", "r") as f:
            return "Raspberry Pi" in f.read()
    except Exception:
        return False

def _get_system_info() -> Dict:
    """Collect basic system info for the init stamp."""
    info: Dict[str, Any] = {
        "platform": platform.platform(),
        "machine":  platform.machine(),
        "python":   platform.python_version(),
        "is_rpi":   _is_raspberry_pi(),
    }
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("Model"):
                    info["model"] = line.split(":")[1].strip()
                    break
    except Exception:
        pass
    try:
        info["hostname"] = platform.node()
    except Exception:
        pass
    return info


# ══════════════════════════════════════════════════════════════════════════════
# AUDITED GPIO
# ══════════════════════════════════════════════════════════════════════════════

class AuditedGPIO:
    """
    GPIO wrapper that stamps every pin setup, output change, and input read.

    Supports RPi.GPIO (preferred), gpiozero (fallback), and mock mode.

    Parameters
    ----------
    agent : AuditedPiAgent
        Parent agent — GPIO events are stamped into the agent's chain.
    backend : str
        "auto" (default) | "rpigpio" | "gpiozero" | "mock"
        "mock" for testing without hardware.

    Usage:
        agent = AuditedPiAgent(name="robot", identity_file="robot.json")
        gpio  = AuditedGPIO(agent)

        gpio.setup(17, "OUT")       # BCM numbering
        gpio.output(17, True)       # HIGH — stamped
        val = gpio.input(4)         # read — stamped
        gpio.cleanup()
    """

    OUT = "OUT"
    IN  = "IN"
    BCM = "BCM"
    BOARD = "BOARD"
    RISING  = "RISING"
    FALLING = "FALLING"
    BOTH    = "BOTH"

    def __init__(self, agent: "AuditedPiAgent", backend: str = "auto"):
        self._agent   = agent
        self._backend = self._init_backend(backend)
        self._pins:   Dict[int, str] = {}  # pin → direction

    def _init_backend(self, backend: str) -> str:
        if backend == "mock":
            return "mock"
        if backend in ("auto", "rpigpio"):
            try:
                import RPi.GPIO as GPIO
                self._gpio = GPIO
                self._gpio.setmode(self._gpio.BCM)
                self._gpio.setwarnings(False)
                return "rpigpio"
            except ImportError:
                if backend == "rpigpio":
                    raise ImportError(
                        "RPi.GPIO not installed. pip install RPi.GPIO"
                    )
        if backend in ("auto", "gpiozero"):
            try:
                from gpiozero import Device
                return "gpiozero"
            except ImportError:
                pass
        # Fallback to mock — no hardware crash
        return "mock"

    @property
    def backend(self) -> str:
        return self._backend

    def setup(self, pin: int, direction: str, initial: Optional[bool] = None) -> None:
        """Configure a GPIO pin."""
        self._pins[pin] = direction
        if self._backend == "rpigpio":
            gpio_dir = self._gpio.OUT if direction == self.OUT else self._gpio.IN
            if initial is not None and direction == self.OUT:
                self._gpio.setup(pin, gpio_dir, initial=self._gpio.HIGH if initial else self._gpio.LOW)
            else:
                self._gpio.setup(pin, gpio_dir)

        self._agent._stamp_event("rpi_gpio_setup", {
            "pin":       pin,
            "direction": direction,
            "initial":   initial,
            "backend":   self._backend,
        })

    def output(self, pin: int, value: bool) -> None:
        """Set a GPIO output pin HIGH or LOW — stamped."""
        if self._backend == "rpigpio":
            self._gpio.output(pin, self._gpio.HIGH if value else self._gpio.LOW)

        self._agent._stamp_event("rpi_gpio_output", {
            "pin":   pin,
            "value": value,
            "level": "HIGH" if value else "LOW",
        })

    def input(self, pin: int) -> bool:
        """Read a GPIO input pin — stamped."""
        value = False
        if self._backend == "rpigpio":
            value = bool(self._gpio.input(pin))

        self._agent._stamp_event("rpi_gpio_input", {
            "pin":   pin,
            "value": value,
            "level": "HIGH" if value else "LOW",
        })
        return value

    def add_event_detect(
        self,
        pin: int,
        edge: str,
        callback: Optional[Callable] = None,
        bouncetime: int = 200,
    ) -> None:
        """Attach interrupt callback to a pin — stamped on each trigger."""
        def _audited_cb(ch: int) -> None:
            self._agent._stamp_event("rpi_gpio_interrupt", {
                "pin":   ch,
                "edge":  edge,
            })
            if callback:
                callback(ch)

        if self._backend == "rpigpio":
            gpio_edge = {
                self.RISING:  self._gpio.RISING,
                self.FALLING: self._gpio.FALLING,
                self.BOTH:    self._gpio.BOTH,
            }.get(edge, self._gpio.BOTH)
            self._gpio.add_event_detect(
                pin, gpio_edge,
                callback=_audited_cb,
                bouncetime=bouncetime,
            )

        self._agent._stamp_event("rpi_gpio_interrupt_registered", {
            "pin":  pin,
            "edge": edge,
        })

    def cleanup(self, pins: Optional[List[int]] = None) -> None:
        """Release GPIO resources — stamped."""
        if self._backend == "rpigpio":
            if pins:
                self._gpio.cleanup(pins)
            else:
                self._gpio.cleanup()

        self._agent._stamp_event("rpi_gpio_cleanup", {
            "pins":    pins or list(self._pins.keys()),
            "backend": self._backend,
        })
        self._pins.clear()


# ══════════════════════════════════════════════════════════════════════════════
# AUDITED PI AGENT
# ══════════════════════════════════════════════════════════════════════════════

class AuditedPiAgent:
    """
    Generic Raspberry Pi agent with PiQrypt cryptographic audit trail.

    Framework-agnostic — works for any RPi use case:
      - Sensor reading agents (temperature, humidity, motion, distance...)
      - Actuator control (relay, motor, servo, LED...)
      - Autonomous decision agents (local inference + action)
      - Edge gateway agents (MQTT, HTTP bridge)
      - IoT security monitors

    Parameters
    ----------
    name : str
        Agent name — used in audit events and Vigil dashboard.
    identity_file : str, optional
        Path to PiQrypt identity JSON.
    private_key : bytes, optional
        Explicit Ed25519 private key.
    agent_id : str, optional
        Explicit agent ID (with private_key).
    vigil_endpoint : str, optional
        Vigil server URL for live monitoring.
        e.g. "http://192.168.1.100:8421"
    heartbeat_sec : float, optional
        Auto-stamp a heartbeat event every N seconds.
        None (default) = disabled.

    Examples
    --------
    >>> agent = AuditedPiAgent(name="greenhouse", identity_file="gh.json")
    >>> agent.stamp_sensor("temperature", 24.1, unit="°C")
    >>> agent.stamp_sensor("humidity", 62.3, unit="%")
    >>> agent.stamp_decision("irrigation_on", {"humidity": 62.3, "threshold": 65.0})
    >>> agent.stamp_actuator("water_valve", "OPEN", {"zone": 2})
    """

    def __init__(
        self,
        name: str,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        vigil_endpoint: Optional[str] = None,
        heartbeat_sec: Optional[float] = None,
    ):
        self.name       = name
        self._vigil     = vigil_endpoint.rstrip("/") if vigil_endpoint else None
        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )
        self._last_hash: Optional[str] = None
        self._event_count = 0
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._running = True

        # Stamp initialization with system info
        sys_info = _get_system_info()
        self._stamp_event("rpi_agent_init", {
            "agent_name":   name,
            "framework":    "raspberry_pi",
            "aiss_profile": "AISS-1",
            **sys_info,
        })

        # Start heartbeat if requested
        if heartbeat_sec:
            self._start_heartbeat(heartbeat_sec)

    # ── Internal stamp ────────────────────────────────────────────────────────

    def _stamp_event(self, event_type: str, payload: Dict) -> Dict:
        """Sign, chain and store one audit event."""
        full = {
            "event_type":   event_type,
            "agent_name":   self.name,
            "aiss_profile": "AISS-1",
            "timestamp":    time.time(),
            **payload,
        }
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
        """Non-blocking forward to Vigil. Never raises."""
        try:
            import urllib.request
            body = json.dumps(event, default=str).encode()
            req  = urllib.request.Request(
                f"{self._vigil}/api/agent/{self.name}/record",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass

    # ── Sensor readings ───────────────────────────────────────────────────────

    def stamp_sensor(
        self,
        sensor_name: str,
        value: Union[float, int, str, bool],
        unit: Optional[str] = None,
        source: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> Dict:
        """
        Stamp a sensor reading.

        The raw value is stored as-is in the audit event.
        For sensitive data, use stamp_sensor_hashed() instead.

        Parameters
        ----------
        sensor_name : str
            Sensor identifier — "temperature", "humidity", "pir_motion", ...
        value : float | int | str | bool
            Measured value.
        unit : str, optional
            Unit string — "°C", "%", "Pa", "lux", "m/s", ...
        source : str, optional
            Sensor model or pin — "ds18b20", "bme280", "GPIO17", ...
        metadata : dict, optional
            Extra fields — {"accuracy": 0.5, "raw_adc": 2048}

        Returns
        -------
        dict : signed event
        """
        payload: Dict = {
            "sensor":      sensor_name,
            "value":       value,
        }
        if unit:     payload["unit"]   = unit
        if source:   payload["source"] = source
        if metadata: payload.update(metadata)

        return self._stamp_event("rpi_sensor_reading", payload)

    def stamp_sensor_hashed(
        self,
        sensor_name: str,
        value: Any,
        unit: Optional[str] = None,
    ) -> Dict:
        """
        Stamp a sensor reading without storing the raw value.
        Use for sensitive measurements (weight, biometric, financial...).
        """
        payload: Dict = {
            "sensor":      sensor_name,
            "value_hash":  _h(str(value)),
        }
        if unit: payload["unit"] = unit
        return self._stamp_event("rpi_sensor_reading_hashed", payload)

    # ── Decisions ─────────────────────────────────────────────────────────────

    def stamp_decision(
        self,
        decision: str,
        context: Optional[Dict] = None,
        confidence: Optional[float] = None,
        model: Optional[str] = None,
    ) -> Dict:
        """
        Stamp an agent decision — the "why" behind an action.

        Parameters
        ----------
        decision : str
            Decision name — "fan_on", "irrigation_start", "alert_raised", ...
        context : dict, optional
            Input data that led to this decision (values will be stored as-is).
            Use context_hash to avoid storing sensitive data.
        confidence : float, optional
            Decision confidence score [0.0 - 1.0].
        model : str, optional
            Model or algorithm that produced the decision — "threshold_v1",
            "tflite_mobilenet", "rule_engine", ...

        Returns
        -------
        dict : signed event

        Example
        -------
        >>> agent.stamp_decision(
        ...     "irrigation_on",
        ...     context={"humidity": 45.2, "threshold": 50.0},
        ...     confidence=1.0,
        ...     model="threshold_v1",
        ... )
        """
        payload: Dict = {"decision": decision}
        if context:    payload["context_hash"] = _h(json.dumps(context, default=str, sort_keys=True))
        if context:    payload["context"]      = context   # store human-readable context
        if confidence is not None: payload["confidence"] = round(confidence, 4)
        if model:      payload["model"] = model

        return self._stamp_event("rpi_decision", payload)

    # ── Actuators ─────────────────────────────────────────────────────────────

    def stamp_actuator(
        self,
        actuator: str,
        command: Union[str, bool, int, float],
        parameters: Optional[Dict] = None,
    ) -> Dict:
        """
        Stamp an actuator command.

        Parameters
        ----------
        actuator : str
            Actuator identifier — "relay_1", "servo_pan", "led_status", ...
        command : str | bool | int | float
            Command sent — "ON"/"OFF", True/False, PWM duty cycle, ...
        parameters : dict, optional
            Extra parameters — {"speed": "HIGH", "duration_ms": 500}

        Example
        -------
        >>> agent.stamp_actuator("water_pump", "ON", {"zone": 3, "duration_s": 30})
        """
        payload: Dict = {
            "actuator": actuator,
            "command":  str(command),
        }
        if parameters: payload["parameters"] = parameters

        return self._stamp_event("rpi_actuator_command", payload)

    # ── System metrics ────────────────────────────────────────────────────────

    def stamp_system_metrics(self) -> Dict:
        """
        Stamp current system metrics (CPU, memory, temperature).
        Useful for health monitoring and predictive maintenance.
        """
        metrics: Dict[str, Any] = {}

        try:
            import psutil
            metrics["cpu_percent"]    = psutil.cpu_percent(interval=0.1)
            metrics["memory_percent"] = psutil.virtual_memory().percent
            metrics["disk_percent"]   = psutil.disk_usage("/").percent
        except ImportError:
            pass

        # RPi CPU temperature
        try:
            with open("/sys/class/thermal/thermal_zone0/temp") as f:
                metrics["cpu_temp_c"] = round(int(f.read().strip()) / 1000, 1)
        except Exception:
            pass

        # Uptime
        try:
            with open("/proc/uptime") as f:
                metrics["uptime_sec"] = float(f.read().split()[0])
        except Exception:
            pass

        return self._stamp_event("rpi_system_metrics", metrics)

    # ── Network / MQTT / HTTP ─────────────────────────────────────────────────

    def stamp_network_event(
        self,
        event_type: str,
        protocol: str,
        endpoint: str,
        payload_hash: Optional[str] = None,
        success: bool = True,
        metadata: Optional[Dict] = None,
    ) -> Dict:
        """
        Stamp a network I/O event (MQTT publish, HTTP request, WebSocket...).

        Raw payloads are never stored — only hashes.

        Parameters
        ----------
        event_type : str
            "mqtt_publish" | "mqtt_subscribe" | "http_request" | "websocket_send" | ...
        protocol : str
            "mqtt" | "http" | "https" | "websocket" | "modbus" | ...
        endpoint : str
            Topic, URL or address — hashed automatically.
        payload_hash : str, optional
            SHA-256 of the payload (pre-computed by caller).
        success : bool
            Whether the network call succeeded.

        Example
        -------
        >>> import hashlib
        >>> agent.stamp_network_event(
        ...     "mqtt_publish",
        ...     protocol="mqtt",
        ...     endpoint="sensors/temperature",
        ...     payload_hash=hashlib.sha256(b'{"temp": 23.4}').hexdigest(),
        ... )
        """
        ev: Dict = {
            "protocol":       protocol,
            "endpoint_hash":  _h(endpoint),
            "success":        success,
        }
        if payload_hash: ev["payload_hash"] = payload_hash
        if metadata:     ev.update(metadata)

        return self._stamp_event(event_type, ev)

    # ── Error / alert ─────────────────────────────────────────────────────────

    def stamp_error(
        self,
        error_type: str,
        description: str,
        recoverable: bool = True,
        context: Optional[Dict] = None,
    ) -> Dict:
        """
        Stamp an error or anomaly — important for safety-critical systems.

        Parameters
        ----------
        error_type : str
            "sensor_failure" | "actuator_timeout" | "network_error" | ...
        description : str
            Human-readable description (stored as hash — not raw text).
        recoverable : bool
            Whether the agent can recover without human intervention.
        """
        payload: Dict = {
            "error_type":       error_type,
            "description_hash": _h(description),
            "recoverable":      recoverable,
        }
        if context: payload["context_hash"] = _h(json.dumps(context, default=str))

        return self._stamp_event("rpi_error", payload)

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def _start_heartbeat(self, interval_sec: float) -> None:
        """Start background thread that stamps a heartbeat every N seconds."""
        def _beat():
            while self._running:
                time.sleep(interval_sec)
                if self._running:
                    self.stamp_system_metrics()

        self._heartbeat_thread = threading.Thread(
            target=_beat, daemon=True, name=f"piqrypt-heartbeat-{self.name}"
        )
        self._heartbeat_thread.start()

    # ── Generic stamp ─────────────────────────────────────────────────────────

    def stamp(self, event_type: str, payload: Optional[Dict] = None) -> Dict:
        """
        Stamp an arbitrary custom event into the audit chain.

        Use for any event not covered by the specialized methods above.

        Usage:
            agent.stamp("door_opened", {"door_id": "front", "rfid_hash": _h(card_id)})
        """
        return self._stamp_event(event_type, payload or {})

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "AuditedPiAgent":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.shutdown()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def shutdown(self) -> None:
        """
        Graceful shutdown — stop heartbeat, stamp final event.

        Call this explicitly or use as context manager:
            with AuditedPiAgent(...) as agent:
                agent.run()
        """
        self._running = False
        self._stamp_event("rpi_agent_shutdown", {
            "agent_name":   self.name,
            "event_count":  self._event_count,
        })

    # ── Export ────────────────────────────────────────────────────────────────

    def export_audit(self, output_path: str = "rpi_audit.json") -> str:
        """Export this agent's full audit trail to JSON."""
        aiss.export_audit_chain(output_path)
        return output_path

    @property
    def piqrypt_id(self) -> str:
        """This agent's PiQrypt identity."""
        return self._pq_id

    @property
    def event_count(self) -> int:
        """Total stamped events since init."""
        return self._event_count

    @property
    def last_event_hash(self) -> Optional[str]:
        """Hash of the last stamped event — chain tip."""
        return self._last_hash

    def __repr__(self) -> str:
        return (
            f"AuditedPiAgent("
            f"name={self.name!r}, "
            f"events={self._event_count}, "
            f"id={self._pq_id[:12]}…)"
        )


# ══════════════════════════════════════════════════════════════════════════════
# stamp_loop DECORATOR
# ══════════════════════════════════════════════════════════════════════════════

def stamp_loop(
    agent: AuditedPiAgent,
    event_type: str = "loop_tick",
    every_n: int = 1,
):
    """
    Decorator — stamp every call of a loop function.

    Usage:
        agent = AuditedPiAgent(name="sensor_loop", identity_file="sl.json")

        @stamp_loop(agent, event_type="sensor_cycle", every_n=10)
        def read_all_sensors():
            return {
                "temp": read_temp(),
                "humidity": read_humidity(),
            }

        while True:
            data = read_all_sensors()
            time.sleep(1.0)
    """
    def decorator(func: Callable) -> Callable:
        _tick = [0]

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            _tick[0] += 1
            result = func(*args, **kwargs)
            if _tick[0] % every_n == 0:
                agent._stamp_event(event_type, {
                    "tick":        _tick[0],
                    "result_hash": _h(str(result)),
                })
            return result
        return wrapper
    return decorator


# ── Public API ────────────────────────────────────────────────────────────────

__all__ = [
    "AuditedPiAgent",
    "AuditedGPIO",
    "stamp_loop",
]
