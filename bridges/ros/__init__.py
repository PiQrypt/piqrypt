# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.

"""
piqrypt-ros — PiQrypt bridge for ROS2  v1.1.0

BridgeProtocol intégré :
    - Injection mémoire au démarrage (__init__)
    - Gate TrustGate sur call_service_audited() et publish()
    - Delta mémoire après chaque action
"""

from __future__ import annotations

__version__ = "1.1.0"
__author__  = "PiQrypt Inc."
__license__ = "Apache-2.0"

import hashlib
import json
import time
import functools
from typing import Any, Callable, Dict, Optional, Type

try:
    import piqrypt as aiss
except ImportError:
    raise ImportError("piqrypt is required. Install with: pip install piqrypt")

try:
    import rclpy
    import rclpy.node
    import rclpy.action
    from rclpy.node import Node
    from rclpy.action import ActionClient, ActionServer
    from rclpy.publisher import Publisher
    from rclpy.subscription import Subscription
except ImportError:
    raise ImportError(
        "rclpy is required. Install ROS2 (Humble or later) and source setup.bash."
    )

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

def _msg_h(msg: Any) -> str:
    try:
        d = {k: getattr(msg, k) for k in msg.__slots__}
        return _h(json.dumps(d, default=str, sort_keys=True))
    except Exception:
        return _h(str(msg))

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
# AUDITED PUBLISHER — gate sur publish()
# ══════════════════════════════════════════════════════════════════════════════

class AuditedPublisher:
    """ROS2 Publisher que stampe chaque message publié. Gate TrustGate sur publish()."""

    def __init__(self, publisher, topic, pq_key, pq_id, stamp_fn, gate_fn=None):
        self._pub      = publisher
        self.topic     = topic
        self._pq_key   = pq_key
        self._pq_id    = pq_id
        self._stamp    = stamp_fn
        self._gate_fn  = gate_fn  # v1.1.0 : gate TrustGate
        self._seq      = 0

    def publish(self, msg: Any) -> None:
        """Publish with gate TrustGate avant émission physique."""
        # ── Gate ─────────────────────────────────────────────────────────────
        if self._gate_fn and _BRIDGE_PROTOCOL_AVAILABLE:
            action = BridgeAction(
                name="ros2_publish",
                payload={"topic": self.topic, "msg_hash": _msg_h(msg)},
            )
            if not self._gate_fn(action):
                self._stamp("ros2_publish_blocked", {
                    "topic":    self.topic,
                    "msg_hash": _msg_h(msg),
                })
                raise RuntimeError(
                    f"[PiQrypt TrustGate] publish() bloqué sur '{self.topic}'. "
                    f"Consultez le dashboard TrustGate (port 8422)."
                )
        # ── Publish + stamp ───────────────────────────────────────────────────
        self._pub.publish(msg)
        self._seq += 1
        self._stamp("ros2_publish", {
            "topic":    self.topic,
            "msg_type": type(msg).__name__,
            "msg_hash": _msg_h(msg),
            "seq":      self._seq,
        })

    def __getattr__(self, name):
        return getattr(self._pub, name)


# ══════════════════════════════════════════════════════════════════════════════
# AUDITED NODE
# ══════════════════════════════════════════════════════════════════════════════

class AuditedNode(Node, BridgeProtocol):
    """
    ROS2 Node avec audit trail PiQrypt.

    v1.1.0 — BridgeProtocol intégré :
        - Injection mémoire au démarrage
        - Gate TrustGate sur call_service_audited() et publish()
        - Delta mémoire après chaque service call
    """

    def __init__(
        self,
        node_name: str,
        *,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        vigil_endpoint: Optional[str] = None,
        inject_memory: bool = True,
        memory_depth: int = 10,
        enable_gate: bool = True,
        **node_kwargs,
    ):
        Node.__init__(self, node_name, **node_kwargs)

        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )
        self._node_name   = node_name
        self._vigil       = vigil_endpoint.rstrip("/") if vigil_endpoint else None
        self._last_hash: Optional[str] = None
        self._event_count = 0
        self._enable_gate = enable_gate

        # ── BridgeProtocol ────────────────────────────────────────────────────
        if _BRIDGE_PROTOCOL_AVAILABLE:
            BridgeProtocol.__init__(
                self,
                agent_name=node_name,
                memory_depth=memory_depth,
            )

        # ── Injection mémoire ─────────────────────────────────────────────────
        self.memory_context: str = ""
        if inject_memory and _BRIDGE_PROTOCOL_AVAILABLE:
            self.memory_context = self.on_session_start()

        # ── Event de démarrage ────────────────────────────────────────────────
        self._stamp_event("ros2_node_init", {
            "node_name":       node_name,
            "framework":       "ros2",
            "memory_injected": bool(self.memory_context),
            "aiss_profile":    "AISS-1",
        })

    # ── Internal stamp (inchangé) ─────────────────────────────────────────────

    def _stamp_event(self, event_type: str, payload: Dict) -> Dict:
        full = {
            "event_type":   event_type,
            "node_name":    self._node_name,
            "aiss_profile": "AISS-1",
            **payload,
        }
        try:
            full["ros_time"] = self.get_clock().now().nanoseconds
        except Exception:
            full["ros_time"] = int(time.time() * 1e9)

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
                f"{self._vigil}/api/agent/{self._node_name}/record",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass

    # ── Publisher avec gate ───────────────────────────────────────────────────

    def create_audited_publisher(self, msg_type, topic, qos_profile, **kwargs):
        """Publisher que gate TrustGate avant chaque publish()."""
        pub = self.create_publisher(msg_type, topic, qos_profile, **kwargs)
        self._stamp_event("ros2_publisher_created", {
            "topic":    topic,
            "msg_type": msg_type.__name__,
            "qos":      str(qos_profile),
        })
        gate_fn = (
            (lambda action: self.on_action_gate(action))
            if self._enable_gate and _BRIDGE_PROTOCOL_AVAILABLE else None
        )
        return AuditedPublisher(
            pub, topic, self._pq_key, self._pq_id, self._stamp_event, gate_fn
        )

    # ── Subscription (inchangée) ──────────────────────────────────────────────

    def create_audited_subscription(self, msg_type, topic, qos_profile,
                                     callback=None, **kwargs):
        def _audited_cb(msg):
            self._stamp_event("ros2_message_received", {
                "topic":    topic,
                "msg_type": type(msg).__name__,
                "msg_hash": _msg_h(msg),
            })
            if callback:
                callback(msg)
        sub = self.create_subscription(msg_type, topic, _audited_cb, qos_profile, **kwargs)
        self._stamp_event("ros2_subscription_created", {
            "topic": topic, "msg_type": msg_type.__name__,
        })
        return sub

    # ── Service call avec gate ────────────────────────────────────────────────

    def call_service_audited(self, client, request, timeout_sec=5.0):
        """Service call avec gate TrustGate avant envoi."""
        # ── Gate ─────────────────────────────────────────────────────────────
        if self._enable_gate and _BRIDGE_PROTOCOL_AVAILABLE:
            action = BridgeAction(
                name="ros2_service_call",
                payload={"request_hash": _h(str(request))},
            )
            if not self.on_action_gate(action):
                self._stamp_event("ros2_service_blocked", {
                    "request_hash": _h(str(request)),
                })
                raise RuntimeError(
                    f"[PiQrypt TrustGate] service call bloqué pour '{self._node_name}'."
                )

        self._stamp_event("ros2_service_call_start", {
            "service": str(client),
            "request_hash": _h(str(request)),
        })
        if not client.wait_for_service(timeout_sec=timeout_sec):
            self._stamp_event("ros2_service_unavailable", {"service": str(client)})
            return None

        future = client.call_async(request)
        rclpy.spin_until_future_complete(self, future, timeout_sec=timeout_sec)
        response = future.result()

        self._stamp_event("ros2_service_call_complete", {
            "service":       str(client),
            "response_hash": _h(str(response)),
            "success":       response is not None,
        })

        # Delta mémoire après service call
        if _BRIDGE_PROTOCOL_AVAILABLE:
            delta = self.on_session_update()
            if delta:
                self.memory_context = delta

        return response

    def stamp(self, event_type, payload=None):
        return self._stamp_event(event_type, payload or {})

    def export_audit(self, output_path="ros2_audit.json"):
        aiss.export_audit_chain(output_path)
        return output_path

    @property
    def piqrypt_id(self): return self._pq_id

    @property
    def audit_event_count(self): return self._event_count


# ── stamp_callback decorator (inchangé) ──────────────────────────────────────

def stamp_callback(node_name="ros2_node", identity_file=None,
                   private_key=None, agent_id=None):
    def decorator(func):
        _key, _id = _resolve_identity(identity_file, private_key, agent_id)
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            aiss.store_event(aiss.stamp_event(_key, _id, {
                "event_type": f"{func.__name__}_executed",
                "node_name":  node_name,
                "args_hash":  _h(args),
                "aiss_profile": "AISS-1",
            }))
            return result
        return wrapper
    return decorator


def export_audit(output_path="ros2_audit.json"):
    aiss.export_audit_chain(output_path)
    return output_path

__all__ = ["AuditedNode", "AuditedPublisher", "stamp_callback", "export_audit"]
