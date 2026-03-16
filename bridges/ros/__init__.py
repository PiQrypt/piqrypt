# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-ros — PiQrypt bridge for ROS2
======================================

Adds cryptographic audit trails to ROS2 nodes.
Every published message, service call, action goal/result/feedback,
and lifecycle transition is Ed25519-signed, hash-chained, and tamper-proof.

Install:
    pip install piqrypt[ros]
    # ROS2 must be installed separately : https://docs.ros.org/en/humble/

Compatibility:
    ROS2 Humble, Iron, Jazzy (rclpy >= 3.3)

Usage:
    from piqrypt_ros import AuditedNode, AuditedLifecycleNode, stamp_callback

    class MyRobot(AuditedNode):
        def __init__(self):
            super().__init__(
                node_name="my_robot",
                identity_file="my_robot.json",
            )
            self.pub = self.create_audited_publisher(String, "/cmd", 10)
            self.sub = self.create_audited_subscription(String, "/sensor", 10)
            self.timer = self.create_timer(1.0, self.tick)

        def tick(self):
            msg = String(data="hello")
            self.pub.publish(msg)   # stamps automatically

IP : e-Soleau DSO2026006483 (INPI France — 19/02/2026)
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__  = "PiQrypt Inc."
__license__ = "Apache-2.0"

import hashlib
import json
import time
import functools
from typing import Any, Callable, Dict, List, Optional, Type

try:
    import piqrypt as aiss
except ImportError:
    raise ImportError(
        "piqrypt is required. Install with: pip install piqrypt"
    )

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
        "rclpy is required. Install ROS2 (Humble or later) and source setup.bash.\n"
        "  See: https://docs.ros.org/en/humble/Installation.html"
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _h(value: Any) -> str:
    """SHA-256 of any value. Never stores raw content."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

def _msg_h(msg: Any) -> str:
    """Hash a ROS2 message. Uses __slots__ if available (most msg types)."""
    try:
        d = {k: getattr(msg, k) for k in msg.__slots__}
        return _h(json.dumps(d, default=str, sort_keys=True))
    except Exception:
        return _h(str(msg))

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


# ══════════════════════════════════════════════════════════════════════════════
# AUDITED PUBLISHER
# ══════════════════════════════════════════════════════════════════════════════

class AuditedPublisher:
    """
    ROS2 Publisher wrapper that stamps every published message.

    Created by AuditedNode.create_audited_publisher() — do not instantiate directly.
    """

    def __init__(
        self,
        publisher: Publisher,
        topic: str,
        pq_key: bytes,
        pq_id: str,
        stamp_fn: Callable,
    ):
        self._pub      = publisher
        self.topic     = topic
        self._pq_key   = pq_key
        self._pq_id    = pq_id
        self._stamp    = stamp_fn
        self._seq      = 0

    def publish(self, msg: Any) -> None:
        """Publish message and stamp the event cryptographically."""
        self._pub.publish(msg)
        self._seq += 1
        self._stamp("ros2_publish", {
            "topic":     self.topic,
            "msg_type":  type(msg).__name__,
            "msg_hash":  _msg_h(msg),
            "seq":       self._seq,
        })

    # Proxy remaining Publisher attributes
    def __getattr__(self, name: str) -> Any:
        return getattr(self._pub, name)


# ══════════════════════════════════════════════════════════════════════════════
# AUDITED NODE
# ══════════════════════════════════════════════════════════════════════════════

class AuditedNode(Node):
    """
    ROS2 Node with PiQrypt cryptographic audit trail.

    Drop-in replacement for rclpy.node.Node.
    Stamps: publish, subscribe callbacks, service calls, timer callbacks,
    action goals/results/feedback, and arbitrary custom events.

    Parameters
    ----------
    node_name : str
        ROS2 node name.
    identity_file : str, optional
        Path to PiQrypt identity JSON.
    private_key : bytes, optional
        Explicit Ed25519 private key.
    agent_id : str, optional
        Explicit agent ID (with private_key).
    vigil_endpoint : str, optional
        Vigil server URL for live monitoring.
        e.g. "http://localhost:8421"
    **node_kwargs
        Passed through to rclpy.node.Node.__init__().

    Examples
    --------
    >>> class MyNode(AuditedNode):
    ...     def __init__(self):
    ...         super().__init__("my_node", identity_file="my_node.json")
    ...         self.pub = self.create_audited_publisher(String, "/out", 10)
    ...         self.create_audited_subscription(String, "/in", 10, self.cb)
    ...
    ...     def cb(self, msg):
    ...         self.pub.publish(msg)
    """

    def __init__(
        self,
        node_name: str,
        *,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        vigil_endpoint: Optional[str] = None,
        **node_kwargs,
    ):
        super().__init__(node_name, **node_kwargs)

        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )
        self._node_name     = node_name
        self._vigil         = vigil_endpoint.rstrip("/") if vigil_endpoint else None
        self._last_hash: Optional[str] = None
        self._event_count   = 0

        # Stamp node initialization
        self._stamp_event("ros2_node_init", {
            "node_name":  node_name,
            "framework":  "ros2",
            "aiss_profile": "AISS-1",
        })

    # ── Internal stamp ────────────────────────────────────────────────────────

    def _stamp_event(self, event_type: str, payload: Dict) -> Dict:
        """Sign, chain and store one audit event."""
        full = {
            "event_type":   event_type,
            "node_name":    self._node_name,
            "aiss_profile": "AISS-1",
            "ros_time":     self.get_clock().now().nanoseconds,
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
                f"{self._vigil}/api/agent/{self._node_name}/record",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass

    # ── Audited publisher ─────────────────────────────────────────────────────

    def create_audited_publisher(
        self,
        msg_type: Type,
        topic: str,
        qos_profile: Any,
        **kwargs,
    ) -> AuditedPublisher:
        """
        Create a publisher that stamps every published message.

        Usage:
            self.pub = self.create_audited_publisher(String, "/cmd_vel", 10)
            self.pub.publish(msg)   # stamped automatically
        """
        pub = self.create_publisher(msg_type, topic, qos_profile, **kwargs)
        self._stamp_event("ros2_publisher_created", {
            "topic":    topic,
            "msg_type": msg_type.__name__,
            "qos":      str(qos_profile),
        })
        return AuditedPublisher(pub, topic, self._pq_key, self._pq_id, self._stamp_event)

    # ── Audited subscription ──────────────────────────────────────────────────

    def create_audited_subscription(
        self,
        msg_type: Type,
        topic: str,
        qos_profile: Any,
        callback: Optional[Callable] = None,
        **kwargs,
    ) -> Subscription:
        """
        Create a subscription that stamps every received message.

        The original callback is wrapped transparently — no changes needed.

        Usage:
            self.create_audited_subscription(String, "/sensor", 10, self.on_sensor)

            def on_sensor(self, msg):
                # msg received, event already stamped
                self.get_logger().info(msg.data)
        """
        def _audited_cb(msg: Any) -> None:
            self._stamp_event("ros2_message_received", {
                "topic":    topic,
                "msg_type": type(msg).__name__,
                "msg_hash": _msg_h(msg),
            })
            if callback:
                callback(msg)

        sub = self.create_subscription(msg_type, topic, _audited_cb, qos_profile, **kwargs)
        self._stamp_event("ros2_subscription_created", {
            "topic":    topic,
            "msg_type": msg_type.__name__,
        })
        return sub

    # ── Audited service call ───────────────────────────────────────────────────

    def call_service_audited(
        self,
        client: Any,
        request: Any,
        timeout_sec: float = 5.0,
    ) -> Any:
        """
        Call a ROS2 service and stamp request + response.

        Usage:
            client = self.create_client(AddTwoInts, "/add_two_ints")
            req    = AddTwoInts.Request(a=3, b=4)
            resp   = self.call_service_audited(client, req)
        """
        service_name = client.srv_name

        self._stamp_event("ros2_service_request", {
            "service":      service_name,
            "request_hash": _h(str(request)),
        })

        if not client.wait_for_service(timeout_sec=timeout_sec):
            self._stamp_event("ros2_service_timeout", {
                "service":     service_name,
                "timeout_sec": timeout_sec,
            })
            raise TimeoutError(f"Service {service_name} not available after {timeout_sec}s")

        future = client.call_async(request)
        rclpy.spin_until_future_complete(self, future, timeout_sec=timeout_sec)

        response = future.result()
        self._stamp_event("ros2_service_response", {
            "service":       service_name,
            "success":       response is not None,
            "response_hash": _h(str(response)) if response else None,
        })
        return response

    # ── Audited action client ─────────────────────────────────────────────────

    def send_action_audited(
        self,
        action_client: ActionClient,
        goal: Any,
        feedback_callback: Optional[Callable] = None,
    ) -> Any:
        """
        Send an action goal and stamp goal, feedback and result.

        Usage:
            client = ActionClient(self, Fibonacci, "/fibonacci")
            goal   = Fibonacci.Goal(order=10)
            result = self.send_action_audited(client, goal)
        """
        action_name = action_client._action_name

        # Stamp goal
        self._stamp_event("ros2_action_goal_sent", {
            "action":     action_name,
            "goal_hash":  _h(str(goal)),
        })

        def _fb_cb(feedback_msg: Any) -> None:
            self._stamp_event("ros2_action_feedback", {
                "action":          action_name,
                "feedback_hash":   _h(str(feedback_msg.feedback)),
            })
            if feedback_callback:
                feedback_callback(feedback_msg)

        action_client.wait_for_server()
        send_goal_future = action_client.send_goal_async(goal, feedback_callback=_fb_cb)
        rclpy.spin_until_future_complete(self, send_goal_future)

        goal_handle = send_goal_future.result()
        if not goal_handle.accepted:
            self._stamp_event("ros2_action_goal_rejected", {
                "action": action_name,
            })
            raise RuntimeError(f"Action goal rejected by {action_name}")

        self._stamp_event("ros2_action_goal_accepted", {
            "action": action_name,
        })

        result_future = goal_handle.get_result_async()
        rclpy.spin_until_future_complete(self, result_future)
        result = result_future.result()

        self._stamp_event("ros2_action_result", {
            "action":      action_name,
            "status":      str(result.status),
            "result_hash": _h(str(result.result)),
        })
        return result

    # ── Audited action server ─────────────────────────────────────────────────

    def create_audited_action_server(
        self,
        action_type: Type,
        action_name: str,
        execute_callback: Callable,
        **kwargs,
    ) -> ActionServer:
        """
        Create an action server that stamps every goal execution.

        Usage:
            self.create_audited_action_server(
                Fibonacci, "/fibonacci", self.execute_fibonacci
            )

            async def execute_fibonacci(self, goal_handle):
                ...
                goal_handle.succeed()
                return Fibonacci.Result(sequence=[...])
        """
        def _audited_execute(goal_handle: Any):
            self._stamp_event("ros2_action_server_goal_received", {
                "action":    action_name,
                "goal_hash": _h(str(goal_handle.request)),
            })
            try:
                result = execute_callback(goal_handle)
                self._stamp_event("ros2_action_server_goal_complete", {
                    "action":      action_name,
                    "result_hash": _h(str(result)),
                    "success":     True,
                })
                return result
            except Exception as e:
                self._stamp_event("ros2_action_server_goal_failed", {
                    "action":     action_name,
                    "error_hash": _h(str(e)),
                    "success":    False,
                })
                raise

        server = ActionServer(
            self,
            action_type,
            action_name,
            _audited_execute,
            **kwargs,
        )
        self._stamp_event("ros2_action_server_created", {
            "action": action_name,
        })
        return server

    # ── Audited timer ─────────────────────────────────────────────────────────

    def create_audited_timer(
        self,
        period_sec: float,
        callback: Callable,
        stamp_every_n: int = 1,
    ):
        """
        Create a timer that stamps its callbacks.

        stamp_every_n : int
            Stamp every N ticks (default=1 → stamp every tick).
            Use stamp_every_n=10 for high-frequency timers to reduce overhead.
        """
        self._timer_tick = 0

        def _audited_cb():
            self._timer_tick += 1
            if self._timer_tick % stamp_every_n == 0:
                self._stamp_event("ros2_timer_tick", {
                    "period_sec":  period_sec,
                    "tick":        self._timer_tick,
                })
            callback()

        return self.create_timer(period_sec, _audited_cb)

    # ── Manual stamp ─────────────────────────────────────────────────────────

    def stamp(self, event_type: str, payload: Optional[Dict] = None) -> Dict:
        """
        Stamp an arbitrary custom event into the audit chain.

        Usage:
            self.stamp("obstacle_detected", {
                "distance": 0.34,
                "direction": "forward",
            })
        """
        return self._stamp_event(event_type, payload or {})

    # ── Export ────────────────────────────────────────────────────────────────

    def export_audit(self, output_path: str = "ros2_audit.json") -> str:
        """Export this node's full audit trail to JSON."""
        aiss.export_audit_chain(output_path)
        return output_path

    @property
    def piqrypt_id(self) -> str:
        """This node's PiQrypt identity."""
        return self._pq_id

    @property
    def audit_event_count(self) -> int:
        """Total number of stamped events since node init."""
        return self._event_count


# ══════════════════════════════════════════════════════════════════════════════
# AUDITED LIFECYCLE NODE
# ══════════════════════════════════════════════════════════════════════════════

try:
    from rclpy.lifecycle import LifecycleNode, TransitionCallbackReturn

    class AuditedLifecycleNode(LifecycleNode):
        """
        ROS2 LifecycleNode with PiQrypt cryptographic audit trail.

        Every lifecycle transition (configure, activate, deactivate,
        cleanup, shutdown) is stamped with a signed event.

        This provides a complete cryptographic record of the node's
        operational history — essential for safety-critical systems
        (industrial robots, autonomous vehicles, medical devices).

        Usage:
            class MyLifecycleNode(AuditedLifecycleNode):
                def __init__(self):
                    super().__init__(
                        "my_lifecycle_node",
                        identity_file="my_node.json",
                    )

                def on_configure(self, state):
                    # your setup
                    return TransitionCallbackReturn.SUCCESS

                def on_activate(self, state):
                    # start publishers etc
                    return TransitionCallbackReturn.SUCCESS

                def on_deactivate(self, state):
                    return TransitionCallbackReturn.SUCCESS

                def on_cleanup(self, state):
                    return TransitionCallbackReturn.SUCCESS

                def on_shutdown(self, state):
                    return TransitionCallbackReturn.SUCCESS
        """

        def __init__(
            self,
            node_name: str,
            *,
            identity_file: Optional[str] = None,
            private_key: Optional[bytes] = None,
            agent_id: Optional[str] = None,
            vigil_endpoint: Optional[str] = None,
            **node_kwargs,
        ):
            super().__init__(node_name, **node_kwargs)

            self._pq_key, self._pq_id = _resolve_identity(
                identity_file, private_key, agent_id
            )
            self._node_name   = node_name
            self._vigil       = vigil_endpoint.rstrip("/") if vigil_endpoint else None
            self._last_hash: Optional[str] = None
            self._event_count = 0

            # Register lifecycle transition callbacks
            self.register_on_configure(self._on_configure_audited)
            self.register_on_activate(self._on_activate_audited)
            self.register_on_deactivate(self._on_deactivate_audited)
            self.register_on_cleanup(self._on_cleanup_audited)
            self.register_on_shutdown(self._on_shutdown_audited)

            self._stamp_event("ros2_lifecycle_node_created", {
                "node_name":    node_name,
                "framework":    "ros2_lifecycle",
                "aiss_profile": "AISS-1",
            })

        # ── Internal stamp (same pattern as AuditedNode) ──────────────────────

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
            return event

        # ── Lifecycle transition stamps ───────────────────────────────────────

        def _on_configure_audited(self, state: Any) -> TransitionCallbackReturn:
            self._stamp_event("ros2_lifecycle_configure", {
                "from_state": str(state.label),
            })
            result = self.on_configure(state)
            self._stamp_event("ros2_lifecycle_configure_result", {
                "result":  str(result),
                "success": result == TransitionCallbackReturn.SUCCESS,
            })
            return result

        def _on_activate_audited(self, state: Any) -> TransitionCallbackReturn:
            self._stamp_event("ros2_lifecycle_activate", {
                "from_state": str(state.label),
            })
            result = self.on_activate(state)
            self._stamp_event("ros2_lifecycle_activate_result", {
                "result":  str(result),
                "success": result == TransitionCallbackReturn.SUCCESS,
            })
            return result

        def _on_deactivate_audited(self, state: Any) -> TransitionCallbackReturn:
            self._stamp_event("ros2_lifecycle_deactivate", {
                "from_state": str(state.label),
            })
            result = self.on_deactivate(state)
            self._stamp_event("ros2_lifecycle_deactivate_result", {
                "result":  str(result),
                "success": result == TransitionCallbackReturn.SUCCESS,
            })
            return result

        def _on_cleanup_audited(self, state: Any) -> TransitionCallbackReturn:
            self._stamp_event("ros2_lifecycle_cleanup", {
                "from_state": str(state.label),
            })
            result = self.on_cleanup(state)
            self._stamp_event("ros2_lifecycle_cleanup_result", {
                "result": str(result),
            })
            return result

        def _on_shutdown_audited(self, state: Any) -> TransitionCallbackReturn:
            self._stamp_event("ros2_lifecycle_shutdown", {
                "from_state":   str(state.label),
                "event_count":  self._event_count,
            })
            result = self.on_shutdown(state)
            self._stamp_event("ros2_lifecycle_shutdown_result", {
                "result": str(result),
            })
            return result

        # ── Overridable lifecycle hooks ───────────────────────────────────────
        # Subclasses override these — NOT the _audited variants.

        def on_configure(self, state: Any) -> TransitionCallbackReturn:
            return TransitionCallbackReturn.SUCCESS

        def on_activate(self, state: Any) -> TransitionCallbackReturn:
            return TransitionCallbackReturn.SUCCESS

        def on_deactivate(self, state: Any) -> TransitionCallbackReturn:
            return TransitionCallbackReturn.SUCCESS

        def on_cleanup(self, state: Any) -> TransitionCallbackReturn:
            return TransitionCallbackReturn.SUCCESS

        def on_shutdown(self, state: Any) -> TransitionCallbackReturn:
            return TransitionCallbackReturn.SUCCESS

        # ── Convenience ───────────────────────────────────────────────────────

        def stamp(self, event_type: str, payload: Optional[Dict] = None) -> Dict:
            """Stamp an arbitrary custom event."""
            return self._stamp_event(event_type, payload or {})

        def export_audit(self, output_path: str = "ros2_lifecycle_audit.json") -> str:
            aiss.export_audit_chain(output_path)
            return output_path

        @property
        def piqrypt_id(self) -> str:
            return self._pq_id

except ImportError:
    # rclpy.lifecycle not available in all ROS2 distros
    class AuditedLifecycleNode:  # type: ignore
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "rclpy.lifecycle not available. "
                "Requires ROS2 Humble or later."
            )


# ══════════════════════════════════════════════════════════════════════════════
# stamp_callback DECORATOR
# ══════════════════════════════════════════════════════════════════════════════

def stamp_callback(
    event_type: str,
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
):
    """
    Decorator — stamp any ROS2 callback function with PiQrypt proof.

    Useful when you cannot subclass AuditedNode (e.g. third-party nodes).

    Usage:
        @stamp_callback("sensor_processed", identity_file="my_node.json")
        def process_sensor(msg):
            return analyze(msg)
    """
    def decorator(func: Callable) -> Callable:
        _key, _id = _resolve_identity(identity_file, private_key, agent_id)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            event = aiss.stamp_event(_key, _id, {
                "event_type":   event_type,
                "args_hash":    _h(args),
                "result_hash":  _h(result),
                "aiss_profile": "AISS-1",
            })
            aiss.store_event(event)
            return result
        return wrapper
    return decorator


# ── Public API ────────────────────────────────────────────────────────────────

__all__ = [
    "AuditedNode",
    "AuditedLifecycleNode",
    "AuditedPublisher",
    "stamp_callback",
]
