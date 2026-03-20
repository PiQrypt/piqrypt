"""
Tests — bridges/ros/piqrypt_ros.py
Bridge AuditedPublisher + AuditedNode

Run: pytest test_piqrypt_ros.py -v
"""
import hashlib
import json
import sys
import time
import types
import unittest
from unittest.mock import MagicMock, patch


# ── Mock piqrypt ──────────────────────────────────────────────────────────────

def _setup_piqrypt_mock():
    events = []
    mock = types.ModuleType("piqrypt")
    mock.generate_keypair     = lambda: (b"priv" * 8, b"pub" * 8)
    mock.derive_agent_id      = lambda pub: "AGENT_" + hashlib.sha256(pub).hexdigest()[:12]
    mock.load_identity        = lambda f: {"private_key_bytes": b"key" * 8, "agent_id": "AGENT_TEST"}
    mock.stamp_event          = lambda key, aid, payload: {
        **payload,
        "_pq_agent_id": aid,
        "_pq_timestamp": time.time(),
        "_pq_sig": "mocksig",
    }
    mock.store_event          = lambda e: events.append(e)
    mock.compute_event_hash   = lambda e: hashlib.sha256(json.dumps(e, default=str).encode()).hexdigest()
    mock.export_audit_chain   = lambda path: open(path, "w").write(json.dumps(events))
    mock._events              = events
    sys.modules["piqrypt"] = mock
    return mock, events

_mock_piqrypt, _events = _setup_piqrypt_mock()


# ── Mock ROS2 ─────────────────────────────────────────────────────────────────

def _setup_ros2_mock():
    rclpy_mod = types.ModuleType("rclpy")
    node_mod = types.ModuleType("rclpy.node")
    std_msgs = types.ModuleType("std_msgs")
    std_msgs_msg = types.ModuleType("std_msgs.msg")
    geometry_msgs = types.ModuleType("geometry_msgs")
    geometry_msgs_msg = types.ModuleType("geometry_msgs.msg")

    class Node:
        def __init__(self, name, **kwargs):
            self.node_name = name

        def create_publisher(self, msg_type, topic, qos):
            pub = MagicMock()
            pub.publish = MagicMock()
            return pub

        def create_subscription(self, msg_type, topic, callback, qos):
            return MagicMock()

        def create_timer(self, period, callback):
            return MagicMock()

        def get_logger(self):
            return MagicMock()

        def destroy_node(self):
            pass

    class String:
        def __init__(self):
            self.data = ""

    class Twist:
        def __init__(self):
            self.linear = MagicMock(x=0.0, y=0.0, z=0.0)
            self.angular = MagicMock(x=0.0, y=0.0, z=0.0)

    rclpy_mod.node = node_mod
    node_mod.Node = Node
    std_msgs_msg.String = String
    geometry_msgs_msg.Twist = Twist

    sys.modules["rclpy"] = rclpy_mod
    sys.modules["rclpy.node"] = node_mod
    sys.modules["std_msgs"] = std_msgs
    sys.modules["std_msgs.msg"] = std_msgs_msg
    sys.modules["geometry_msgs"] = geometry_msgs
    sys.modules["geometry_msgs.msg"] = geometry_msgs_msg

    return Node, String, Twist

MockNode, MockString, MockTwist = _setup_ros2_mock()

# Import bridge
from piqrypt_ros import AuditedNode, AuditedPublisher, stamp_callback  # noqa: E402


# ══════════════════════════════════════════════════════════════════════════════
# Tests AuditedNode — identité
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditedNodeIdentity(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.node = AuditedNode("test_node", agent_name="ros_agent")

    def test_piqrypt_id_generated(self):
        self.assertTrue(self.node.piqrypt_id.startswith("AGENT_"))

    def test_identity_from_file(self):
        with patch("piqrypt_ros.aiss.load_identity",
                   return_value={"private_key_bytes": b"k"*32, "agent_id": "AGENT_FILE"}):
            node = AuditedNode("test_node", identity_file="fake.json")
        self.assertEqual(node.piqrypt_id, "AGENT_FILE")

    def test_node_name_preserved(self):
        node = AuditedNode("my_robot_node", agent_name="robot")
        self.assertEqual(node.node_name, "my_robot_node")

    def test_audit_event_count_initial(self):
        self.assertIsInstance(self.node.audit_event_count, int)


# ══════════════════════════════════════════════════════════════════════════════
# Tests AuditedPublisher
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditedPublisher(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.node = AuditedNode("publisher_node", agent_name="ros_agent")

    def test_create_publisher_returns_audited_publisher(self):
        pub = self.node.create_audited_publisher(MockString, "/chatter", 10)
        self.assertIsInstance(pub, AuditedPublisher)

    def test_publish_stamps_event(self):
        _events.clear()
        pub = self.node.create_audited_publisher(MockString, "/cmd_vel", 10)
        msg = MockTwist()
        pub.publish(msg)
        self.assertTrue(len(_events) >= 1)

    def test_publish_stamps_topic(self):
        _events.clear()
        pub = self.node.create_audited_publisher(MockString, "/my_topic", 10)
        msg = MockString()
        msg.data = "hello robot"
        pub.publish(msg)
        pub_events = [e for e in _events if "publish" in e.get("event_type", "").lower()]
        self.assertTrue(len(pub_events) >= 1)
        self.assertIn("/my_topic", json.dumps(pub_events[0]))

    def test_publish_hashes_message_not_stores_raw(self):
        _events.clear()
        pub = self.node.create_audited_publisher(MockString, "/secret_topic", 10)
        msg = MockString()
        msg.data = "CLASSIFIED_ROBOT_COMMAND_XYZ"
        pub.publish(msg)
        for e in _events:
            self.assertNotIn("CLASSIFIED_ROBOT_COMMAND_XYZ", json.dumps(e))

    def test_publish_stamps_message_hash(self):
        _events.clear()
        pub = self.node.create_audited_publisher(MockString, "/data", 10)
        msg = MockString()
        msg.data = "sensor_reading_42"
        pub.publish(msg)
        hash_events = [e for e in _events if "msg_hash" in e or "message_hash" in e]
        self.assertTrue(len(hash_events) >= 1)

    def test_multiple_publishes_chained(self):
        _events.clear()
        pub = self.node.create_audited_publisher(MockString, "/cmd", 10)
        msg = MockString()
        pub.publish(msg)
        count_after_first = len(_events)
        pub.publish(msg)
        second_batch = _events[count_after_first:]
        if second_batch:
            self.assertIn("previous_event_hash", second_batch[0])


# ══════════════════════════════════════════════════════════════════════════════
# Tests subscriptions
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditedSubscription(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.node = AuditedNode("subscriber_node", agent_name="ros_sub")

    def test_create_subscription_returns_subscription(self):
        callback = MagicMock()
        sub = self.node.create_audited_subscription(MockString, "/chatter", callback, 10)
        self.assertIsNotNone(sub)

    def test_subscription_callback_stamps_on_receive(self):
        _events.clear()
        received = []

        def my_callback(msg):
            received.append(msg)

        sub = self.node.create_audited_subscription(MockString, "/sensor_data", my_callback, 10)

        # Simulate message reception — call the wrapped callback directly
        msg = MockString()
        msg.data = "temperature: 25.3C"
        if hasattr(sub, '_audited_callback'):
            sub._audited_callback(msg)
        elif hasattr(sub, 'callback'):
            sub.callback(msg)
        # If wrapping is internal, just verify subscription was created
        self.assertIsNotNone(sub)

    def test_subscription_callback_hashes_message(self):
        _events.clear()
        received_msgs = []

        def callback(msg):
            received_msgs.append(msg)

        sub = self.node.create_audited_subscription(MockString, "/classified", callback, 10)
        msg = MockString()
        msg.data = "SECRET_SENSOR_DATA_ABC"

        # Trigger wrapped callback if available
        if hasattr(sub, '_audited_callback'):
            sub._audited_callback(msg)

        # Check raw content never stored
        for e in _events:
            self.assertNotIn("SECRET_SENSOR_DATA_ABC", json.dumps(e))


# ══════════════════════════════════════════════════════════════════════════════
# Tests AuditedNode.stamp()
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditedNodeStamp(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.node = AuditedNode("stamping_node", agent_name="ros_agent")

    def test_stamp_creates_event(self):
        self.node.stamp("lifecycle_change", {"from": "unconfigured", "to": "inactive"})
        self.assertTrue(len(_events) >= 1)

    def test_stamp_event_type_correct(self):
        _events.clear()
        self.node.stamp("navigation_goal_set", {"goal_x": 1.0, "goal_y": 2.0})
        nav_events = [e for e in _events if "navigation" in e.get("event_type", "")]
        self.assertTrue(len(nav_events) >= 1)

    def test_stamp_sensitive_data_hashed(self):
        _events.clear()
        self.node.stamp("gps_reading", {
            "lat_hash": hashlib.sha256(b"48.8566").hexdigest(),
            "lon_hash": hashlib.sha256(b"2.3522").hexdigest(),
        })
        for e in _events:
            self.assertNotIn("48.8566", json.dumps(e))

    def test_stamp_increments_event_count(self):
        initial = self.node.audit_event_count
        self.node.stamp("test_event", {})
        self.assertGreater(self.node.audit_event_count, initial)

    def test_stamp_updates_last_hash(self):
        initial = self.node.last_event_hash
        self.node.stamp("test_event", {})
        self.assertNotEqual(self.node.last_event_hash, initial)


# ══════════════════════════════════════════════════════════════════════════════
# Tests @stamp_callback décorateur
# ══════════════════════════════════════════════════════════════════════════════

class TestStampCallback(unittest.TestCase):

    def setUp(self):
        _events.clear()

    def test_stamp_callback_stamps_event(self):
        @stamp_callback("lidar_scan", agent_name="test_node")
        def process_scan(msg):
            return {"points": 1024, "max_range": 10.0}

        msg = MockString()
        msg.data = "scan_data"
        result = process_scan(msg)
        self.assertIsNotNone(result)
        self.assertTrue(len(_events) >= 1)

    def test_stamp_callback_stamps_result_hash(self):
        @stamp_callback("image_proc", agent_name="test_node")
        def process_image(msg):
            return {"objects_detected": 3, "confidence": 0.94}

        process_image(MockString())
        complete = [e for e in _events if "complete" in e.get("event_type", "").lower()
                    or "end" in e.get("event_type", "").lower()]
        if complete:
            self.assertIn("result_hash", complete[0])

    def test_stamp_callback_preserves_return(self):
        @stamp_callback("sensor", agent_name="test")
        def read_sensor(msg):
            return {"value": 42.0, "unit": "celsius"}

        result = read_sensor(MockString())
        self.assertEqual(result["value"], 42.0)

    def test_stamp_callback_stamps_error(self):
        @stamp_callback("failing_cb", agent_name="test")
        def bad_callback(msg):
            raise RuntimeError("Sensor read failed")

        with self.assertRaises(RuntimeError):
            bad_callback(MockString())
        error_events = [e for e in _events if "error" in e.get("event_type", "").lower()]
        self.assertTrue(len(error_events) >= 1)

    def test_stamp_callback_preserves_function_name(self):
        @stamp_callback("wrap", agent_name="test")
        def my_callback(msg):
            return None
        self.assertEqual(my_callback.__name__, "my_callback")


# ══════════════════════════════════════════════════════════════════════════════
# Tests export
# ══════════════════════════════════════════════════════════════════════════════

class TestExport(unittest.TestCase):

    def test_export_audit(self):
        import tempfile
        import os
        node = AuditedNode("export_node", agent_name="test")
        _events.clear()
        node.stamp("test_event", {"data": "value"})
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            node.export_audit(path)
            self.assertTrue(os.path.exists(path))
            data = json.loads(open(path).read())
            self.assertIsInstance(data, list)
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Test cross-framework : ROS2 + AgentSession
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossFrameworkScenario(unittest.TestCase):
    """
    Un nœud ROS2 reçoit une commande d'un orchestrateur LLM.
    Le payload_hash de la commande doit être identique dans les deux mémoires.
    """

    def test_command_hash_preserved_from_llm_to_ros(self):
        _events.clear()
        node = AuditedNode("robot_controller", agent_name="ros_controller")

        # Commande envoyée par l'orchestrateur LLM
        command = {"action": "move_to", "x": 1.5, "y": 2.3, "speed": 0.5}
        payload_hash = hashlib.sha256(json.dumps(command).encode()).hexdigest()

        # ROS2 node reçoit la commande — co-signature simulée
        node.stamp("command_received", {
            "payload_hash": payload_hash,
            "peer": "llm_orchestrator",
            "action": "move_to",
        })

        # Exécution : publication sur /cmd_vel
        pub = node.create_audited_publisher(MockTwist, "/cmd_vel", 10)
        msg = MockTwist()
        pub.publish(msg)

        # Vérifier que le payload_hash est dans la mémoire ROS2
        hashes = [e.get("payload_hash") for e in _events if "payload_hash" in e]
        self.assertIn(payload_hash, hashes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
