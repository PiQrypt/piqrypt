# piqrypt-ros

**Cryptographic audit trail for ROS2 robotics agents.**

[![PyPI](https://img.shields.io/pypi/v/piqrypt-ros)](https://pypi.org/project/piqrypt-ros/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![PiQrypt](https://img.shields.io/badge/powered%20by-PiQrypt-00C8E0)](https://piqrypt.com)

Every topic publication, service call, action, and timer tick — signed Ed25519,
hash-chained, tamper-proof. Audit what your robots actually did, when, and why.

---

## Install

```bash
pip install piqrypt[ros]
# Requires: ROS2 (Humble/Iron/Jazzy) + rclpy
```

---

## Quickstart — drop-in node

```python
import rclpy
from geometry_msgs.msg import Twist
from piqrypt_ros import AuditedNode

rclpy.init()

node = AuditedNode(
    "robot_controller",
    identity_file="~/.piqrypt/robot.json",
)

# AuditedPublisher — every publish() is signed
cmd_pub = node.create_audited_publisher(Twist, "/cmd_vel", 10)

twist = Twist()
twist.linear.x = 0.5
cmd_pub.publish(twist)   # ← signed, hash-chained, tamper-proof

# Export audit trail
node.export_audit("robot_audit.json")
```

---

## What gets stamped

| Event | Stamped data |
|-------|-------------|
| `topic_publish` | topic, msg_hash, timestamp |
| `topic_received` | topic, msg_hash, sender |
| `service_call` | service name, request_hash |
| `service_response` | response_hash, duration_ms |
| `action_goal` | action name, goal_hash |
| `action_result` | result_hash, success |
| `timer_tick` | timer name, tick count |
| `lifecycle_change` | from_state, to_state |

**Privacy:** message content is never stored — only SHA-256 hashes.

---

## AuditedNode

```python
from piqrypt_ros import AuditedNode

node = AuditedNode(
    "my_node",
    identity_file="~/.piqrypt/robot.json",
    # or auto-generate ephemeral:
    # agent_name="my_node"
)

# Audited publisher
pub = node.create_audited_publisher(String, "/chatter", 10)
pub.publish(msg)  # signed

# Audited subscription — callback wrapped automatically
def on_scan(msg):
    # process lidar scan
    pass

sub = node.create_audited_subscription(LaserScan, "/scan", on_scan, 10)
# Every received message stamped: topic, msg_hash

# Audited service call
response = node.call_service_audited("/compute_path", request)

# Audited action
result = node.send_action_audited("/navigate_to_pose", goal)

# Audited timer
node.create_audited_timer(0.1, my_control_loop)  # 10 Hz

# Manual stamp — any custom event
node.stamp("collision_detected", {
    "location_hash": sha256(str(pose)),
    "severity": "high",
})

# Inspection
print(node.piqrypt_id)         # AGENT_...
print(node.audit_event_count)  # 142
print(node.last_event_hash)    # sha256...

node.export_audit("audit.json")
```

## @stamp_callback — audit any callback

```python
from piqrypt_ros import stamp_callback

@stamp_callback("lidar_processing", identity_file="~/.piqrypt/robot.json")
def process_scan(msg: LaserScan) -> dict:
    points = len(msg.ranges)
    min_range = min(msg.ranges)
    return {"points": points, "min_range": min_range}

# Every call stamped: callback_start (input_hash), callback_complete (result_hash)
```

---

## Cross-framework: ROS2 + LLM orchestrator

The key use case: an LLM agent (CrewAI, LangChain, AutoGen) sends a command
to a ROS2 robot. Every handoff is cryptographically co-signed in both memories.

```python
from piqrypt_ros import AuditedNode
from piqrypt_session import AgentSession
from geometry_msgs.msg import PoseStamped

# Session: co-signs LLM ↔ ROS2 interactions
session = AgentSession([
    {"name": "llm_planner", "identity_file": "~/.piqrypt/planner.json"},
    {"name": "ros2_robot",  "identity_file": "~/.piqrypt/robot.json"},
])
session.start()

# LLM planner sends navigation goal — co-signed in both memories
goal = {"x": 3.5, "y": 1.2, "theta": 0.0}
session.stamp("llm_planner", "navigation_goal_sent", {
    "goal_hash": sha256(json.dumps(goal)),
    "map_id": "warehouse_floor_2",
}, peer="ros2_robot")

# ROS2 robot receives and executes
node = AuditedNode("robot", identity_file="~/.piqrypt/robot.json")
result = node.send_action_audited("/navigate_to_pose", goal)

# Execution result sent back to LLM — co-signed
session.stamp("ros2_robot", "navigation_complete", {
    "result_hash": sha256(str(result)),
    "status": "SUCCESS",
}, peer="llm_planner")

# Full cross-framework audit: who ordered what, what the robot did
session.export("mission_audit.json")
node.export_audit("robot_audit.json")
```

**What this proves in case of incident:**
- The LLM planner issued this specific navigation goal (its Ed25519 signature)
- The ROS2 robot received exactly this goal (same hash, its signature)
- The robot's execution followed from that goal (causal chain)
- Timestamp RFC 3161 optionally seals the entire sequence

---

## Use cases

**Autonomous vehicles (ISO 26262 / UN R157)**
Every trajectory command, sensor reading processed, and actuator activation —
signed and hash-chained. Reproducible audit for any safety investigation.

**Industrial robotics (IEC 62443)**
Multi-robot system with LLM orchestration. Each inter-agent command co-signed.
In case of incident, distinguishes software fault from external modification.

**Medical robotics (IEC 62304 / FDA 21 CFR Part 11)**
Surgical or rehabilitation robot with AI supervision. Every command signed by the
AI agent that issued it. Human override always stamped with human principal ID.

**Warehouse automation**
LLM-coordinated robot fleet. Each pick-and-place task assigned by LLM,
co-signed with the executing robot. Full traceability per SKU.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

Part of [PiQrypt](https://piqrypt.com) — Trust infrastructure for autonomous AI agents.  
IP: e-Soleau DSO2026006483 (INPI France — 19/02/2026)
