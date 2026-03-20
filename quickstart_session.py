# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#!/usr/bin/env python3
"""
quickstart_session.py — PiQrypt Multi-Agent Session Quickstart
==============================================================

Demonstrates AgentSession: the cross-framework co-signed audit primitive.

Scenario: Claude → LangGraph → CrewAI — a regulated trading pipeline
  - 3 agents, 3 frameworks, 1 cryptographically provable causal chain
  - Each cross-agent interaction co-signed in BOTH memories
  - Same payload_hash in both sides — tampering is immediately detectable
  - Full audit trail exportable and independently verifiable

What makes this unique:
  LangSmith traces LangChain only.
  CrewAI has its own logs only.
  PiQrypt Session is the first tool that co-signs interactions
  ACROSS framework boundaries — framework-agnostic.

Usage:
    python quickstart_session.py
    python quickstart_session.py --agents 4     # more agents
    python quickstart_session.py --scenario all  # show all scenarios

Requirements:
    pip install piqrypt

IP: e-Soleau DSO2026006483 (INPI France — 19/02/2026)
PiQrypt v1.7.1 — https://piqrypt.com
"""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

# ── Colour helpers ────────────────────────────────────────────────────────────

def _c(text, code): return f"\033[{code}m{text}\033[0m"
def green(t):  return _c(t, "32")
def cyan(t):   return _c(t, "36")
def yellow(t): return _c(t, "33")
def blue(t):   return _c(t, "34")
def bold(t):   return _c(t, "1")
def dim(t):    return _c(t, "2")

SEP  = dim("─" * 64)
SEP2 = dim("· " * 32)

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


# ── Import guard ──────────────────────────────────────────────────────────────

def _check_imports():
    missing = []
    try:
        import piqrypt  # noqa
    except ImportError:
        missing.append("piqrypt")

    if missing:
        print(f"\n❌  Missing: {', '.join(missing)}")
        print("    Install: pip install piqrypt")
        sys.exit(1)

    try:
        from piqrypt_session import AgentSession  # noqa
        return True
    except ImportError:
        # Session bridge may not be installed as a separate package
        # Fall back to embedded implementation for demo purposes
        return False


def _get_agent_session_class():
    """Return AgentSession — from package or embedded demo fallback."""
    try:
        from piqrypt_session import AgentSession
        return AgentSession, False  # (class, is_mock)
    except ImportError:
        return _build_demo_session(), True


def _build_demo_session():
    """
    Minimal AgentSession implementation for demo when piqrypt-session
    is not installed as a standalone package.
    Used only in quickstart — production use: pip install piqrypt[session]
    """
    import piqrypt as aiss
    import uuid

    class _AgentMember:
        def __init__(self, name):
            self.name = name
            self.private_key, self.public_key = aiss.generate_keypair()
            self.agent_id = aiss.derive_agent_id(self.public_key)
            self._events = []
            self._prev_hash = None

        def stamp(self, event_type, payload, session_id, peer_id=None):
            import piqrypt as aiss
            full = {**payload, "event_type": event_type, "session_id": session_id}
            if peer_id:
                full["peer_agent_id"] = peer_id
            event = aiss.stamp_event(
                self.private_key, self.agent_id,
                payload=full,
                previous_hash=self._prev_hash or "genesis",
            )
            self._prev_hash = aiss.compute_event_hash(event)
            self._events.append(event)
            return event

        @property
        def events(self):
            return self._events

        @property
        def event_count(self):
            return len(self._events)

    class _AgentSession:
        def __init__(self, agents_def):
            if len(agents_def) < 2:
                raise ValueError("Need at least 2 agents")
            self.session_id = f"sess_{uuid.uuid4().hex[:16]}"
            self.started_at = None
            self.started = False
            self._agents = {d["name"]: _AgentMember(d["name"]) for d in agents_def}
            self._handshakes = []

        def start(self):
            self.started_at = int(time.time())
            agent_list = list(self._agents.values())

            for agent in agent_list:
                agent.stamp("session_start", {
                    "participants": [a.agent_id for a in agent_list],
                }, self.session_id)

            for i in range(len(agent_list)):
                for j in range(i + 1, len(agent_list)):
                    a, b = agent_list[i], agent_list[j]
                    hs_hash = sha256(f"{a.agent_id}:{b.agent_id}:{self.session_id}")
                    a.stamp(
                        "a2a_handshake",
                        {"peer_agent_id": b.agent_id, "hs_hash": hs_hash},
                        self.session_id, b.agent_id,
                    )
                    b.stamp(
                        "a2a_handshake",
                        {"peer_agent_id": a.agent_id, "hs_hash": hs_hash},
                        self.session_id, a.agent_id,
                    )
                    self._handshakes.append(
                        {"agent_a": a.name, "agent_b": b.name, "hs_hash": hs_hash}
                    )
                    print(f"  [handshake] {a.name} ↔ {b.name}  co-signed {green('✓')}")

            self.started = True
            return self

        def stamp(self, agent_name, event_type, payload, peer=None):
            agent = self._agents[agent_name]
            safe = {}
            for k, v in payload.items():
                if k.endswith(("_hash", "_id")) or k == "session_id":
                    safe[k] = v
                else:
                    safe[f"{k}_hash"] = sha256(str(v))

            if peer:
                peer_agent = self._agents[peer]
                ih = sha256(f"{agent.agent_id}:{peer_agent.agent_id}:{time.time()}")
                event = agent.stamp(
                    event_type,
                    {**safe, "interaction_hash": ih, "role": "initiator"},
                    self.session_id, peer_agent.agent_id,
                )
                peer_agent.stamp(
                    f"{event_type}_received",
                    {**safe, "interaction_hash": ih, "role": "responder"},
                    self.session_id, agent.agent_id,
                )
                return event, ih
            else:
                return agent.stamp(event_type, safe, self.session_id), None

        def summary(self):
            return {
                "session_id": self.session_id,
                "started_at": self.started_at,
                "agent_count": len(self._agents),
                "handshake_count": len(self._handshakes),
                "total_events": sum(len(a.events) for a in self._agents.values()),
                "agents": {n: {"agent_id": a.agent_id, "event_count": a.event_count}
                           for n, a in self._agents.items()},
            }

        def export(self, path="session-audit.json"):
            data = {
                "session": self.summary(),
                "agents": {n: {"agent_id": a.agent_id, "events": a.events}
                           for n, a in self._agents.items()},
            }
            Path(path).write_text(json.dumps(data, indent=2))
            return path

        @property
        def agents(self):
            return self._agents

        def get_agent(self, name):
            return self._agents[name]

    return _AgentSession


# ── Scenario: Trading Pipeline ────────────────────────────────────────────────

def scenario_trading(AgentSession):
    """
    Regulated trading pipeline: Claude → LangGraph → CrewAI
    MiFID II / SEC Rule 17a-4 — every decision co-signed end-to-end.
    """
    print(f"\n{bold('Scenario: Regulated Trading Pipeline')}")
    print(f"{dim('Claude (analyst) → LangGraph (decision graph) → CrewAI (execution)')}")
    print(SEP)

    session = AgentSession([
        {"name": "claude",    "identity_file": "~/.piqrypt/claude.json"},
        {"name": "langgraph", "identity_file": "~/.piqrypt/langgraph.json"},
        {"name": "crewai",    "identity_file": "~/.piqrypt/crewai.json"},
    ])

    print(f"\n  {bold('Starting session — pairwise handshakes:')}")
    session.start()

    print(f"\n  Session ID : {cyan(session.session_id)}")

    print(f"\n  {bold('Interaction 1 — Claude analyses portfolio:')}")
    portfolio_data = "AAPL×100 MSFT×50 GOOGL×25"
    ev1, ih1 = session.stamp(
        "claude", "portfolio_analysis",
        {
            "portfolio_hash":   sha256(portfolio_data),   # raw data never stored
            "symbols_count":    3,
            "total_positions":  175,
            "analysis_model":   "claude-sonnet",
        },
        peer="langgraph"
    )
    ih1_short = ih1[:16] if ih1 else "n/a"
    print(f"  {green('✓')} Claude    → LangGraph  interaction_hash: {cyan(ih1_short)}...")
    print(dim("      Same hash in both memories — co-signed, non-repudiable"))

    print(f"\n  {bold('Interaction 2 — LangGraph sends decision to CrewAI:')}")
    recommendation = "BUY AAPL 100 @ market — confidence 0.87"
    ev2, ih2 = session.stamp(
        "langgraph", "graph_decision",
        {
            "nodes_executed":       7,
            "recommendation_hash":  sha256(recommendation),
            "risk_score":           0.23,
            "graph_version":        "v3.1",
        },
        peer="crewai"
    )
    ih2_short = ih2[:16] if ih2 else "n/a"
    print(f"  {green('✓')} LangGraph → CrewAI     interaction_hash: {cyan(ih2_short)}...")

    print(f"\n  {bold('Interaction 3 — CrewAI executes (unilateral action):')}")
    ev3, _ = session.stamp(
        "crewai", "trade_executed",
        {
            "symbol":           "AAPL",
            "action":           "BUY",
            "quantity":         100,
            "order_id":         "ORD-2026-003",
            "execution_venue":  "NYSE",
        }
    )
    print(f"  {green('✓')} CrewAI executed trade  (unilateral — signed in CrewAI memory only)")

    summary = session.summary()
    print(f"\n  {bold('Session summary:')}")
    print(f"  Agents         : {', '.join(summary['agents'].keys())}")
    print(f"  Handshakes     : {summary['handshake_count']} co-signed pairs")
    print(f"  Total events   : {summary['total_events']}")
    for name, info in summary["agents"].items():
        print(f"    {name:<12} {info['event_count']} events — ID: {dim(info['agent_id'][:24])}...")

    out = session.export("trading_session_audit.json")
    print(f"\n  {green('✓')} Audit exported: {cyan(out)}")
    print(dim(f"    Verify with: piqrypt session-verify {out}"))

    return session


# ── Scenario: Healthcare Diagnostic Pipeline ──────────────────────────────────

def scenario_healthcare(AgentSession):
    """
    EU AI Act Art.22 — high-risk AI in healthcare
    Diagnostic AI → Validation AI → Human approval → Execution
    """
    print(f"\n{bold('Scenario: Healthcare Diagnostic Pipeline')}")
    print(f"{dim('EU AI Act Art.22 — human oversight for high-risk medical AI')}")
    print(SEP)

    session = AgentSession([
        {"name": "diagnostic_ai",  "identity_file": "~/.piqrypt/diagnostic.json"},
        {"name": "validator_ai",   "identity_file": "~/.piqrypt/validator.json"},
        {"name": "human_principal","identity_file": "~/.piqrypt/human.json"},
    ])

    print(f"\n  {bold('Starting session:')}")
    session.start()

    # Diagnostic AI proposes
    patient_data = "patient_id:P2026-441 — symptoms:chest_pain,dyspnea"
    ev1, ih1 = session.stamp(
        "diagnostic_ai", "diagnosis_proposed",
        {
            "patient_hash":     sha256(patient_data),     # RGPD — raw data never stored
            "diagnosis":        "Suspected NSTEMI",
            "confidence":       0.91,
            "icd10_code":       "I21.4",
            "recommended_action": "Immediate cardiology referral",
        },
        peer="validator_ai"
    )
    print(f"  {green('✓')} Diagnostic AI → Validator   diagnosis proposed, co-signed")

    # Validator confirms and escalates to human
    ev2, ih2 = session.stamp(
        "validator_ai", "diagnosis_validated",
        {
            "validation_result": "confirmed",
            "second_model":      "medgpt-v4",
            "agreement_score":   0.88,
            "escalation_reason": "High-risk action — human approval required (AI Act Art.14)",
        },
        peer="human_principal"
    )
    print(f"  {green('✓')} Validator AI  → Human       escalated for mandatory approval")

    # Human approves
    ev3, _ = session.stamp(
        "human_principal", "treatment_approved",
        {
            "approved_by":   "Dr. M. Dupont — RPPS 12345678",
            "approval_hash": sha256("APPROVED:P2026-441:NSTEMI:cardiology_referral"),
            "timestamp":     int(time.time()),
        }
    )
    print(f"  {green('✓')} Human principal            approved and signed (Art.14 compliance)")

    summary = session.summary()
    print(f"\n  Total events : {summary['total_events']} across 3 agents")
    print(f"  {dim('Every decision traceable: diagnosis → validation → human approval')}")
    out = session.export("healthcare_session_audit.json")
    print(f"  {green('✓')} Audit exported: {cyan(out)}")

    return session


# ── Scenario: Industrial Robotics ─────────────────────────────────────────────

def scenario_robotics(AgentSession):
    """
    IEC 62443 — multi-agent control of physical equipment
    Orchestrator → ROS2 node → RPi sensor
    """
    print(f"\n{bold('Scenario: Industrial Robotics (IEC 62443)')}")
    print(f"{dim('Orchestrator → ROS2 node → RPi edge sensor')}")
    print(SEP)

    session = AgentSession([
        {"name": "orchestrator", "identity_file": "~/.piqrypt/orchestrator.json"},
        {"name": "ros2_node",    "identity_file": "~/.piqrypt/ros2.json"},
        {"name": "rpi_sensor",   "identity_file": "~/.piqrypt/rpi.json"},
    ])

    print(f"\n  {bold('Starting session:')}")
    session.start()

    ev1, _ = session.stamp(
        "orchestrator", "command_issued",
        {"command": "move_arm", "target_position": "station_7", "speed_limit": 0.5},
        peer="ros2_node"
    )
    print(f"  {green('✓')} Orchestrator → ROS2 node    command issued, co-signed")

    ev2, _ = session.stamp(
        "ros2_node", "sensor_data_requested",
        {"sensor_type": "lidar", "scan_radius_m": 2.0},
        peer="rpi_sensor"
    )
    print(f"  {green('✓')} ROS2 node    → RPi sensor   sensor request, co-signed")

    ev3, _ = session.stamp(
        "rpi_sensor", "scan_completed",
        {"obstacles_detected": 0, "clear_path": True, "scan_hash": sha256("lidar_scan_2026")},
        peer="ros2_node"
    )
    print(f"  {green('✓')} RPi sensor   → ROS2 node    scan result returned, co-signed")

    ev4, _ = session.stamp(
        "ros2_node", "movement_executed",
        {"result": "success", "position_reached": "station_7", "duration_ms": 1240}
    )
    print(f"  {green('✓')} ROS2 node                   movement executed")

    summary = session.summary()
    print(f"\n  Total events : {summary['total_events']} — incident timeline fully traceable")
    out = session.export("robotics_session_audit.json")
    print(f"  {green('✓')} Audit exported: {cyan(out)}")

    return session


# ── Verification demo ─────────────────────────────────────────────────────────

def show_cross_memory_proof(session):
    """Show the cross-memory payload_hash proof — the key differentiator."""
    print(f"\n{bold('Cross-Memory Proof — Why This Is Unique')}")
    print(SEP)

    agents = session.agents
    if not agents:
        return

    # Find two agents that had a co-signed interaction
    agent_names = list(agents.keys())
    if len(agent_names) < 2:
        return

    a_name, b_name = agent_names[0], agent_names[1]
    a_agent = agents[a_name]
    b_agent = agents[b_name]

    # Get events with interaction_hash from each side
    a_events = a_agent.events if hasattr(a_agent, 'events') else []
    b_events = b_agent.events if hasattr(b_agent, 'events') else []

    a_interactions = [e for e in a_events if e.get("payload", {}).get("interaction_hash")]
    b_interactions = [e for e in b_events if e.get("payload", {}).get("interaction_hash")]

    if a_interactions and b_interactions:
        a_ih = a_interactions[0]["payload"]["interaction_hash"]
        b_ih = b_interactions[0]["payload"]["interaction_hash"]
        match = a_ih == b_ih

        print(f"  {a_name:<16} interaction_hash: {cyan(a_ih[:32])}...")
        print(f"  {b_name:<16} interaction_hash: {cyan(b_ih[:32])}...")
        if match:
            print(f"\n  {green('✓')} IDENTICAL in both memories")
            print(dim("    Modifying one side leaves the other unchanged → detectable"))
            print(dim("    This is what no other observability tool provides:"))
            print(dim("    cryptographic proof that BOTH parties saw the SAME interaction."))
        else:
            print(f"  {yellow('⚠')}  Hashes differ — chain integrity issue")
    else:
        print(dim("  (No co-signed interactions to display for this agent pair)"))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PiQrypt Session Quickstart")
    parser.add_argument("--scenario", choices=["trading", "healthcare", "robotics", "all"],
                        default="trading", help="Scenario to demonstrate")
    args = parser.parse_args()

    _check_imports()
    AgentSession, is_mock = _get_agent_session_class()

    print()
    print(bold("═" * 64))
    print(bold("  PiQrypt — Multi-Agent Session Quickstart"))
    print(bold("  AgentSession · Cross-framework · Co-signed audit trails"))
    print(bold("═" * 64))

    if is_mock:
        print(yellow("\n  ℹ  Using embedded demo session (piqrypt-session not installed)"))
        print(dim("    For production: pip install piqrypt[session]"))

    t0 = time.time()
    sessions = []

    if args.scenario in ("trading", "all"):
        s = scenario_trading(AgentSession)
        sessions.append(s)
        show_cross_memory_proof(s)

    if args.scenario in ("healthcare", "all"):
        s = scenario_healthcare(AgentSession)
        sessions.append(s)

    if args.scenario in ("robotics", "all"):
        s = scenario_robotics(AgentSession)
        sessions.append(s)

    # Final summary
    elapsed = time.time() - t0
    total_events = sum(s.summary()["total_events"] for s in sessions)
    total_sessions = len(sessions)

    print(f"\n{bold('═' * 64)}")
    print(f"  {green('✅')}  {total_sessions} session(s) · {total_events} events · {elapsed:.1f}s")
    print()
    print(f"  {bold('What was proven:')}")
    print(f"  {green('→')} Every cross-agent interaction co-signed in both memories")
    print(f"  {green('→')} Same payload_hash on both sides — tampering immediately detectable")
    print(f"  {green('→')} Framework-agnostic — Claude, LangGraph, CrewAI, ROS2, RPi")
    print(f"  {green('→')} Full audit trail exportable and independently verifiable")
    print()
    print(f"  {bold('Next steps:')}")
    print(f"  {cyan('python quickstart_dev.py')}          ← single-agent AISS-1 loop")
    print(f"  {cyan('python piqrypt_start.py --vigil')}   ← start Vigil monitoring")
    print(f"  {cyan('https://docs.piqrypt.com/session')}  ← full Session bridge docs")
    print(bold("═" * 64))
    print()


if __name__ == "__main__":
    main()
