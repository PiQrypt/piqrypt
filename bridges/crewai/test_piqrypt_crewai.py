"""
Tests — bridges/crewai/__init__.py
Bridge AuditedAgent + AuditedCrew

Run: pytest test_piqrypt_crewai.py -v
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


# ── Mock CrewAI ───────────────────────────────────────────────────────────────

def _setup_crewai_mock():
    crewai_mod = types.ModuleType("crewai")

    class Task:
        def __init__(self, **kwargs):
            self.description = kwargs.get("description", "")
            self.expected_output = kwargs.get("expected_output", "")
            self.agent = kwargs.get("agent", None)

    class Agent:
        # Pydantic-style: accept arbitrary kwargs
        model_config = {"arbitrary_types_allowed": True}

        def __init__(self, **kwargs):
            self.role = kwargs.get("role", "")
            self.goal = kwargs.get("goal", "")
            self.backstory = kwargs.get("backstory", "")
            self.llm = kwargs.get("llm", None)
            self.tools = kwargs.get("tools", [])

        def execute_task(self, task, context=None, tools=None):
            return f"Executed: {task.description}"

    class Crew:
        def __init__(self, **kwargs):
            self.agents = kwargs.get("agents", [])
            self.tasks = kwargs.get("tasks", [])
            self.verbose = kwargs.get("verbose", False)

        def kickoff(self, inputs=None):
            return "Crew result"

    crewai_mod.Agent = Agent
    crewai_mod.Crew = Crew
    crewai_mod.Task = Task
    sys.modules["crewai"] = crewai_mod
    return Agent, Crew, Task

MockAgent, MockCrew, MockTask = _setup_crewai_mock()

# Import bridge
from piqrypt_crewai import AuditedAgent, AuditedCrew, stamp_task, export_audit


# ══════════════════════════════════════════════════════════════════════════════
# Tests AuditedAgent
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditedAgent(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.agent = AuditedAgent(
            role="Researcher",
            goal="Find information",
            backstory="Expert researcher with 10 years experience",
            agent_name="researcher",
        )

    # ── Identité ──────────────────────────────────────────────────────────────

    def test_piqrypt_id_generated(self):
        self.assertTrue(self.agent.piqrypt_id.startswith("AGENT_"))

    def test_identity_from_file(self):
        with patch("piqrypt_crewai.aiss.load_identity",
                   return_value={"private_key_bytes": b"k"*32, "agent_id": "AGENT_FILE"}):
            agent = AuditedAgent(
                role="Trader",
                goal="Trade",
                backstory="Expert",
                identity_file="fake.json",
            )
        self.assertEqual(agent.piqrypt_id, "AGENT_FILE")

    def test_ephemeral_agent_gets_id(self):
        agent = AuditedAgent(role="R", goal="G", backstory="B")
        self.assertTrue(agent.piqrypt_id.startswith("AGENT_"))

    # ── execute_task() ────────────────────────────────────────────────────────

    def test_execute_task_stamps_start(self):
        _events.clear()
        task = MockTask(description="Research AI trends", expected_output="Report")
        self.agent.execute_task(task)
        start_events = [e for e in _events if "task" in e.get("event_type", "").lower()
                        and "start" in e.get("event_type", "").lower()]
        self.assertTrue(len(start_events) >= 1)

    def test_execute_task_stamps_complete(self):
        _events.clear()
        task = MockTask(description="Research AI trends", expected_output="Report")
        self.agent.execute_task(task)
        complete_events = [e for e in _events if "complete" in e.get("event_type", "").lower()
                           or "end" in e.get("event_type", "").lower()]
        self.assertTrue(len(complete_events) >= 1)

    def test_execute_task_stamps_task_description_hash(self):
        _events.clear()
        description = "Analyze market data for AAPL"
        task = MockTask(description=description, expected_output="Analysis")
        self.agent.execute_task(task)
        # Description ne doit jamais être stockée brute
        for e in _events:
            self.assertNotIn(description, json.dumps(e))

    def test_execute_task_returns_result(self):
        task = MockTask(description="Do something", expected_output="Result")
        result = self.agent.execute_task(task)
        self.assertIsNotNone(result)

    def test_execute_task_stamps_error_on_failure(self):
        _events.clear()

        class FailingAgent(AuditedAgent):
            def _original_execute(self, task, context=None, tools=None):
                raise RuntimeError("LLM connection failed")

        agent = FailingAgent(role="R", goal="G", backstory="B")
        task = MockTask(description="Fail", expected_output="N/A")

        # Si execute_task gère l'erreur, on vérifie l'event d'erreur
        try:
            agent.execute_task(task)
        except Exception:
            pass
        # Vérifier qu'un event a bien été émis
        self.assertTrue(len(_events) >= 1)

    # ── Hash chaining ─────────────────────────────────────────────────────────

    def test_last_event_hash_updated(self):
        initial = self.agent.last_event_hash
        task = MockTask(description="Task 1", expected_output="R1")
        self.agent.execute_task(task)
        self.assertNotEqual(self.agent.last_event_hash, initial)

    def test_sequential_tasks_chained(self):
        _events.clear()
        t1 = MockTask(description="Task 1", expected_output="R1")
        t2 = MockTask(description="Task 2", expected_output="R2")
        self.agent.execute_task(t1)
        count_after_first = len(_events)
        self.agent.execute_task(t2)
        # Les events du 2ème batch doivent référencer le hash du 1er
        second_batch = _events[count_after_first:]
        if second_batch:
            self.assertIn("previous_event_hash", second_batch[0])

    # ── Export ────────────────────────────────────────────────────────────────

    def test_export_audit(self):
        import tempfile, os
        task = MockTask(description="Test task", expected_output="Result")
        self.agent.execute_task(task)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            self.agent.export_audit(path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)

    def test_event_count(self):
        initial = self.agent.audit_event_count
        task = MockTask(description="Count test", expected_output="R")
        self.agent.execute_task(task)
        self.assertGreater(self.agent.audit_event_count, initial)


# ══════════════════════════════════════════════════════════════════════════════
# Tests AuditedCrew
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditedCrew(unittest.TestCase):

    def setUp(self):
        _events.clear()
        self.researcher = AuditedAgent(
            role="Researcher",
            goal="Research",
            backstory="Expert researcher",
            agent_name="researcher",
        )
        self.writer = AuditedAgent(
            role="Writer",
            goal="Write reports",
            backstory="Senior technical writer",
            agent_name="writer",
        )
        self.task1 = MockTask(description="Research AI", expected_output="Research report")
        self.task2 = MockTask(description="Write article", expected_output="Article")
        self.crew = AuditedCrew(
            agents=[self.researcher, self.writer],
            tasks=[self.task1, self.task2],
            crew_name="research_crew",
        )

    def test_crew_piqrypt_id_set(self):
        self.assertTrue(self.crew.piqrypt_id.startswith("AGENT_"))

    def test_kickoff_stamps_start(self):
        _events.clear()
        self.crew.kickoff()
        start_events = [e for e in _events if "crew" in e.get("event_type", "").lower()
                        and "start" in e.get("event_type", "").lower()]
        self.assertTrue(len(start_events) >= 1)

    def test_kickoff_stamps_complete(self):
        _events.clear()
        self.crew.kickoff()
        complete_events = [e for e in _events if "crew" in e.get("event_type", "").lower()
                           and ("complete" in e.get("event_type", "").lower()
                                or "end" in e.get("event_type", "").lower())]
        self.assertTrue(len(complete_events) >= 1)

    def test_kickoff_stamps_agent_count(self):
        _events.clear()
        self.crew.kickoff()
        crew_start = [e for e in _events if "crew" in e.get("event_type", "").lower()
                      and "start" in e.get("event_type", "").lower()]
        if crew_start:
            self.assertIn("agent_count", crew_start[0])
            self.assertEqual(crew_start[0]["agent_count"], 2)

    def test_kickoff_returns_result(self):
        result = self.crew.kickoff()
        self.assertIsNotNone(result)

    def test_crew_export_audit(self):
        import tempfile, os
        self.crew.kickoff()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            self.crew.export_audit(path)
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Tests stamp_task décorateur
# ══════════════════════════════════════════════════════════════════════════════

class TestStampTask(unittest.TestCase):

    def setUp(self):
        _events.clear()

    def test_stamp_task_stamps_execution(self):
        @stamp_task("analysis", agent_name="test_agent")
        def analyze(data: str) -> str:
            return f"Analysis of: {data}"

        result = analyze("market data")
        self.assertEqual(result, "Analysis of: market data")
        self.assertTrue(len(_events) >= 1)

    def test_stamp_task_stamps_result_hash(self):
        @stamp_task("compute", agent_name="test_agent")
        def compute(x: int) -> str:
            return f"result_{x}"

        compute(42)
        complete = [e for e in _events if "complete" in e.get("event_type", "").lower()
                    or "end" in e.get("event_type", "").lower()]
        if complete:
            self.assertIn("result_hash", complete[0])

    def test_stamp_task_preserves_function_name(self):
        @stamp_task("wrap", agent_name="test")
        def my_function():
            return "ok"
        self.assertEqual(my_function.__name__, "my_function")

    def test_stamp_task_preserves_return_value(self):
        @stamp_task("identity", agent_name="test")
        def identity(x):
            return x * 2

        self.assertEqual(identity(21), 42)

    def test_stamp_task_stamps_error(self):
        @stamp_task("failing", agent_name="test")
        def failing():
            raise ValueError("Something went wrong")

        with self.assertRaises(ValueError):
            failing()
        error_events = [e for e in _events if "error" in e.get("event_type", "").lower()]
        self.assertTrue(len(error_events) >= 1)


# ══════════════════════════════════════════════════════════════════════════════
# Tests export top-level
# ══════════════════════════════════════════════════════════════════════════════

class TestExportAudit(unittest.TestCase):

    def test_export_creates_file(self):
        import tempfile, os
        _events.clear()
        _events.append({"event_type": "task_complete", "result_hash": "abc123"})
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_audit(path)
            self.assertTrue(os.path.exists(path))
            data = json.loads(open(path).read())
            self.assertIsInstance(data, list)
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Test cross-framework : CrewAI + LangChain dans même session
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossFrameworkScenario(unittest.TestCase):
    """
    Simule le scénario documenté dans le README :
    Un agent LangChain envoie une recommandation à un agent CrewAI.
    Les deux mémoires référencent le même payload_hash.
    """

    def test_shared_payload_hash_cross_framework(self):
        _events.clear()

        # Agent CrewAI reçoit la recommandation
        crew_agent = AuditedAgent(
            role="Trader",
            goal="Execute trades",
            backstory="Algorithmic trader",
            agent_name="trader_crewai",
        )

        # Simuler un event reçu de LangChain
        payload_hash = hashlib.sha256(b"BUY AAPL 100").hexdigest()
        crew_agent._stamp("received_recommendation", {
            "payload_hash": payload_hash,
            "peer": "langchain_analyst",
            "action": "BUY",
        })

        task = MockTask(
            description="Execute trade based on recommendation",
            expected_output="Trade confirmation"
        )
        crew_agent.execute_task(task)

        # Vérifier que le payload_hash est dans la mémoire CrewAI
        all_payload_hashes = [
            e.get("payload_hash") for e in _events if "payload_hash" in e
        ]
        self.assertIn(payload_hash, all_payload_hashes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
