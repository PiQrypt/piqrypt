# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
conftest.py - bridges/
Mock piqrypt + frameworks externes AVANT collection pytest.
"""
import hashlib
import json
import sys
import time
import types
from pathlib import Path
from unittest.mock import MagicMock

# 1. Mock piqrypt
events = []
mock_pq = types.ModuleType("piqrypt")
mock_pq.generate_keypair   = lambda: (b"priv" * 8, b"pub" * 8)
mock_pq.derive_agent_id    = lambda pub: "AGENT_" + hashlib.sha256(pub).hexdigest()[:12]
mock_pq.load_identity      = lambda f: {"private_key_bytes": b"key" * 8, "agent_id": "AGENT_TEST"}
mock_pq.stamp_event        = lambda key, aid, payload: {**payload, "_pq_agent_id": aid, "_pq_timestamp": time.time(), "_pq_sig": "mocksig"}
mock_pq.store_event        = lambda e: events.append(e)
mock_pq.compute_event_hash = lambda e: hashlib.sha256(json.dumps(e, default=str).encode()).hexdigest()
mock_pq.export_audit_chain = lambda path: open(path, "w").write(json.dumps(events))
mock_pq._events            = events
sys.modules["piqrypt"]     = mock_pq

# 2. Mock langchain
lc_mod       = types.ModuleType("langchain")
lc_agents    = types.ModuleType("langchain.agents")
lc_tools     = types.ModuleType("langchain.tools")
lc_callbacks = types.ModuleType("langchain.callbacks.base")
lc_schema    = types.ModuleType("langchain.schema")

class BaseCallbackHandler:
    def on_llm_start(self, *a, **kw): pass
    def on_llm_end(self, *a, **kw): pass
    def on_llm_error(self, *a, **kw): pass
    def on_chain_start(self, *a, **kw): pass
    def on_chain_end(self, *a, **kw): pass
    def on_chain_error(self, *a, **kw): pass
    def on_tool_start(self, *a, **kw): pass
    def on_tool_end(self, *a, **kw): pass
    def on_tool_error(self, *a, **kw): pass
    def on_agent_action(self, *a, **kw): pass
    def on_agent_finish(self, *a, **kw): pass

class AgentExecutor:
    def __init__(self, **kwargs): self.callbacks = kwargs.get("callbacks", [])
    def invoke(self, input, **kw): return {"output": "mock result"}
    def run(self, input, **kw): return "mock result"

class BaseTool:
    name = "mock_tool"
    description = "mock"
    def _run(self, *a, **kw): return "tool result"
    def run(self, *a, **kw): return "tool result"

class LLMResult:
    def __init__(self, generations=None):
        self.generations = generations or [[MagicMock(text="mock response")]]

lc_callbacks.BaseCallbackHandler = BaseCallbackHandler
lc_agents.AgentExecutor          = AgentExecutor
lc_tools.BaseTool                = BaseTool
lc_schema.LLMResult              = LLMResult
lc_mod.agents                    = lc_agents
sys.modules["langchain"]                = lc_mod
sys.modules["langchain.agents"]         = lc_agents
sys.modules["langchain.tools"]          = lc_tools
sys.modules["langchain.callbacks"]      = types.ModuleType("langchain.callbacks")
sys.modules["langchain.callbacks.base"] = lc_callbacks
sys.modules["langchain.schema"]         = lc_schema

# 3. Mock autogen
autogen_mod = types.ModuleType("autogen")

class ConversableAgent:
    def __init__(self, **kwargs):
        self.name = kwargs.get("name", "agent")
        self.llm_config = kwargs.get("llm_config", {})
        self.system_message = kwargs.get("system_message", "")
        self._reply_func_list = []
    def generate_reply(self, messages=None, sender=None, **kwargs): return "Mock reply"
    def initiate_chat(self, recipient, message="", **kwargs):
        return MagicMock(
            summary="Chat completed",
            chat_history=[
                {"role": "user", "content": message},
                {"role": "assistant", "content": "Mock response"},
            ],
        )
    def register_reply(self, *args, **kwargs): pass

class AssistantAgent(ConversableAgent):
    pass

class UserProxyAgent(ConversableAgent):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.human_input_mode = kwargs.get("human_input_mode", "TERMINATE")
        self.code_execution_config = kwargs.get("code_execution_config", False)
    def execute_code_blocks(self, code_blocks, **kwargs): return 0, "mock output"

autogen_mod.ConversableAgent = ConversableAgent
autogen_mod.AssistantAgent   = AssistantAgent
autogen_mod.UserProxyAgent   = UserProxyAgent
sys.modules["autogen"]   = autogen_mod
sys.modules["pyautogen"] = autogen_mod

# 4. Mock crewai
crewai_mod = types.ModuleType("crewai")

class Task:
    def __init__(self, **kwargs):
        self.description = kwargs.get("description", "")
        self.expected_output = kwargs.get("expected_output", "")
        self.agent = kwargs.get("agent", None)

class CrewAgent:
    model_config = {"arbitrary_types_allowed": True}
    def __init__(self, **kwargs):
        self.role = kwargs.get("role", "")
        self.goal = kwargs.get("goal", "")
        self.backstory = kwargs.get("backstory", "")
        self.llm = kwargs.get("llm", None)
        self.tools = kwargs.get("tools", [])
    def execute_task(self, task, context=None, tools=None): return f"Executed: {task.description}"

class Crew:
    def __init__(self, **kwargs):
        self.agents = kwargs.get("agents", [])
        self.tasks = kwargs.get("tasks", [])
        self.verbose = kwargs.get("verbose", False)
    def kickoff(self, inputs=None): return "Crew result"

crewai_mod.Agent = CrewAgent
crewai_mod.Crew  = Crew
crewai_mod.Task  = Task
sys.modules["crewai"] = crewai_mod

# 5. Mock openclaw
openclaw_mod = types.ModuleType("openclaw")

class ExecutionResult:
    def __init__(self, stdout="ok", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

class OpenClaw:
    def __init__(self, **kwargs): self.config = kwargs
    def execute(self, language, code, **kwargs):
        if "raise" in code:
            raise RuntimeError(f"Execution failed: {code}")
        return ExecutionResult(stdout=f"[{language}] {code[:30]}... executed")
    def run_tool(self, tool_name, **kwargs): return {"tool": tool_name, "result": "mock_result", "success": True}

openclaw_mod.OpenClaw        = OpenClaw
openclaw_mod.ExecutionResult = ExecutionResult
sys.modules["openclaw"]      = openclaw_mod

# 6. Injecter chaque dossier bridge dans sys.path
bridges_root = Path(__file__).parent
for bridge_dir in sorted(bridges_root.iterdir()):
    if bridge_dir.is_dir() and (bridge_dir / "__init__.py").exists():
        sys.path.insert(0, str(bridge_dir))

# 7. Mock ollama
ollama_mod = types.ModuleType("ollama")
class Client:
    def __init__(self, **kwargs): self.config = kwargs
    def generate(self, model, prompt, **kwargs): return {"response": "mock response"}
    def chat(self, model, messages, **kwargs): return {"message": {"content": "mock"}}
    def embeddings(self, model, prompt, **kwargs): return {"embedding": [0.1, 0.2]}
ollama_mod.Client = Client
sys.modules["ollama"] = ollama_mod

# 8. Mock rclpy (ROS2 - unavailable on Windows)
rclpy_mod = types.ModuleType("rclpy")
rclpy_mod.init = lambda *a, **kw: None
rclpy_mod.shutdown = lambda *a, **kw: None
rclpy_node = types.ModuleType("rclpy.node")
class Node:
    def __init__(self, *a, **kw): pass
    def create_publisher(self, *a, **kw): return MagicMock()
    def create_subscription(self, *a, **kw): return MagicMock()
    def destroy_node(self): pass
rclpy_node.Node = Node
rclpy_mod.node = rclpy_node
sys.modules["rclpy"] = rclpy_mod
sys.modules["rclpy.node"] = rclpy_node
sys.modules["std_msgs"] = types.ModuleType("std_msgs")
sys.modules["std_msgs.msg"] = types.ModuleType("std_msgs.msg")
sys.modules["RPi"] = types.ModuleType("RPi")
sys.modules["RPi.GPIO"] = types.ModuleType("RPi.GPIO")
