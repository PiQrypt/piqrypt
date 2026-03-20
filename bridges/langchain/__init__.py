# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-langchain — PiQrypt bridge for LangChain

Adds Verifiable AI Agent Memory to LangChain agents, tools, and chains.
Every tool call, chain execution, and agent action is signed,
hash-chained, and tamper-proof.

Install:
    pip install piqrypt-langchain

Usage:
    from piqrypt_langchain import AuditedAgentExecutor, piqrypt_tool, stamp_chain
"""

__version__ = "1.0.0"
__author__ = "PiQrypt Contributors"
__license__ = "Apache-2.0"

import hashlib
import functools
from typing import Any, Dict, Optional

try:
    import piqrypt as aiss
except ImportError:
    raise ImportError(
        "piqrypt is required. Install with: pip install piqrypt"
    )

try:
    from langchain.agents import AgentExecutor
    from langchain.callbacks.base import BaseCallbackHandler
    from langchain.schema import LLMResult
except ImportError:
    raise ImportError(
        "langchain is required. Install with: pip install langchain"
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _h(value: Any) -> str:
    """SHA-256 hash of any value. Never stores raw content."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _load_identity(identity_file: str):
    """Load PiQrypt identity from file."""
    identity = aiss.load_identity(identity_file)
    return identity["private_key_bytes"], identity["agent_id"]


def _resolve_identity(identity_file, private_key, agent_id):
    """Resolve PiQrypt identity from file or explicit keys."""
    if identity_file:
        return _load_identity(identity_file)
    elif private_key and agent_id:
        return private_key, agent_id
    else:
        pq_priv, pq_pub = aiss.generate_keypair()
        return pq_priv, aiss.derive_agent_id(pq_pub)


# ─── PiQryptCallbackHandler ───────────────────────────────────────────────────

class PiQryptCallbackHandler(BaseCallbackHandler):
    """
    LangChain callback handler that stamps every LLM call,
    tool call, and chain event with PiQrypt cryptographic proof.

    This is the most powerful integration — attach once to any
    LangChain component and every event is automatically stamped.

    Usage:
        from piqrypt_langchain import PiQryptCallbackHandler

        handler = PiQryptCallbackHandler(identity_file="my-agent.json")

        # Attach to any LangChain component
        llm = ChatOpenAI(callbacks=[handler])
        agent = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])
        chain = MyChain(callbacks=[handler])
    """

    def __init__(
        self,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
    ):
        super().__init__()
        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )

        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "callback_handler_initialized",
            "framework": "langchain",
            "aiss_profile": "AISS-1",
        }))

    def on_llm_end(self, response: LLMResult, **kwargs) -> None:
        """Stamp every LLM response."""
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "llm_response",
            "response_hash": _h(response),
            "generation_count": len(response.generations),
            "aiss_profile": "AISS-1",
        }))

    def on_tool_start(self, serialized: Dict, input_str: str, **kwargs) -> None:
        """Stamp every tool call start."""
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "tool_start",
            "tool_name": serialized.get("name", "unknown"),
            "input_hash": _h(input_str),
            "aiss_profile": "AISS-1",
        }))

    def on_tool_end(self, output: str, **kwargs) -> None:
        """Stamp every tool call result."""
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "tool_end",
            "output_hash": _h(output),
            "aiss_profile": "AISS-1",
        }))

    def on_tool_error(self, error: Exception, **kwargs) -> None:
        """Stamp tool errors — important for audit."""
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "tool_error",
            "error_hash": _h(str(error)),
            "aiss_profile": "AISS-1",
        }))

    def on_chain_start(self, serialized: Dict, inputs: Dict, **kwargs) -> None:
        """Stamp chain start."""
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "chain_start",
            "chain_name": serialized.get("name", "unknown"),
            "inputs_hash": _h(inputs),
            "aiss_profile": "AISS-1",
        }))

    def on_chain_end(self, outputs: Dict, **kwargs) -> None:
        """Stamp chain completion."""
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "chain_end",
            "outputs_hash": _h(outputs),
            "aiss_profile": "AISS-1",
        }))

    def on_agent_action(self, action, **kwargs) -> None:
        """Stamp every agent action decision."""
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "agent_action",
            "tool": action.tool,
            "tool_input_hash": _h(action.tool_input),
            "log_hash": _h(action.log),
            "aiss_profile": "AISS-1",
        }))

    def on_agent_finish(self, finish, **kwargs) -> None:
        """Stamp agent completion."""
        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "agent_finish",
            "output_hash": _h(finish.return_values),
            "aiss_profile": "AISS-1",
        }))

    @property
    def piqrypt_id(self) -> str:
        return self._pq_id

    def export_audit(self, output_path: str = "langchain-audit.json") -> str:
        aiss.export_audit_chain(output_path)
        return output_path


# ─── AuditedAgentExecutor ─────────────────────────────────────────────────────

class AuditedAgentExecutor(AgentExecutor):
    """
    LangChain AgentExecutor with PiQrypt audit trail.

    Drop-in replacement for AgentExecutor.
    Stamps every invoke with input and output hashes.

    Usage:
        executor = AuditedAgentExecutor(
            agent=your_agent,
            tools=your_tools,
            identity_file="my-agent.json"
        )
        result = executor.invoke({"input": "Analyze this document"})
    """

    model_config = {"arbitrary_types_allowed": True}

    def __init__(
        self,
        *args,
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )

    def invoke(self, input: Dict, **kwargs) -> Dict:
        """Invoke agent and stamp input + output."""

        start_event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "executor_invoke",
            "input_hash": _h(input),
            "aiss_profile": "AISS-1",
        })
        aiss.store_event(start_event)

        result = super().invoke(input, **kwargs)

        aiss.store_event(aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type": "executor_complete",
            "output_hash": _h(result),
            "previous_event_hash": aiss.compute_event_hash(start_event),
            "aiss_profile": "AISS-1",
        }))

        return result

    def export_audit(self, output_path: str = "langchain-audit.json") -> str:
        aiss.export_audit_chain(output_path)
        return output_path

    @property
    def piqrypt_id(self) -> str:
        return self._pq_id


# ─── piqrypt_tool decorator ───────────────────────────────────────────────────

def piqrypt_tool(
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
):
    """
    Decorator: wrap any LangChain tool function with PiQrypt proof.

    Usage:
        from langchain.tools import tool
        from piqrypt_langchain import piqrypt_tool

        @tool
        @piqrypt_tool(identity_file="my-agent.json")
        def search_web(query: str) -> str:
            \"\"\"Search the web.\"\"\"
            return your_search_logic(query)

        @tool
        @piqrypt_tool(identity_file="my-agent.json")
        def send_email(content: str) -> str:
            \"\"\"Send an email.\"\"\"
            return your_email_logic(content)
    """
    def decorator(func):
        _key, _id = _resolve_identity(identity_file, private_key, agent_id)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            aiss.store_event(aiss.stamp_event(_key, _id, {
                "event_type": "tool_executed",
                "tool": func.__name__,
                "args_hash": _h(args),
                "kwargs_hash": _h(kwargs),
                "result_hash": _h(result),
                "aiss_profile": "AISS-1",
            }))

            return result
        return wrapper
    return decorator


# ─── stamp_chain decorator ────────────────────────────────────────────────────

def stamp_chain(
    chain_name: str,
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
):
    """
    Decorator: stamp any chain invocation with PiQrypt proof.

    Usage:
        from piqrypt_langchain import stamp_chain

        @stamp_chain("document_analysis", identity_file="my-agent.json")
        def analyze_document(doc: str) -> dict:
            return your_chain.invoke({"input": doc})
    """
    def decorator(func):
        _key, _id = _resolve_identity(identity_file, private_key, agent_id)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            aiss.store_event(aiss.stamp_event(_key, _id, {
                "event_type": "chain_executed",
                "chain": chain_name,
                "args_hash": _h(args),
                "result_hash": _h(result),
                "aiss_profile": "AISS-1",
            }))

            return result
        return wrapper
    return decorator


# ─── Convenience export ───────────────────────────────────────────────────────

def export_audit(output_path: str = "langchain-audit.json") -> str:
    """Export full audit trail for this session."""
    aiss.export_audit_chain(output_path)
    return output_path


__all__ = [
    "PiQryptCallbackHandler",
    "AuditedAgentExecutor",
    "piqrypt_tool",
    "stamp_chain",
    "export_audit",
]
