# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Apache License, Version 2.0.
# See bridges/LICENSE or cli/LICENSE for full terms.

"""
piqrypt-ollama — PiQrypt bridge for Ollama
==========================================

Adds cryptographic audit trails to Ollama local LLM calls.
Every generate() and chat() call is signed with Ed25519,
hash-chained, and tamper-proof.

Install:
    pip install piqrypt-ollama

Usage:
    from piqrypt_ollama import AuditedOllama, stamp_ollama

    llm = AuditedOllama(
        model="llama3.2",
        identity_file="my_agent.json",
    )

    # generate
    response = llm.generate("What is the capital of France?")
    print(response["response"])

    # chat
    response = llm.chat([
        {"role": "user", "content": "Hello!"}
    ])
    print(response["message"]["content"])

    # streaming
    for chunk in llm.generate("Tell me a story", stream=True):
        print(chunk["response"], end="", flush=True)

    # tool use
    response = llm.chat_with_tools(messages, tools, dispatcher)

    # export audit trail
    llm.export_audit("ollama_audit.json")
"""

__version__ = "1.0.0"
__author__  = "PiQrypt Contributors"
__license__ = "Apache-2.0"

import functools
import hashlib
import json
import time
from typing import Any, Callable, Dict, Generator, List, Optional, Union

try:
    import piqrypt as aiss
except ImportError:
    raise ImportError(
        "piqrypt is required. Install with: pip install piqrypt"
    )

try:
    import ollama
    from ollama import Client as OllamaClient
except ImportError:
    raise ImportError(
        "ollama is required. Install with: pip install ollama>=0.1.0"
    )


# ── Helpers ────────────────────────────────────────────────────────────────────

def _h(value: Any) -> str:
    """SHA-256 of any value. Never stores raw content in the audit chain."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _load_identity(identity_file: str):
    """Load a PiQrypt identity from a .json file."""
    identity = aiss.load_identity(identity_file)
    return identity["private_key_bytes"], identity["agent_id"]


def _resolve_identity(identity_file, private_key, agent_id):
    """Resolve PiQrypt identity — file, explicit keys, or ephemeral."""
    if identity_file:
        return _load_identity(identity_file)
    elif private_key and agent_id:
        return private_key, agent_id
    else:
        pq_priv, pq_pub = aiss.generate_keypair()
        return pq_priv, aiss.derive_agent_id(pq_pub)


# ── AuditedOllama ─────────────────────────────────────────────────────────────

class AuditedOllama:
    """
    Ollama LLM client with PiQrypt cryptographic audit trail.

    Drop-in replacement for ollama.Client — every generate() and chat()
    call is Ed25519-signed, hash-chained, and stored locally.

    Parameters
    ----------
    model : str
        Ollama model name — "llama3.2", "mistral", "phi3", "gemma3", etc.
    identity_file : str, optional
        Path to PiQrypt identity JSON.
        If None, an ephemeral identity is generated (not persisted).
    private_key : bytes, optional
        Explicit Ed25519 private key bytes (alternative to identity_file).
    agent_id : str, optional
        Explicit agent ID (required if private_key is provided).
    agent_name : str, optional
        Human-readable name in audit events. Defaults to model name.
    host : str
        Ollama server URL. Default: http://localhost:11434
    tier : str
        "free" or "pro". Pro enables TSA anchoring.
    stamp_prompts : bool
        Include SHA-256 of prompts in audit events. Default: True.
        Set False for sensitive prompts — responses are still audited.
    stamp_responses : bool
        Include SHA-256 of responses in audit events. Default: True.
    vigil_endpoint : str, optional
        Vigil server URL for live monitoring.
        e.g. "http://localhost:8421"

    Examples
    --------
    >>> llm = AuditedOllama(model="llama3.2", identity_file="agent.json")
    >>> r = llm.generate("What is 2+2?")
    >>> print(r["response"])

    >>> for chunk in llm.generate("Tell me a story", stream=True):
    ...     print(chunk["response"], end="")
    """

    def __init__(
        self,
        model: str = "llama3.2",
        identity_file: Optional[str] = None,
        private_key: Optional[bytes] = None,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        host: str = "http://localhost:11434",
        tier: str = "free",
        stamp_prompts: bool = True,
        stamp_responses: bool = True,
        vigil_endpoint: Optional[str] = None,
    ):
        self.model           = model
        self.agent_name      = agent_name or model.replace(":", "_")
        self.tier            = tier
        self.stamp_prompts   = stamp_prompts
        self.stamp_responses = stamp_responses
        self.vigil_endpoint  = vigil_endpoint.rstrip("/") if vigil_endpoint else None
        self._last_hash: Optional[str] = None

        # Identity
        self._pq_key, self._pq_id = _resolve_identity(
            identity_file, private_key, agent_id
        )

        # Ollama client
        self._client = OllamaClient(host=host)

        # Stamp initialization
        self._stamp("agent_initialized", {
            "model":        model,
            "agent_name":   self.agent_name,
            "tier":         tier,
            "host":         host,
            "framework":    "ollama",
            "aiss_profile": "AISS-1",
        })

    # ── Internal stamp ─────────────────────────────────────────────────────────

    def _stamp(self, event_type: str, payload: Dict) -> Dict:
        """Sign, chain and store one audit event."""
        if self._last_hash:
            payload["previous_event_hash"] = self._last_hash

        event = aiss.stamp_event(self._pq_key, self._pq_id, {
            "event_type":   event_type,
            "agent_name":   self.agent_name,
            "aiss_profile": "AISS-1",
            **payload,
        })
        aiss.store_event(event)
        self._last_hash = aiss.compute_event_hash(event)

        if self.vigil_endpoint:
            self._forward_vigil(event)

        return event

    def _forward_vigil(self, event: Dict) -> None:
        """Non-blocking forward to Vigil server. Never raises."""
        try:
            import urllib.request
            body = json.dumps(event, default=str).encode()
            req  = urllib.request.Request(
                f"{self.vigil_endpoint}/api/agent/{self.agent_name}/record",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass

    # ── generate() ─────────────────────────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        *,
        stream: bool = False,
        options: Optional[Dict] = None,
        system: Optional[str] = None,
        template: Optional[str] = None,
        context: Optional[List[int]] = None,
        keep_alive: Optional[Union[str, int]] = None,
        **kwargs,
    ) -> Union[Dict, Generator]:
        """
        Generate a completion — mirrors ollama.generate() exactly.
        Returns raw Ollama response (or generator for stream=True).
        """
        call_kwargs = {
            k: v for k, v in dict(
                model=self.model, prompt=prompt, stream=stream,
                options=options, system=system, template=template,
                context=context, keep_alive=keep_alive, **kwargs
            ).items() if v is not None
        }

        payload: Dict = {
            "model":         self.model,
            "prompt_length": len(prompt),
            "stream":        stream,
        }
        if self.stamp_prompts:
            payload["prompt_hash"] = _h(prompt)
            if system:
                payload["system_hash"] = _h(system)

        self._stamp("ollama_generate_start", payload)
        t0 = time.perf_counter()

        if stream:
            return self._gen_stream(call_kwargs, t0)
        else:
            return self._gen_sync(call_kwargs, t0)

    def _gen_sync(self, kwargs: Dict, t0: float) -> Dict:
        response = self._client.generate(**kwargs)
        elapsed  = time.perf_counter() - t0
        result: Dict = {
            "model":      self.model,
            "elapsed_ms": round(elapsed * 1000, 1),
            "done":       response.get("done", True),
            "total_tokens": (
                response.get("eval_count", 0) +
                response.get("prompt_eval_count", 0)
            ),
        }
        if self.stamp_responses:
            result["response_hash"] = _h(response.get("response", ""))
        self._stamp("ollama_generate_complete", result)
        return response

    def _gen_stream(self, kwargs: Dict, t0: float) -> Generator:
        chunks: List[str] = []
        for chunk in self._client.generate(**kwargs):
            chunks.append(chunk.get("response", ""))
            yield chunk
        elapsed = time.perf_counter() - t0
        result: Dict = {
            "model":       self.model,
            "elapsed_ms":  round(elapsed * 1000, 1),
            "streamed":    True,
            "chunk_count": len(chunks),
        }
        if self.stamp_responses:
            result["response_hash"] = _h("".join(chunks))
        self._stamp("ollama_generate_stream_complete", result)

    # ── chat() ─────────────────────────────────────────────────────────────────

    def chat(
        self,
        messages: List[Dict[str, str]],
        *,
        stream: bool = False,
        tools: Optional[List[Dict]] = None,
        options: Optional[Dict] = None,
        keep_alive: Optional[Union[str, int]] = None,
        **kwargs,
    ) -> Union[Dict, Generator]:
        """
        Chat completion — mirrors ollama.chat() exactly.
        Every turn is signed and chained.
        """
        call_kwargs = {
            k: v for k, v in dict(
                model=self.model, messages=messages, stream=stream,
                tools=tools, options=options, keep_alive=keep_alive,
                **kwargs
            ).items() if v is not None
        }

        payload: Dict = {
            "model":         self.model,
            "message_count": len(messages),
            "stream":        stream,
            "last_role":     messages[-1].get("role", "user") if messages else "user",
        }
        if self.stamp_prompts:
            payload["messages_hash"] = _h(json.dumps(messages, default=str))

        self._stamp("ollama_chat_start", payload)
        t0 = time.perf_counter()

        if stream:
            return self._chat_stream(call_kwargs, t0)
        else:
            return self._chat_sync(call_kwargs, t0)

    def _chat_sync(self, kwargs: Dict, t0: float) -> Dict:
        response = self._client.chat(**kwargs)
        elapsed  = time.perf_counter() - t0
        result: Dict = {
            "model":      self.model,
            "elapsed_ms": round(elapsed * 1000, 1),
            "role":       response.get("message", {}).get("role", "assistant"),
        }
        if self.stamp_responses:
            content = response.get("message", {}).get("content", "")
            result["response_hash"] = _h(content)
        self._stamp("ollama_chat_complete", result)
        return response

    def _chat_stream(self, kwargs: Dict, t0: float) -> Generator:
        chunks: List[str] = []
        for chunk in self._client.chat(**kwargs):
            chunks.append(chunk.get("message", {}).get("content", ""))
            yield chunk
        elapsed = time.perf_counter() - t0
        result: Dict = {
            "model":       self.model,
            "elapsed_ms":  round(elapsed * 1000, 1),
            "streamed":    True,
            "chunk_count": len(chunks),
        }
        if self.stamp_responses:
            result["response_hash"] = _h("".join(chunks))
        self._stamp("ollama_chat_stream_complete", result)

    # ── chat_with_tools() ──────────────────────────────────────────────────────

    def chat_with_tools(
        self,
        messages: List[Dict],
        tools: List[Dict],
        tool_dispatcher: Optional[Callable[[str, Dict], str]] = None,
        max_rounds: int = 10,
    ) -> Dict:
        """
        Multi-turn tool use loop — each tool call and result is stamped.

        Parameters
        ----------
        messages : list
            Initial message list.
        tools : list
            Ollama tool definitions.
        tool_dispatcher : callable(name, args) -> str, optional
            Executes tool calls. If None, calls are stamped but not run.
        max_rounds : int
            Maximum tool call iterations before stopping.

        Returns
        -------
        dict : final Ollama response
        """
        rounds = 0
        history = list(messages)

        while rounds < max_rounds:
            response = self._client.chat(
                model=self.model,
                messages=history,
                tools=tools,
            )
            rounds += 1
            tool_calls = response.get("message", {}).get("tool_calls") or []

            if not tool_calls:
                # Final answer — stamp and return
                final: Dict = {"model": self.model, "rounds": rounds}
                if self.stamp_responses:
                    content = response.get("message", {}).get("content", "")
                    final["response_hash"] = _h(content)
                self._stamp("ollama_tool_final_answer", final)
                return response

            # Stamp each tool call
            history.append(response["message"])
            for tc in tool_calls:
                fn   = tc.get("function", {})
                name = fn.get("name", "unknown")
                args = fn.get("arguments", {})
                self._stamp("ollama_tool_call", {
                    "tool_name": name,
                    "args_hash": _h(args),
                    "round":     rounds,
                })

                # Execute and stamp result
                if tool_dispatcher:
                    try:
                        result = str(tool_dispatcher(name, args))
                    except Exception as exc:
                        result = f"Error: {exc}"
                    self._stamp("ollama_tool_result", {
                        "tool_name":   name,
                        "result_hash": _h(result),
                        "round":       rounds,
                    })
                    history.append({"role": "tool", "content": result})

        return response

    # ── Convenience ────────────────────────────────────────────────────────────

    def stamp_event(self, event_type: str, payload: Optional[Dict] = None) -> Dict:
        """Stamp an arbitrary custom event into the audit chain."""
        return self._stamp(event_type, payload or {})

    def export_audit(self, output_path: str = "ollama_audit.json") -> str:
        """Export this agent's full audit trail to JSON."""
        aiss.export_audit_chain(output_path)
        return output_path

    @property
    def piqrypt_id(self) -> str:
        """This agent's PiQrypt identity (agent_id)."""
        return self._pq_id

    @property
    def last_event_hash(self) -> Optional[str]:
        """Hash of the last stamped event — chain tip."""
        return self._last_hash

    def __repr__(self) -> str:
        return (
            f"AuditedOllama("
            f"model={self.model!r}, "
            f"agent={self.agent_name!r}, "
            f"tier={self.tier!r}, "
            f"id={self._pq_id[:12]}…)"
        )


# ── stamp_ollama decorator ─────────────────────────────────────────────────────

def stamp_ollama(
    task_name: str,
    identity_file: Optional[str] = None,
    private_key: Optional[bytes] = None,
    agent_id: Optional[str] = None,
):
    """
    Decorator — stamp any function that wraps Ollama with PiQrypt proof.

    Usage:
        @stamp_ollama("summarize", identity_file="agent.json")
        def summarize(text: str) -> str:
            r = ollama.generate(model="llama3.2", prompt=f"Summarize: {text}")
            return r["response"]
    """
    def decorator(func: Callable) -> Callable:
        _key, _id = _resolve_identity(identity_file, private_key, agent_id)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_event = aiss.stamp_event(_key, _id, {
                "event_type":   f"{task_name}_start",
                "args_hash":    _h(args),
                "kwargs_hash":  _h(kwargs),
                "aiss_profile": "AISS-1",
            })
            aiss.store_event(start_event)

            result = func(*args, **kwargs)

            aiss.store_event(aiss.stamp_event(_key, _id, {
                "event_type":          f"{task_name}_complete",
                "result_hash":         _h(result),
                "previous_event_hash": aiss.compute_event_hash(start_event),
                "aiss_profile":        "AISS-1",
            }))
            return result

        return wrapper
    return decorator


# ── Module-level export helper ─────────────────────────────────────────────────

def export_audit(output_path: str = "ollama_audit.json") -> str:
    """Export full audit trail for all Ollama events in this session."""
    aiss.export_audit_chain(output_path)
    return output_path


# ── Public API ─────────────────────────────────────────────────────────────────

__all__ = [
    "AuditedOllama",
    "stamp_ollama",
    "export_audit",
]
