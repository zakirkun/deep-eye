"""OpenAI-compatible provider supporting both chat-completions and responses APIs.

One provider covers any endpoint that speaks the OpenAI wire format: OpenAI
itself, Azure OpenAI, vLLM, LM Studio, OpenRouter, LiteLLM proxies, and
self-hosted gateways. ``api_mode`` selects the protocol:

* ``chat``      -- ``POST /v1/chat/completions`` (the default, widest support)
* ``responses`` -- ``POST /v1/responses`` (OpenAI's newer API)

The provider must be able to present the same ``generate(prompt, **kwargs) ->
str`` contract the rest of the codebase already depends on, and it must also
expose ``generate_with_tools`` so the shared tool loop keeps working.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

API_MODES = ("chat", "responses")
DEFAULT_MODE = "chat"

_SYSTEM = (
    "You are a security expert specializing in penetration testing "
    "and vulnerability research."
)


def is_reasoning_model(model: str) -> bool:
    m = (model or "").lower().split("/")[-1]
    return (
        m.startswith("o1")
        or m.startswith("o3")
        or m.startswith("o4")
        or m.startswith("gpt-5")
    )


class OpenAICompatibleProvider:
    """Any endpoint speaking the OpenAI protocol, chat or responses API."""

    name = "openai_compatible"

    def __init__(self, config: Dict):
        self.config = config or {}
        self.api_key = (self.config.get("api_key") or "").strip()
        self.model = self.config.get("model") or "gpt-4o"
        self.temperature = float(self.config.get("temperature", 0.7))
        self.max_tokens = int(self.config.get("max_tokens", 2000) or 2000)
        self.base_url = (self.config.get("base_url") or "").strip() or None
        self.timeout = float(self.config.get("timeout", 60) or 60)
        self.organization = (self.config.get("organization") or "").strip() or None

        mode = str(self.config.get("api_mode") or DEFAULT_MODE).strip().lower()
        if mode not in API_MODES:
            raise ValueError(
                f"api_mode must be one of {API_MODES}, got {mode!r}"
            )
        self.api_mode = mode

        self.reasoning_effort = (
            str(self.config.get("reasoning_effort") or "").strip().lower() or None
        )
        if self.reasoning_effort and self.reasoning_effort not in (
            "minimal",
            "low",
            "medium",
            "high",
        ):
            raise ValueError(
                "reasoning_effort must be minimal|low|medium|high, "
                f"got {self.reasoning_effort!r}"
            )

        if (
            not self.api_key
            or self.api_key.startswith("your-")
            or self.api_key.startswith("sk-your-")
        ):
            raise ValueError(
                f"{self.name}: a real api_key is required "
                "(set ai_providers.openai_compatible.api_key)"
            )

        try:
            from openai import OpenAI
        except ImportError as e:
            raise RuntimeError(
                "the 'openai' package is required: pip install openai"
            ) from e

        client_kwargs: Dict[str, Any] = {
            "api_key": self.api_key,
            "timeout": self.timeout,
        }
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        if self.organization:
            client_kwargs["organization"] = self.organization
        self.client = OpenAI(**client_kwargs)

    def _token_kwargs(self, model: str, max_tokens: int) -> Dict[str, Any]:
        """Pick the token parameter this model accepts.

        Reasoning models reject ``max_tokens`` in favour of
        ``max_completion_tokens``; ordinary chat models still accept both.
        """
        if is_reasoning_model(model):
            return {"max_completion_tokens": max_tokens}
        return {"max_tokens": max_tokens}

    def _reasoning_kwargs(self, model: str) -> Dict[str, Any]:
        effort = self.reasoning_effort
        if not effort:
            return {}
        if is_reasoning_model(model) or self.api_mode == "responses":
            return {"reasoning_effort": effort}
        logger.debug(
            f"reasoning_effort ignored for non-reasoning model {model}"
        )
        return {}

    def generate(self, prompt: str, **kwargs) -> str:
        tools = kwargs.pop("tools", None)
        handlers = kwargs.pop("handlers", None)
        if tools and handlers:
            from ai_providers.tool_runtime import run_tool_loop

            return run_tool_loop(
                self,
                prompt,
                tools,
                handlers,
                max_rounds=int(kwargs.pop("max_tool_rounds", 5) or 5),
                **kwargs,
            )

        model = kwargs.get("model") or self.model
        system = kwargs.get("system") or _SYSTEM
        max_tokens = int(kwargs.get("max_tokens", self.max_tokens) or self.max_tokens)
        temperature = kwargs.get("temperature", self.temperature)

        try:
            if self.api_mode == "responses":
                return self._generate_responses(
                    model, prompt, system, max_tokens, temperature
                )
            return self._generate_chat(
                model, prompt, system, max_tokens, temperature
            )
        except Exception as e:
            logger.error(f"{self.name} generation error ({self.api_mode}): {e}")
            raise

    def _generate_chat(
        self,
        model: str,
        prompt: str,
        system: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        payload: Dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            **self._token_kwargs(model, max_tokens),
            **self._reasoning_kwargs(model),
        }
        if not is_reasoning_model(model):
            payload["temperature"] = temperature

        response = self.client.chat.completions.create(**payload)
        choice = response.choices[0]
        msg = getattr(choice, "message", None)
        content = getattr(msg, "content", None) if msg is not None else None
        if content is None and isinstance(choice, dict):
            content = (choice.get("message") or {}).get("content")
        return (content or "").strip() if isinstance(content, str) else str(content or "").strip()

    def _generate_responses(
        self,
        model: str,
        prompt: str,
        system: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        payload: Dict[str, Any] = {
            "model": model,
            "instructions": system,
            "input": prompt,
            "max_output_tokens": max_tokens,
            **self._reasoning_kwargs(model),
        }
        if not is_reasoning_model(model):
            payload["temperature"] = temperature

        response = self.client.responses.create(**payload)
        text = getattr(response, "output_text", None)
        if text:
            return str(text).strip()
        return self._extract_responses_output(response)

    @staticmethod
    def _extract_responses_output(response) -> str:
        chunks: List[str] = []
        for item in getattr(response, "output", None) or []:
            for part in getattr(item, "content", None) or []:
                text = getattr(part, "text", None)
                if text:
                    chunks.append(str(text))
        if chunks:
            return "".join(chunks).strip()
        if isinstance(response, dict):
            for item in response.get("output") or []:
                for part in item.get("content") or []:
                    if part.get("text"):
                        chunks.append(str(part["text"]))
        return "".join(chunks).strip()

    def generate_with_tools(
        self,
        prompt: str,
        tools: List[Any],
        messages: Optional[List[Dict]] = None,
        tool_results: Optional[List[Dict]] = None,
        system: Optional[str] = None,
        **kwargs,
    ):
        from ai_providers.tool_runtime import (
            ToolCall,
            ToolRoundResult,
            normalize_tools,
            parse_json_args,
        )

        model = kwargs.get("model") or self.model

        if self.api_mode == "responses":
            text = self.generate(prompt, system=system, model=model)
            return ToolRoundResult(text=text, finish_reason="stop")

        if is_reasoning_model(model):
            text = self.generate(
                prompt,
                system=system,
                model=model,
                **{k: v for k, v in kwargs.items() if k != "model"},
            )
            return ToolRoundResult(text=text, finish_reason="stop")

        max_tokens = int(kwargs.get("max_tokens", self.max_tokens) or self.max_tokens)
        temperature = kwargs.get("temperature", self.temperature)
        system_text = system or _SYSTEM
        specs = normalize_tools(tools)
        openai_tools = [s.to_openai() for s in specs]

        if messages is None:
            messages = [
                {"role": "system", "content": system_text},
                {"role": "user", "content": prompt},
            ]
        else:
            messages = list(messages)

        if tool_results:
            for tr in tool_results:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tr.get("id") or "",
                        "content": tr.get("content") or "",
                    }
                )

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            **self._token_kwargs(model, max_tokens),
        }
        if openai_tools:
            payload["tools"] = openai_tools
            payload["tool_choice"] = kwargs.get("tool_choice", "auto")

        response = self.client.chat.completions.create(**payload)

        choice = response.choices[0]
        msg = getattr(choice, "message", None)
        finish = str(getattr(choice, "finish_reason", "") or "")
        text = (getattr(msg, "content", None) or "") if msg is not None else ""
        text = text.strip() if isinstance(text, str) else ""

        raw_calls = getattr(msg, "tool_calls", None) if msg is not None else None
        tool_calls: List[ToolCall] = []
        if raw_calls:
            assistant_msg: Dict[str, Any] = {
                "role": "assistant",
                "content": getattr(msg, "content", None),
                "tool_calls": [],
            }
            for tc in raw_calls:
                tc_id = getattr(tc, "id", None) or str(uuid.uuid4())
                fn = getattr(tc, "function", None)
                name = getattr(fn, "name", None) if fn is not None else None
                args_raw = getattr(fn, "arguments", None) if fn is not None else "{}"
                if name is None and isinstance(tc, dict):
                    tc_id = tc.get("id") or tc_id
                    fn = tc.get("function") or {}
                    name = fn.get("name")
                    args_raw = fn.get("arguments")
                args = parse_json_args(args_raw)
                tool_calls.append(
                    ToolCall(id=tc_id, name=name or "", arguments=args)
                )
                assistant_msg["tool_calls"].append(
                    {
                        "id": tc_id,
                        "type": "function",
                        "function": {
                            "name": name or "",
                            "arguments": args_raw
                            if isinstance(args_raw, str)
                            else json.dumps(args),
                        },
                    }
                )
            messages.append(assistant_msg)

        result = ToolRoundResult(
            text=text,
            tool_calls=tool_calls,
            raw={"messages": messages, "response": response},
            finish_reason=finish,
        )
        result.messages = messages  # type: ignore[attr-defined]
        return result
