"""Anthropic Claude Messages API provider (current Claude models + tools)."""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

CLAUDE_MODELS: List[str] = [
    "claude-sonnet-4-20250514",
    "claude-sonnet-4-0",
    "claude-3-7-sonnet-20250219",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-3-opus-20240229",
    "claude-3-haiku-20240307",
]

_DEFAULT_MODEL = "claude-sonnet-4-20250514"

_SYSTEM = (
    "You are a security expert specializing in penetration testing "
    "and vulnerability research."
)


class ClaudeProvider:
    def __init__(self, config: Dict):
        self.config = config or {}
        self.api_key = (self.config.get("api_key") or "").strip()
        self.model = self.config.get("model") or _DEFAULT_MODEL
        self.temperature = float(self.config.get("temperature", 0.7))
        self.max_tokens = int(self.config.get("max_tokens", 2000) or 2000)
        self.timeout = float(self.config.get("timeout", 60) or 60)
        self.base_url = (self.config.get("base_url") or "").strip() or None
        self.thinking_budget = int(self.config.get("thinking_budget_tokens", 0) or 0)

        if (
            not self.api_key
            or self.api_key.startswith("your-")
            or self.api_key.startswith("sk-ant-your")
        ):
            raise ValueError(
                "Claude/Anthropic API key not provided or still a placeholder"
            )

        from anthropic import Anthropic

        client_kwargs = {"api_key": self.api_key, "timeout": self.timeout}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        self.client = Anthropic(**client_kwargs)

    def list_models(self) -> List[str]:
        known = list(CLAUDE_MODELS)
        try:
            page = self.client.models.list()
            ids = []
            for m in getattr(page, "data", None) or []:
                mid = getattr(m, "id", None)
                if mid and "claude" in mid:
                    ids.append(mid)
            if ids:
                return list(dict.fromkeys(ids + known))
        except Exception as e:
            logger.debug(f"Anthropic models.list failed: {e}")
        return known

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
        temperature = kwargs.get("temperature", self.temperature)
        max_tokens = int(kwargs.get("max_tokens", self.max_tokens) or self.max_tokens)
        system = kwargs.get("system") or _SYSTEM

        budget = int(kwargs.get("thinking_budget_tokens", self.thinking_budget) or 0)
        request: Dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        if budget > 0:
            request["thinking"] = {"type": "enabled", "budget_tokens": budget}
            request["temperature"] = 1
        else:
            request["temperature"] = temperature

        try:
            response = self.client.messages.create(**request)
            return _extract_claude_text(response)
        except Exception as e:
            if "temperature" in str(e).lower() and "temperature" in request:
                request.pop("temperature")
                response = self.client.messages.create(**request)
                return _extract_claude_text(response)
            logger.error(f"Claude generation error: {e}")
            raise

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
        temperature = kwargs.get("temperature", self.temperature)
        max_tokens = int(kwargs.get("max_tokens", self.max_tokens) or self.max_tokens)
        system = system or _SYSTEM
        specs = normalize_tools(tools)
        anth_tools = [s.to_anthropic() for s in specs]

        if messages is None:
            messages = [{"role": "user", "content": prompt}]
        else:
            messages = list(messages)

        if tool_results:
            # Anthropic: user message with tool_result blocks
            blocks = []
            for tr in tool_results:
                blocks.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tr.get("id") or "",
                        "content": tr.get("content") or "",
                    }
                )
            messages.append({"role": "user", "content": blocks})

        create_kwargs = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
            "tools": anth_tools,
        }
        try:
            create_kwargs["temperature"] = temperature
            response = self.client.messages.create(**create_kwargs)
        except Exception as e:
            if "temperature" in str(e).lower():
                create_kwargs.pop("temperature", None)
                response = self.client.messages.create(**create_kwargs)
            else:
                logger.error(f"Claude tool call error: {e}")
                raise

        text_parts: List[str] = []
        tool_calls: List[ToolCall] = []
        assistant_content: List[Dict] = []

        for block in getattr(response, "content", None) or []:
            btype = getattr(block, "type", None) or (
                block.get("type") if isinstance(block, dict) else None
            )
            if btype == "text":
                t = getattr(block, "text", None)
                if t is None and isinstance(block, dict):
                    t = block.get("text")
                if t:
                    text_parts.append(str(t))
                    assistant_content.append({"type": "text", "text": str(t)})
            elif btype == "tool_use":
                tc_id = getattr(block, "id", None) or str(uuid.uuid4())
                name = getattr(block, "name", None) or ""
                inp = getattr(block, "input", None)
                if isinstance(block, dict):
                    tc_id = block.get("id") or tc_id
                    name = block.get("name") or name
                    inp = block.get("input")
                args = parse_json_args(inp if inp is not None else {})
                tool_calls.append(ToolCall(id=tc_id, name=name, arguments=args))
                assistant_content.append(
                    {
                        "type": "tool_use",
                        "id": tc_id,
                        "name": name,
                        "input": args,
                    }
                )

        if assistant_content:
            messages.append({"role": "assistant", "content": assistant_content})

        stop = getattr(response, "stop_reason", "") or ""
        result = ToolRoundResult(
            text="".join(text_parts).strip(),
            tool_calls=tool_calls,
            raw={"messages": messages, "response": response},
            finish_reason=str(stop),
        )
        result.messages = messages  # type: ignore[attr-defined]
        return result


def _extract_claude_text(response) -> str:
    blocks = getattr(response, "content", None) or []
    parts = []
    for block in blocks:
        text = getattr(block, "text", None)
        if text is None and isinstance(block, dict):
            text = block.get("text")
        if text:
            parts.append(str(text))
    out = "".join(parts).strip()
    if not out:
        raise RuntimeError("empty Claude response")
    return out
