"""Google Gemini provider using the google-genai SDK.

Gemini does not speak the OpenAI protocol natively, so it stays a first-class
provider rather than an ``openai_compatible`` base_url. It has no tool loop in
this codebase -- ``generate_with_tools`` is absent, and the shared tool runtime
falls back to plain generation for it.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

GEMINI_MODELS: List[str] = [
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-pro",
    "gemini-1.5-flash",
]

_DEFAULT_MODEL = "gemini-2.0-flash"

_SYSTEM = (
    "You are a security expert specializing in penetration testing "
    "and vulnerability research."
)

THINKING_BUDGETS = ("low", "high")


class GeminiProvider:
    """Google Gemini provider."""

    name = "gemini"

    def __init__(self, config: Dict):
        self.config = config or {}
        self.api_key = (self.config.get("api_key") or "").strip()
        self.model = self.config.get("model") or _DEFAULT_MODEL
        self.temperature = float(self.config.get("temperature", 0.7))
        self.max_tokens = int(self.config.get("max_tokens", 2000) or 2000)
        self.timeout = float(self.config.get("timeout", 60) or 60)

        budget = self.config.get("thinking_budget")
        if budget is not None:
            budget = str(budget).strip().lower()
            if budget not in THINKING_BUDGETS:
                raise ValueError(
                    f"thinking_budget must be one of {THINKING_BUDGETS}, got {budget!r}"
                )
        self.thinking_budget = budget or None

        if (
            not self.api_key
            or self.api_key.startswith("your-")
            or self.api_key.startswith("sk-your-")
        ):
            raise ValueError(
                "Gemini API key not provided or still a placeholder "
                "(set ai_providers.gemini.api_key)"
            )

        try:
            from google import genai
        except ImportError as e:
            raise RuntimeError(
                "the 'google-genai' package is required: pip install google-genai"
            ) from e

        self.client = genai.Client(api_key=self.api_key)

    def list_models(self) -> List[str]:
        known = list(GEMINI_MODELS)
        try:
            names = []
            for model in self.client.models.list():
                name = getattr(model, "name", None) or ""
                if "gemini" in name:
                    names.append(name.split("/")[-1])
            if names:
                return list(dict.fromkeys(names + known))
        except Exception as e:
            logger.debug(f"Gemini models.list failed: {e}")
        return known

    def _build_config(self, model: str, **kwargs) -> Dict[str, Any]:
        from google.genai import types

        config: Dict[str, Any] = {
            "temperature": kwargs.get("temperature", self.temperature),
            "max_output_tokens": int(
                kwargs.get("max_tokens", self.max_tokens) or self.max_tokens
            ),
            "system_instruction": kwargs.get("system") or _SYSTEM,
        }

        budget = kwargs.get("thinking_budget", self.thinking_budget)
        if budget:
            config["thinking_config"] = types.ThinkingConfig(
                thinking_budget=budget
            )
        return config

    def generate(self, prompt: str, **kwargs) -> str:
        model = kwargs.get("model") or self.model

        try:
            generation_config = self._build_config(model, **kwargs)
            response = self.client.models.generate_content(
                model=model,
                contents=prompt,
                config=generation_config,
            )
            return self._extract_text(response)
        except Exception as e:
            if "thinking" in str(e).lower() and "thinking_config" in locals().get(
                "generation_config", {}
            ):
                generation_config.pop("thinking_config", None)
                response = self.client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=generation_config,
                )
                return self._extract_text(response)
            logger.error(f"Gemini generation error: {e}")
            raise

    @staticmethod
    def _extract_text(response) -> str:
        text = getattr(response, "text", None)
        if text:
            return str(text).strip()

        chunks: List[str] = []
        for candidate in getattr(response, "candidates", None) or []:
            content = getattr(candidate, "content", None)
            for part in getattr(content, "parts", None) or []:
                part_text = getattr(part, "text", None)
                if part_text:
                    chunks.append(str(part_text))
        return "".join(chunks).strip()
