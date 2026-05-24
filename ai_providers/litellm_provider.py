"""
LiteLLM Provider

Routes to 100+ LLM providers (OpenAI, Anthropic, Google, Azure, Bedrock,
Ollama, etc.) via the litellm SDK. No proxy server needed.

Model strings use the provider/model format, e.g.
anthropic/claude-sonnet-4-20250514, azure/gpt-4o, openai/gpt-4o.

See https://docs.litellm.ai/docs/providers for all supported models.
"""

from typing import Dict

import litellm

from utils.logger import get_logger

logger = get_logger(__name__)


class LiteLLMProvider:
    """LiteLLM API provider for 100+ LLM providers."""

    def __init__(self, config: Dict):
        """Initialize LiteLLM provider."""
        self.config = config
        self.api_key = config.get("api_key")
        self.model = config.get("model", "openai/gpt-4o")
        self.temperature = config.get("temperature", 0.7)
        self.max_tokens = config.get("max_tokens", 2000)

    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response using LiteLLM.

        Args:
            prompt: Input prompt
            **kwargs: Additional arguments

        Returns:
            Generated response
        """
        try:
            params = {
                "model": kwargs.get("model", self.model),
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security expert specializing in penetration testing and vulnerability research.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": kwargs.get("temperature", self.temperature),
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
                "drop_params": True,
            }

            if self.api_key:
                params["api_key"] = self.api_key

            response = litellm.completion(**params)

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"LiteLLM generation error: {e}")
            raise
