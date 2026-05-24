"""
LM Studio Provider (Local LLM via OpenAI-compatible API)
"""

from typing import Dict
import requests
from utils.logger import get_logger

logger = get_logger(__name__)


class LMStudioProvider:
    """LM Studio local LLM provider using OpenAI-compatible API."""

    def __init__(self, config: Dict):
        """Initialize LM Studio provider."""
        self.config = config
        self.base_url = config.get("base_url", "http://127.0.0.1:1234")
        self.model = config.get("model", "local-model")
        self.temperature = config.get("temperature", 0.7)
        self.timeout = config.get("timeout", 60)

    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response using LM Studio.

        Args:
            prompt: Input prompt
            **kwargs: Additional arguments

        Returns:
            Generated response
        """
        try:
            url = f"{self.base_url}/v1/chat/completions"

            payload = {
                "model": kwargs.get("model", self.model),
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security expert. Provide concise, actionable advice."
                    },
                    {"role": "user", "content": prompt}
                ],
                "temperature": kwargs.get("temperature", self.temperature),
                "stream": False
            }

            response = requests.post(
                url,
                json=payload,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "")
            else:
                raise Exception(f"LM Studio API error: {response.status_code} - {response.text}")

        except Exception as e:
            logger.error(f"LM Studio generation error: {e}")
            raise