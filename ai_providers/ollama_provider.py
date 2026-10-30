"""
OLLAMA Provider (Local LLM)
"""

from typing import Dict
import requests
from utils.logger import get_logger

logger = get_logger(__name__)

_SYSTEM = (
    "You are a security expert specializing in penetration testing "
    "and vulnerability research."
)

THINKING_MODELS = ("deepseek-r1", "qwq", "qwen3", "phi4-reasoning", "magistral")


def supports_thinking(model: str) -> bool:
    """Local reasoning is a property of the model, not a request flag."""
    m = (model or "").lower().split(":")[0].split("/")[-1]
    return any(m.startswith(prefix) for prefix in THINKING_MODELS)


class OllamaProvider:
    """OLLAMA local LLM provider."""

    name = "ollama"

    def __init__(self, config: Dict):
        self.config = config or {}
        self.base_url = (self.config.get("base_url") or "http://localhost:11434").rstrip("/")
        self.model = self.config.get("model") or "llama2"
        self.temperature = float(self.config.get("temperature", 0.7))
        self.timeout = float(self.config.get("timeout", 60) or 60)
        self.think = self.config.get("think")
        if self.think is None:
            self.think = supports_thinking(self.model)

    def check_available(self) -> bool:
        """Return True when the server answers, so failover can skip a dead one."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"OLLAMA not reachable at {self.base_url}: {e}")
            return False

    def generate(self, prompt: str, **kwargs) -> str:
        try:
            model = kwargs.get("model") or self.model
            system = kwargs.get("system") or _SYSTEM

            payload = {
                "model": model,
                "prompt": prompt,
                "system": system,
                "options": {
                    "temperature": kwargs.get("temperature", self.temperature),
                },
                "stream": False,
            }

            think = kwargs.get("think", self.think)
            if think:
                payload["think"] = True

            max_tokens = kwargs.get("max_tokens")
            if max_tokens:
                payload["options"]["num_predict"] = int(max_tokens)

            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )

            if response.status_code != 200:
                raise RuntimeError(f"OLLAMA API error: {response.status_code}")

            data = response.json()
            answer = data.get("response") or ""
            thinking = data.get("thinking") or ""
            if thinking and not answer:
                return str(thinking).strip()
            return str(answer).strip()

        except Exception as e:
            logger.error(f"OLLAMA generation error: {e}")
            raise
