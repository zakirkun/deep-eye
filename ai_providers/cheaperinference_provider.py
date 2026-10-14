"""
Cheaper Inference Provider
"""

from typing import Dict

from openai import OpenAI

from utils.logger import get_logger

logger = get_logger(__name__)


class CheaperInferenceProvider:
    """Cheaper Inference API provider."""

    def __init__(self, config: Dict):
        """Initialize Cheaper Inference provider."""
        self.config = config or {}
        self.api_key = (self.config.get('api_key') or '').strip()
        self.model = self.config.get('model', 'gpt-5.4-mini')
        self.temperature = float(self.config.get('temperature', 0.7))
        self.max_tokens = int(self.config.get('max_tokens', 2000) or 2000)
        self.base_url = (self.config.get('base_url') or '').strip() or "https://api.cheaperinference.com/v1"
        self.timeout = float(self.config.get('timeout', 60) or 60)

        if (
            not self.api_key
            or self.api_key.startswith('your-')
            or self.api_key.startswith('ci_live_your')
        ):
            raise ValueError("Cheaper Inference API key not provided or still a placeholder")

        # Initialize OpenAI client with Cheaper Inference base URL
        self.client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=self.timeout,
        )

    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response using Cheaper Inference.

        Args:
            prompt: Input prompt
            **kwargs: Additional arguments

        Returns:
            Generated response
        """
        try:
            response = self.client.chat.completions.create(
                model=kwargs.get('model', self.model),
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security expert specializing in penetration testing and vulnerability research."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=kwargs.get('temperature', self.temperature),
                max_tokens=kwargs.get('max_tokens', self.max_tokens),
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"Cheaper Inference generation error: {e}")
            raise
