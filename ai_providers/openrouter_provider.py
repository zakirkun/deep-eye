"""
OpenRouter Provider
"""

from typing import Dict, Optional
from openai import OpenAI
from utils.logger import get_logger

logger = get_logger(__name__)


class OpenRouterProvider:
    """OpenRouter API provider."""
    
    def __init__(self, config: Dict):
        """Initialize OpenRouter provider."""
        self.config = config
        self.api_key = config.get('api_key')
        self.model = config.get('model', 'openai/gpt-3.5-turbo')
        self.temperature = config.get('temperature', 0.7)
        self.max_tokens = config.get('max_tokens', 2000)
        self.site_url = config.get('site_url', 'https://github.com/zakirkun/deep-eye')
        self.site_name = config.get('site_name', 'Deep Eye')
        
        if not self.api_key:
            raise ValueError("OpenRouter API key not provided")
        
        # Initialize OpenAI client with OpenRouter base URL
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=self.api_key,
        )
    
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response using OpenRouter.
        
        Args:
            prompt: Input prompt
            **kwargs: Additional arguments
            
        Returns:
            Generated response
        """
        try:
            # Add OpenRouter specific headers
            extra_headers = {
                "HTTP-Referer": self.site_url,
                "X-Title": self.site_name,
            }
            
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
                extra_headers=extra_headers
            )
            
            return response.choices[0].message.content
        
        except Exception as e:
            logger.error(f"OpenRouter generation error: {e}")
            raise
