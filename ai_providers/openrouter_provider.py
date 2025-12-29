"""
OpenRouter Provider
"""

from typing import Dict, Optional
import requests
from utils.logger import get_logger

logger = get_logger(__name__)


class OpenRouterProvider:
    """OpenRouter API provider."""
    
    def __init__(self, config: Dict):
        """Initialize OpenRouter provider."""
        self.config = config
        self.api_key = config.get('api_key')
        self.model = config.get('model', 'openai/gpt-4o')
        self.temperature = config.get('temperature', 0.7)
        self.max_tokens = config.get('max_tokens', 2000)
        self.base_url = config.get('base_url', 'https://openrouter.ai/api/v1')
        self.timeout = config.get('timeout', 30)
        
        if not self.api_key:
            raise ValueError("OpenRouter API key not provided")
        
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'HTTP-Referer': 'https://github.com/deep-eye/deep-eye',  # Optional: for analytics
            'X-Title': 'Deep Eye Security Scanner'  # Optional: for analytics
        }
    
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
            payload = {
                'model': kwargs.get('model', self.model),
                'messages': [
                    {
                        'role': 'system',
                        'content': 'You are a security expert specializing in penetration testing and vulnerability research.'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'temperature': kwargs.get('temperature', self.temperature),
                'max_tokens': kwargs.get('max_tokens', self.max_tokens)
            }
            
            response = requests.post(
                f'{self.base_url}/chat/completions',
                headers=self.headers,
                json=payload,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            result = response.json()
            
            if 'choices' in result and len(result['choices']) > 0:
                return result['choices'][0]['message']['content']
            else:
                logger.error("No choices in OpenRouter response")
                return ""
        
        except requests.exceptions.RequestException as e:
            logger.error(f"OpenRouter API request error: {e}")
            raise
        except KeyError as e:
            logger.error(f"OpenRouter response parsing error: {e}")
            raise
        except Exception as e:
            logger.error(f"OpenRouter generation error: {e}")
            raise