from mistralai import Mistral
from typing import Dict
from utils.logger import get_logger

logger = get_logger(__name__)

class MistralProvider:
    """Provider for Mistral AI API"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.api_key = config.get('api_key')
        self.model = config.get('model', '')
        self.temperature = config.get('temperature', 0.7)
        self.max_tokens = config.get('max_tokens', 2000)
        
        if not self.api_key:
            raise ValueError("Mistral API key not provided")
        
        self.client = Mistral(api_key=self.api_key)
        logger.info(f"MistralProvider initialized with model: {self.model}")
    
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response using Mistral.
        
        Args:
            prompt: Input prompt
            **kwargs: Additional arguments
            
        Returns:
            Generated response
        """
        try:
            response = self.client.chat.complete(
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
                max_tokens=kwargs.get('max_tokens', self.max_tokens)
            )
            
            return response.choices[0].message.content
    
        except Exception as e:
            logger.error(f"Mistral generation error: {e}")
            raise