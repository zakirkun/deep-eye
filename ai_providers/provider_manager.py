"""
AI Provider Manager
Manages multiple AI providers with dynamic switching
"""

from typing import Dict, Optional
from utils.logger import get_logger

logger = get_logger(__name__)


class AIProviderManager:
    """Manage multiple AI providers."""
    
    def __init__(self, config: Dict):
        """Initialize AI provider manager."""
        self.config = config
        self.providers = {}
        self.active_provider = None
        
        # Initialize available providers
        self._initialize_providers()
    
    def _initialize_providers(self):
        """Initialize all configured AI providers."""
        ai_config = self.config.get('ai_providers', {})
        
        # OpenAI
        if ai_config.get('openai', {}).get('enabled', False):
            try:
                from ai_providers.openai_provider import OpenAIProvider
                self.providers['openai'] = OpenAIProvider(ai_config['openai'])
                logger.info("OpenAI provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI provider: {e}")
        
        # Claude
        if ai_config.get('claude', {}).get('enabled', False):
            try:
                from ai_providers.claude_provider import ClaudeProvider
                self.providers['claude'] = ClaudeProvider(ai_config['claude'])
                logger.info("Claude provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Claude provider: {e}")
        
        # Grok
        if ai_config.get('grok', {}).get('enabled', False):
            try:
                from ai_providers.grok_provider import GrokProvider
                self.providers['grok'] = GrokProvider(ai_config['grok'])
                logger.info("Grok provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Grok provider: {e}")
        
        # OLLAMA
        if ai_config.get('ollama', {}).get('enabled', False):
            try:
                from ai_providers.ollama_provider import OllamaProvider
                self.providers['ollama'] = OllamaProvider(ai_config['ollama'])
                logger.info("OLLAMA provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OLLAMA provider: {e}")
        
        # Gemini
        if ai_config.get('gemini', {}).get('enabled', False):
            try:
                from ai_providers.gemini_provider import GeminiProvider
                self.providers['gemini'] = GeminiProvider(ai_config['gemini'])
                logger.info("Gemini provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini provider: {e}")

        # OpenRouter
        if ai_config.get('openrouter', {}).get('enabled', False):
            try:
                from ai_providers.openrouter_provider import OpenRouterProvider
                self.providers['openrouter'] = OpenRouterProvider(ai_config['openrouter'])
                logger.info("OpenRouter provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenRouter provider: {e}")
    
    def set_provider(self, provider_name: str) -> bool:
        """
        Set active AI provider.
        
        Args:
            provider_name: Name of provider to activate
            
        Returns:
            True if successful, False otherwise
        """
        if provider_name not in self.providers:
            logger.error(f"Provider {provider_name} not available")
            return False
        
        self.active_provider = self.providers[provider_name]
        logger.info(f"Active AI provider set to: {provider_name}")
        return True
    
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response from active AI provider.
        
        Args:
            prompt: Input prompt
            **kwargs: Additional provider-specific arguments
            
        Returns:
            Generated response
        """
        if not self.active_provider:
            logger.error("No active AI provider")
            return ""
        
        try:
            return self.active_provider.generate(prompt, **kwargs)
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return ""
    
    def get_available_providers(self) -> list:
        """Get list of available providers."""
        return list(self.providers.keys())
