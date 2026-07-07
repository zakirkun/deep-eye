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
        # Mistral
        if ai_config.get('mistral', {}).get('enabled', False):
            try:
                from ai_providers.mistral_provider import MistralProvider
                self.providers['mistral'] = MistralProvider(ai_config['mistral'])
                logger.info("Mistral provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Mistral provider: {e}")
        
        # OpenRouter
        if ai_config.get('openrouter', {}).get('enabled', False):
            try:
                from ai_providers.openrouter_provider import OpenRouterProvider
                self.providers['openrouter'] = OpenRouterProvider(ai_config['openrouter'])
                logger.info("OpenRouter provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenRouter provider: {e}")

        # Requesty
        if ai_config.get('requesty', {}).get('enabled', False):
            try:
                from ai_providers.requesty_provider import RequestyProvider
                self.providers['requesty'] = RequestyProvider(ai_config['requesty'])
                logger.info("Requesty provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Requesty provider: {e}")

        
        # Gemini
        if ai_config.get('gemini', {}).get('enabled', False):
            try:
                from ai_providers.gemini_provider import GeminiProvider
                self.providers['gemini'] = GeminiProvider(ai_config['gemini'])
                logger.info("Gemini provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini provider: {e}")

        # Groq
        if ai_config.get('groq', {}).get('enabled', False):
            try:
                from ai_providers.groq_provider import GroqProvider
                self.providers['groq'] = GroqProvider(ai_config['groq'])
                logger.info("Groq provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Groq provider: {e}")

        # LM Studio
        if ai_config.get('lmstudio', {}).get('enabled', False):
            try:
                from ai_providers.lmstudio_provider import LMStudioProvider
                self.providers['lmstudio'] = LMStudioProvider(ai_config['lmstudio'])
                logger.info("LM Studio provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize LM Studio provider: {e}")

        # LiteLLM
        if ai_config.get('litellm', {}).get('enabled', False):
            try:
                from ai_providers.litellm_provider import LiteLLMProvider
                self.providers['litellm'] = LiteLLMProvider(ai_config['litellm'])
                logger.info("LiteLLM provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize LiteLLM provider: {e}")

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
        Generate response with retry and automatic failover.

        Tries active provider first with exponential backoff,
        then fails over to other available providers.
        """
        if not self.active_provider and not self.providers:
            logger.error("No AI providers available")
            return ""

        # Try active provider with retries
        max_retries = 3
        if self.active_provider:
            for attempt in range(max_retries):
                try:
                    return self.active_provider.generate(prompt, **kwargs)
                except Exception as e:
                    wait = 2 ** attempt
                    logger.warning(f"Provider attempt {attempt + 1}/{max_retries} failed: {e}. Retrying in {wait}s...")
                    if attempt < max_retries - 1:
                        import time
                        time.sleep(wait)

        # Failover to other providers
        for name, provider in self.providers.items():
            if provider == self.active_provider:
                continue
            try:
                logger.info(f"Failing over to provider: {name}")
                result = provider.generate(prompt, **kwargs)
                self.active_provider = provider
                logger.info(f"Failover successful. Active provider now: {name}")
                return result
            except Exception as e:
                logger.warning(f"Failover to {name} failed: {e}")

        logger.error("All AI providers failed")
        return ""
    
    def get_available_providers(self) -> list:
        """Get list of available providers."""
        return list(self.providers.keys())
