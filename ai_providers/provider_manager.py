"""
AI Provider Manager
Manages multiple AI providers with dynamic switching and tool calling
"""

from typing import Any, Callable, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class AIProviderManager:
    """Manage multiple AI providers."""

    def __init__(self, config: Dict):
        self.config = config
        self.providers = {}
        self.active_provider = None
        self._active_name = None
        self._initialize_providers()
        preferred = (config.get("scanner") or {}).get("ai_provider")
        if preferred and preferred in self.providers:
            self.set_provider(preferred)
        elif self.providers:
            self.set_provider(next(iter(self.providers)))

    def _initialize_providers(self):
        ai_config = self.config.get("ai_providers", {})

        if ai_config.get("openai", {}).get("enabled", False):
            try:
                from ai_providers.openai_provider import OpenAIProvider

                self.providers["openai"] = OpenAIProvider(ai_config["openai"])
                logger.info("OpenAI provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI provider: {e}")

        if ai_config.get("claude", {}).get("enabled", False):
            try:
                from ai_providers.claude_provider import ClaudeProvider

                self.providers["claude"] = ClaudeProvider(ai_config["claude"])
                logger.info("Claude provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Claude provider: {e}")

        if ai_config.get("grok", {}).get("enabled", False):
            try:
                from ai_providers.grok_provider import GrokProvider

                self.providers["grok"] = GrokProvider(ai_config["grok"])
                logger.info("Grok provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Grok provider: {e}")

        if ai_config.get("ollama", {}).get("enabled", False):
            try:
                from ai_providers.ollama_provider import OllamaProvider

                self.providers["ollama"] = OllamaProvider(ai_config["ollama"])
                logger.info("OLLAMA provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OLLAMA provider: {e}")

        if ai_config.get("mistral", {}).get("enabled", False):
            try:
                from ai_providers.mistral_provider import MistralProvider

                self.providers["mistral"] = MistralProvider(ai_config["mistral"])
                logger.info("Mistral provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Mistral provider: {e}")

        if ai_config.get("openrouter", {}).get("enabled", False):
            try:
                from ai_providers.openrouter_provider import OpenRouterProvider

                self.providers["openrouter"] = OpenRouterProvider(ai_config["openrouter"])
                logger.info("OpenRouter provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenRouter provider: {e}")

        if ai_config.get("orcarouter", {}).get("enabled", False):
            try:
                from ai_providers.orcarouter_provider import OrcaRouterProvider

                self.providers["orcarouter"] = OrcaRouterProvider(ai_config["orcarouter"])
                logger.info("OrcaRouter provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OrcaRouter provider: {e}")

        if ai_config.get("gemini", {}).get("enabled", False):
            try:
                from ai_providers.gemini_provider import GeminiProvider

                self.providers["gemini"] = GeminiProvider(ai_config["gemini"])
                logger.info("Gemini provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini provider: {e}")

        if ai_config.get("groq", {}).get("enabled", False):
            try:
                from ai_providers.groq_provider import GroqProvider

                self.providers["groq"] = GroqProvider(ai_config["groq"])
                logger.info("Groq provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Groq provider: {e}")

        if ai_config.get("lmstudio", {}).get("enabled", False):
            try:
                from ai_providers.lmstudio_provider import LMStudioProvider

                self.providers["lmstudio"] = LMStudioProvider(ai_config["lmstudio"])
                logger.info("LM Studio provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize LM Studio provider: {e}")

        if ai_config.get("litellm", {}).get("enabled", False):
            try:
                from ai_providers.litellm_provider import LiteLLMProvider

                self.providers["litellm"] = LiteLLMProvider(ai_config["litellm"])
                logger.info("LiteLLM provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize LiteLLM provider: {e}")

        if ai_config.get("nvidia_nim", {}).get("enabled", False):
            try:
                from ai_providers.nvidia_nim_provider import NvidiaNIMProvider

                self.providers["nvidia_nim"] = NvidiaNIMProvider(ai_config["nvidia_nim"])
                logger.info("NVIDIA NIM provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize NVIDIA NIM provider: {e}")

        if ai_config.get("atlascloud", {}).get("enabled", False):
            try:
                from ai_providers.atlascloud_provider import AtlasCloudProvider

                self.providers["atlascloud"] = AtlasCloudProvider(ai_config["atlascloud"])
                logger.info("Atlas Cloud provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Atlas Cloud provider: {e}")

    def set_provider(self, provider_name: str) -> bool:
        if provider_name not in self.providers:
            logger.error(f"Provider {provider_name} not available")
            return False
        self.active_provider = self.providers[provider_name]
        self._active_name = provider_name
        logger.info(f"Active AI provider set to: {provider_name}")
        return True

    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response with retry and automatic failover.
        Pass tools= + handlers= for multi-round tool calling (OpenAI/Claude).
        """
        if not self.active_provider and not self.providers:
            logger.error("No AI providers available")
            return ""

        max_retries = 3
        if self.active_provider:
            for attempt in range(max_retries):
                try:
                    result = self.active_provider.generate(prompt, **kwargs)
                    if result is None or (isinstance(result, str) and not result.strip()):
                        raise RuntimeError("empty AI response")
                    return result
                except Exception as e:
                    wait = 2 ** attempt
                    logger.warning(
                        f"Provider attempt {attempt + 1}/{max_retries} failed: {e}. "
                        f"Retrying in {wait}s..."
                    )
                    if attempt < max_retries - 1:
                        import time

                        time.sleep(wait)

        for name, provider in self.providers.items():
            if provider == self.active_provider:
                continue
            try:
                logger.info(f"Failing over to provider: {name}")
                result = provider.generate(prompt, **kwargs)
                if result is None or (isinstance(result, str) and not result.strip()):
                    raise RuntimeError("empty AI response")
                self.active_provider = provider
                self._active_name = name
                logger.info(f"Failover successful. Active provider now: {name}")
                return result
            except Exception as e:
                logger.warning(f"Failover to {name} failed: {e}")

        logger.error("All AI providers failed (returning empty string)")
        return ""

    def generate_with_tools(
        self,
        prompt: str,
        tools: List[Any],
        handlers: Dict[str, Callable],
        max_rounds: int = 5,
        **kwargs,
    ) -> str:
        """Multi-round tool calling via active provider (OpenAI/Claude)."""
        from ai_providers.tool_runtime import run_tool_loop

        if not self.active_provider and not self.providers:
            logger.error("No AI providers available for tools")
            return ""

        order = []
        if self.active_provider:
            order.append(self.active_provider)
        for p in self.providers.values():
            if p not in order:
                order.append(p)

        last_err = None
        for provider in order:
            if not hasattr(provider, "generate_with_tools"):
                continue
            try:
                return run_tool_loop(
                    provider,
                    prompt,
                    tools,
                    handlers,
                    max_rounds=max_rounds,
                    **kwargs,
                )
            except Exception as e:
                last_err = e
                logger.warning(f"Tool loop failed on provider: {e}")
                continue

        logger.warning(
            f"Tool calling unavailable ({last_err}); falling back to plain generate"
        )
        return self.generate(prompt, **kwargs)

    def get_available_providers(self) -> list:
        return list(self.providers.keys())

    def supports_tools(self, provider_name: Optional[str] = None) -> bool:
        name = provider_name or self._active_name
        if name and name in self.providers:
            return hasattr(self.providers[name], "generate_with_tools")
        if self.active_provider:
            return hasattr(self.active_provider, "generate_with_tools")
        return False
