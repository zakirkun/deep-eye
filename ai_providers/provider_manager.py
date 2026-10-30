"""
AI Provider Manager
Manages the supported AI providers with dynamic switching and tool calling

Five providers are supported: openai (native), openai_compatible (any
OpenAI-protocol endpoint, chat or responses API), claude (Anthropic), gemini
(Google), and ollama (local). Anything else is a config error with an explicit
migration hint rather than a silent omission.
"""

from typing import Any, Callable, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

SUPPORTED_PROVIDERS = ("openai", "openai_compatible", "claude", "gemini", "ollama")

DEPRECATED_PROVIDERS: Dict[str, str] = {
    "grok": "openai_compatible with base_url https://api.x.ai/v1",
    "mistral": "openai_compatible with base_url https://api.mistral.ai/v1",
    "openrouter": "openai_compatible with base_url https://openrouter.ai/api/v1",
    "groq": "openai_compatible with base_url https://api.groq.com/openai/v1",
    "lmstudio": "openai_compatible with base_url http://localhost:1234/v1",
    "litellm": "openai_compatible pointing at your LiteLLM proxy base_url",
    "requesty": "openai_compatible with base_url https://router.requesty.ai/v1",
}


class AIProviderManager:
    """Manage the supported AI providers."""

    def __init__(self, config: Dict):
        self.config = config
        self.providers = {}
        self.active_provider = None
        self._active_name = None
        self._warn_deprecated()
        self._initialize_providers()
        preferred = (config.get("scanner") or {}).get("ai_provider")
        if preferred and preferred in self.providers:
            self.set_provider(preferred)
        elif self.providers:
            self.set_provider(next(iter(self.providers)))

    def _warn_deprecated(self):
        ai_config = self.config.get("ai_providers") or {}
        if not isinstance(ai_config, dict):
            return
        for name, replacement in DEPRECATED_PROVIDERS.items():
            block = ai_config.get(name)
            if isinstance(block, dict) and block.get("enabled", False):
                logger.error(
                    f"Provider '{name}' was removed in this release. "
                    f"Use {replacement}, then delete the ai_providers.{name} block."
                )

    def _initialize_providers(self):
        ai_config = self.config.get("ai_providers") or {}
        if not isinstance(ai_config, dict):
            ai_config = {}

        openai_cfg = ai_config.get("openai") or {}
        if openai_cfg.get("enabled", False):
            try:
                from ai_providers.openai_provider import OpenAIProvider

                self.providers["openai"] = OpenAIProvider(openai_cfg)
                logger.info("OpenAI provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI provider: {e}")

        compat_cfg = ai_config.get("openai_compatible") or {}
        if compat_cfg.get("enabled", False):
            try:
                from ai_providers.openai_compatible import OpenAICompatibleProvider

                self.providers["openai_compatible"] = OpenAICompatibleProvider(compat_cfg)
                mode = compat_cfg.get("api_mode") or "chat"
                logger.info(f"OpenAI-compatible provider initialized ({mode} API)")
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI-compatible provider: {e}")

        claude_cfg = ai_config.get("claude") or {}
        if claude_cfg.get("enabled", False):
            try:
                from ai_providers.claude_provider import ClaudeProvider

                self.providers["claude"] = ClaudeProvider(claude_cfg)
                logger.info("Claude provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Claude provider: {e}")

        ollama_cfg = ai_config.get("ollama") or {}
        if ollama_cfg.get("enabled", False):
            try:
                from ai_providers.ollama_provider import OllamaProvider

                self.providers["ollama"] = OllamaProvider(ollama_cfg)
                logger.info("OLLAMA provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize OLLAMA provider: {e}")

        gemini_cfg = ai_config.get("gemini") or {}
        if gemini_cfg.get("enabled", False):
            try:
                from ai_providers.gemini_provider import GeminiProvider

                self.providers["gemini"] = GeminiProvider(gemini_cfg)
                logger.info("Gemini provider initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini provider: {e}")

    def set_provider(self, provider_name: str) -> bool:
        if provider_name in DEPRECATED_PROVIDERS:
            logger.error(
                f"Provider '{provider_name}' was removed. "
                f"Use {DEPRECATED_PROVIDERS[provider_name]}."
            )
            return False
        if provider_name not in self.providers:
            available = list(self.providers) or list(SUPPORTED_PROVIDERS)
            logger.error(
                f"Provider {provider_name} not available. Available: {available}"
            )
            return False
        self.active_provider = self.providers[provider_name]
        self._active_name = provider_name
        logger.info(f"Active AI provider set to: {provider_name}")
        return True

    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate response with retry and automatic failover.
        Pass tools= + handlers= for multi-round tool calling.
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
        """Multi-round tool calling via the active provider."""
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
