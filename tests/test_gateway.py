"""Provider gateway: 4 providers, api modes, and reasoning controls."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def test_supported_provider_list_is_five():
    from ai_providers.provider_manager import SUPPORTED_PROVIDERS

    assert SUPPORTED_PROVIDERS == (
        "openai",
        "openai_compatible",
        "claude",
        "gemini",
        "ollama",
    )


def test_deprecated_providers_each_have_replacement():
    from ai_providers.provider_manager import DEPRECATED_PROVIDERS, SUPPORTED_PROVIDERS

    assert len(DEPRECATED_PROVIDERS) == 7
    for name, replacement in DEPRECATED_PROVIDERS.items():
        assert name not in SUPPORTED_PROVIDERS
        assert "openai_compatible" in replacement


def test_manager_rejects_deprecated_provider():
    from ai_providers.provider_manager import AIProviderManager

    manager = AIProviderManager({"ai_providers": {}})
    assert manager.set_provider("grok") is False


def test_manager_only_initializes_enabled_providers():
    from ai_providers.provider_manager import AIProviderManager

    manager = AIProviderManager(
        {
            "ai_providers": {
                "openai": {"enabled": False},
                "claude": {"enabled": False},
                "gemini": {"enabled": False},
                "ollama": {"enabled": False},
                "openai_compatible": {"enabled": False},
            }
        }
    )
    assert manager.get_available_providers() == []


def test_compatible_provider_defaults_to_chat_mode():
    from ai_providers.openai_compatible import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider(
        {"api_key": "sk-test-key", "model": "gpt-4o"}
    )
    assert provider.api_mode == "chat"


def test_compatible_provider_accepts_responses_mode():
    from ai_providers.openai_compatible import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider(
        {"api_key": "sk-test-key", "api_mode": "responses"}
    )
    assert provider.api_mode == "responses"


def test_compatible_provider_rejects_unknown_mode():
    import pytest

    from ai_providers.openai_compatible import OpenAICompatibleProvider

    with pytest.raises(ValueError, match="api_mode"):
        OpenAICompatibleProvider({"api_key": "sk-test-key", "api_mode": "grpc"})


def test_compatible_provider_rejects_bad_reasoning_effort():
    import pytest

    from ai_providers.openai_compatible import OpenAICompatibleProvider

    with pytest.raises(ValueError, match="reasoning_effort"):
        OpenAICompatibleProvider(
            {"api_key": "sk-test-key", "reasoning_effort": "extreme"}
        )


def test_compatible_provider_rejects_placeholder_key():
    import pytest

    from ai_providers.openai_compatible import OpenAICompatibleProvider

    with pytest.raises(ValueError):
        OpenAICompatibleProvider({"api_key": "sk-your-openai-api-key-here"})


def test_reasoning_models_use_completion_tokens():
    from ai_providers.openai_compatible import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider({"api_key": "sk-test-key"})
    assert provider._token_kwargs("o3-mini", 500) == {"max_completion_tokens": 500}
    assert provider._token_kwargs("gpt-4o", 500) == {"max_tokens": 500}
    assert provider._token_kwargs("gpt-5", 500) == {"max_completion_tokens": 500}


def test_reasoning_effort_only_sent_to_reasoning_models():
    from ai_providers.openai_compatible import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider(
        {"api_key": "sk-test-key", "reasoning_effort": "high"}
    )
    assert provider._reasoning_kwargs("o4-mini") == {"reasoning_effort": "high"}
    assert provider._reasoning_kwargs("gpt-4o") == {}


def test_reasoning_effort_sent_in_responses_mode_for_any_model():
    from ai_providers.openai_compatible import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider(
        {"api_key": "sk-test-key", "api_mode": "responses", "reasoning_effort": "low"}
    )
    assert provider._reasoning_kwargs("gpt-4o") == {"reasoning_effort": "low"}


def test_claude_thinking_budget_configured(monkeypatch):
    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", lambda **kwargs: object())
    from ai_providers.claude_provider import ClaudeProvider

    provider = ClaudeProvider(
        {"api_key": "sk-ant-real-key", "thinking_budget_tokens": 4000}
    )
    assert provider.thinking_budget == 4000


def test_claude_thinking_defaults_to_disabled(monkeypatch):
    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", lambda **kwargs: object())
    from ai_providers.claude_provider import ClaudeProvider

    provider = ClaudeProvider({"api_key": "sk-ant-real-key"})
    assert provider.thinking_budget == 0


def test_ollama_thinking_autodetected_per_model():
    from ai_providers.ollama_provider import supports_thinking

    assert supports_thinking("deepseek-r1:7b") is True
    assert supports_thinking("qwq") is True
    assert supports_thinking("qwen3:14b") is True
    assert supports_thinking("llama2") is False


def test_ollama_thinking_can_be_disabled_explicitly():
    from ai_providers.ollama_provider import OllamaProvider

    provider = OllamaProvider({"model": "deepseek-r1", "think": False})
    assert provider.think is False


def test_openai_compatible_extracts_responses_output():
    from ai_providers.openai_compatible import OpenAICompatibleProvider

    part = MagicMock()
    part.text = "hello"
    item = MagicMock()
    item.content = [part]
    response = MagicMock()
    response.output_text = None
    response.output = [item]

    assert OpenAICompatibleProvider._extract_responses_output(response) == "hello"


def test_gemini_registered_and_validates_config():
    from ai_providers.gemini_provider import GeminiProvider

    try:
        GeminiProvider({"api_key": "your-gemini-api-key-here"})
    except ValueError:
        pass
    else:
        raise AssertionError("placeholder key should be rejected")


def test_gemini_thinking_budget_validated():
    import pytest

    from ai_providers.gemini_provider import GeminiProvider

    with pytest.raises(ValueError, match="thinking_budget"):
        GeminiProvider({"api_key": "real-key", "thinking_budget": "extreme"})


def test_gemini_thinking_config_built_when_set(monkeypatch):
    import pytest

    pytest.importorskip("google.genai")

    from ai_providers import gemini_provider as mod

    class FakeClient:
        def __init__(self, **kwargs):
            pass

    import google.genai as real_genai

    monkeypatch.setattr(real_genai, "Client", FakeClient)
    provider = mod.GeminiProvider({"api_key": "real-key", "thinking_budget": "low"})
    config = provider._build_config("gemini-2.0-flash")
    assert "thinking_config" in config
