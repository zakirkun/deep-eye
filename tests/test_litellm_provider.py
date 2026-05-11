"""Tests for LiteLLM provider."""

from pathlib import Path
from unittest.mock import MagicMock, patch


class TestLiteLLMProviderInit:
    def test_default_model(self):
        from ai_providers.litellm_provider import LiteLLMProvider

        p = LiteLLMProvider({"api_key": "sk-test"})
        assert p.model == "openai/gpt-4o"

    def test_custom_model(self):
        from ai_providers.litellm_provider import LiteLLMProvider

        p = LiteLLMProvider({"model": "anthropic/claude-sonnet-4-20250514"})
        assert p.model == "anthropic/claude-sonnet-4-20250514"

    def test_api_key_stored(self):
        from ai_providers.litellm_provider import LiteLLMProvider

        p = LiteLLMProvider({"api_key": "sk-test"})
        assert p.api_key == "sk-test"

    def test_default_temperature(self):
        from ai_providers.litellm_provider import LiteLLMProvider

        p = LiteLLMProvider({})
        assert p.temperature == 0.7


class TestLiteLLMProviderGenerate:
    @patch("ai_providers.litellm_provider.litellm")
    def test_calls_litellm_completion(self, mock_litellm):
        mock_msg = MagicMock(content="test response")
        mock_litellm.completion.return_value = MagicMock(
            choices=[MagicMock(message=mock_msg)]
        )

        from ai_providers.litellm_provider import LiteLLMProvider

        p = LiteLLMProvider({"api_key": "sk-test", "model": "openai/gpt-4o"})
        result = p.generate("hello")

        assert result == "test response"
        kwargs = mock_litellm.completion.call_args.kwargs
        assert kwargs["model"] == "openai/gpt-4o"
        assert kwargs["drop_params"] is True
        assert kwargs["api_key"] == "sk-test"

    @patch("ai_providers.litellm_provider.litellm")
    def test_omits_api_key_when_none(self, mock_litellm):
        mock_msg = MagicMock(content="ok")
        mock_litellm.completion.return_value = MagicMock(
            choices=[MagicMock(message=mock_msg)]
        )

        from ai_providers.litellm_provider import LiteLLMProvider

        p = LiteLLMProvider({"model": "openai/gpt-4o"})
        p.generate("hi")
        assert "api_key" not in mock_litellm.completion.call_args.kwargs

    @patch("ai_providers.litellm_provider.litellm")
    def test_system_prompt_is_security_expert(self, mock_litellm):
        mock_msg = MagicMock(content="ok")
        mock_litellm.completion.return_value = MagicMock(
            choices=[MagicMock(message=mock_msg)]
        )

        from ai_providers.litellm_provider import LiteLLMProvider

        p = LiteLLMProvider({"api_key": "sk-test"})
        p.generate("test")
        messages = mock_litellm.completion.call_args.kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert "security" in messages[0]["content"].lower()

    @patch("ai_providers.litellm_provider.litellm")
    def test_forwards_kwargs(self, mock_litellm):
        mock_msg = MagicMock(content="ok")
        mock_litellm.completion.return_value = MagicMock(
            choices=[MagicMock(message=mock_msg)]
        )

        from ai_providers.litellm_provider import LiteLLMProvider

        p = LiteLLMProvider({"api_key": "sk-test"})
        p.generate("test", model="anthropic/claude-haiku-4-5", temperature=0.2)
        kwargs = mock_litellm.completion.call_args.kwargs
        assert kwargs["model"] == "anthropic/claude-haiku-4-5"
        assert kwargs["temperature"] == 0.2


class TestRegistration:
    def test_litellm_in_provider_manager(self):
        src = Path("ai_providers/provider_manager.py").read_text()
        assert "litellm" in src
        assert "LiteLLMProvider" in src

    def test_litellm_in_requirements(self):
        reqs = Path("requirements.txt").read_text()
        assert "litellm" in reqs
