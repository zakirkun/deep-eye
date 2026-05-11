"""Tests for LiteLLM provider."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


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


class TestLiteLLMProviderEdgeCases:
    @patch("ai_providers.litellm_provider.litellm")
    def test_raises_on_api_error(self, mock_litellm):
        mock_litellm.completion.side_effect = Exception("401 Unauthorized")

        from ai_providers.litellm_provider import LiteLLMProvider

        p = LiteLLMProvider({"api_key": "bad-key"})
        with pytest.raises(Exception, match="401"):
            p.generate("hello")

    @patch("ai_providers.litellm_provider.litellm")
    def test_returns_none_content_gracefully(self, mock_litellm):
        mock_msg = MagicMock(content=None)
        mock_litellm.completion.return_value = MagicMock(
            choices=[MagicMock(message=mock_msg)]
        )

        from ai_providers.litellm_provider import LiteLLMProvider

        p = LiteLLMProvider({"api_key": "sk-test"})
        result = p.generate("hello")
        assert result is None

    @patch("ai_providers.litellm_provider.litellm")
    def test_provider_manager_can_load_litellm(self, mock_litellm):
        from ai_providers.provider_manager import AIProviderManager

        config = {
            "ai_providers": {
                "litellm": {
                    "enabled": True,
                    "api_key": "sk-test",
                    "model": "openai/gpt-4o",
                }
            }
        }
        manager = AIProviderManager(config)
        assert "litellm" in manager.get_available_providers()

    @patch("ai_providers.litellm_provider.litellm")
    def test_provider_manager_generate_routes_to_litellm(self, mock_litellm):
        mock_msg = MagicMock(content="manager response")
        mock_litellm.completion.return_value = MagicMock(
            choices=[MagicMock(message=mock_msg)]
        )

        from ai_providers.provider_manager import AIProviderManager

        config = {
            "ai_providers": {
                "litellm": {
                    "enabled": True,
                    "api_key": "sk-test",
                    "model": "openai/gpt-4o",
                }
            }
        }
        manager = AIProviderManager(config)
        manager.set_provider("litellm")
        result = manager.generate("test prompt")
        assert result == "manager response"


class TestRegistration:
    def test_litellm_in_provider_manager(self):
        src = Path("ai_providers/provider_manager.py").read_text()
        assert "litellm" in src
        assert "LiteLLMProvider" in src

    def test_litellm_in_requirements(self):
        reqs = Path("requirements.txt").read_text()
        assert "litellm" in reqs
