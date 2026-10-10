"""Tests for the optional Atlas Cloud provider."""

from unittest.mock import MagicMock

import pytest


def test_atlascloud_defaults_and_generate(monkeypatch):
    from ai_providers import openai_provider as openai_mod
    from ai_providers.atlascloud_provider import AtlasCloudProvider

    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="atlas response"))]
    )
    monkeypatch.setattr(openai_mod, "OpenAI", lambda **kwargs: fake_client, raising=False)
    monkeypatch.setattr("openai.OpenAI", lambda **kwargs: fake_client)

    provider = AtlasCloudProvider({"api_key": "test-atlascloud-key"})
    assert provider.base_url == "https://api.atlascloud.ai/v1"
    assert provider.model == "openai/gpt-4.1-mini"
    assert provider.generate("test prompt") == "atlas response"
    assert fake_client.chat.completions.create.call_args.kwargs["model"] == (
        "openai/gpt-4.1-mini"
    )


def test_atlascloud_allows_config_overrides(monkeypatch):
    from ai_providers import openai_provider as openai_mod
    from ai_providers.atlascloud_provider import AtlasCloudProvider

    fake_client = MagicMock()
    monkeypatch.setattr(openai_mod, "OpenAI", lambda **kwargs: fake_client, raising=False)
    monkeypatch.setattr("openai.OpenAI", lambda **kwargs: fake_client)

    provider = AtlasCloudProvider(
        {
            "api_key": "test-atlascloud-key",
            "base_url": "https://atlas.example/v1",
            "model": "deepseek-ai/deepseek-v4-pro",
        }
    )
    assert provider.base_url == "https://atlas.example/v1"
    assert provider.model == "deepseek-ai/deepseek-v4-pro"


def test_atlascloud_rejects_missing_or_placeholder_key():
    from ai_providers.atlascloud_provider import AtlasCloudProvider

    with pytest.raises(ValueError):
        AtlasCloudProvider({"api_key": ""})
    with pytest.raises(ValueError):
        AtlasCloudProvider({"api_key": "your-atlascloud-api-key-here"})


def test_provider_manager_initializes_atlascloud(monkeypatch):
    from ai_providers import openai_provider as openai_mod
    from ai_providers.provider_manager import AIProviderManager

    fake_client = MagicMock()
    monkeypatch.setattr(openai_mod, "OpenAI", lambda **kwargs: fake_client, raising=False)
    monkeypatch.setattr("openai.OpenAI", lambda **kwargs: fake_client)

    manager = AIProviderManager(
        {
            "ai_providers": {
                "atlascloud": {
                    "enabled": True,
                    "api_key": "test-atlascloud-key",
                }
            },
            "scanner": {"ai_provider": "atlascloud"},
        }
    )
    assert manager.get_available_providers() == ["atlascloud"]
    assert manager._active_name == "atlascloud"

