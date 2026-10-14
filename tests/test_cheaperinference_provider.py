"""Cheaper Inference completion provider unit tests (mocked SDK)."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def test_cheaperinference_generate_chat(monkeypatch):
    from ai_providers import cheaperinference_provider as mod

    fake_client = MagicMock()
    msg = MagicMock()
    msg.content = "payload list here"
    choice = MagicMock()
    choice.message = msg
    fake_resp = MagicMock()
    fake_resp.choices = [choice]
    fake_client.chat.completions.create.return_value = fake_resp

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def __getattr__(self, name):
            return getattr(fake_client, name)

    monkeypatch.setattr(mod, "OpenAI", FakeOpenAI, raising=False)
    import openai as openai_mod

    monkeypatch.setattr(openai_mod, "OpenAI", FakeOpenAI)

    p = mod.CheaperInferenceProvider(
        {"api_key": "ci_live_test-key-not-placeholder", "model": "gpt-5.4-mini", "max_tokens": 100}
    )
    p.client = fake_client
    out = p.generate("give me xss payloads")
    assert "payload" in out.lower()
    assert fake_client.chat.completions.create.called


def test_cheaperinference_rejects_placeholder_key():
    import pytest

    from ai_providers.cheaperinference_provider import CheaperInferenceProvider

    with pytest.raises(ValueError):
        CheaperInferenceProvider({"api_key": "ci_live_your-cheaperinference-api-key-here", "model": "gpt-5.4-mini"})


def test_cheaperinference_default_base_url():
    from ai_providers.cheaperinference_provider import CheaperInferenceProvider

    p = CheaperInferenceProvider({"api_key": "ci_live_test-key-not-placeholder", "model": "gpt-5.4-mini"})
    assert p.base_url == "https://api.cheaperinference.com/v1"
    assert p.client is not None
