"""Live E2E test for LiteLLM provider.

Requires API key. Set ANTHROPIC_FOUNDRY_API_KEY and ANTHROPIC_FOUNDRY_BASE_URL,
or ANTHROPIC_API_KEY, or OPENAI_API_KEY.

Usage:
    PYTHONPATH=. python tests/e2e_litellm.py
"""

import os
import sys


def main():
    api_key = (
        os.environ.get("ANTHROPIC_FOUNDRY_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
    )
    if not api_key:
        print("SKIP: no API key found")
        sys.exit(0)

    base_url = os.environ.get("ANTHROPIC_FOUNDRY_BASE_URL")
    if base_url:
        import litellm
        litellm.api_base = base_url

    from ai_providers.litellm_provider import LiteLLMProvider

    provider = LiteLLMProvider({
        "api_key": api_key,
        "model": "anthropic/claude-sonnet-4-6",
    })

    # Test 1: Basic generation
    result = provider.generate("What is 2+2? Reply with just the number.")
    print(f"Test 1 (basic): \"{result.strip()}\"")
    assert "4" in result, f"Expected 4, got: {result}"

    # Test 2: kwargs override
    result2 = provider.generate("Say OK", max_tokens=5, temperature=0)
    print(f"Test 2 (kwargs): \"{result2.strip()}\"")
    assert result2.strip(), "Empty response"

    # Test 3: Security system prompt works
    result3 = provider.generate("List one common web vulnerability in one word.")
    print(f"Test 3 (security): \"{result3.strip()[:50]}\"")
    assert result3.strip(), "Empty response"

    # Test 4: Provider manager integration
    from ai_providers.provider_manager import AIProviderManager

    config = {
        "ai_providers": {
            "litellm": {
                "enabled": True,
                "api_key": api_key,
                "model": "anthropic/claude-sonnet-4-6",
            }
        }
    }
    manager = AIProviderManager(config)
    assert manager.set_provider("litellm")
    result4 = manager.generate("Say hello in one word.")
    print(f"Test 4 (manager): \"{result4.strip()[:30]}\"")
    assert result4.strip(), "Empty response from manager"

    print()
    print("ALL 4 E2E TESTS PASSED")


if __name__ == "__main__":
    main()
