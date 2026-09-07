"""Atlas Cloud provider using its OpenAI-compatible chat API."""

from ai_providers.openai_provider import OpenAIProvider


class AtlasCloudProvider(OpenAIProvider):
    """OpenAI-compatible provider with Atlas Cloud defaults."""

    def __init__(self, config: dict):
        atlas_config = dict(config or {})
        atlas_config.setdefault("base_url", "https://api.atlascloud.ai/v1")
        atlas_config.setdefault("model", "openai/gpt-4.1-mini")
        super().__init__(atlas_config)
