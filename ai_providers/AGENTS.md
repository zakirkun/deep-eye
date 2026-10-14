# AI PROVIDERS

## OVERVIEW
Multi-vendor AI wrapper layer. Each backend implements `generate(prompt, **kwargs) -> str`. `AIProviderManager` selects the active provider from config and delegates all calls. OpenAI + Claude support multi-round tool calling.

## STRUCTURE
```
ai_providers/
├── provider_manager.py    # AIProviderManager: init, set, generate, generate_with_tools
├── tool_runtime.py        # ToolSpec, run_tool_loop, run_handlers
├── openai_provider.py     # chat.completions + tools
├── claude_provider.py     # Messages API + tool_use
├── grok_provider.py
├── ollama_provider.py
├── gemini_provider.py
├── groq_provider.py
├── mistral_provider.py
├── openrouter_provider.py
├── orcarouter_provider.py
├── cheaperinference_provider.py
├── litellm_provider.py
├── nvidia_nim_provider.py
└── lmstudio_provider.py
```

## WHERE TO LOOK
| Task | File |
|------|------|
| Add a new vendor | New `*_provider.py` + `provider_manager._initialize_providers` + `config.example.yaml` |
| Change active backend | `AIProviderManager.set_provider(name)` or config `ai_providers.<name>.enabled` |
| Generate payloads / triage | Consumers call `ai_manager.generate(...)` |
| Tool calling | `generate(..., tools=, handlers=)` or `generate_with_tools` |
| Failover logic | `provider_manager.generate()` |

## CONVENTIONS
- Provider class name: `<Vendor>Provider`.
- Required method: `generate(prompt: str, **kwargs) -> str`.
- Optional: `generate_with_tools` for multi-round tools.
- Shared: `tool_runtime.ToolSpec`, `run_tool_loop`.
- Config gate: skip unless `ai_providers.<name>.enabled`.
- API keys in `config.yaml` only.

## TOOL CALLING
```python
from ai_providers.tool_runtime import ToolSpec

tools = [ToolSpec("lookup_cve", "Lookup CVE", {
    "type": "object",
    "properties": {"cve_id": {"type": "string"}},
    "required": ["cve_id"],
})]
handlers = {"lookup_cve": lambda cve_id: {"id": cve_id, "cvss": 9.8}}

text = ai_manager.generate(prompt, tools=tools, handlers=handlers)
# or: ai_manager.generate_with_tools(prompt, tools, handlers, max_rounds=5)
```

## ANTI-PATTERNS
- Do not call provider constructors outside `AIProviderManager`.
- Do not add a provider without config example update.
- Do not hardcode model names; read from config.
- Do not reimplement tool loops outside `tool_runtime`.

## NOTES
- OpenAI: `tools` + `tool_calls`; o-series skips tools.
- Claude: `tools` + `tool_use` / `tool_result` blocks.
- Both reject placeholder API keys.
- Tests: `tests/test_ai_tool_calling.py`, `tests/test_openai_claude_providers.py`.
