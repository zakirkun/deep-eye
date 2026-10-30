# AI PROVIDERS

## OVERVIEW
Multi-vendor AI wrapper layer, 13 modules + `__init__`. Each backend implements `generate(prompt, **kwargs) -> str`. `AIProviderManager` selects the active provider from config, retries it, then fails over across the rest. Only OpenAI and Claude implement real multi-round tool calling.

## STRUCTURE
```
ai_providers/
├── provider_manager.py    # AIProviderManager: init, set_provider, generate, generate_with_tools
├── tool_runtime.py        # ToolSpec, run_tool_loop, normalize_tools, run_handlers
├── openai_provider.py     # 242 LOC — chat.completions + tools
├── claude_provider.py     # 204 LOC — Messages API + tool_use
├── gemini_provider.py     # 94
├── openrouter_provider.py # 69
├── requesty_provider.py   # 69 — NOT registered (see ANTI-PATTERNS)
├── grok_provider.py       # 61
├── groq_provider.py       # 53
├── mistral_provider.py    # 53
├── ollama_provider.py     # 53
├── lmstudio_provider.py   # 52
├── litellm_provider.py    # 51
└── __init__.py
```

## WHERE TO LOOK
| Task | File |
|------|------|
| Add a new vendor | New `*_provider.py` + register in `provider_manager._initialize_providers` (lines 28–120) + `config.example.yaml` |
| Change active backend | `AIProviderManager.set_provider(name)` or config `scanner.ai_provider` |
| Failover semantics | `provider_manager.generate()` (line ~140) |
| Tool calling | `generate(..., tools=, handlers=)` or `generate_with_tools(...)` |
| Provider/tool schema | `tool_runtime.ToolSpec`, `normalize_tools` |
| Generate payloads / triage | Consumers call `ai_manager.generate(...)` |

## FAILOVER BEHAVIOUR (verified)
- Active provider is retried `max_retries` times with exponential backoff (`2 ** attempt` seconds).
- Empty/`None` responses count as failures, not successes.
- On exhaustion it iterates every other provider in dict order; the first success **becomes** the new active provider for the rest of the process.
- Total failure returns `""` — callers must not treat empty string as valid JSON. All AI consumers must degrade gracefully (triage, evidence, bounty, planner, payloads).
- Context is fixed at construction from config; there is no hot reload.

## CONVENTIONS
- Class name: `<Vendor>Provider`; required method `generate(prompt: str, **kwargs) -> str`.
- Config gate: skip unless `ai_providers.<name>.enabled`; keys live in `config.yaml` only (gitignored).
- Never hardcode model names — read from config.
- Reuse `tool_runtime` instead of writing another tool loop.

## ANTI-PATTERNS
- Calling a provider constructor outside `AIProviderManager`.
- Adding a provider without the `config.example.yaml` block (silently never initialised).
- Assuming `requesty` works: `requesty_provider.py` exists and README advertises it, but `_initialize_providers` never instantiates it.
- Treating `generate()` returning `""` as a model answer.
- Reimplementing tool loops outside `tool_runtime`.

## NOTES
- OpenAI: `tools` + `tool_calls`; o-series skips tools.
- Claude: `tools` + `tool_use` / `tool_result` blocks.
- Both reject placeholder API keys.
- Tests: `tests/test_ai_tool_calling.py`, `tests/test_openai_claude_providers.py`, `tests/test_litellm_provider.py`.

