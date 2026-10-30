# TEMPLATE ENGINE KNOWLEDGE BASE

**Scope:** Nuclei-style YAML template parser, matcher, and executor.

## OVERVIEW
Declarative vulnerability checks via YAML. Templates define HTTP requests, matchers (status, word, regex, size, dsl), and extractors. Executor substitutes `{{BaseURL}}`, `{{Hostname}}`, `{{RandomString}}`, fires requests, and emits standard vuln dicts on match.

## STRUCTURE
```
modules/template_engine/
├── __init__.py      # Public API exports
├── parser.py        # YAML parse + schema validation (id, info, http, matchers)
├── loader.py        # Directory walk, tag/severity filtering
├── matcher.py       # evaluate_matchers, run_extractors
└── executor.py      # TemplateExecutor.run() → List[vuln dict]

templates/
├── exposures/
└── misconfig/
```

## WHERE TO LOOK
| Task | File | Notes |
|------|------|-------|
| Parse / validate | `parser.py` | `TemplateError` on bad schema; required: `id`, `info.name`, `info.severity`, `http` list |
| Load + filter | `loader.py` | `load_templates(dirs, tag_filters, severity_filter)` |
| Match logic | `matcher.py` | Types: `status`, `word`, `regex`, `size`, `dsl`. Condition: `and` / `or`. Part: `header`, `body`, `response`, `all` |
| Execute | `executor.py` | `TemplateExecutor(http_client).run(template, target_url)` |
| Var substitution | `executor.py` | `substitute_vars()` replaces `{{BaseURL}}`, `{{Hostname}}`, `{{RandomString}}` |
| Tests | `tests/test_template_engine.py` | 250 LOC — parser, matcher, extractor, executor, loader, var substitution |

## CONVENTIONS
- Template YAML lives under repo `templates/`, not inside this package. The shipped catalog is **5 files**: `exposures/` (backup-file, env-file, git-config, swagger-ui) and `misconfig/` (cors-wildcard).
- Config block: `templates.enabled`, `template_directories`, `tag_filters`, `severity_filter`.
- Severity must be one of `critical`, `high`, `medium`, `low`, `info`.
- Matchers array + `matchers-condition` (`and`/`or`). Extractors run only when matchers pass.
- Executor returns standard vuln dicts with `type`, `severity`, `url`, `evidence`, `cve_references`, `template_id`.
- `http_client` is the shared `utils/http_client.HTTPClient` instance.

## ANTI-PATTERNS
- Do not store templates inside `modules/template_engine/`.
- Do not add new matcher types without updating `VALID_MATCHER_TYPES` and `_MATCHERS`.
- Do not skip `TemplateError` handling in loaders; bad YAML must be logged and skipped, not crashed.
- Do not break vuln dict key contract (`type`, `url`, `severity`) because reports, exports, and diff depend on them.
