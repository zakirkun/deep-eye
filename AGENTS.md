# PROJECT KNOWLEDGE BASE

**Generated:** 2026-10-23  
**Commit:** `8125ca0`  
**Branch:** dev/hanzou  
**Version:** 1.4.0 Hanzou

## OVERVIEW

AI-driven pentest tool. Multi-provider AI payloads → crawl/OpenAPI seed → per-URL checks → dedupe → RAG/compliance/triage → reports. Sync `requests` + `ThreadPoolExecutor`; **not async** despite `aiohttp`/`httpx`/`playwright` being installed (async rewrite deferred, Group I).

Scale: 232 `.py` files, ~30k LOC, 64 packages under `modules/`. `setup.py` declares `python_requires>=3.8`; the local venv currently runs 3.14 — keep new code 3.8-compatible (no `match`, `X | Y` annotations at runtime).

## STRUCTURE

```
deep-eye/
├── deep_eye.py          # CLI: -u/-c/-v/--formats/--diff*/--retest-new/--scope-nl
├── core/                # ScannerEngine, VulnerabilityScanner, payloads, reports, plugins
├── ai_providers/        # generate() + AIProviderManager
├── modules/             # Attack + pipeline modules (see docs/MODULES.md)
├── utils/               # HTTP, scope, OAST, exports, fingerprint, nl_scope
├── config/              # config.example.yaml = source of truth
├── templates/           # Nuclei-style YAML (exposures/, misconfig/)
├── plugins/             # PluginBase drop-ins
├── .agents/skills/      # Skills: workflows + vulnerabilities/payloads/tools (loader: proxy/system.py)
├── proxy/               # system.py skill discovery → <available_skills>
├── scripts/             # CVE DB + RAG index
├── tests/               # pytest (+ e2e_litellm.py script)
├── docs/                # User docs (CONFIGURATION, MODULES, ARCHITECTURE, …)
├── data/                # SQLite + auth_sessions + RAG pickle
└── reports/             # Scan output (gitignored)
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| CLI / retest / NL scope | `deep_eye.py` | `--retest-new`, `--scope-nl` |
| Scan lifecycle | `core/scanner_engine.py` | Crawl, OpenAPI, planner, post-process |
| Per-URL checks | `core/vulnerability_scanner.py` | `_check_*` + `_feature_testers` |
| Feature modules | `modules/<name>/` | cors_csp, jwt_deep, idor, … |
| Dedupe fingerprints | `utils/finding_fingerprint.py` | `reporting.dedupe` |
| NL scope | `utils/nl_scope.py` | → `scope` config |
| OpenAPI seed | `modules/openapi_ingest/` | `openapi.enabled` |
| Auth roles | `modules/auth_session/` | multi-cookie roles |
| AI planner / evidence / FP replay | `modules/ai_planner/`, `evidence_summary/`, `fp_replay/` | post-scan pipeline |
| Templates | `modules/template_engine/` + `templates/` | config `templates` |
| Challenge / login / captcha / proxy | respective `modules/*` | config-gated in engine |
| Exports | `utils/exports/` | junit/csv/xlsx/diff |
| Compliance mapping | `utils/compliance/` | `frameworks/*.json` (PCI/SOC2/ISO, 42 mappings each) |
| CVE matching / RAG | `modules/cve_intelligence/` | `cve_matcher.py`, `rag_index.py` (TF-IDF pickle) |
| Presence detection | `core/injection_surfaces.py` | Query/form/JSON/cookie/header/path surfaces |
| Agent skills | `.agents/skills/` | workflows + vulnerabilities/payloads/tools; loader `proxy/system.py` |
| Full knobs | `config/config.example.yaml` | 71 `enabled_checks` entries |

## CODE MAP

Refs = occurrence count across `.py` (grep). No Python LSP server is installed here (`basedpyright`/`pyright`/`ty` missing), so true reference centrality is unmeasured — re-derive with `lsp_find_references` after installing one.

| Symbol | Location | Refs | Role |
|--------|----------|------|------|
| `VulnerabilityScanner` | `core/vulnerability_scanner.py` | 23 | Per-URL checks; `_feature_testers` dispatch |
| `CVERagIndex` | `modules/cve_intelligence/rag_index.py` | 20 | TF-IDF pickle index (no ChromaDB) |
| `AIProviderManager` | `ai_providers/provider_manager.py` | 19 | Failover `generate()` |
| `AITriage` | `modules/ai_triage/triage.py` | 15 | FP filtering, in-place list mutation |
| `enrich_vulnerabilities` | `utils/compliance/mapper.py` | 12 | Adds `compliance` key |
| `ScannerEngine` | `core/scanner_engine.py` | 11 | Lifecycle owner |
| `TemplateExecutor` | `modules/template_engine/executor.py` | 9 | Nuclei YAML → vuln dicts |
| `run_tool_loop` | `ai_providers/tool_runtime.py` | 9 | Multi-round tool calling |
| `main` | `deep_eye.py` | — | CLI, onboard, retest filter |
| `AIPayloadGenerator` | `core/ai_payload_generator.py` | — | AI/static payloads + OAST URL |
| `ReportGenerator` | `core/report_generator.py` | — | 7 formats, one `generate()` switch |
| `HTTPClient` | `utils/http_client.py` | 6 | Shared client + TokenBucket |
| `dedupe_findings` | `utils/finding_fingerprint.py` | 5 | Collapse dupes |
| `ScopeManager` | `utils/scope_manager.py` | 7 | Host/path/port allow |
| `parse_nl_scope` | `utils/nl_scope.py` | 4 | NL → scope dict |

**Flow:** CLI → engine → (login) → recon? → mobile? → crawl + OpenAPI? → planner? → scan_url (checks) → dedupe → FP replay → evidence summary → RAG → compliance → triage → bounty → report → checkpoint. Note mobile runs **before** crawl; subdomain scan runs between recon and mobile.

## CONVENTIONS

- Config-driven; extend YAML not CLI for scan knobs (CLI only thin flags above).
- Vuln dict: `type`, `severity`, `url`, `parameter`, `payload`, `evidence`, `remediation` (+ optional `cve_references`, `fingerprint`, `compliance`, `rag_matched`).
- Module: `(http_client, config)`, `scan(url, context=None) -> List[Dict]`. **Reversed in core**: `VulnerabilityScanner(config, http_client)`.
- Three registration paths, pick by weight: 23 `_check_*` methods in `vulnerability_scanner.py`; 27 lazy-imported `_feature_testers` (`_specs` tuple, import failures log-and-skip); 5 `_init_extra_module_testers` in `scanner_engine.py` (dirb/port/saml/takeover/cache-poison).
- Adding a check requires the `enabled_checks` YAML entry — dispatch checks the list at call time, not just construction.
- Paths: `pathlib.Path`. PDF: ReportLab. Venv: `.deep-venv/`.
- PowerShell is the default shell here; `cp`/`source` in docs are bash-only.

## ANTI-PATTERNS

- Unauthorized targets.
- Full async rewrite without dedicated Group I branch.
- WeasyPrint as default PDF (GTK missing on Windows).
- Inventing result keys that break report/export/diff.
- Skipping `enabled_checks` / config gates.
- Committing secrets in `config.yaml` (gitignored — never un-ignore).
- Growing `vulnerability_scanner.py` (already 1597 lines) instead of new `modules/`.
- Importing `ScannerEngine` from a tester module (cycle).
- Merging `secrets_scanner` / `secret_scanning` — they are distinct packages.
- Storing Nuclei templates inside `modules/template_engine/` (they live in `templates/`).

## COMMANDS

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt        # pytest, pytest-cov, ruff
cp config/config.example.yaml config/config.yaml   # PowerShell: Copy-Item
python deep_eye.py -u https://example.com --scope-nl "only /api/*" --retest-new baseline.json
python deep_eye.py --diff baseline.json current.json --diff-format html
pytest tests/test_features_1_19.py -v
python scripts/update_cve_database.py
python scripts/build_cve_rag_index.py
```

Windows install: `.\scripts\install.ps1` (creates `.deep-venv/`).

## GOTCHAS

- `openpyxl` is **not** in `requirements.txt`; `utils/exports/xlsx_builder.py` lazy-`pip install`s it on first `xlsx` export. It prompts on a TTY and silently fails otherwise, so `--formats xlsx` breaks in CI unless you preinstall it. (`scikit-learn` **is** declared, but `rag_index._ensure_sklearn()` has the same runtime-install fallback.)
- `ai_providers/requesty_provider.py` exists but is **not** registered in `provider_manager._initialize_providers`. README lists `requesty` as supported — it is not reachable.
- No `pyproject.toml` / `pytest.ini` / `conftest.py`. `ruff` is installed but has no config, so its defaults apply.
- 33 of 34 test files bootstrap with `sys.path.insert(0, REPO_ROOT)`; there is no package-level `conftest.py`. Follow that pattern when adding tests.
- Local venv is Python 3.14 while `setup.py` promises `>=3.8`. Don't add 3.10+ syntax.
- `modules/cve_intelligence/` has ~2.8k LOC; `cve_scraper.py` alone is 1725 — the hotspot.
- `templates/` holds only 5 YAML files (4 exposures, 1 misconfig); the "Nuclei-style template engine" surface is real but the shipped catalog is thin.
- `modules/reporting/` and `modules/collaboration/` are unreachable from any scan path (only `examples/demo_v1.2.0.py` imports them). Don't assume a module under `modules/` is live.

## NOTES

- Child AGENTS.md: `core/`, `modules/`, `utils/`, `tests/`, `ai_providers/`, plus `modules/{cve_intelligence,reconnaissance,template_engine,ai_triage,frida_mobile}/` and `utils/exports/`.
- User docs: `docs/CONFIGURATION.md`, `MODULES.md`, `ARCHITECTURE.md`, `QUICKSTART.md`, `SCAN_FLOW.md`, `SKILLS.md`.
- See `CLAUDE.md` for agent-oriented development patterns; it is accurate on the RAG stack (TF-IDF + pickle). Only the older `modules/cve_intelligence/AGENTS.md` claimed ChromaDB — that claim was wrong and has been corrected.
