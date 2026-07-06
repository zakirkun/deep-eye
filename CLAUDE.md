# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Deep Eye is an AI-driven penetration testing tool. It orchestrates multiple AI providers for payload generation, scans targets for 45+ vulnerability types, and produces professional reports. Python 3.8+, MIT license, v1.4.0 (Code Name: Hanzou).

## Commands

```bash
# Setup
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml

# Browser automation (optional)
pip install playwright && playwright install chromium

# Run
python deep_eye.py -u https://example.com
python deep_eye.py -c config/config.yaml
python deep_eye.py -u https://example.com -v        # verbose
python deep_eye.py -u https://example.com --no-banner

# CVE database update
python scripts/update_cve_database.py

# Build RAG index for CVE intelligence
python scripts/build_cve_rag_index.py

# Tests
pytest
pytest tests/test_litellm_provider.py -v            # single test file
pytest tests/test_export_formats.py -v              # export formats
pytest tests/test_compliance_mapping.py -v          # compliance
pytest tests/test_scan_diff.py -v                   # scan diffing
pytest tests/test_rag_index.py -v                   # RAG/CVE index
pytest tests/test_ai_triage.py -v                   # AI triage
pytest tests/test_captcha_detection.py -v           # CAPTCHA detection
pytest tests/test_template_engine.py -v             # Nuclei-style templates
pytest tests/test_challenge_solver.py -v            # CF/Akamai solver
pytest tests/test_intercepting_proxy.py -v          # intercepting proxy
python tests/e2e_litellm.py                         # e2e test (requires API key)
```

## Architecture

**Scan Flow**: CLI → `ScannerEngine` → Web Crawler → URL Discovery → `AIPayloadGenerator` → `VulnerabilityScanner` → `ReportGenerator`

### Layers

| Layer | Purpose |
|-------|---------|
| `core/` | Orchestration: scanner engine, vuln scanner, AI payload gen, report gen, state manager, subdomain scanner, plugin manager, scan diff |
| `ai_providers/` | Unified interface to OpenAI, Claude, Grok, OLLAMA, Gemini, Groq, Mistral, OpenRouter, Requesty, LiteLLM, LM Studio. All implement `generate(prompt, **kwargs) -> str` |
| `modules/` | Specialized testers (see Module Categories below) |
| `utils/` | http_client, config_loader, parser, logger, notification_manager, exports (JUnit/CSV/XLSX), compliance mapper, scope_manager, oast_server, ai_summary_generator |
| `scripts/` | CVE database updater, RAG index builder, notification tester |

### Module Categories

**Original**: api_security, authentication, browser_automation, business_logic, cve_intelligence, file_upload, ml_detection, payload_obfuscation, reconnaissance, reporting, secrets_scanner, websocket, collaboration

**v1.4.0+**: nosql_injection, http_smuggling, race_condition, log4shell, mass_assignment, prototype_pollution, oauth_testing, cache_poisoning, subdomain_takeover, directory_bruteforce, port_scanner, saml_attacks, secret_scanning

**Hanzou-era**: ai_triage (AI false-positive filtering + bounty report writer), captcha_detection (CAPTCHA detect + login macro replay), template_engine (Nuclei-style YAML templates), challenge_solver (CF/Akamai challenge bypass), intercepting_proxy (mitmproxy-based interceptor)

### Key Design Decisions

- **Config-driven**: Almost all behavior controlled via `config/config.yaml`. CLI is intentionally minimal (target URL, config path, verbose flag).
- **Multi-threaded scanning**: `ScannerEngine` uses `ThreadPoolExecutor` for concurrent URL scanning. Thread count configurable 1-50.
- **Browser automation is hybrid**: Playwright handles deterministic tests (SQLi, DOM XSS, clickjacking). Browser Use AI (experimental, disabled by default) handles intelligent tests. Automatic fallback to Playwright when AI unavailable.
- **AI provider abstraction**: All providers share `generate()` interface. `provider_manager.py` handles failover/retry.
- **State tracking**: `PentestStateManager` tracks phases (RECON → CRAWLING → VULNERABILITY_SCAN → REPORTING) with per-attack progress.
- **Export formats**: JUnit XML (CI integration), CSV, XLSX via `utils/exports/`. Configured in `reporting.formats` list.
- **Compliance mapping**: Maps findings to PCI-DSS v4, SOC2 CC, ISO 27001:2022 via `utils/compliance/`. Framework JSON definitions in `utils/compliance/frameworks/`.
- **Scan diffing**: `core/scan_diff.py` compares two scan results to show new/fixed/unchanged findings. Rendered via `utils/exports/diff_renderer.py`.

### Vulnerability Result Format

All scanners return dicts with: `type`, `severity` (critical/high/medium/low/info), `url`, `parameter`, `payload`, `evidence`, `remediation`, optional `cve_references`.

## Development Patterns

### Adding a vulnerability check
1. Add `_check_new_vuln(self, url, payloads)` method to `core/vulnerability_scanner.py`
2. Register in `scan()` with state manager start/end calls
3. Add to `config.example.yaml` `enabled_checks` list

### Adding an AI provider
1. Create class in `ai_providers/` with `generate(prompt, **kwargs) -> str`
2. Register in `provider_manager.py` `_initialize_providers()`
3. Add config section to `config.example.yaml`

### Adding a module
1. Create directory in `modules/` with `__init__.py`
2. Module class takes `(http_client, config)` in constructor
3. Expose `scan(url) -> List[Dict]` following the vulnerability result format
4. Register in scanner engine or plugin manager

### Adding a plugin
Create class in `plugins/` with `__init__(self, http_client, config)` and `scan(self, url) -> List[Dict]`. Enable via `plugin_manager.enabled: true` in config.

### Adding an export format
1. Create builder in `utils/exports/` following `junit_builder.py` pattern
2. Builder takes scan results list, returns bytes or string
3. Register in `utils/exports/__init__.py`

## Important Context

- **Authorized testing only** — never scan without explicit permission
- **Windows primary dev environment** — uses ReportLab (not WeasyPrint) for PDF, `pathlib.Path` for cross-platform paths
- **Virtual env** at `.deep-venv/` (gitignored)
- **SQLite databases**: `data/deep_eye.db` (scan results), `data/cve_intelligence.db` (CVE data)
- **Experimental features** gated behind `experimental.*` config flags: CVE matching, subdomain scanning
- **Notifications** (v1.3.0): Email/Slack/Discord via `utils/notification_manager.py`
- **RAG index**: ChromaDB-based CVE search in `modules/cve_intelligence/rag_index.py`, built via `scripts/build_cve_rag_index.py`
- **AI triage**: Uses LiteLLM for false-positive classification and bounty report generation (`modules/ai_triage/`)
- **Template engine**: Nuclei-compatible YAML templates in `modules/template_engine/`, supports matchers/extractors/conditions
- **Deferred**: async/httpx migration (would require full rewrite — current code uses synchronous `requests`)
