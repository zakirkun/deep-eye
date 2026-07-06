# Architecture

## Overview

Deep Eye is a config-driven, multi-threaded penetration testing tool. The scan pipeline flows through distinct phases, each orchestrated by `ScannerEngine`.

## Scan Pipeline

```
CLI (deep_eye.py)
 │
 ▼
ScannerEngine.scan()
 │
 ├─ 1. INITIALIZATION ─── PentestStateManager setup
 │
 ├─ 2. RECONNAISSANCE ─── ReconEngine (DNS, WHOIS, OSINT, tech detection)
 │
 ├─ 3. SUBDOMAIN_DISCOVERY ─── SubdomainScanner (CT logs, DNS brute, liveness)
 │                              [experimental, config-gated]
 │
 ├─ 4. CRAWLING ─── ThreadPoolExecutor BFS crawl
 │                  URL filtering (extensions, patterns, scope)
 │
 ├─ 5. VULNERABILITY_SCANNING ─── Per-URL parallel scan:
 │     │
 │     ├─ AIPayloadGenerator.generate_payloads(context)
 │     ├─ VulnerabilityScanner.scan() ─── 45+ checks
 │     ├─ SmartBrowserTester ─── Playwright/Browser Use AI
 │     ├─ PluginManager ─── Custom plugins
 │     ├─ SecretsDetector ─── Response secret scanning
 │     └─ CVEMatcher.enrich_vulnerability()
 │
 ├─ 6. POST-SCAN ENRICHMENT
 │     ├─ CVERagIndex ─── Semantic CVE search (ChromaDB)
 │     ├─ ComplianceMapper ─── PCI-DSS/SOC2/ISO 27001
 │     ├─ AITriage ─── False-positive filtering
 │     └─ BountyWriter ─── Bug bounty report generation
 │
 ├─ 7. REPORTING ─── ReportGenerator (HTML/PDF/JSON/SARIF/JUnit/CSV/XLSX)
 │
 └─ 8. NOTIFICATIONS ─── Email/Slack/Discord alerts
```

## Layer Responsibilities

### `core/` — Orchestration

| File | Role |
|------|------|
| `scanner_engine.py` | Main orchestrator. ThreadPoolExecutor crawl + scan. Coordinates all phases. |
| `vulnerability_scanner.py` | 45+ vulnerability check methods. Each returns standardized result dicts. |
| `ai_payload_generator.py` | Context-aware payload generation via AI providers. WAF/tech detection, caching. |
| `report_generator.py` | Multi-format report dispatch. Jinja2 HTML, ReportLab PDF, SARIF, delegates to exports/. |
| `pentest_state_manager.py` | Phase tracking, live stats, attack progress, time tracking. |
| `scan_diff.py` | Compare two scan JSONs. URL normalization, identity matching, severity change detection. |
| `subdomain_scanner.py` | CT log queries, DNS bruteforce, liveness checks. |
| `plugin_manager.py` | Auto-discovery and loading of plugins from `plugins/` directory. |

### `ai_providers/` — AI Abstraction

All providers implement: `generate(prompt, **kwargs) -> str`

`provider_manager.py` handles: provider selection, failover, retry logic, API key management.

Providers: OpenAI, Claude, Grok, OLLAMA, Gemini, OpenRouter, Requesty, Mistral, Groq, LM Studio, LiteLLM.

### `modules/` — Specialized Testers

Each module follows the pattern:
- Constructor: `__init__(self, http_client, config)`
- Entry point: `scan(self, url) -> List[Dict]`
- Returns standardized vulnerability result dicts

**33 modules** organized by capability:

| Category | Modules |
|----------|---------|
| Web Vulns | api_security, authentication, business_logic, file_upload, websocket |
| Injection | nosql_injection, http_smuggling, log4shell, prototype_pollution |
| Auth/Session | oauth_testing, saml_attacks, captcha_detection, login_replay |
| Infrastructure | port_scanner, directory_bruteforce, subdomain_takeover, cache_poisoning |
| Detection | ml_detection, secrets_scanner, secret_scanning, reconnaissance |
| Advanced | race_condition, mass_assignment, payload_obfuscation |
| AI-Powered | ai_triage, cve_intelligence, template_engine |
| Automation | browser_automation, challenge_solver, intercepting_proxy |
| Collaboration | collaboration, reporting |

### `utils/` — Shared Infrastructure

| Component | Role |
|-----------|------|
| `http_client.py` | Requests wrapper with retry, proxy, headers, cookies, rate limiting |
| `config_loader.py` | YAML config loading with defaults and validation |
| `logger.py` | Loguru-based logging with file rotation |
| `parser.py` | URL parsing, HTML extraction, form detection, tech fingerprinting |
| `notification_manager.py` | Email/Slack/Discord dispatch |
| `scope_manager.py` | Allowed hosts, excluded paths, port filtering |
| `oast_server.py` | Out-of-band application security testing callbacks |
| `ai_summary_generator.py` | AI-generated executive summaries |
| `exports/` | JUnit XML, CSV, XLSX builders |
| `compliance/` | Framework mapper + JSON control definitions |

## Key Design Patterns

### Config-Driven Architecture
Nearly all behavior is controlled via `config/config.yaml`. The CLI provides only target URL override, config path, verbose flag, and diff mode. Modules read their own config sections.

### Standardized Vulnerability Result
```python
{
    "type": "sql_injection",
    "severity": "critical",  # critical/high/medium/low/info
    "url": "https://target.com/page?id=1",
    "parameter": "id",
    "payload": "' OR 1=1--",
    "evidence": "MySQL error in response...",
    "remediation": "Use parameterized queries",
    "cve_references": ["CVE-2024-1234"],
    # Added by enrichment pipeline:
    "compliance": {"PCI-DSS": [{"control_id": "6.5.1", ...}]},
    "triage_reason": "...",
    "false_positive": false,
    "confidence": 0.95,
    "bounty_report": "..."
}
```

### Threading Model
- `ScannerEngine` uses `ThreadPoolExecutor` (configurable 1-50 threads)
- Crawling: parallel BFS with URL deduplication
- Scanning: parallel per-URL vulnerability testing
- Subdomain scanning: parallel liveness checks

### AI Provider Failover
`ProviderManager` tries the configured primary provider, falls back to alternatives on failure. Retry with exponential backoff.

### Post-Scan Enrichment Pipeline
After all URLs are scanned, results pass through:
1. RAG CVE enrichment (semantic similarity search)
2. Compliance mapping (control ID lookup)
3. AI triage (false-positive scoring)
4. Bounty report generation (per-vuln markdown)

Each step is config-gated and operates in-place on the results list.

### Challenge Solving
When `ChallengeDetector` identifies a Cloudflare/Akamai interstitial, `ChallengeSolver` launches headless Chromium, waits for JS challenge completion, extracts cookies, and injects them into the HTTP client session. Cookies are cached with configurable TTL.

## Data Storage

| Store | Path | Purpose |
|-------|------|---------|
| Scan results DB | `data/deep_eye.db` | SQLAlchemy/SQLite scan history |
| CVE intelligence | `data/cve_intelligence.db` | NVD/MITRE CVE data, exploits, tech mappings |
| RAG vector index | `data/rag_index/` | ChromaDB embeddings for CVE semantic search |
| Reports | `reports/` | Generated output (HTML, PDF, JSON, etc.) |
| Logs | `logs/` | Rotating log files |

## Configuration Sections

Full reference: `config/config.example.yaml`

Top-level sections: `ai_providers`, `scanner`, `vulnerability_scanner`, `websocket`, `ml_detection`, `osint`, `payload_obfuscation`, `api_security`, `business_logic`, `authentication`, `file_upload`, `collaboration`, `reconnaissance`, `reporting`, `compliance`, `rag`, `ai_triage`, `bug_bounty`, `captcha`, `login_replay`, `templates`, `challenge_solver`, `intercepting_proxy`, `logging`, `database`, `rate_limiting`, `proxy`, `advanced`, `scope`, `oast`, `passive_mode`, `experimental`, `plugin_manager`, `notifications`, `secrets_scanner`
