# Configuration Reference

All scan behavior is controlled by **`config/config.yaml`**.  
Copy from **`config/config.example.yaml`** (source of truth for keys).

```bash
cp config/config.example.yaml config/config.yaml
```

CLI only overrides a few things: target URL, config path, verbose, formats, diff, retest-new, NL scope.

---

## First-time setup

Missing config → interactive wizard (`utils/onboard.py`) writes `config.yaml`.

Env substitution in YAML: `${VAR}` and `${VAR:-default}` (`utils/config_loader.py`).

---

## `ai_providers`

Enable **one or more** providers. Active provider: `scanner.ai_provider`.

Supported: `openai`, `claude`, `grok`, `ollama`, `gemini`, `openrouter`, `orcarouter`, `mistral`, `groq`, `lmstudio`, `litellm`, `nvidia_nim`, `atlascloud`.

Each block: `enabled`, `api_key` (if needed), `model`, `temperature`, `max_tokens`, `timeout`, optional `base_url`.

Providers implement `generate(prompt, **kwargs) -> str`. Manager retries and failovers; empty responses are treated as failure.

---

## `scanner`

| Key | Notes |
|-----|--------|
| `target_url` | Default target (CLI `-u` overrides) |
| `default_threads` | 1–50 |
| `default_depth` | Crawl depth 1–10 |
| `max_urls` | Cap discovered URLs |
| `timeout` / `scan_url_timeout` | HTTP / per-URL scan timeout |
| `enable_recon` / `full_scan` / `quick_scan` | Modes |
| `ai_provider` | Name under `ai_providers` |
| `oast_callback_url` | Blind SSRF/XXE callback (preferred if set) |
| `proxy`, `custom_headers`, `cookies` | Transport |

---

## `vulnerability_scanner`

### `enabled_checks`

List of check names. Built-ins + modules. Examples:

**Classic:** `sql_injection`, `xss`, `ssrf`, `xxe`, `jwt_vulnerabilities`, `cors_misconfiguration`, …

**Modules:** `api_security`, `nosql_injection`, `http_smuggling`, `directory_bruteforce`, `port_scanner`, …

**Feature pack:** `cors_csp`, `jwt_deep`, `graphql_deep`, `idor`, `stored_xss`, `email_injection`, `cache_deception`, `h2_smuggle`, `supply_chain_js`, `waf_fingerprint`, `ssrf_cloud`

Full list is maintained in `config.example.yaml`.

### `payload_generation`

`use_ai`, `context_aware`, `cve_database`, `use_payload_obfuscation`, …

---

## Pipeline features

### `openapi`

```yaml
openapi:
  enabled: false
  source: ""   # file path or URL
```

Seeds crawl with expanded OpenAPI/Swagger endpoints.

### `auth_session`

```yaml
auth_session:
  enabled: false
  default_role: "user"
  store_path: "data/auth_sessions.json"
  roles:
    user: { cookies: {}, headers: {} }
```

### `ai_planner` / `evidence_summary` / `fp_replay`

```yaml
ai_planner:
  enabled: false
  use_ai: true
  budget_seconds: 600
  max_urls: 50
  threads: 5

evidence_summary:
  enabled: false
  min_severity: high
  max_findings: 15

fp_replay:
  enabled: false
```

### `ai_triage` / `bug_bounty`

```yaml
ai_triage:
  enabled: false
  drop_false_positives: false
  drop_threshold: 0.8
  min_severity: high

bug_bounty:
  enabled: false
  format: hackerone   # hackerone | bugcrowd | generic
  min_severity: high
  output_directory: reports/bounty
```

### `templates` / `challenge_solver` / `login_replay` / `captcha` / `intercepting_proxy`

```yaml
templates:
  enabled: false
  template_directories: ["templates"]
  tag_filters: []
  severity_filter: []

challenge_solver:
  enabled: false
  vendors: [cloudflare, akamai]

login_replay:
  enabled: false
  macro_path: config/login_macro.json
  abort_on_fail: true

captcha:
  enabled: false
  skip_protected: true

intercepting_proxy:
  enabled: false
  required: false
  proxy_port: 8080
  mitmweb_port: 8081
```

### `rag` / `compliance` / `cve_intelligence`

```yaml
rag:
  enabled: false
  index_path: data/cve_rag_index.pkl
  auto_rebuild: true
  top_k: 5
  min_score: 0.15

compliance:
  enabled: false
  frameworks: [pci_dss, soc2, iso_27001]

cve_intelligence:
  database_path: data/cve_intelligence.db
```

### `oast` / `tls_evasion` / `scope`

```yaml
oast:
  enabled: false
  host: "0.0.0.0"
  port: 9999

tls_evasion:
  enabled: false
  impersonate: "chrome120"   # requires: pip install curl_cffi

scope:
  enabled: false
  allowed_hosts: ["*.example.com"]
  excluded_paths: ["/logout"]
  allowed_ports: [80, 443, 8080]
  path_allow: ["/api/*"]     # optional allowlist of path patterns
```

NL CLI: `--scope-nl "only /api/* no /logout host target.com ports 80,443"` merges into `scope`.

### `reporting`

```yaml
reporting:
  enabled: true
  output_directory: reports
  default_format: html
  formats: []              # e.g. [html, json, junit]
  dedupe: true             # fingerprint collapse
  xlsx_interactive_install: true
```

### `advanced`

Browser automation, timeouts, UA rotation, jitter, `proxy_pool`, `exclude_extensions`, `exclude_patterns`, `max_response_size`.

### `experimental`

```yaml
experimental:
  enable_subdomain_scanning: false
  enable_cve_matching: false
  cve_database_path: data/cve_intelligence.db
```

### `plugin_manager` / `plugins` / `notifications` / `rate_limiting` / `database` / `logging`

See `config.example.yaml` for full fields. Plugins: `plugin_manager.enabled: true`, per-plugin `plugins.<id>.enabled`.

### Feature knobs

```yaml
idor: { max_swaps: 5 }
jwt_deep: { weak_secrets: ["secret", "password"] }
stored_xss: { marker: "deepeye_sxss_" }
osint: { hibp_api_key: "" }
```

---

## Environment notes

- Prefer **not** committing real `config.yaml` (secrets).
- `chmod 600 config/config.yaml` on Unix when keys present.
- Custom DNS cannot be set per-request in `requests`; use OS DNS tools.

## Related

- [QUICKSTART.md](QUICKSTART.md)  
- [MODULES.md](MODULES.md)  
- [SCAN_FLOW.md](SCAN_FLOW.md)  
