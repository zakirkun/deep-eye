# Configuration Reference

All Deep Eye behavior is controlled via `config/config.yaml`. The CLI is intentionally minimal.

## First-Time Setup

If no config file exists, Deep Eye runs an interactive setup wizard on first launch:

```bash
python deep_eye.py -u https://target.com
# Wizard prompts: provider, API key, model, threads, depth, scan mode, report format
# Writes config/config.yaml automatically
```

Or copy the example manually:
```bash
cp config/config.example.yaml config/config.yaml
```

## Configuration Sections

### ai_providers

Configure one or more AI providers. Deep Eye uses the provider specified in `scanner.ai_provider`.

```yaml
ai_providers:
  openai:
    enabled: true
    api_key: "sk-..."
    model: "gpt-4o"
    temperature: 0.7
    max_tokens: 2000
    timeout: 30

  claude:
    enabled: true
    api_key: "sk-ant-..."
    model: "claude-3-5-sonnet-20241022"
    temperature: 0.7
    max_tokens: 2000
    timeout: 30

  ollama:
    enabled: false
    base_url: "http://localhost:11434"
    model: "llama2"
    timeout: 60
```

Supported providers: `openai`, `claude`, `grok`, `ollama`, `gemini`, `openrouter`, `mistral`, `groq`, `lmstudio`, `litellm`

### scanner

```yaml
scanner:
  target_url: "https://target.com"
  default_threads: 5            # 1-50
  default_depth: 2              # crawl depth 1-10
  max_urls: 100
  timeout: 10                   # HTTP timeout (seconds)
  scan_url_timeout: 30
  user_agent: "Deep-Eye/1.4"
  follow_redirects: true
  verify_ssl: true
  max_retries: 3
  enable_recon: false
  full_scan: false
  quick_scan: false
  ai_provider: "openai"        # which provider to use
  oast_callback_url: ""
  proxy: ""
  custom_headers: {}
  cookies: {}
```

### vulnerability_scanner

```yaml
vulnerability_scanner:
  enabled_checks:
    - sql_injection
    - xss
    - command_injection
    - ssrf
    - xxe
    - path_traversal
    - csrf
    - open_redirect
    - cors_misconfiguration
    - security_misconfiguration
    - lfi
    - rfi
    - ssti
    - crlf_injection
    - host_header_injection
    - ldap_injection
    - xml_injection
    - insecure_deserialization
    - authentication_bypass
    - information_disclosure
    - sensitive_data_exposure
    - jwt_vulnerabilities
    - broken_authentication

  payload_generation:
    use_ai: true
    context_aware: true
    cve_database: false
    custom_wordlists: []
    use_payload_obfuscation: false

  testing:
    thorough_mode: false
    time_based_detection_delay: 5
    blind_injection_attempts: 3
```

### reporting

```yaml
reporting:
  enabled: true
  output_directory: "reports"
  output_filename: ""           # auto-generated if empty
  default_format: "html"        # html, pdf, json, sarif
  formats:                      # additional exports
    - junit
    - csv
    - xlsx
  xlsx_interactive_install: true
```

### compliance

```yaml
compliance:
  enabled: false
  frameworks:
    - pci_dss        # PCI-DSS v4.0
    - soc2           # SOC 2 Type II
    - iso_27001      # ISO 27001:2022
```

### ai_triage

```yaml
ai_triage:
  enabled: false
  drop_false_positives: true
  drop_threshold: 0.8          # confidence to drop (0.0-1.0)
  min_severity: "low"
```

### bug_bounty

```yaml
bug_bounty:
  enabled: false
  format: "markdown"
  min_severity: "medium"
  output_directory: "reports/bounty"
  one_file_per_vuln: true
```

### templates

```yaml
templates:
  enabled: false
  template_directories:
    - "templates/nuclei"
  tag_filters: []              # empty = all tags
  severity_filter: ""          # empty = all severities
```

### challenge_solver

```yaml
challenge_solver:
  enabled: false
  vendors:
    - "cloudflare"
    - "akamai"
  playwright_headless: true
  cookie_ttl_seconds: 1800
  timeout_seconds: 30
```

### intercepting_proxy

```yaml
intercepting_proxy:
  enabled: false
  required: false
  bind_host: "127.0.0.1"
  proxy_port: 8080
  mitmweb_port: 8081
```

### captcha

```yaml
captcha:
  enabled: false
  skip_protected: true
  vendors:
    - "recaptcha"
    - "hcaptcha"
    - "turnstile"
    - "arkose"
```

### login_replay

```yaml
login_replay:
  enabled: false
  macro_path: "config/login_macro.yaml"
  abort_on_fail: true
  recheck_interval_seconds: 300
```

### rag

```yaml
rag:
  enabled: false
  index_path: "data/rag_index"
  auto_rebuild: false
  top_k: 5
  min_score: 0.7
```

### websocket

```yaml
websocket:
  enabled: false
  test_origin_validation: true
  test_authentication: true
  test_injection_attacks: true
  test_dos_attacks: false
  test_rate_limiting: true
  test_tls_verification: true
  connection_timeout: 10
  max_message_size: 65536
```

### ml_detection

```yaml
ml_detection:
  enabled: false
  baseline_samples: 50
  anomaly_threshold: 0.7
  features:
    - response_time
    - status_code
    - content_length
    - error_keywords
  save_model: true
  model_path: "data/ml_model.pkl"
```

### osint

```yaml
osint:
  enabled: false
  google_dorking: true
  email_harvesting: true
  metadata_extraction: true
  social_media_check: true
  breach_database_check: true
  certificate_transparency: true
  github_search: true
  pastebin_search: true
  max_search_results: 50
  timeout: 15
```

### payload_obfuscation

```yaml
payload_obfuscation:
  enabled: false
  techniques:
    - base64
    - url_encode
    - double_url_encode
    - unicode
    - hex
    - random_case
    - comment_insertion
    - string_concatenation
    - null_byte
    - char_substitution
    - multiple_encoding
  waf_bypass_mode: false
```

### reconnaissance

```yaml
reconnaissance:
  enabled_modules:
    - dns_enumeration
    - whois_lookup
    - technology_detection
    - ssl_analysis
    - osint_gathering
  subdomain_sources:
    - certificate_transparency
    - dns_bruteforce
  port_scan:
    common_ports: [80, 443, 8080, 8443, 3000, 5000, 8000, 9090]
    scan_timeout: 5
```

### rate_limiting

```yaml
rate_limiting:
  enabled: true
  requests_per_second: 5
  burst_size: 10
  delay_on_error: 3
```

### proxy

```yaml
proxy:
  enabled: false
  http: "http://127.0.0.1:8080"
  https: "http://127.0.0.1:8080"
```

### scope

```yaml
scope:
  enabled: false
  allowed_hosts: []            # empty = target host only
  excluded_paths:
    - "/logout"
    - "/admin"
  allowed_ports: [80, 443, 8080, 8443]
```

### advanced

```yaml
advanced:
  enable_javascript_rendering: false
  screenshot_enabled: false
  enable_browser_use_ai: false
  browser_timeout: 30
  ua_rotation: false
  jitter_min: 0
  jitter_max: 0
  proxy_pool: []
  exclude_extensions: [".jpg", ".png", ".gif", ".css", ".js", ".ico"]
  exclude_patterns: []
  max_response_size: 10485760  # 10MB
  custom_dns_servers: []
```

### experimental

```yaml
experimental:
  enable_subdomain_scanning: false
  aggressive_subdomain_enum: false
  max_subdomains_to_scan: 50
  enable_cve_matching: false
  cve_database_path: "data/cve_intelligence.db"
  auto_update_cve_db: false
  cve_lookback_days: 365
```

### notifications

```yaml
notifications:
  enabled: false
  notify_on_critical: true
  email:
    enabled: false
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    username: ""
    password: ""
    from_address: ""
    recipients: []
  slack:
    enabled: false
    webhook_url: ""
  discord:
    enabled: false
    webhook_url: ""
```

### secrets_scanner

```yaml
secrets_scanner:
  enabled: true
  scan_response_body: true
  scan_response_headers: true
  scan_javascript_files: true
  check_git_exposure: true
  enable_entropy_detection: true
  min_entropy: 4.5
  min_length: 8
```

### logging

```yaml
logging:
  level: "INFO"                # DEBUG, INFO, WARNING, ERROR
  log_to_file: true
  log_file: "logs/deep_eye.log"
  max_file_size: 10485760      # 10MB
  backup_count: 5
```

### database

```yaml
database:
  enabled: true
  type: "sqlite"
  path: "data/deep_eye.db"
  auto_cleanup_days: 30
```

### plugin_manager

```yaml
plugin_manager:
  enabled: false
  plugin_directory: "plugins"
  auto_load: true
```

## Environment Variable Substitution

Config values support `${ENV_VAR}` and `${ENV_VAR:-default}` syntax:

```yaml
ai_providers:
  openai:
    api_key: "${OPENAI_API_KEY}"
    model: "${OPENAI_MODEL:-gpt-4o}"
```

## CLI Overrides

| CLI Flag | Overrides |
|----------|-----------|
| `-u URL` | `scanner.target_url` |
| `--formats` | `reporting.formats` |
| `-v` | Sets verbose logging |
