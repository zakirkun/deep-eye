# Quick Start Guide

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure

```bash
cp config/config.example.yaml config/config.yaml
```

Edit `config/config.yaml` and add at least one AI provider API key:

```yaml
ai_providers:
  openai:
    enabled: true
    api_key: "sk-your-key-here"
    model: "gpt-4o"
```

### 3. Browser Automation (Optional)

```bash
pip install playwright && playwright install chromium
```

Required for: DOM XSS testing, clickjacking detection, challenge solving, hidden element discovery.

## Running a Scan

### Minimal

```bash
python deep_eye.py -u https://target.com
```

### From Config (recommended)

Set `scanner.target_url` in config.yaml, then:

```bash
python deep_eye.py
```

### Verbose

```bash
python deep_eye.py -u https://target.com -v
```

## CLI Reference

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL (overrides config) |
| `-c, --config` | Config file path (default: `config/config.yaml`) |
| `-v, --verbose` | Verbose output |
| `--version` | Show version |
| `--no-banner` | Disable ASCII banner |
| `--formats` | Export formats: `junit,csv,xlsx` (comma-separated) |
| `--diff` | Diff two scan JSONs: `--diff baseline.json current.json` |
| `--diff-output` | Output path for diff report |
| `--diff-format` | Diff format: `html`, `json`, `csv` |

## AI Provider Setup

### OpenAI
```yaml
ai_providers:
  openai:
    enabled: true
    api_key: "sk-..."
    model: "gpt-4o"
```

### Claude (Anthropic)
```yaml
ai_providers:
  claude:
    enabled: true
    api_key: "sk-ant-..."
    model: "claude-3-5-sonnet-20241022"
```

### Grok (xAI)
```yaml
ai_providers:
  grok:
    enabled: true
    api_key: "xai-..."
    model: "grok-beta"
```

### Google Gemini
```yaml
ai_providers:
  gemini:
    enabled: true
    api_key: "..."
    model: "gemini-1.5-flash"
```

### OLLAMA (Local)
```yaml
ai_providers:
  ollama:
    enabled: true
    base_url: "http://localhost:11434"
    model: "llama2"
```

### OpenRouter
```yaml
ai_providers:
  openrouter:
    enabled: true
    api_key: "sk-..."
    model: "openai/gpt-4o"
```

### Requesty
```yaml
ai_providers:
  requesty:
    enabled: true
    api_key: "sk-..."
    model: "openai/gpt-4o-mini"
```

### LiteLLM (Universal Proxy)
```yaml
ai_providers:
  litellm:
    enabled: true
    api_key: "..."
    model: "gpt-4o"
    base_url: "http://localhost:4000"
```

## Common Configurations

### Quick Scan (main URL only)

```yaml
scanner:
  quick_scan: true
  default_threads: 5
```

### Full Deep Scan

```yaml
scanner:
  full_scan: true
  default_depth: 5
  default_threads: 10
  enable_recon: true

vulnerability_scanner:
  payload_generation:
    use_ai: true
    context_aware: true
    cve_database: true
```

### With Compliance Reporting

```yaml
compliance:
  enabled: true
  frameworks:
    - pci_dss
    - soc2
    - iso_27001

reporting:
  formats:
    - html
    - xlsx
    - junit
```

### With AI Triage (reduce false positives)

```yaml
ai_triage:
  enabled: true
  drop_false_positives: true
  drop_threshold: 0.8

bug_bounty:
  enabled: true
  format: "markdown"
  output_directory: "reports/bounty"
```

### With Challenge Bypass

```yaml
challenge_solver:
  enabled: true
  vendors:
    - "cloudflare"
    - "akamai"
  playwright_headless: true
  cookie_ttl_seconds: 1800
```

### Through Proxy

```yaml
proxy:
  enabled: true
  http: "http://127.0.0.1:8080"
  https: "http://127.0.0.1:8080"
```

### With Intercepting Proxy (mitmproxy)

```yaml
intercepting_proxy:
  enabled: true
  bind_host: "127.0.0.1"
  proxy_port: 8080
  mitmweb_port: 8081
```

Requires `mitmproxy` installed: `pip install mitmproxy`

## Scan Diffing

Compare two scans to track remediation progress:

```bash
# Run baseline scan (results saved as JSON)
python deep_eye.py -u https://target.com

# Later, run another scan
python deep_eye.py -u https://target.com

# Compare
python deep_eye.py --diff reports/scan_baseline.json reports/scan_current.json \
  --diff-format html --diff-output reports/diff.html
```

Output shows: new vulnerabilities, fixed vulnerabilities, unchanged, severity changes.

## CVE Intelligence (Experimental)

### Build the Database

```bash
python scripts/update_cve_database.py
```

### Build RAG Index

```bash
python scripts/build_cve_rag_index.py
```

### Enable

```yaml
experimental:
  enable_cve_matching: true
  cve_database_path: "data/cve_intelligence.db"

rag:
  enabled: true
  index_path: "data/rag_index"
  top_k: 5
  min_score: 0.7
```

## Subdomain Scanning (Experimental)

```yaml
experimental:
  enable_subdomain_scanning: true
  max_subdomains_to_scan: 50
```

Discovery methods: Certificate Transparency (crt.sh), DNS bruteforce (100+ patterns), liveness verification.

## Custom Templates (Nuclei-Style)

Create YAML templates for custom checks:

```yaml
# templates/custom/my-check.yaml
id: my-custom-check
info:
  name: Custom Header Check
  severity: medium
  description: Checks for missing security header
  tags:
    - headers

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "X-Custom-Header"
        negative: true
        part: header
```

Enable:

```yaml
templates:
  enabled: true
  template_directories:
    - "templates/custom"
```

## Notifications

```yaml
notifications:
  enabled: true
  notify_on_critical: true
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/..."
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/..."
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    username: "..."
    password: "..."
    recipients:
      - "security@company.com"
```

## Troubleshooting

### AI Provider Errors
- Verify API keys in config.yaml
- Check API credit balance

### PDF Generation Fails
- Uses ReportLab (Windows-friendly). Falls back to HTML automatically.
- Verify: `pip install reportlab>=4.0.0`

### Browser Tests Fail
```bash
playwright install chromium --force
```

### Import Errors
```bash
pip install -r requirements.txt --upgrade
```

### Rate Limiting / WAF Blocking
```yaml
rate_limiting:
  requests_per_second: 2
  delay_on_error: 5

scanner:
  default_threads: 2
```

## Output Formats

Reports saved to `reports/` by default:

| Format | File | Use Case |
|--------|------|----------|
| HTML | `*.html` | Interactive viewing with charts/filtering |
| PDF | `*.pdf` | Executive reporting |
| JSON | `*.json` | Programmatic access, scan diffing |
| JUnit XML | `*.xml` | CI/CD pipeline integration |
| CSV | `*.csv` | Spreadsheet analysis |
| XLSX | `*.xlsx` | Multi-sheet workbook with compliance data |
| SARIF | `*.sarif` | GitHub Code Scanning, Azure DevOps |

## Legal Notice

Only use Deep Eye on systems you own or have explicit written permission to test. Unauthorized security testing is illegal.
