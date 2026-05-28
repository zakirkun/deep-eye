<p align="center">
  <img src="./assets/Screenshot 2025-10-20 150312.png" height="300">
</p>

<h1 align="center">Deep Eye</h1>

<p align="center">
  Advanced AI-Driven Penetration Testing Tool
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.4.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8+-green" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/code_name-Hanzou-purple" alt="Code Name">
</p>

---

Deep Eye orchestrates multiple AI providers (OpenAI, Claude, Grok, Gemini, OLLAMA, Groq, Mistral, OpenRouter, LiteLLM, LM Studio) for intelligent payload generation, scans targets for 45+ vulnerability types, and produces professional reports with compliance mapping.

## Features

- **Multi-AI Provider Support** — Dynamic switching and failover across 10 AI providers
- **45+ Vulnerability Scanners** — SQLi, XSS, SSRF, XXE, SSTI, RCE, deserialization, JWT, OAuth, and more
- **Context-Aware Payloads** — WAF detection, tech stack fingerprinting, database-specific injection
- **CVE Intelligence** — RAG-indexed CVE database with real exploit patterns from NVD/MITRE/Exploit-DB
- **AI Triage** — Automated false-positive filtering and bug bounty report generation
- **Nuclei-Style Templates** — YAML-based custom vulnerability templates with matchers/extractors
- **Browser Automation** — Playwright + Browser Use AI for client-side testing
- **Challenge Bypass** — Cloudflare/Akamai challenge solver with cookie persistence
- **Intercepting Proxy** — mitmproxy-based traffic interception and modification
- **Compliance Mapping** — PCI-DSS v4, SOC2 CC, ISO 27001:2022 framework mapping
- **Export Formats** — HTML, PDF, JSON, JUnit XML, CSV, XLSX
- **Scan Diffing** — Compare scans to track new/fixed vulnerabilities over time
- **Collaborative Scanning** — Team-based distributed scanning with session management
- **Notifications** — Real-time alerts via Email, Slack, Discord

## Requirements

- Python 3.8+
- At least one AI provider API key (or local OLLAMA)
- Playwright (optional, for browser-based testing)

## Installation

**Windows:**
```powershell
.\scripts\install.ps1
```

**Linux/Mac:**
```bash
chmod +x scripts/install.sh && ./scripts/install.sh
```

**Manual:**
```bash
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your API keys
```

**Or skip manual config — the setup wizard runs automatically on first launch:**
```bash
pip install -r requirements.txt
python deep_eye.py -u https://target.com
# Interactive wizard guides you through provider selection, API key, and settings
```

**Browser automation (optional):**
```bash
pip install playwright && playwright install chromium
```

## Usage

### Basic Scan

```bash
python deep_eye.py -u https://target.com
```

### With Configuration File

```bash
python deep_eye.py -c config/config.yaml
```

### Verbose Output

```bash
python deep_eye.py -u https://target.com -v
```

### Export in Multiple Formats

```bash
python deep_eye.py -u https://target.com --formats junit,csv,xlsx
```

### Scan Diffing

Compare two scan results to see what changed:

```bash
python deep_eye.py --diff baseline.json current.json --diff-format html --diff-output diff_report.html
```

### CLI Reference

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL (overrides config) |
| `-c, --config` | Config file path (default: `config/config.yaml`) |
| `-v, --verbose` | Verbose output |
| `--version` | Show version |
| `--no-banner` | Disable ASCII banner |
| `--formats` | Comma-separated export formats: `junit,csv,xlsx` |
| `--diff` | Diff two scan JSON files (positional: BASELINE CURRENT) |
| `--diff-output` | Output path for diff report |
| `--diff-format` | Diff format: `html`, `json`, `csv` |

## Configuration

All behavior is controlled via `config/config.yaml`. The CLI is intentionally minimal.

### AI Providers

Configure one or more providers:

```yaml
ai_providers:
  openai:
    enabled: true
    api_key: "sk-..."
    model: "gpt-4o"
  claude:
    enabled: true
    api_key: "sk-ant-..."
    model: "claude-3-5-sonnet-20241022"
  ollama:
    enabled: true
    base_url: "http://localhost:11434"
    model: "llama2"
```

Supported: `openai`, `claude`, `grok`, `ollama`, `gemini`, `openrouter`, `mistral`, `groq`, `lmstudio`, `litellm`

### Scanner Settings

```yaml
scanner:
  target_url: "https://target.com"
  default_threads: 5          # 1-50
  default_depth: 2            # crawl depth
  enable_recon: true
  full_scan: false
  ai_provider: "openai"
```

### Vulnerability Checks

```yaml
vulnerability_scanner:
  enabled_checks:
    - sql_injection
    - xss
    - command_injection
    - ssrf
    - ssti
    - lfi
    - rfi
    - jwt_vulnerabilities
    # ... 45+ available checks
  payload_generation:
    use_ai: true
    context_aware: true
    cve_database: true
```

### Compliance Mapping

```yaml
compliance:
  enabled: true
  frameworks:
    - pci_dss
    - soc2
    - iso_27001
```

### AI Triage

```yaml
ai_triage:
  enabled: true
  drop_false_positives: true
  drop_threshold: 0.8
  min_severity: "low"

bug_bounty:
  enabled: true
  format: "markdown"
  min_severity: "medium"
  output_directory: "reports/bounty"
```

### Nuclei-Style Templates

```yaml
templates:
  enabled: true
  template_directories:
    - "templates/nuclei"
  tag_filters:
    - "cve"
    - "rce"
  severity_filter: "critical,high"
```

### Challenge Solver

```yaml
challenge_solver:
  enabled: true
  vendors:
    - "cloudflare"
    - "akamai"
  playwright_headless: true
  cookie_ttl_seconds: 1800
```

### Reporting

```yaml
reporting:
  enabled: true
  output_directory: "reports"
  default_format: "html"
  formats:
    - html
    - pdf
    - json
    - junit
    - csv
    - xlsx
```

### Experimental Features

```yaml
experimental:
  enable_cve_matching: true
  enable_subdomain_scanning: true
  max_subdomains_to_scan: 50
```

## Scripts

```bash
# Update CVE intelligence database from NVD
python scripts/update_cve_database.py

# Build RAG vector index for CVE search
python scripts/build_cve_rag_index.py
```

## Testing

```bash
# Run all tests
pytest

# Run specific test
pytest tests/test_export_formats.py -v

# E2E test (requires API key)
python tests/e2e_litellm.py
```

## Project Structure

```
deep-eye/
├── deep_eye.py              # Entry point
├── core/                    # Orchestration layer
│   ├── scanner_engine.py    # Main scan orchestrator (ThreadPoolExecutor)
│   ├── vulnerability_scanner.py  # 45+ vuln checks
│   ├── ai_payload_generator.py   # AI-powered payload gen
│   ├── report_generator.py       # PDF/HTML/JSON reports
│   ├── scan_diff.py              # Scan comparison
│   └── pentest_state_manager.py  # Phase/progress tracking
├── ai_providers/            # 10 AI provider integrations
├── modules/                 # Specialized security testers
│   ├── ai_triage/           # False-positive filtering + bounty writer
│   ├── template_engine/     # Nuclei-style YAML templates
│   ├── challenge_solver/    # CF/Akamai challenge bypass
│   ├── intercepting_proxy/  # mitmproxy interceptor
│   ├── captcha_detection/   # CAPTCHA detect + login replay
│   ├── cve_intelligence/    # CVE scraper + RAG index
│   ├── browser_automation/  # Playwright + Browser Use AI
│   └── ...                  # 25+ more modules
├── utils/
│   ├── exports/             # JUnit, CSV, XLSX builders
│   ├── compliance/          # PCI-DSS, SOC2, ISO 27001 mapping
│   └── ...                  # http_client, logger, parser, etc.
├── config/
│   └── config.example.yaml  # Full configuration reference
├── scripts/                 # CVE updater, RAG builder
├── tests/                   # pytest test suite
└── reports/                 # Generated output (gitignored)
```

## Vulnerability Coverage

### Core (v1.0+)
SQL Injection (error/blind/time-based), XSS (reflected/stored/DOM), Command Injection, SSRF, XXE, Path Traversal, CSRF, Open Redirect, CORS Misconfiguration, Security Headers

### Extended (v1.1-1.3)
API Security (OWASP API Top 10), GraphQL, Business Logic, Authentication/Session, File Upload, WebSocket, ML Anomaly Detection, OSINT, Payload Obfuscation, LFI/RFI, SSTI, CRLF, Host Header Injection, LDAP Injection, Insecure Deserialization, JWT, Broken Auth

### Advanced (v1.4+)
NoSQL Injection, HTTP Smuggling, Race Conditions, Log4Shell, Mass Assignment, Prototype Pollution, OAuth, Cache Poisoning, Subdomain Takeover, SAML Attacks, Port Scanning, Directory Bruteforce, Secret Scanning

## Legal Disclaimer

Deep Eye is designed for **authorized security testing only**.

- Only use on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- Users are responsible for complying with all applicable laws
- The developers assume no liability for misuse

## License

MIT License. See [LICENSE](LICENSE) for details.

## Links

- [Quick Start Guide](docs/QUICKSTART.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [Modules Reference](docs/MODULES.md)
- [Scan Flow](docs/SCAN_FLOW.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Changelog](CHANGELOG.md)
- [Issues](https://github.com/zakirkun/deep-eye/issues)
