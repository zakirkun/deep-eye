<p align="center">
  <a href="https://trendshift.io/repositories/24003?utm_source=repository-badge&amp;utm_medium=badge&amp;utm_campaign=badge-repository-24003" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/repositories/24003" alt="zakirkun%2Fdeep-eye | Trendshift" width="250" height="55"/></a>
  <br />
  <img src="./assets/logo.png" height="300">
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

Deep Eye orchestrates multiple AI providers (OpenAI, Claude, Grok, Gemini, OLLAMA, Groq, Mistral, OpenRouter, OrcaRouter, LiteLLM, LM Studio) for intelligent payload generation, scans targets for **50+** vulnerability checks, and produces professional reports with compliance mapping, dedupe, and retest workflows.

## Features

- **Multi-AI Provider Support** — Failover across 11 providers (`generate()` abstraction)
- **50+ Vulnerability Checks** — SQLi, XSS, SSRF, JWT deep, IDOR, GraphQL deep, CORS/CSP, supply-chain JS, and more
- **OpenAPI Ingest** — Seed crawl from OpenAPI/Swagger specs
- **Context-Aware Payloads** — WAF fingerprint, tech stack, CVE-aware generation
- **CVE Intelligence** — RAG-indexed CVE DB (NVD/MITRE/Exploit-DB patterns)
- **AI Triage & Evidence** — FP filtering, per-finding evidence summaries, FP replay
- **Bug Bounty Report Writer** — Auto-generates HackerOne-style Markdown reports per vulnerability
- **AI Attack Planner** — Optional post-recon check order / budget
- **Nuclei-Style Templates** — YAML matchers/extractors under `templates/`
- **Auth Helpers** — Login macro replay, multi-role session store
- **CAPTCHA Detection** — reCAPTCHA, hCaptcha, Cloudflare Turnstile, Arkose; challenge solver + skip
- **Browser Automation** — Playwright (+ optional Browser Use AI)
- **Intercepting Proxy** — mitmproxy/mitmweb integration
- **Compliance Mapping** — PCI-DSS v4, SOC2 CC, ISO 27001:2022
- **Export Formats** — HTML, PDF, JSON, SARIF, JUnit, CSV, XLSX
- **Scan Diff & Retest** — Diff baselines; `--retest-new` keeps only new findings
- **NL Scope** — `--scope-nl` natural-language allow/deny
- **Finding Dedupe** — Fingerprint collapse for cleaner reports
- **Notifications** — Email / Slack / Discord

## Requirements

- Python 3.8+
- At least one AI provider API key (or local OLLAMA)
- Playwright (optional, browser tests / challenge solve)
- `curl_cffi` (optional, `tls_evasion`)

## Installation

**Windows:**
```powershell
.\scripts\install.ps1
# uses .deep-venv
```

**Linux/Mac:**
```bash
chmod +x scripts/install.sh && ./scripts/install.sh
source .deep-venv/bin/activate
```

**Manual:**
```bash
pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with API keys
```

First launch without config runs the interactive wizard.

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

### Verbose / Multi-format

```bash
python deep_eye.py -u https://target.com -v
python deep_eye.py -u https://target.com --formats junit,csv,xlsx
```

### Natural-language scope

```bash
python deep_eye.py -u https://target.com --scope-nl "only /api/* no /logout host target.com"
```

### Scan Diffing

```bash
python deep_eye.py --diff baseline.json current.json --diff-format html --diff-output diff_report.html
```

### Retest only new findings

```bash
python deep_eye.py -u https://target.com --retest-new baseline.json
```

### CLI Reference

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL (overrides config) |
| `-c, --config` | Config file path (default: `config/config.yaml`) |
| `-v, --verbose` | Verbose output |
| `--version` | Show version |
| `--no-banner` | Disable ASCII banner |
| `--formats` | Comma-separated: `html,pdf,json,junit,csv,xlsx,sarif` |
| `--diff` | Diff two scan JSON files (`BASELINE` `CURRENT`) |
| `--diff-output` | Diff report path |
| `--diff-format` | `html`, `json`, or `csv` |
| `--retest-new` | After scan, keep only findings new vs baseline JSON |
| `--scope-nl` | Natural-language scope string |
| `--setup` | Run interactive config setup wizard and exit |
| `--setup-force` | With `--setup`, overwrite existing config without extra prompt |

## Configuration

All behavior is controlled via `config/config.yaml`. See **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** and `config/config.example.yaml`.

### AI Providers

```yaml
ai_providers:
  openai:
    enabled: true
    api_key: "sk-..."
    model: "gpt-4o"
  ollama:
    enabled: true
    base_url: "http://localhost:11434"
    model: "llama2"
  atlascloud:
    enabled: false
    api_key: "${ATLASCLOUD_API_KEY}"
    base_url: "https://api.atlascloud.ai/v1"
    model: "openai/gpt-4.1-mini"
```

Supported: `openai`, `claude`, `grok`, `ollama`, `gemini`, `openrouter`, `orcarouter`, `requesty`, `mistral`, `groq`, `lmstudio`, `litellm`, `nvidia_nim`, `atlascloud`

### Scanner Settings

```yaml
scanner:
  target_url: "https://target.com"
  default_threads: 5
  default_depth: 2
  enable_recon: true
  ai_provider: "openai"
```

### Vulnerability Checks

```yaml
vulnerability_scanner:
  enabled_checks:
    - sql_injection
    - xss
    - ssrf
    - cors_csp
    - jwt_deep
    - idor
    - graphql_deep
    # full list in config.example.yaml
  payload_generation:
    use_ai: true
    context_aware: true
```

### OpenAPI / AI pipeline (optional)

```yaml
openapi:
  enabled: true
  source: "https://target.com/openapi.json"

ai_planner: { enabled: true }
ai_triage: { enabled: true }
evidence_summary: { enabled: true, min_severity: high }
fp_replay: { enabled: true }

reporting:
  formats: [html, json]
  dedupe: true
```

## Project structure

```
deep-eye/
├── deep_eye.py           # CLI
├── core/                 # Engine, scanner, reports, plugins
├── ai_providers/         # Provider adapters
├── modules/              # Attack + pipeline modules
├── utils/                # HTTP, exports, compliance, scope, fingerprints
├── config/               # config.example.yaml
├── templates/            # Nuclei-style YAML templates
├── plugins/              # Custom PluginBase plugins
├── .agents/skills/       # Agent skills (pentest, bounty, red/blue, ctf)
├── proxy/                # Skill discovery loader
├── scripts/              # CVE DB + RAG builders
├── tests/                # pytest suite
├── data/                 # SQLite + auth_sessions + RAG index
└── docs/                 # Full documentation
```

## Documentation

| Doc | Content |
|-----|---------|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Install + first scan |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Full YAML reference |
| [docs/MODULES.md](docs/MODULES.md) | Module catalog |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layers + contracts |
| [docs/SCAN_FLOW.md](docs/SCAN_FLOW.md) | Phase pipeline |
| [docs/SKILLS.md](docs/SKILLS.md) | Agent skills (pentest / bounty / red / blue / CTF) |
| [CLAUDE.md](CLAUDE.md) | Agent/dev patterns |
| [AGENTS.md](AGENTS.md) | Hierarchical agent map |

## Testing

```bash
pip install -r requirements-dev.txt
pytest
pytest tests/test_features_1_19.py -v
```

## Scripts

```bash
python scripts/update_cve_database.py
python scripts/build_cve_rag_index.py
```

## Sponsors

<p align="center">
  <a href="https://www.swiftproxy.net/?ref=zakirkun" target="_blank" rel="noopener noreferrer">
    <img src="./assets/swiftproxy_banner.png" alt="Swiftproxy" width="100%">
  </a>
</p>

<p align="center">
  <a href="https://www.swiftproxy.net/?ref=zakirkun"><b>Swiftproxy</b></a> provides 90M+ clean residential IPs across 220+ locations, supporting HTTP(S)/SOCKS5, IP rotation, sticky sessions, and precise location targeting. It helps browser automation and AI-powered workflows access websites reliably from different locations — suitable for web scraping, automation, research, and location-based testing. Residential proxies from $0.7/GB.
  <br />
  Free testing available. Use code <code>PROXY90</code> for 10% off.
</p>

<p align="center">
  <a href="https://inferhub.dev/signup?ref=saqutsy3" target="_blank" rel="noopener noreferrer">
    <img src="./assets/inferhub-logo.jpg" alt="InferHub" height="140" widht="100">
  </a>
</p>

<p align="center">
  Deep Eye is proudly sponsored by <a href="https://inferhub.dev/signup?ref=saqutsy3">InferHub</a>.
</p>

## Legal Disclaimer

Deep Eye is for **authorized security testing only**.

- Only use on systems you own or have explicit written permission to test
- Unauthorized access is illegal
- Users are responsible for compliance with applicable laws
- Authors assume no liability for misuse

## License

MIT License. See [LICENSE](LICENSE).

## Links

- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Issues](https://github.com/zakirkun/deep-eye/issues)
