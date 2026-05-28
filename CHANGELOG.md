# Changelog

All notable changes to Deep Eye will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4] - Hanzou Development

### Added

#### Export Formats
- **JUnit XML Export** — CI/CD integration for Jenkins, GitLab, Azure DevOps
- **CSV Export** — RFC 4180 compliant with UTF-8 BOM, compliance columns when available
- **XLSX Export** — Multi-sheet workbook (Summary, Vulnerabilities, Recon, CVEs, Compliance, Control Summary) with severity-colored rows, auto-filter, frozen headers
- **CLI `--formats` flag** — Comma-separated format selection overriding config

#### Compliance Mapping
- **PCI-DSS v4.0** — Full control mapping for payment card security
- **SOC 2 Type II** — Common Criteria (CC) control mapping
- **ISO 27001:2022** — Information security management controls
- Framework JSON definitions in `utils/compliance/frameworks/`
- Auto-enrichment of vulnerabilities with applicable controls

#### AI Triage & Bug Bounty
- **AI False-Positive Filtering** — LLM-based confidence scoring with configurable drop threshold
- **Bug Bounty Report Writer** — Auto-generates HackerOne-style Markdown reports per vulnerability
- Severity gating, per-vuln file output, slugified filenames

#### CAPTCHA Detection & Login Replay
- **CAPTCHA Vendor Detection** — Identifies reCAPTCHA, hCaptcha, Cloudflare Turnstile, Arkose
- **Login Macro Replay** — YAML-defined login sequences with session persistence
- Configurable abort-on-fail and recheck intervals

#### Scan Diffing
- **Scan Comparison** — Diff two JSON scan results: new, fixed, unchanged, severity-changed
- **Diff Rendering** — HTML, JSON, CSV output formats for diff reports
- **CLI `--diff` flag** — Run diff mode instead of scanning
- URL normalization for accurate matching across scans

#### RAG CVE Intelligence
- **ChromaDB Vector Index** — Semantic search over CVE descriptions and exploit data
- **Auto-rebuild** — Configurable index refresh from SQLite CVE database
- **Top-K retrieval** — Score-filtered results enriching scan findings
- Build script: `scripts/build_cve_rag_index.py`

#### Nuclei-Style Template Engine
- **YAML Template Parser** — Nuclei-compatible template format with validation
- **Matchers** — word, regex, status, binary matchers with AND/OR conditions
- **Extractors** — regex, kval, json, xpath extraction from responses
- **Template Executor** — Variable substitution (BaseURL, Hostname, RandomString), multi-method requests
- **Template Loader** — Directory scanning with tag/severity filtering
- CVSS score mapping from severity levels

#### Challenge Solver & Intercepting Proxy
- **Cloudflare Challenge Bypass** — Playwright-based JS challenge solving with cookie caching
- **Akamai Bot Manager Bypass** — Detects and solves Akamai interstitials
- **Cookie TTL Cache** — Reuses solved cookies within configurable TTL window
- **Intercepting Proxy (mitmproxy)** — `ProxyRunner` manages mitmweb subprocess lifecycle
- Localhost-bound by default, atexit cleanup, configurable ports

### Changed
- `ScannerEngine.scan()` now orchestrates: RAG enrichment → compliance mapping → AI triage → bounty writing (post-scan pipeline)
- `ReportGenerator` dispatches to `utils/exports/` builders for junit/csv/xlsx formats
- Config expanded with sections: `compliance`, `rag`, `ai_triage`, `bug_bounty`, `captcha`, `login_replay`, `templates`, `challenge_solver`, `intercepting_proxy`

### Fixed
- Version string inconsistency (banner vs `--version` flag vs setup.py)

---

## [1.3.1] - 2025-12-30

### Fixed
- **NIX Installer** — Fixed issue where *nix installer unable to run as expected.

## [1.4.0] - 2025-10-27

### Added

#### AI-Powered Browser Automation with Browser Use
- **Smart Browser Tester Module** — AI-driven browser-based vulnerability testing
  - Browser Use Integration ([browser-use.com](https://browser-use.com))
  - AI-Powered XSS Testing — GPT-4 navigates pages and tests for XSS
  - AI SQLi Detection — AI reads page content and identifies SQL errors
  - Hidden Element Discovery & Testing — finds hidden inputs, display:none, opacity:0 elements
  - Automatic Fallback to Playwright if Browser Use unavailable
  - DOM XSS Testing, Clickjacking Detection, Screenshot Capture

#### Enhanced Reporting System
- Interactive HTML Reports with Chart.js and DataTables
- Dynamic severity/type filtering, expandable details
- Screenshot evidence embedded as base64
- Responsive design, export options

#### Real-Time Pentest State Management
- Phase tracking (Initialization → Recon → Crawling → Scanning → Reporting)
- Live vulnerability counts, attack statistics, time tracking
- Rich CLI tables, state persistence for analysis

#### Optimized Attack Logic
- Context-Aware Payload Generation (tech stack detection, WAF detection)
- Database-specific SQLi payloads (MySQL, PostgreSQL, MSSQL, Oracle)
- WAF bypass techniques, payload caching, smart selection
- SSTI detection per framework (Jinja, Flask, Django, PHP)

#### Experimental Features
- **CVE Intelligence System** — NVD scraper, SQLite storage, CVE matcher, exploit extraction
- **Subdomain Discovery** — Certificate Transparency, DNS bruteforce, liveness verification, parallel scanning

### Changed
- Added Google Gemini as AI provider (5 → 10 providers total)
- Scanner engine integrated with browser automation and state management
- HTML template overhaul with Chart.js/DataTables
- Performance: payload caching, context hashing, deduplication, CVE indexing

### Fixed
- Browser automation error handling
- Screenshot capture edge cases
- Payload generation for edge cases
- State tracking in concurrent scans

### Dependencies
- Added `playwright>=1.40.0`, `google-generativeai>=0.3.0`
- Chart.js 4.4.0, DataTables 1.13.7, jQuery 3.7.0 (CDN)

## [1.3.0] - 2025-10-20

### Added
- **Custom Plugin System** — Hot-reload plugins from `plugins/` directory
- **Multi-Channel Notifications** — Email (SMTP), Slack (webhook), Discord (webhook)
- **Enhanced OSINT Reporting** — DNS, emails, subdomains, technologies, breaches in reports
- **15 New Vulnerability Scanners** — LFI, RFI, SSTI, CRLF, Host Header Injection, LDAP Injection, XML Injection, Insecure Deserialization, Authentication Bypass, Information Disclosure, Sensitive Data Exposure, JWT Vulnerabilities, Broken Authentication

### Changed
- Vulnerability scanner expanded from 30+ to 45+ attack methods
- CLI simplified — all scan options via config.yaml
- Report generation fully config-driven

### Fixed
- PDF special character escaping
- OSINT data flow into reports
- Reconnaissance data properly flattened

## [1.2.1] - 2025-10-15

### Fixed
- Replaced WeasyPrint with ReportLab for Windows PDF compatibility
- Enhanced PDF layout with color-coded severity indicators
- Moved OSINT from vulnerability scanner to reconnaissance phase

## [1.2.0] - 2025-10-15

### Added
- **WebSocket Security Testing** — Origin validation, auth, injection, DoS, rate limiting, TLS
- **ML Anomaly Detection** — IsolationForest-based behavioral analysis
- **Interactive HTML Reports** — Chart.js visualizations, filtering, search
- **Enhanced OSINT** — Google dorking, breach databases, CT logs, GitHub/Pastebin
- **Payload Obfuscation** — 11+ techniques (Base64, URL encoding, Unicode, hex, null byte, WAF bypass)

### Changed
- Core scanner integrates WebSocket, ML, OSINT, obfuscation modules
- New dependencies: websocket-client, scikit-learn, numpy, pandas

## [1.1.0] - 2025-10-15

### Added
- **API Security Testing** — OWASP API Top 10 2023 (BOLA, auth, rate limiting, mass assignment)
- **GraphQL Security** — Introspection, depth limits, batch attacks
- **Business Logic Testing** — Price manipulation, workflow bypass, race conditions
- **Authentication Testing** — Session management, JWT, OAuth, MFA bypass
- **File Upload Vulnerabilities** — Unrestricted upload, path traversal, type bypass, polyglot
- **Collaborative Scanning** — Team sessions, work distribution, progress tracking

### Changed
- Vulnerability scanner expanded from 25+ to 30+ attack methods

## [1.0.0] - 2025-10-15

### Added
- Initial release
- Multi-AI provider support (OpenAI, Claude, Grok, OLLAMA)
- 25+ vulnerability detection methods
- Web crawler with configurable depth
- Multi-threaded scanning engine
- AI-powered payload generation
- Reconnaissance module (DNS, WHOIS, subdomain discovery)
- Professional reports (HTML, PDF, JSON)
- Rich CLI with progress indicators
- Configuration management, proxy support, rate limiting

---

For releases, see [GitHub Releases](https://github.com/zakirkun/deep-eye/releases).
