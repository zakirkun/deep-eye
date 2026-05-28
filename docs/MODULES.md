# Modules Reference

Deep Eye includes 33 specialized security testing modules. Each follows the same interface pattern.

## Module Interface

```python
class ModuleName:
    def __init__(self, http_client, config):
        ...

    def scan(self, url) -> List[Dict]:
        # Returns list of vulnerability result dicts
        ...
```

## Module Categories

### Web Application Vulnerabilities

| Module | Config Key | Description |
|--------|-----------|-------------|
| `api_security` | `api_security` | OWASP API Top 10 2023 — BOLA, auth, rate limiting, mass assignment, data exposure |
| `authentication` | `authentication` | Session management, JWT, OAuth, MFA bypass, brute force protection |
| `business_logic` | `business_logic` | Price manipulation, workflow bypass, race conditions, coupon abuse |
| `file_upload` | `file_upload` | Unrestricted upload, path traversal, type bypass, polyglot files |
| `websocket` | `websocket` | Origin validation, auth, injection, DoS, rate limiting, TLS |

### Injection & Exploitation

| Module | Config Key | Description |
|--------|-----------|-------------|
| `nosql_injection` | — | MongoDB/NoSQL query injection |
| `http_smuggling` | — | HTTP request smuggling (CL.TE, TE.CL) |
| `log4shell` | — | Log4j JNDI injection (CVE-2021-44228) |
| `prototype_pollution` | — | JavaScript prototype pollution |
| `mass_assignment` | — | Object property mass assignment |

### Authentication & Session

| Module | Config Key | Description |
|--------|-----------|-------------|
| `oauth_testing` | — | OAuth flow vulnerabilities, token leakage |
| `saml_attacks` | — | SAML assertion manipulation, signature bypass |
| `captcha_detection` | `captcha` | Identifies reCAPTCHA, hCaptcha, Turnstile, Arkose vendors |
| `login_replay` | `login_replay` | YAML-defined login macro replay with session persistence |

### Infrastructure & Discovery

| Module | Config Key | Description |
|--------|-----------|-------------|
| `port_scanner` | `reconnaissance` | TCP port scanning on common ports |
| `directory_bruteforce` | — | Directory/file enumeration |
| `subdomain_takeover` | — | Dangling CNAME detection |
| `cache_poisoning` | — | Web cache poisoning via headers |
| `reconnaissance` | `reconnaissance` | DNS, WHOIS, OSINT, tech detection, CT logs |

### Detection & Scanning

| Module | Config Key | Description |
|--------|-----------|-------------|
| `ml_detection` | `ml_detection` | IsolationForest anomaly detection on response patterns |
| `secrets_scanner` | `secrets_scanner` | 40+ secret patterns in responses (API keys, tokens, credentials) |
| `secret_scanning` | — | Additional secret detection patterns |
| `race_condition` | — | TOCTOU and concurrent request race conditions |

### AI-Powered

| Module | Config Key | Description |
|--------|-----------|-------------|
| `ai_triage` | `ai_triage` | LLM-based false-positive scoring + bug bounty report generation |
| `cve_intelligence` | `experimental` | CVE matching, RAG index, exploit pattern extraction |
| `template_engine` | `templates` | Nuclei-style YAML template execution with matchers/extractors |

### Automation

| Module | Config Key | Description |
|--------|-----------|-------------|
| `browser_automation` | `advanced` | Playwright + Browser Use AI for DOM XSS, clickjacking, hidden elements |
| `challenge_solver` | `challenge_solver` | Cloudflare/Akamai JS challenge bypass with cookie caching |
| `intercepting_proxy` | `intercepting_proxy` | mitmweb subprocess management for traffic interception |
| `payload_obfuscation` | `payload_obfuscation` | 11+ encoding/bypass techniques for WAF evasion |

### Collaboration & Reporting

| Module | Config Key | Description |
|--------|-----------|-------------|
| `collaboration` | `collaboration` | Team scanning sessions, work distribution, progress tracking |
| `reporting` | `reporting` | Report generation helpers |

## Module Details

### ai_triage

**Purpose**: Reduce noise by having an LLM classify each finding as true/false positive.

**Config**:
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
  one_file_per_vuln: true
```

**Flow**: After scanning completes, `AITriage.triage_vulnerabilities()` sends each finding to the LLM. Findings flagged as FP with confidence >= threshold are dropped. Then `BountyWriter.generate_reports()` creates per-vuln Markdown reports.

### template_engine

**Purpose**: Run Nuclei-compatible YAML templates for custom/declarative checks.

**Config**:
```yaml
templates:
  enabled: true
  template_directories:
    - "templates/nuclei"
    - "templates/custom"
  tag_filters:
    - "cve"
    - "rce"
  severity_filter: "critical,high"
```

**Template format**:
```yaml
id: custom-check-id
info:
  name: Check Name
  severity: high
  description: What this checks
  tags:
    - custom
  reference:
    - https://example.com

http:
  - method: GET
    path:
      - "{{BaseURL}}/endpoint"
    matchers:
      - type: word
        words:
          - "sensitive_string"
        part: body
      - type: status
        status:
          - 200
    matchers-condition: and
    extractors:
      - type: regex
        regex:
          - "token=([a-f0-9]+)"
        group: 1
```

**Variables**: `{{BaseURL}}`, `{{Hostname}}`, `{{RandomString}}`

### challenge_solver

**Purpose**: Bypass Cloudflare/Akamai bot challenges to scan protected targets.

**Config**:
```yaml
challenge_solver:
  enabled: true
  vendors:
    - "cloudflare"
    - "akamai"
  playwright_headless: true
  cookie_ttl_seconds: 1800
  timeout_seconds: 30
```

**Flow**: `ChallengeDetector.detect()` checks response for challenge signatures. If detected, `ChallengeSolver.solve()` launches headless Chromium, waits for JS challenge, extracts clearance cookies, injects into HTTP client. Cookies cached per-domain with TTL.

### intercepting_proxy

**Purpose**: Run mitmproxy alongside scans for traffic inspection.

**Config**:
```yaml
intercepting_proxy:
  enabled: true
  required: false
  bind_host: "127.0.0.1"
  proxy_port: 8080
  mitmweb_port: 8081
```

**Usage**: `ProxyRunner.start()` spawns mitmweb. Web UI at `http://127.0.0.1:8081`. All scan traffic routes through proxy. Terminates on scan completion via `atexit`.

### captcha_detection / login_replay

**Config**:
```yaml
captcha:
  enabled: true
  skip_protected: true
  vendors:
    - "recaptcha"
    - "hcaptcha"
    - "turnstile"

login_replay:
  enabled: true
  macro_path: "config/login_macro.yaml"
  abort_on_fail: true
  recheck_interval_seconds: 300
```

**Login macro format**:
```yaml
steps:
  - url: "https://target.com/login"
    method: POST
    body:
      username: "testuser"
      password: "testpass"
    expect_status: 302
  - url: "https://target.com/dashboard"
    method: GET
    expect_status: 200
```

### cve_intelligence

**Config**:
```yaml
experimental:
  enable_cve_matching: true
  cve_database_path: "data/cve_intelligence.db"

rag:
  enabled: true
  index_path: "data/rag_index"
  auto_rebuild: false
  top_k: 5
  min_score: 0.7
```

**Components**: `CVEScraper` (NVD/MITRE/Exploit-DB), `CVEMatcher` (tech-to-CVE mapping), `CVERagIndex` (ChromaDB vector search).

**Scripts**:
```bash
python scripts/update_cve_database.py
python scripts/build_cve_rag_index.py
```

### ml_detection

**Config**:
```yaml
ml_detection:
  enabled: true
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

Uses scikit-learn IsolationForest trained on baseline responses. Flags outliers in response time, size, status codes, and error patterns.

### secrets_scanner

**Config**:
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

Scans for 40+ patterns: AWS keys, GitHub tokens, Slack webhooks, private keys, database URIs, JWT tokens, etc.
