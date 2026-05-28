# Scan Flow

This document describes the complete execution flow when Deep Eye runs a scan.

## Entry Point

```bash
python deep_eye.py -u https://target.com
```

`deep_eye.py:main()` handles:
1. Argument parsing
2. Config loading (or onboard wizard if config missing)
3. Validation
4. `ScannerEngine` initialization
5. `scan()` invocation
6. Report generation

## Phase Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        INITIALIZATION                            │
│  PentestStateManager setup, HTTPClient init, module loading      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                       RECONNAISSANCE                             │
│  ReconEngine: DNS, WHOIS, OSINT, tech detection, SSL analysis   │
│  (skipped if enable_recon: false)                                │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SUBDOMAIN DISCOVERY                            │
│  SubdomainScanner: CT logs, DNS bruteforce, liveness checks     │
│  (experimental, config-gated)                                    │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                         CRAWLING                                  │
│  ThreadPoolExecutor BFS crawl                                    │
│  URL deduplication, extension/pattern filtering, scope checks    │
│  Discovers all scannable URLs up to configured depth             │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   VULNERABILITY SCANNING                          │
│  Per-URL parallel scan (ThreadPoolExecutor):                     │
│                                                                   │
│  For each URL:                                                   │
│  1. HTTP GET response                                            │
│  2. AIPayloadGenerator.generate_payloads(context)                │
│  3. VulnerabilityScanner.scan() - 45+ checks                    │
│  4. SmartBrowserTester (if JS rendering enabled)                 │
│  5. PluginManager.run_plugins()                                  │
│  6. SecretsDetector.scan_response()                              │
│  7. CVEMatcher.enrich_vulnerability() per finding                │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   POST-SCAN ENRICHMENT                            │
│                                                                   │
│  1. CVERagIndex.search() - semantic CVE matching per finding     │
│  2. ComplianceMapper.enrich_vulnerabilities()                    │
│     PCI-DSS, SOC2, ISO 27001 control mapping                    │
│  3. AITriage.triage_vulnerabilities()                            │
│     LLM scores each finding, drops false positives              │
│  4. BountyWriter.generate_reports()                              │
│     Per-vuln Markdown bug bounty reports                         │
│                                                                   │
│  (Each step config-gated, operates in-place on results list)     │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                         REPORTING                                 │
│  ReportGenerator.generate(results, path, format)                 │
│  Formats: HTML, PDF, JSON, SARIF, JUnit XML, CSV, XLSX          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                       NOTIFICATIONS                               │
│  NotificationManager: Email, Slack, Discord                      │
│  Triggered on scan completion or critical findings               │
└─────────────────────────────────────────────────────────────────┘
```

## Payload Generation Flow

```
URL + Response Context
        |
        v
Context Analysis (tech stack, WAF, DB fingerprint)
        |
        v
AI Provider generate(prompt) --> Generated Payloads
        |                              |
        v                              v
CVE-based payloads            Obfuscated variants
```

Context-aware generation considers:
- **Technology**: PHP, ASP.NET, Node.js, Java specific payloads
- **Database**: MySQL vs PostgreSQL vs MSSQL vs Oracle syntax
- **WAF**: Cloudflare/Sucuri/Akamai encoding bypass techniques
- **CVE database**: Real exploit patterns from NVD when enabled

## Challenge Solving Flow

When a target is behind Cloudflare/Akamai:

```
HTTP Request --> Response
        |
        v
ChallengeDetector.detect(html, headers)
        |
        +-- No challenge --> proceed normally
        |
        +-- Challenge detected
                |
                v
        ChallengeSolver.solve(url)
                |
                +-- Cache hit (within TTL) --> inject cached cookies
                |
                +-- Cache miss --> launch headless Chromium
                        --> wait for JS challenge
                        --> extract clearance cookies
                        --> inject into HTTPClient
                        --> cache with TTL
```

## Scan Diff Flow (--diff mode)

```bash
python deep_eye.py --diff baseline.json current.json --diff-format html
```

```
Load baseline.json + current.json
        |
        v
diff_scans(baseline, current)
        |
        +-- Normalize URLs (lowercase, sort params)
        +-- Build identity tuples (type, url, param, severity)
        +-- Set operations: new, fixed, unchanged
        +-- Detect severity changes
        |
        v
Render output (HTML/JSON/CSV)
```

## Threading Model

- **Crawl Phase**: `ThreadPoolExecutor(max_workers=threads)` — each worker fetches URL, extracts links, queues new URLs
- **Scan Phase**: `ThreadPoolExecutor(max_workers=threads)` — each worker runs all checks on one URL
- **Subdomain Phase**: `ThreadPoolExecutor` — parallel liveness verification and scanning

Thread count: 1-50 via `scanner.default_threads`. Higher = faster but more aggressive.

## State Tracking

`PentestStateManager` tracks throughout:

| Metric | Description |
|--------|-------------|
| Current phase | INIT, RECON, CRAWL, SCAN, REPORT, COMPLETE |
| URLs discovered | Total unique URLs found during crawl |
| URLs scanned | URLs that completed vulnerability testing |
| Vulns by severity | Running count: critical/high/medium/low/info |
| Attack stats | Per-attack-type success/failure/total counts |
| Time per phase | Elapsed seconds in each phase |

State displayed in CLI via Rich tables when verbose mode enabled.
