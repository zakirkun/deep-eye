# CORE KNOWLEDGE BASE

## OVERVIEW
Scan lifecycle owner: crawl, OpenAPI seed, per-URL checks, post-process (dedupe/RAG/triage), report. 10 modules, ~5.2k LOC. `scanner_engine.py` and `vulnerability_scanner.py` are the two files you will touch most.

## STRUCTURE
| File | LOC | Purpose |
|------|-----|---------|
| `vulnerability_scanner.py` | 1597 | 23 `_check_*` methods + 27 `_feature_testers` dispatch |
| `report_generator.py` | 997 | `generate()` → html/pdf/json/sarif/junit/csv/xlsx |
| `scanner_engine.py` | 929 | Lifecycle, ThreadPool, OpenAPI, planner, templates, extras |
| `ai_payload_generator.py` | 612 | AI/static payloads + OAST callback URL |
| `pentest_state_manager.py` | 385 | `PentestPhase` enum, progress, checkpoint save |
| `subdomain_scanner.py` | 226 | Experimental subdomain orchestration |
| `plugin_manager.py` | 167 | `PluginBase` + dynamic `plugins/*.py` load |
| `injection_surfaces.py` | 163 | `Surface` enum: query/form_post/json_body/cookie/header/path_segment |
| `scan_diff.py` | 100 | `diff_scans`, `load_scan_json`, `_identity_no_sev` |
| `obfuscation.py` | 53 | Payload encoding techniques (WAF bypass) |

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Wire a pipeline step | `scanner_engine.scan` (line 682; ordered phases below) |
| Add built-in check | `_check_*` on `VulnerabilityScanner` + `enabled_checks` |
| Add feature check | `_specs` tuple in `VulnerabilityScanner.__init__` (line 71) |
| Add heavy module | `_init_extra_module_testers` in `scanner_engine.py` (line 244) |
| Diff identity | `scan_diff._identity_no_sev` |
| Report format dispatch | `report_generator.generate` (line 25) |

## SCAN ORDER (verified against `scanner_engine.scan`)
1. INITIALIZATION → login replay (optional, aborts on fail unless `login_replay.abort_on_fail: false`)
2. RECONNAISSANCE (optional)
3. Subdomain discovery + scan (optional) — vulns merged into main list
4. **Mobile** (`mobile.enabled`) — loops the 5 mobile `_feature_testers` only
5. CRAWLING (`crawl_recursive`) + OpenAPI seed + AI planner
6. VULNERABILITY SCANNING (`scan_all_urls`, ThreadPool)
7. dedupe → FP replay → evidence summary → RAG → compliance → AI triage → bounty
8. state summary → notification → OAST/proxy shutdown → checkpoint save

## CONVENTIONS
- Ctor: `VulnerabilityScanner(config, http_client)` — **reversed** vs modules.
- Post-process steps are individually try/except'd with `logger.debug/warning`; a failure degrades, never aborts the scan. Keep that.
- Every post-processor re-syncs `results['vulnerabilities']` after mutating `self.vulnerabilities` in place.
- Report formats are one `if/elif` chain in `generate()`; unsupported → `ValueError`.
- Non-atomic reads are fine here: `scan_all_urls` guards list appends with `self.lock`.

## ANTI-PATTERNS
- Skip `enabled_checks` gates — dispatch re-checks the list at call time (line 325, 779).
- Invent vuln keys that break export/diff.
- Put scan knobs on CLI (use YAML).
- Grow `vulnerability_scanner.py`; add a `modules/` package instead.
- Assume `_feature_testers` is complete — import failures are swallowed at `logger.debug`.
- Read `severity_summary` before the post-process phase: dedupe, triage and bounty all mutate the list, and the engine recomputes the summary after each.
