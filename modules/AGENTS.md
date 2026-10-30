# MODULES KNOWLEDGE BASE

**Scope:** `modules/` only — 64 packages, ~15.6k LOC. Full catalog: `docs/MODULES.md`.

## OVERVIEW
Attack packages + pipeline helpers. Standard surface: ctor `(http_client, config)`, `scan(url, context=None) -> List[Dict]`. Every package has `__init__.py` exporting its tester class.

## WIRING — pick the lightest path that works
| Path | Count | Members |
|------|-------|---------|
| Classic imports in `VulnerabilityScanner.__init__` | 16 | api_security, business_logic, authentication, file_upload, websocket, ml_detection, payload_obfuscation, secrets_scanner, nosql_injection, http_smuggling, race_condition, log4shell, oauth_testing, mass_assignment, prototype_pollution, secret_scanning¹ |
| `_feature_testers` (`_specs` tuple, lazy import) | 27 | cors_csp, jwt_deep, graphql_deep, idor, stored_xss, email_injection, cache_deception, h2_smuggle, supply_chain_js, waf_fingerprint, ssrf_cloud, open_redirect_deep, hpp_pollution, http_method_override, host_header_deep, crlf_header_inject_deep, ssti_engines, api_bola_deep, websocket_deep, sse_injection, cloud_misconfig, php_webshell, frida_mobile, android_static, ios_plist, mobile_ssl_pinning, mobile_ai_chain |
| `ScannerEngine._init_extra_module_testers` | 5 | directory_bruteforce, port_scanner, saml_attacks, subdomain_takeover, cache_poisoning |
| Engine lifecycle (called directly) | 13 | openapi_ingest, auth_session, ai_planner, evidence_summary, fp_replay, template_engine, challenge_solver, login_replay, captcha_detection, intercepting_proxy, ai_triage, cve_intelligence, reconnaissance |
| Standalone / optional | 3 | browser_automation (engine, `smart_tester`), and **not wired into any scan path**: reporting, collaboration (only reachable via `examples/demo_v1.2.0.py`) |

¹ `secret_scanning` is the one classic-import exception: it is wrapped in `try/except` inside `VulnerabilityScanner.__init__` (lines 55–59) and stored as `self._content_secret_scanner`, so a missing package degrades instead of raising.

## SIZE HOTSPOTS (LOC, package total)
`cve_intelligence` 2839 · `reconnaissance` 800 · `api_security` 524 · `reporting` 514 · `browser_automation` 508 · `secrets_scanner` 430 · `template_engine` 373 · `frida_mobile` 350.
Most single-purpose testers are 60–130 LOC in one `tester.py` — copy one of those as a template.

## CONVENTIONS
- Adding a check: package + `__init__.py` export + register in one of the wiring paths above + add the name to `vulnerability_scanner.enabled_checks` in `config.example.yaml` (71 entries).
- Choose `_feature_testers` for anything that can fail to import (heavy/optional deps); the tuple logs and skips instead of crashing engine init.
- `secrets_scanner` (value-pattern detector) and `secret_scanning` (content scanner) are **distinct**; the latter is optional-imported.
- Mobile testers are only driven from the engine's `mobile.*` block, not per-URL scanning.

## ANTI-PATTERNS
- Import `ScannerEngine` from a tester (cycle: engine → scanner → modules).
- Merge `secrets_scanner` / `secret_scanning` casually.
- Skip config gates for side-effectful services (proxy, OAST, browser, Frida attach).
- Rely on import success to mean availability — handshake happens at `scan()` time.
- Assume all 64 packages run in a scan. `reporting/` and `collaboration/` have **no** engine wiring; `browser_automation` is engine-owned, not a `_feature_testers` entry.

## CHILD AGENTS
`cve_intelligence/`, `reconnaissance/`, `template_engine/`, `ai_triage/`, `frida_mobile/`.

