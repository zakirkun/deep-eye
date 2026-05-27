# Group H — TLS Evasion + CF/Akamai Solver + Intercepting Proxy

**Date:** 2026-05-28
**Status:** Design — pending approval
**Scope:** Three optional, opt-in network features:
1. TLS/JA3 fingerprint evasion via `curl-cffi` browser impersonation.
2. Cloudflare/Akamai challenge detection + Playwright-based cookie warm-up.
3. Local intercepting HTTP proxy for traffic capture.

---

## Goals

- **TLS evasion**: bypass JA3 fingerprinting via curl-cffi browser impersonation.
- **Challenge solver**: detect CF/Akamai challenge HTML, run Playwright once to capture clearance cookies, return them to scanner.
- **Intercepting proxy**: local mitmproxy server scanner routes through; mitmweb UI for inspection.

## Non-Goals

- 100% WAF bypass.
- Custom JA3 authoring.
- Active proxy payload mutation.
- Upstream HTTPS interception.

---

## Architecture

### 1. TLS evasion via curl-cffi

```
utils/http_client.py
  HttpClient
    + use_curl_cffi: bool
    + impersonate: str ("chrome120" | "firefox110" | ...)
    + _adapter: requests.Session OR curl_cffi.Session
```

When `tls_evasion.enabled: true`, HttpClient uses `curl_cffi.requests.Session(impersonate=...)`. Same `get`/`post`/`request` API. Lazy import.

### 2. CF/Akamai challenge solver

```
modules/challenge_solver/
  __init__.py
  detector.py
  solver.py
```

Detection signals:
- Cloudflare: `cf-mitigated` header, "Just a moment..." title, `cf_clearance` expected
- Akamai: `_abck` cookie, "Pardon Our Interruption" body

Solver flow: detect → Playwright headless visit → extract cookies (`cf_clearance`, `_abck`) → inject into http_client.session.cookies. Cached per-domain with TTL.

### 3. Intercepting proxy

```
modules/intercepting_proxy/
  __init__.py
  proxy_runner.py
```

Wraps `mitmweb` CLI subprocess. Listens on configurable port, scanner routes through it via `HttpClient.proxies`. User opens mitmweb UI for live inspection. Stops on scanner exit.

---

## Config

```yaml
tls_evasion:
  enabled: false
  impersonate: "chrome120"
  fallback_to_requests: true

challenge_solver:
  enabled: false
  vendors: [cloudflare, akamai]
  playwright_headless: true
  cookie_ttl_seconds: 1800
  timeout_seconds: 30

intercepting_proxy:
  enabled: false
  mitmweb_port: 8081
  proxy_port: 8080
  bind_host: "127.0.0.1"
```

---

## Components

```
utils/http_client.py
  + curl_cffi adapter when tls_evasion.enabled
  + proxy injection when intercepting_proxy.enabled

modules/challenge_solver/
  __init__.py
  detector.py
  solver.py

modules/intercepting_proxy/
  __init__.py
  proxy_runner.py

deep_eye.py
  + start/stop intercepting proxy
```

---

## Error Handling

| Failure | Behavior |
|---------|----------|
| `curl-cffi` missing | Fall back to `requests`, continue |
| Playwright missing | Skip solver, continue |
| Solver timeout | Return False, record "challenge-protected" finding |
| Proxy subprocess fails | Continue without proxy unless `required: true` |
| mitmproxy not on PATH | Skip proxy |

All three features degrade gracefully.

---

## Testing

`tests/test_tls_evasion.py`:
- `test_http_client_falls_back_when_curl_cffi_missing`
- `test_http_client_uses_curl_cffi_when_enabled`

`tests/test_challenge_solver.py`:
- `test_detect_cloudflare_html`
- `test_detect_cloudflare_header`
- `test_detect_akamai_body`
- `test_no_challenge`
- `test_solver_skipped_when_disabled`
- `test_solver_returns_false_when_playwright_missing`

`tests/test_intercepting_proxy.py`:
- `test_proxy_runner_constructs_command`
- `test_proxy_runner_skip_when_disabled`
- `test_proxy_runner_handles_missing_mitmproxy`

---

## Migration / Compat

- All off by default.
- HttpClient API unchanged.
- Vuln dict unchanged.

---

## Open Questions

None. Locked:
- curl-cffi for TLS
- Playwright for solver
- mitmweb subprocess for proxy
- Lazy install pattern

---

## Out of Scope

- Custom JA3
- Datadome/PerimeterX/Imperva solvers
- Active proxy mutation
- Upstream HTTPS MITM
