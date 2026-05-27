# Group I — async/httpx Migration

**Date:** 2026-05-28
**Status:** Design — DEFERRED. Spec only. Implementation requires dedicated session.
**Scope:** Replace synchronous `requests` + `ThreadPoolExecutor` with `httpx.AsyncClient` + `asyncio` across the entire codebase.

---

## Why Deferred

This is the only XL change in the 13-feature backlog. It is **not additive** — every scanner method, every test, every URL fetch site touches it. Shipping it incrementally produces a codebase that is half sync, half async, with conversion shims at every boundary. That tax compounds.

Reasonable scope: a dedicated branch (`feat/async-migration`), all 30+ scan modules rewritten together, full test suite ported, CI green before merge.

## Goals (when implemented)

- Single async client (`httpx.AsyncClient`) replaces `requests.Session`.
- Concurrency via `asyncio.Semaphore` instead of `ThreadPoolExecutor`.
- Streaming response bodies for large content.
- HTTP/2 support (httpx default).
- Per-host connection pooling.
- Cancellation propagates cleanly.

## Non-Goals

- Maintain sync API surface in parallel.
- Custom event loop integration.

---

## Architecture (proposed)

### HttpClient rewrite

```python
class HttpClient:
    async def __aenter__(self): ...
    async def __aexit__(self, ...): ...
    async def get(self, url, **kwargs) -> httpx.Response: ...
    async def post(self, url, **kwargs) -> httpx.Response: ...
```

Internal: single `httpx.AsyncClient(http2=True, limits=...)`.

### Scanner methods

```python
class VulnerabilityScanner:
    async def _check_sql_injection(self, url, payloads): ...
    async def _check_xss(self, url, payloads): ...
    # ... all 45+ check methods
```

### Scan loop

```python
async def scan_all_urls(self, urls):
    sem = asyncio.Semaphore(self.threads)
    async def bounded(url):
        async with sem:
            return await self.scan_url(url)
    results = await asyncio.gather(*(bounded(u) for u in urls), return_exceptions=True)
```

### CLI entry

```python
def main():
    asyncio.run(_amain())
```

---

## Migration steps

1. Replace `requests` → `httpx[http2]` in requirements.txt.
2. Rewrite `utils/http_client.py` to async — keep TokenBucket, retry logic.
3. Rewrite `core/scanner_engine.py` `scan_all_urls`, `scan_url`, helpers.
4. Rewrite `core/vulnerability_scanner.py` — every `_check_*` method.
5. Rewrite each `modules/*/scanner.py` / `tester.py` to async.
6. Rewrite `deep_eye.py` `main()` via `asyncio.run`.
7. Rewrite all tests using `pytest-asyncio` `async def` style.
8. Update Group D login_replay player → async.
9. Update Group G template executor → async.
10. RAG (Group F) stays sync (CPU-bound — wrap in `asyncio.to_thread` if called from async).
11. AI triage (Group C) — async if provider is async; else `asyncio.to_thread`.

---

## Open Questions

- Keep sync API for embedders? Recommend: no — clean cut.
- Order: bottom-up (http_client first) → vuln_scanner → scanner_engine → main.

---

## Out of Scope

- Staged migration (one module at a time) — too many shim layers, not worth.

---

## Why Spec Only This Session

Implementation must:
- be its own branch (`feat/async-migration`)
- ship as a single PR (architectural)
- run the full existing test suite ported to async-aware fixtures
- be reviewed independent of the 7 additive groups already merged
