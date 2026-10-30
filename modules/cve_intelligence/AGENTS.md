# CVE INTELLIGENCE MODULE

## OVERVIEW
CVE intelligence pipeline: fetch → store in SQLite → match findings → optional RAG enrichment. **RAG is TF-IDF + pickle, not ChromaDB** (older docs are stale). 5 modules, ~2.8k LOC — the largest package in the repo.

## STRUCTURE
| File | LOC | Role |
|------|-----|------|
| `cve_scraper.py` | 1725 | NVD/API scraper → `data/cve_intelligence.db`. **Hotspot.** |
| `cve_matcher.py` | 695 | Matches findings to CVE records by keyword/product/vendor/version |
| `live_lookup.py` | 229 | Optional online NVD 2.0 + GitHub POC search |
| `rag_index.py` | 189 | `CVERagIndex` — TF-IDF matrix persisted as pickle |

Build scripts live at repo root: `scripts/update_cve_database.py`, `scripts/build_cve_rag_index.py`.

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add a CVE source | `cve_scraper.py` | Prefer a new helper module over inline growth |
| Matching rules | `cve_matcher.py` | `get_cve_matcher(config, auto_seed=True)` |
| Vector search | `rag_index.py` | `CVERagIndex(config)`; `build/load/save/is_stale/search(query, top_k)` |
| Refresh DB | `scripts/update_cve_database.py` | Idempotent |
| Rebuild index | `scripts/build_cve_rag_index.py` | Idempotent |
| Integration | `core/scanner_engine.py` ~L878 | Matcher enrich, then RAG if `rag.enabled` |
| Tests | `tests/test_rag_index.py`, `test_cve_matching.py`, `test_cve_live_lookup.py` | |

## CONVENTIONS
- Matching is gated by `experimental.enable_cve_matching`; RAG by `rag.enabled` (independent switches).
- Config keys: `experimental.cve_database_path`, `cve_intelligence.database_path`, `rag.*`, `vulnerability_scanner.payload_generation.cve_database`.
- `enrich_vulnerability` sets `related_cves`, `cve_references`, `cve_matched`, `cve_links`.
- Severity `UNKNOWN` is treated as `LOW` so sparse scrapes still match.
- `CVERagIndex` lazy-imports scikit-learn via `_ensure_sklearn()`; when stdin is not a TTY it silently returns False, so CI must preinstall `scikit-learn`.
- Auto-rebuild: engine calls `rag.is_stale(db_path)` then `build(..., interactive=False)` when `rag.auto_rebuild` (default true).
- RAG only fills `cve_references` when a finding has none (`if hits and not vuln.get('cve_references')`).

## ENABLE
```yaml
experimental:
  enable_cve_matching: true
  cve_database_path: "data/cve_intelligence.db"
  cve_live_lookup: true          # optional online NVD/GitHub refs
  nvd_api_key: ""                # optional NIST key
  github_token: ""
rag:
  enabled: true
  auto_rebuild: true
  top_k: 3
vulnerability_scanner:
  payload_generation:
    cve_database: true
```
```bash
python scripts/update_cve_database.py
python scripts/build_cve_rag_index.py
pytest tests/test_cve_matching.py tests/test_cve_live_lookup.py tests/test_rag_index.py -v
```

## ANTI-PATTERNS
- Do not describe or "restore" ChromaDB — the index is a TF-IDF pickle matrix; there is no vector DB in this package.
- Do not vendor or import third-party tools that forbid integration (e.g. the exploit-eye license).
- Do not call the NVD API in unit tests; `test_cve_live_lookup.py` is the guarded exception.
- Do not grow `cve_scraper.py` further without a reason; it is already the repo's biggest file.

