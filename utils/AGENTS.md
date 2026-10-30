# UTILS KNOWLEDGE BASE

## OVERVIEW
Shared infrastructure — no attack logic. 12 modules + 2 subpackages, ~2.75k LOC.

## STRUCTURE
| File / dir | LOC | Purpose |
|------------|-----|---------|
| `onboard.py` | 510 | Interactive config wizard (runs when `config/config.yaml` is missing) |
| `notification_manager.py` | 449 | Email / Slack / Discord sending, per-channel gates |
| `http_client.py` | 303 | `TokenBucket` + `HTTPClient`; optional `curl_cffi` TLS impersonation |
| `parser.py` | 193 | HTML/form/param extraction |
| `config_loader.py` | 99 | YAML load + recursive `${ENV_VAR}` / `${ENV_VAR:-default}` substitution |
| `nl_scope.py` | 86 | `parse_nl_scope`, `apply_nl_scope_to_config` |
| `oast_server.py` | 83 | Local OAST listener |
| `ai_summary_generator.py` | 83 | Short AI summaries |
| `cvss_cwe_mapper.py` | 74 | Score/CWE lookup |
| `logger.py` | 64 | `get_logger`, `setup_logger` |
| `finding_fingerprint.py` | 61 | `fingerprint`, `dedupe_findings`, `identity_tuple` |
| `scope_manager.py` | 54 | Host/port/path allow + `path_allow` |
| `exports/` | 595 | junit / csv / xlsx / diff builders — see `exports/AGENTS.md` |
| `compliance/` | 103 | Framework JSON mapping — see below |

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Add HTTP header / retry / rate limit | `http_client.py` (`get`, `post`, `head`, `options`) |
| Change dedupe identity | `finding_fingerprint.py` — but see ANTI-PATTERNS |
| Scope syntax | `scope_manager.py` (`allowed_hosts`, `excluded_paths` regex, `path_allow`) |
| NL → scope | `nl_scope.apply_nl_scope_to_config` |
| New export format | `exports/AGENTS.md` |
| New compliance framework | `compliance/mapper.FRAMEWORK_KEYS` + a `frameworks/*.json` |

## COMPLIANCE
- `FRAMEWORK_KEYS` maps config key → (filename, display name): `pci_dss`, `soc2`, `iso_27001`.
- Each `frameworks/*.json` has `framework`, `version`, `_source`, `controls`, `vuln_mappings`.
- All three files ship **42** `vuln_mappings` entries; keep them in parity when adding one.
- `enrich_vulnerabilities` mutates in place, adding a `compliance` dict keyed by display name.
- `load_frameworks` caches in module-level `_cache` — a test that mutates a loaded framework leaks into later tests.

## CONVENTIONS
- One shared `HTTPClient` from the engine; nothing here constructs its own.
- Export builders are pure functions returning `str`/`bytes`; callers write files.
- Scope regexes are compiled at construction — invalid patterns raise at init, not at request time.

## ANTI-PATTERNS
- Second `HTTPClient` per module.
- Scan/payload logic inside utils.
- Writing files inside builders.
- Changing `fingerprint()` inputs casually — it is the dedupe **and** diff identity; baselines silently change meaning.
- Removing `identity_tuple` fields used by `core/scan_diff.py`.
