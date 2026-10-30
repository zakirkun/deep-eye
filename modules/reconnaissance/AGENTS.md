# RECONNAISSANCE MODULE

**Scope:** this package only. 4 files, ~800 LOC — the second-largest `modules/` package.

## OVERVIEW
Recon + OSINT gathering. **Deviation from the module standard:** there is no `(http_client, config)` + `scan(url, context)` contract here. Three classes with three different entry points.

## STRUCTURE
| File | LOC | Class | Ctor | Entry |
|------|-----|-------|------|-------|
| `recon_engine.py` | 156 | `ReconEngine` | `(config, http_client)` — reversed | `run(target_url) -> Dict` |
| `subdomain_hunter.py` | 239 | `SubdomainHunter` | `(config)` — no http client | `discover_subdomains(domain, aggressive=True) -> Set[str]` |
| `osint_enhanced.py` | 398 | `EnhancedOSINT` | `(http_client, config)` | `gather_intelligence(target) -> Dict` |
| `__init__.py` | 7 | exports `EnhancedOSINT` / alias `OSINTEnhanced` **only** | | |

`ReconEngine` and `SubdomainHunter` are imported by path elsewhere, not through `__init__`:
`core/scanner_engine.py:21` imports `ReconEngine`; `core/subdomain_scanner.py:13` imports `SubdomainHunter`.

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Add a recon phase step | `recon_engine.run` — each step is `if '<name>' in self.enabled_modules` |
| Add an OSINT source | `osint_enhanced.py` (`find_email_addresses`, `find_social_media_accounts`, `check_data_breaches`, `find_exposed_files`, `search_web_archives`, `gather_dns_intelligence`, `check_certificate_transparency`) |
| Add a subdomain source | `subdomain_hunter.py` (`_crt_sh`, `_dns_bruteforce`, `_search_engines`, `_common_subdomains`) |
| Engine wiring | `ScannerEngine.run_reconnaissance` → `self.recon_engine.run(target_url)` |

## CONVENTIONS
- `ReconEngine.enabled_modules` is a plain list of strings from `reconnaissance.enabled_modules`; unknown names are silently ignored. There is no registry — adding a module means adding an `if` branch.
- Only **6** names actually branch: `dns_records`, `whois_lookup`, `technology_detection`, `ssl_certificate_info`, `subdomain_enumeration`, `osint_gathering`. The example YAML also lists `port_scanning`, `directory_bruteforce`, `email_harvesting` — those three are dead config keys (email harvesting happens inside `osint_gathering` instead).
- `osint_gathering` results are flattened into `results['osint']` keys (`emails`, `subdomains`, `technologies`, `breaches`, `github_leaks`, `social_media`, `cloud_resources`) for report consumption.
- `EnhancedOSINT` reads `osint.*` (all `true` by default in the example) and `osint.hibp_api_key` for breaches.
- Subdomain sources are network-bound public APIs (crt.sh, hackertarget, threatcrowd, virustotal) — expect rate limits and full-scan slowness.
- Recon runs only when `scanner.enable_recon: true`; subdomain scanning is a second, separate gate: `experimental.enable_subdomain_scanning`.

## ANTI-PATTERNS
- Do not call these classes from a per-URL check; they are scan-lifecycle scoped.
- Do not assume `__init__.py` exposes all three classes.
- Do not add a recon module without both the `if` branch and the `reconnaissance.enabled_modules` YAML entry.
- No unit tests cover this package — add one before changing parsing/normalisation logic.
