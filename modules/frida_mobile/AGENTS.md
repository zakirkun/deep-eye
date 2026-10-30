# MOBILE / FRIDA

**Scope:** this file documents the **mobile cluster** — five sibling packages driven from one `mobile.*` config block in the engine, not just `frida_mobile/`.

## OVERVIEW
Static + dynamic mobile helpers. Frida scripts generated offline; live attach optional and off by default. `frida_mobile/tester.py` is 348 LOC and holds the whole tester for this package.

## MODULES
| Package | Role |
|---------|------|
| `frida_mobile` | Write Frida JS hooks; AI payload advice + attack chain |
| `android_static` | APK zip heuristics (debuggable, backup, secrets) |
| `ios_plist` | Info.plist ATS + URL schemes |
| `mobile_ssl_pinning` | Detect pinning indicators |
| `mobile_ai_chain` | Ordered attack chain + suggested payloads (AI optional) |

## ENABLE
```yaml
mobile:
  enabled: true
  platform: android   # or ios
  package: com.example.app
  artifact: path/to/app.apk
  use_ai: true
  script_output_dir: reports/frida_scripts
  try_attach: false
  spawn: false
  device: ""

vulnerability_scanner:
  enabled_checks:
    - frida_mobile
    - android_static
    - ios_plist
    - mobile_ssl_pinning
    - mobile_ai_chain
```

## HOW IT RUNS
- `ScannerEngine.scan` runs mobile **before** crawl, outside the per-URL loop — these five are never dispatched by `scan_url`.
- Engine filters `_feature_testers` by name (the 5 above) **and** re-checks `enabled_checks`, then calls `tester.scan(target_url, mobile_ctx)`.
- `mobile_ctx` carries `platform`, `package`, `artifact`, `ai_manager`; `mobile_ai_chain` additionally receives accumulated `mobile_findings`.
- Findings get `source: "mobile"`; `results["mobile_findings"]` is a count.
- Whole phase is try/except-wrapped: failures log a warning and the scan continues.

## AI
- `set_ai_manager` injected from ScannerEngine for Frida + mobile_ai_chain.
- Without AI: heuristic chain/payloads still returned.
- With AI: JSON hooks/payloads/attack_chain merged into findings (`ai_payload_advice`, `attack_chain`).

## ANTI-PATTERNS
- Do not add a mobile tester without also adding it to the engine's hardcoded name tuple — it will never run.
- `try_attach: true` needs `frida-tools` plus a device; never enable it in CI.

## VERIFY
```bash
pytest tests/test_mobile_frida.py -v
```
