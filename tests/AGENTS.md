# TESTS

## OVERVIEW
Flat `tests/`, 34 `test_*.py` + `e2e_litellm.py` (script, not pytest). No `conftest.py`, no `pytest.ini`, no `pyproject.toml`.

## BOOTSTRAP PATTERN (33 of 34 `test_*.py` — copy it)
```python
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
```
Only `test_litellm_provider.py` omits it. Then import lazily *inside* the test function so a missing optional dep fails one test, not collection.

## FILES BY AREA
| Area | Files |
|------|-------|
| Pipeline / core | `test_features_1_19.py`, `test_bugfix_gaps.py`, `test_oracle_verification_gaps.py`, `test_forms_pipeline.py` |
| Exports / diff | `test_export_formats.py`, `test_scan_diff.py` |
| AI layer | `test_ai_tool_calling.py`, `test_openai_claude_providers.py`, `test_ai_payload_generator.py`, `test_ai_triage.py`, `test_litellm_provider.py`, `test_captcha_detection.py` |
| Modules | `test_api_ws_cloud_php.py`, `test_crlf_header_inject_deep.py`, `test_host_header_deep.py`, `test_hpp_pollution.py`, `test_http_method_override.py`, `test_open_redirect_deep.py`, `test_ssti_engines.py`, `test_waf_cache_cors_supply.py`, `test_payload_module_enhance.py`, `test_obfuscation.py`, `test_injection_surfaces.py` |
| CVE / RAG | `test_cve_matching.py`, `test_cve_live_lookup.py`, `test_rag_index.py` |
| Other infra | `test_compliance_mapping.py`, `test_template_engine.py`, `test_challenge_solver.py`, `test_login_replay.py`, `test_intercepting_proxy.py`, `test_mobile_frida.py`, `test_onboard_wizard.py`, `test_proxy_skills.py` |

## CONVENTIONS
- `MagicMock`/`patch` in 122 places; no fixture library beyond `monkeypatch`. Build fake `http_client`/`ai_manager` mocks, don't hit the network.
- 9 skip/importorskip guards around optional deps (playwright, curl_cffi, frida, sklearn). Follow that instead of importing at module top.
- No shared fixtures means every file re-declares its helpers — that is the current norm, not a bug to fix mid-change.
- `e2e_litellm.py` needs `ANTHROPIC_FOUNDRY_API_KEY`+`_BASE_URL`, `ANTHROPIC_API_KEY`, or `OPENAI_API_KEY`; run it directly, never under pytest collection (it has no `test_` prefix, so plain `pytest` skips it).

## GAPS
Directly covered: exports, diff, template engine, compliance, CVE/RAG, AI providers, most v1.4/v1.5 testers, `ScannerEngine` (narrow: CVE-matcher init + mobile phase in `test_cve_matching.py` / `test_mobile_frida.py`), `ScopeManager` (`test_features_1_19.py`).
Not directly covered: `core/subdomain_scanner.py`, `core/pentest_state_manager.py`, `utils/http_client.py`, `utils/notification_manager.py`, `utils/config_loader.py`, `modules/reconnaissance/`, `modules/cve_intelligence/cve_scraper.py`. Add a focused test when you change those.

## COMMANDS
```bash
pip install -r requirements-dev.txt
pytest
pytest tests/test_features_1_19.py -v
pytest tests/test_template_engine.py tests/test_export_formats.py -v
```
