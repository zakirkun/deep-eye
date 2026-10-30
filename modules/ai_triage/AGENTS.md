# AI TRIAGE MODULE

**Scope:** false-positive filtering + bug-bounty report generation. `triage.py` 93 LOC, `bounty_writer.py` 73 LOC, `prompts.py` 44 LOC.

## OVERVIEW
Post-scan AI review. `AITriage` scores each finding for confidence and false-positive likelihood. `BountyWriter` generates per-vuln Markdown reports. Both run in `ScannerEngine.scan` after RAG/compliance enrichment, before the final report. Operates on the results list in-place and can drop entries.

## WHERE TO LOOK
| Task | File | Notes |
|------|------|-------|
| FP filtering | `triage.py` | `_triage_one`, `_parse_ai_json`, `triage_vulnerabilities` |
| Bounty reports | `bounty_writer.py` | `_generate_one`, `generate_reports`, `_slugify` |
| Prompt text | `prompts.py` | JSON triage prompt + Markdown bounty prompt |
| Integration | `core/scanner_engine.py` ~L925 | After RAG/compliance, before `ReportGenerator` |
| Tests | `tests/test_ai_triage.py` | MockAI-based unit tests |

## CONVENTIONS
- Config keys: `ai_triage.enabled`, `drop_false_positives`, `drop_threshold`, `min_severity`; `bug_bounty.enabled`, `format`, `output_directory`, `one_file_per_vuln`.
- `SEVERITY_RANK` is defined separately in `triage.py:16` and `bounty_writer.py:8` — keep them identical if you add a severity.
- `_parse_ai_json` tolerates code fences and prose. Malformed responses get confidence 0.4 and the finding is kept.
- `triage_vulnerabilities` mutates the list in place; `drop_fps` rebuilds it, discarding high-confidence FPs.
- Engine re-syncs `results['vulnerabilities']` and recomputes `severity_summary` after triage — triage happens before the engine's final summary.
- Bounty writer skips `false_positive=True` vulns regardless of severity.

## ANTI-PATTERNS
- Do not crash the scan if the AI provider fails (it may legitimately return `""`); both classes catch and degrade.
- Do not drop FPs below `drop_threshold`. Borderline cases stay for human review.
- Do not write bounty files when `one_file_per_vuln` is false. Only attach `bounty_report` to the dict.
- Do not invent new severity strings. Use the same `critical|high|medium|low|info` scale as the rest of the scanner.
