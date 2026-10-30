# EXPORTS MODULE

**Scope:** JUnit XML, CSV, XLSX, and diff renderers for scan results. 5 builders, 595 LOC.

## OVERVIEW
Pure builder functions that turn vulnerability result lists into bytes or strings.
`junit`/`csv`/`xlsx` are called by `ReportGenerator`; `diff_renderer` is called directly from `deep_eye.py:196` (`--diff` mode).
No I/O here; callers handle file writes.

## STRUCTURE
```
utils/exports/
├── __init__.py        # Re-exports build_*; __all__ is the registry
├── junit_builder.py   # 99 LOC  — build_junit_xml(results) -> str
├── csv_builder.py     # 85 LOC  — build_csv(results) -> str
├── xlsx_builder.py    # 271 LOC — build_xlsx(results) -> bytes (openpyxl, lazy)
└── diff_renderer.py   # 135 LOC — render_html/json/csv for scan diffs (not in __all__)
```

## WHERE TO LOOK
| Task | File | Notes |
|------|------|-------|
| Add export format | New `*_builder.py` + `__init__.py` | Must return bytes or str |
| Diff reports | `diff_renderer.py` | Imported **directly** by `deep_eye.py` (`_run_diff_mode`); it is not in `__all__` |
| Format tests | `tests/test_export_formats.py` | All builders |
| Diff tests | `tests/test_scan_diff.py` | Diff renderer coverage |
| XLSX dependency | `xlsx_builder.py:46` | `_ensure_openpyxl()` lazy-installs `openpyxl` — not in `requirements.txt` |

## CONVENTIONS
- Builder signature: `build_<format>(results: List[Dict]) -> Union[str, bytes]`.
- Register in `__init__.__all__` so `ReportGenerator` discovers it. Current `__all__` is exactly `build_junit_xml`, `build_csv`, `build_xlsx`.
- Input dicts use standard vuln keys: `type`, `severity`, `url`, `parameter`, `evidence`.
- Keep dependencies minimal; xlsx uses `openpyxl`, junit uses stdlib `xml.etree`.
- `xlsx_builder` writes five sheets: Summary, Vulnerabilities, Reconnaissance, CVEs, Compliance (placeholder — currently empty).
- `SEVERITY_COLORS` maps each severity to a (bg, font) hex pair; add new severities there, nowhere else.

## ANTI-PATTERNS
- Do not open/write files inside builders; return data only.
- Do not add side effects (logging, HTTP calls, DB reads).
- Do not skip `__all__` registration for new builders.
- Do not invent new vuln result keys; stick to the standard dict shape.
