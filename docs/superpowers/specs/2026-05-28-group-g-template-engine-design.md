# Group G — Nuclei-Style YAML Template Engine

**Date:** 2026-05-28
**Status:** Design — pending approval
**Scope:** Add a declarative template engine that lets users write vulnerability checks as YAML files, similar to ProjectDiscovery Nuclei. Templates execute via `http_client`, match on response body/status/headers, and produce vuln findings.

---

## Goals

- Lower barrier to add new checks: write YAML, no Python.
- Compatible with a useful subset of the Nuclei DSL (HTTP only).
- Ship a small starter pack of templates.
- Run alongside built-in scanners; produce same vuln dict shape.

## Non-Goals

- 100% Nuclei DSL coverage (network/dns/javascript protocols deferred).
- Workflow chaining.
- Authoring UI.

---

## Architecture

### New module

```
modules/template_engine/
  __init__.py
  parser.py
  matcher.py
  executor.py
  loader.py

templates/
  exposures/git-config-exposure.yaml
  cves/cve-2021-44228-log4shell-headers.yaml
  misconfig/cors-wildcard.yaml
```

### Template schema (Nuclei v3 subset)

```yaml
id: cors-wildcard
info:
  name: CORS Wildcard Origin with Credentials
  author: deep-eye
  severity: high
  description: ...
  tags: [cors, misconfig]
  references: [...]
  classification:
    cwe-id: CWE-942
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/user"
    headers:
      Origin: "https://evil.example.com"
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words: ["Access-Control-Allow-Origin: https://evil.example.com"]
        case-insensitive: true
      - type: word
        part: header
        words: ["Access-Control-Allow-Credentials: true"]
        case-insensitive: true
    extractors:
      - type: regex
        part: header
        regex: ["Access-Control-Allow-Origin:\\s*([^\\r\\n]+)"]
        group: 1
```

### Matcher types

| type | parts | function |
|------|-------|----------|
| `status` | response | match status code in list |
| `word` | header / body | substring match (case-insensitive flag) |
| `regex` | header / body | regex match |
| `size` | response | byte length comparator |
| `dsl` | -- | minimal: `status_code == 200`, `len(body) > 100` |

`matchers-condition: and|or` (default `or`).

### Variables

- `{{BaseURL}}` → target URL stripped of trailing slash
- `{{Hostname}}` → host portion
- `{{RandomString}}` → 8-char alnum

### Vuln dict from template

```python
{
  "type": template['info']['name'],
  "severity": template['info']['severity'],
  "url": str,
  "parameter": "",
  "payload": str(used_payload),
  "evidence": "Matched: <words>",
  "description": template['info']['description'],
  "remediation": "See template references",
  "cve_references": [...],
  "cvss_score": derived_from_severity,
  "template_id": template['id'],
  "template_path": "...",
}
```

### Config

```yaml
templates:
  enabled: false
  template_directories: ["templates"]
  tag_filters: []
  severity_filter: []
```

---

## Components

```
modules/template_engine/
  __init__.py
  parser.py
  matcher.py
  executor.py
  loader.py

templates/                  # ship starter pack
  exposures/git-config-exposure.yaml
  cves/cve-2021-44228-log4shell-headers.yaml
  misconfig/cors-wildcard.yaml

core/scanner_engine.py
  + invoke template engine after built-in scans

config/config.example.yaml
  + templates: {...}
```

---

## Error Handling

| Failure | Behavior |
|---------|----------|
| Invalid YAML | Skip file, log error |
| Schema invalid | Skip template |
| Network error | Skip URL, continue |
| Regex compile error | Treat matcher as not-matched |
| DSL eval error | Treat as not-matched |

Template failures never abort scans.

---

## Testing

- `test_parse_valid_template`
- `test_parse_missing_id_rejects`
- `test_var_substitution_baseurl`
- `test_matcher_word_body`
- `test_matcher_word_header_case_insensitive`
- `test_matcher_regex`
- `test_matcher_status_code`
- `test_matchers_condition_and`
- `test_matchers_condition_or`
- `test_executor_produces_vuln_on_match`
- `test_executor_no_match_no_vuln`
- `test_loader_walks_directory`
- `test_loader_filters_by_tag`
- `test_loader_filters_by_severity`
- `test_extractor_regex_group`

Tests use mock http_client.

---

## Migration / Compat

- All opt-in via config.
- Vuln dict gains optional `template_id`, `template_path`.

---

## Open Questions

None. Locked.

---

## Out of Scope

- Workflow chaining
- network/dns/javascript protocols
- Clusterbomb/pitchfork attack modes
- Authoring UI
