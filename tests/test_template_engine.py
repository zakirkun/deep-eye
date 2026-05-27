"""Tests for template engine (Group G)."""
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

yaml_available = True
try:
    import yaml  # noqa: F401
except ImportError:
    yaml_available = False

pytestmark = pytest.mark.skipif(not yaml_available, reason="PyYAML not installed")

from modules.template_engine import (
    parse_template,
    parse_template_file,
    TemplateError,
    evaluate_matchers,
    run_extractors,
    TemplateExecutor,
    substitute_vars,
    load_templates,
)


VALID_TEMPLATE_YAML = textwrap.dedent("""
id: test-template
info:
  name: Test Template
  author: tester
  severity: medium
  description: testing
  tags: [test, demo]
http:
  - method: GET
    path:
      - "{{BaseURL}}/api"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words:
          - "vulnerable"
""")


class MockResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class MockHttpClient:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def get(self, url, headers=None, **kwargs):
        self.calls.append(("get", url, headers))
        return self.responses.get(url, MockResponse())

    def post(self, url, data=None, headers=None, **kwargs):
        self.calls.append(("post", url, data, headers))
        return self.responses.get(url, MockResponse())


class TestParser:
    def test_parse_valid(self):
        tpl = parse_template(VALID_TEMPLATE_YAML)
        assert tpl["id"] == "test-template"
        assert tpl["info"]["severity"] == "medium"

    def test_missing_id(self):
        bad = textwrap.dedent("""
        info:
          name: x
          severity: high
        http:
          - path: ["{{BaseURL}}/"]
        """)
        with pytest.raises(TemplateError):
            parse_template(bad)

    def test_invalid_severity(self):
        bad = textwrap.dedent("""
        id: x
        info:
          name: x
          severity: omega
        http:
          - path: ["{{BaseURL}}/"]
        """)
        with pytest.raises(TemplateError):
            parse_template(bad)

    def test_invalid_matcher_type(self):
        bad = textwrap.dedent("""
        id: x
        info:
          name: x
          severity: low
        http:
          - path: ["{{BaseURL}}/"]
            matchers:
              - type: bogus
        """)
        with pytest.raises(TemplateError):
            parse_template(bad)

    def test_parse_file(self, tmp_path):
        p = tmp_path / "t.yaml"
        p.write_text(VALID_TEMPLATE_YAML, encoding="utf-8")
        tpl = parse_template_file(str(p))
        assert tpl["id"] == "test-template"


class TestVarSubstitution:
    def test_baseurl(self):
        assert substitute_vars("{{BaseURL}}/api", "https://example.com/") == "https://example.com/api"

    def test_hostname(self):
        result = substitute_vars("Origin: {{Hostname}}", "https://example.com:8080/x")
        assert result == "Origin: example.com:8080"

    def test_random_string(self):
        a = substitute_vars("{{RandomString}}", "https://example.com")
        assert len(a) == 8


class TestMatchers:
    def test_status_match(self):
        r = MockResponse(status_code=200)
        ok, _ = evaluate_matchers(r, [{"type": "status", "status": [200, 201]}])
        assert ok

    def test_status_no_match(self):
        r = MockResponse(status_code=404)
        ok, _ = evaluate_matchers(r, [{"type": "status", "status": [200]}])
        assert not ok

    def test_word_body(self):
        r = MockResponse(text="server is vulnerable to attack")
        ok, _ = evaluate_matchers(r, [
            {"type": "word", "part": "body", "words": ["vulnerable"]}
        ])
        assert ok

    def test_word_header_case_insensitive(self):
        r = MockResponse(headers={"X-Powered-By": "Apache Struts"})
        ok, _ = evaluate_matchers(r, [
            {"type": "word", "part": "header",
             "words": ["x-powered-by: apache"], "case-insensitive": True}
        ])
        assert ok

    def test_regex_body(self):
        r = MockResponse(text="DB_PASSWORD=hunter2")
        ok, _ = evaluate_matchers(r, [
            {"type": "regex", "part": "body",
             "regex": [r"DB_PASSWORD=\w+"]}
        ])
        assert ok

    def test_size(self):
        r = MockResponse(text="abc")
        ok, _ = evaluate_matchers(r, [{"type": "size", "size": [3, 5]}])
        assert ok

    def test_dsl_status(self):
        r = MockResponse(status_code=200, text="x" * 50)
        ok, _ = evaluate_matchers(r, [
            {"type": "dsl", "dsl": ["status_code == 200", "len(body) > 10"], "condition": "and"}
        ])
        assert ok

    def test_condition_and(self):
        r = MockResponse(status_code=200, text="vulnerable")
        ok, _ = evaluate_matchers(
            r,
            [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "words": ["vulnerable"]},
            ],
            condition="and",
        )
        assert ok

    def test_condition_or_partial(self):
        r = MockResponse(status_code=404, text="vulnerable")
        ok, _ = evaluate_matchers(
            r,
            [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body", "words": ["vulnerable"]},
            ],
            condition="or",
        )
        assert ok

    def test_unknown_matcher(self):
        r = MockResponse()
        ok, _ = evaluate_matchers(r, [{"type": "bogus"}])
        assert not ok


class TestExtractors:
    def test_regex_extractor(self):
        r = MockResponse(text="version=2.4.50 patch=1")
        out = run_extractors(r, [{
            "type": "regex", "part": "body",
            "name": "version", "regex": [r"version=([\d.]+)"], "group": 1,
        }])
        assert out["version"] == ["2.4.50"]


class TestExecutor:
    def test_produces_vuln_on_match(self):
        client = MockHttpClient(responses={
            "https://example.com/api": MockResponse(200, "this app is vulnerable"),
        })
        executor = TemplateExecutor(client)
        tpl = parse_template(VALID_TEMPLATE_YAML)
        findings = executor.run(tpl, "https://example.com")
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "Test Template"
        assert f["severity"] == "medium"
        assert f["template_id"] == "test-template"

    def test_no_match_no_vuln(self):
        client = MockHttpClient(responses={
            "https://example.com/api": MockResponse(200, "all good"),
        })
        executor = TemplateExecutor(client)
        tpl = parse_template(VALID_TEMPLATE_YAML)
        findings = executor.run(tpl, "https://example.com")
        assert findings == []

    def test_status_only_no_match_with_and(self):
        client = MockHttpClient(responses={
            "https://example.com/api": MockResponse(200, "no match"),
        })
        executor = TemplateExecutor(client)
        tpl = parse_template(VALID_TEMPLATE_YAML)
        findings = executor.run(tpl, "https://example.com")
        assert findings == []


class TestLoader:
    def test_walks_directory(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "a.yaml").write_text(VALID_TEMPLATE_YAML, encoding="utf-8")

        second = VALID_TEMPLATE_YAML.replace("id: test-template", "id: another-template")
        (tmp_path / "sub" / "b.yml").write_text(second, encoding="utf-8")

        templates = load_templates([str(tmp_path)])
        ids = sorted(t["id"] for t in templates)
        assert ids == ["another-template", "test-template"]

    def test_skips_invalid_yaml(self, tmp_path):
        (tmp_path / "good.yaml").write_text(VALID_TEMPLATE_YAML, encoding="utf-8")
        (tmp_path / "bad.yaml").write_text("this is: : : invalid yaml: : [", encoding="utf-8")

        templates = load_templates([str(tmp_path)])
        assert any(t["id"] == "test-template" for t in templates)

    def test_filter_by_tag(self, tmp_path):
        (tmp_path / "t.yaml").write_text(VALID_TEMPLATE_YAML, encoding="utf-8")
        other = VALID_TEMPLATE_YAML.replace(
            "id: test-template", "id: other-template"
        ).replace("tags: [test, demo]", "tags: [other]")
        (tmp_path / "o.yaml").write_text(other, encoding="utf-8")

        templates = load_templates([str(tmp_path)], tag_filters=["test"])
        ids = [t["id"] for t in templates]
        assert "test-template" in ids
        assert "other-template" not in ids

    def test_filter_by_severity(self, tmp_path):
        (tmp_path / "med.yaml").write_text(VALID_TEMPLATE_YAML, encoding="utf-8")
        high = VALID_TEMPLATE_YAML.replace(
            "id: test-template", "id: high-template"
        ).replace("severity: medium", "severity: high")
        (tmp_path / "high.yaml").write_text(high, encoding="utf-8")

        templates = load_templates([str(tmp_path)], severity_filter=["high"])
        ids = [t["id"] for t in templates]
        assert ids == ["high-template"]

    def test_missing_directory(self, tmp_path):
        result = load_templates([str(tmp_path / "nonexistent")])
        assert result == []
