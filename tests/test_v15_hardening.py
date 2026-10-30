"""Registry, config validation, suppression, and OAST correlation."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def test_registry_is_complete():
    from utils.check_registry import ALL_NAMES, BY_KIND

    assert len(ALL_NAMES) == 72
    assert len(BY_KIND["builtin"]) == 23
    assert len(BY_KIND["module"]) == 17
    assert len(BY_KIND["feature"]) == 27
    assert len(BY_KIND["extra"]) == 5


def test_registry_matches_example_config():
    import yaml

    from utils.check_registry import unknown

    path = REPO_ROOT / "config" / "config.example.yaml"
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    enabled = config["vulnerability_scanner"]["enabled_checks"]
    assert len(enabled) == 71
    assert unknown(enabled) == []


def test_unknown_check_names_are_reported():
    from utils.config_validator import validate_config

    config = {
        "scanner": {"default_depth": 2, "default_threads": 5},
        "vulnerability_scanner": {"enabled_checks": ["sql_injection", "sqli_typo"]},
    }
    report = validate_config(config)
    assert report.unknown_checks == ["sqli_typo"]
    assert not report.ok
    assert any("sqli_typo" in issue.message for issue in report.errors)


def test_mobile_checks_warn_when_mobile_disabled():
    from utils.config_validator import validate_config

    config = {
        "scanner": {"default_depth": 2, "default_threads": 5},
        "vulnerability_scanner": {"enabled_checks": ["frida_mobile"]},
        "mobile": {"enabled": False},
    }
    report = validate_config(config)
    assert any("mobile.enabled is false" in issue.message for issue in report.warnings)


def test_passive_mode_strips_state_changing_checks():
    from utils.check_registry import passive_allowed

    names = ["sql_injection", "file_upload", "http_smuggling", "xss"]
    assert passive_allowed(names) == ["sql_injection", "xss"]


def test_passive_mode_blocks_post_in_http_client():
    from utils.http_client import HTTPClient

    client = HTTPClient(config={"passive_mode": True, "scope": {"enabled": False}})
    assert client.post("http://example.test/api", json={"a": 1}) is None


def test_per_host_rate_limiter_tracks_hosts_separately():
    from utils.http_client import HostRateLimiter

    limiter = HostRateLimiter(rate=1000, burst=1000)
    limiter.acquire("https://a.test/x")
    limiter.acquire("https://b.test/y")
    limiter.acquire("https://a.test/z")
    assert limiter.host_count() == 2


def test_http_client_rejects_out_of_scope_url():
    from utils.http_client import HTTPClient

    config = {
        "scope": {
            "enabled": True,
            "allowed_hosts": ["target.test"],
            "excluded_paths": [],
            "allowed_ports": [80, 443],
            "path_allow": [],
        }
    }
    client = HTTPClient(config=config)
    assert client.get("https://evil.test/x") is None


def test_suppression_filters_by_fingerprint(tmp_path):
    import yaml

    from utils.finding_fingerprint import fingerprint
    from utils.suppression import apply_suppressions

    finding = {
        "type": "XSS",
        "url": "https://t.test/a",
        "parameter": "q",
        "payload": "<script>",
        "evidence": "reflected",
        "severity": "high",
    }
    ignore = tmp_path / ".deep-eye.ignore.yml"
    ignore.write_text(
        yaml.safe_dump(
            {
                "suppressions": [
                    {
                        "fingerprint": fingerprint(finding),
                        "reason": "accepted risk",
                        "expires": "2099-01-01",
                        "ticket": "SEC-7",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    kept, suppressed = apply_suppressions(
        [finding], {"reporting": {"suppress_file": str(ignore)}}
    )
    assert kept == []
    assert len(suppressed) == 1
    assert suppressed[0]["suppressed_by"]["ticket"] == "SEC-7"


def test_expired_suppression_stops_suppressing(tmp_path):
    import yaml

    from utils.finding_fingerprint import fingerprint
    from utils.suppression import apply_suppressions

    finding = {"type": "XSS", "url": "https://t.test/a", "parameter": "q"}
    ignore = tmp_path / "ignore.yml"
    ignore.write_text(
        yaml.safe_dump(
            {
                "suppressions": [
                    {"fingerprint": fingerprint(finding), "expires": "2000-01-01"}
                ]
            }
        ),
        encoding="utf-8",
    )
    kept, suppressed = apply_suppressions(
        [finding], {"reporting": {"suppress_file": str(ignore)}}
    )
    assert len(kept) == 1
    assert suppressed == []


def test_oast_token_registry_roundtrip():
    from utils.oast_server import OastTokenRegistry

    registry = OastTokenRegistry("http://oast.test")
    url = registry.register("ssrf", "https://t.test/a", "q")
    assert "/t/" in url
    token = url.rsplit("/", 1)[-1]
    resolved = registry.resolve(f"/t/{token}?c=1")
    assert resolved["check"] == "ssrf"
    assert resolved["parameter"] == "q"


def test_oast_correlation_promotes_only_matching_tokens():
    from utils.oast_server import correlate

    findings = [
        {"type": "SSRF", "severity": "low", "oast_token": "abc"},
        {"type": "SSRF", "severity": "low", "oast_token": "never"},
    ]
    callbacks = [{"path": "/t/abc", "timestamp": "now", "source_ip": "1.2.3.4", "method": "GET"}]
    assert correlate(findings, callbacks) == 1
    assert findings[0]["oast_confirmed"] is True
    assert findings[0]["severity"] == "high"
    assert "oast_confirmed" not in findings[1]


def test_fail_on_gate_thresholds():
    from deep_eye import _fail_on_exit_code

    counts = {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}
    assert _fail_on_exit_code(counts, "high") == 1
    assert _fail_on_exit_code(counts, "critical") == 0
    assert _fail_on_exit_code({"critical": 0, "high": 0}, "low") == 0
