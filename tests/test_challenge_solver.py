"""Tests for CF/Akamai challenge detection (Group H)."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules.challenge_solver import detect_challenge, ChallengeDetector, ChallengeSolver


HTML_CF = """<html><head><title>Just a moment...</title></head>
<body>
  <div id="challenge-form">
    <input name="__cf_chl_jschl_tk__" value="abc">
  </div>
</body></html>"""

HTML_AKAMAI = """<html><body>
<h1>Pardon Our Interruption</h1>
<p>reference #18.abcd1234</p>
</body></html>"""

HTML_CLEAN = "<html><body><h1>Welcome</h1></body></html>"


class TestDetect:
    def test_cloudflare_body(self):
        result = detect_challenge(html=HTML_CF)
        assert result is not None
        assert result["vendor"] == "cloudflare"

    def test_cloudflare_header(self):
        result = detect_challenge(headers={"cf-mitigated": "challenge"})
        assert result is not None
        assert result["vendor"] == "cloudflare"

    def test_akamai_body(self):
        result = detect_challenge(html=HTML_AKAMAI)
        assert result is not None
        assert result["vendor"] == "akamai"

    def test_clean_html(self):
        assert detect_challenge(html=HTML_CLEAN) is None

    def test_empty_inputs(self):
        assert detect_challenge() is None
        assert detect_challenge(html="") is None

    def test_vendor_filter(self):
        result = detect_challenge(html=HTML_CF, vendors=["akamai"])
        assert result is None


class TestChallengeDetector:
    def test_disabled(self):
        det = ChallengeDetector({"challenge_solver": {"enabled": False}})
        assert det.detect(html=HTML_CF) is None
        assert not det.is_enabled()

    def test_enabled(self):
        det = ChallengeDetector({"challenge_solver": {"enabled": True}})
        assert det.is_enabled()
        assert det.detect(html=HTML_CF)["vendor"] == "cloudflare"


class TestSolver:
    def test_disabled(self):
        client = MagicMock()
        solver = ChallengeSolver(client, {"challenge_solver": {"enabled": False}})
        assert solver.solve("https://example.com") is False

    def test_playwright_missing_returns_false(self, monkeypatch):
        client = MagicMock()
        solver = ChallengeSolver(client, {"challenge_solver": {"enabled": True}})
        monkeypatch.setattr(solver, "_ensure_playwright", lambda: False)
        assert solver.solve("https://example.com") is False

    def test_cache_hit(self):
        import time
        client = MagicMock()
        solver = ChallengeSolver(client, {
            "challenge_solver": {"enabled": True, "cookie_ttl_seconds": 1800}
        })
        solver._cache["example.com"] = (time.time(), {"cf_clearance": "x"})
        assert solver.solve("https://example.com/path") is True
