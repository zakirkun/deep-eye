"""Tests for CAPTCHA detection (Group D)."""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from modules.captcha_detection import detect_captcha, CaptchaDetector


HTML_RECAPTCHA = """<html><body>
<form>
  <div class="g-recaptcha" data-sitekey="6LcAAAAAAAAAAAAA"></div>
  <script src="https://www.google.com/recaptcha/api.js"></script>
</form>
</body></html>"""

HTML_HCAPTCHA = """<html><body>
<div class="h-captcha" data-sitekey="abc"></div>
<script src="https://js.hcaptcha.com/1/api.js"></script>
</body></html>"""

HTML_TURNSTILE = """<html><body>
<div class="cf-turnstile" data-sitekey="0xaaa"></div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
</body></html>"""

HTML_GENERIC = """<html><body>
<form>
  <input type="hidden" name="captcha_token" value="x">
  <img src="/captcha.png">
</form>
</body></html>"""

HTML_CLEAN = "<html><body><h1>Welcome</h1></body></html>"


class TestDetectCaptcha:
    def test_recaptcha(self):
        result = detect_captcha(HTML_RECAPTCHA)
        assert result is not None
        assert result["vendor"] == "recaptcha"

    def test_hcaptcha(self):
        result = detect_captcha(HTML_HCAPTCHA)
        assert result is not None
        assert result["vendor"] == "hcaptcha"

    def test_turnstile(self):
        result = detect_captcha(HTML_TURNSTILE)
        assert result is not None
        assert result["vendor"] == "turnstile"

    def test_generic(self):
        result = detect_captcha(HTML_GENERIC)
        assert result is not None
        assert result["vendor"] == "generic"

    def test_no_captcha(self):
        assert detect_captcha(HTML_CLEAN) is None

    def test_empty(self):
        assert detect_captcha("") is None
        assert detect_captcha(None) is None

    def test_vendor_filter(self):
        result = detect_captcha(HTML_RECAPTCHA, vendors=["hcaptcha"])
        assert result is None


class TestCaptchaDetector:
    def test_disabled(self):
        det = CaptchaDetector({"captcha": {"enabled": False}})
        assert det.detect(HTML_RECAPTCHA) is None
        assert not det.is_enabled()

    def test_enabled(self):
        det = CaptchaDetector({"captcha": {"enabled": True}})
        assert det.is_enabled()
        result = det.detect(HTML_RECAPTCHA)
        assert result["vendor"] == "recaptcha"

    def test_vendors_subset(self):
        det = CaptchaDetector({
            "captcha": {"enabled": True, "vendors": ["turnstile"]}
        })
        assert det.detect(HTML_RECAPTCHA) is None
        assert det.detect(HTML_TURNSTILE)["vendor"] == "turnstile"
