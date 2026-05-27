"""CAPTCHA vendor detection from HTML.

Identifies reCAPTCHA, hCaptcha, Cloudflare Turnstile, and generic CAPTCHA forms.
Returns vendor info when detected; None otherwise.
"""
import re
from typing import Dict, List, Optional


# Vendor signatures: (vendor_name, list of regex patterns)
_VENDOR_PATTERNS = {
    "recaptcha": [
        r'src=["\'][^"\']*google\.com/recaptcha',
        r'class=["\'][^"\']*\bg-recaptcha\b',
        r'<iframe[^>]+src=["\'][^"\']*google\.com/recaptcha',
        r'data-sitekey=["\'][^"\']+["\'][^>]*g-recaptcha',
    ],
    "hcaptcha": [
        r'src=["\'][^"\']*hcaptcha\.com',
        r'class=["\'][^"\']*\bh-captcha\b',
        r'<iframe[^>]+src=["\'][^"\']*hcaptcha\.com',
    ],
    "turnstile": [
        r'src=["\'][^"\']*challenges\.cloudflare\.com/turnstile',
        r'class=["\'][^"\']*\bcf-turnstile\b',
    ],
    "generic": [
        r'<input[^>]+type=["\']hidden["\'][^>]+name=["\'][^"\']*captcha[^"\']*["\']',
        r'<img[^>]+src=["\'][^"\']*captcha[^"\']*["\']',
        r'<label[^>]*>\s*captcha\s*</label>',
    ],
}


def detect_captcha(html: str, vendors: Optional[List[str]] = None) -> Optional[Dict]:
    """Detect CAPTCHA vendor in HTML.

    Returns:
        {"vendor": ..., "matched": ...} or None.
    """
    if not html:
        return None

    check_vendors = vendors or list(_VENDOR_PATTERNS.keys())
    for vendor in check_vendors:
        patterns = _VENDOR_PATTERNS.get(vendor, [])
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return {
                    "vendor": vendor,
                    "matched": match.group(0)[:200],
                }
    return None


class CaptchaDetector:
    """Wrapper class for config-driven detection."""

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        captcha_cfg = config.get("captcha", {}) if isinstance(config.get("captcha"), dict) else {}
        self.enabled = bool(captcha_cfg.get("enabled", False))
        self.skip_protected = bool(captcha_cfg.get("skip_protected", True))
        self.vendors = captcha_cfg.get(
            "vendors", ["recaptcha", "hcaptcha", "turnstile", "generic"]
        )

    def is_enabled(self) -> bool:
        return self.enabled

    def detect(self, html: str, url: str = "") -> Optional[Dict]:
        if not self.enabled:
            return None
        return detect_captcha(html, vendors=self.vendors)
