"""Cloudflare / Akamai challenge page detection."""
import re
from typing import Dict, Optional


_CF_BODY_PATTERNS = [
    re.compile(r"<title>\s*Just a moment", re.IGNORECASE),
    re.compile(r"cf-browser-verification", re.IGNORECASE),
    re.compile(r"checking your browser before accessing", re.IGNORECASE),
    re.compile(r"__cf_chl_jschl_tk__", re.IGNORECASE),
    re.compile(r"id=[\"']challenge-form[\"']", re.IGNORECASE),
]

_AKAMAI_BODY_PATTERNS = [
    re.compile(r"Pardon Our Interruption", re.IGNORECASE),
    re.compile(r"reference\s*#?\s*\d+", re.IGNORECASE),
    re.compile(r"_abck", re.IGNORECASE),
]


def detect_challenge(html: str = "", headers: Optional[Dict] = None,
                     vendors: Optional[list] = None) -> Optional[Dict]:
    """Detect Cloudflare or Akamai challenge response."""
    headers = headers or {}
    check = vendors or ["cloudflare", "akamai"]

    if "cloudflare" in check:
        for header_name, header_val in headers.items():
            lname = header_name.lower()
            lval = str(header_val).lower()
            if lname == "cf-mitigated" and lval:
                return {"vendor": "cloudflare", "matched": f"header cf-mitigated: {header_val}"}
        if html:
            for pat in _CF_BODY_PATTERNS:
                m = pat.search(html)
                if m:
                    return {"vendor": "cloudflare", "matched": m.group(0)[:200]}

    if "akamai" in check:
        if html:
            for pat in _AKAMAI_BODY_PATTERNS:
                m = pat.search(html)
                if m:
                    return {"vendor": "akamai", "matched": m.group(0)[:200]}

    return None


class ChallengeDetector:
    """Wrapper for config-driven challenge detection."""

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        cs_cfg = config.get("challenge_solver", {}) if isinstance(config.get("challenge_solver"), dict) else {}
        self.enabled = bool(cs_cfg.get("enabled", False))
        self.vendors = cs_cfg.get("vendors", ["cloudflare", "akamai"])

    def is_enabled(self) -> bool:
        return self.enabled

    def detect(self, html: str = "", headers: Optional[Dict] = None) -> Optional[Dict]:
        if not self.enabled:
            return None
        return detect_challenge(html, headers, self.vendors)
