"""Playwright-based challenge solver — gets cf_clearance / _abck cookies."""
import logging
import time
from typing import Dict, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ChallengeSolver:
    """Solves CF/Akamai challenges via headless browser, hands cookies back to http_client."""

    def __init__(self, http_client, config: Optional[Dict] = None):
        self.http_client = http_client
        config = config or {}
        cs_cfg = config.get("challenge_solver", {}) if isinstance(config.get("challenge_solver"), dict) else {}
        self.enabled = bool(cs_cfg.get("enabled", False))
        self.headless = bool(cs_cfg.get("playwright_headless", True))
        self.cookie_ttl = int(cs_cfg.get("cookie_ttl_seconds", 1800))
        self.timeout = int(cs_cfg.get("timeout_seconds", 30))
        self._cache: Dict[str, tuple] = {}

    def is_enabled(self) -> bool:
        return self.enabled

    def _domain_of(self, url: str) -> str:
        try:
            return urlparse(url).netloc
        except Exception:
            return url

    def _is_cached(self, domain: str) -> bool:
        if domain not in self._cache:
            return False
        ts, _ = self._cache[domain]
        return (time.time() - ts) < self.cookie_ttl

    def _ensure_playwright(self) -> bool:
        try:
            import playwright.sync_api  # noqa: F401
            return True
        except ImportError:
            logger.warning("ChallengeSolver: playwright not installed")
            return False

    def solve(self, url: str) -> bool:
        """Solve challenge. Returns True if cookies obtained.

        Cookies injected into http_client.session.cookies on success.
        """
        if not self.enabled:
            return False

        domain = self._domain_of(url)
        if self._is_cached(domain):
            logger.debug(f"ChallengeSolver: cache hit for {domain}")
            return True

        if not self._ensure_playwright():
            return False

        try:
            return self._solve_playwright(url, domain)
        except Exception as e:
            logger.error(f"ChallengeSolver: error solving {url}: {e}")
            return False

    def _solve_playwright(self, url: str, domain: str) -> bool:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            try:
                context = browser.new_context()
                page = context.new_page()
                page.goto(url, timeout=self.timeout * 1000)
                page.wait_for_timeout(min(self.timeout * 1000, 8000))

                cookies = context.cookies()
                interesting = [c for c in cookies if c["name"] in ("cf_clearance", "_abck", "ak_bmsc", "bm_sv")]
                if not interesting:
                    logger.warning(f"ChallengeSolver: no clearance cookies after solve for {domain}")
                    return False

                if hasattr(self.http_client, "session") and hasattr(self.http_client.session, "cookies"):
                    for c in interesting:
                        self.http_client.session.cookies.set(
                            c["name"], c["value"],
                            domain=c.get("domain"),
                            path=c.get("path", "/"),
                        )

                self._cache[domain] = (time.time(), {c["name"]: c["value"] for c in interesting})
                logger.info(f"ChallengeSolver: solved {domain}, got {[c['name'] for c in interesting]}")
                return True
            finally:
                browser.close()
