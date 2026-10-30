"""
HTTP Client for making requests
"""

import time
import random
import threading
import requests
from typing import Dict, Optional
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from utils.logger import get_logger

logger = get_logger(__name__)

PASSIVE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class ScopeViolation(RuntimeError):
    pass


class PassiveModeViolation(RuntimeError):
    pass


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, rate: float, burst: int):
        """
        Args:
            rate: Tokens per second (requests_per_second)
            burst: Maximum burst size
        """
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        """Block until a token is available."""
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
                self.last_refill = now

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
            time.sleep(0.05)


class HostRateLimiter:
    """One TokenBucket per host.

    A single global bucket lets N threads hammer one host at N x rate and
    makes the effective rate depend on how many hosts happen to be scanned.
    Limiting per host keeps the promise configured in ``rate_limiting``.
    """

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self._buckets = {}
        self._lock = threading.Lock()

    def acquire(self, url: str):
        host = (urlparse(url).hostname or "").lower() or "<unknown>"
        with self._lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                bucket = TokenBucket(self.rate, self.burst)
                self._buckets[host] = bucket
        bucket.acquire()

    def host_count(self) -> int:
        with self._lock:
            return len(self._buckets)


class HTTPClient:
    """HTTP client with retry logic and configuration."""
    
    def __init__(
        self,
        proxy: Optional[str] = None,
        custom_headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        config: Optional[Dict] = None,
        scope_manager=None
    ):
        """Initialize HTTP client."""
        self.config = config or {}
        scanner_config = self.config.get('scanner', {})
        advanced_config = self.config.get('advanced', {})

        self.timeout = scanner_config.get('timeout', 10)
        self.verify_ssl = scanner_config.get('verify_ssl', True)
        self.max_retries = scanner_config.get('max_retries', 3)
        self.user_agent = scanner_config.get('user_agent', 'Deep-Eye/1.0')

        self.passive_mode = bool(self.config.get('passive_mode', False))
        self.scope_manager = scope_manager
        if self.scope_manager is None:
            from utils.scope_manager import ScopeManager
            self.scope_manager = ScopeManager(self.config)
        if self.passive_mode:
            logger.info("Passive mode enabled: only GET/HEAD/OPTIONS are permitted")

        # Advanced settings
        self.max_response_size = advanced_config.get('max_response_size', 5242880)  # 5MB default
        logger.debug(f"HTTP Client initialized with max_response_size: {self.max_response_size} bytes")

        # Rate limiting
        rate_config = self.config.get('rate_limiting', {})
        if rate_config.get('enabled', False):
            rps = rate_config.get('requests_per_second', 10)
            burst = rate_config.get('burst_size', 20)
            self.rate_limiter = HostRateLimiter(rate=rps, burst=burst)
            logger.debug(f"Rate limiting enabled: {rps} req/s per host, burst {burst}")
        else:
            self.rate_limiter = None

        # UA rotation
        self.ua_rotation = advanced_config.get('ua_rotation', False)
        self.ua_pool = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/125.0.0.0 Safari/537.36',
        ]

        # Request jitter (random delay between requests)
        self.jitter_min = advanced_config.get('jitter_min', 0.0)
        self.jitter_max = advanced_config.get('jitter_max', 0.0)

        # Proxy rotation
        self.proxy_pool = advanced_config.get('proxy_pool', [])
        self.proxy_index = 0

        tls_cfg = self.config.get('tls_evasion', {})
        self.session = None
        if tls_cfg.get('enabled', False):
            try:
                from curl_cffi import requests as curl_requests
                impersonate = tls_cfg.get('impersonate', 'chrome120')
                self.session = curl_requests.Session(impersonate=impersonate)
                logger.info(f"TLS evasion enabled (curl_cffi impersonate={impersonate})")
            except ImportError:
                logger.warning(
                    "tls_evasion.enabled but curl_cffi not installed; "
                    "pip install curl_cffi — falling back to requests"
                )
            except Exception as e:
                logger.warning(f"TLS evasion init failed: {e}")
        if self.session is None:
            self.session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        if custom_headers:
            self.session.headers.update(custom_headers)
        
        # Set cookies
        if cookies:
            self.session.cookies.update(cookies)
        
        # Set proxy
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }

    def _guard(self, method: str, url: str):
        """Reject out-of-scope and (in passive mode) state-changing requests.

        Called before every request including redirect hops, so a redirect to
        an off-scope host cannot slip through the crawler's URL filter.
        """
        if self.passive_mode and method.upper() not in PASSIVE_METHODS:
            raise PassiveModeViolation(
                f"passive_mode blocks {method.upper()} {url}"
            )
        if not self.scope_manager.is_in_scope(url):
            raise ScopeViolation(f"out of scope: {url}")

    def _prepare(self, method: str, url: str) -> bool:
        """Apply guards + rate limit + jitter + UA/proxy rotation.

        Returns False when the request must be skipped without raising: callers
        treat a skipped request the same as a failed one (returns None).
        """
        try:
            self._guard(method, url)
        except (ScopeViolation, PassiveModeViolation) as e:
            logger.warning(str(e))
            return False

        if self.rate_limiter:
            self.rate_limiter.acquire(url)
        if self.jitter_max > 0:
            time.sleep(random.uniform(self.jitter_min, self.jitter_max))
        if self.ua_rotation:
            self.session.headers['User-Agent'] = random.choice(self.ua_pool)
        if self.proxy_pool:
            proxy = self.proxy_pool[self.proxy_index % len(self.proxy_pool)]
            self.session.proxies = {'http': proxy, 'https': proxy}
            self.proxy_index += 1
        return True

    def _read_capped(self, response, url: str) -> Optional[requests.Response]:
        """Read a streamed response up to max_response_size with a read deadline."""
        content_length = response.headers.get('Content-Length')
        if content_length:
            try:
                if int(content_length) > self.max_response_size:
                    logger.warning(
                        f"Response too large for {url}: {content_length} bytes "
                        f"(max: {self.max_response_size}). Skipping."
                    )
                    response.close()
                    return None
            except (TypeError, ValueError):
                pass

        content = b''
        start_time = time.time()
        read_timeout = self.timeout * 2

        for chunk in response.iter_content(chunk_size=8192):
            if time.time() - start_time > read_timeout:
                logger.warning(
                    f"Response reading timeout exceeded for {url} after {read_timeout}s. Truncating."
                )
                response.close()
                if content:
                    response._content = content
                    return response
                return None

            content += chunk
            if len(content) > self.max_response_size:
                logger.warning(
                    f"Response size exceeded limit for {url}: {len(content)} bytes "
                    f"(max: {self.max_response_size}). Truncating."
                )
                response.close()
                response._content = content[:self.max_response_size]
                return response

        response._content = content
        return response

    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        allow_redirects: bool = True,
        **kwargs
    ) -> Optional[requests.Response]:
        """Make GET request with response size limiting."""
        if not self._prepare('GET', url):
            return None
        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
                stream=True,  # Enable streaming to check content length
                **kwargs
            )
            return self._read_capped(response, url)
        except requests.exceptions.RequestException as e:
            logger.debug(f"GET request failed for {url}: {e}")
            return None
    
    def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> Optional[requests.Response]:
        """Make POST request with response size limiting."""
        if not self._prepare('POST', url):
            return None
        try:
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                stream=True,  # Enable streaming
                **kwargs
            )
            return self._read_capped(response, url)
        except requests.exceptions.RequestException as e:
            logger.debug(f"POST request failed for {url}: {e}")
            return None
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HEAD request."""
        if not self._prepare('HEAD', url):
            return None
        try:
            return self.session.head(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
        except requests.exceptions.RequestException as e:
            logger.debug(f"HEAD request failed for {url}: {e}")
            return None
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make OPTIONS request."""
        if not self._prepare('OPTIONS', url):
            return None
        try:
            return self.session.options(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
        except requests.exceptions.RequestException as e:
            logger.debug(f"OPTIONS request failed for {url}: {e}")
            return None
