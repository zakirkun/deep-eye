"""
OAST (Out-of-Band Application Security Testing) Callback Server
Receives out-of-band callbacks from blind vulnerabilities (SSRF, XXE, RCE)
"""

import secrets
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional
from datetime import datetime
from utils.logger import get_logger

logger = get_logger(__name__)

_callbacks = []
_callbacks_lock = threading.Lock()

TOKEN_PREFIX = "/t/"


class OastTokenRegistry:
    """Maps unguessable callback tokens back to the request that planted them.

    A bare callback URL proves *a* request fired but attributes it to nothing.
    Each injection point gets its own token in the path, so an inbound
    callback identifies the exact check, target URL, and parameter that caused
    it -- that is the difference between "possible blind SSRF" and a finding
    with server-side proof.
    """

    def __init__(self, base_url: str):
        self.base_url = (base_url or "").rstrip("/")
        self._tokens: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def register(self, check: str, url: str, parameter: str = "") -> str:
        token = secrets.token_urlsafe(12)
        with self._lock:
            self._tokens[token] = {
                "check": check,
                "url": url,
                "parameter": parameter,
                "created": datetime.now().isoformat(),
            }
        return f"{self.base_url}{TOKEN_PREFIX}{token}"

    def resolve(self, path: str) -> Optional[Dict]:
        if not path or TOKEN_PREFIX not in path:
            return None
        token = path.split(TOKEN_PREFIX, 1)[1].split("?", 1)[0].split("/", 1)[0]
        with self._lock:
            entry = self._tokens.get(token)
        if not entry:
            return None
        return dict(entry, token=token)

    def token_count(self) -> int:
        with self._lock:
            return len(self._tokens)


_registry: Optional[OastTokenRegistry] = None
_registry_lock = threading.Lock()


def get_registry() -> OastTokenRegistry:
    """Return the process-wide token registry, creating it on first use."""
    global _registry
    with _registry_lock:
        if _registry is None:
            _registry = OastTokenRegistry("")
        return _registry


def register_token(check: str, url: str, parameter: str = "") -> Optional[str]:
    """Register a callback token for one injection point.

    Returns the tokenized callback URL, or None when no OAST base URL has been
    configured -- callers must fall back to non-OAST payloads in that case.
    """
    registry = get_registry()
    if not registry.base_url:
        return None
    return registry.register(check, url, parameter)


def correlate(findings: List[Dict], callbacks: List[Dict]) -> int:
    """Attach callback proof to findings whose OAST token was called back.

    Returns the number of findings newly marked as confirmed. A finding is only
    promoted when a token it planted actually fired; unmatched callbacks stay
    unclaimed rather than being attributed to a plausible-looking finding.
    """
    if not findings or not callbacks:
        return 0

    fired: Dict[str, Dict] = {}
    for cb in callbacks:
        path = cb.get("path") or ""
        if TOKEN_PREFIX not in path:
            continue
        token = path.split(TOKEN_PREFIX, 1)[1].split("?", 1)[0].split("/", 1)[0]
        if not token:
            continue
        fired.setdefault(
            token,
            {
                "token": token,
                "timestamp": cb.get("timestamp"),
                "source_ip": cb.get("source_ip"),
                "method": cb.get("method"),
            },
        )

    confirmed = 0
    for finding in findings:
        planted = finding.get("oast_token")
        if not planted:
            continue
        hit = fired.get(planted)
        if not hit:
            continue
        finding["oast_confirmed"] = True
        finding["oast_evidence"] = hit
        if finding.get("severity") in ("info", "low"):
            finding["severity"] = "high"
        confirmed += 1
    return confirmed



class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs all incoming requests."""

    def do_GET(self):
        self._log_callback('GET')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_POST(self):
        self._log_callback('POST')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def do_PUT(self):
        self._log_callback('PUT')
        self.send_response(200)
        self.end_headers()

    def _log_callback(self, method: str):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': self.client_address[0],
            'source_port': self.client_address[1],
            'method': method,
            'path': self.path,
            'headers': dict(self.headers),
        }
        with _callbacks_lock:
            _callbacks.append(entry)
        logger.info(f"[OAST] Callback received: {method} {self.path} from {self.client_address[0]}")

    def log_message(self, format, *args):
        """Suppress default HTTP server logging."""
        pass


class OASTCallbackServer:
    """Out-of-band callback server for blind vulnerability detection."""

    def __init__(self, host: str = '0.0.0.0', port: int = 9999):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None

    def start(self):
        """Start OAST server in background daemon thread."""
        global _callbacks
        _callbacks = []
        registry = get_registry()
        registry.base_url = self.get_callback_url().rstrip("/")

        self.server = HTTPServer((self.host, self.port), _CallbackHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        logger.info(f"[OAST] Callback server started on {self.host}:{self.port}")

    def stop(self):
        """Stop OAST server."""
        if self.server:
            self.server.shutdown()
            self.server = None
            logger.info("[OAST] Callback server stopped")

    def get_callback_url(self) -> str:
        """Get the URL targets should call back to."""
        return f"http://{self.host}:{self.port}/callback"

    def get_callbacks(self) -> List[Dict]:
        """Get all received callbacks."""
        with _callbacks_lock:
            return list(_callbacks)

    def has_callbacks(self) -> bool:
        """Check if any callbacks were received."""
        with _callbacks_lock:
            return len(_callbacks) > 0

    def clear(self):
        """Clear callback history."""
        global _callbacks
        with _callbacks_lock:
            _callbacks = []
