"""Local mitmweb subprocess wrapper for traffic capture."""
import atexit
import logging
import shutil
import subprocess
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class ProxyRunner:
    """Wrap mitmweb CLI subprocess. Provides proxy URL for HttpClient."""

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        ip_cfg = config.get("intercepting_proxy", {}) if isinstance(config.get("intercepting_proxy"), dict) else {}
        self.enabled = bool(ip_cfg.get("enabled", False))
        self.required = bool(ip_cfg.get("required", False))
        self.bind_host = str(ip_cfg.get("bind_host", "127.0.0.1"))
        self.proxy_port = int(ip_cfg.get("proxy_port", 8080))
        self.mitmweb_port = int(ip_cfg.get("mitmweb_port", 8081))
        self._process: Optional[subprocess.Popen] = None

    def is_enabled(self) -> bool:
        return self.enabled

    def proxy_url(self) -> str:
        return f"http://{self.bind_host}:{self.proxy_port}"

    def proxies_dict(self) -> Dict[str, str]:
        url = self.proxy_url()
        return {"http": url, "https": url}

    def build_command(self) -> list:
        return [
            "mitmweb",
            "--listen-host", self.bind_host,
            "--listen-port", str(self.proxy_port),
            "--web-host", self.bind_host,
            "--web-port", str(self.mitmweb_port),
            "--no-web-open-browser",
        ]

    def start(self) -> bool:
        """Start mitmweb subprocess. Returns True on success."""
        if not self.enabled:
            return False

        if shutil.which("mitmweb") is None:
            msg = "mitmweb not found on PATH (install with: pip install mitmproxy)"
            if self.required:
                raise RuntimeError(msg)
            logger.warning(msg)
            return False

        try:
            self._process = subprocess.Popen(
                self.build_command(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, FileNotFoundError) as e:
            msg = f"Failed to start mitmweb: {e}"
            if self.required:
                raise RuntimeError(msg)
            logger.warning(msg)
            return False

        atexit.register(self.stop)
        logger.info(
            f"Intercepting proxy started: proxy={self.proxy_url()} "
            f"web=http://{self.bind_host}:{self.mitmweb_port}"
        )
        return True

    def stop(self) -> None:
        if self._process is None:
            return
        try:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        except Exception as e:
            logger.warning(f"Error stopping mitmweb: {e}")
        finally:
            self._process = None
