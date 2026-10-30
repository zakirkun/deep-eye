"""Multi-role auth session store: import/export cookies + role switch."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class AuthSessionStore:
    def __init__(self, http_client, config: Dict):
        self.http_client = http_client
        self.config = config
        self.cfg = config.get("auth_session", {})
        self.roles: Dict[str, Dict] = dict(self.cfg.get("roles") or {})
        self.active_role = self.cfg.get("default_role") or (
            next(iter(self.roles), None)
        )
        store_path = self.cfg.get("store_path")
        if not store_path:
            from utils.paths import auth_sessions_path
            store_path = str(auth_sessions_path())
        self.store_path = Path(store_path)
        if self.store_path.exists():
            try:
                data = json.loads(self.store_path.read_text(encoding="utf-8"))
                self.roles.update(data.get("roles") or {})
                self.active_role = data.get("active_role") or self.active_role
            except Exception as e:
                logger.debug(f"Auth session load failed: {e}")

    def list_roles(self) -> List[str]:
        return list(self.roles.keys())

    def apply_role(self, role: str) -> bool:
        if role not in self.roles:
            logger.warning(f"Unknown auth role: {role}")
            return False
        data = self.roles[role]
        cookies = data.get("cookies") or {}
        headers = data.get("headers") or {}
        if hasattr(self.http_client, "session"):
            for k, v in cookies.items():
                self.http_client.session.cookies.set(k, v)
            if headers:
                self.http_client.session.headers.update(headers)
        self.active_role = role
        logger.info(f"Applied auth role: {role}")
        return True

    def capture_current(self, role: str) -> None:
        cookies = {}
        if hasattr(self.http_client, "session"):
            try:
                cookies = dict(self.http_client.session.cookies)
            except Exception:
                cookies = {}
        self.roles[role] = {
            "cookies": cookies,
            "headers": dict(self.roles.get(role, {}).get("headers") or {}),
        }
        self.active_role = role
        self.save()

    def save(self) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(
            json.dumps(
                {"active_role": self.active_role, "roles": self.roles},
                indent=2,
            ),
            encoding="utf-8",
        )

    def export_path(self) -> str:
        return str(self.store_path)
