"""Template executor — run templates against target URLs."""
import logging
import random
import string
from typing import Dict, List, Optional
from urllib.parse import urlparse

from modules.template_engine.matcher import evaluate_matchers, run_extractors

logger = logging.getLogger(__name__)


SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 3.0,
    "info": 0.0,
}


def _random_string(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def substitute_vars(text: str, base_url: str) -> str:
    """Replace {{BaseURL}} / {{Hostname}} / {{RandomString}}."""
    if not isinstance(text, str):
        return text
    parsed = urlparse(base_url)
    hostname = parsed.netloc
    base = base_url.rstrip("/")
    out = text.replace("{{BaseURL}}", base)
    out = out.replace("{{Hostname}}", hostname)
    while "{{RandomString}}" in out:
        out = out.replace("{{RandomString}}", _random_string(), 1)
    return out


def _substitute_dict(d: Dict, base_url: str) -> Dict:
    return {k: substitute_vars(v, base_url) for k, v in (d or {}).items()}


class TemplateExecutor:
    """Execute parsed templates against a target URL."""

    def __init__(self, http_client, config: Optional[Dict] = None):
        self.http_client = http_client
        self.config = config or {}

    def run(self, template: Dict, target_url: str) -> List[Dict]:
        """Execute one template against one base URL. Returns list of vuln dicts."""
        findings: List[Dict] = []
        info = template.get("info", {})
        template_id = template.get("id", "unknown")
        source = template.get("_source", "<inline>")

        for block in template.get("http", []):
            method = (block.get("method") or "GET").upper()
            paths = block.get("path", []) or []
            if isinstance(paths, str):
                paths = [paths]
            condition = block.get("matchers-condition", "or")
            matchers = block.get("matchers", []) or []
            extractors = block.get("extractors", []) or []
            headers_template = block.get("headers", {}) or {}
            body_template = block.get("body", "")

            for path_template in paths:
                url = substitute_vars(path_template, target_url)
                headers = _substitute_dict(headers_template, target_url)
                body = substitute_vars(body_template, target_url) if body_template else None

                response = self._send_request(method, url, headers, body)
                if response is None:
                    continue

                overall, per_matcher = evaluate_matchers(response, matchers, condition)
                if not overall:
                    continue

                extracted = run_extractors(response, extractors)
                evidence_parts = []
                for name, vals in extracted.items():
                    if vals:
                        evidence_parts.append(f"{name}: {vals[0]}")
                if not evidence_parts:
                    matched_types = [r["type"] for r in per_matcher if r["matched"]]
                    evidence_parts.append(f"matched: {', '.join(matched_types)}")

                vuln = self._build_vuln(
                    template, url, evidence_parts, response, body or "", template_id, source
                )
                findings.append(vuln)

        return findings

    def _send_request(self, method: str, url: str, headers: Dict, body: Optional[str]):
        try:
            if method == "GET":
                return self.http_client.get(url, headers=headers)
            if method == "POST":
                return self.http_client.post(url, data=body, headers=headers)
            if method in ("PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                if hasattr(self.http_client, "request"):
                    return self.http_client.request(method, url, headers=headers, data=body)
                logger.warning(f"http_client doesn't support {method}; skipping")
                return None
            return None
        except Exception as e:
            logger.warning(f"Template request error for {url}: {e}")
            return None

    def _build_vuln(
        self,
        template: Dict,
        url: str,
        evidence_parts: List[str],
        response,
        payload: str,
        template_id: str,
        source: str,
    ) -> Dict:
        info = template.get("info", {})
        severity = str(info.get("severity", "info")).lower()
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id") or info.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]

        return {
            "type": info.get("name", template_id),
            "severity": severity,
            "url": url,
            "parameter": "",
            "payload": payload[:200] if payload else "",
            "evidence": "; ".join(evidence_parts)[:500],
            "description": info.get("description", ""),
            "remediation": "; ".join(info.get("references", []))[:500] or "See template references",
            "cve_references": cve_ids,
            "cvss_score": SEVERITY_TO_CVSS.get(severity, 0.0),
            "template_id": template_id,
            "template_path": source,
        }
