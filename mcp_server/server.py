"""MCP server exposing Deep Eye scans as tools.

Agents drive Deep Eye through this instead of shelling out: no argument
string assembly, no scraping console output, no report-file guessing. Every
tool delegates to ``core.facade`` so the CLI and MCP paths cannot drift.

Run with ``python -m mcp_server``. Requires the ``mcp`` package.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from utils.check_registry import REGISTRY, summary as registry_summary
from utils.logger import get_logger

logger = get_logger(__name__)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None


def _require_mcp():
    if FastMCP is None:
        raise RuntimeError(
            "the 'mcp' package is required for the MCP server: pip install mcp"
        )


def list_checks() -> Dict[str, Any]:
    """Every check Deep Eye can dispatch, grouped by registration path."""
    return {
        "counts": registry_summary(),
        "total": len(REGISTRY),
        "checks": [
            {
                "name": spec.name,
                "kind": spec.kind,
                "per_url": spec.per_url,
                "description": spec.description,
            }
            for spec in REGISTRY.values()
        ],
    }


def validate(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """Validate a config file against the check registry."""
    from utils.config_validator import validate_config_file, format_report

    report = validate_config_file(config_path)
    return {
        "ok": report.ok,
        "errors": [issue._asdict() for issue in report.errors],
        "warnings": [issue._asdict() for issue in report.warnings],
        "enabled": len(report.effective),
        "unknown_checks": report.unknown_checks,
        "text": format_report(report, config_path),
    }


def scan(
    url: str,
    config_path: str = "config/config.yaml",
    formats: Optional[List[str]] = None,
    quick: bool = False,
) -> Dict[str, Any]:
    """Run a scan against ``url`` and return a summary plus written reports."""
    from core.facade import run_scan_with_reports, findings_summary

    results = run_scan_with_reports(
        config_path=config_path,
        url=url,
        quick_scan=quick,
        full_scan=not quick,
    )
    summary = findings_summary(results)
    summary["ok"] = True
    return summary


def get_findings(
    url: str,
    config_path: str = "config/config.yaml",
    severity: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Run a scan and return findings, optionally filtered by minimum severity."""
    from core.facade import run_scan

    results = run_scan(config_path=config_path, url=url)
    findings = results.get("vulnerabilities") or []

    if severity:
        order = ["info", "low", "medium", "high", "critical"]
        if severity not in order:
            raise ValueError(f"unknown severity: {severity}")
        floor = order.index(severity)
        allowed = set(order[floor:])
        findings = [
            f for f in findings
            if str(f.get("severity", "info")).lower() in allowed
        ]

    trimmed = [
        {
            "type": f.get("type", ""),
            "severity": f.get("severity", ""),
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
            "evidence": str(f.get("evidence", ""))[:400],
            "confirmed": bool(f.get("oast_confirmed")),
            "fingerprint": f.get("fingerprint", ""),
        }
        for f in findings[:limit]
    ]
    return {"target": url, "returned": len(trimmed), "total": len(findings), "findings": trimmed}


def diff_runs(
    baseline_path: str,
    current_path: str,
    format: str = "json",
) -> Dict[str, Any]:
    """Diff two saved scan JSON files."""
    from core.scan_diff import diff_scans, load_scan_json

    diff = diff_scans(load_scan_json(baseline_path), load_scan_json(current_path))
    return {
        "summary": diff.get("summary", {}),
        "new": diff.get("new", []),
        "fixed": diff.get("fixed", []),
        "severity_changed": diff.get("severity_changed", []),
    }


def build_server():
    """Construct the FastMCP server with all Deep Eye tools registered."""
    _require_mcp()
    server = FastMCP("deep-eye")

    server.tool()(list_checks)
    server.tool()(validate)
    server.tool()(scan)
    server.tool()(get_findings)
    server.tool()(diff_runs)
    return server


def main() -> int:
    server = build_server()
    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
