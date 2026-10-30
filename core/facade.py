"""Programmatic scan entry point.

``main()`` in ``deep_eye.py`` interleaves argparse, config loading, engine
construction, report writing, and printing. Anything that wants to run a scan
without a terminal -- the MCP server, tests, CI jobs, embedders -- cannot reuse
it. This module owns the same pipeline minus the presentation layer.

Returns plain dicts so callers stay independent of rich/console output.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from ai_providers.provider_manager import AIProviderManager
from core.report_generator import ReportGenerator
from core.scanner_engine import ScannerEngine
from utils.config_loader import ConfigLoader
from utils.logger import get_logger

logger = get_logger(__name__)


class ScanError(RuntimeError):
    pass


def load_config(config_path: Optional[str] = None) -> Dict:
    """Load a YAML config, raising ScanError when the file is unusable."""
    from utils.paths import resolve_config

    path = resolve_config(config_path)
    if not path.exists():
        raise ScanError(f"config not found: {path}")
    try:
        return ConfigLoader.load(str(path))
    except Exception as e:
        raise ScanError(f"invalid config {path}: {e}") from e


def run_scan(
    config_path: Optional[str] = None,
    url: Optional[str] = None,
    *,
    enable_recon: Optional[bool] = None,
    quick_scan: Optional[bool] = None,
    full_scan: Optional[bool] = None,
    ai_provider: Optional[str] = None,
) -> Dict:
    """Run one scan and return the results dict.

    Keyword arguments override the matching config values; passing None keeps
    whatever the config specifies. No reports are written -- call
    :func:`run_scan_with_reports` for that.
    """
    config = load_config(config_path)
    scanner_config = config.get("scanner") or {}

    target = url or scanner_config.get("target_url", "")
    if not target:
        raise ScanError("no target: pass url= or set scanner.target_url in config")
    if not target.startswith(("http://", "https://")):
        raise ScanError(f"target must be http(s): {target}")

    provider = ai_provider or scanner_config.get("ai_provider", "openai")
    depth = int(scanner_config.get("default_depth", 2))
    threads = int(scanner_config.get("default_threads", 5))

    if enable_recon is None:
        enable_recon = bool(scanner_config.get("enable_recon", False))
    if quick_scan is None:
        quick_scan = bool(scanner_config.get("quick_scan", False))
    if full_scan is None:
        full_scan = bool(scanner_config.get("full_scan", False))

    experimental = config.get("experimental") or {}
    scan_subdomains = bool(experimental.get("enable_subdomain_scanning", False))

    ai_manager = AIProviderManager(config)
    ai_manager.set_provider(provider)

    engine = ScannerEngine(
        target_url=target,
        config=config,
        ai_manager=ai_manager,
        depth=depth,
        threads=threads,
        proxy=scanner_config.get("proxy") or None,
        custom_headers=scanner_config.get("custom_headers", {}),
        cookies=scanner_config.get("cookies", {}),
        verbose=False,
    )
    results = engine.scan(
        enable_recon=enable_recon,
        full_scan=full_scan,
        quick_scan=quick_scan,
        scan_subdomains=scan_subdomains,
    )
    results.setdefault("target", target)
    return results


def write_reports(
    results: Dict,
    config: Dict,
    formats: Optional[List[str]] = None,
    output_dir: Optional[str] = None,
    stem: Optional[str] = None,
) -> List[str]:
    """Write reports for ``results`` and return the paths created."""
    reporting = config.get("reporting") or {}
    if not reporting.get("enabled", True):
        return []

    directory = Path(output_dir or reporting.get("output_directory", "reports"))
    directory.mkdir(parents=True, exist_ok=True)

    if formats is None:
        configured = reporting.get("formats")
        formats = list(configured) if configured else [reporting.get("default_format", "html")]

    ext_map = {
        "html": "html",
        "pdf": "pdf",
        "json": "json",
        "sarif": "sarif.json",
        "junit": "junit.xml",
        "csv": "csv",
        "xlsx": "xlsx",
    }

    if stem is None:
        from datetime import datetime

        domain = Path(results.get("target", "scan")).stem.replace(":", "_")
        stem = f"deep_eye_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    generator = ReportGenerator(config)
    written: List[str] = []
    for fmt in formats:
        path = str(directory / f"{stem}.{ext_map.get(fmt, fmt)}")
        generator.generate(results=results, output_path=path, format=fmt)
        written.append(path)
    return written


def run_scan_with_reports(
    config_path: Optional[str] = None,
    url: Optional[str] = None,
    **kwargs,
) -> Dict:
    """Run a scan and write its reports, returning results plus ``reports``."""
    results = run_scan(config_path=config_path, url=url, **kwargs)
    config = load_config(config_path)
    results["reports"] = write_reports(results, config)
    return results


def findings_summary(results: Dict) -> Dict:
    """Compact, JSON-safe view of a results dict for tool output."""
    findings = results.get("vulnerabilities") or []
    severities: Dict[str, int] = {}
    for finding in findings:
        key = str(finding.get("severity", "info")).lower()
        severities[key] = severities.get(key, 0) + 1
    return {
        "target": results.get("target", ""),
        "total": len(findings),
        "severities": severities,
        "confirmed": sum(1 for f in findings if f.get("oast_confirmed")),
        "suppressed": int(results.get("suppressed_count", 0) or 0),
        "urls_crawled": results.get("urls_crawled", 0),
        "duration": results.get("duration", ""),
        "reports": results.get("reports", []),
    }
