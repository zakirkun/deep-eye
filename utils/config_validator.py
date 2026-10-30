"""Configuration validation against the check registry.

A misspelled name in ``vulnerability_scanner.enabled_checks`` is silently
ignored at dispatch time: the scanner simply never runs it and the scan
completes looking clean. That failure mode is indistinguishable from "no
vulnerabilities found", so it gets validated here instead.

Validation is non-fatal by design. Loading a config with an unknown check
should print a clear warning and keep scanning with the valid subset, not
crash a long-running engagement.
"""
from __future__ import annotations

from typing import Dict, List, NamedTuple

import yaml

from utils.check_registry import ALL_NAMES, MOBILE_NAMES, REGISTRY, unknown


class ValidationIssue(NamedTuple):
    """One config problem, addressed at a dotted path."""

    path: str
    message: str
    severity: str


class ValidationReport(NamedTuple):
    """Result of validating a config dict."""

    issues: List[ValidationIssue]
    enabled: List[str]
    effective: List[str]
    unknown_checks: List[str]

    @property
    def ok(self) -> bool:
        return not self.issues

    @property
    def errors(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == "warning"]


def validate_config(config: Dict) -> ValidationReport:
    """Validate a loaded config dict.

    Checks the check list against the registry plus the handful of numeric
    knobs the CLI also validates, so ``--check-config`` and a real scan agree.
    """
    issues: List[ValidationIssue] = []
    if not isinstance(config, dict):
        return ValidationReport(
            issues=[ValidationIssue("<root>", "config is not a mapping", "error")],
            enabled=[],
            effective=[],
            unknown_checks=[],
        )

    scanner = config.get("scanner") or {}
    vs = config.get("vulnerability_scanner") or {}

    if not isinstance(scanner, dict):
        issues.append(ValidationIssue("scanner", "must be a mapping", "error"))
        scanner = {}
    if not isinstance(vs, dict):
        issues.append(ValidationIssue("vulnerability_scanner", "must be a mapping", "error"))
        vs = {}

    enabled = vs.get("enabled_checks") or []
    if not isinstance(enabled, list):
        issues.append(
            ValidationIssue(
                "vulnerability_scanner.enabled_checks", "must be a list", "error"
            )
        )
        enabled = []

    enabled = [str(name) for name in enabled]
    bad = unknown(enabled)
    if bad:
        issues.append(
            ValidationIssue(
                "vulnerability_scanner.enabled_checks",
                "unknown check name(s): " + ", ".join(sorted(bad)),
                "error",
            )
        )

    duplicates = sorted({name for name in enabled if enabled.count(name) > 1})
    if duplicates:
        issues.append(
            ValidationIssue(
                "vulnerability_scanner.enabled_checks",
                "duplicate check name(s): " + ", ".join(duplicates),
                "warning",
            )
        )

    effective = [name for name in enabled if name in REGISTRY]

    depth = scanner.get("default_depth", 2)
    if not isinstance(depth, int) or not 1 <= depth <= 10:
        issues.append(
            ValidationIssue("scanner.default_depth", "must be an int 1..10", "error")
        )

    threads = scanner.get("default_threads", 5)
    if not isinstance(threads, int) or not 1 <= threads <= 50:
        issues.append(
            ValidationIssue("scanner.default_threads", "must be an int 1..50", "error")
        )

    mobile = config.get("mobile") or {}
    if isinstance(mobile, dict) and mobile.get("enabled", False):
        missing = sorted(MOBILE_NAMES - set(effective))
        if missing:
            issues.append(
                ValidationIssue(
                    "mobile.enabled",
                    "mobile phase is on but these checks are not enabled: "
                    + ", ".join(missing),
                    "warning",
                )
            )

    active = set(effective)
    if active & MOBILE_NAMES and not (isinstance(mobile, dict) and mobile.get("enabled", False)):
        issues.append(
            ValidationIssue(
                "vulnerability_scanner.enabled_checks",
                "mobile checks are enabled but mobile.enabled is false; they will not run",
                "warning",
            )
        )

    if config.get("passive_mode", False):
        state_changing = sorted(
            {
                "file_upload",
                "mass_assignment",
                "prototype_pollution",
                "race_condition",
                "http_smuggling",
                "h2_smuggle",
                "login_replay",
                "frida_mobile",
            }
            & active
        )
        if state_changing:
            issues.append(
                ValidationIssue(
                    "passive_mode",
                    "enabled with state-changing checks: " + ", ".join(state_changing),
                    "warning",
                )
            )

    return ValidationReport(
        issues=issues,
        enabled=enabled,
        effective=effective,
        unknown_checks=sorted(bad),
    )


def validate_config_file(path: str) -> ValidationReport:
    """Load a YAML config file and validate it.

    Raises FileNotFoundError or yaml.YAMLError to the caller; those are not
    validation findings, they are "the file is not readable config".
    """
    with open(path, encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    return validate_config(config)


def format_report(report: ValidationReport, config_path: str = "") -> str:
    """Render a validation report as plain text for CLI output."""
    lines: List[str] = []
    if config_path:
        lines.append(f"config: {config_path}")
    lines.append(
        f"checks: {len(report.effective)} enabled, "
        f"{len(ALL_NAMES)} registered, {len(report.unknown_checks)} unknown"
    )
    by_kind: Dict[str, int] = {}
    for spec in REGISTRY.values():
        by_kind[spec.kind] = by_kind.get(spec.kind, 0) + 1
    lines.append(
        "registry: "
        + ", ".join(f"{kind}={count}" for kind, count in sorted(by_kind.items()))
    )
    if not report.issues:
        lines.append("result: OK")
        return "\n".join(lines)

    lines.append("result: issues found")
    for issue in report.issues:
        lines.append(f"  [{issue.severity}] {issue.path}: {issue.message}")
    return "\n".join(lines)
