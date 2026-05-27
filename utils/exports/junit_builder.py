"""JUnit XML builder for CI/CD integration.

Maps each vulnerability to one <testcase> with embedded <failure>.
Compatible with Jenkins, GitLab, Azure DevOps test reporters.
"""
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict


_EVIDENCE_LIMIT = 500


def _format_failure_body(vuln: Dict) -> str:
    """Build multiline failure body with payload, evidence, remediation, CVE."""
    parts = []
    payload = vuln.get("payload", "")
    if payload:
        parts.append(f"Payload: {payload}")

    evidence = str(vuln.get("evidence", ""))[:_EVIDENCE_LIMIT]
    if evidence:
        parts.append(f"Evidence: {evidence}")

    remediation = vuln.get("remediation", "")
    if remediation:
        parts.append(f"Remediation: {remediation}")

    cve_refs = vuln.get("cve_references", [])
    if cve_refs:
        if isinstance(cve_refs, list):
            parts.append(f"CVE: {'; '.join(str(c) for c in cve_refs)}")
        else:
            parts.append(f"CVE: {cve_refs}")

    return "\n".join(parts) if parts else "No additional details"


def build_junit_xml(results: Dict) -> bytes:
    """Build JUnit XML bytes from scan results.

    Args:
        results: Scan result dict with 'target', 'duration', 'vulnerabilities'.

    Returns:
        UTF-8 encoded XML bytes.
    """
    vulnerabilities = results.get("vulnerabilities", [])
    target = results.get("target", "unknown")
    duration = results.get("duration", 0)
    try:
        duration_str = f"{float(duration):.2f}"
    except (TypeError, ValueError):
        duration_str = "0"

    vuln_count = len(vulnerabilities)

    testsuites = ET.Element(
        "testsuites",
        {
            "name": "Deep Eye",
            "tests": str(vuln_count),
            "failures": str(vuln_count),
            "errors": "0",
            "time": duration_str,
        },
    )

    testsuite = ET.SubElement(
        testsuites,
        "testsuite",
        {
            "name": str(target),
            "tests": str(vuln_count),
            "failures": str(vuln_count),
            "errors": "0",
            "skipped": "0",
            "time": duration_str,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )

    for vuln in vulnerabilities:
        vuln_type = str(vuln.get("type", "unknown"))
        url = str(vuln.get("url", ""))
        parameter = str(vuln.get("parameter", ""))
        severity = str(vuln.get("severity", "info"))

        case_name = f"{url} [{parameter}]" if parameter else url
        message = (
            f"{vuln_type} on parameter '{parameter}'" if parameter else vuln_type
        )

        testcase = ET.SubElement(
            testsuite,
            "testcase",
            {
                "classname": vuln_type,
                "name": case_name,
                "time": "0",
            },
        )

        failure = ET.SubElement(
            testcase,
            "failure",
            {
                "type": severity,
                "message": message,
            },
        )
        failure.text = _format_failure_body(vuln)

    # Pretty-print: indent (Python 3.9+)
    try:
        ET.indent(testsuites, space="  ")
    except AttributeError:
        pass  # Python <3.9 — skip indent

    xml_bytes = ET.tostring(testsuites, encoding="utf-8", xml_declaration=True)
    return xml_bytes
