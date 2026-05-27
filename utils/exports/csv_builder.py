"""CSV builder for spreadsheet export.

UTF-8 BOM for Excel compatibility, RFC 4180 quoting.
"""
import csv
import io
from datetime import datetime, timezone
from typing import Dict


COLUMNS = [
    "type",
    "severity",
    "url",
    "parameter",
    "payload",
    "evidence",
    "description",
    "remediation",
    "cve_references",
    "cvss_score",
    "timestamp",
]

_EVIDENCE_LIMIT = 1000
_UTF8_BOM = "\ufeff"


def _flatten_cve(refs) -> str:
    if not refs:
        return ""
    if isinstance(refs, list):
        return "; ".join(str(r) for r in refs)
    return str(refs)


def build_csv(results: Dict) -> str:
    """Build CSV string from scan results.

    Args:
        results: Scan result dict with 'vulnerabilities' list.

    Returns:
        CSV string with UTF-8 BOM prefix.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    vulnerabilities = results.get("vulnerabilities", [])

    buf = io.StringIO()
    buf.write(_UTF8_BOM)
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(COLUMNS)

    for vuln in vulnerabilities:
        evidence = str(vuln.get("evidence", ""))[:_EVIDENCE_LIMIT]
        row = [
            str(vuln.get("type", "")),
            str(vuln.get("severity", "")),
            str(vuln.get("url", "")),
            str(vuln.get("parameter", "")),
            str(vuln.get("payload", "")),
            evidence,
            str(vuln.get("description", "")),
            str(vuln.get("remediation", "")),
            _flatten_cve(vuln.get("cve_references", [])),
            str(vuln.get("cvss_score", "")),
            timestamp,
        ]
        writer.writerow(row)

    return buf.getvalue()
