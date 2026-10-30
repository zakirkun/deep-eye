"""Accepted-risk suppression for scan findings.

Every repeat scan re-reports findings a team has already reviewed and accepted.
That noise is why scanners get switched off. A suppression file records those
decisions explicitly -- with a reason and an optional expiry -- so they are
auditable rather than silently filtered.

Entries key on the finding fingerprint, which already folds in type, normalized
path, parameter, and a root-cause hint. A suppression therefore survives
severity changes and cosmetic payload differences, but not moving to a new URL.
"""
from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

from utils.finding_fingerprint import fingerprint
from utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_PATH = ".deep-eye.ignore.yml"


def _parse_date(value) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def load_suppressions(config: Dict) -> List[Dict]:
    """Load suppression entries from the configured ignore file.

    A missing file is normal (suppression is opt-in). A malformed file is logged
    and treated as empty: refusing to scan because an ignore file is broken
    would be worse than ignoring it.
    """
    reporting = config.get("reporting") or {}
    path_value = reporting.get("suppress_file") or DEFAULT_PATH
    path = Path(path_value)
    if not path.exists():
        return []

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        logger.warning(f"Could not read suppression file {path}: {e}")
        return []

    if isinstance(raw, list):
        entries = raw
    elif isinstance(raw, dict):
        entries = raw.get("suppressions") or []
    else:
        logger.warning(f"Suppression file {path} has unexpected structure; ignoring")
        return []

    out: List[Dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        fp = entry.get("fingerprint") or entry.get("id")
        if not fp:
            continue
        out.append(
            {
                "fingerprint": str(fp),
                "reason": str(entry.get("reason") or ""),
                "expires": _parse_date(entry.get("expires")),
                "ticket": str(entry.get("ticket") or ""),
            }
        )
    return out


def _is_active(entry: Dict, today: date) -> bool:
    expires = entry.get("expires")
    if expires is None:
        return True
    return expires >= today


def apply_suppressions(
    findings: List[Dict], config: Dict, today: date | None = None
) -> Tuple[List[Dict], List[Dict]]:
    """Split findings into (kept, suppressed).

    Findings are copied before decoration so the caller's list is never
    mutated in place. Expired entries stop suppressing automatically, which is
    the point of an expiry date.
    """
    if not findings:
        return findings, []

    entries = load_suppressions(config)
    if not entries:
        return findings, []

    today = today or date.today()
    index: Dict[str, Dict] = {}
    for entry in entries:
        if _is_active(entry, today):
            index[entry["fingerprint"]] = entry
        else:
            logger.debug(f"Suppression expired for {entry['fingerprint'][:8]}")

    if not index:
        return findings, []

    kept: List[Dict] = []
    suppressed: List[Dict] = []
    for finding in findings:
        fp = finding.get("fingerprint") or fingerprint(finding)
        entry = index.get(fp)
        if entry is None:
            kept.append(finding)
            continue
        record = dict(finding)
        record["fingerprint"] = fp
        record["suppressed_by"] = {
            "reason": entry.get("reason", ""),
            "ticket": entry.get("ticket", ""),
            "expires": entry["expires"].isoformat() if entry.get("expires") else "",
        }
        suppressed.append(record)
    return kept, suppressed


def build_template(findings: List[Dict]) -> Dict:
    """Produce an ignore-file skeleton pre-filled with current fingerprints."""
    entries = []
    for finding in findings:
        entries.append(
            {
                "fingerprint": finding.get("fingerprint") or fingerprint(finding),
                "reason": "",
                "expires": "",
                "ticket": "",
                "type": finding.get("type", ""),
                "url": finding.get("url", ""),
            }
        )
    return {"suppressions": entries}
