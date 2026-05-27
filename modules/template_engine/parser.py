"""Template parser — load and validate Nuclei-style YAML templates."""
import logging
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)


REQUIRED_TOP_LEVEL = ["id", "info", "http"]
REQUIRED_INFO = ["name", "severity"]
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_MATCHER_TYPES = {"status", "word", "regex", "size", "dsl"}
VALID_PARTS = {"header", "body", "response", "all"}


class TemplateError(Exception):
    """Raised on invalid template structure."""


def parse_template(text: str, source_path: str = "<inline>") -> Dict:
    """Parse YAML template text and validate schema."""
    try:
        import yaml
    except ImportError as e:
        raise TemplateError(f"PyYAML not installed: {e}")

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise TemplateError(f"YAML parse error in {source_path}: {e}")

    if not isinstance(data, dict):
        raise TemplateError(f"{source_path}: top-level must be a mapping")

    validate_template(data, source_path)
    data["_source"] = source_path
    return data


def parse_template_file(path: str) -> Dict:
    """Load a template file from disk."""
    p = Path(path)
    if not p.exists():
        raise TemplateError(f"Template file not found: {path}")
    text = p.read_text(encoding="utf-8")
    return parse_template(text, source_path=str(p))


def validate_template(data: Dict, source_path: str = "<inline>") -> None:
    """Raise TemplateError if structure is wrong."""
    for key in REQUIRED_TOP_LEVEL:
        if key not in data:
            raise TemplateError(f"{source_path}: missing required field '{key}'")

    info = data.get("info", {})
    for key in REQUIRED_INFO:
        if key not in info:
            raise TemplateError(f"{source_path}: info.{key} required")

    severity = str(info.get("severity", "")).lower()
    if severity not in VALID_SEVERITIES:
        raise TemplateError(
            f"{source_path}: invalid severity '{severity}'. Must be one of {sorted(VALID_SEVERITIES)}"
        )

    http_blocks = data.get("http", [])
    if not isinstance(http_blocks, list) or not http_blocks:
        raise TemplateError(f"{source_path}: http must be a non-empty list")

    for i, block in enumerate(http_blocks):
        if not isinstance(block, dict):
            raise TemplateError(f"{source_path}: http[{i}] must be a mapping")
        if "path" not in block and "raw" not in block:
            raise TemplateError(f"{source_path}: http[{i}] requires 'path' or 'raw'")

        for j, m in enumerate(block.get("matchers", []) or []):
            mtype = m.get("type")
            if mtype not in VALID_MATCHER_TYPES:
                raise TemplateError(
                    f"{source_path}: http[{i}].matchers[{j}].type '{mtype}' invalid"
                )
