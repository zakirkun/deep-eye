"""Template loader — discover .yaml/.yml templates from filesystem."""
import logging
from pathlib import Path
from typing import Dict, List, Optional

from modules.template_engine.parser import parse_template_file, TemplateError

logger = logging.getLogger(__name__)


def load_templates(
    directories: List[str],
    tag_filters: Optional[List[str]] = None,
    severity_filter: Optional[List[str]] = None,
) -> List[Dict]:
    """Walk directories, parse all .yaml/.yml templates."""
    tag_set = set(tag_filters or [])
    sev_set = set(s.lower() for s in (severity_filter or []))

    templates: List[Dict] = []
    for d in directories:
        path = Path(d).expanduser()
        if not path.exists() or not path.is_dir():
            logger.debug(f"Template directory missing or not a dir: {path}")
            continue

        for file_path in list(path.rglob("*.yaml")) + list(path.rglob("*.yml")):
            try:
                tpl = parse_template_file(str(file_path))
            except TemplateError as e:
                logger.warning(f"Skipping template {file_path}: {e}")
                continue

            info = tpl.get("info", {})
            tpl_tags = set(info.get("tags", []) or [])
            tpl_sev = str(info.get("severity", "")).lower()

            if tag_set and not (tag_set & tpl_tags):
                continue
            if sev_set and tpl_sev not in sev_set:
                continue

            templates.append(tpl)

    return templates
