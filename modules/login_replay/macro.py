"""Login macro parser and validator."""
import json
import logging
from typing import Dict

logger = logging.getLogger(__name__)


VALID_ACTIONS = {
    "get",
    "post",
    "extract_csrf",
    "extract_header",
    "set_cookie",
    "wait",
    "playwright",
}


class MacroError(Exception):
    """Raised on invalid macro structure."""


def load_macro(path: str) -> Dict:
    """Load and validate a macro JSON file."""
    with open(path, encoding="utf-8") as f:
        macro = json.load(f)
    validate_macro(macro)
    return macro


def validate_macro(macro: Dict) -> None:
    """Raise MacroError if structure is wrong."""
    if not isinstance(macro, dict):
        raise MacroError("Macro must be a JSON object")
    if "steps" not in macro or not isinstance(macro["steps"], list):
        raise MacroError("Macro must have a 'steps' list")
    for i, step in enumerate(macro["steps"]):
        if not isinstance(step, dict):
            raise MacroError(f"Step {i} must be an object")
        action = step.get("action")
        if action not in VALID_ACTIONS:
            raise MacroError(
                f"Step {i} has invalid action '{action}'. Valid: {sorted(VALID_ACTIONS)}"
            )
