"""Nuclei-style YAML template engine for declarative vuln checks."""
from modules.template_engine.parser import (
    parse_template,
    parse_template_file,
    validate_template,
    TemplateError,
)
from modules.template_engine.matcher import evaluate_matchers, run_extractors
from modules.template_engine.executor import TemplateExecutor, substitute_vars
from modules.template_engine.loader import load_templates

__all__ = [
    "parse_template",
    "parse_template_file",
    "validate_template",
    "TemplateError",
    "evaluate_matchers",
    "run_extractors",
    "TemplateExecutor",
    "substitute_vars",
    "load_templates",
]
