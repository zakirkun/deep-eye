"""Matcher logic for template engine."""
import re
from typing import Dict, List, Tuple


def _get_part(response, part: str) -> str:
    """Extract response part as string."""
    if part == "header":
        headers = getattr(response, "headers", {})
        if hasattr(headers, "items"):
            return "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        return str(headers)
    if part == "body":
        return getattr(response, "text", "") or ""
    if part in ("response", "all"):
        body = getattr(response, "text", "") or ""
        headers = getattr(response, "headers", {})
        if hasattr(headers, "items"):
            header_str = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        else:
            header_str = str(headers)
        return f"{header_str}\r\n\r\n{body}"
    return ""


def match_status(response, matcher: Dict) -> bool:
    status = getattr(response, "status_code", None)
    expected = matcher.get("status", [])
    return status in expected


def match_word(response, matcher: Dict) -> bool:
    part = matcher.get("part", "body")
    text = _get_part(response, part)
    case_insensitive = matcher.get("case-insensitive", False)
    if case_insensitive:
        text = text.lower()
    words = matcher.get("words", [])
    condition = matcher.get("condition", "or").lower()

    matches = []
    for w in words:
        target = w.lower() if case_insensitive else w
        matches.append(target in text)

    if condition == "and":
        return all(matches) if matches else False
    return any(matches)


def match_regex(response, matcher: Dict) -> bool:
    part = matcher.get("part", "body")
    text = _get_part(response, part)
    patterns = matcher.get("regex", [])
    condition = matcher.get("condition", "or").lower()

    matches = []
    for pat in patterns:
        try:
            matches.append(bool(re.search(pat, text)))
        except re.error:
            matches.append(False)

    if condition == "and":
        return all(matches) if matches else False
    return any(matches)


def match_size(response, matcher: Dict) -> bool:
    text = getattr(response, "text", "") or ""
    body_size = len(text)
    sizes = matcher.get("size", [])
    return body_size in sizes


def match_dsl(response, matcher: Dict) -> bool:
    """Minimal DSL: status_code, len(body), simple comparisons."""
    text = getattr(response, "text", "") or ""
    status_code = getattr(response, "status_code", 0)
    safe_globals = {
        "__builtins__": {},
        "len": len,
        "status_code": status_code,
        "body": text,
        "True": True,
        "False": False,
    }
    expressions = matcher.get("dsl", [])
    condition = matcher.get("condition", "and").lower()
    results = []
    for expr in expressions:
        try:
            results.append(bool(eval(str(expr), safe_globals, {})))
        except Exception:
            results.append(False)
    if condition == "or":
        return any(results)
    return all(results) if results else False


_MATCHERS = {
    "status": match_status,
    "word": match_word,
    "regex": match_regex,
    "size": match_size,
    "dsl": match_dsl,
}


def evaluate_matchers(response, matchers: List[Dict], condition: str = "or") -> Tuple[bool, List[Dict]]:
    """Run all matchers, combine via condition. Returns (overall, individual results)."""
    if not matchers:
        return False, []

    results = []
    for m in matchers:
        mtype = m.get("type")
        fn = _MATCHERS.get(mtype)
        if fn is None:
            results.append({"type": mtype, "matched": False, "error": "unknown matcher"})
            continue
        try:
            matched = fn(response, m)
        except Exception:
            matched = False
        results.append({"type": mtype, "matched": matched})

    cond = (condition or "or").lower()
    overall_results = [r["matched"] for r in results]
    if cond == "and":
        overall = all(overall_results) if overall_results else False
    else:
        overall = any(overall_results)
    return overall, results


def run_extractors(response, extractors: List[Dict]) -> Dict[str, List[str]]:
    """Run extractors. Returns {name: [matched values]}."""
    out: Dict[str, List[str]] = {}
    for i, ext in enumerate(extractors or []):
        ext_type = ext.get("type")
        name = ext.get("name", f"extracted_{i}")
        part = ext.get("part", "body")
        text = _get_part(response, part)
        values: List[str] = []
        if ext_type == "regex":
            patterns = ext.get("regex", [])
            group = int(ext.get("group", 0))
            for pat in patterns:
                try:
                    for m in re.finditer(pat, text):
                        try:
                            values.append(m.group(group))
                        except (IndexError, TypeError):
                            values.append(m.group(0))
                except re.error:
                    continue
        out[name] = values
    return out
