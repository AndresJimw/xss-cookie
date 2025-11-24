from __future__ import annotations

import html
from typing import Any, Dict, List

from flask import current_app

# XSS-related pattern groups, aligned with dataset families
PATTERN_GROUPS: Dict[str, List[str]] = {
    # Direct script injection
    "script_tag": [
        "<script",
        "</script",
    ],
    # Active / embedded content
    "active_tag": [
        "<iframe",
        "<frame",
        "<frameset",
        "srcdoc=",
        "<svg",
        "<math",
        "<object",
        "<embed",
        "<video",
        "<audio",
        "<source",
    ],
    # Images and graphics
    "image_tag": [
        "<img",
        "<image",
        "srcset=",
        "xlink:href",
    ],
    # Forms and inputs
    "form_tag": [
        "<form",
        "<input",
        "<textarea",
        "<button",
        "<select",
        "onsubmit=",
        "onreset=",
    ],
    # Meta/refresh and similar tricks
    "meta_tag": [
        "<meta",
        'http-equiv="refresh',
        "http-equiv='refresh",
        "charset=",
    ],
    # Dangerous URI schemes
    "scheme": [
        "javascript:",
        "data:text/html",
        "data:text/javascript",
        "vbscript:",
    ],
    # Event handlers (dataset family: "event")
    "event": [
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "onmouseenter=",
        "onmouseleave=",
        "onfocus=",
        "onblur=",
        "onkeydown=",
        "onkeyup=",
        "onkeypress=",
        "onpointerdown=",
        "onpointerup=",
        "onwheel=",
    ],
    # Typical DOM sinks
    "dom_sink": [
        "document.write",
        "document.writeln",
        "document.cookie",
        "document.location",
        "window.location",
        "location.href",
        "innerhtml",
        "outerhtml",
        "eval(",
        "settimeout(",
        "setinterval(",
    ],
    # Polyglot / obfuscated-style payloads
    "neutral_polyglot": [
        "</script><svg",
        "<svg><script",
        '";alert(',
        "';alert(",
        "`;alert(",
        "\u0061\u006c\u0065\u0072\u0074(",  # "alert(" in Unicode
    ],
    # Generic HTML-like content (low-risk, mostly for logging)
    "html_like": [
        "<html",
        "<body",
        "</html",
        "</body",
        "<!--",
        "-->",
    ],
}

SUSPICIOUS_PATTERNS: List[str] = sorted(
    {p for patterns in PATTERN_GROUPS.values() for p in patterns}
)


def get_security_mode() -> str:
    try:
        mode = current_app.config.get("SECURITY_MODE", "off")
    except RuntimeError:
        mode = "off"

    mode = (mode or "off").lower()
    if mode not in {"off", "log", "block"}:
        return "off"
    return mode


def _analyze_patterns(lowered: str) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []

    for group, patterns in PATTERN_GROUPS.items():
        for pattern in patterns:
            idx = lowered.find(pattern)
            if idx != -1:
                matches.append(
                    {
                        "group": group,
                        "pattern": pattern,
                        "index": idx,
                    }
                )

    return matches


def _extract_categories(matches: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not matches:
        return {"categories": [], "main_category": None}

    groups = [m["group"] for m in matches]
    categories = sorted(set(groups))

    # Choose the first match as main category (earliest occurrence)
    first_match = min(matches, key=lambda m: m["index"])
    main_category = first_match["group"]

    return {
        "categories": categories,
        "main_category": main_category,
    }


def analyze_input(value: str, context: str) -> Dict[str, Any]:
    if not value:
        return {
            "is_suspicious": False,
            "reasons": [],
            "context": context,
            "matches": [],
            "categories": [],
            "main_category": None,
        }

    lowered = value.lower()
    matches = _analyze_patterns(lowered)
    cats = _extract_categories(matches)

    groups_present = {m["group"] for m in matches}
    patterns_present = {m["pattern"] for m in matches}

    reasons: List[str] = []
    for g in sorted(groups_present):
        reasons.append(f"group:{g}")
    for p in sorted(patterns_present):
        reasons.append(f"pattern:{p}")

    return {
        "is_suspicious": bool(matches),
        "reasons": reasons,
        "context": context,
        "matches": matches,
        "categories": cats["categories"],
        "main_category": cats["main_category"],
    }


def sanitize_for_context(value: str, context: str) -> str:
    if value is None:
        return ""
    return html.escape(value)


def secure_output(value: str, context: str) -> str:
    mode = get_security_mode()
    analysis = analyze_input(value or "", context=context)

    if mode == "off":
        return value or ""

    escaped = sanitize_for_context(value or "", context=context)

    if mode == "log":
        if analysis["is_suspicious"]:
            try:
                current_app.logger.warning(
                    "Suspicious input detected: context=%s reasons=%s matches=%s value=%r",
                    context,
                    analysis["reasons"],
                    analysis.get("matches", []),
                    value,
                )
            except RuntimeError:
                pass
        return escaped

    if mode == "block":
        if analysis["is_suspicious"]:
            return "[blocked by simple context-based filter]"
        return escaped

    return value or ""


def apply_security_headers(response):
    mode = get_security_mode()
    if mode in {"log", "block"}:
        csp = "default-src 'self'; script-src 'self'; object-src 'none';"
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
    return response
