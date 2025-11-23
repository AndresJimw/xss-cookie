from __future__ import annotations

import html
from typing import Dict, List

from flask import current_app

# Patrones simples típicos en payloads XSS
SUSPICIOUS_PATTERNS = [
    "<script",
    "</script",
    "onerror=",
    "onload=",
    "javascript:",
    "<img",
    "<iframe",
]

def get_security_mode() -> str:
    """Obtiene el modo de seguridad desde la config de la app."""
    try:
        mode = current_app.config.get("SECURITY_MODE", "off")
    except RuntimeError:
        mode = "off"

    mode = (mode or "off").lower()
    if mode not in {"off", "log", "block"}:
        return "off"
    return mode

def analyze_input(value: str, context: str) -> Dict[str, object]:
    """Analiza la entrada buscando patrones sospechosos."""
    if not value:
        return {"is_suspicious": False, "reasons": [], "context": context}

    lowered = value.lower()
    reasons: List[str] = []

    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in lowered:
            reasons.append(f"pattern:{pattern}")

    return {
        "is_suspicious": bool(reasons),
        "reasons": reasons,
        "context": context,
    }

def sanitize_for_context(value: str, context: str) -> str:
    """Aplica escape simple según contexto (aquí, siempre HTML)."""
    if value is None:
        return ""
    return html.escape(value)

def secure_output(value: str, context: str) -> str:
    """
    Aplica la política según el modo:
    - off: devuelve el valor tal cual.
    - log: escapa el valor y registra si es sospechoso.
    - block: si es sospechoso, lo reemplaza por un placeholder.
    """
    mode = get_security_mode()
    analysis = analyze_input(value or "", context=context)

    if mode == "off":
        return value or ""

    escaped = sanitize_for_context(value or "", context=context)

    if mode == "log":
        if analysis["is_suspicious"]:
            try:
                current_app.logger.warning(
                    "Suspicious input detected: context=%s reasons=%s value=%r",
                    context,
                    analysis["reasons"],
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
    """Añade cabeceras de seguridad simples (CSP) en modos log/block."""
    mode = get_security_mode()
    if mode in {"log", "block"}:
        csp = "default-src 'self'; script-src 'self'; object-src 'none';"
        response.headers.setdefault("Content-Security-Policy", csp)
    return response
