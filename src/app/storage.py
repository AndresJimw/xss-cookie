from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


# Directorios base relativos al proyecto
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

COMMENTS_FILE = DATA_DIR / "comments.json"
MESSAGES_FILE = DATA_DIR / "messages.json"
STOLEN_COOKIES_LOG = LOGS_DIR / "stolen_cookies.log"
BLIND_XSS_LOG = LOGS_DIR / "blind_xss.log"


def _ensure_dirs() -> None:
    """Asegura que existan los directorios data y logs."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def _read_json_list(file_path: Path) -> List[Dict[str, Any]]:
    """Lee un JSON que contiene una lista; si falla devuelve lista vacía."""
    _ensure_dirs()
    if not file_path.exists():
        return []

    try:
        raw = file_path.read_text(encoding="utf-8").strip()
        if not raw:
            return []
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        return []
    except (json.JSONDecodeError, OSError):
        return []


def _write_json_list(file_path: Path, items: List[Dict[str, Any]]) -> None:
    """Escribe una lista de objetos en un archivo JSON."""
    _ensure_dirs()
    try:
        file_path.write_text(
            json.dumps(items, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError:
        # Para el lab ignoramos errores de escritura
        pass


# ---------- Comments (Stored XSS) ----------

def load_comments() -> List[Dict[str, Any]]:
    """Carga todos los comentarios."""
    return _read_json_list(COMMENTS_FILE)


def add_comment(text: str) -> None:
    """Añade un comentario nuevo."""
    comments = load_comments()
    next_id = (max((c.get("id", 0) for c in comments), default=0) + 1) if comments else 1

    comment = {
        "id": next_id,
        "text": text,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    comments.append(comment)
    _write_json_list(COMMENTS_FILE, comments)


# ---------- Contact messages (Blind XSS) ----------

def load_messages() -> List[Dict[str, Any]]:
    """Carga todos los mensajes de contacto."""
    return _read_json_list(MESSAGES_FILE)


def add_message(text: str) -> None:
    """Añade un mensaje de contacto nuevo."""
    messages = load_messages()
    next_id = (max((m.get("id", 0) for m in messages), default=0) + 1) if messages else 1

    message = {
        "id": next_id,
        "text": text,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    messages.append(message)
    _write_json_list(MESSAGES_FILE, messages)


# ---------- Logs: stolen cookies & blind XSS ----------

def log_stolen_cookie(ip: str, cookie_value: str) -> None:
    """Registra una entrada en el log de cookies robadas."""
    _ensure_dirs()
    timestamp = datetime.utcnow().isoformat() + "Z"
    line = f"[{timestamp}] IP={ip} c={cookie_value}\n"
    try:
        with STOLEN_COOKIES_LOG.open("a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def log_blind_xss_event(message_count: int) -> None:
    """Registra cuándo el admin ve los mensajes (para Blind XSS)."""
    _ensure_dirs()
    timestamp = datetime.utcnow().isoformat() + "Z"
    line = f"[{timestamp}] admin_view messages={message_count}\n"
    try:
        with BLIND_XSS_LOG.open("a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def read_stolen_cookies() -> List[Dict[str, str]]:
    """Lee stolen_cookies.log y parsea cada línea a un dict."""
    _ensure_dirs()
    entries: List[Dict[str, str]] = []

    if not STOLEN_COOKIES_LOG.exists():
        return entries

    try:
        for raw_line in STOLEN_COOKIES_LOG.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue

            timestamp = ""
            ip = ""
            cookie_value = ""

            if line.startswith("[") and "]" in line:
                end_idx = line.find("]")
                timestamp = line[1:end_idx]
                remainder = line[end_idx + 1 :].strip()
            else:
                remainder = line

            parts = remainder.split()
            for part in parts:
                if part.startswith("IP="):
                    ip = part[len("IP="):]
                elif part.startswith("c="):
                    cookie_value = part[len("c="):]

            entries.append(
                {
                    "timestamp": timestamp,
                    "ip": ip,
                    "cookie": cookie_value,
                }
            )
    except OSError:
        pass

    return entries
