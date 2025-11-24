from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

try:
    from flask import current_app  # type: ignore
except Exception:  # pragma: no cover
    current_app = None  # type: ignore


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

COMMENTS_FILE = DATA_DIR / "comments.json"
MESSAGES_FILE = DATA_DIR / "messages.json"

STOLEN_COOKIES_LOG = LOGS_DIR / "stolen_cookies.log"
BLIND_XSS_LOG = LOGS_DIR / "blind_xss.log"

STOLEN_COOKIES_JSONL = LOGS_DIR / "stolen_cookies.jsonl"
BLIND_XSS_JSONL = LOGS_DIR / "blind_xss.jsonl"


def _ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def _now_utc_iso() -> str:
    """
    Retorna timestamp RFC 3339/ISO en UTC con Z (timezone-aware).
    Compatible con pandas y con tus logs existentes.
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_json_list(file_path: Path) -> List[Dict[str, Any]]:
    _ensure_dirs()
    if not file_path.exists():
        return []
    try:
        raw = file_path.read_text(encoding="utf-8").strip()
        if not raw:
            return []
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _write_json_list(file_path: Path, items: List[Dict[str, Any]]) -> None:
    _ensure_dirs()
    try:
        file_path.write_text(
            json.dumps(items, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError:
        pass


def _get_security_mode_for_log() -> str:
    if current_app is None:
        return "unknown"
    try:
        mode = current_app.config.get("SECURITY_MODE", "off")
    except RuntimeError:
        return "unknown"
    if not isinstance(mode, str):
        return "unknown"
    return (mode or "off").lower()


# ---------------- Comments (Stored XSS) ----------------

def load_comments() -> List[Dict[str, Any]]:
    return _read_json_list(COMMENTS_FILE)


def add_comment(text: str) -> None:
    comments = load_comments()
    next_id = (max((c.get("id", 0) for c in comments), default=0) + 1) if comments else 1

    comment = {
        "id": next_id,
        "text": text,
        "created_at": _now_utc_iso(),
    }
    comments.append(comment)
    _write_json_list(COMMENTS_FILE, comments)


# ---------------- Messages (Blind XSS) ----------------

def load_messages() -> List[Dict[str, Any]]:
    return _read_json_list(MESSAGES_FILE)


def add_message(text: str) -> None:
    messages = load_messages()
    next_id = (max((m.get("id", 0) for m in messages), default=0) + 1) if messages else 1

    message = {
        "id": next_id,
        "text": text,
        "created_at": _now_utc_iso(),
    }
    messages.append(message)
    _write_json_list(MESSAGES_FILE, messages)


# ---------------- Logs: stolen cookies, blind XSS ----------------

def log_stolen_cookie(ip: str, cookie_value: str) -> None:
    _ensure_dirs()
    timestamp = _now_utc_iso()
    mode = _get_security_mode_for_log()

    # Log legible
    line = f"[{timestamp}] mode={mode} IP={ip} c={cookie_value}\n"
    try:
        with STOLEN_COOKIES_LOG.open("a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass

    # Log estructurado JSONL
    record = {
        "timestamp": timestamp,
        "event": "stolen_cookie",
        "mode": mode,
        "ip": ip,
        "cookie": cookie_value,
    }
    try:
        with STOLEN_COOKIES_JSONL.open("a", encoding="utf-8") as fj:
            fj.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def log_blind_xss_event(message_count: int) -> None:
    _ensure_dirs()
    timestamp = _now_utc_iso()
    mode = _get_security_mode_for_log()

    # Log visible
    line = f"[{timestamp}] mode={mode} admin_view messages={message_count}\n"
    try:
        with BLIND_XSS_LOG.open("a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass

    # JSONL
    record = {
        "timestamp": timestamp,
        "event": "blind_xss_admin_view",
        "mode": mode,
        "message_count": message_count,
    }
    try:
        with BLIND_XSS_JSONL.open("a", encoding="utf-8") as fj:
            fj.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def read_stolen_cookies() -> List[Dict[str, str]]:
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
            mode = ""

            if line.startswith("[") and "]" in line:
                end_idx = line.find("]")
                timestamp = line[1:end_idx]
                remainder = line[end_idx + 1:].strip()
            else:
                remainder = line

            parts = remainder.split()
            for part in parts:
                if part.startswith("mode="):
                    mode = part[len("mode="):]
                elif part.startswith("IP="):
                    ip = part[len("IP="):]
                elif part.startswith("c="):
                    cookie_value = part[len("c="):]

            entries.append(
                {
                    "timestamp": timestamp,
                    "mode": mode,
                    "ip": ip,
                    "cookie": cookie_value,
                }
            )
    except OSError:
        pass

    return entries
