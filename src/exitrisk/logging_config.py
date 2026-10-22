"""Logging: human-readable console output plus a rotating JSON-lines file.

Every record carries a ``run_id`` (the scan id, or ``-`` outside a scan) so one scan's
log lines can be pulled out of the file with ``grep``/``jq``. Credentials never reach a
log record: we log profile names and account ids, never keys or session tokens.
"""

from __future__ import annotations

import contextvars
import json
import logging
import logging.handlers
import re
from datetime import datetime, timezone

from .config import settings

run_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("run_id", default="-")

# Belt and braces: redact anything that looks like an AWS secret before it is written.
_SECRET_PATTERNS = [
    re.compile(
        r"(?i)(aws_secret_access_key|secretaccesskey|sessiontoken|aws_session_token|accesstoken|refreshtoken|clientsecret|devicecode)(['\"]?\s*[:=]\s*['\"]?)[^\s'\",}]+"
    ),
    re.compile(r"\b(ASIA|AKIA)[A-Z0-9]{16}\b"),
]


def redact(text: str) -> str:
    text = _SECRET_PATTERNS[0].sub(r"\1\2***REDACTED***", text)
    return _SECRET_PATTERNS[1].sub(r"\1****************", text)


class _RunIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = run_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "run_id": getattr(record, "run_id", "-"),
            "msg": redact(record.getMessage()),
        }
        for key in ("account_id", "service", "region", "error_code", "phase"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        rid = getattr(record, "run_id", "-")
        line = f"{ts} {record.levelname:<7} [{rid}] {redact(record.getMessage())}"
        if record.exc_info:
            line += "\n" + redact(self.formatException(record.exc_info))
        return line


_configured = False


def configure_logging(level: str | None = None) -> None:
    global _configured
    if _configured:
        return
    settings.ensure_dirs()
    root = logging.getLogger("exitrisk")
    root.setLevel(level or settings.log_level)
    root.propagate = False

    console = logging.StreamHandler()
    console.setFormatter(ConsoleFormatter())
    console.addFilter(_RunIdFilter())
    root.addHandler(console)

    file_handler = logging.handlers.RotatingFileHandler(
        settings.log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(JsonFormatter())
    file_handler.addFilter(_RunIdFilter())
    root.addHandler(file_handler)

    # botocore is noisy at INFO; keep its warnings.
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"exitrisk.{name}")


def tail_log(lines: int = 200, run_id: str | None = None) -> list[dict]:
    """Return the last ``lines`` JSON records from the log file, optionally for one run."""
    path = settings.log_file
    if not path.exists():
        return []
    out: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for raw in fh.readlines()[-max(lines * 5, lines) :]:
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if run_id and rec.get("run_id") != run_id:
                continue
            out.append(rec)
    return out[-lines:]
