"""Scan persistence: one JSON file per scan under ``$EXITRISK_DATA_DIR/scans``."""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import threading
from datetime import datetime
from pathlib import Path

from .config import settings
from .logging_config import get_logger

log = get_logger("store")

_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[a-z0-9]{4,8}$")
_lock = threading.Lock()


class ScanNotFound(KeyError):
    pass


def new_scan_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)


def _path(scan_id: str):
    # The id is used in a file path: reject anything that is not exactly our format.
    if not _ID_RE.fullmatch(scan_id):
        raise ScanNotFound(scan_id)
    return settings.scans_dir / f"{scan_id}.json"


def save_scan(scan: dict) -> None:
    settings.ensure_dirs()
    path = _path(scan["id"])
    with _lock:
        fd, tmp = tempfile.mkstemp(dir=settings.scans_dir, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(scan, fh, indent=1, default=str)
                fh.flush()
                os.fsync(fh.fileno())  # a crash after the rename never leaves an empty scan
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)  # atomic: a reader never sees half a file
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            log.exception("could not save scan %s", scan["id"])
            raise


def load_scan(scan_id: str) -> dict:
    path = _path(scan_id)
    if not path.exists():
        raise ScanNotFound(scan_id)
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


# Scan files run to several MB; listing them should not parse every one on each page load.
# Summaries are kept per file and re-read only when the file changes.
_summaries: dict[str, tuple[tuple[int, int], dict]] = {}
_summaries_lock = threading.Lock()  # the console lists scans from several request threads at once


def list_scans() -> list[dict]:
    settings.ensure_dirs()
    out = []
    paths = [p for p in sorted(settings.scans_dir.glob("*.json"), reverse=True) if not p.name.startswith(".tmp-")]
    with _summaries_lock:
        for gone in set(_summaries) - {str(p) for p in paths}:
            _summaries.pop(gone, None)
    for path in paths:
        try:
            st = path.stat()
        except OSError:
            continue
        stamp = (st.st_mtime_ns, st.st_size)
        with _summaries_lock:
            hit = _summaries.get(str(path))
        if hit and hit[0] == stamp:
            out.append(hit[1])
            continue
        try:
            with path.open(encoding="utf-8") as fh:
                s = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("skipping unreadable scan file %s: %s", path.name, exc)
            continue
        summary = {
            "id": s["id"],
            "created_at": s.get("created_at"),
            "status": s.get("status"),
            "mode": s.get("mode"),
            "ou": (s.get("ou") or {}).get("path"),
            "profile": (s.get("params") or {}).get("profile"),
            "accounts": len(s.get("accounts", [])),
            "label": s.get("label", ""),
            "target": (s.get("params") or {}).get("target"),
        }
        with _summaries_lock:
            _summaries[str(path)] = (stamp, summary)
        out.append(summary)
    return out


def delete_scan(scan_id: str) -> None:
    path = _path(scan_id)
    if not path.exists():
        raise ScanNotFound(scan_id)
    path.unlink()
