"""Scan persistence: one JSON file per scan under ``$EXITRISK_DATA_DIR/scans``."""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import threading
from datetime import datetime

from .config import settings

_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[a-z0-9]{4,8}$")
_lock = threading.Lock()


class ScanNotFound(KeyError):
    pass


def new_scan_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)


def _path(scan_id: str):
    # The id is used in a file path: reject anything that is not exactly our format.
    if not _ID_RE.match(scan_id):
        raise ScanNotFound(scan_id)
    return settings.scans_dir / f"{scan_id}.json"


def save_scan(scan: dict) -> None:
    settings.ensure_dirs()
    path = _path(scan["id"])
    with _lock:
        fd, tmp = tempfile.mkstemp(dir=settings.scans_dir, prefix=".tmp-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(scan, fh, indent=1, default=str)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)  # atomic: a reader never sees half a file


def load_scan(scan_id: str) -> dict:
    path = _path(scan_id)
    if not path.exists():
        raise ScanNotFound(scan_id)
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def list_scans() -> list[dict]:
    settings.ensure_dirs()
    out = []
    for path in sorted(settings.scans_dir.glob("*.json"), reverse=True):
        if path.name.startswith(".tmp-"):
            continue
        try:
            with path.open(encoding="utf-8") as fh:
                s = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        out.append(
            {
                "id": s["id"],
                "created_at": s.get("created_at"),
                "status": s.get("status"),
                "mode": s.get("mode"),
                "ou": (s.get("ou") or {}).get("path"),
                "profile": (s.get("params") or {}).get("profile"),
                "accounts": len(s.get("accounts", [])),
                "label": s.get("label", ""),
            }
        )
    return out


def delete_scan(scan_id: str) -> None:
    path = _path(scan_id)
    if not path.exists():
        raise ScanNotFound(scan_id)
    path.unlink()
