"""Rulesets: which Cloud Assurance Framework rules apply, saved by name for reuse.

A ruleset is a list of rule ids from data/assurance.yaml with optional severity overrides. It is
applied when the report is built, never at scan time: the scan reads everything it can, so changing
the ruleset needs no new scan. Saved rulesets live in ``$EXITRISK_DATA_DIR/rulesets.json``; the
built-in ones are made from the catalogue itself and cannot be changed or deleted.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from .collectors.assurance import catalog
from .config import settings
from .logging_config import get_logger

log = get_logger("rulesets")

_lock = threading.Lock()
SEVERITIES = ("critical", "high", "medium", "low")
NAME_RE = r"^[\w ().,&+/-]{1,60}$"


class Ruleset(BaseModel):
    name: str = Field(..., pattern=NAME_RE)
    description: str = Field("", max_length=300)
    rules: list[str] = Field(default_factory=list, max_length=500)
    # Rule id -> severity, where this ruleset rates a rule differently from the catalogue.
    severity: dict[str, str] = Field(default_factory=dict)


def _path() -> Path:
    return settings.data_dir / "rulesets.json"


def _ids() -> list[str]:
    return [c["id"] for c in catalog()["checks"]]


def builtin() -> list[dict]:
    checks = catalog()["checks"]

    def having(test) -> list[str]:
        return [c["id"] for c in checks if test(c)]

    sets = [
        ("All rules", "Every rule in the catalogue.", having(lambda c: True)),
        (
            "Regulator essentials",
            "Critical and high severity rules: the controls a regulator asks about first.",
            having(lambda c: c["severity"] in ("critical", "high")),
        ),
        (
            "CIS AWS Foundations",
            "Rules mapped to the CIS AWS Foundations Benchmark v3.0.",
            having(lambda c: any(str(r).startswith("CIS ") for r in c.get("refs") or [])),
        ),
        (
            "AWS Foundational Security Best Practices",
            "Rules mapped to the AWS Foundational Security Best Practices controls in Security Hub.",
            having(lambda c: any(str(r).startswith("FSBP ") for r in c.get("refs") or [])),
        ),
        (
            "Resilience and disaster recovery",
            "Multi-AZ, backups, restore tests and recovery for production.",
            having(lambda c: c["area"] == "resilience"),
        ),
        (
            "Sensitive data",
            "Payment and customer data: write access, versioning, locking, logging and encryption.",
            having(lambda c: c["area"] in ("sensitive", "data")),
        ),
        (
            "Identity and access",
            "Root, administrators, credentials, guardrails and outside access.",
            having(lambda c: c["area"] in ("access", "third_party")),
        ),
    ]
    return [{"name": n, "description": d, "rules": r, "severity": {}, "builtin": True} for n, d, r in sets]


def _read() -> dict[str, dict]:
    try:
        return json.loads(_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        log.exception("could not read %s", _path())
        return {}


def _write(data: dict[str, dict]) -> None:
    settings.ensure_dirs()
    fd, tmp = tempfile.mkstemp(dir=settings.data_dir, prefix=".tmp-rulesets-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, _path())
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def list_all() -> list[dict]:
    saved = sorted(_read().values(), key=lambda r: r["name"].lower())
    return builtin() + [{**r, "builtin": False} for r in saved]


def get(name: str | None) -> dict:
    """The ruleset called ``name``; "All rules" when there is none by that name."""
    for r in list_all():
        if r["name"] == name:
            return r
    return builtin()[0]


def _key(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip()).casefold()


def save(rs: Ruleset) -> dict:
    name = re.sub(r"\s+", " ", rs.name.strip())
    if _key(name) in {_key(b["name"]) for b in builtin()}:
        raise ValueError(f"'{name}' is a built-in ruleset: save it under another name")
    known = set(_ids())
    rules = [r for r in dict.fromkeys(rs.rules) if r in known]
    if not rules:
        raise ValueError("a ruleset needs at least one rule")
    bad = {k: v for k, v in rs.severity.items() if k not in known or v not in SEVERITIES}
    if bad:
        raise ValueError(f"unknown rule or severity: {', '.join(sorted(bad))}")
    item = {
        "name": name,
        "description": rs.description.strip(),
        "rules": rules,
        "severity": dict(rs.severity),
        "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with _lock:
        data = _read()
        data = {k: v for k, v in data.items() if _key(k) != _key(name)}
        data[name] = item
        _write(data)
    log.info("saved ruleset %r with %d rule(s)", name, len(rules))
    return {**item, "builtin": False}


def delete(name: str) -> bool:
    with _lock:
        data = _read()
        keep = {k: v for k, v in data.items() if _key(k) != _key(name)}
        if len(keep) == len(data):
            return False
        _write(keep)
    log.info("deleted ruleset %r", name)
    return True
