"""Monthly scan: repeat a saved scan's settings once a month, so Compare scans shows a trend.

The schedule is one JSON file in the data directory. The console checks it while it runs; for a
laptop where the console is not always open, `exitrisk schedule run` (from launchd or cron) does
the same check from the command line. Either way the scan runs with the analyst's own AWS sign-in:
when that has expired the attempt fails, is recorded, and is retried a day later, and the console
says so until a scan succeeds.
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone

from pydantic import BaseModel, Field

from .config import settings
from .logging_config import get_logger

log = get_logger("schedule")

RETRY_AFTER = timedelta(hours=24)
CHECK_EVERY_S = 600
# A scan claimed but never finished (the process died) is given up after this long.
STALE_RUN = timedelta(hours=12)
# Settings a scheduled scan repeats; anything else in a scan's params is left behind.
PARAM_KEYS = (
    "profile",
    "ou_id",
    "ou_ids",
    "months",
    "role_name",
    "inventory",
    "dependencies",
    "inventory_scope",
    "regions",
    "region_scope",
    "target",
)


class ScheduleRequest(BaseModel):
    from_scan: str = Field(..., max_length=40)
    day: int = Field(3, ge=1, le=28)
    enabled: bool = True


def _path():
    return settings.data_dir / "schedule.json"


def load() -> dict | None:
    try:
        return json.loads(_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("ignoring unreadable schedule file %s: %s", _path(), exc)
        return None


def save(s: dict) -> None:
    settings.ensure_dirs()
    fd, tmp = tempfile.mkstemp(dir=settings.data_dir, prefix=".tmp-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(s, fh, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, _path())


def clear() -> None:
    _path().unlink(missing_ok=True)


@contextmanager
def _locked():
    """The console and `exitrisk schedule run` may both look at once: one claims the run."""
    settings.ensure_dirs()
    with open(settings.data_dir / "schedule.lock", "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def create(req: ScheduleRequest, scan: dict, now: datetime | None = None) -> dict:
    if scan.get("mode") != "live":
        raise ValueError("only a live scan can be repeated: the demo has no AWS settings")
    params = {k: v for k, v in (scan.get("params") or {}).items() if k in PARAM_KEYS}
    s = {
        "enabled": req.enabled,
        "day": req.day,
        "from_scan": scan["id"],
        "params": params,
        "label": scan.get("label") or "",
        "ou": (scan.get("ou") or {}).get("path") or "",
        "created_at": (now or _now()).isoformat(timespec="seconds"),
        # The scan it repeats counts as this month's run: the next is due on `day` next month.
        "last_success_at": scan.get("created_at") or (now or _now()).isoformat(timespec="seconds"),
        "last_scan_id": scan["id"],
        "last_attempt_at": None,
        "last_status": "complete",
        "last_error": "",
        "running": None,
    }
    save(s)
    log.info("monthly scan set: repeats %s on day %d of each month", scan["id"], req.day)
    return s


def next_run(s: dict) -> date:
    """The schedule day in the month after the last successful run (or after the schedule was set)."""
    anchor = (_ts(s.get("last_success_at")) or _ts(s.get("created_at")) or _now()).date()
    y, m = (anchor.year + 1, 1) if anchor.month == 12 else (anchor.year, anchor.month + 1)
    return date(y, m, s["day"])


def status(s: dict | None, now: datetime | None = None) -> dict:
    """What the console shows: when the next scan runs, and whether the last attempt failed."""
    if not s:
        return {"schedule": None}
    now = now or _now()
    due_on = next_run(s)
    attempt = _ts(s.get("last_attempt_at"))
    retry_at = attempt + RETRY_AFTER if attempt and s.get("last_status") == "failed" else None
    return {
        "schedule": s,
        "next_run": due_on.isoformat(),
        "due": bool(s.get("enabled")) and now.date() >= due_on,
        "overdue_days": max(0, (now.date() - due_on).days) if s.get("enabled") else 0,
        "failing": s.get("last_status") == "failed" and now.date() >= due_on,
        "retry_at": retry_at.isoformat(timespec="minutes") if retry_at and retry_at > now else None,
        "running": s.get("running"),
    }


def should_run(s: dict | None, now: datetime | None = None) -> bool:
    if not s or not s.get("enabled"):
        return False
    now = now or _now()
    running = _ts((s.get("running") or {}).get("started_at"))
    if running and now - running < STALE_RUN:
        return False
    if now.date() < next_run(s):
        return False
    attempt = _ts(s.get("last_attempt_at"))
    return not (s.get("last_status") == "failed" and attempt and now - attempt < RETRY_AFTER)


def _label(s: dict, now: datetime) -> str:
    return f"{s.get('label') or s.get('ou') or 'Scan'} · monthly {now:%Y-%m}"


def claim(force: bool = False, now: datetime | None = None) -> dict | None:
    """Mark the scheduled scan as started, if it is due (or forced). Returns the schedule claimed."""
    now = now or _now()
    with _locked():
        s = load()
        if not s or not (force or should_run(s, now)):
            return None
        if force and (r := _ts((s.get("running") or {}).get("started_at"))) and now - r < STALE_RUN:
            return None
        s["running"] = {"started_at": now.isoformat(timespec="seconds"), "scan_id": None}
        s["last_attempt_at"] = now.isoformat(timespec="seconds")
        save(s)
        return s


def started(scan_id: str) -> None:
    with _locked():
        s = load()
        if s and s.get("running"):
            s["running"]["scan_id"] = scan_id
            save(s)


def finished(scan_id: str | None, outcome: str, error: str = "", now: datetime | None = None) -> None:
    now = now or _now()
    with _locked():
        s = load()
        if not s:
            return
        s["running"] = None
        s["last_status"] = "failed" if outcome == "failed" else outcome
        s["last_error"] = error if outcome == "failed" else ""
        if scan_id:
            s["last_scan_id"] = scan_id
        if outcome != "failed":
            s["last_success_at"] = now.isoformat(timespec="seconds")
        save(s)
    (log.warning if outcome == "failed" else log.info)(
        "monthly scan %s: %s%s", scan_id or "-", outcome, f" ({error})" if error else ""
    )


def scan_params(s: dict, now: datetime | None = None) -> dict:
    return {**s["params"], "label": _label(s, now or _now())}


# ------------------------------------------------------------------ console runner
def run_in_console(force: bool = False) -> str | None:
    """Start the scheduled scan in the console's scan runner; a thread records the outcome."""
    from .scanner import ScanParams, get_job, running_scans, start_scan

    if not force and running_scans():
        return None  # never stack a scheduled scan on one the analyst started
    s = claim(force=force)
    if not s:
        return None
    try:
        job = start_scan(ScanParams(**scan_params(s)))
    except Exception as exc:  # bad saved settings: record it rather than retry blindly
        finished(None, "failed", str(exc))
        return None
    started(job.id)

    def watch():
        while (j := get_job(job.id)) and j.status == "running":
            threading.Event().wait(5)
        j = get_job(job.id)
        outcome = j.status if j else "failed"
        finished(job.id, outcome, j.message if j and outcome == "failed" else "")
        if outcome == "failed":
            _drop_empty(job.id)

    threading.Thread(target=watch, name=f"schedule-{job.id}", daemon=True).start()
    return job.id


def _drop_empty(scan_id: str) -> None:
    """A retried attempt that failed before reading any account (sign-in expired) would add a
    failed scan to the list every day: the schedule keeps the error, so the empty file goes."""
    from . import store

    try:
        if not store.load_scan(scan_id).get("accounts"):
            store.delete_scan(scan_id)
    except store.ScanNotFound:
        pass


def start_runner(stop: threading.Event) -> threading.Thread:
    """Check the schedule now and every few minutes while the console runs."""

    def loop():
        while not stop.is_set():
            try:
                run_in_console()
            except Exception:
                log.exception("monthly scan check failed")
            stop.wait(CHECK_EVERY_S)

    t = threading.Thread(target=loop, name="schedule", daemon=True)
    t.start()
    return t
