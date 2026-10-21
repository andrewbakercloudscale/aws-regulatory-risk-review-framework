from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from exitrisk import schedule, store
from exitrisk.server import create_app

H = {"X-ExitRisk": "1"}
T0 = datetime(2026, 10, 21, 9, 0, tzinfo=timezone.utc)


def _live_scan(scan_id="20261021-090000-abcd"):
    scan = {
        "id": scan_id,
        "mode": "live",
        "status": "complete",
        "label": "Prod review",
        "created_at": T0.isoformat(),
        "ou": {"path": "Root / Prod"},
        "params": {"profile": "mgmt", "ou_id": None, "ou_ids": ["ou-ab12-cdef3456"], "months": 12,
                   "role_name": None, "inventory": False, "regions": None, "label": "Prod review", "target": "azure"},
        "accounts": [], "costs": [], "issues": [],
    }  # fmt: skip
    store.save_scan(scan)
    return scan


@pytest.fixture(autouse=True)
def _no_schedule():
    schedule.clear()
    yield
    schedule.clear()


def test_next_run_is_the_day_after_the_last_success():
    s = schedule.create(schedule.ScheduleRequest(from_scan="x", day=3), _live_scan(), now=T0)
    assert s["params"]["ou_ids"] == ["ou-ab12-cdef3456"] and "label" not in s["params"]
    assert schedule.next_run(s).isoformat() == "2026-11-03"
    assert not schedule.should_run(s, T0 + timedelta(days=12))  # 2 November
    assert schedule.should_run(s, T0 + timedelta(days=13))  # 3 November
    s["last_success_at"] = "2026-12-04T09:00:00+00:00"
    assert schedule.next_run(s).isoformat() == "2027-01-03"


def test_failed_attempt_waits_a_day_and_is_reported():
    schedule.create(schedule.ScheduleRequest(from_scan="x", day=3), _live_scan(), now=T0)
    due = datetime(2026, 11, 3, 6, 0, tzinfo=timezone.utc)
    s = schedule.claim(now=due)
    assert s and s["running"]
    assert schedule.claim(now=due) is None  # claimed once: a second checker does not start it again
    schedule.finished(None, "failed", "The SSO session has expired", now=due)
    s = schedule.load()
    st = schedule.status(s, due + timedelta(hours=1))
    assert st["failing"] and st["due"] and st["retry_at"]
    assert not schedule.should_run(s, due + timedelta(hours=23))
    assert schedule.should_run(s, due + timedelta(hours=25))
    schedule.claim(now=due + timedelta(hours=25))
    schedule.finished("20261104-070000-beef", "complete", now=due + timedelta(hours=25))
    st = schedule.status(schedule.load(), due + timedelta(hours=26))
    assert not st["failing"] and not st["due"] and st["next_run"] == "2026-12-03"
    assert schedule.load()["last_scan_id"] == "20261104-070000-beef"


def test_disabled_or_demo_never_runs():
    s = schedule.create(schedule.ScheduleRequest(from_scan="x", day=3, enabled=False), _live_scan(), now=T0)
    assert not schedule.should_run(s, T0 + timedelta(days=60))
    with pytest.raises(ValueError):
        schedule.create(schedule.ScheduleRequest(from_scan="x"), {"id": "d", "mode": "demo"})


def test_schedule_api(monkeypatch):
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    assert c.get("/api/schedule").json() == {"schedule": None}
    scan = _live_scan()
    assert c.put("/api/schedule", headers=H, json={"from_scan": "20261021-090001-0000"}).status_code == 404
    demo = c.post("/api/scans/demo", headers=H).json()["id"]
    assert c.put("/api/schedule", headers=H, json={"from_scan": demo}).status_code == 400
    r = c.put("/api/schedule", headers=H, json={"from_scan": scan["id"], "day": 5}).json()
    assert r["schedule"]["day"] == 5 and r["schedule"]["ou"] == "Root / Prod" and r["next_run"].endswith("-05")

    started = []
    monkeypatch.setattr(schedule, "run_in_console", lambda force=False: started.append(force) or "20261021-100000-aaaa")
    assert c.post("/api/schedule/run", headers=H).json()["scan_id"] == "20261021-100000-aaaa"
    assert started == [True]
    assert c.delete("/api/schedule", headers=H).json() == {"schedule": None}
    assert c.post("/api/schedule/run", headers=H).status_code == 404


def test_console_run_records_failure_and_drops_the_empty_scan(monkeypatch):
    from exitrisk import scanner

    s = schedule.create(schedule.ScheduleRequest(from_scan="x", day=1), _live_scan(), now=T0)
    s["last_success_at"] = "2026-01-05T09:00:00+00:00"  # long overdue
    schedule.save(s)
    seen = {}

    def fake_start(params):
        seen["params"] = params
        job = scanner.ScanJob(id="20261021-100000-dead", params=params, status="failed", message="SSO session expired")
        store.save_scan({"id": job.id, "mode": "live", "status": "failed", "accounts": [], "costs": [], "issues": []})
        monkeypatch.setitem(scanner._jobs, job.id, job)
        return job

    monkeypatch.setattr(scanner, "start_scan", fake_start)
    monkeypatch.setattr(
        schedule.threading, "Thread", lambda target, **_: type("T", (), {"start": lambda self: target()})()
    )
    assert schedule.run_in_console() == "20261021-100000-dead"
    assert seen["params"].ou_ids == ["ou-ab12-cdef3456"] and "monthly" in seen["params"].label
    s = schedule.load()
    assert s["last_status"] == "failed" and s["last_error"] == "SSO session expired" and not s["running"]
    assert all(x["id"] != "20261021-100000-dead" for x in store.list_scans())
    assert schedule.run_in_console() is None  # retried a day later, not straight away
