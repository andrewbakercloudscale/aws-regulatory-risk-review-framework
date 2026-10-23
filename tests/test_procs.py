"""Deep-scan worker processes: work crosses as plain data, logs come home, dead workers lose nothing."""

import logging
import os
import subprocess
import sys
import threading
import time
from concurrent.futures.process import BrokenProcessPool
from dataclasses import replace

import boto3
import pytest

from exitrisk import cli, procs, scanner, store
from exitrisk.logging_config import run_id_var
from exitrisk.scanner import ScanJob, ScanParams


def _pid_and_log(run_id):
    """Runs in a worker: functions sent to a worker must be importable, so this lives at module level."""
    run_id_var.set(run_id)
    logging.getLogger("exitrisk.test").warning("hello from worker %d", os.getpid())
    return os.getpid()


class _Records(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def records():
    h, root = _Records(), logging.getLogger("exitrisk")
    root.addHandler(h)
    old = root.level
    root.setLevel(logging.INFO)
    yield h.records
    root.removeHandler(h)
    root.setLevel(old)


def test_work_runs_in_other_processes_and_their_logs_come_home(records):
    with procs.InventoryPool(2) as pool:
        pids = {pool.call(_pid_and_log, "scan-1") for _ in range(4)}
    assert pids and os.getpid() not in pids
    mine = [r for r in records if r.name == "exitrisk.test"]
    assert len(mine) == 4 and {r.run_id for r in mine} == {"scan-1"}


def test_dead_workers_mean_this_process_reads_the_account(monkeypatch, records):
    seen = []
    monkeypatch.setattr(
        procs.inventory, "inventory_account", lambda s, a, r, dependencies=False: seen.append(a) or ({}, [])
    )
    session = boto3.Session(aws_access_key_id="A", aws_secret_access_key="B", region_name="eu-west-1")
    with procs.InventoryPool(1) as pool:
        with pytest.raises(BrokenProcessPool):
            pool.call(os._exit, 1)  # a worker killed part-way, as by the out-of-memory killer
        assert pool.inventory_account(session, "111111111111", None) == ({}, [])
        assert pool.inventory_account(session, "222222222222", None) == ({}, [])
    assert seen == ["111111111111", "222222222222"]
    assert sum("worker processes stopped" in r.getMessage() for r in records) == 1  # said once


def test_worker_builds_its_session_from_the_credentials(monkeypatch):
    got = {}

    def inv(session, account_id, regions, dependencies=False):
        c = session.get_credentials()
        got.update(key=c.access_key, token=c.token, region=session.region_name, run=run_id_var.get())
        return {"totals": {}}, []

    monkeypatch.setattr(procs.inventory, "inventory_account", inv)
    assert procs._inventory(("AK", "SK", "TOK"), "af-south-1", "1", None, True, "scan-9") == ({"totals": {}}, [])
    assert got == {"key": "AK", "token": "TOK", "region": "af-south-1", "run": "scan-9"}
    assert run_id_var.get() == "-"


def test_deep_scan_uses_worker_processes_and_always_closes_them(monkeypatch):
    from test_scanner import _org

    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})
    monkeypatch.setattr(scanner, "member_session", lambda s, pr, a, r, j: object())
    monkeypatch.setattr(scanner, "settings", replace(scanner.settings, processes=4))
    pools = []

    class Pool:
        def __init__(self, n):
            self.n, self.closed, self.read = n, False, []
            pools.append(self)

        def inventory_account(self, sess, account_id, regions, dependencies=False):
            self.read.append(account_id)
            return {"totals": {}}, []

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.closed = True

    monkeypatch.setattr(scanner, "InventoryPool", Pool)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams(inventory=True, role_name="r")))
    [pool] = pools
    assert pool.n == 2 and pool.closed and sorted(pool.read) == ["222222222222", "333333333333"]
    assert set(doc["inventory"]) == {"222222222222", "333333333333"}


def test_finished_jobs_are_dropped_after_an_hour(monkeypatch):
    monkeypatch.setattr(scanner, "_run_safely", lambda job: None)
    old = ScanJob(id="old", params=ScanParams())
    old.finish("complete", "done")
    old.finished_at -= scanner.JOB_KEEP_SECONDS + 1
    recent = ScanJob(id="recent", params=ScanParams())
    recent.finish("partial", "done")
    running = ScanJob(id="running", params=ScanParams())
    monkeypatch.setattr(scanner, "_jobs", {"old": old, "recent": recent, "running": running})
    job = scanner.start_scan(ScanParams())
    assert set(scanner._jobs) == {"recent", "running", job.id}
    assert recent.snapshot()["phase"] == "complete" and recent.snapshot()["status"] == "partial"


def test_replace_signals_again_a_console_that_will_not_stop(monkeypatch):
    # Ignores the first stop signal (as a console stuck on an open connection would), not the second.
    code = (
        "import signal, sys, time\n"
        "n = []\n"
        "signal.signal(signal.SIGTERM, lambda *a: sys.exit(0) if n else n.append(1))\n"
        "print('ready', flush=True)\n"
        "time.sleep(60)\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "ready"
        # Reap it as it exits: a real console is not our child, but this one would linger as a zombie.
        reaper = threading.Thread(target=proc.wait, daemon=True)
        reaper.start()
        monkeypatch.setattr(cli, "REPLACE_STOP_SECONDS", 0.5)
        monkeypatch.setattr(cli, "_console_busy", lambda port: False)

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, *a):
                return f'{{"pid": {proc.pid}, "scans_running": [], "reviews_running": []}}'.encode()

        monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Resp())
        started = time.monotonic()
        assert cli._stop_running_console(8799)
        reaper.join(5)
        assert proc.returncode == 0 and time.monotonic() - started < 10
    finally:
        proc.kill()


def test_replace_waits_while_the_console_is_busy(monkeypatch):
    busy = iter([True, True, False, False])
    monkeypatch.setattr(cli, "_console_busy", lambda port: next(busy, False))
    monkeypatch.setattr(cli, "REPLACE_STOP_SECONDS", 60)
    alive = iter([True] * 3 + [False])

    def kill(pid, sig):
        if sig == 0 and not next(alive):
            raise ProcessLookupError

    monkeypatch.setattr(os, "kill", kill)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, *a):
            return b'{"pid": 4242, "scans_running": ["s"], "reviews_running": []}'

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Resp())
    assert cli._stop_running_console(8799)


def test_stop_waits_for_ai_reviews_too(monkeypatch):
    import signal

    import uvicorn

    from exitrisk.ai import review

    monkeypatch.setattr("exitrisk.scanner.running_scans", lambda: [])
    review.expect("20261023-000000-aaaa")
    try:
        assert "20261023-000000-aaaa" in review.running_reviews()
        server = cli._scan_safe_server(uvicorn.Config(lambda *a: None))
        server.handle_exit(signal.SIGTERM, None)
        assert not server.should_exit
    finally:
        review.cancel("20261023-000000-aaaa")
    assert "20261023-000000-aaaa" not in review.running_reviews()
