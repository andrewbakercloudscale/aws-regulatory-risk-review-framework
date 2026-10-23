"""Deep-scan accounts in worker processes, so a large scan uses more than one CPU core.

A deep scan spends most of its time parsing AWS answers, which holds Python's GIL: with threads alone
the console runs on one core however many accounts it reads at once. Each account's inventory
therefore runs in a worker process, ``settings.processes`` at a time.

Only plain data crosses between processes: an account's temporary credentials go in (held in memory,
never written or logged), counts and issues come back. Log lines come back through a queue and are
written by the console process alone, so two processes never write or rotate the log file at once.
Workers are started with "spawn", not "fork": forking a process that runs threads can copy a lock
another thread holds into the child, which then hangs on it.
"""

from __future__ import annotations

import logging
import logging.handlers
import multiprocessing
import multiprocessing.connection
import os
import signal
import threading
import weakref
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool

import boto3

from .collectors import inventory
from .config import settings
from .logging_config import get_logger, run_id_var

log = get_logger("procs")

_live: weakref.WeakSet[InventoryPool] = weakref.WeakSet()
_live_lock = threading.Lock()


class _Relay(logging.Handler):
    """In the console process: hand a worker's log record to the logger it was made by."""

    def emit(self, record: logging.LogRecord) -> None:
        logging.getLogger(record.name).handle(record)


class _KeepRunId(logging.Filter):
    """In a worker: stamp the record with the scan id before it crosses to the console."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = run_id_var.get()
        return True


def _exit_with(sentinel) -> None:
    multiprocessing.connection.wait([sentinel])
    os._exit(1)


def _init_worker(queue, level: str) -> None:
    # Ctrl+C reaches the whole process group; the console decides when the workers stop.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # A console killed outright (SIGKILL, or SIGTERM to a CLI scan) cannot stop its workers, so each
    # worker stops itself when the console is gone instead of reading on for nobody.
    parent = multiprocessing.parent_process()
    if parent is not None:
        threading.Thread(target=_exit_with, args=(parent.sentinel,), name="exitrisk-parent", daemon=True).start()
    handler = logging.handlers.QueueHandler(queue)
    handler.addFilter(_KeepRunId())
    root = logging.getLogger("exitrisk")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False
    for noisy in ("botocore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _inventory(creds: tuple[str, str, str | None], region: str | None, account_id: str, regions, dependencies, run_id):
    """In a worker: one account's inventory, with a session made here from the credentials."""
    token = run_id_var.set(run_id)
    try:
        session = boto3.Session(
            aws_access_key_id=creds[0], aws_secret_access_key=creds[1], aws_session_token=creds[2], region_name=region
        )
        return inventory.inventory_account(session, account_id, regions, dependencies=dependencies)
    finally:
        run_id_var.reset(token)


class InventoryPool:
    """Worker processes for one deep scan. Safe to call from the scan's many threads at once."""

    def __init__(self, processes: int):
        ctx = multiprocessing.get_context("spawn")
        self._queue = ctx.Queue()
        self._listener = logging.handlers.QueueListener(self._queue, _Relay())
        self._listener.start()
        self._pool = ProcessPoolExecutor(
            max_workers=processes, mp_context=ctx, initializer=_init_worker, initargs=(self._queue, settings.log_level)
        )
        self._lock = threading.Lock()
        self._broken = False
        self._closed = False
        self._stopped = False
        with _live_lock:
            _live.add(self)

    def call(self, fn, *args):
        """``fn(*args)`` in a worker process; ``fn`` must be a module-level function."""
        return self._pool.submit(fn, *args).result()

    def inventory_account(self, session, account_id: str, regions, dependencies: bool = False):
        """As inventory.inventory_account, in a worker. If the workers have died (killed, out of memory),
        the account is read in this process instead, so a scan never loses accounts to it."""
        base = getattr(session, "session", session)  # a ClientCache stands in for the scan's own session
        creds = base.get_credentials().get_frozen_credentials()  # refreshed here if close to expiry
        try:
            return self.call(
                _inventory,
                (creds.access_key, creds.secret_key, creds.token),
                base.region_name,
                account_id,
                regions,
                dependencies,
                run_id_var.get(),
            )
        except BrokenProcessPool:
            with self._lock:
                if self._stopped:  # terminate() killed them: the scan is stopping, not falling back
                    raise
                first, self._broken = not self._broken, True
            if first:
                log.warning("the deep-scan worker processes stopped; reading the remaining accounts in the console")
            return inventory.inventory_account(session, account_id, regions, dependencies=dependencies)

    def close(self) -> None:
        """Stop the workers, then the log relay once their last lines are in. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        with _live_lock:
            _live.discard(self)
        self._pool.shutdown(wait=True, cancel_futures=True)
        self._listener.stop()
        self._queue.close()
        self._queue.join_thread()

    def terminate(self) -> None:
        """Kill the workers now, for a scan stopped by Ctrl+C or a console told to stop at once."""
        with self._lock:
            self._stopped = True
        for proc in list((getattr(self._pool, "_processes", None) or {}).values()):
            proc.terminate()

    def __enter__(self) -> InventoryPool:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def terminate_all() -> None:
    """Kill every deep-scan worker process; the console calls this when it is stopped at once."""
    with _live_lock:
        pools = list(_live)
    for pool in pools:
        pool.terminate()
