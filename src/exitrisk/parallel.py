"""A small thread pool map that keeps the scan's run id on log lines from worker threads."""

from __future__ import annotations

import contextvars
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")

# AWS calls in flight at once per collector. Organizations and Cost Explorer both throttle hard;
# four keeps a scan quick without tripping them (botocore's adaptive retries absorb the rest).
WORKERS = 4


def pmap(
    fn: Callable[[T], R],
    items: Iterable[T],
    workers: int = WORKERS,
    on_done: Callable[[int, int], None] | None = None,
) -> list[R]:
    """``[fn(x) for x in items]`` on up to ``workers`` threads, results in input order.
    ``on_done(done, total)`` is called as each item finishes, one call at a time."""
    items = list(items)
    lock = threading.Lock()
    done = 0

    def run(x: T) -> R:
        nonlocal done
        out = fn(x)
        if on_done:
            with lock:
                done += 1
                on_done(done, len(items))
        return out

    if len(items) <= 1:
        return [run(x) for x in items]
    pool = ThreadPoolExecutor(max_workers=min(workers, len(items)))
    # Copy the caller's context once per item, here: a context can run on one thread at a time.
    futures = [pool.submit(contextvars.copy_context().run, run, x) for x in items]
    try:
        out = [f.result() for f in futures]
    except BaseException:
        pool.shutdown(wait=False, cancel_futures=True)  # a failure or a stopped scan: start no more items
        raise
    pool.shutdown()
    return out


def background(fn: Callable[[], R]) -> Future[R]:
    """Run ``fn`` on its own thread now; ``.result()`` waits for it and re-raises its error."""
    pool = ThreadPoolExecutor(max_workers=1)
    fut = pool.submit(contextvars.copy_context().run, fn)
    pool.shutdown(wait=False)
    return fut
