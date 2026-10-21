"""A small thread pool map that keeps the scan's run id on log lines from worker threads."""

from __future__ import annotations

import contextvars
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")

# AWS calls in flight at once per collector. Organizations and Cost Explorer both throttle hard;
# four keeps a scan quick without tripping them (botocore's adaptive retries absorb the rest).
WORKERS = 4


def pmap(fn: Callable[[T], R], items: Iterable[T], workers: int = WORKERS) -> list[R]:
    """``[fn(x) for x in items]`` on up to ``workers`` threads, results in input order."""
    items = list(items)
    if len(items) <= 1:
        return [fn(x) for x in items]
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        # Copy the caller's context once per item, here: a context can run on one thread at a time.
        futures = [pool.submit(contextvars.copy_context().run, fn, x) for x in items]
        return [f.result() for f in futures]


def background(fn: Callable[[], R]) -> Future[R]:
    """Run ``fn`` on its own thread now; ``.result()`` waits for it and re-raises its error."""
    pool = ThreadPoolExecutor(max_workers=1)
    fut = pool.submit(contextvars.copy_context().run, fn)
    pool.shutdown(wait=False)
    return fut
