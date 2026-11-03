"""Is this machine online? A scan or an AI run that loses the network (a laptop shut, Wi-Fi dropped)
pauses and carries on by itself once the connection is back, instead of failing every account left.

Online means a TCP connection to AWS opens: through the HTTPS proxy when one is set, else straight to
the STS endpoint. A connection refused still means the network is there.
"""

from __future__ import annotations

import errno
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
from collections.abc import Callable

from botocore.exceptions import (
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    HTTPClientError,
    ProxyConnectionError,
    ReadTimeoutError,
)

from .logging_config import get_logger

log = get_logger("network")

PROBE_HOSTS = (("sts.amazonaws.com", 443), ("aws.amazon.com", 443))
PROBE_TIMEOUT = 4
POLL_SECONDS = 5
CACHE_SECONDS = 2

# The error codes a scan records for a call that never reached AWS (describe_exception and the
# collectors' own codes: the exception's class name).
NETWORK_CODES = frozenset({
    "EndpointConnection", "EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError",
    "ConnectionClosedError", "ProxyConnectionError", "HTTPClientError", "SSLError", "TimeoutError",
    "ConnectionError", "ConnectionResetError", "URLError", "gaierror",
})  # fmt: skip

_NET_ERRNOS = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN, errno.ECONNRESET, errno.ETIMEDOUT,
               errno.ECONNABORTED, errno.EHOSTDOWN}  # fmt: skip

_last: tuple[float, bool] = (0.0, True)
_lock = threading.Lock()


def is_network_error(exc: BaseException | None) -> bool:
    """True for an error that says the request never got an answer: no route, no DNS, a dropped
    connection or a timeout. Follows the exception's cause, as an SDK often wraps the socket error."""
    seen = 0
    while exc is not None and seen < 5:
        if isinstance(exc, (EndpointConnectionError, ConnectTimeoutError, ReadTimeoutError, ConnectionClosedError,
                            ProxyConnectionError, HTTPClientError, socket.gaierror, TimeoutError,
                            ConnectionError, urllib.error.URLError)):  # fmt: skip
            return not isinstance(exc, urllib.error.HTTPError)  # an HTTP answer came back
        if isinstance(exc, OSError) and exc.errno in _NET_ERRNOS:
            return True
        exc, seen = exc.__cause__ or exc.__context__, seen + 1
    return False


def _targets() -> list[tuple[str, int]]:
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy:
        u = urllib.parse.urlparse(proxy if "://" in proxy else f"http://{proxy}")
        if u.hostname:
            return [(u.hostname, u.port or 8080)]
    return list(PROBE_HOSTS)


def online() -> bool:
    """One probe every couple of seconds at most, however many threads ask."""
    global _last
    with _lock:
        at, ok = _last
        if time.monotonic() - at < CACHE_SECONDS:
            return ok
        ok = False
        for host, port in _targets():
            try:
                socket.create_connection((host, port), timeout=PROBE_TIMEOUT).close()
                ok = True
                break
            except ConnectionRefusedError:
                ok = True  # something answered: the network is up
                break
            except OSError:
                continue
        _last = (time.monotonic(), ok)
        return ok


class Cancelled(Exception):
    """The wait was stopped (the scan or run was cancelled)."""


def wait_until_online(on_wait: Callable[[float], None] | None = None, stop: Callable[[], bool] | None = None) -> float:
    """Block until online; seconds waited (0 when it already was). ``on_wait(seconds_so_far)`` is called
    each poll, for a progress message; ``stop()`` true ends the wait with Cancelled."""
    if online():
        return 0.0
    t0 = time.monotonic()
    log.warning("network lost: paused until the connection is back")
    while True:
        if stop and stop():
            raise Cancelled
        if on_wait:
            on_wait(time.monotonic() - t0)
        time.sleep(POLL_SECONDS)
        if online():
            waited = time.monotonic() - t0
            log.info("network back after %.0f s: carrying on", waited)
            return waited


def paused_message(seconds: float) -> str:
    mins = int(seconds // 60)
    since = f" ({mins} min so far)" if mins else ""
    return f"No network connection: paused{since}. It carries on by itself when you are back online."
