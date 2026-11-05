"""Zscaler's published egress ranges: where a laptop behind Zscaler appears to come from.

Read from Zscaler's own config feed, cached for a day under the data directory. Used only to label an address
range on a database's port as a laptop range; every unknown range is a finding either way.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .config import settings
from .logging_config import get_logger

log = get_logger("zscaler")

CLOUDS = ("zscaler.net", "zscalerone.net", "zscalertwo.net", "zscalerthree.net", "zscloud.net", "zscalerbeta.net")
FEED = "https://config.zscaler.com/api/{cloud}/cenr/json"
CACHE_SECONDS = 86400
_memo: dict = {}
_lock = threading.Lock()


def _walk(node, out: set[str]) -> None:
    if isinstance(node, dict):
        if isinstance(node.get("range"), str):
            out.add(node["range"])
        for v in node.values():
            _walk(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk(v, out)


def ranges() -> list[str]:
    """Every published Zscaler egress range, from the cache when fresh; [] when it cannot be had."""
    with _lock:
        if _memo.get("at", 0) > time.time() - CACHE_SECONDS:
            return _memo["ranges"]
    got = _read()
    with _lock:
        _memo.update(at=time.time(), ranges=got)
    return got


def _read() -> list[str]:
    path = settings.data_dir / "zscaler-ranges.json"
    try:
        cached = json.loads(path.read_text())
        if time.time() - cached["at"] < CACHE_SECONDS and cached["ranges"]:
            return cached["ranges"]
    except (OSError, ValueError, KeyError):
        cached = None
    found: set[str] = set()

    def one(cloud: str) -> None:
        try:
            with urllib.request.urlopen(FEED.format(cloud=cloud), timeout=5) as resp:  # noqa: S310 - fixed https URL
                _walk(json.load(resp), found)
        except (OSError, ValueError) as exc:
            log.info("Zscaler ranges for %s not read: %s", cloud, exc)

    with ThreadPoolExecutor(max_workers=len(CLOUDS)) as pool:
        list(pool.map(one, CLOUDS))
    if found:
        path.write_text(json.dumps({"at": time.time(), "ranges": sorted(found)}))
        return sorted(found)
    return (cached or {}).get("ranges") or []


def overlaps(cidr: str, nets: list) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return any(net.version == n.version and net.overlaps(n) for n in nets)


def networks(cidrs: list[str]) -> list:
    out = []
    for c in cidrs:
        try:
            out.append(ipaddress.ip_network(c.strip(), strict=False))
        except ValueError:
            continue
    return out
