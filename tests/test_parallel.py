import threading
import time

from exitrisk import store
from exitrisk.demo import create_demo_scan
from exitrisk.logging_config import run_id_var
from exitrisk.parallel import background, pmap


def test_pmap_keeps_order_and_uses_four_threads():
    seen: set[str] = set()

    def slow(x):
        seen.add(threading.current_thread().name)
        time.sleep(0.05)
        return x * 2

    started = time.monotonic()
    assert pmap(slow, range(8)) == [0, 2, 4, 6, 8, 10, 12, 14]
    assert len(seen) == 4
    assert time.monotonic() - started < 0.3  # two rounds of four, not eight in a row


def test_worker_threads_keep_the_scan_run_id():
    token = run_id_var.set("scan-123")
    try:
        assert pmap(lambda _: run_id_var.get(), range(3)) == ["scan-123"] * 3
        assert background(run_id_var.get).result() == "scan-123"
    finally:
        run_id_var.reset(token)


def test_background_reraises():
    def boom():
        raise ValueError("no")

    fut = background(boom)
    try:
        fut.result()
    except ValueError as exc:
        assert str(exc) == "no"
    else:
        raise AssertionError("expected the error")


def test_scan_list_rereads_only_changed_files(monkeypatch):
    scan_id = create_demo_scan()["id"]
    store.list_scans()
    reads = []
    real = store.json.load
    monkeypatch.setattr(store.json, "load", lambda fh: reads.append(fh.name) or real(fh))
    assert any(s["id"] == scan_id for s in store.list_scans())
    assert reads == []
    store.delete_scan(scan_id)
    assert not any(s["id"] == scan_id for s in store.list_scans())


def test_accounts_share_connections_but_not_clients():
    """Each account gets its own clients (its own credentials) over one pool of connections per process."""
    import boto3
    from botocore.config import Config

    from exitrisk.aws_session import ClientCache

    def cache(key):
        return ClientCache(boto3.Session(aws_access_key_id=key, aws_secret_access_key="s", region_name="eu-west-1"))

    a, b = cache("A").client("ec2", "eu-west-1"), cache("B").client("sqs", "af-south-1")
    assert a is not b and a._request_signer._credentials.access_key == "A"
    assert a._endpoint.http_session is b._endpoint.http_session
    own = cache("C").client("ec2", "eu-west-1", config=Config(read_timeout=5))
    assert own._endpoint.http_session is not a._endpoint.http_session  # other settings, other pool
