"""Lost network: a scan or AI run pauses and carries on by itself once the connection is back."""

import socket
import urllib.error

from botocore.exceptions import ClientError, EndpointConnectionError, ReadTimeoutError
from test_scanner import _org

from exitrisk import network, scanner, store
from exitrisk.ai import providers
from exitrisk.scanner import ScanJob, ScanParams


def _offline_for(monkeypatch, polls: int) -> dict:
    """Offline for ``polls`` probes, then back. The waits are instant."""
    left = {"n": polls}

    def online():
        if left["n"] > 0:
            left["n"] -= 1
            return False
        return True

    monkeypatch.setattr(network, "online", online)
    monkeypatch.setattr(network, "POLL_SECONDS", 0)
    return left


def test_network_errors_are_told_apart_from_aws_answers():
    assert network.is_network_error(EndpointConnectionError(endpoint_url="https://sts.amazonaws.com"))
    assert network.is_network_error(ReadTimeoutError(endpoint_url="https://x"))
    assert network.is_network_error(urllib.error.URLError(socket.gaierror(8, "nodename nor servname")))
    wrapped = RuntimeError("could not reach the provider")
    wrapped.__cause__ = ConnectionResetError()
    assert network.is_network_error(wrapped)
    assert not network.is_network_error(ClientError({"Error": {"Code": "AccessDenied"}}, "X"))
    assert not network.is_network_error(urllib.error.HTTPError("https://x", 500, "boom", {}, None))
    assert not network.is_network_error(ValueError("bad"))


def test_wait_until_online_says_it_is_paused_and_can_be_stopped(monkeypatch):
    _offline_for(monkeypatch, 3)
    said = []
    assert network.wait_until_online(said.append) >= 0
    assert said and "paused" in network.paused_message(said[0])
    _offline_for(monkeypatch, 10**6)
    try:
        network.wait_until_online(stop=lambda: True)
        raise AssertionError("not stopped")
    except network.Cancelled:
        pass


def test_a_deep_scan_pauses_offline_and_reads_the_account_again(monkeypatch):
    """The laptop shut mid-scan: every call failed. Once back online the account is read again in
    full, and nothing is recorded as failed for the time it was offline."""
    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})
    monkeypatch.setattr(scanner, "member_session", lambda *a: object())
    state = _offline_for(monkeypatch, 0)
    calls = {"n": 0}
    paused_seen = []
    job = ScanJob(id=store.new_scan_id(), params=ScanParams(inventory=True, role_name="R"))

    def read(*_a, **_k):
        calls["n"] += 1
        if calls["n"] == 1:  # the network goes as the first account is read
            state["n"] = 3
            raise EndpointConnectionError(endpoint_url="https://ec2.eu-west-1.amazonaws.com")
        paused_seen.append(job.paused)
        return {"resources": {}}, []

    monkeypatch.setattr(scanner.inventory, "inventory_account", read)
    doc = scanner.run_scan(job)
    assert set(doc["inventory"]) == {"222222222222", "333333333333"}
    assert not any(i["error_code"] in network.NETWORK_CODES for i in doc["issues"])
    assert doc["status"] == "complete" and job.net_epoch == 1 and not job.paused


def test_a_collector_that_records_network_failures_is_read_again(monkeypatch):
    """Collectors turn each failed call into an issue rather than raising: those count too."""
    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})
    monkeypatch.setattr(scanner, "member_session", lambda *a: object())
    state = _offline_for(monkeypatch, 0)
    calls = {"n": 0}

    def read(_s, account_id, *_a, **_k):
        calls["n"] += 1
        if calls["n"] == 1:
            state["n"] = 2
            return {"resources": {}}, [
                scanner.Issue(
                    "warning",
                    "inventory",
                    "ec2 in eu-west-1: no route",
                    account_id=account_id,
                    error_code="EndpointConnectionError",
                )
            ]
        return {"resources": {"ok": 1}}, []

    monkeypatch.setattr(scanner.inventory, "inventory_account", read)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams(inventory=True, role_name="R")))
    assert calls["n"] == 3
    assert all(v["resources"] == {"ok": 1} for v in doc["inventory"].values())
    assert not [i for i in doc["issues"] if i["error_code"] == "EndpointConnectionError"]


def test_a_timeout_while_online_is_kept_as_an_issue(monkeypatch):
    """A slow API is not a lost network: no pause, no second read."""
    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})
    monkeypatch.setattr(scanner, "member_session", lambda *a: object())
    calls = {"n": 0}

    def read(_s, account_id, *_a, **_k):
        calls["n"] += 1
        return {"resources": {}}, [
            scanner.Issue("warning", "inventory", "x: slow", account_id=account_id, error_code="ReadTimeoutError")
        ]

    monkeypatch.setattr(scanner.inventory, "inventory_account", read)
    job = ScanJob(id=store.new_scan_id(), params=ScanParams(inventory=True, role_name="R"))
    doc = scanner.run_scan(job)
    assert calls["n"] == 2 and job.net_epoch == 0
    assert sum(i["error_code"] == "ReadTimeoutError" for i in doc["issues"]) == 2


def test_cost_explorer_offline_waits_instead_of_failing_the_scan(monkeypatch):
    _org(monkeypatch)
    monkeypatch.setattr(scanner.organizations, "fetch_account_tags", lambda s, ids: {})
    state = _offline_for(monkeypatch, 0)
    real = scanner.cost.fetch_costs
    calls = {"n": 0}

    def costs(*a):
        calls["n"] += 1
        if calls["n"] == 1:
            state["n"] = 2
            raise EndpointConnectionError(endpoint_url="https://ce.us-east-1.amazonaws.com")
        return real(*a)

    monkeypatch.setattr(scanner.cost, "fetch_costs", costs)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    assert doc["status"] == "complete" and doc["costs"] and calls["n"] == 2


def test_stop_works_while_paused(monkeypatch):
    _offline_for(monkeypatch, 10**6)
    job = ScanJob(id=store.new_scan_id(), params=ScanParams())
    job.cancel()
    try:
        job.wait_for_network()
        raise AssertionError("not stopped")
    except scanner.ScanCancelled:
        pass
    assert not job.paused


def test_an_ai_call_waits_for_the_network_then_asks_again(monkeypatch):
    _offline_for(monkeypatch, 0)
    c = object.__new__(providers.Client)
    c.modes, c.stop, said = [], None, []
    c.on_offline = said.append
    calls = {"n": 0}

    def call(*_a):
        calls["n"] += 1
        if calls["n"] == 1:
            try:
                raise urllib.error.URLError(OSError(51, "Network is unreachable"))
            except urllib.error.URLError as exc:
                raise providers.AIError("Could not reach the provider") from exc
        return "ok"

    state = {"n": 2}

    def online():
        if state["n"]:
            state["n"] -= 1
            return False
        return True

    monkeypatch.setattr(network, "online", online)
    c._call = call
    assert c.complete("s", "u") == "ok" and calls["n"] == 2
    assert said and said[-1] is None  # the message is put back once online
