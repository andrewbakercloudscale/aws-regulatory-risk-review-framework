"""The Outage Risk Report's views for hundreds of accounts: coverage, service reviews, spend against risk."""

import json
import re
import time
from importlib import resources

import pytest
import yaml

from exitrisk.collectors import outage as collector
from exitrisk.collectors import outage_services as services
from exitrisk.demo import build_demo_scan
from exitrisk.outage import build_outage, catalog
from exitrisk.outage_views import HEAT_ACCOUNTS, TOP_RISKS, service_of, services_catalog


@pytest.fixture(scope="module")
def scan():
    return build_demo_scan(3)


@pytest.fixture(scope="module")
def report(scan):
    return build_outage(scan)


def _scan_of(accounts):
    """A minimal scan: (name, spend, rows, checks)."""
    return {
        "id": "t",
        "accounts": [
            {"id": f"{i:012d}", "name": n, "status": "ACTIVE", "ou_path": ""} for i, (n, *_) in enumerate(accounts)
        ],
        "costs": [
            {"month": "2026-10", "account_id": f"{i:012d}", "service": "Amazon MQ", "amount": s}
            for i, (_, s, *_) in enumerate(accounts)
            if s
        ],
        "outage": {
            "accounts": {
                f"{i:012d}": {"rows": rows, "checks": checks, "regions": ["eu-west-1"]}
                for i, (_, _, rows, checks) in enumerate(accounts)
            }
        },
    }


def test_every_rule_the_collector_emits_is_in_the_catalog():
    """A rule missing from data/outage.yaml is dropped by the report in silence."""
    code = "".join(
        resources.files("exitrisk").joinpath(f"collectors/{f}").read_text(encoding="utf-8")
        for f in ("outage.py", "outage_services.py")
    )
    emitted = set(re.findall(r'ctx\.add\(\s*"(\w+)"', code))
    known = {r["id"] for r in catalog()["rules"]}
    assert emitted and emitted <= known, emitted - known


def test_every_service_rule_exists_and_each_level_is_defined():
    cat = services_catalog()
    known = {r["id"] for r in catalog()["rules"]}
    for s in cat["services"]:
        assert set(s.get("rules") or []) <= known, s["id"]
        assert s["level"] in cat["levels"]
        assert s.get("not_seen"), f"{s['id']} must say what it cannot see"


def test_every_finding_rule_belongs_to_a_service():
    cat = services_catalog()
    mapped = {r for s in cat["services"] for r in s.get("rules") or []}
    # These name their service in the resource.
    assert {r["id"] for r in catalog()["rules"]} - mapped <= {
        "no_alarm",
        "limit_product",
        "limit_account",
        "limit_region_mismatch",
    }


@pytest.mark.parametrize(
    ("rule", "res", "want"),
    [
        ("msk_disk", "c", "msk"),
        ("no_alarm", "rds: db1", "rds"),
        ("limit_product", "rds: DB instances", "rds"),
        ("limit_account", "IAM roles", "iam"),
        ("limit_account", "Route 53 hosted zones", "route53"),
    ],
)
def test_a_finding_maps_to_its_service(rule, res, want):
    from exitrisk.outage_views import _service_maps

    by_rule, by_quota, _ = _service_maps(services_catalog())
    assert service_of(rule, res, by_rule, by_quota) == want


def test_coverage_shows_what_is_billed_and_not_covered(report):
    c = report["coverage"]
    names = {r["name"] for r in c["not_covered"]}
    assert "AWS Backup" in names  # billed in the demo, no checks
    assert sum(x["share"] for x in c["levels"]) == pytest.approx(100, abs=0.5)
    assert all(r["level"] == "none" for r in c["not_covered"])


def test_a_billed_service_nobody_knows_is_not_covered():
    s = _scan_of([("a-prod", 100.0, [], {})])
    s["costs"].append(
        {"month": "2026-10", "account_id": "000000000000", "service": "Amazon Brand New", "amount": 900.0}
    )
    c = build_outage(s)["coverage"]
    assert c["not_covered"][0] == {
        "name": "Amazon Brand New",
        "monthly": 900.0,
        "level": "none",
        "service": "",
        "label": "",
    }


def test_a_review_leads_with_its_verdict_and_says_what_it_cannot_see(report):
    rds = next(x for x in report["services"] if x["id"] == "rds")
    assert rds["verdict"] and rds["resource_rows"] and rds["actions"]
    assert any("Terraform" in x for x in rds["not_seen"])
    assert rds["resource_rows"][0]["facts"]["Class"]
    tones = [x["tone"] for x in report["services"]]
    assert tones[0] == "critical"


def test_a_check_not_read_is_never_a_clear_verdict():
    down = {"mq": {"status": "unknown", "note": "AccessDenied in eu-west-1"}}
    r = build_outage(_scan_of([("a-prod", 100.0, [], down)]))
    mq = next(x for x in r["services"] if x["id"] == "mq")
    assert mq["tone"] == "unknown"
    assert "Not read in 1 account" in mq["verdict"]


def test_an_account_that_could_not_be_read_is_not_rated_low():
    down = {"fixed": {"status": "unknown", "note": "ExpiredToken"}}
    ok = {"fixed": {"status": "pass", "note": ""}}
    r = build_outage(_scan_of([("big-prod", 1000.0, [], down), ("small-prod", 10.0, [], ok)]))
    assert r["accounts"][0]["name"] == "big-prod"
    assert r["accounts"][0]["rating"] == "Not measured"
    assert r["summary"]["accounts_blind"] == 1
    assert next(x for x in r["heatmap"]["rows"] if x["rating"] == "Not measured")["cells"][2]["accounts"] == 1


def test_a_check_read_in_part_counts_as_not_measured():
    part = {"fixed": {"status": "pass", "note": "not measured in part: ExpiredToken in eu-west-1"}}
    r = build_outage(_scan_of([("a-prod", 10.0, [], part)]))
    assert r["accounts"][0]["not_measured"] == ["fixed"]
    assert r["summary"]["accounts_full"] == 0
    assert r["accounts"][0]["rating"] != "Not measured"


def test_top_risks_collapse_by_account_and_rank_production_then_severity(scan):
    r = build_outage(scan)
    top = r["top_risks"]
    assert 0 < len(top) <= TOP_RISKS
    assert len({(x["rule"], x["account_id"]) for x in top}) == len(top)
    prod = [x["production"] for x in top]
    assert prod == sorted(prod, reverse=True)
    assert all(x["fix"] and x["start_by"] for x in top)


def test_top_risks_prefer_the_account_with_more_spend():
    row = {"rule": "mq_single", "res": "b", "region": "eu-west-1"}
    r = build_outage(_scan_of([("cheap-prod", 50.0, [row], {}), ("large-prod", 500000.0, [row], {})]))
    assert r["top_risks"][0]["account"] == "large-prod"


def test_exposure_is_score_times_spend_and_unknown_spend_is_shown_apart():
    row = {"rule": "mq_single", "res": "b", "region": "eu-west-1"}
    r = build_outage(_scan_of([("a-prod", 2000.0, [row], {}), ("b-prod", 0, [row], {})]))
    a = next(x for x in r["accounts"] if x["name"] == "a-prod")
    assert a["exposure"] == pytest.approx(a["score"] / 100 * 2000, abs=0.01)
    assert r["spend"]["unknown"] == 1
    cells = {c["band"]: c["accounts"] for row in r["heatmap"]["rows"] for c in row["cells"] if c["accounts"]}
    assert cells == {"US$1k to 10k": 1, "Spend unknown": 1}


def test_account_service_heat_keeps_critical_accounts_with_no_spend():
    row = {"rule": "msk_offline", "res": "c", "region": "eu-west-1", "used": 1, "unit": "partitions"}
    many = [
        (f"a{i}-prod", 1000.0 + i, [{"rule": "mq_single", "res": "m", "region": "eu-west-1"}], {})
        for i in range(HEAT_ACCOUNTS + 5)
    ]
    r = build_outage(_scan_of([*many, ("hidden-prod", 0, [row], {})]))
    assert "hidden-prod" in {x["name"] for x in r["account_service"]["rows"]}


def test_the_scale_of_300_accounts_stays_quick(scan):
    """342 accounts: the build is what a user waits for on every change of an answer."""
    src = list(scan["outage"]["accounts"].items())
    accounts, read, costs = [], {}, []
    for i in range(342):
        sid, raw = src[i % len(src)]
        aid = f"{i:012d}"
        accounts.append({"id": aid, "name": f"acct-{i}-prod", "status": "ACTIVE", "ou_path": ""})
        read[aid] = raw
        costs.append({"month": "2026-10", "account_id": aid, "service": "Amazon MQ", "amount": 100.0 + i})
    t = time.perf_counter()
    r = build_outage({"id": "s", "accounts": accounts, "costs": costs, "outage": {"accounts": read}})
    assert time.perf_counter() - t < 5
    assert len(json.dumps(r)) < 12_000_000
    assert len(r["accounts"]) == 342


@pytest.mark.parametrize(
    ("text", "memory", "want"),
    [
        ("500", None, 500),
        ("LEAST({DBInstanceClassMemory/9531392},5000)", 16 * 1024**3, 1802),
        ("{log(DBInstanceClassMemory/8187281408)*1000}", 16 * 1024**3, None),
        ("rubbish(", 1, None),
        (None, 1, None),
    ],
)
def test_max_connections(text, memory, want):
    got = services.max_connections(text, memory)
    assert (round(got) if got else got) == want


def test_msk_settings_read_the_properties():
    class Client:
        def describe_configuration_revision(self, Arn, Revision):  # noqa: N803
            return {"ServerProperties": b"unclean.leader.election.enable=true\nmin.insync.replicas = 2\n"}

    got = services.msk_settings(Client(), {"ConfigurationArn": "a", "ConfigurationRevision": 1})
    assert got == {"unclean.leader.election.enable": "true", "min.insync.replicas": "2"}
    assert services.msk_settings(Client(), {}) is None


def test_a_dropped_network_is_not_a_service_missing_from_the_region(monkeypatch):
    from botocore.exceptions import EndpointConnectionError

    from exitrisk.collectors import assurance

    exc = EndpointConnectionError(endpoint_url="https://kafka.af-south-1.amazonaws.com/")
    monkeypatch.setattr(assurance, "_network_up", lambda region: False)
    assert not assurance._not_here(exc, "EndpointConnectionError", "af-south-1")
    monkeypatch.setattr(assurance, "_network_up", lambda region: True)
    assert assurance._not_here(exc, "EndpointConnectionError", "af-south-1")


def test_a_saved_scan_is_compact_and_changes_its_stamp():
    from exitrisk import store

    store.save_scan({"id": "20260101-000000-abcd", "accounts": []})
    assert "\n" not in store._path("20260101-000000-abcd").read_text()
    assert store.scan_stamp("20260101-000000-abcd")[1] > 0


def test_yaml_catalog_loads_with_unique_ids():
    cat = yaml.safe_load(resources.files("exitrisk").joinpath("data/outage_services.yaml").read_text())
    ids = [s["id"] for s in cat["services"]]
    assert len(ids) == len(set(ids))
    assert collector.METRICS  # the reviews added theirs


def test_progress_is_saved_with_the_accounts_read_so_far():
    from exitrisk import store
    from exitrisk.scanner import ScanJob, ScanParams, _save_progress, _with_step

    job = ScanJob(id="20260102-000000-abcd", params=ScanParams(profile="p"))
    assert _save_progress(job) == 0  # nothing to keep yet
    job.data = {"accounts": [{"id": "1", "name": "a"}], "assurance": {"catalog_version": "x"}}
    job.step = ("assurance", {"1": {"rows": []}})
    assert _with_step(job)["assurance"] == {"catalog_version": "x", "accounts": {"1": {"rows": []}}}
    assert _save_progress(job) == 1
    saved = store.load_scan(job.id)
    assert saved["status"] == "interrupted"
    assert saved["assurance"]["accounts"]["1"] == {"rows": []}
    job.step = ("inventory", {"1": {"services": []}})
    assert _with_step(job)["inventory"] == {"1": {"services": []}}


def test_a_failed_save_of_progress_does_not_stop_the_scan(monkeypatch):
    from exitrisk import store
    from exitrisk.scanner import ScanJob, ScanParams, _save_progress

    def full(_):
        raise OSError("No space left on device")

    monkeypatch.setattr(store, "save_scan", full)
    job = ScanJob(id="20260102-000000-abce", params=ScanParams(profile="p"), data={"accounts": [{"id": "1"}]})
    assert _save_progress(job) == 0


def test_a_revoked_sign_in_waits_for_a_new_token(monkeypatch):
    from exitrisk import scanner, sso

    tokens = iter(["old", "old", "new"])
    monkeypatch.setattr(sso, "load_token", lambda name: next(tokens))
    monkeypatch.setattr(scanner, "SIGN_IN_POLL_SECONDS", 0)
    job = scanner.ScanJob(id="20260102-000000-abcf", params=scanner.ScanParams(profile="p"))
    assert job.wait_for_sign_in("s", rejected="old") is True
