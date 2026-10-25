"""Resilience view: criticality from tags or names, data held, concentration, stressed exit."""

import pytest

from exitrisk.demo import build_demo_scan
from exitrisk.estimate import Questionnaire
from exitrisk.resilience import classify, usage_region
from exitrisk.scoring import build_report


@pytest.mark.parametrize(
    "tags,critical,channel",
    [
        ({"Criticality": "Tier 1"}, True, ""),
        ({"business_criticality ": "Mission-Critical", "Channel": "Cards"}, True, "Cards"),
        ({"service-tier": "T1"}, True, ""),
        ({"Criticality": "Tier 3", "channel": "Mobile app"}, False, "Mobile app"),
        ({}, False, ""),
    ],
)
def test_classify_reads_criticality_and_channel_tags(tags, critical, channel):
    got = classify({"name": "x", "tags": tags}, [])
    assert got[0] is critical and got[2] == channel
    assert got[1] == ("tag" if critical else "")


def test_classify_falls_back_to_name_patterns():
    assert classify({"name": "Cards-Prod", "tags": {}}, ["cards"]) == (True, "name", "")


@pytest.mark.parametrize(
    "usage,region",
    [
        ("AFS1-TimedStorage-ByteHrs", "af-south-1"),
        ("EU-TimedStorage-ByteHrs", "eu-west-1"),
        ("TimedStorage-ByteHrs", "us-east-1"),
        ("EBS:SnapshotUsage", "us-east-1"),
        ("XYZ9-TimedStorage-ByteHrs", "XYZ9"),
    ],
)
def test_usage_region(usage, region):
    assert usage_region(usage) == region


@pytest.fixture(scope="module")
def demo():
    return build_demo_scan(6)


def test_demo_resilience_finds_shared_region_and_stuck_spend(demo):
    r = build_report(demo)
    res = r["resilience"]
    assert res["criticality"]["critical_accounts"] == 5 and res["criticality"]["by_tag"] == 5
    c = res["concentration"]
    assert c["basis"] == "critical" and c["region"] == "eu-west-2" and c["pct"] == pytest.approx(90, abs=0.5)
    assert {"Card payments", "Mobile app"} <= set(c["no_anti_affinity"][0]["channels"])
    buckets = {b["key"]: b["pct"] for b in res["stressed_exit"]["buckets"]}
    assert abs(sum(buckets.values()) - 100) < 0.5 and buckets["none"] > 10
    assert res["stressed_exit"]["accounts"][0]["name"] == "cards-processing-prod"
    flagged = {a["name"] for a in r["accounts"] if a["critical"]}
    assert "cards-processing-prod" in flagged and "sandbox-innovation" not in flagged
    # One action reaches the executive summary; losing a region belongs to the Multi-Region Report.
    ex = r["summary"]["executive"]
    assert not any("no anti-affinity" in f for f in ex["findings"])
    assert any(a.startswith("Pre-build a stressed-exit fallback") for a in ex["actions"])


def test_data_held_and_migration_links(demo):
    d = build_report(demo)["resilience"]["data"]
    assert d["available"] and d["move_tb"] == pytest.approx(d["live_tb"] + d["archive_tb"], abs=0.2)
    assert d["dynamodb_largest_account"] == "cards-processing-prod"
    # Today's links come from port-hours: two 10G ports billed all month in London.
    t = d["links_today"]
    assert t["count"] == 2 and t["total_gbps"] == 20 and t["ports"][0]["region"] == "eu-west-2"
    m = d["migration_links"]
    assert m["region"] == "eu-west-2" and m["port_hour_usd"] == 2.25
    cheap, medium, urgent = m["options"]
    assert [o["links"] for o in m["options"]] == [1, 2, 4]
    # TB -> bits / (10 Gbps x 50%) -> days; more links, proportionally faster.
    assert cheap["days"] == pytest.approx(d["move_tb"] * 1024 * 8 / 5 / 86400, rel=0.01)
    assert urgent["days"] == pytest.approx(cheap["days"] / 4, rel=0.01)
    # Ports are paid for the copy plus a month; data out costs the same for every option.
    assert cheap["port_cost"] == round(2.25 * 730 * cheap["months_billed"])
    assert cheap["transfer_cost"] == urgent["transfer_cost"] > 0
    assert cheap["total_cost"] <= medium["total_cost"] <= urgent["total_cost"]
    assert cheap["circuit_cost"] == 0
    with_carrier = build_report(demo, questionnaire=Questionnaire(migration_circuit_monthly=3000))
    o = with_carrier["resilience"]["data"]["migration_links"]["options"][2]
    assert o["circuit_cost"] == 4 * 3000 * o["months_billed"]


def test_direct_connect_ports_are_counted_from_port_hours():
    from exitrisk.collectors.cost import parse_port
    from exitrisk.resilience import _links_today

    assert parse_port("AFS1-TECT1-PortUsage:10G") == {
        "location": "TECT1",
        "kind": "dedicated",
        "gbps": 10.0,
        "ports": 1,
    }
    assert parse_port("EUW2-EqLD5-HCPortUsage:500M")["gbps"] == 0.5
    assert parse_port("AFS1-TECT1-FlatRatePortUsage:10G-Pair-Tier1")["ports"] == 2
    assert parse_port("AFS1-TECT1-DataXfer-Out:dc.3") is None
    dx = {
        "month": "2026-09",
        "hours": 720,
        "rows": [
            {
                "account_id": "1",
                "usage_type": "AFS1-TECT1-PortUsage:10G",
                "unit": "Hrs",
                "quantity": 2880,
                "cost": 6480,
            },
            {"account_id": "1", "usage_type": "AFS1-TECT1-DataXfer-Out", "unit": "GB", "quantity": 2048, "cost": 225},
        ],
    }
    t = _links_today(dx, {"1": {"name": "network"}})
    assert t["count"] == 4 and t["total_gbps"] == 40
    assert t["ports"][0]["location"].startswith("Teraco CT1") and t["ports"][0]["accounts"] == ["network"]
    assert t["out_tb_month"] == 2.0
    assert _links_today(None, {})["available"] is False
    # Links billed to a network account outside the report still count; its data out does not.
    t = _links_today(dx, {"2": {"name": "app-prod"}})
    assert t["count"] == 4 and t["ports"][0]["accounts"] == ["1"] and t["out_tb_month"] == 0


def test_without_tags_or_storage_it_degrades(demo):
    scan = {**demo, "accounts": [{k: v for k, v in a.items() if k != "tags"} for a in demo["accounts"]]}
    scan.pop("storage")
    r = build_report(scan)
    res = r["resilience"]
    assert not res["criticality"]["tags_read"] and res["criticality"]["critical_accounts"] == 0
    assert res["concentration"]["basis"] == "all"
    assert not res["data"]["available"]
    assert any(a.startswith("Tag critical accounts") for a in r["summary"]["executive"]["actions"])
    named = build_report(scan, questionnaire=Questionnaire(critical_accounts="cards"))["resilience"]
    assert named["criticality"]["by_name"] == 2  # cards-processing-prod and -uat
