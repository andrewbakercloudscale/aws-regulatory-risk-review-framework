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
    # One finding and one action reach the executive summary.
    ex = r["summary"]["executive"]
    assert any("critical accounts" in f and "no anti-affinity" in f for f in ex["findings"])
    assert any(a.startswith("Pre-build a stressed-exit fallback") for a in ex["actions"])


def test_data_held_and_transfer_time(demo):
    d = build_report(demo, questionnaire=Questionnaire(transfer_gbps=10))["resilience"]["data"]
    assert d["available"] and d["move_tb"] == pytest.approx(d["live_tb"] + d["archive_tb"], abs=0.2)
    # TB -> bits / (10 Gbps x 50%) -> days
    assert d["transfer_days"] == pytest.approx(d["move_tb"] * 1024 * 8 / 5 / 86400, rel=0.01)
    faster = build_report(demo, questionnaire=Questionnaire(transfer_gbps=100))["resilience"]["data"]
    assert faster["transfer_days"] == pytest.approx(d["transfer_days"] / 10, rel=0.02)
    assert faster["fits_credit_window"]
    assert d["dynamodb_largest_account"] == "cards-processing-prod"


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
