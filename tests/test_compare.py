"""Comparing two scans: same answers for both, so every difference comes from the estate."""

from __future__ import annotations

import copy

from exitrisk.compare import compare_scans
from exitrisk.demo import build_demo_scan


def _pair():
    before = build_demo_scan(6)
    after = copy.deepcopy(before)
    after["id"] = "20990101-000000-zzzz"
    return before, after


def test_identical_scans_show_no_change():
    before, after = _pair()
    c = compare_scans(before, after)
    assert c["headline"]["score"]["change"] == 0
    assert c["headline"]["monthly_spend"]["change"] == 0
    assert not c["accounts"]["added"] and not c["accounts"]["removed"] and not c["accounts"]["movers"]
    assert c["services"] == [] and c["same_period"]
    assert "unchanged" in c["summary"][0] and "same months" in c["summary"][-1]


def test_added_removed_and_grown_accounts():
    before, after = _pair()
    gone = after["accounts"].pop(0)
    big = after["accounts"][0]["id"]
    for r in after["costs"]:
        if r["account_id"] == big and r["service"] == "Amazon DynamoDB":
            r["amount"] *= 3
    c = compare_scans(before, after)
    a = c["accounts"]
    assert a["removed_count"] == 1 and a["removed"][0]["name"] == gone["name"] and a["added_count"] == 0
    assert a["movers"][0]["id"] == big and a["movers"][0]["spend_at_risk"]["change"] > 0
    ddb = next(s for s in c["services"] if s["service"] == "DynamoDB")
    assert ddb["change"] > 0
    assert c["headline"]["high_risk_monthly"]["change"] > 0
    assert any("1 account removed" in t for t in c["summary"])
    tiers = sum(t["change"] for t in c["tiers"])
    assert abs(tiers - c["headline"]["monthly_spend"]["change"]) < 1


def test_account_with_a_new_id_pairs_by_name():
    before, after = _pair()
    old = after["accounts"][1]["id"]
    after["accounts"][1]["id"] = "999999999999"
    for r in after["costs"]:
        if r["account_id"] == old:
            r["account_id"] = "999999999999"
    c = compare_scans(before, after)
    assert c["accounts"]["added_count"] == 0 and c["accounts"]["removed_count"] == 0
