"""Account owners and executives read from tags, and the "who owns the risk" rollup."""

from __future__ import annotations

from exitrisk.demo import build_demo_scan
from exitrisk.resilience import owner_of
from exitrisk.scoring import build_report


def test_owner_tags_in_any_style():
    acct = {"tags": {"Account_Holder_/_Product_Head": " Jane Doe ", "Linked_Executive": "Ann Exec"}}
    assert owner_of(acct) == ("Jane Doe", "Ann Exec")
    assert owner_of({"tags": {"owner": "x", "Account Holder": "y"}}) == ("x", "")
    assert owner_of({"tags": {"Team": "Payments"}}) == ("Payments", "")
    assert owner_of({}) == ("", "")


def test_rollup_by_executive_adds_up():
    r = build_report(build_demo_scan(12))
    o = r["resilience"]["owners"]
    rows = [a for a in r["accounts"] if a["monthly_spend"] > 0]
    tagged = [a for a in rows if a["owner"] or a["executive"]]
    assert o["tagged_accounts"] == len(tagged) and 0 < len(tagged) < len(rows)
    assert sum(g["accounts"] for g in o["by_executive"]) == len(tagged)
    assert abs(sum(g["spend_at_risk"] for g in o["by_executive"]) - sum(a["spend_at_risk"] for a in tagged)) < 1
    assert abs(o["untagged_monthly"] - sum(a["monthly_spend"] for a in rows if a not in tagged)) < 1
    risk = [g["spend_at_risk"] for g in o["by_executive"]]
    assert risk == sorted(risk, reverse=True)
    assert not o["single_owner"]


def test_single_owner_is_reported_once():
    scan = build_demo_scan(3)
    for a in scan["accounts"]:
        a["tags"] = {"Owner": "Pat Owner", "Executive": "Pat Exec"}
    o = build_report(scan)["resilience"]["owners"]
    assert o["single_owner"] == "Pat Owner" and o["single_executive"] == "Pat Exec"
    assert len(o["by_executive"]) == 1


def test_same_person_typed_differently_is_one_group():
    scan = build_demo_scan(3)
    for i, a in enumerate(scan["accounts"]):
        a["tags"] = {"Executive": "Pat  Exec" if i % 2 else "pat exec"}
    o = build_report(scan)["resilience"]["owners"]
    assert len(o["by_executive"]) == 1
