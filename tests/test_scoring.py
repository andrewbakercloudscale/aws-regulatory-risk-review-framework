import pytest

from exitrisk.demo import build_demo_scan
from exitrisk.filtering import AccountFilter
from exitrisk.scoring import build_report, rating


def _scan(costs, accounts=None):
    accounts = accounts or [{"id": "1", "name": "big-prod"}, {"id": "2", "name": "small-prod"}]
    return {
        "id": "20260101-000000-abcd",
        "accounts": accounts,
        "costs": costs,
        "period": {"start": "2026-01-01", "end": "2026-02-01", "months": 1},
        "issues": [],
    }


def test_small_high_risk_account_moves_ou_score_little():
    costs = [
        {"month": "2026-01", "account_id": "1", "service": "Amazon Elastic Kubernetes Service", "amount": 99000},
        {"month": "2026-01", "account_id": "2", "service": "Amazon DynamoDB", "amount": 1000},
    ]
    r = build_report(_scan(costs))
    small = next(a for a in r["accounts"] if a["name"] == "small-prod")
    big = next(a for a in r["accounts"] if a["name"] == "big-prod")
    assert small["score"] == 95 and big["score"] == 10
    assert small["weight"] == pytest.approx(0.01)
    # OU score = spend-weighted: 0.99*10 + 0.01*95
    assert r["summary"]["score"] == pytest.approx(10.85, abs=0.06)
    assert r["summary"]["rating"] == "Low"
    assert sum(a["contribution"] for a in r["accounts"]) == pytest.approx(r["summary"]["score"], abs=0.06)


def test_tax_and_negatives_excluded_and_unclassified_flagged():
    costs = [
        {"month": "2026-01", "account_id": "1", "service": "AWS Lambda", "amount": 100},
        {"month": "2026-01", "account_id": "1", "service": "Tax", "amount": 15},
        {"month": "2026-01", "account_id": "1", "service": "AWS Lambda", "amount": -5},
        {"month": "2026-01", "account_id": "1", "service": "AWS Transform", "amount": 100},
    ]
    r = build_report(_scan(costs, [{"id": "1", "name": "a"}]))
    assert r["summary"]["monthly_spend"] == 200
    assert r["summary"]["excluded_billing_monthly"] == 15
    assert r["accounts"][0]["score"] == pytest.approx((100 * 75 + 100 * 50) / 200)
    assert any(i["category"] == "catalog" and "AWS Transform" in i["message"] for i in r["issues"])


def test_filter_limits_scope_and_issues():
    scan = build_demo_scan()
    full = build_report(scan)
    prod = build_report(scan, AccountFilter(include="prod"))
    assert prod["summary"]["accounts_in_scope"] < full["summary"]["accounts_in_scope"]
    assert all("prod" in a["name"] for a in prod["accounts"])
    assert not any("sandbox-innovation" in i["message"] for i in prod["issues"])


def test_no_spend_gives_no_score():
    r = build_report(_scan([], [{"id": "1", "name": "empty"}]))
    assert r["summary"]["score"] is None
    assert r["summary"]["rating"] == "n/a"


@pytest.mark.parametrize(
    "score,label",
    [
        (0, "Low"),
        (24.9, "Low"),
        (25, "Moderate"),
        (54.9, "Elevated"),
        (69.9, "High"),
        (70, "Critical"),
        (100, "Critical"),
    ],
)
def test_rating_bands(score, label):
    assert rating(score) == label


def test_demo_report_is_consistent():
    r = build_report(build_demo_scan())
    assert 0 < r["summary"]["score"] < 100
    assert abs(sum(t["pct"] for t in r["tiers"]) - 100) < 0.5
    assert len(r["trend"]) == 6
    assert r["summary"]["narrative"]


def test_zero_cost_lines_are_ignored():
    costs = [
        {"month": "2026-01", "account_id": "1", "service": "AWS Lambda", "amount": 100},
        {"month": "2026-01", "account_id": "1", "service": "Some Free Service", "amount": 0.0},
    ]
    r = build_report(_scan(costs, [{"id": "1", "name": "a"}]))
    assert [s["service"] for s in r["services"]] == ["AWS Lambda"]
    assert not any(i["category"] == "catalog" for i in r["issues"])


def test_tiny_estate_has_small_landing_zone():
    costs = [{"month": "2026-01", "account_id": "1", "service": "Amazon Simple Storage Service", "amount": 60}]
    e = build_report(_scan(costs, [{"id": "1", "name": "a"}]))["estimate"]
    assert e["effort"]["landing_zone_weeks"] < 6


def test_filter_matching_nothing_explains_itself_and_has_no_estimate():
    scan = build_demo_scan()
    r = build_report(scan, AccountFilter(include="no-such-account"))
    assert r["summary"]["accounts_in_scope"] == 0
    assert r["estimate"]["empty"] is True
    assert any("No account matches the filter" in n for n in r["summary"]["coverage"])
    assert build_report(scan)["summary"]["coverage"] == []


def test_billing_lines_of_one_service_merge_and_tiers_count_accounts():
    costs = [
        {"account_id": "1", "service": s, "month": "2026-09", "amount": a}
        for s, a in (("Amazon Connect", 5000), ("Contact Lens for Amazon Connect", 3000), ("Amazon EC2", 100))
    ] + [{"account_id": "2", "service": "Amazon Elastic Compute Cloud - Compute", "month": "2026-09", "amount": 50}]
    r = build_report(_scan(costs, [{"id": "1", "name": "a-prd"}, {"id": "2", "name": "b-prd"}]))
    a1 = next(a for a in r["accounts"] if a["id"] == "1")
    assert [s["service"] for s in a1["top_lockin"]] == ["Connect"]
    connect = next(s for s in r["services"] if s["display"] == "Connect")
    assert connect["monthly_spend"] == 8000 and connect["accounts"] == 1
    assert {t["tier"]: t["accounts"] for t in r["tiers"]}[5] == 1
