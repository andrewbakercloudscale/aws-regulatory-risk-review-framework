import pytest

from exitrisk.demo import build_demo_scan
from exitrisk.estimate import Questionnaire
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
    # The by-accounts view counts each account once: (10 + 95) / 2.
    assert r["summary"]["score_by_accounts"] == pytest.approx(52.5)
    assert r["summary"]["rating_by_accounts"] == "Elevated"


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
        (24.4, "Low"),
        (24.5, "Moderate"),  # displayed as 25, so rated as 25: the label always matches the number shown
        (25, "Moderate"),
        (54.4, "Elevated"),
        (69.4, "High"),
        (69.5, "Critical"),
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


def test_one_dominant_account_shows_in_spend_view_not_account_view():
    # One very large Connect account and nine small portable ones.
    costs = [{"account_id": "big", "service": "Amazon Connect", "month": "2026-09", "amount": 100000}] + [
        {"account_id": str(i), "service": "Amazon Elastic Compute Cloud - Compute", "month": "2026-09", "amount": 2000}
        for i in range(9)
    ]
    accounts = [{"id": "big", "name": "big-prd"}] + [{"id": str(i), "name": f"app{i}-prd"} for i in range(9)]
    scan = _scan(costs, accounts)
    s = build_report(scan)["summary"]
    assert s["weighting"] == "spend" and s["score"] == s["score_by_spend"]
    assert s["rating_by_spend"] == "Critical" and s["rating_by_accounts"] == "Low"
    assert s["score_by_accounts"] == pytest.approx((95 + 9 * 10) / 10)
    balanced = build_report(scan, weighting="balanced")["summary"]
    assert s["score_by_spend"] > balanced["score"] > s["score_by_accounts"]
    assert balanced["score_by_spend"] == s["score_by_spend"]
    assert s["portable_accounts"] == 9 and s["high_risk_accounts"] == 1 and s["accounts_rated"] == 10
    crit = next(b for b in s["accounts_by_rating"] if b["rating"] == "Critical")
    assert crit["accounts"] == 1 and crit["pct_accounts"] == 10.0 and crit["pct_spend"] > 80
    assert "counting every account equally" in s["narrative"][0]


def test_unknown_weighting_is_rejected():
    with pytest.raises(ValueError):
        build_report(_scan([]), weighting="bogus")


def test_executive_summary_flags_concentration_and_default_answers():
    costs = [{"account_id": "big", "service": "Amazon Connect", "month": "2026-09", "amount": 100000}] + [
        {"account_id": str(i), "service": "Amazon Elastic Compute Cloud - Compute", "month": "2026-09", "amount": 2000}
        for i in range(9)
    ]
    accounts = [{"id": "big", "name": "big-prd"}] + [{"id": str(i), "name": f"app{i}-prd"} for i in range(9)]
    x = build_report(_scan(costs, accounts))["summary"]["executive"]
    assert "concentrated" in x["context"] and "1 account (" in x["context"] and "carries most of it" in x["context"]
    assert "9 of 10 accounts (90%) are broadly portable" in x["context"]
    assert any("big-prd" in a for a in x["actions"])
    assert "default answers" in x["actions"][0]  # answering the questions comes first
    assert x["confidence"] in {"Medium", "Low"} and x["exit"].startswith("Exit window: roughly ")
    assert "of a year's AWS spend" in x["exit"] and all("account(s)" not in f for f in x["findings"])
    # Every reason confidence is below High comes with the step that removes it.
    steps = {st["key"]: st for st in x["confidence_steps"]}
    assert len(steps) == len(x["confidence_reasons"])
    assert steps["defaults"]["action"] == "model" and steps["deep"]["action"] == "deep"
    assert "Deep scan" in steps["deep"]["fix"]


def test_default_answers_keep_cost_and_time_out_of_the_headline():
    costs = [{"account_id": "1", "service": "Amazon Connect", "month": "2026-09", "amount": 50000}]
    scan = _scan(costs, [{"id": "1", "name": "a-prd"}])
    r = build_report(scan)
    x = r["summary"]["executive"]
    assert r["estimate"]["provisional"] and x["provisional"]
    assert "$" not in x["headline"] and "answer the delivery questions" in x["headline"]
    assert all(f["provisional"] for f in x["exit_facts"][:3])
    r = build_report(scan, questionnaire=Questionnaire(confirmed=True))
    x = r["summary"]["executive"]
    assert not r["estimate"]["provisional"] and not x["provisional"]
    assert "years" in x["headline"] or "months" in x["headline"]
    assert "$" in x["headline"] and "default" not in x["actions"][0]


def test_executive_summary_without_spend():
    x = build_report(_scan([]))["summary"]["executive"]
    assert x["confidence"] == "Low" and not x["findings"]


def test_growth_by_product_type():
    costs = [
        {"account_id": "1", "service": "Amazon Connect", "month": "2026-07", "amount": 1000},
        {"account_id": "1", "service": "Amazon Connect", "month": "2026-09", "amount": 1500},
        {"account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "month": "2026-07", "amount": 2000},
        {"account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "month": "2026-09", "amount": 1500},
    ]
    r = build_report(_scan(costs, [{"id": "1", "name": "a-prod"}]))
    g = r["growth"]
    assert (g["first_month"], g["last_month"]) == ("2026-07", "2026-09")
    assert g["total"]["pct"] == 0.0 and g["lockin"]["pct"] == 50.0
    cats = {c["category"]: c for c in g["by_category"]}
    assert cats["Business apps"]["change"] == 500 and cats["Compute"]["pct"] == -25.0
    assert cats["Business apps"]["lockin_pct"] == 100.0
    assert any("lock-in is growing faster than the estate" in f for f in r["summary"]["executive"]["findings"])
    assert r["estimate"]["cost"]["pct_of_annual_spend"] > 0


def test_growth_names_the_services_and_products_behind_it():
    mkt = "AWS Marketplace (third-party)"
    costs = [
        {"account_id": "1", "service": "Amazon Connect", "month": "2026-07", "amount": 1000},
        {"account_id": "1", "service": "Amazon Connect", "month": "2026-09", "amount": 1200},
        {"account_id": "1", "service": "Amazon Redshift", "month": "2026-07", "amount": 500},
        {"account_id": "1", "service": "Amazon Redshift", "month": "2026-09", "amount": 500},
        {"account_id": "1", "service": mkt, "product": "Acme SaaS", "month": "2026-07", "amount": 10},
        {"account_id": "1", "service": mkt, "product": "Acme SaaS", "month": "2026-09", "amount": 900},
        {"account_id": "1", "service": "Amazon Bedrock", "month": "2026-09", "amount": 50},
        {
            "account_id": "1",
            "service": "Amazon Bedrock",
            "product": "Claude Sonnet 4.6 (Amazon Bedrock Edition)",
            "month": "2026-09",
            "amount": 300,
        },
    ]
    r = build_report(_scan(costs, [{"id": "1", "name": "a-prod"}]))
    cats = {c["category"]: c for c in r["growth"]["by_category"]}
    assert cats["Business apps"]["services"] == ["Connect"]
    assert cats["Business apps"]["drivers"][0]["display"] == "Connect"
    assert cats["Business apps"]["drivers"][0]["change"] == 200
    third = cats["Third-party software"]["drivers"][0]
    assert third["products"] == ["Acme SaaS"] and third["change"] == 890
    svc = {s["service"]: s for s in r["services"]}
    assert svc["Amazon Connect"]["change_pct"] == 20.0
    assert svc["Amazon Bedrock"]["products"] == [
        {"name": "Claude Sonnet 4.6", "monthly_spend": 150.0, "accounts": 1, "change": 300.0}
    ]
    findings = r["summary"]["executive"]["findings"]
    assert any("Connect $" in f and "a year (1 account)" in f for f in findings)
    assert any("Biggest monthly rises: Acme SaaS via Marketplace +$890" in f for f in findings)


def test_growth_needs_two_months():
    costs = [{"account_id": "1", "service": "Amazon Connect", "month": "2026-09", "amount": 100}]
    g = build_report(_scan(costs, [{"id": "1", "name": "a-prod"}]))["growth"]
    assert g["total"] is None and g["by_category"] == []


def test_accounts_rank_by_spend_at_risk():
    costs = [
        # Big but portable: 100k x 10 = 10k at risk.
        {"month": "2026-01", "account_id": "1", "service": "Amazon Elastic Kubernetes Service", "amount": 100000},
        # Smaller but locked in: 20k x 95 = 19k at risk.
        {"month": "2026-01", "account_id": "2", "service": "Amazon DynamoDB", "amount": 20000},
    ]
    r = build_report(_scan(costs))
    assert [a["name"] for a in r["accounts"]] == ["small-prod", "big-prod"]
    assert r["accounts"][0]["spend_at_risk"] == 19000 and r["accounts"][0]["rank"] == 1
    assert r["accounts"][1]["spend_at_risk"] == 10000


def test_aws_spend_is_quoted_in_usd_whatever_the_labour_currency():
    q = Questionnaire(currency="ZAR", fx_per_usd=18.5)
    x = build_report(build_demo_scan(), questionnaire=q)["summary"]["executive"]
    text = " ".join(x["findings"])
    assert "ZAR" not in text.split("Exit")[0]
    assert "$" in text


def test_one_account_reads_as_one_account():
    costs = [{"month": "2026-01", "account_id": "1", "service": "Amazon Simple Storage Service", "amount": 5000}]
    s = build_report(_scan(costs, [{"id": "1", "name": "a"}]))["summary"]
    text = " ".join([*s["narrative"], *s["executive"]["findings"]])
    assert "1 of 1 account is portable" in text
    assert "1 accounts" not in text
    assert "The 0 High" not in text


def test_empty_estimate_has_no_ranges():
    r = build_report(build_demo_scan(), AccountFilter(include="no-such-account"))
    assert set(r["estimate"]["ranges"].values()) == {None}


def test_ai_agents_cut_effort_by_each_services_rating():
    costs = [
        {"month": "2026-01", "account_id": "1", "service": "AWS Lambda", "amount": 4000},  # high
        {"month": "2026-01", "account_id": "1", "service": "Amazon DynamoDB", "amount": 4000},  # low
        {"month": "2026-01", "account_id": "1", "service": "Amazon Elastic File System", "amount": 4000},  # none
    ]
    scan = _scan(costs, [{"id": "1", "name": "a"}])
    without = build_report(scan, questionnaire=Questionnaire())["accounts"][0]["effort_by_tier"]
    r = build_report(scan, questionnaire=Questionnaire(ai_agents=True))
    with_ai = r["accounts"][0]["effort_by_tier"]
    assert with_ai[4] == pytest.approx(without[4] * 0.5, abs=0.01)  # Lambda
    assert with_ai[5] == pytest.approx(without[5] * 0.9, abs=0.01)  # DynamoDB: redesign and a data move
    assert with_ai[1] == pytest.approx(without[1], abs=0.01)  # EFS: a data move an agent cannot shorten
    assert r["accounts"][0]["agentic_saved_weeks"] > 0
    assert r["estimate"]["effort"]["agentic_saved_weeks"] > 0
    assert any(a.startswith("AI coding agents") for a in r["estimate"]["assumptions"])
    # The score does not change: agents shorten the work, not the lock-in.
    assert r["summary"]["score"] == build_report(scan)["summary"]["score"]


def test_products_left_out_drop_from_score_and_estimate_and_are_reported():
    costs = [
        {"month": "2026-01", "account_id": "1", "service": "AWS Lambda", "amount": 100},
        {"month": "2026-01", "account_id": "1", "service": "AWS Marketplace (third-party)", "amount": 300},
        {"month": "2026-01", "account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "amount": 100},
    ]
    scan = _scan(costs, [{"id": "1", "name": "a"}])
    r = build_report(scan, questionnaire=Questionnaire(exclude_services=["AWS Marketplace (third-party)"]))
    s = r["summary"]
    assert s["monthly_spend"] == 200
    assert s["score"] == pytest.approx((100 * 75 + 100 * 10) / 200)
    assert s["excluded_services"] == [
        {"service": "AWS Marketplace (third-party)", "display": "Marketplace (3rd party)", "monthly_spend": 300}
    ]
    assert s["excluded_services_monthly"] == 300
    assert any("Left out" in n and "Marketplace" in n for n in s["coverage"])
    assert all(x["service"] != "AWS Marketplace (third-party)" for x in r["services"])
    # The console still offers every product, with the left-out one ticked.
    choices = {c["service"]: c["excluded"] for c in r["product_choices"]}
    assert choices == {
        "AWS Marketplace (third-party)": True,
        "AWS Lambda": False,
        "Amazon Elastic Compute Cloud - Compute": False,
    }
    # Nothing left out means nothing to report.
    assert not build_report(scan)["summary"]["excluded_services"]


def test_commitments_written_off_is_a_key_figure():
    from datetime import date, timedelta

    scan = build_demo_scan()
    end = (date.today() + timedelta(days=5 * 365)).isoformat()
    scan["commitments"] = [
        {"kind": "reservation", "type": "", "service": "Amazon Redshift", "term": "3yr", "end": end, "monthly": 50_000}
    ]
    x = build_report(scan, questionnaire=Questionnaire(confirmed=True))["summary"]["executive"]
    f = next(f for f in x["exit_facts"] if f["label"] == "Commitments written off")
    assert "$" in f["value"] and "Savings Plans and reservations" in f["note"]
    assert any("write-off" in t for t in x["findings"])


def test_headline_follows_the_rounded_rating():
    from exitrisk.scoring import _headline

    s = {"score_by_spend": 54.6, "rating_by_spend": rating(54.6)}
    assert s["rating_by_spend"] == "High" and "re-engineering programme" in _headline(s, {"empty": True}, False)
    s = {"score_by_spend": 39.6, "rating_by_spend": rating(39.6)}
    assert "needs significant re-engineering" in _headline(s, {"empty": True}, False)


def test_confidence_drops_for_partial_scan_and_partial_deep_scan():
    scan = build_demo_scan()
    q = Questionnaire(confirmed=True)
    scan["mode"] = "live"
    r = build_report(scan, questionnaire=q)
    keys = {x["key"] for x in r["summary"]["executive"]["confidence_steps"]}
    assert "partial_deep" in keys and r["summary"]["deep_scan_pct"] < 90
    scan["status"] = "partial"
    r = build_report(scan, questionnaire=q)
    assert r["summary"]["coverage"][0].startswith("Partial scan")
    assert r["summary"]["executive"]["confidence"] != "High"


def test_leaving_a_service_out_is_not_an_access_gap():
    scan = build_demo_scan()
    scan["mode"] = "live"
    r = build_report(scan, questionnaire=Questionnaire(confirmed=True, exclude_services=["AWS Lambda"]))
    assert r["summary"]["coverage"] and r["summary"]["coverage_gaps"] == 0
    assert "coverage" not in {x["key"] for x in r["summary"]["executive"]["confidence_steps"]}


def test_narrative_holds_back_cost_on_default_answers():
    r = build_report(build_demo_scan())
    assert not any("would take roughly" in line for line in r["summary"]["narrative"])
