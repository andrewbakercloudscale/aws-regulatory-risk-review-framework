from exitrisk.demo import build_demo_scan
from exitrisk.estimate import Questionnaire
from exitrisk.filtering import AccountFilter
from exitrisk.multiregion import MultiRegionAnswers, build_multiregion, latency_ms, load_region_data, support_fee


def _scan(costs, region_costs=None, accounts=None):
    return {
        "id": "20260101-000000-abcd",
        "accounts": accounts or [{"id": "1", "name": "a-prod"}, {"id": "2", "name": "b-prod"}],
        "costs": costs,
        "region_costs": region_costs,
        "issues": [],
    }


def test_every_catalog_service_has_region_behaviour():
    from exitrisk.catalog import load_catalog

    cfg = load_region_data()
    names = {s.service for s in load_catalog().services if not s.excluded}
    assert names <= set(cfg["services"])
    for v in cfg["services"].values():
        assert v["regional"] in (None, "global") or v["regional"] in cfg["availability"]


def test_instant_costs_more_than_three_hour_recovery():
    scan = build_demo_scan(12)
    slow = build_multiregion(scan, mq=MultiRegionAnswers(recovery="rto_3h"))["summary"]
    fast = build_multiregion(scan, mq=MultiRegionAnswers(recovery="instant"))["summary"]
    assert fast["run"]["annual_total"] > slow["run"]["annual_total"]
    assert fast["build"]["total_weeks"] > slow["build"]["total_weeks"]
    assert fast["staff"]["fte"] > slow["staff"]["fte"]
    for k in ("run_annual", "build_cost", "build_duration", "staff"):
        assert " to " in slow["ranges"][k]  # always a range, never one figure


def test_primary_region_is_where_spend_runs_and_recommendation_respects_residency():
    scan = build_demo_scan(12)
    r = build_multiregion(scan)
    assert r["summary"]["primary"] == "eu-west-2"
    assert r["summary"]["recommended"] != "eu-west-2"
    eu = build_multiregion(scan, mq=MultiRegionAnswers(residency="same_continent"))["summary"]
    assert load_region_data()["regions"][eu["recommended"]]["continent"] == "Europe"
    uk = build_multiregion(scan, mq=MultiRegionAnswers(residency="same_country"))["summary"]
    assert uk["recommended"] is None and uk["no_second_region_in_country"]


def test_account_selection_scales_the_estimate_and_accounts_sort_by_spend():
    scan = build_demo_scan(12)
    every = build_multiregion(scan)
    spends = [a["monthly_spend"] for a in every["accounts"]]
    assert spends == sorted(spends, reverse=True)
    top = [a["id"] for a in every["accounts"][:3]]
    few = build_multiregion(scan, mq=MultiRegionAnswers(accounts=top))
    assert few["summary"]["accounts_selected"] == 3
    assert few["summary"]["run"]["annual_total"] < every["summary"]["run"]["annual_total"]
    assert [a["selected"] for a in few["accounts"]][:4] == [True, True, True, False]


def test_per_account_risks_name_the_failover_gap():
    costs = [
        {"month": "2026-09", "account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "amount": 5000},
        {"month": "2026-09", "account_id": "1", "service": "Amazon DynamoDB", "amount": 2000},
        {"month": "2026-09", "account_id": "1", "service": "Amazon Redshift", "amount": 3000},
    ]
    rc = [{"account_id": "1", "service": r["service"], "region": "af-south-1", "monthly": r["amount"]} for r in costs]
    a = build_multiregion(_scan(costs, rc), mq=MultiRegionAnswers(recovery="rto_3h"))["accounts"][0]
    risks = {r["service"]: r for r in a["risks"]}
    assert risks["EC2"]["failover"] == "manual" and "Manual failover" in risks["EC2"]["note"]
    assert risks["DynamoDB"]["failover"] == "native" and risks["DynamoDB"]["severity"] == "Low"
    assert risks["Redshift"]["severity"] == "High"
    assert a["readiness"] == "High"
    instant = build_multiregion(_scan(costs, rc), mq=MultiRegionAnswers(recovery="instant"))["accounts"][0]
    assert instant["readiness"] == "Critical"


def test_dynamodb_import_quota_depends_on_the_second_region():
    costs = [{"month": "2026-09", "account_id": "1", "service": "Amazon DynamoDB", "amount": 2000}]
    rc = [{"account_id": "1", "service": "Amazon DynamoDB", "region": "af-south-1", "monthly": 2000}]

    def note(secondary):
        mr = build_multiregion(_scan(costs, rc), mq=MultiRegionAnswers(secondary=secondary))
        return mr["accounts"][0]["risks"][0]["note"]

    assert "only 1 TB" in note("eu-central-1") and "Frankfurt" in note("eu-central-1")
    assert "up to 15 TB" in note("eu-west-1")


def test_missing_service_in_the_second_region_is_flagged():
    costs = [{"month": "2026-09", "account_id": "1", "service": "Amazon Connect", "amount": 9000}]
    rc = [{"account_id": "1", "service": "Amazon Connect", "region": "eu-west-2", "monthly": 9000}]
    r = build_multiregion(_scan(costs, rc), mq=MultiRegionAnswers(secondary="eu-west-1"))
    assert r["summary"]["target"]["missing"][0]["display"] == "Connect"
    assert r["accounts"][0]["risks"][0]["severity"] == "Critical"
    assert any(f["lead"] == "Service gaps." for f in r["summary"]["executive"]["findings"])


def test_scan_without_region_data_assumes_one_region_and_says_so():
    costs = [
        {"month": "2026-09", "account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "amount": 5000}
    ]
    s = build_multiregion(_scan(costs), mq=MultiRegionAnswers(primary="eu-west-1"))["summary"]
    assert not s["has_region_data"] and s["primary"] == "eu-west-1"
    assert s["by_region"][0]["region"] == "eu-west-1"


def test_staff_and_filter():
    scan = build_demo_scan(12)
    small = build_multiregion(scan, q=Questionnaire(cloud_team_size=5))["summary"]["staff"]["fte"]
    big = build_multiregion(scan, q=Questionnaire(cloud_team_size=60))["summary"]["staff"]["fte"]
    assert big > small
    prod = build_multiregion(scan, AccountFilter(include="prod"))["summary"]
    assert prod["accounts_in_scope"] < build_multiregion(scan)["summary"]["accounts_in_scope"]


def test_latency_and_support_helpers():
    r = load_region_data()["regions"]
    assert 5 < latency_ms(r["eu-west-1"], r["eu-west-2"], r) < 25
    assert latency_ms(r["af-south-1"], r["sa-east-1"], r) > 200  # routed via Europe, not the South Atlantic
    assert support_fee(100_000, "enterprise") == 15_000
    assert support_fee(1_000_000, "enterprise") == 15_000 + 24_500 + 25_000
    assert support_fee(100_000, "none") == 0


def _notes(r):
    return " ".join(n["text"] for n in r["notes"])


def test_data_problems_become_notes_on_the_page():
    costs = [
        {"month": "2026-09", "account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "amount": 900},
        {"month": "2026-09", "account_id": "1", "service": "Some Brand New Service", "amount": 50},
    ]
    rc = [
        {"account_id": "1", "service": costs[0]["service"], "region": "xx-moon-1", "monthly": 100},
        {"account_id": "1", "service": costs[0]["service"], "region": "eu-west-1", "monthly": 800},
    ]
    r = build_multiregion(_scan(costs, rc), mq=MultiRegionAnswers(secondary="eu-west-1"))
    text = _notes(r)
    assert "xx-moon-1" in text  # a region this version does not know: said, not silently mispriced
    assert "no multi-region profile" in text
    assert "is not usable here" in text  # the chosen second region is the primary
    assert r["summary"]["primary"] == "eu-west-1"
    assert all(n["level"] in ("warning", "info") for n in r["notes"])


def test_scan_without_region_data_explains_what_it_assumed():
    costs = [{"month": "2026-09", "account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "amount": 5}]
    text = _notes(build_multiregion(_scan(costs)))
    assert "no spend-by-region data" in text and "Primary region" in text
    assert "Primary region" not in _notes(build_multiregion(_scan(costs), mq=MultiRegionAnswers(primary="eu-west-1")))


def test_old_availability_list_is_flagged():
    from datetime import date

    from exitrisk.multiregion import _availability_age_days

    assert _availability_age_days({"availability_fetched": "2026-01-01"}, date(2026, 10, 1)) == 273
    assert _availability_age_days({"availability_fetched": "not a date"}) is None


def test_notes_are_logged_once_per_scan(caplog):
    costs = [{"month": "2026-09", "account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "amount": 5}]
    scan = _scan(costs)
    scan["id"] = "20260101-000000-once"
    with caplog.at_level("INFO", logger="exitrisk.multiregion"):
        build_multiregion(scan)
        build_multiregion(scan)
    msgs = [r.getMessage() for r in caplog.records]
    assert sum("no spend-by-region data" in m for m in msgs) == 1
    assert sum(m.startswith("multi-region 20260101-000000-once: rto_3h") for m in msgs) == 2  # one summary per run


def test_no_accounts_selected_is_a_clean_empty_estimate():
    r = build_multiregion(build_demo_scan(12), mq=MultiRegionAnswers(accounts=[]))
    s = r["summary"]
    assert s["accounts_selected"] == 0 and s["run"]["annual_total"] == 0 and s["staff"]["fte"] == 0
    assert s["ranges"]["run_annual"] == "n/a" and "Pick at least one account" in s["executive"]["headline"]


def _connect_scan():
    costs = [
        {"month": "2026-09", "account_id": "1", "service": "Amazon Connect", "amount": 9000},
        {"month": "2026-09", "account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "amount": 5000},
    ]
    rc = [
        {"account_id": "1", "service": "Amazon Connect", "region": "af-south-1", "monthly": 9000},
        {
            "account_id": "1",
            "service": "Amazon Elastic Compute Cloud - Compute",
            "region": "af-south-1",
            "monthly": 5000,
        },
    ]
    return _scan(costs, rc)


def test_each_candidate_says_why_it_ranks_there():
    r = build_multiregion(_connect_scan())
    cands = {c["region"]: c for c in r["candidates"]}
    assert cands[r["summary"]["recommended"]]["why"].startswith("Best balance")
    assert "No Connect here" in cands["eu-west-1"]["why"]
    assert all(c["why"] for c in r["candidates"])
    assert any(f["lead"] == "Runners-up." for f in r["summary"]["executive"]["findings"])


def test_user_corrections_change_parity_and_cost():
    base = build_multiregion(_connect_scan(), mq=MultiRegionAnswers(secondary="eu-west-1"))
    assert base["summary"]["target"]["missing"]
    fixed = build_multiregion(
        _connect_scan(), mq=MultiRegionAnswers(secondary="eu-west-1", assume_available=["Amazon Connect@eu-west-1"])
    )
    t = fixed["summary"]["target"]
    assert not t["missing"] and t["parity_pct"] == 100
    assert fixed["accounts"][0]["risks"][0]["availability"] == "available"
    # The correction is for that region only: elsewhere the AWS list still decides.
    sydney = next(c for c in fixed["candidates"] if c["region"] == "ap-southeast-2")
    assert sydney["parity_pct"] == base_sydney(base)["parity_pct"]

    skip = build_multiregion(
        _connect_scan(), mq=MultiRegionAnswers(secondary="eu-west-1", not_needed=["Amazon Connect"])
    )
    s = skip["summary"]
    assert s["not_needed"] == [{"service": "Amazon Connect", "display": "Connect", "monthly_spend": 9000}]
    assert not s["target"]["missing"]
    assert s["run"]["infra_monthly"] < base["summary"]["run"]["infra_monthly"]
    assert all(r["service"] != "Connect" for a in skip["accounts"] for r in a["risks"])


def base_sydney(r):
    return next(c for c in r["candidates"] if c["region"] == "ap-southeast-2")


def test_regulation_follows_the_primary_and_the_border():
    za = build_multiregion(_connect_scan(), mq=MultiRegionAnswers(secondary="eu-central-1"))["summary"]
    names = [x["name"] for x in za["regulation"]]
    assert names[0].startswith("POPIA section 72") and any("Prudential Authority" in n for n in names)
    assert "Germany" in za["regulation"][0]["text"]
    unregulated = build_multiregion(
        _connect_scan(), q=Questionnaire(regulated=False), mq=MultiRegionAnswers(secondary="eu-central-1")
    )["summary"]
    assert [x["name"] for x in unregulated["regulation"]] == names[:1]
    # Inside one country there is no cross-border transfer to flag.
    costs = [
        {"month": "2026-09", "account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "amount": 5000}
    ]
    rc = [
        {"account_id": "1", "service": "Amazon Elastic Compute Cloud - Compute", "region": "us-east-1", "monthly": 5000}
    ]
    us = build_multiregion(
        _scan(costs, rc), q=Questionnaire(regulated=False), mq=MultiRegionAnswers(secondary="us-west-2")
    )
    assert us["summary"]["regulation"] == []


def test_known_errors_in_the_aws_list_are_corrected():
    cfg = load_region_data()
    fixes = {(c["service"], c["region"]): c for c in cfg["availability_corrections"]}
    assert fixes[("Amazon Lex", "eu-west-1")]["available"] and fixes[("Amazon Lex", "eu-west-1")]["evidence"]
    assert "eu-west-1" in cfg["availability"]["Amazon Lex"]
    # Connect really is not in Ireland: no correction, still missing.
    assert "eu-west-1" not in cfg["availability"]["Amazon Connect"]
    r = build_multiregion(_connect_scan())
    assert any("Amazon Lex available in eu-west-1" in a for a in r["assumptions"])


def test_correction_can_remove_a_region():
    from exitrisk.multiregion import _apply_corrections

    cfg = {
        "availability": {"X": {"a", "b"}},
        "availability_corrections": [
            {"service": "X", "region": "b", "available": False},
            {"service": "Y", "region": "c", "available": True},
        ],
    }
    _apply_corrections(cfg)
    assert cfg["availability"] == {"X": {"a"}, "Y": {"c"}}
