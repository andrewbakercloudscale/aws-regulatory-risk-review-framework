"""Every finance figure in the report agrees with the others it can be derived from.

The page shows the same money several ways (by service, account, tier, product type, month, as a
range and in the executive text); these tests pin that they add up, with and without exclusions
and with a large team (short exit window).
"""

import re

import pytest

from exitrisk.demo import build_demo_scan
from exitrisk.estimate import COST_RANGE, DURATION_RANGE, WEEKS_PER_MONTH, Questionnaire
from exitrisk.scoring import build_report

CASES = {
    "defaults": {},
    "answered, big team": {"confirmed": True, "cloud_team_size": 40, "app_engineers_fte": 108},
    "exclusions": {"exclude_services": ["Amazon Redshift", "Amazon DynamoDB", "AWS Lambda"]},
}
MULT = {"bn": 1e9, "m": 1e6, "k": 1e3, "": 1.0}


def close(a: float, b: float, rel: float = 0.005, abs_: float = 2.0) -> bool:
    return abs(a - b) <= max(abs_, rel * max(abs(a), abs(b)))


def money(text: str) -> list[float]:
    return [float(n.replace(",", "")) * MULT[u] for n, u in re.findall(r"\$([\d.,]+)(bn|m|k)?", text)]


def nums(text: str) -> list[float]:
    return [float(n.replace(",", "")) for n in re.findall(r"\d[\d,]*\.?\d*", text)]


def tier(row: dict, t: int) -> float:
    return row["tier_spend"].get(t, row["tier_spend"].get(str(t), 0.0))


@pytest.fixture(scope="module", params=list(CASES))
def report(request):
    return build_report(build_demo_scan(months=12), None, Questionnaire(**CASES[request.param]))


def test_spend_adds_up_by_service_account_and_tier(report):
    s, svcs, accts = report["summary"], report["services"], report["accounts"]
    m = s["monthly_spend"]
    assert close(s["annual_spend"], 12 * m)
    assert close(sum(x["monthly_spend"] for x in svcs), m)
    assert close(sum(a["monthly_spend"] for a in accts), m)
    high = sum(x["monthly_spend"] for x in svcs if x["tier"] >= 4)
    assert close(s["high_risk_monthly"], high)
    assert abs(s["high_risk_pct"] - 100 * high / m) < 0.6
    for a in accts:
        assert close(sum(a["tier_spend"].values()), a["monthly_spend"])
        if a["monthly_spend"]:
            assert abs(a["high_risk_pct"] - 100 * (tier(a, 4) + tier(a, 5)) / a["monthly_spend"]) < 0.6
    bands = s["accounts_by_rating"]
    assert abs(sum(b["pct_spend"] for b in bands) - 100) < 1
    risky = [b for b in bands if b["rating"] in ("High", "Critical")]
    assert sum(b["accounts"] for b in risky) == s["high_risk_accounts"]
    assert abs(sum(b["pct_spend"] for b in risky) - s["high_risk_accounts_spend_pct"]) < 0.6


def test_trend_growth_and_product_types_agree(report):
    trend, g, svcs = report["trend"], report["growth"], report["services"]
    m = report["summary"]["monthly_spend"]
    assert close(sum(sum(x["tier_spend"].values()) for x in trend) / len(trend), m, rel=0.01)
    assert close(g["total"]["first"], sum(trend[0]["tier_spend"].values()))
    assert close(g["total"]["last"], sum(trend[-1]["tier_spend"].values()))
    assert close(g["lockin"]["last"], tier(trend[-1], 4) + tier(trend[-1], 5))
    cats = g["by_category"]
    assert close(sum(c["first"] for c in cats), g["total"]["first"])
    assert close(sum(c["last"] for c in cats), g["total"]["last"])
    for c in cats:
        members = [x for x in svcs if x["category"] == c["category"]]
        assert close(c["change"], c["last"] - c["first"])
        assert close(sum(x["first"] for x in members), c["first"])
        assert close(sum(x["last"] for x in members), c["last"])
        if c["first"] > 0:
            assert abs(c["pct"] - 100 * c["change"] / c["first"]) < 0.1


def test_estimate_ranges_contain_the_model_and_agree_with_each_other(report):
    e, s = report["estimate"], report["summary"]
    c, ef, d, rg = e["cost"], e["effort"], e["duration"], e["ranges"]
    assert close(c["total"], c["labour"] + c["parallel_run"] + c["hardware"] + c["facility"])
    lo, hi = money(rg["cost"])
    assert lo <= c["total"] * COST_RANGE[0] + 1 and hi >= c["total"] * COST_RANGE[1] - 1
    # The share of annual spend is taken from the rounded cost range, so the two never disagree.
    annual = s["annual_spend"] * e["inputs"]["fx_per_usd"]
    plo, phi = nums(rg["pct_of_annual_spend"])
    assert plo <= 100 * lo / annual and phi >= 100 * hi / annual
    assert close(ef["person_months"], ef["total_weeks"] / WEEKS_PER_MONTH)
    assert close(
        ef["total_weeks"],
        ef["delivery_weeks"] + ef["landing_zone_weeks"] + ef["pmo_weeks"] + ef["contingency_weeks"],
    )
    elo, ehi = nums(rg["effort"])
    k = 12 if "years" in rg["effort"] else 1
    assert elo * k <= ef["person_months"] * COST_RANGE[0] + 0.5 and ehi * k >= ef["person_months"] * COST_RANGE[1] - 0.5
    dlo, dhi = nums(rg["duration"])
    k = 12 if "years" in rg["duration"] else 1
    assert dlo * k <= d["calendar_months"] * DURATION_RANGE[0] and dhi * k >= d["calendar_months"] * DURATION_RANGE[1]
    assert report["timing"]["duration_range"] == rg["duration"]
    last = e["waves"][-1]
    assert abs(last["start"] + last["weeks"] - d["calendar_weeks"]) <= 1.1


def test_executive_text_quotes_the_figures(report):
    s, g = report["summary"], report["growth"]
    high = [x for x in report["services"] if x["tier"] >= 4 and x["monthly_spend"] >= 1]
    seen = 0
    for f in s["executive"]["findings"]:
        if m := re.match(r"Spend grew (\d+)%", f):
            assert abs(int(m.group(1)) - g["total"]["pct"]) < 1
            seen += 1
        if m := re.match(r"(\d+)% of spend \((\$[\d.]+[mk]?) a year\) runs on (\d+) bespoke", f):
            assert abs(int(m.group(1)) - s["high_risk_pct"]) < 1 and int(m.group(3)) == len(high)
            assert abs(money(m.group(2))[0] - 12 * s["high_risk_monthly"]) <= 0.05 * 12 * s["high_risk_monthly"]
            seen += 1
        if m := re.match(r"(\d+) of (\d+) accounts are portable.*The (\d+) High or Critical accounts hold (\d+)%", f):
            assert [int(x) for x in m.groups()[:3]] == [
                s["portable_accounts"],
                s["accounts_rated"],
                s["high_risk_accounts"],
            ]
            assert abs(int(m.group(4)) - s["high_risk_accounts_spend_pct"]) < 1
            seen += 1
    assert seen >= 2


def test_commitments_add_up(report):
    cm = report["timing"]["commitments"]
    if not cm.get("available") or cm.get("empty"):
        pytest.skip("no commitments in this scan")
    assert close(sum(x["monthly"] for x in cm["runoff"]) + cm.get("undated_monthly", 0), cm["monthly"])
    lo, hi = money(cm["stressed_range"])
    assert lo <= cm["stressed_owed"] <= hi
