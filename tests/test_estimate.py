import pytest

from exitrisk.demo import build_demo_scan
from exitrisk.estimate import (
    Questionnaire,
    count_range,
    duration_range,
    effort_range,
    money_range,
    share_range,
    size_multiplier,
)
from exitrisk.scoring import build_report


def test_size_multiplier_scaling():
    assert size_multiplier(1000) == pytest.approx(1.0)
    assert size_multiplier(4000) == pytest.approx(2.0)
    assert size_multiplier(1) == 0.25  # floor
    assert size_multiplier(10_000_000) == 8.0  # cap
    assert size_multiplier(100, count=100, typical=25) == pytest.approx(2.0)  # counts win when higher


def _est(**q):
    return build_report(build_demo_scan(), questionnaire=Questionnaire(**q))["estimate"]


def test_maturity_lowers_effort():
    good = _est(cicd="standard", iac="terraform_current")
    poor = _est(cicd="manual", iac="none")
    assert good["effort"]["total_weeks"] < poor["effort"]["total_weeks"]


def test_bigger_team_is_faster_but_not_cheaper():
    small = _est(cloud_team_size=5, app_engineers_fte=0)
    large = _est(cloud_team_size=60, app_engineers_fte=40)
    assert large["duration"]["calendar_weeks"] < small["duration"]["calendar_weeks"]
    assert large["cost"]["labour"] == small["cost"]["labour"]


def test_critical_path_floor():
    huge = _est(cloud_team_size=2000, cloud_team_allocation_pct=100, app_engineers_fte=5000)
    assert huge["duration"]["constrained_by"] == "critical path"
    assert huge["duration"]["calendar_weeks"] >= 26


def test_fx_applies_to_parallel_run_only():
    usd = _est()
    zar = _est(currency="ZAR", fx_per_usd=18, day_rate=750)
    assert zar["cost"]["parallel_run"] == pytest.approx(usd["cost"]["parallel_run"] * 18, rel=1e-3)
    assert zar["cost"]["labour"] == usd["cost"]["labour"]


def test_waves_are_contiguous():
    e = _est()
    for prev, nxt in zip(e["waves"], e["waves"][1:], strict=False):
        assert nxt["start"] == pytest.approx(prev["start"] + prev["weeks"], abs=0.2)


def test_questionnaire_validation():
    with pytest.raises(ValueError):
        Questionnaire(cicd="sometimes")
    with pytest.raises(ValueError):
        Questionnaire(cloud_team_size=0)


def test_ranges_are_rounded_outward_and_never_a_single_figure():
    assert money_range(7.44e6, 14.88e6) == "$7m to $16m"
    assert money_range(74e3, 151e3, "ZAR") == "ZAR 70k to ZAR 160k"
    assert duration_range(31.4, 55.0) == "2.5 to 5 years"
    assert duration_range(7.2, 13.1) == "6 to 15 months"
    assert duration_range(5.9, 10.4) == "5 to 11 months"  # not "3 to 12": quarters are too coarse here
    # The share agrees with the rounded money range beside it: $12m to $30m of $30.9m a year.
    assert money_range(12.1e6, 27.4e6) == "$12m to $30m" and share_range(12.1e6, 27.4e6, 30.9e6) == "35 to 100%"
    assert count_range(343, 687) == "300 to 700"
    assert effort_range(14, 30) == "14 to 30 person-months"
    assert effort_range(450, 1000) == "35 to 90 person-years"  # 37.5 to 83 years, widened to round numbers
    est = build_report(build_demo_scan(), questionnaire=Questionnaire(confirmed=True))["estimate"]
    r = est["ranges"]
    assert (
        r["cost"].count(" to ") == 1
        and r["duration"].count(" to ") == 1
        and r["effort"].endswith(("person-months", "person-years"))
    )
    lo, hi = (float(x.strip("$m")) * 1e6 for x in r["cost"].split(" to "))
    assert lo <= est["cost"]["low"] and hi >= est["cost"]["high"]


def test_datacenter_adds_hardware_facility_and_lead_time():
    huge = dict(cloud_team_size=2000, cloud_team_allocation_pct=100, app_engineers_fte=5000)
    onprem = _est(target="onprem", **huge)
    colo = _est(target="datacenter", dc_facility="colocation", **huge)
    build = _est(target="datacenter", dc_facility="build", **huge)
    assert onprem["datacenter"] is None and onprem["cost"]["hardware"] == 0
    assert colo["cost"]["hardware"] > 0 and colo["cost"]["facility"] > 0
    assert colo["cost"]["total"] > onprem["cost"]["total"]
    assert build["cost"]["facility"] > colo["cost"]["facility"]
    # The facility has to exist before workloads move: lead time sits on the critical path.
    assert colo["duration"]["critical_path_weeks"] == pytest.approx(onprem["duration"]["critical_path_weeks"] + 26)
    assert build["duration"]["calendar_weeks"] > colo["duration"]["calendar_weeks"]
    assert colo["waves"][0]["name"].startswith("Mobilise, data centre") and colo["waves"][0]["weeks"] >= 26
    assert any("Physical data centre" in a for a in colo["assumptions"])


def test_datacenter_options():
    with_dr = _est(target="datacenter", dc_facility="existing")
    no_dr = _est(target="datacenter", dc_facility="existing", dc_dr_site=False)
    assert with_dr["cost"]["facility"] == 0
    assert no_dr["cost"]["hardware"] < with_dr["cost"]["hardware"]
    # Only the data-centre target uses these answers.
    assert _est(dc_facility="build")["cost"]["facility"] == 0
    with pytest.raises(ValueError):
        Questionnaire(target="datacenter", dc_facility="cave")


def test_datacenter_reads_in_the_executive_summary():
    r = build_report(build_demo_scan(), questionnaire=Questionnaire(target="datacenter", confirmed=True))
    text = str(r["summary"]["executive"])
    assert "your own data centre" in text and "hardware" in text
