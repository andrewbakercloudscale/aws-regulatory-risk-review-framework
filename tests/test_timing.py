from datetime import date

import pytest

from exitrisk.estimate import Questionnaire
from exitrisk.timing import build_timing

TODAY = date(2026, 10, 1)
# An exit of 12 to 24 months from today.
EST = {"duration": {"low_months": 12, "high_months": 24}, "ranges": {"duration": "1–2 years"}}


def _c(months_left, monthly, kind="savings_plan", term="3yr"):
    end = date.fromordinal(TODAY.toordinal() + round(months_left * 30.44)).isoformat()
    return {"kind": kind, "type": "ComputeSavingsPlans", "service": "", "term": term, "end": end, "monthly": monthly}


@pytest.mark.parametrize("deadline,status", [(30, "fits"), (18, "at_risk"), (6, "misses")])
def test_deadline_status(deadline, status):
    t = build_timing({}, EST, Questionnaire(exit_deadline_months=deadline, confirmed=True), today=TODAY)
    assert t["deadline"]["status"] == status
    assert t["deadline"]["short_months"] == pytest.approx(max(0, 24 - deadline), abs=0.1)
    assert not t["provisional"]


def test_no_deadline_and_old_scan():
    t = build_timing({}, EST, Questionnaire(), today=TODAY)
    assert t["deadline"] == {"set": False} and t["edp"] == {"set": False}
    assert t["commitments"]["available"] is False and t["provisional"]


def test_stranded_commitments_run_past_the_exit():
    scan = {"commitments": [_c(6, 1000), _c(30, 10000), _c(-1, 5000)]}
    c = build_timing(scan, EST, Questionnaire(), today=TODAY)["commitments"]
    assert c["count"] == 2  # the expired one is dropped
    assert c["monthly"] == 11000
    # 30 months left: 6 to 18 months still owed after a 24 or 12 month exit.
    assert c["stranded"] == [pytest.approx(60000, rel=0.01), pytest.approx(180000, rel=0.01)]
    assert c["stranded_range"] and c["monthly_past_exit"] == 10000
    assert c["pct_runs_off_before_exit"] == pytest.approx(9.1, abs=0.1)
    assert [r["quarter"] for r in c["runoff"]] == ["2027 Q2", "2029 Q2"]


def test_commitments_inside_the_window_strand_nothing():
    c = build_timing({"commitments": [_c(6, 1000)]}, EST, Questionnaire(), today=TODAY)["commitments"]
    assert c["stranded"] == [0, 0] and c["stranded_range"] is None
    assert c["stressed_owed"] == pytest.approx(6000, rel=0.01)
    assert c["buy_by"] == {}  # any new term bought now outlasts a 12-month exit


def test_edp_shortfall_when_it_outlasts_the_exit():
    q = Questionnaire(edp_end="2029-09", edp_annual_commit=1_200_000)
    e = build_timing({}, EST, q, today=TODAY)["edp"]
    assert e["set"] and not e["ends_before_exit"]
    lo, hi = e["shortfall"]
    assert lo == pytest.approx(100_000 * 12, rel=0.03) and hi == pytest.approx(100_000 * 24, rel=0.03)


def test_empty_estimate_has_no_exit_dates():
    t = build_timing({"commitments": []}, {"empty": True}, Questionnaire(exit_deadline_months=12), today=TODAY)
    assert t["exit_end"] is None and t["deadline"]["status"] == "unknown"
    assert t["commitments"] == {"available": True, "empty": True, "undated": 0, "undated_monthly": 0}


def test_undated_commitments_are_counted_not_dropped():
    undated = {**_c(12, 700), "end": ""}
    c = build_timing({"commitments": [_c(30, 1000), undated]}, EST, Questionnaire(), today=TODAY)["commitments"]
    assert c["count"] == 1 and c["undated"] == 1 and c["undated_monthly"] == 700
    only = build_timing({"commitments": [undated]}, EST, Questionnaire(), today=TODAY)["commitments"]
    assert only["empty"] and only["undated"] == 1
