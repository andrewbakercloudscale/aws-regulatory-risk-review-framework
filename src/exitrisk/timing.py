"""Timing an exit: the deadline you would have, and the AWS commitments still to run.

Two questions a board asks once it has an exit window: *would we make it in time?* (a supplier
notice period or a regulator's expectation, answered on the page) and *what would we still owe
AWS?* Savings Plans and reservations come from Cost Explorer with their end dates; an enterprise
discount agreement (EDP or PPA) is not visible through any API, so its end month and yearly
commitment are answered on the page.

Commitments are amortised: ``monthly`` already spreads any upfront fee over the term, so what is
left is ``monthly`` times the months remaining. Commitments are bought in one account and shared
across the organisation, so they are organisation-wide, not filtered by OU. None of this changes
the exit estimate, which excludes commitments; see docs/METHODOLOGY.md, "Timing".
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import date

from .estimate import Questionnaire, _round_step, _short, duration_bounds, money_range

DAYS_PER_MONTH = 30.44
# A commitment counts as "running past the exit" when it ends after the fastest exit would finish.
MATERIAL_STRANDED = 1000.0  # USD: below this the finding is noise


def owed_range(lo: float, hi: float) -> str:
    """ "$1m to $2m"; "up to $2m" when the slow end owes next to nothing."""
    if lo >= MATERIAL_STRANDED:
        return money_range(lo, hi)
    step = _round_step(hi)
    return f"up to ${_short(math.ceil(hi / step) * step)}"


def _date(text: str) -> date | None:
    try:
        return date.fromisoformat(text[:10])
    except (TypeError, ValueError):
        return None


def _add_months(d: date, months: float) -> date:
    return date.fromordinal(d.toordinal() + round(months * DAYS_PER_MONTH))


def _months(a: date, b: date) -> float:
    """Months from a to b, never negative."""
    return max(0.0, (b - a).days / DAYS_PER_MONTH)


def _quarter(d: date) -> str:
    return f"{d.year} Q{(d.month - 1) // 3 + 1}"


def _service(c: dict) -> str:
    if c["kind"] == "savings_plan":
        return {
            "compute": "Compute Savings Plan",
            "ec2instance": "EC2 Instance Savings Plan",
            "sagemaker": "SageMaker Savings Plan",
            "database": "Database Savings Plan",
        }.get(c["type"].lower().replace("savingsplans", "").replace("savingsplan", "").replace(" ", ""), c["type"])
    short = (
        c["service"]
        .replace("Amazon Elastic Compute Cloud - Compute", "EC2")
        .replace("Amazon Relational Database Service", "RDS")
        .replace("Amazon ", "")
    )
    return f"{short} reservation"


def _month_starts(first: date, last: date) -> list[date]:
    out, d = [], first.replace(day=1)
    while d <= last:
        out.append(d)
        d = date(d.year + (d.month == 12), d.month % 12 + 1, 1)
    return out


def _by_month(active: list[dict], today: date) -> list[dict]:
    """What each month bills in commitments, and what would be written off if the exit finished then.

    Each commitment counts its amortised monthly fee for the days of the month it still runs.
    ``written_off`` for a month is everything billed after that month ends: finish the exit at the end
    of it, and that is what is paid for capacity no longer used.
    """
    ends = [date.fromisoformat(c["end"]) for c in active]
    months = _month_starts(today, max(ends))
    rows = []
    for m in months:
        nxt = date(m.year + (m.month == 12), m.month % 12 + 1, 1)
        sp = ri = 0.0
        for c, end in zip(active, ends, strict=True):
            days = (min(nxt, end) - max(m, today)).days
            if days > 0:
                amount = c["monthly"] * days / DAYS_PER_MONTH
                if c["kind"] == "savings_plan":
                    sp += amount
                else:
                    ri += amount
        rows.append({"month": m.isoformat()[:7], "savings_plans": round(sp, 2), "reservations": round(ri, 2)})
    left = 0.0
    for r in reversed(rows):
        r["written_off"] = round(left)
        left += r["savings_plans"] + r["reservations"]
    return rows


def _commitments(
    rows: list[dict] | None, today: date, exit_end: tuple[date, date] | None, unavailable: str | None = None
) -> dict:
    if rows is None:
        if unavailable:  # the scan asked and AWS refused: say why, not "run a new scan"
            return {"available": False, "reason": f"Savings Plans and reservations could not be read: {unavailable}"}
        return {"available": False, "reason": "This scan predates commitment tracking; run a new scan."}
    active = []
    # Billed this month but with no end date from AWS: counted and shown, never silently dropped.
    undated = [c for c in rows if c.get("monthly", 0) > 0 and not _date(c.get("end", ""))]
    for c in rows:
        end = _date(c.get("end", ""))
        if not end or end <= today or c.get("monthly", 0) <= 0:
            continue
        left = _months(today, end)
        # Stranded = what is still owed once the exit has finished: least for the slowest exit.
        stranded = (
            (c["monthly"] * _months(exit_end[1], end), c["monthly"] * _months(exit_end[0], end)) if exit_end else None
        )
        active.append(
            {
                "kind": c["kind"],
                "name": _service(c),
                "term": c.get("term", ""),
                "payment": c.get("payment", ""),
                "end": end.isoformat(),
                "months_left": round(left, 1),
                "monthly": c["monthly"],
                "remaining": round(c["monthly"] * left),
                "utilization_pct": c.get("utilization_pct"),
                "stranded": [round(x) for x in stranded] if stranded else None,
            }
        )
    gaps = {"undated": len(undated), "undated_monthly": round(sum(c["monthly"] for c in undated), 2)}
    if not active:
        return {"available": True, "empty": True, **gaps}
    active.sort(key=lambda c: -c["remaining"])
    monthly = sum(c["monthly"] for c in active)
    remaining = sum(c["remaining"] for c in active)
    runoff: dict[str, float] = defaultdict(float)
    for c in active:
        runoff[_quarter(date.fromisoformat(c["end"]))] += c["monthly"]
    out = {
        "available": True,
        "empty": False,
        # Leaving in a hurry: everything still to run is owed.
        "stressed_owed": round(remaining),
        "stressed_range": money_range(remaining * 0.95, remaining * 1.05),
        "count": len(active),
        "savings_plans": sum(1 for c in active if c["kind"] == "savings_plan"),
        "reservations": sum(1 for c in active if c["kind"] == "reservation"),
        "monthly": round(monthly, 2),
        "remaining": round(remaining),
        "last_end": max(c["end"] for c in active),
        "runoff": [{"quarter": q, "monthly": round(m, 2)} for q, m in sorted(runoff.items())],
        "by_month": _by_month(active, today),
        "rows": active[:15],
        **gaps,
    }
    if exit_end:
        lo = sum(c["stranded"][0] for c in active)
        hi = sum(c["stranded"][1] for c in active)
        past = [c for c in active if date.fromisoformat(c["end"]) > exit_end[0]]
        out.update(
            {
                # The last day a commitment of each term can start and still end before the fastest exit.
                "buy_by": {
                    term: _add_months(exit_end[0], -months).isoformat()
                    for term, months in (("1yr", 12), ("3yr", 36))
                    if _add_months(exit_end[0], -months) > today
                },
                "stranded": [round(lo), round(hi)],
                "stranded_range": owed_range(lo, hi) if hi >= MATERIAL_STRANDED else None,
                "monthly_past_exit": round(sum(c["monthly"] for c in past), 2),
                "pct_runs_off_before_exit": round(100 * (1 - sum(c["monthly"] for c in past) / monthly), 1),
            }
        )
    return out


def _billed(rows: list[dict] | None, today: date) -> list[tuple[date, float]]:
    """(end, monthly) of each commitment still running: what keeps being billed after an exit."""
    out = []
    for c in rows or []:
        end = _date(c.get("end", ""))
        if end and end > today and c.get("monthly", 0) > 0:
            out.append((end, c["monthly"]))
    return out


def _edp_shortfall(commit_monthly: float, start: date, end: date, billed: list[tuple[date, float]]) -> float:
    """What an EDP still demands from ``start`` to ``end`` once workloads have left AWS. Savings Plan and
    reservation fees keep being billed after the exit and count towards the commitment, so each stretch
    owes only the part they do not cover; counting both in full would charge the same dollars twice."""
    cuts = sorted({start, end, *(e for e, _ in billed if start < e < end)})
    owed = 0.0
    for a, b in zip(cuts, cuts[1:], strict=False):
        running = sum(m for e, m in billed if e > a)
        owed += max(0.0, commit_monthly - running) * _months(a, b)
    return owed


def _edp(q: Questionnaire, today: date, exit_end: tuple[date, date] | None, billed=()) -> dict:
    if not (q.edp_end and q.edp_annual_commit > 0):
        return {"set": False}
    y, m = map(int, q.edp_end.split("-"))
    end = date(y + (m == 12), m % 12 + 1, 1)  # the agreement runs to the end of that month
    out = {
        "set": True,
        "end_month": q.edp_end,
        "annual_commit": q.edp_annual_commit,
        "months_left": round(_months(today, end), 1),
        "remaining": round(q.edp_annual_commit / 12 * _months(today, end)),
    }
    if exit_end:
        # If spend stops when the exit finishes, the rest of the commitment is a shortfall to pay,
        # less the commitment fees still billed (already counted as written off).
        lo = _edp_shortfall(q.edp_annual_commit / 12, exit_end[1], end, list(billed)) if exit_end[1] < end else 0.0
        hi = _edp_shortfall(q.edp_annual_commit / 12, exit_end[0], end, list(billed)) if exit_end[0] < end else 0.0
        out["shortfall"] = [round(lo), round(hi)]
        out["shortfall_range"] = owed_range(lo, hi) if hi >= MATERIAL_STRANDED else None
        out["ends_before_exit"] = end <= exit_end[0]
    return out


def _deadline(q: Questionnaire, lo: float | None, hi: float | None) -> dict:
    if not q.exit_deadline_months:
        return {"set": False}
    if lo is None:
        return {"set": True, "months": q.exit_deadline_months, "status": "unknown"}
    # Judge against the range the reader sees ("12 to 21 months"), or 12.3 months would "not fit" 12.
    lo, hi = duration_bounds(lo, hi)
    d = q.exit_deadline_months
    status = "fits" if hi <= d else "at_risk" if lo <= d else "misses"
    return {
        "set": True,
        "months": d,
        "status": status,
        "label": {"fits": "Fits", "at_risk": "At risk", "misses": "Does not fit"}[status],
        "short_months": round(max(0.0, hi - d), 1),
    }


def build_timing(scan: dict, est: dict, q: Questionnaire, today: date | None = None) -> dict:
    today = today or date.today()
    dur = est.get("duration") or {}
    lo, hi = (None, None) if est.get("empty") else (dur.get("low_months"), dur.get("high_months"))
    exit_end = (_add_months(today, lo), _add_months(today, hi)) if lo is not None else None
    return {
        "as_of": today.isoformat(),
        "duration_range": None if est.get("empty") else (est.get("ranges") or {}).get("duration"),
        "exit_end": [d.isoformat() for d in exit_end] if exit_end else None,
        "provisional": not q.confirmed,
        "deadline": _deadline(q, lo, hi),
        "commitments": _commitments(
            scan.get("commitments"), today, exit_end, (scan.get("unavailable") or {}).get("commitments")
        ),
        "edp": _edp(q, today, exit_end, _billed(scan.get("commitments"), today)),
    }
