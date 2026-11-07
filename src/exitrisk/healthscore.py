"""Health Score: one number out of 100 per account, with a red, amber or green rating.

Seven parts, each worth a share of the 100. Every finding in a part costs points by severity, and a part
loses half of what is left for each 35 points against it, so a few issues cost a lot and the hundredth
costs little: the score separates a healthy account from an unhealthy one rather than counting rows.
Many alike findings of one rule (forty old instances) count as one issue that grows with the log of
the count. A fault live now overrides the number: critical is red, high is at best amber.

What could not be read is never taken as healthy. A check refused or failed in a region is a blind spot:
it costs Visibility points (high when it failed everywhere), any blind spot caps the rating at amber,
and an account where less than half the checks ran is not rated at all. A partial read (more events than
one read returns) and AWS Health without a support plan cost little: the rest of the check still saw.
"""

from __future__ import annotations

import math
import re
from functools import cache
from importlib import resources

import yaml

POINTS = {"critical": 40, "high": 15, "medium": 5, "low": 1}
HALF = 35.0  # points against a part that halve what is left of it
GREEN, AMBER = 80, 60
MIN_COVERAGE = 0.5  # below this share of checks run, no rating is given
# Gaps that still leave the check seeing most of what it looks for: not blind spots.
MINOR_GAPS = {"Partial", "SubscriptionRequiredException", "ResourceNotFoundException", "MalformedQueryException"}

PARTS = [
    ("live", "Live faults", 20, "Faults in the window that were not there a day earlier."),
    ("standing", "Standing faults", 10, "Faults found in the window that were already there a day earlier."),
    ("capacity", "Limits and capacity", 20, "Quotas and limits close to their ceiling, and resources running hot."),
    ("resilience", "Resilience", 15, "Single points of failure and missing failover."),
    ("currency", "Old versions and hardware", 15,
     "Databases, Kubernetes, operating systems and runtimes out of support or soon to be,"
     " and previous generation instances."),
    ("usage", "Use of what is paid for", 10, "Read replicas and readers nobody reads, while a writer runs hot."),
    ("visibility", "Visibility", 10, "Logging and monitoring that is off, and checks that could not read something."),
]  # fmt: skip
CURRENCY_RULES = {"lambda_runtime"}
VISIBILITY_RULES = {"no_alarm", "eks_not_read"}
QUOTA = re.compile(r"quota|limit", re.I)


@cache
def _kinds() -> dict[str, str]:
    cat = yaml.safe_load(resources.files("exitrisk").joinpath("data/outage.yaml").read_text(encoding="utf-8"))
    return {r["id"]: r.get("kind", "") for r in cat["rules"]}


def risk_part(r: dict) -> str:
    rule, area = r.get("rule") or "", r.get("area") or ""
    if area in ("lifecycle", "hardware") or rule in CURRENCY_RULES:
        return "currency"
    if area == "usage":
        return "usage"
    if rule in VISIBILITY_RULES:
        return "visibility"
    if area == "limits" or _kinds().get(rule) in ("capacity", "event"):
        return "capacity"
    return "resilience"


def signal_part(s: dict) -> str:
    if not s.get("chronic"):
        return "live"
    return "capacity" if QUOTA.search(f"{s.get('area', '')} {s.get('title', '')}") else "standing"


def _off(item: str) -> str:
    return item if re.search(r"\boff\b", item) else f"{item} is off"


def rag(score: float) -> str:
    return "green" if score >= GREEN else "amber" if score >= AMBER else "red"


def blind_spots(gaps: list[dict]) -> tuple[list[dict], list[dict]]:
    """(blind, minor): gaps where a check did not run, and gaps where it ran but read only part."""
    blind = [g for g in gaps if g.get("code") not in MINOR_GAPS]
    return blind, [g for g in gaps if g.get("code") in MINOR_GAPS]


def score_account(
    signals: list[dict],
    risks: list[dict],
    readiness: list[dict],
    gaps: list[dict],
    ran: int = 0,
    regions: int = 1,
    finished: bool = True,
) -> dict:
    """The Health Score of one account from what its health check found. ``ran`` is the checks run (one per
    check and region); ``regions`` how many regions were read, for the share of a check that failed."""
    items: dict[str, list[tuple[str, str, str]]] = {k: [] for k, *_ in PARTS}  # part: [(group, severity, title)]
    for s in signals:
        title = s.get("title", "")
        # the same fault on many resources is one issue: the title with the resource taken out
        grp = title.replace(s["resource"], "*") if s.get("resource") else title
        items[signal_part(s)].append((grp, s["severity"], title))
    for r in risks:
        items[risk_part(r)].append(
            (r.get("rule") or r.get("title", ""), r.get("severity") or "low", r.get("title", ""))
        )
    for x in readiness:
        items["visibility"].append((f"ready:{x.get('item')}", "medium", _off(x.get("item") or "")))
    blind, minor = blind_spots(gaps)
    where: dict[str, set] = {}
    for g in blind:
        where.setdefault(g.get("check") or "?", set()).add(g.get("region"))
    for check, regs in where.items():
        everywhere = len(regs - {"global"}) >= regions or "global" in regs or regions <= 1
        items["visibility"].append((f"gap:{check}", "high" if everywhere else "medium", f"Could not run: {check}"))
    for g in minor:
        items["visibility"].append((f"gap:{g.get('check')}", "low", f"Read only in part: {g.get('check')}"))
    parts = []
    for key, label, weight, what in PARTS:
        groups: dict[str, list[tuple[str, str]]] = {}
        for grp, sev, title in items[key]:
            groups.setdefault(grp, []).append((sev, title))
        lost, worst = 0.0, []
        for rows in groups.values():
            top = max(rows, key=lambda r: POINTS.get(r[0], 1))
            pts = POINTS.get(top[0], 1) * (1 + math.log(len(rows)))
            lost += pts
            worst.append((pts, top[1] + (f" (×{len(rows)})" if len(rows) > 1 else ""), top[0]))
        got = weight * 0.5 ** (lost / HALF)
        worst.sort(key=lambda w: -w[0])
        parts.append({"key": key, "label": label, "weight": weight, "what": what, "score": round(got, 1),
                      "issues": len(items[key]), "rag": rag(100 * got / weight),
                      "top": [{"title": t, "severity": sev} for _, t, sev in worst[:3]]})  # fmt: skip
    score = round(sum(p["score"] for p in parts))
    live = {s["severity"] for s in signals if not s.get("chronic")}
    level, why = rag(score), f"{score} out of 100."
    if "critical" in live:
        level, why = "red", f"{score} out of 100, rated red because a critical fault is live now."
    elif "high" in live and level == "green":
        level, why = "amber", f"{score} out of 100, rated amber at best because a high severity fault is live now."
    weakest = min(parts, key=lambda p: p["score"] / p["weight"])
    if weakest["score"] < weakest["weight"] * 0.8:
        why += f" Weakest: {weakest['label'].lower()}."
    # what could not be seen: coverage first, then the cap
    failed = len(blind)
    coverage = max(0.0, 1 - failed / ran) if ran else (0.0 if failed else 1.0)
    names = sorted(where)
    unseen = ", ".join(names[:4]) + (f" and {len(names) - 4} more" if len(names) > 4 else "")
    if coverage < MIN_COVERAGE:
        level = "unrated"
        why = (
            f"Not rated: only {coverage:.0%} of the checks could run ({failed} of {ran or failed} failed: {unseen})."
            " A score from so little would look healthier than the account may be."
        )
    elif names:
        if level == "green":
            level = "amber"
        why += (
            f" {len(names)} check{'s' if len(names) > 1 else ''} could not run ({unseen}), so this is"
            f" from {coverage:.0%} of the checks and rated amber at best: what was not read is not counted as healthy."
        )
    if not finished and level != "unrated":
        level = "amber" if level == "green" else level
        why += " The run did not finish, so not everything was read; rated amber at best."
    return {"score": score, "rag": level, "why": why, "parts": parts, "coverage": round(coverage, 3),
            "blind": names, "partial": bool(names) or not finished}  # fmt: skip
