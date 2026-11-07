"""Health Score: one number out of 100 per account, with a red, amber or green rating.

Seven parts, each worth a share of the 100. Every finding in a part costs points by severity, and a part
loses half of what is left for each 35 points against it, so a few issues cost a lot and the hundredth
costs little: the score separates a healthy account from an unhealthy one rather than counting rows.
Many alike findings of one rule (forty old instances) count as one issue that grows with the log of
the count. A fault live now overrides the number: critical is red, high is at best amber.
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


def score_account(signals: list[dict], risks: list[dict], readiness: list[dict], gaps: list[dict]) -> dict:
    """The Health Score of one account from what its health check found."""
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
    for g in gaps:
        items["visibility"].append((f"gap:{g.get('check')}", "low", f"Could not check {g.get('check')}"))
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
    return {"score": score, "rag": level, "why": why, "parts": parts}
