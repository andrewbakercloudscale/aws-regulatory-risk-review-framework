"""The Outage Risk Report's views for working through hundreds of accounts: what is covered, a review of
each service, where spend and risk meet, and the top risks.

Spend is a proxy for importance, so a cheap account that matters (payments, say) can rank too low: the
views say so, and an account with no known spend is shown apart rather than ranked last in silence.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, timedelta
from functools import lru_cache
from importlib import resources

import yaml

SEVERITIES = ("critical", "high", "medium", "low")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
TOP_RISKS = 50  # and every critical one beyond it
CELL_RISKS = 6  # distinct risks listed for one account and service
HEAT_ACCOUNTS = 40
HEAT_SERVICES = 16
REVIEW_RESOURCES = 50  # sent per service, worst first; the counts cover every resource
REVIEW_LIMITS = 12
RUNWAY_ROWS = 30
SPEND_BANDS = ((100_000.0, "US$100k+"), (10_000.0, "US$10k to 100k"), (1_000.0, "US$1k to 10k"), (0.01, "Under US$1k"))
NO_SPEND = "Spend unknown"
RATINGS = ("Critical", "High", "Medium", "Low", "Not measured")
# A limit with no code to name its service.
LIMIT_NAMES = (("IAM ", "iam"), ("Route 53", "route53"), ("Lambda", "lambda"), ("General purpose", "s3"))


@lru_cache(maxsize=1)
def services_catalog() -> dict:
    """What is checked for each service, data/outage_services.yaml."""
    text = resources.files("exitrisk").joinpath("data/outage_services.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


def _service_maps(cat: dict) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    by_rule, by_quota, by_billed = {}, {}, {}
    for s in cat["services"]:
        by_rule.update(dict.fromkeys(s.get("rules") or [], s["id"]))
        by_quota.update(dict.fromkeys(s.get("quota") or [], s["id"]))
        by_billed.update(dict.fromkeys(s.get("billed") or [], s["id"]))
    return by_rule, by_quota, by_billed


def service_of(rule: str, res: str, by_rule: dict[str, str], by_quota: dict[str, str]) -> str:
    """The service a finding belongs to; "" for a limit that names none."""
    if rule == "no_alarm":
        return res.split(":", 1)[0]
    if rule in by_rule:
        return by_rule[rule]
    code = res.split(":", 1)[0] if ":" in res else ""
    if code in by_quota:
        return by_quota[code]
    return next((svc for prefix, svc in LIMIT_NAMES if res.startswith(prefix)), "")


def _monthly_by_service(scan: dict, ids: set[str]) -> dict[str, float]:
    rows = [r for r in scan.get("costs") or [] if r["account_id"] in ids]
    months = len({r["month"] for r in rows}) or 1
    out: dict[str, float] = defaultdict(float)
    for r in rows:
        out[r.get("service") or "Unknown"] += float(r.get("amount") or 0) / months
    return out


def _coverage(billed: dict[str, float], cat: dict, by_billed: dict[str, str]) -> dict:
    """Every billed service by how far it is checked. Credits and tax-like lines are not counted as a gap."""
    level = {s["id"]: s["level"] for s in cat["services"]}
    label = {s["id"]: s["label"] for s in cat["services"]}
    skip = set(cat.get("not_runtime") or [])
    rows, spend, skipped = [], Counter(), 0.0
    for name, amount in billed.items():
        if amount <= 0:
            continue
        if name in skip:
            skipped += amount
            continue
        sid = by_billed.get(name, "")
        lv = level.get(sid, "none")
        spend[lv] += amount
        rows.append(
            {"name": name, "monthly": round(amount, 2), "level": lv, "service": sid, "label": label.get(sid, "")}
        )
    rows.sort(key=lambda r: -r["monthly"])
    total = sum(spend.values())
    return {
        "levels": [
            {
                "level": k,
                **cat["levels"][k],
                "monthly": round(spend[k], 2),
                "share": round(100.0 * spend[k] / total, 1) if total else 0.0,
                "services": sum(r["level"] == k for r in rows),
            }
            for k in ("deep", "partial", "generic", "none")
        ],
        "billed": rows,
        "not_covered": [r for r in rows if r["level"] == "none"],
        "not_runtime_monthly": round(skipped, 2),
        "total": round(total, 2),
        "catalog_version": cat.get("version"),
        "catalog": [
            {
                "id": s["id"],
                "label": s["label"],
                "level": s["level"],
                "reads": s.get("reads") or [],
                "not_seen": s.get("not_seen") or [],
            }
            for s in cat["services"]
        ],
    }


def _verdict(counts: Counter, unread: int, resources_n: int, level: str, monthly: float) -> tuple[str, str]:
    """(tone, sentence), the answer before the detail. Nothing found is never called safe."""
    gap = f" Not read in {unread} account{'s' if unread != 1 else ''}, which is not a pass." if unread else ""
    if counts["critical"]:
        return "critical", f"Act now: {counts['critical']} critical and {counts['high']} high in production.{gap}"
    if counts["high"]:
        return "high", f"Act before the freeze: {counts['high']} high in production.{gap}"
    if counts["medium"]:
        return "medium", f"Watch: {counts['medium']} medium in production, nothing at high or above.{gap}"
    if level == "generic":
        return "unknown", f"Only quotas were checked, and none is close. The resources were not looked at.{gap}"
    if not resources_n and not counts["low"] and monthly > 0:
        return "unknown", f"Billed, but no resource was read in this scan.{gap}"
    return "clear", f"These checks found nothing at medium or above. See what they cannot see.{gap}"


def _rule_rows(mine: list[dict], rules: dict) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for f in mine:
        grouped[f["rule"]].append(f)
    out = []
    for rid, rows in grouped.items():
        worst = min(rows, key=lambda f: SEV_ORDER[f["severity"]])
        out.append(
            {
                "rule": rid,
                "title": rules[rid]["title"],
                "severity": worst["severity"],
                "findings": len(rows),
                "accounts": len({f["account_id"] for f in rows}),
                "why": rules[rid]["why"],
                "fix": rules[rid]["fix"],
            }
        )
    out.sort(key=lambda r: (SEV_ORDER[r["severity"]], -r["findings"]))
    return out


def _resources(profiles: list[dict], mine: list[dict]) -> list[dict]:
    """The worst resources: most severe finding first, then the busiest."""
    worst: dict[tuple, str] = {}
    for f in mine:
        res = f["res"].split(": ", 1)[-1] if f["rule"] == "no_alarm" else f["res"]
        key = (f["account_id"], res, f["region"])
        if key not in worst or SEV_ORDER[f["severity"]] < SEV_ORDER[worst[key]]:
            worst[key] = f["severity"]

    def rank(p: dict) -> tuple:
        sev = worst.get((p["account_id"], p["res"], p["region"]))
        return (SEV_ORDER.get(sev, 9), -max((s.get("peak") or 0 for s in p["stats"]), default=0))

    rows = sorted(profiles, key=rank)[:REVIEW_RESOURCES]
    return [{**p, "severity": worst.get((p["account_id"], p["res"], p["region"]), "")} for p in rows]


def _reviews(accounts, checked, findings, rules, cat, by_billed, billed) -> list[dict]:
    """A review of each service in use, worst first."""
    profiles: dict[str, list[dict]] = defaultdict(list)
    counted: Counter = Counter()
    accounts_with: dict[str, set[str]] = defaultdict(set)
    unread: dict[str, list[str]] = defaultdict(list)
    scan_has_profiles = False
    names = {a["id"]: a["name"] for a in accounts}
    per_service = [(s, set(s.get("checks") or [])) for s in cat["services"]]
    for acct_id, name in names.items():
        raw = checked.get(acct_id)
        if raw is None:
            continue
        scan_has_profiles = scan_has_profiles or "profiles" in raw
        for p in raw.get("profiles") or []:
            profiles[p["svc"]].append({**p, "account": name, "account_id": acct_id})
            accounts_with[p["svc"]].add(acct_id)
        counted.update(raw.get("profile_counts") or {})
        down = {k for k, v in (raw.get("checks") or {}).items() if v.get("status") == "unknown"}
        for s, checks in per_service:
            if down & checks:
                unread[s["id"]].append(name)
    by_service: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_service[f["service"]].append(f)
    monthly: Counter = Counter()
    for name, amount in billed.items():
        if name in by_billed:
            monthly[by_billed[name]] += amount
    always = cat.get("always_not_seen") or []
    out = []
    for s, _ in per_service:
        sid = s["id"]
        mine = by_service.get(sid) or []
        if not (mine or profiles.get(sid) or monthly[sid] > 0):
            continue
        prod = [f for f in mine if f["production"]]
        counts = Counter(f["severity"] for f in prod)
        n = counted[sid] or len(profiles.get(sid) or [])
        tone, verdict = _verdict(counts, len(unread[sid]), n, s["level"], monthly[sid])
        hits = {f["account_id"] for f in mine} | accounts_with[sid]
        limits = sorted(
            (f for f in mine if f["kind_capacity"]),
            key=lambda f: (not f["production"], SEV_ORDER[f["severity"]], -(f["at_peak"] or f["pct"] or 0)),
        )[:REVIEW_LIMITS]
        out.append(
            {
                "id": sid,
                "label": s["label"],
                "level": s["level"],
                "tone": tone,
                "verdict": verdict,
                "monthly": round(monthly[sid], 2),
                "resources": n,
                "resources_sent": min(len(profiles.get(sid) or []), REVIEW_RESOURCES),
                "accounts": len(hits),
                "findings": len(mine),
                **{k: counts[k] for k in SEVERITIES},
                "non_production": len(mine) - len(prod),
                "no_alarm": sum(f["rule"] == "no_alarm" for f in mine),
                "not_read": unread[sid][:12],
                "not_read_count": len(unread[sid]),
                "actions": _rule_rows(mine, rules),
                "limits": [
                    {
                        k: f[k]
                        for k in (
                            "account",
                            "res",
                            "region",
                            "severity",
                            "pct",
                            "at_peak",
                            "used",
                            "limit",
                            "unit",
                            "days",
                            "why",
                            "title",
                            "production",
                        )
                    }
                    for f in limits
                ],
                "resource_rows": _resources(profiles.get(sid) or [], mine),
                "reads": s.get("reads") or [],
                "not_seen": (s.get("not_seen") or []) + always,
                "options": s.get("options") or [],
                "docs": s.get("docs") or [],
                "no_profiles": not scan_has_profiles,
            }
        )
    tone_rank = {"critical": 0, "high": 1, "medium": 2, "unknown": 3, "clear": 4}
    out.sort(key=lambda r: (tone_rank[r["tone"]], -r["critical"], -r["high"], -r["monthly"]))
    return out


def _band(spend: float) -> str:
    return next((label for floor, label in SPEND_BANDS if spend >= floor), NO_SPEND)


def _heatmap(table: list[dict]) -> dict:
    """Accounts in a matrix of spend by rating, with what is at stake in each cell."""
    bands = [label for _, label in SPEND_BANDS] + [NO_SPEND]
    cells: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in table:
        cells[(r["rating"], _band(r["monthly_spend"]))].append(r)
    rows = []
    for rating in RATINGS:
        row = []
        for band in bands:
            mine = sorted(cells.get((rating, band)) or [], key=lambda r: -r["exposure"])
            row.append(
                {
                    "band": band,
                    "accounts": len(mine),
                    "monthly": round(sum(r["monthly_spend"] for r in mine), 2),
                    "names": [r["name"] for r in mine[:15]],
                }
            )
        rows.append({"rating": rating, "cells": row})
    return {"bands": bands, "rows": rows}


def _cell_risks(mine: list[dict], rules: dict) -> list[dict]:
    """The distinct risks in one account and service, worst first, each with what to do about it."""
    by: dict[str, list[dict]] = defaultdict(list)
    for f in mine:
        by[f["rule"]].append(f)
    out = []
    for rid, fs in by.items():
        worst = min(fs, key=lambda f: (SEV_ORDER[f["severity"]], -(f["at_peak"] or f["pct"] or 0)))
        out.append(
            {
                "title": rules[rid]["title"],
                "severity": worst["severity"],
                "count": len(fs),
                "res": worst["res"],
                "why": worst["why"],
                "fix": rules[rid]["fix"],
            }
        )
    out.sort(key=lambda r: (SEV_ORDER[r["severity"]], -r["count"]))
    return out[:CELL_RISKS]


def _account_service(table: list[dict], findings: list[dict], labels: dict[str, str], rules: dict) -> dict:
    """Severity by account and service, for the accounts with the most at stake. An account with no known
    spend has no exposure, so its critical ones are added rather than left out."""
    top = sorted(table, key=lambda r: (-r["exposure"], -r["score"]))[:HEAT_ACCOUNTS]
    shown = {r["id"] for r in top}
    top += [r for r in table if r["rating"] == "Critical" and r["id"] not in shown and not r["monthly_spend"]][:10]
    shown = {r["id"] for r in top}
    grid: dict[tuple[str, str], Counter] = defaultdict(Counter)
    held: dict[tuple[str, str], list[dict]] = defaultdict(list)
    weight: Counter = Counter()
    points = {"critical": 100, "high": 10, "medium": 1, "low": 0}
    for f in findings:
        if f["account_id"] in shown and f["service"]:
            grid[(f["account_id"], f["service"])][f["severity"]] += 1
            held[(f["account_id"], f["service"])].append(f)
            weight[f["service"]] += points[f["severity"]]
    columns = [s for s, _ in weight.most_common(HEAT_SERVICES)]
    rows = []
    for r in top:
        cells = []
        for s in columns:
            c = grid.get((r["id"], s))
            worst = next((k for k in SEVERITIES if c and c[k]), "")
            cell = {"severity": worst, "count": sum(c.values()) if c else 0}
            if c:
                cell["risks"] = _cell_risks(held[(r["id"], s)], rules)
            cells.append(cell)
        rows.append(
            {
                "id": r["id"],
                "name": r["name"],
                "score": r["score"],
                "rating": r["rating"],
                "monthly": r["monthly_spend"],
                "exposure": r["exposure"],
                "cells": cells,
            }
        )
    return {
        "columns": [{"id": s, "label": labels.get(s, s)} for s in columns],
        "rows": rows,
        "total_accounts": len(table),
    }


def _top_risks(
    findings: list[dict], table: list[dict], rules: dict, cat: dict, freeze: date, peak: date, today: date
) -> list[dict]:
    """One line per rule per account, with the rest of that account's copies counted. Production first, then
    severity, then the account's spend band, then how far past its limit."""
    spend = {r["id"]: r["monthly_spend"] for r in table}
    band_rank = {label: i for i, (_, label) in enumerate(SPEND_BANDS)}
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in findings:
        grouped[(f["rule"], f["account_id"])].append(f)
    leads = cat["areas"]
    rows = []
    for mine in grouped.values():
        f = min(mine, key=lambda x: (SEV_ORDER[x["severity"]], -(x["at_peak"] or x["pct"] or 0)))
        acct = spend.get(f["account_id"], 0.0)
        start = min(freeze, peak) - timedelta(days=leads.get(f["area"], {}).get("lead_days", 0))
        rows.append(
            {
                "rule": f["rule"],
                "title": f["title"],
                "severity": f["severity"],
                "account": f["account"],
                "account_id": f["account_id"],
                "production": f["production"],
                "service": f["service_label"],
                "res": f["res"],
                "region": f["region"],
                "more": len(mine) - 1,
                "pct": f["pct"],
                "at_peak": f["at_peak"],
                "days": f["days"],
                "why": f["why"],
                "fix": rules[f["rule"]]["fix"],
                "monthly": acct,
                "start_by": start.isoformat(),
                "late": start < today,
                "_key": (
                    not f["production"],
                    SEV_ORDER[f["severity"]],
                    band_rank.get(_band(acct), len(SPEND_BANDS)),
                    -(f["at_peak"] or f["pct"] or 0),
                    f["account"],
                ),
            }
        )
    rows.sort(key=lambda r: r["_key"])
    keep = [r for i, r in enumerate(rows) if i < TOP_RISKS or r["severity"] == "critical"]
    return [{k: v for k, v in r.items() if k != "_key"} for r in keep]


def _runway(findings: list[dict], peak: date, today: date) -> dict:
    """What reaches a limit soonest, against the peak."""
    rows = sorted((f for f in findings if f["days"] is not None and f["production"]), key=lambda f: f["days"])
    return {
        "days_to_peak": (peak - today).days,
        "total": len(rows),
        "rows": [
            {
                "title": f["title"],
                "res": f["res"],
                "account": f["account"],
                "region": f["region"],
                "days": f["days"],
                "severity": f["severity"],
            }
            for f in rows[:RUNWAY_ROWS]
        ],
    }


def build_views(scan, accounts, checked, table, findings, rules, cat, peak: date, freeze: date, today: date) -> dict:
    """Add to the report what it needs to rank 300 accounts. Marks each finding with its service, and each
    account with its exposure: risk score as a share, times monthly spend."""
    svc_cat = services_catalog()
    by_rule, by_quota, by_billed = _service_maps(svc_cat)
    labels = {s["id"]: s["label"] for s in svc_cat["services"]}
    for f in findings:
        f["service"] = service_of(f["rule"], f["res"], by_rule, by_quota)
        f["service_label"] = labels.get(f["service"], "")
    for r in table:
        r["exposure"] = round(r["score"] / 100.0 * r["monthly_spend"], 2)
    billed = _monthly_by_service(scan, {a["id"] for a in table})
    return {
        "coverage": _coverage(billed, svc_cat, by_billed),
        "services": _reviews(accounts, checked, findings, rules, svc_cat, by_billed, billed),
        "heatmap": _heatmap(table),
        "account_service": _account_service(table, findings, labels, rules),
        "top_risks": _top_risks(findings, table, rules, cat, freeze, peak, today),
        "runway": _runway(findings, peak, today),
        "spend": {
            "total": round(sum(r["monthly_spend"] for r in table), 2),
            "exposure": round(sum(r["exposure"] for r in table), 2),
            "unknown": sum(1 for r in table if not r["monthly_spend"]),
        },
    }
