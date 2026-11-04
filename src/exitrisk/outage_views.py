"""The Outage Risk Report's views for working through hundreds of accounts: what is covered, a review of
each service, the services and accounts most at risk, and the top risks.

Risk is ranked on what was found, not on spend: severity, whether it is production, how many accounts it
is in, and how far an outage of that service spreads (data/outage_services.yaml "impact"). Spend is shown
as context only, since a cheap account that takes payments can matter more than a large data platform.
"""

from __future__ import annotations

import re
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
RATINGS = ("Critical", "High", "Medium", "Low", "Not measured")
# Risk points: one critical outweighs any number of highs an account is likely to have, and so on down.
POINTS = {"critical": 100, "high": 10, "medium": 1, "low": 0}
NON_PROD_SHARE = 0.1  # a non-production finding counts a tenth
SERVICES_AT_RISK = 15
ENVIRONMENTS = ("Production", "Non-production")
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
    issues: dict[tuple, list[dict]] = {}
    for f in mine:
        res = f["res"].split(": ", 1)[-1] if f["rule"] == "no_alarm" else f["res"]
        key = (f["account_id"], res, f["region"])
        if key not in worst or SEV_ORDER[f["severity"]] < SEV_ORDER[worst[key]]:
            worst[key] = f["severity"]
        issues.setdefault(key, []).append({"severity": f["severity"], "title": f["title"], "why": f.get("why") or ""})

    def rank(p: dict) -> tuple:
        sev = worst.get((p["account_id"], p["res"], p["region"]))
        return (SEV_ORDER.get(sev, 9), -max((s.get("peak") or 0 for s in p["stats"]), default=0))

    rows = sorted(profiles, key=rank)[:REVIEW_RESOURCES]
    out = []
    for p in rows:
        key = (p["account_id"], p["res"], p["region"])
        found = sorted(issues.get(key, []), key=lambda i: SEV_ORDER[i["severity"]])
        out.append({**p, "severity": worst.get(key, ""), "issues": found})
    return out


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


def _risk_points(found: list[dict]) -> float:
    """An account's risk: its findings by severity, one per rule (copies of a rule are one risk), with a
    non-production finding counting a tenth."""
    worst: dict[str, dict] = {}
    for f in found:
        w = worst.get(f["rule"])
        if w is None or (f["production"], -SEV_ORDER[f["severity"]]) > (w["production"], -SEV_ORDER[w["severity"]]):
            worst[f["rule"]] = f
    return round(sum(POINTS[f["severity"]] * (1 if f["production"] else NON_PROD_SHARE) for f in worst.values()), 1)


def _reach(found: list[dict], ranks: dict[str, int]) -> float | None:
    """How far an outage from an account's findings would spread: the impact rank of each finding's service
    (1 one workload, 2 data, 3 shared), averaged with the same weights as _risk_points. None with no finding."""
    worst: dict[str, dict] = {}
    for f in found:
        w = worst.get(f["rule"])
        if w is None or (f["production"], -SEV_ORDER[f["severity"]]) > (w["production"], -SEV_ORDER[w["severity"]]):
            worst[f["rule"]] = f
    weights = [(POINTS[f["severity"]] * (1 if f["production"] else NON_PROD_SHARE), f) for f in worst.values()]
    total = sum(w for w, _ in weights)
    if not total:
        return None
    return round(sum(w * ranks.get(f["service"], 1) for w, f in weights) / total, 2)


def _heatmap(table: list[dict]) -> dict:
    """Accounts in a matrix of rating by environment, with their critical and high findings."""
    cells: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in table:
        cells[(r["rating"], ENVIRONMENTS[0] if r["production"] else ENVIRONMENTS[1])].append(r)
    rows = []
    for rating in RATINGS:
        row = []
        for env in ENVIRONMENTS:
            mine = sorted(cells.get((rating, env)) or [], key=lambda r: (-r["risk"], r["name"]))
            row.append(
                {
                    "band": env,
                    "accounts": len(mine),
                    "critical": sum(r["critical"] for r in mine),
                    "high": sum(r["high"] for r in mine),
                    "names": [r["name"] for r in mine[:15]],
                }
            )
        rows.append({"rating": rating, "cells": row})
    return {"bands": list(ENVIRONMENTS), "rows": rows}


def _services_at_risk(findings: list[dict], rules: dict, cat: dict) -> list[dict]:
    """The services most likely to cause an outage, weighted by how far one would spread: production risk
    points (one per rule per account) times the service's impact rank. Spend plays no part."""
    impacts = cat["impacts"]
    meta = {s["id"]: s for s in cat["services"]}
    by: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        if f["service"] in meta and f["severity"] in ("critical", "high", "medium"):
            by[f["service"]].append(f)
    out = []
    for sid, mine in by.items():
        prod = [f for f in mine if f["production"]]
        pairs: dict[tuple[str, str], dict] = {}
        for f in prod:
            k = (f["rule"], f["account_id"])
            if k not in pairs or SEV_ORDER[f["severity"]] < SEV_ORDER[pairs[k]["severity"]]:
                pairs[k] = f
        likelihood = sum(POINTS[f["severity"]] for f in pairs.values())
        if not likelihood:
            continue
        impact = impacts[meta[sid].get("impact", "workload")]
        worst = min(prod, key=lambda f: (SEV_ORDER[f["severity"]], -(f["at_peak"] or f["pct"] or 0)))
        counts = Counter(f["severity"] for f in pairs.values())
        out.append(
            {
                "id": sid,
                "label": meta[sid]["label"],
                "impact": meta[sid].get("impact", "workload"),
                "impact_label": impact["label"],
                "impact_about": impact["about"],
                "priority": likelihood * impact["rank"],
                "severity": worst["severity"],
                **{k: counts[k] for k in ("critical", "high", "medium")},
                "accounts": len({f["account_id"] for f in prod}),
                "resources": len({(f["account_id"], f["res"]) for f in prod}),
                "worst": {
                    "title": worst["title"],
                    "res": worst["res"],
                    "account": worst["account"],
                    "why": worst["why"],
                    "fix": rules[worst["rule"]]["fix"],
                },
            }
        )
    out.sort(key=lambda s: (-s["priority"], SEV_ORDER[s["severity"]], -s["accounts"], s["label"]))
    return out[:SERVICES_AT_RISK]


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
    """Severity by account and service, for the accounts with the most risk."""
    top = [r for r in sorted(table, key=lambda r: (-r["risk"], -r["score"], r["name"])) if r["risk"]][:HEAT_ACCOUNTS]
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
                "production": r["production"],
                "risk": r["risk"],
                "critical": r["critical"],
                "high": r["high"],
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
    severity, then how far an outage of the service spreads, then how far past its limit."""
    spend = {r["id"]: r["monthly_spend"] for r in table}
    svc = services_catalog()
    reach = {s["id"]: svc["impacts"][s.get("impact", "workload")]["rank"] for s in svc["services"]}
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
                    -reach.get(f["service"], 1),
                    -len(mine),
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


IMMEDIATE_ROWS = 60  # everything that needs someone today, not a sample
IMMEDIATE_SOON = 14  # days: a change AWS will make this soon needs a decision now
LOOKBACK_DAYS = 35  # matches outage.LOOKBACK_HOURS
SCHEDULED = ("rds_maintenance", "ec2_event")
SCHEDULED_ON = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _immediate(findings: list[dict], table: list[dict], rules: dict, today: date) -> dict:
    """What needs someone today, in production only: what is past or at its limit, has failed in the lookback,
    is failing now, fills before the peak, or is a change AWS will make within IMMEDIATE_SOON days. One row per
    finding per account, its other resources counted. Each says why now, who owns the account and what to do."""
    owners = {r["id"]: r.get("owner") or "" for r in table}
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in findings:
        if not f["production"]:
            continue
        rule = rules.get(f["rule"]) or {}
        when, rank, by = None, 9, today
        if f["rule"] in SCHEDULED:
            m = SCHEDULED_ON.search(f.get("why") or "")
            on = date.fromisoformat(m.group(1)) if m else None
            if on and 0 <= (on - today).days <= IMMEDIATE_SOON and f["severity"] in ("critical", "high"):
                when, rank, by = f"AWS applies it on {on.isoformat()}", 4, max(today, on - timedelta(days=1))
        elif f["severity"] == "critical" or f.get("now"):
            if f.get("now"):
                when, rank = "Failing now", 0
            elif rule.get("kind") == "event":
                when, rank = f"Failed in the last {LOOKBACK_DAYS} days", 2
            elif f.get("days") is not None and (f.get("pct") or 0) < 90:
                when, rank, by = (
                    f"Full in about {round(f['days'])} days",
                    5,
                    today + timedelta(days=max(0, int(f["days"]) - 7)),
                )
            elif round(f.get("pct") or 0) >= 100:
                when, rank = "At or past its limit now", 1
            else:
                when, rank = "Near its limit now", 3
        if when:
            grouped[(f["rule"], f["account_id"])].append({**f, "_when": when, "_rank": rank, "_by": by})
    rows = []
    for mine in grouped.values():
        f = min(mine, key=lambda x: (x["_rank"], SEV_ORDER[x["severity"]], -(x["pct"] or 0)))
        rows.append(
            {
                "rule": f["rule"],
                "title": f["title"],
                "severity": f["severity"],
                "when": f["_when"],
                "do_by": min(x["_by"] for x in mine).isoformat(),
                "account": f["account"],
                "owner": owners.get(f["account_id"], ""),
                "service": f.get("service_label", ""),
                "res": f["res"],
                "region": f["region"],
                "more": len(mine) - 1,
                "why": f["why"],
                "fix": (rules.get(f["rule"]) or {}).get("fix", ""),
                "_key": (
                    f["_rank"],
                    min(x["_by"] for x in mine),
                    SEV_ORDER[f["severity"]],
                    -(f["pct"] or 0),
                    f["account"],
                    f["rule"],
                ),
            }
        )
    rows.sort(key=lambda r: r["_key"])
    keep = [{k: v for k, v in r.items() if k != "_key"} for r in rows]
    return {
        "rows": keep[:IMMEDIATE_ROWS],
        "total": len(keep),
        "accounts": len({r["account"] for r in keep}),
        "resources": sum(1 + r["more"] for r in keep),
        "soon_days": IMMEDIATE_SOON,
    }


def build_views(scan, accounts, checked, table, findings, rules, cat, peak: date, freeze: date, today: date) -> dict:
    """Add to the report what it needs to rank 300 accounts. Marks each finding with its service, and each
    account with its risk points (see _risk_points)."""
    svc_cat = services_catalog()
    by_rule, by_quota, by_billed = _service_maps(svc_cat)
    labels = {s["id"]: s["label"] for s in svc_cat["services"]}
    for f in findings:
        f["service"] = service_of(f["rule"], f["res"], by_rule, by_quota)
        f["service_label"] = labels.get(f["service"], "")
    mine: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        mine[f["account_id"]].append(f)
    ranks = {s["id"]: svc_cat["impacts"][s.get("impact", "workload")]["rank"] for s in svc_cat["services"]}
    for r in table:
        r["risk"] = _risk_points(mine.get(r["id"]) or [])
        r["reach"] = _reach(mine.get(r["id"]) or [], ranks)
    billed = _monthly_by_service(scan, {a["id"] for a in table})
    return {
        "coverage": _coverage(billed, svc_cat, by_billed),
        "services": _reviews(accounts, checked, findings, rules, svc_cat, by_billed, billed),
        "heatmap": _heatmap(table),
        "services_at_risk": _services_at_risk(findings, rules, svc_cat),
        "account_service": _account_service(table, findings, labels, rules),
        "top_risks": _top_risks(findings, table, rules, cat, freeze, peak, today),
        "immediate": _immediate(findings, table, rules, today),
        "runway": _runway(findings, peak, today),
        "spend": {
            "total": round(sum(r["monthly_spend"] for r in table), 2),
            "unknown": sum(1 for r in table if not r["monthly_spend"]),
        },
    }
