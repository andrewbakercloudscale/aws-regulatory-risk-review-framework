"""Turn a scan into the report: exit-risk scores, rankings, trend and estimate.

Scoring (see docs/METHODOLOGY.md):

* every service has a tier 1-5 and a tier score (10, 30, 50, 75, 95);
* an account's **inherent risk** is the spend-weighted mean tier score of its services
  (0-100) - how hard *that account* is to move;
* an account's **weight** is its share of the in-scope spend;
* its **contribution** = inherent risk x weight - how many points of the OU score it carries;
* the **OU exit-risk score** is the sum of contributions, i.e. the spend-weighted risk of
  the whole OU. A small account full of DynamoDB scores high on its own but contributes
  little, which is exactly the behaviour the executive view needs.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from . import __version__
from .catalog import Catalog, load_catalog
from .estimate import TARGET_LABELS, TYPICAL_COUNTS, Questionnaire, build_estimate, service_effort
from .filtering import AccountFilter
from .issues import Issue

RATINGS = [(25, "Low"), (40, "Moderate"), (55, "Elevated"), (70, "High"), (101, "Critical")]


def rating(score: float | None) -> str:
    if score is None:
        return "n/a"
    for limit, label in RATINGS:
        if score < limit:
            return label
    return "Critical"


def _weighted_score(amounts: dict[str, float], catalog: Catalog) -> float | None:
    total = sum(amounts.values())
    if total <= 0:
        return None
    return sum(amt * catalog.tier_score(catalog.lookup(s).tier) for s, amt in amounts.items()) / total


def build_report(
    scan: dict,
    account_filter: AccountFilter | None = None,
    questionnaire: Questionnaire | None = None,
    catalog: Catalog | None = None,
) -> dict:
    catalog = catalog or load_catalog()
    account_filter = account_filter or AccountFilter()
    questionnaire = questionnaire or Questionnaire()
    all_ids = {a["id"] for a in scan.get("accounts", [])}

    period = scan.get("period") or {"months": 1}
    months_in_data = sorted({r["month"] for r in scan.get("costs", [])})
    n_months = max(len(months_in_data), 1)

    all_accounts = {a["id"]: a for a in scan.get("accounts", [])}
    in_scope = {aid: a for aid, a in all_accounts.items() if account_filter.matches(a["name"])}
    excluded_count = len(all_accounts) - len(in_scope)
    # Keep scan-wide issues, and account issues only for accounts the filter kept.
    issues: list[dict] = [
        i
        for i in scan.get("issues", [])
        if not i.get("account_id") or i["account_id"] in in_scope or i["account_id"] not in all_ids
    ]

    # Aggregate spend: account -> service -> total; month -> tier -> total.
    per_account: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    trend: dict[str, dict[int, float]] = defaultdict(lambda: defaultdict(float))
    excluded_spend = 0.0
    unclassified: dict[str, float] = defaultdict(float)
    negative_lines = 0
    for r in scan.get("costs", []):
        if r["account_id"] not in in_scope:
            continue
        info = catalog.lookup(r["service"])
        if info.excluded:
            excluded_spend += r["amount"]
            continue
        if r["amount"] == 0:
            continue  # Cost Explorer lists free-tier services at exactly zero
        if r["amount"] < 0:
            negative_lines += 1
            continue
        per_account[r["account_id"]][r["service"]] += r["amount"]
        trend[r["month"]][info.tier] += r["amount"]
        if not info.classified:
            unclassified[r["service"]] += r["amount"]

    for svc, amt in sorted(unclassified.items(), key=lambda kv: -kv[1]):
        issues.append(
            Issue(
                "warning",
                "catalog",
                f"'{svc}' is not in the service catalog; scored as Moderate "
                f"(tier 3). {amt / n_months:,.0f}/month in scope.",
                "Add it to src/exitrisk/data/service_catalog.yaml (see CONTRIBUTING.md).",
                service=svc,
            ).to_dict()
        )
    if negative_lines:
        issues.append(
            Issue(
                "info",
                "cost",
                f"{negative_lines} negative cost line(s) (credits/refunds not caught "
                "by the record-type filter) were ignored",
            ).to_dict()
        )

    total_monthly = sum(sum(s.values()) for s in per_account.values()) / n_months
    inventory = scan.get("inventory") or {}

    accounts_out = []
    services_agg: dict[str, dict] = {}
    for aid, acct in in_scope.items():
        svc_totals = per_account.get(aid, {})
        monthly = sum(svc_totals.values()) / n_months
        score = _weighted_score(svc_totals, catalog)
        weight = monthly / total_monthly if total_monthly else 0.0
        tier_spend = {t: 0.0 for t in range(1, 6)}
        effort_by_tier = {t: 0.0 for t in range(1, 6)}
        inv_totals = (inventory.get(aid) or {}).get("totals", {})
        top = []
        for svc, amt in svc_totals.items():
            info = catalog.lookup(svc)
            m = amt / n_months
            tier_spend[info.tier] += m
            if m >= questionnaire.materiality:
                probe = TYPICAL_COUNTS.get(info.service)
                count = inv_totals.get(probe[0]) if probe else None
                effort_by_tier[info.tier] += service_effort(info.effort_weeks, m, count, probe[1] if probe else None)
            top.append((m, info))
            agg = services_agg.setdefault(
                info.service,
                {
                    "service": info.service,
                    "display": info.display,
                    "category": info.category,
                    "tier": info.tier,
                    "tier_label": catalog.tier_label(info.tier),
                    "classified": info.classified,
                    "monthly_spend": 0.0,
                    "accounts": 0,
                },
            )
            agg["monthly_spend"] += m
            agg["accounts"] += 1
        top.sort(key=lambda x: -x[0])
        lockin = [{"service": i.display, "tier": i.tier, "monthly_spend": round(m, 2)} for m, i in top if i.tier >= 4][
            :3
        ]
        accounts_out.append(
            {
                "id": aid,
                "name": acct["name"],
                "ou_path": acct.get("ou_path", ""),
                "status": acct.get("status"),
                "monthly_spend": round(monthly, 2),
                "weight": round(weight, 5),
                "score": round(score, 1) if score is not None else None,
                "rating": rating(score),
                "contribution": round((score or 0) * weight, 2),
                "tier_spend": {t: round(v, 2) for t, v in tier_spend.items()},
                "high_risk_pct": round(100 * (tier_spend[4] + tier_spend[5]) / monthly, 1) if monthly else 0.0,
                "top_services": [
                    {"service": i.display, "tier": i.tier, "monthly_spend": round(m, 2)} for m, i in top[:5]
                ],
                "top_lockin": lockin,
                "effort_by_tier": {t: round(v, 2) for t, v in effort_by_tier.items()},
                "effort_weeks": round(sum(effort_by_tier.values()), 1),
                "inventory": inv_totals,
            }
        )
    accounts_out.sort(key=lambda a: (-a["contribution"], -(a["score"] or 0)))
    for rank, a in enumerate(accounts_out, 1):
        a["rank"] = rank

    # Sum of unrounded contributions = spend-weighted mean score across the OU.
    ou_score = (
        sum(a["monthly_spend"] * (a["score"] or 0) for a in accounts_out) / total_monthly if total_monthly else None
    )
    tiers = []
    for t in range(1, 6):
        spend = sum(a["tier_spend"][t] for a in accounts_out)
        tiers.append(
            {
                "tier": t,
                "label": catalog.tier_label(t),
                "score": catalog.tier_score(t),
                "monthly_spend": round(spend, 2),
                "pct": round(100 * spend / total_monthly, 1) if total_monthly else 0.0,
                "services": sum(1 for s in services_agg.values() if s["tier"] == t),
            }
        )
    services_out = sorted(services_agg.values(), key=lambda s: -s["monthly_spend"])
    for s in services_out:
        s["monthly_spend"] = round(s["monthly_spend"], 2)
        s["pct"] = round(100 * s["monthly_spend"] / total_monthly, 2) if total_monthly else 0.0

    high_pct = sum(t["pct"] for t in tiers if t["tier"] >= 4)
    estimate = build_estimate(questionnaire, accounts_out, total_monthly)
    summary = {
        "score": round(ou_score, 1) if ou_score is not None else None,
        "rating": rating(ou_score),
        "monthly_spend": round(total_monthly, 2),
        "annual_spend": round(total_monthly * 12, 2),
        "accounts_in_scope": len(in_scope),
        "accounts_with_spend": sum(1 for a in accounts_out if a["monthly_spend"] > 0),
        "accounts_excluded": excluded_count,
        "accounts_total": len(all_accounts),
        "high_risk_pct": round(high_pct, 1),
        "high_risk_monthly": round(sum(t["monthly_spend"] for t in tiers if t["tier"] >= 4), 2),
        "services": len(services_out),
        "unclassified_services": len(unclassified),
        "excluded_billing_monthly": round(excluded_spend / n_months, 2),
        "top_lockin_services": [s for s in services_out if s["tier"] >= 4][:5],
    }
    summary["narrative"] = _narrative(summary, accounts_out, estimate, questionnaire)

    sev_order = {"critical": 0, "error": 1, "warning": 2, "info": 3}
    issues.sort(key=lambda i: sev_order.get(i.get("severity"), 9))
    return {
        "meta": {
            "scan_id": scan["id"],
            "label": scan.get("label", ""),
            "mode": scan.get("mode", "live"),
            "scan_status": scan.get("status"),
            "scanned_at": scan.get("finished_at") or scan.get("created_at"),
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "profile": (scan.get("params") or {}).get("profile"),
            "identity": scan.get("identity"),
            "org": scan.get("org"),
            "ou": scan.get("ou"),
            "period": period,
            "months_in_data": months_in_data,
            "filter": account_filter.to_dict(),
            "catalog_version": catalog.version,
            "tool_version": __version__,
            "inventory": bool(inventory),
            "target_label": TARGET_LABELS[questionnaire.target],
        },
        "summary": summary,
        "tiers": tiers,
        "accounts": accounts_out,
        "services": services_out,
        "trend": [{"month": m, "tier_spend": {t: round(trend[m][t], 2) for t in range(1, 6)}} for m in months_in_data],
        "estimate": estimate,
        "issues": issues,
        "issue_counts": {s: sum(1 for i in issues if i.get("severity") == s) for s in sev_order},
    }


def _money(v: float, cur: str) -> str:
    if v >= 1e6:
        return f"{cur} {v / 1e6:,.1f}m"
    if v >= 1e3:
        return f"{cur} {v / 1e3:,.0f}k"
    return f"{cur} {v:,.0f}"


def _narrative(summary: dict, accounts: list[dict], est: dict, q: Questionnaire) -> list[str]:
    if summary["score"] is None:
        return ["No in-scope spend was found, so no exit-risk score could be calculated."]
    cur = q.currency
    lines = [
        f"The in-scope estate scores {int(summary['score'] + 0.5)}/100 ({summary['rating']}) for exit difficulty, "
        f"across {summary['accounts_with_spend']} account(s) spending {_money(summary['annual_spend'], 'USD')} a year.",
        f"{summary['high_risk_pct']:.0f}% of spend ({_money(summary['high_risk_monthly'] * 12, 'USD')}/yr) runs on "
        "High or Critical services that have no direct equivalent outside AWS and need re-engineering.",
    ]
    if summary["top_lockin_services"]:
        names = ", ".join(s["display"] for s in summary["top_lockin_services"][:3])
        lines.append(f"The largest lock-in exposures are {names}.")
    top = [a for a in accounts if a["contribution"] > 0][:3]
    if len([a for a in accounts if a["contribution"] > 0]) > 1:
        share = sum(a["contribution"] for a in top) / summary["score"] * 100 if summary["score"] else 0
        lines.append(
            f"{len(top)} account(s) - {', '.join(a['name'] for a in top)} - carry {share:.0f}% of the "
            "weighted risk; they set the pace of any exit."
        )
    lines.append(
        f"A full exit to {TARGET_LABELS[q.target]} is estimated at {est['effort']['person_months']:,.0f} "
        f"person-months over ~{est['duration']['calendar_months']:.0f} months "
        f"({est['duration']['low_months']:.0f}-{est['duration']['high_months']:.0f}), costing about "
        f"{_money(est['cost']['total'], cur)} ({_money(est['cost']['low'], cur)}-{_money(est['cost']['high'], cur)}) "
        "in engineering and parallel running."
    )
    return lines
