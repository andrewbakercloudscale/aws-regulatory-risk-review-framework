"""Turn a scan into the report: exit-risk scores, rankings, trend and estimate.

Scoring (see docs/METHODOLOGY.md):

* every service has a tier 1-5 and a tier score (10, 30, 50, 75, 95);
* an account's **inherent risk** is the spend-weighted mean tier score of its services
  (0-100) - how hard *that account* is to move;
* an account's **weight** is, by default, its share of spend ("spend"), so a small account full
  of DynamoDB scores high on its own but contributes little;
* its **contribution** = inherent risk x weight - how many points of the OU score it carries;
* the **OU exit-risk score** is the sum of contributions;
* its **criticality** = spend x inherent risk / 100 ("spend at risk", USD a month) - what the
  account ranking sorts by, so the accounts that matter most to an exit come first.

Spend weighting lets one huge account (say a contact centre on Connect) dominate, so the report
always gives a second headline score **by number of accounts** ("equal": one account, one vote)
plus counts of accounts per rating. "balanced" (square root of spend) is a selectable blend.
"""

from __future__ import annotations

import copy
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .catalog import AGENTIC_FACTORS, Catalog, load_catalog
from .estimate import (
    TARGET_LABELS,
    TARGET_PHRASES,
    TYPICAL_COUNTS,
    Questionnaire,
    build_estimate,
    money_range,
    service_effort,
)
from .filtering import AccountFilter
from .issues import Issue
from .resilience import build_resilience
from .timing import MATERIAL_STRANDED, build_timing, owed_range

# Confidence stays High only when the deep scan reached accounts with this share of spend, and
# services missing from the catalog are under this share of spend.
DEEP_SCAN_FULL_PCT = 90.0
UNCLASSIFIED_MAX_PCT = 2.0
RATINGS = [(25, "Low"), (40, "Moderate"), (55, "Elevated"), (70, "High"), (101, "Critical")]

WEIGHTINGS = {
    "spend": ("By spend", lambda m: m),
    "equal": ("By number of accounts", lambda m: 1.0 if m > 0 else 0.0),
    "balanced": ("Blend (square root of spend)", math.sqrt),
}
DEFAULT_WEIGHTING = "spend"
RATING_NAMES = [label for _, label in RATINGS]

# An account counts as exposed to a tier when it spends at least this much a month on it.
MATERIAL_TIER_SPEND = 1.0


def _change(first: float, last: float, months_between: int) -> dict:
    """Spend change from the first to the last complete month, with an annualised rate."""
    pct = 100 * (last - first) / first if first > 0 else None
    annual = 100 * ((last / first) ** (12 / months_between) - 1) if first > 0 and last > 0 and months_between else None
    return {
        "first": round(first, 2),
        "last": round(last, 2),
        "change": round(last - first, 2),
        "pct": round(pct, 1) if pct is not None else None,
        # Annualising a short window magnifies noise; cap so one odd month cannot read as 10,000%.
        "annualised_pct": round(max(min(annual, 999.0), -100.0), 1) if annual is not None else None,
    }


def _growth(months: list[str], trend: dict, cat_trend: dict, cat_lockin: dict, services: list[dict]) -> dict:
    """Spend growth over the scanned period, overall, for lock-in services and by product type.

    Each product type lists the services in it (largest first) and the ones that moved its spend
    most, so a product type's rise names the services behind it.
    """
    if len(months) < 2:
        return {
            "months": len(months),
            "first_month": None,
            "last_month": None,
            "total": None,
            "lockin": None,
            "by_category": [],
        }
    a, b, span = months[0], months[-1], len(months) - 1
    total = _change(sum(trend[a].values()), sum(trend[b].values()), span)
    lockin = _change(trend[a][4] + trend[a][5], trend[b][4] + trend[b][5], span)
    cats = []
    for cat, by_month in cat_trend.items():
        row = _change(by_month.get(a, 0.0), by_month.get(b, 0.0), span)
        spend = sum(by_month.values())
        row.update(
            category=cat,
            monthly=[round(by_month.get(m, 0.0), 2) for m in months],
            lockin_pct=round(100 * cat_lockin.get(cat, 0.0) / spend, 1) if spend else 0.0,
            share_of_growth=round(100 * row["change"] / total["change"], 1) if total["change"] else None,
        )
        members = [s for s in services if s["category"] == cat]
        row["services"] = [s["display"] for s in members]
        # The change split by exit tier, so a hard service inside a mostly easy type stays visible.
        by_tier = {t: 0.0 for t in range(1, 6)}
        for s in members:
            by_tier[s["tier"]] += s.get("last", 0.0) - s.get("first", 0.0)
        row["by_tier"] = {t: round(v, 2) for t, v in by_tier.items()}
        movers = sorted((s for s in members if abs(s.get("change", 0)) >= 1), key=lambda s: -abs(s["change"]))
        row["drivers"] = [
            {k: s[k] for k in ("display", "tier", "first", "last", "change", "change_pct")}
            # For Marketplace, name the products that moved, largest rise first.
            | (
                {"products": [p["name"] for p in sorted(s["products"], key=lambda p: -p.get("change", 0))[:3]]}
                if s.get("products")
                else {}
            )
            for s in movers[:3]
        ]
        cats.append(row)
    cats.sort(key=lambda r: -r["last"])
    return {
        "months": len(months),
        "first_month": a,
        "last_month": b,
        "total": total,
        "lockin": lockin,
        "by_category": cats,
    }


def _round(v: float | None) -> float | None:
    return round(v, 1) if v is not None else None


def rating(score: float | None) -> str:
    """Rate the score as it is displayed (whole number, half up), so "Moderate · 40" cannot happen."""
    if score is None:
        return "n/a"
    score = int(score + 0.5)
    for limit, label in RATINGS:
        if score < limit:
            return label
    return "Critical"


def _weighted_score(amounts: dict[str, float], catalog: Catalog) -> float | None:
    total = sum(amounts.values())
    if total <= 0:
        return None
    return sum(amt * catalog.tier_score(catalog.lookup(s).tier) for s, amt in amounts.items()) / total


@dataclass
class _Spend:
    """In-scope spend from the cost lines, aggregated every way the report needs it."""

    per_account: dict[str, dict[str, float]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(float)))
    trend: dict[str, dict[int, float]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(float)))
    cat_trend: dict[str, dict[str, float]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(float)))
    cat_lockin: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    svc_trend: dict[str, dict[str, float]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(float)))
    # Marketplace: one catalog entry, many third-party products. service -> product -> month -> spend.
    products: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(float))))
    product_accounts: dict[tuple, set] = field(default_factory=lambda: defaultdict(set))
    excluded: float = 0.0
    # Products the Exit model leaves out (catalog service -> spend), and every product with spend in
    # scope, so the console can offer them for exclusion and show what was left out.
    user_excluded: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    offered: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    unclassified: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    negative_lines: int = 0
    negative_amount: float = 0.0


def _aggregate(costs: list[dict], in_scope: dict, catalog: Catalog, leave_out: frozenset[str] = frozenset()) -> _Spend:
    sp = _Spend()
    for r in costs:
        if r["account_id"] not in in_scope:
            continue
        info = catalog.lookup(r["service"])
        if info.excluded:
            sp.excluded += r["amount"]
            continue
        if r["amount"] == 0:
            continue  # Cost Explorer lists free-tier services at exactly zero
        if r["amount"] < 0:
            sp.negative_lines += 1
            sp.negative_amount += r["amount"]
            continue
        sp.offered[info.service] += r["amount"]
        if info.service in leave_out:
            sp.user_excluded[info.service] += r["amount"]
            continue
        # Key by catalog entry so billing lines of one service (Connect, Contact Lens, telephony...)
        # count once for effort and lock-in, not once per line.
        sp.per_account[r["account_id"]][info.service] += r["amount"]
        sp.trend[r["month"]][info.tier] += r["amount"]
        sp.cat_trend[info.category][r["month"]] += r["amount"]
        sp.svc_trend[info.service][r["month"]] += r["amount"]
        if r.get("product"):
            product = r["product"].removesuffix(" (Amazon Bedrock Edition)")
            sp.products[info.service][product][r["month"]] += r["amount"]
            sp.product_accounts[(info.service, product)].add(r["account_id"])
        if info.tier >= 4:
            sp.cat_lockin[info.category] += r["amount"]
        if not info.classified:
            sp.unclassified[r["service"]] += r["amount"]
    return sp


def _left_out(sp: _Spend, n_months: int, catalog: Catalog) -> list[dict]:
    """Products the Exit model left out of the score and estimate, largest first."""
    return [
        {"service": svc, "display": catalog.lookup(svc).display, "monthly_spend": round(amt / n_months, 2)}
        for svc, amt in sorted(sp.user_excluded.items(), key=lambda kv: -kv[1])
    ]


def _product_choices(sp: _Spend, n_months: int, catalog: Catalog) -> list[dict]:
    """Every product with spend in scope, for the Exit model's 'leave out' list, largest first."""
    out = []
    for svc, amt in sorted(sp.offered.items(), key=lambda kv: -kv[1]):
        info = catalog.lookup(svc)
        out.append(
            {
                "service": svc,
                "display": info.display,
                "tier": info.tier,
                "monthly_spend": round(amt / n_months, 2),
                "excluded": svc in sp.user_excluded,
            }
        )
    return out


def _spend_issues(sp: _Spend, n_months: int) -> list[dict]:
    out = [
        Issue(
            "warning",
            "catalog",
            f"'{svc}' is not in the service catalog; scored as Moderate "
            f"(tier 3). {_money(amt / n_months) if amt / n_months >= 1 else 'Under $1'}/month in scope.",
            "Add it to src/exitrisk/data/service_catalog.yaml (see CONTRIBUTING.md).",
            service=svc,
        ).to_dict()
        for svc, amt in sorted(sp.unclassified.items(), key=lambda kv: -kv[1])
    ]
    if sp.negative_lines:
        out.append(
            Issue(
                "info",
                "cost",
                f"{_plural(sp.negative_lines, 'negative cost line')} ({_money(-sp.negative_amount / n_months)}/month: "
                "discounts or credits the record-type filter did not catch) were ignored, so spend is shown "
                "before them",
            ).to_dict()
        )
    return out


def _accounts(
    in_scope: dict,
    sp: _Spend,
    n_months: int,
    catalog: Catalog,
    q: Questionnaire,
    weight_fn,
    inventory: dict,
) -> tuple[list[dict], dict[str, dict]]:
    """One row per in-scope account, ranked by spend at risk, and the per-service totals across them."""
    monthly_of = {aid: sum(sp.per_account.get(aid, {}).values()) / n_months for aid in in_scope}
    total_weight = sum(weight_fn(m) for m in monthly_of.values())
    rows: list[dict] = []
    services: dict[str, dict] = {}
    for aid, acct in in_scope.items():
        svc_totals = sp.per_account.get(aid, {})
        monthly = monthly_of[aid]
        score = _weighted_score(svc_totals, catalog)
        weight = weight_fn(monthly) / total_weight if total_weight else 0.0
        tier_spend = {t: 0.0 for t in range(1, 6)}
        effort_by_tier = {t: 0.0 for t in range(1, 6)}
        agentic_saved = 0.0
        inv_totals = (inventory.get(aid) or {}).get("totals", {})
        top = []
        for svc, amt in svc_totals.items():
            info = catalog.lookup(svc)
            m = amt / n_months
            tier_spend[info.tier] += m
            if m >= q.materiality:
                probe = TYPICAL_COUNTS.get(info.service)
                count = inv_totals.get(probe[0]) if probe else None
                weeks = service_effort(info.effort_weeks, m, count, probe[1] if probe else None)
                if q.ai_agents:
                    agentic_saved += weeks * (1 - AGENTIC_FACTORS[info.agentic])
                    weeks *= AGENTIC_FACTORS[info.agentic]
                effort_by_tier[info.tier] += weeks
            top.append((m, info))
            agg = services.setdefault(
                info.service,
                {
                    "service": info.service,
                    "display": info.display,
                    "category": info.category,
                    "tier": info.tier,
                    "tier_label": catalog.tier_label(info.tier),
                    "classified": info.classified,
                    "agentic": info.agentic,
                    "monthly_spend": 0.0,
                    "accounts": 0,
                },
            )
            agg["monthly_spend"] += m
            agg["accounts"] += 1
        top.sort(key=lambda x: -x[0])
        rows.append(
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
                "spend_at_risk": round(monthly * (score or 0) / 100, 2),
                "tier_spend": {t: round(v, 2) for t, v in tier_spend.items()},
                "high_risk_pct": round(100 * (tier_spend[4] + tier_spend[5]) / monthly, 1) if monthly else 0.0,
                "top_services": [
                    {"service": i.display, "tier": i.tier, "monthly_spend": round(m, 2)} for m, i in top[:5]
                ],
                "top_lockin": [
                    {"service": i.display, "tier": i.tier, "monthly_spend": round(m, 2)} for m, i in top if i.tier >= 4
                ][:3],
                "effort_by_tier": {t: round(v, 2) for t, v in effort_by_tier.items()},
                "effort_weeks": round(sum(effort_by_tier.values()), 1),
                "agentic_saved_weeks": round(agentic_saved, 2),
                "inventory": inv_totals,
            }
        )
    # Rank by criticality (spend x risk): large and hard to move first.
    rows.sort(key=lambda a: (-a["spend_at_risk"], -(a["score"] or 0)))
    for rank, a in enumerate(rows, 1):
        a["rank"] = rank
    return rows, services


def _scores_by_weighting(accounts: list[dict], total_monthly: float) -> dict[str, float | None]:
    """Sum of contributions = weighted mean score across the OU, under each weighting for comparison."""

    def by(fn) -> float | None:
        w = [(fn(a["monthly_spend"]), a["score"] or 0) for a in accounts]
        tw = sum(x for x, _ in w)
        return sum(x * sc for x, sc in w) / tw if tw and total_monthly else None

    return {k: by(fn) for k, (_, fn) in WEIGHTINGS.items()}


def _by_rating(accounts: list[dict], total_monthly: float) -> dict[str, dict]:
    """Breadth: how many accounts sit in each rating, and how much spend they carry."""
    out = {r: {"rating": r, "accounts": 0, "monthly_spend": 0.0} for r in RATING_NAMES}
    for a in accounts:
        if a["score"] is not None:
            out[a["rating"]]["accounts"] += 1
            out[a["rating"]]["monthly_spend"] += a["monthly_spend"]
    rated = sum(b["accounts"] for b in out.values())
    for b in out.values():
        b["monthly_spend"] = round(b["monthly_spend"], 2)
        b["pct_accounts"] = round(100 * b["accounts"] / rated, 1) if rated else 0.0
        b["pct_spend"] = round(100 * b["monthly_spend"] / total_monthly, 1) if total_monthly else 0.0
    return out


def _tiers(accounts: list[dict], services: dict[str, dict], total_monthly: float, catalog: Catalog) -> list[dict]:
    out = []
    for t in range(1, 6):
        spend = sum(a["tier_spend"][t] for a in accounts)
        out.append(
            {
                "tier": t,
                "label": catalog.tier_label(t),
                "score": catalog.tier_score(t),
                "monthly_spend": round(spend, 2),
                "pct": round(100 * spend / total_monthly, 1) if total_monthly else 0.0,
                "services": sum(1 for s in services.values() if s["tier"] == t),
                "accounts": sum(1 for a in accounts if a["tier_spend"][t] >= MATERIAL_TIER_SPEND),
            }
        )
    return out


def _services(services: dict[str, dict], sp: _Spend, months: list[str], n_months: int, total_monthly: float):
    """Services by spend, with first-to-last-month change and, for Marketplace, the products behind them."""
    out = sorted(services.values(), key=lambda s: -s["monthly_spend"])
    first_m, last_m = (months[0], months[-1]) if len(months) >= 2 else (None, None)
    for s in out:
        s["monthly_spend"] = round(s["monthly_spend"], 2)
        s["pct"] = round(100 * s["monthly_spend"] / total_monthly, 2) if total_monthly else 0.0
        if first_m:
            by_month = sp.svc_trend.get(s["service"], {})
            first, last = by_month.get(first_m, 0.0), by_month.get(last_m, 0.0)
            s["first"], s["last"], s["change"] = round(first, 2), round(last, 2), round(last - first, 2)
            s["change_pct"] = round(100 * (last - first) / first, 1) if first > 0 else None
        if s["service"] in sp.products:
            rows = []
            for name, by_month in sp.products[s["service"]].items():
                row = {
                    "name": name,
                    "monthly_spend": round(sum(by_month.values()) / n_months, 2),
                    "accounts": len(sp.product_accounts[(s["service"], name)]),
                }
                if first_m:
                    row["change"] = round(by_month.get(last_m, 0.0) - by_month.get(first_m, 0.0), 2)
                rows.append(row)
            s["products"] = sorted(rows, key=lambda x: -x["monthly_spend"])[:10]
    return out


def _top_rises(services: list[dict]) -> list[dict]:
    """The services whose monthly spend rose most, so growth names its causes."""
    return [
        {
            "display": s["display"],
            "category": s["category"],
            "tier": s["tier"],
            "change": s["change"],
            "product": max(s["products"], key=lambda p: p.get("change", 0))["name"] if s.get("products") else None,
        }
        for s in sorted(services, key=lambda s: -s.get("change", 0))[:3]
        if s.get("change", 0) >= 1
    ]


def build_report(
    scan: dict,
    account_filter: AccountFilter | None = None,
    questionnaire: Questionnaire | None = None,
    catalog: Catalog | None = None,
    weighting: str = DEFAULT_WEIGHTING,
) -> dict:
    if weighting not in WEIGHTINGS:
        raise ValueError(f"weighting must be one of {', '.join(WEIGHTINGS)}")
    catalog = catalog or load_catalog()
    account_filter = account_filter or AccountFilter()
    questionnaire = questionnaire or Questionnaire()

    months_in_data = sorted({r["month"] for r in scan.get("costs", [])})
    n_months = max(len(months_in_data), 1)
    all_accounts = {a["id"]: a for a in scan.get("accounts", [])}
    in_scope = {aid: a for aid, a in all_accounts.items() if account_filter.matches(a["name"])}
    # Keep scan-wide issues, and account issues only for accounts the filter kept.
    issues: list[dict] = [
        i
        for i in scan.get("issues", [])
        if not i.get("account_id") or i["account_id"] in in_scope or i["account_id"] not in all_accounts
    ]

    sp = _aggregate(scan.get("costs", []), in_scope, catalog, frozenset(questionnaire.exclude_services))
    issues += _spend_issues(sp, n_months)
    total_monthly = sum(sum(s.values()) for s in sp.per_account.values()) / n_months
    inventory = scan.get("inventory") or {}
    accounts_out, services_agg = _accounts(
        in_scope, sp, n_months, catalog, questionnaire, WEIGHTINGS[weighting][1], inventory
    )
    scores = _scores_by_weighting(accounts_out, total_monthly)
    ou_score = scores[weighting]
    by_rating = _by_rating(accounts_out, total_monthly)
    tiers = _tiers(accounts_out, services_agg, total_monthly, catalog)
    services_out = _services(services_agg, sp, months_in_data, n_months, total_monthly)

    estimate = build_estimate(questionnaire, accounts_out, total_monthly)
    resilience = build_resilience(scan, accounts_out, questionnaire)
    summary = {
        "score": round(ou_score, 1) if ou_score is not None else None,
        "rating": rating(ou_score),
        "monthly_spend": round(total_monthly, 2),
        "annual_spend": round(total_monthly * 12, 2),
        "accounts_in_scope": len(in_scope),
        "accounts_with_spend": sum(1 for a in accounts_out if a["monthly_spend"] > 0),
        "accounts_excluded": len(all_accounts) - len(in_scope),
        "accounts_total": len(all_accounts),
        "high_risk_pct": round(sum(t["pct"] for t in tiers if t["tier"] >= 4), 1),
        "high_risk_monthly": round(sum(t["monthly_spend"] for t in tiers if t["tier"] >= 4), 2),
        "services": len(services_out),
        "unclassified_services": len(sp.unclassified),
        "unclassified_monthly": round(sum(sp.unclassified.values()) / n_months, 2),
        "excluded_billing_monthly": round(sp.excluded / n_months, 2),
        "excluded_services": _left_out(sp, n_months, catalog),
        "excluded_services_monthly": round(sum(sp.user_excluded.values()) / n_months, 2),
        "top_lockin_services": [s for s in services_out if s["tier"] >= 4][:5],
        # "Bespoke" = AWS-only services (High/Critical tiers) with material spend in scope.
        "bespoke_services": sum(
            1 for s in services_out if s["tier"] >= 4 and s["monthly_spend"] >= MATERIAL_TIER_SPEND
        ),
        "weighting": weighting,
        "weighting_label": WEIGHTINGS[weighting][0],
        "score_by_weighting": {k: _round(v) for k, v in scores.items()},
        "score_by_spend": _round(scores["spend"]),
        "rating_by_spend": rating(scores["spend"]),
        "score_by_accounts": _round(scores["equal"]),
        "rating_by_accounts": rating(scores["equal"]),
        "accounts_rated": sum(b["accounts"] for b in by_rating.values()),
        "accounts_by_rating": list(by_rating.values()),
        "portable_accounts": by_rating["Low"]["accounts"] + by_rating["Moderate"]["accounts"],
        "high_risk_accounts": by_rating["High"]["accounts"] + by_rating["Critical"]["accounts"],
        "high_risk_accounts_spend_pct": round(by_rating["High"]["pct_spend"] + by_rating["Critical"]["pct_spend"], 1),
    }
    growth = _growth(months_in_data, sp.trend, sp.cat_trend, sp.cat_lockin, services_out)
    summary["growth"] = {k: growth[k] for k in ("months", "first_month", "last_month", "total", "lockin")}
    summary["growth"]["top_rises"] = _top_rises(services_out)
    estimate["empty"] = total_monthly <= 0
    if estimate["empty"]:  # nothing to move: no "$0–$0" ranges for a caller to show by mistake
        estimate["ranges"] = dict.fromkeys(estimate["ranges"])
    estimate["provisional"] = not questionnaire.confirmed
    summary["coverage"], summary["coverage_gaps"] = _coverage_notes(
        scan, summary, list(all_accounts.values()), account_filter, issues
    )
    # Deep-scan coverage: the share of in-scope spend in accounts the inventory reached.
    summary["deep_scan_pct"] = (
        round(100 * sum(a["monthly_spend"] for a in accounts_out if a["id"] in inventory) / total_monthly, 1)
        if inventory and total_monthly > 0
        else 0.0
    )
    summary["narrative"] = _narrative(summary, accounts_out, estimate, questionnaire)
    timing = build_timing(scan, estimate, questionnaire)
    summary["executive"] = _executive_summary(
        summary, accounts_out, estimate, questionnaire, scan, bool(inventory), resilience, timing
    )

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
            "period": scan.get("period") or {"months": 1},
            "months_in_data": months_in_data,
            "filter": account_filter.to_dict(),
            "catalog_version": catalog.version,
            "tool_version": __version__,
            "inventory": bool(inventory),
            "target_label": TARGET_LABELS[questionnaire.target],
            "weighting": weighting,
        },
        "summary": summary,
        "tiers": tiers,
        "accounts": accounts_out,
        "services": services_out,
        "product_choices": _product_choices(sp, n_months, catalog),
        "trend": [
            {"month": m, "tier_spend": {t: round(sp.trend[m][t], 2) for t in range(1, 6)}} for m in months_in_data
        ],
        "growth": growth,
        "estimate": estimate,
        "resilience": resilience,
        "timing": timing,
        "issues": issues,
        "issue_counts": {s: sum(1 for i in issues if i.get("severity") == s) for s in sev_order},
    }


def _coverage_notes(
    scan: dict, summary: dict, all_accounts: list, account_filter, issues: list
) -> tuple[list[str], int]:
    """Plain warnings for the top of the report when it covers less than the reader would assume, and
    how many of them are gaps in what the scan could see (services left out on request are not)."""
    notes = []
    if scan.get("status") == "partial":
        n = sum(1 for i in issues if i.get("severity") in ("error", "critical"))
        notes.append(
            f"Partial scan: {_plural(n, 'error')} while scanning, so some data is missing (see Issues). "
            "Fix the cause and run a new scan."
        )
    if scan.get("mode", "live") == "live" and (scan.get("ou") or {}).get("id") == "-":
        org_issue = next((i for i in issues if i.get("category") == "organizations"), None)
        if org_issue:
            notes.append(f"Partial view: {org_issue['message']} {org_issue.get('hint') or ''}".strip())
    if all_accounts and summary["accounts_in_scope"] == 0:
        names = ", ".join(a["name"] for a in all_accounts[:5]) + (" ..." if len(all_accounts) > 5 else "")
        notes.append(
            f"No account matches the filter ({account_filter.to_dict()['description']}). "
            f"The scan holds {_plural(len(all_accounts), 'account')}: {names}. Clear or change the filter."
        )
    gaps = len(notes)
    if summary["excluded_services"]:
        left = _join(s["display"] for s in summary["excluded_services"][:6])
        more = len(summary["excluded_services"]) - 6
        notes.append(
            f"Left out of the score and estimate at your request (Exclusions): {left}"
            + (f" and {more} more" if more > 0 else "")
            + f", {_money(summary['excluded_services_monthly'])}/month."
        )
    return notes, gaps


def _money(v: float, cur: str = "USD") -> str:
    sym = "$" if cur == "USD" else f"{cur} "
    if v >= 1e6:
        return f"{sym}{v / 1e6:,.1f}m"
    if v >= 1e3:
        return f"{sym}{v / 1e3:,.0f}k"
    return f"{sym}{v:,.0f}"


def _plural(n: float, word: str, plural: str | None = None) -> str:
    return f"{n:,.0f} {word if round(n) == 1 else plural or word + 's'}"


def _join(items: list[str]) -> str:
    """'A', 'A and B', 'A, B and C'."""
    items = list(items)
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1] if items else ""


def _month(m: str) -> str:
    """'2025-10' -> 'Oct 2025'."""
    try:
        return datetime.strptime(m, "%Y-%m").strftime("%b %Y")
    except (TypeError, ValueError):
        return str(m)


_NO_SPEND_SUMMARY = {
    "headline": "No in-scope spend was found, so this report cannot rate exit risk.",
    "context": "",
    "bottom_line": "No in-scope spend was found, so this report cannot rate exit risk.",
    "findings": [],
    "findings_rich": [],
    "exit": "",
    "exit_facts": [],
    "actions": ["Widen the account filter or scan an OU that has spend, then re-run the report."],
    "actions_rich": [{"lead": "Widen the scope.", "text": "Change the account filter or scan an OU that has spend."}],
    "confidence": "Low",
    "confidence_reasons": ["No spend in scope."],
    "confidence_steps": [],
}


def _executive_summary(
    summary: dict,
    accounts: list[dict],
    est: dict,
    q: Questionnaire,
    scan: dict,
    deep_scan: bool,
    resilience: dict | None = None,
    timing: dict | None = None,
) -> dict:
    """The one-page brief that opens the report: bottom line, findings, the exit, actions, confidence.

    Findings and actions come in two forms: ``*_rich`` ({lead, text}) for the console, where the lead
    is set in bold, and plain strings for JSON and CLI readers.
    """
    if summary["score"] is None:
        return copy.deepcopy(_NO_SPEND_SUMMARY)
    defaults, empty = not q.confirmed, bool(est.get("empty"))
    headline = _headline(summary, est, defaults)
    context = _context(summary)
    findings = _findings(summary, accounts) + _timing_findings(timing or {}) + _resilience_findings(resilience or {})
    exit_facts, exit_line = _exit(est, q, defaults)
    links = (((resilience or {}).get("data") or {}).get("migration_links") or {}).get("options") or []
    if exit_facts and links:  # not in the one-off cost: say what copying the data adds beside it
        totals = sorted(x["total_cost"] for x in links)
        if totals[-1] >= MATERIAL_STRANDED:
            exit_facts[1]["note"] += (
                f"; copying the data out adds {money_range(totals[0], totals[-1])} (Links for the migration)"
            )
    if exit_facts and (written_off := _written_off(timing or {})):
        exit_facts.insert(2, {**written_off, "provisional": defaults})
    actions = _actions(summary, accounts, defaults, deep_scan, resilience or {}, timing or {})
    confidence, reasons, steps = _confidence(summary, scan, defaults, deep_scan)
    plain = lambda x: f"{x['lead']} {x['text']}"  # noqa: E731
    return {
        "headline": headline,
        "context": context,
        "bottom_line": f"{headline} {context}",
        "findings": [plain(f) for f in findings],
        "findings_rich": findings,
        "exit": exit_line,
        "exit_facts": exit_facts,
        "provisional": defaults and not empty,
        "actions": [plain(a) for a in actions[:5]],
        "actions_rich": actions[:5],
        "confidence": confidence,
        "confidence_reasons": reasons,
        "confidence_steps": steps,
    }


def _headline(s: dict, est: dict, defaults: bool) -> str:
    """Rating, what kind of exit it is, and what it would take: one sentence."""
    # From the rating label, not raw thresholds: 54.6 shows as "High · 55", so it must read as High.
    label, empty = s["rating_by_spend"], est.get("empty")
    if label in ("High", "Critical"):
        kind = "leaving AWS would be a re-engineering programme, not a migration"
    elif label == "Elevated":
        kind = "an exit is feasible but needs significant re-engineering"
    elif ((est.get("cost") or {}).get("pct_of_annual_spend") or 0) >= 50:
        kind = "most workloads are portable, but the size of the estate makes an exit a large programme"
    else:
        kind = "an exit is feasible, and most workloads would move with modest change"
    rg = est.get("ranges", {})
    pct_annual = f" ({rg['pct_of_annual_spend']} of a year's AWS spend)" if rg.get("pct_of_annual_spend") else ""
    # Cost and time only reach the headline once the delivery questions are answered: with default
    # answers they describe a made-up organisation, not this one. Always as ranges, never one figure.
    take = "" if empty or defaults else f": roughly {rg['duration']} and {rg['cost']}{pct_annual}"
    headline = f"Exit risk is {s['rating_by_spend']}. {kind[0].upper() + kind[1:]}{take}."
    if defaults and not empty:
        headline += (
            " Cost and time are not yet estimated for your organisation:"
            " answer the delivery questions under Exit model."
        )
    return headline


def _context(s: dict) -> str:
    """Both scores, and whether risk is concentrated in a few accounts or spread across many."""
    by_spend, by_acc = s["score_by_spend"], s["score_by_accounts"]
    n, port, hi = s["accounts_rated"], s["portable_accounts"], s["high_risk_accounts"]
    lockin = [x["display"] for x in s["top_lockin_services"][:3]]
    gap = by_spend - by_acc
    scores = f"Scores {int(by_spend + 0.5)}/100 by spend and {int(by_acc + 0.5)}/100 by number of accounts."
    if gap >= 5:
        shape = (
            f"Risk is concentrated: {_plural(hi, 'account')} ({s['high_risk_accounts_spend_pct']:.0f}% of spend)"
            + (f", mostly on {_join(lockin)}," if lockin else "")
            + f" {'carries' if hi == 1 else 'carry'} most of it, while {port} of {_plural(n, 'account')} "
            + f"({100 * port / n:.0f}%) {'is' if port == 1 else 'are'} broadly portable."
        )
    elif gap <= -5:
        shape = (
            "Risk is widespread: it sits across many smaller accounts, so the spend view understates how many "
            "workloads need re-engineering."
        )
    else:
        shape = (
            f"Risk is spread in line with spend; {port} of {_plural(n, 'account')} ({100 * port / n:.0f}%) "
            f"{'is' if port == 1 else 'are'} broadly portable."
        )
    return f"{scores} {shape}"


def _findings(s: dict, accounts: list[dict]) -> list[dict]:
    n, port, hi = s["accounts_rated"], s["portable_accounts"], s["high_risk_accounts"]
    # Name the bespoke services with what they cost and how widely they are used, not just a count.
    bespoke = [x for x in s["top_lockin_services"] if x["monthly_spend"] >= MATERIAL_TIER_SPEND]
    named = [
        f"{x['display']} {_money(x['monthly_spend'] * 12)}"
        + (f" a year ({_plural(x['accounts'], 'account')})" if i == 0 else f" ({x['accounts']:,})")
        for i, x in enumerate(bespoke[:3])
    ]
    rest = s["bespoke_services"] - len(named)
    rest_spend = (s["high_risk_monthly"] - sum(x["monthly_spend"] for x in bespoke[:3])) * 12
    findings = [
        {
            "lead": f"{s['high_risk_pct']:.0f}% of spend ({_money(s['high_risk_monthly'] * 12)} a year)",
            "text": f"runs on {_plural(s['bespoke_services'], 'bespoke, AWS-only service')} that must be "
            "re-engineered"
            + (f": {_join(named)}" if named else "")
            + (f"; {_plural(rest, 'other')} {_money(rest_spend)}" if rest > 0 else "")
            + ".",
        },
        {
            "lead": f"{port} of {_plural(n, 'account')} {'is' if port == 1 else 'are'} portable",
            "text": "(Low or Moderate risk)."
            + (
                f" The {_plural(hi, 'High or Critical account')} {'holds' if hi == 1 else 'hold'} "
                f"{s['high_risk_accounts_spend_pct']:.0f}% of spend."
                if hi
                else " None is High or Critical."
            ),
        },
    ]
    top, share = _pace_setters(accounts)
    if top:
        findings.append(
            {
                "lead": f"{len(top)} accounts set the pace:",
                "text": f"{_join([a['name'] for a in top])} carry {share:.0f}% of the spend at risk (spend x risk).",
            }
        )
    growth = _growth_finding(s.get("growth") or {})
    return findings + ([growth] if growth else [])


def _growth_finding(g: dict) -> dict | None:
    if not (g.get("total") and g["total"]["pct"] is not None and g["lockin"]["pct"] is not None):
        return None
    t, lk = g["total"]["pct"], g["lockin"]["pct"]
    rises = [
        (f"{x['product']} via {x['display'].split(' (')[0]}" if x.get("product") else x["display"], x["change"])
        for x in g.get("top_rises", [])
    ]
    pace = "faster than" if lk > t + 1 else "more slowly than" if lk < t - 1 else "in line with"
    verb = lambda v: f"grew {v:.0f}%" if v >= 0 else f"fell {-v:.0f}%"  # noqa: E731
    return {
        "lead": f"Spend {verb(t)}",
        "text": f"from {_month(g['first_month'])} to {_month(g['last_month'])}; High/Critical spend "
        f"{verb(lk)}, so lock-in is growing {pace} the estate."
        + (f" Biggest monthly rises: {_join([f'{x[0]} +{_money(x[1])}' for x in rises])}." if rises else ""),
    }


def _cost_parts(est: dict) -> str:
    """What the one-off cost is made of: hardware only appears for an exit to your own data centre."""
    return "engineering, hardware and parallel running" if est.get("datacenter") else "engineering and parallel running"


def _exit(est: dict, q: Questionnaire, defaults: bool) -> tuple[list[dict], str]:
    """The exit as tiles (window, cost, effort, target) and as one sentence; nothing when there is no spend."""
    if est.get("empty"):
        return [], ""
    rg, target, phrase = est["ranges"], TARGET_LABELS[q.target], TARGET_PHRASES[q.target]
    pct = rg.get("pct_of_annual_spend")
    others = "hardware and parallel running" if est.get("datacenter") else "parallel running"
    facts = [
        {"label": "Exit window", "value": rg["duration"], "note": f"bound by {est['duration']['constrained_by']}"},
        {
            "label": "One-off cost",
            "value": rg["cost"],
            "note": (f"{pct} of a year's AWS spend; " if pct else "") + _cost_parts(est),
        },
        {"label": "Engineering", "value": rg["effort"], "note": "plus " + others},
        {"label": "Target", "value": target, "note": "assumed exit destination"},
    ]
    for f in facts[:3]:
        f["provisional"] = defaults
    line = (
        f"Exit window: roughly {rg['duration']} to move everything to {phrase}. One-off cost: {rg['cost']}"
        + (f", {pct} of a year's AWS spend" if pct else "")
        + f"; {rg['effort']} of engineering plus {others}."
    )
    return facts, line


def _written_off(tm: dict) -> dict | None:
    """Commitments still running when the exit finishes: paid for, no longer used, so written off."""
    c, e = tm.get("commitments") or {}, tm.get("edp") or {}
    if not c.get("stranded") and not e.get("shortfall"):
        return None
    sp, edp = c.get("stranded") or [0, 0], e.get("shortfall") or [0, 0]
    lo, hi = sp[0] + edp[0], sp[1] + edp[1]
    if hi < MATERIAL_STRANDED:
        return {
            "label": "Commitments written off",
            "value": "None",
            "note": "every Savings Plan and reservation ends before the fastest exit finishes",
        }
    parts = [f"{owed_range(*sp)} of Savings Plans and reservations" if sp[1] >= MATERIAL_STRANDED else ""]
    parts.append(f"{owed_range(*edp)} of enterprise discount commitment" if edp[1] >= MATERIAL_STRANDED else "")
    return {
        "label": "Commitments written off",
        "value": owed_range(lo, hi),
        "note": f"still owed once the exit finishes: {_join([x for x in parts if x])}; more if it finishes sooner. "
        "They cover the whole organisation, even when the report is filtered to some accounts",
    }


def _resilience_findings(r: dict) -> list[dict]:
    """Correlated failure: how much of the critical estate one regional event would take down."""
    c, crit = r.get("concentration") or {}, r.get("criticality") or {}
    if not c.get("available") or c["pct"] < 70:
        return []
    who = (
        f"the spend of {_plural(crit['critical_accounts'], 'critical account')}"
        if c["basis"] == "critical"
        else "in-scope spend (no account is marked critical yet)"
    )
    text = f"runs in {c['region_name']}, so one regional event takes down most of it at once."
    if c["no_anti_affinity"]:
        x = c["no_anti_affinity"][0]
        text += f" Channels {_join(x['channels'])} share that region: no anti-affinity between them."
    return [{"lead": f"{c['pct']:.0f}% of {who}", "text": text}]


def _resilience_action(r: dict) -> dict | None:
    st, crit = r.get("stressed_exit") or {}, r.get("criticality") or {}
    none = next((b for b in st.get("buckets", []) if b["key"] == "none"), None)
    if not crit.get("critical_accounts"):
        return {
            "lead": "Tag critical accounts",
            "text": "(Criticality = Tier1 in AWS Organizations, or name them in section 6) so the resilience "
            "view measures the critical estate, not all of it.",
        }
    if none and none["pct"] >= 10:
        return {
            "lead": "Pre-build a stressed-exit fallback",
            "text": f"for the {none['pct']:.0f}% of critical spend on AWS-only services: a stand-in process, a "
            "manual workaround or a warm copy elsewhere, tested before it is needed.",
        }
    return None


def _timing_findings(tm: dict) -> list[dict]:
    """Would the exit meet the deadline, and what would still be owed to AWS when it finishes."""
    out = []
    d, c, e = tm.get("deadline") or {}, tm.get("commitments") or {}, tm.get("edp") or {}
    if d.get("status") in ("at_risk", "misses"):
        out.append(
            {
                "lead": f"The exit {'may not fit' if d['status'] == 'at_risk' else 'does not fit'} the "
                f"{d['months']}-month deadline:",
                "text": f"it takes roughly {tm['duration_range']}"
                + (" on default delivery answers" if tm.get("provisional") else "")
                + ". Start earlier, add capacity, or agree a longer transition.",
            }
        )
    owed = [x for x in (c.get("stranded_range"), e.get("shortfall_range")) if x]
    if not owed and c.get("stressed_range"):
        out.append(
            {
                "lead": f"Leaving in a hurry would still owe AWS {c['stressed_range']}",
                "text": f"in Savings Plans and reservations (the last ends {_month(c['last_end'][:7])}); a planned "
                "exit lets them run off.",
            }
        )
    if owed:
        parts = []
        if c.get("stranded_range"):
            parts.append(f"{c['stranded_range']} of Savings Plans and reservations")
        if e.get("shortfall_range"):
            parts.append(f"{e['shortfall_range']} of enterprise discount commitment")
        out.append(
            {
                "lead": "Commitments outlast the exit:",
                "text": f"{_join(parts)} would still be owed when it finishes, a write-off; the last commitment ends "
                f"{_month(max(x for x in ((c.get('last_end') or '')[:7], e.get('end_month') or '') if x))}.",
            }
        )
    return out


def _timing_action(tm: dict) -> dict | None:
    c = tm.get("commitments") or {}
    buy_by = c.get("buy_by") or {}
    if c.get("stranded_range"):
        return {
            "lead": "Match commitment terms to the exit plan:",
            "text": f"{_money(c['monthly_past_exit'] * 12)} a year of commitments runs past the fastest exit. "
            "Buy new Savings Plans and reservations on terms that end inside the exit window.",
        }
    if "3yr" in buy_by and c.get("available") and not c.get("empty"):
        return {
            "lead": "Keep commitments inside the exit window:",
            "text": f"a 3-year Savings Plan or reservation bought after {_month(buy_by['3yr'][:7])} would outlast "
            "the fastest exit; after that, buy 1-year terms.",
        }
    return None


def _actions(
    s: dict, accounts: list[dict], defaults: bool, deep_scan: bool, resilience: dict, timing: dict
) -> list[dict]:
    top, _ = _pace_setters(accounts)
    lockin = [x["display"] for x in s["top_lockin_services"][:3]]
    actions = []
    if defaults:
        actions.append(
            {
                "lead": "Answer the delivery questions under Exit model",
                "text": "(CI/CD, Terraform, team size, day rate). Until then the cost and time figures use default "
                "answers, not your organisation's.",
            }
        )
    if top and (s["high_risk_accounts"] or s["score_by_spend"] - s["score_by_accounts"] >= 5):
        actions.append(
            {
                "lead": "Plan the hardest accounts first.",
                "text": f"Write and test exit plans for {_join([a['name'] for a in top])}; they drive most of the "
                "cost and the timeline.",
            }
        )
    if lockin:
        actions.append(
            {
                "lead": "Make portability a design criterion",
                "text": f"for new work on {_join(lockin)}: prefer the open-standard alternative in Appendix A "
                "unless the business case says otherwise.",
            }
        )
    for extra in (_resilience_action(resilience), _timing_action(timing)):
        if extra:
            actions.append(extra)
    if not deep_scan:
        actions.append(
            {
                "lead": "Grant the read-only deep-scan role",
                "text": "so the estimate uses resource counts, not spend alone.",
            }
        )
    actions.append(
        {"lead": "Re-run this review quarterly", "text": "and track both scores; a rising score means new lock-in."}
    )
    return actions


# What to do about each reason confidence is below High; "action" names the console control that does it.
_CONFIDENCE_FIX = {
    "demo": ("Scan your own organisation.", "scan"),
    "coverage": ("Fix the access gaps in the note at the top, then scan again.", "scan"),
    "partial_deep": (
        "Deploy the ExitRiskReadOnly role to the accounts the deep scan could not reach (Issues lists them), "
        "then run a new deep scan.",
        "deep",
    ),
    "defaults": ("Answer the delivery questions under Exit model (about ten minutes).", "model"),
    "deep": (
        "Deploy the read-only ExitRiskReadOnly role to every member account (one CloudFormation StackSet, "
        "see IAM_PERMISSIONS.md), then run a new scan with Deep scan ticked.",
        "deep",
    ),
    "catalog": ("Add the missing services to the service catalog (Appendix A lists them).", None),
}


def _confidence(s: dict, scan: dict, defaults: bool, deep_scan: bool) -> tuple[str, list[str], list[dict]]:
    """The confidence level, the reasons it is not higher, and the step that fixes each reason."""
    found, level = [], 3
    if scan.get("mode") == "demo":
        found.append(("demo", "Synthetic demo data."))
        level = 1
    if s.get("coverage_gaps"):
        found.append(("coverage", "Partial coverage of the estate (see the note at the top)."))
        level = min(level, 2)
    if defaults:
        found.append(("defaults", "Cost and time use default delivery answers, not yours."))
        level = min(level, 2)
    if not deep_scan:
        found.append(("deep", "Spend data only; no resource counts."))
        level = min(level, 2)
    elif (s.get("deep_scan_pct") or 0) < DEEP_SCAN_FULL_PCT:
        found.append(("partial_deep", f"The deep scan reached accounts with {s['deep_scan_pct']:.0f}% of spend."))
        level = min(level, 2)
    if s["unclassified_services"]:
        share = 100 * s.get("unclassified_monthly", 0) / s["monthly_spend"] if s["monthly_spend"] else 0
        found.append(
            (
                "catalog",
                f"{_plural(s['unclassified_services'], 'service')} not in the catalog ({share:.1f}% of spend), "
                "scored as tier 3.",
            )
        )
        if share >= UNCLASSIFIED_MAX_PCT:
            level = min(level, 2)
    if not found:
        return "High", ["Full scan, answered questionnaire, every service classified."], []
    steps = [{"key": k, "reason": r, "fix": _CONFIDENCE_FIX[k][0], "action": _CONFIDENCE_FIX[k][1]} for k, r in found]
    return {1: "Low", 2: "Medium", 3: "High"}[level], [r for _, r in found], steps


def _pace_setters(accounts: list[dict]) -> tuple[list[dict], float]:
    """The (up to) three accounts with the most spend at risk and their share of it; empty if fewer than two."""
    at_risk = sum(a["spend_at_risk"] for a in accounts)
    top = [a for a in accounts if a["spend_at_risk"] > 0][:3]
    if len(top) < 2 or not at_risk:
        return [], 0.0
    return top, sum(a["spend_at_risk"] for a in top) / at_risk * 100


def _narrative(summary: dict, accounts: list[dict], est: dict, q: Questionnaire) -> list[str]:
    if summary["score"] is None:
        return ["No in-scope spend was found, so no exit-risk score could be calculated."]
    lines = [
        f"The in-scope estate scores {int(summary['score_by_spend'] + 0.5)}/100 ({summary['rating_by_spend']}) "
        f"for exit difficulty weighted by spend, and {int(summary['score_by_accounts'] + 0.5)}/100 "
        f"({summary['rating_by_accounts']}) counting every account equally, across "
        f"{_plural(summary['accounts_with_spend'], 'account')} spending {_money(summary['annual_spend'])} a year.",
        f"{summary['high_risk_pct']:.0f}% of spend ({_money(summary['high_risk_monthly'] * 12)} a year) runs on "
        "High or Critical services that have no direct equivalent outside AWS and need re-engineering.",
    ]
    n, port, hi = summary["accounts_rated"], summary["portable_accounts"], summary["high_risk_accounts"]
    if n:
        lines.append(
            f"{port} of {_plural(n, 'account')} ({100 * port / n:.0f}%) {'is' if port == 1 else 'are'} Low or "
            "Moderate risk and broadly portable"
            + (
                f"; {hi} ({100 * hi / n:.0f}%) {'is' if hi == 1 else 'are'} High or Critical, holding "
                f"{summary['high_risk_accounts_spend_pct']:.0f}% of spend."
                if hi
                else "; none is High or Critical."
            )
        )
    if summary["top_lockin_services"]:
        names = _join([s["display"] for s in summary["top_lockin_services"][:3]])
        lines.append(f"The largest lock-in exposures are {names}.")
    top, share = _pace_setters(accounts)
    if top:
        lines.append(
            f"{len(top)} accounts ({_join([a['name'] for a in top])}) carry {share:.0f}% of the "
            "spend at risk; they set the pace of any exit."
        )
    if est.get("empty"):
        return lines
    if not q.confirmed:  # as in the headline: default answers describe a made-up organisation
        lines.append(
            "Cost and time are not yet estimated for this organisation: answer the delivery questions under Exit model."
        )
        return lines
    lines.append(
        f"A full exit to {TARGET_PHRASES[q.target]} would take roughly {est['ranges']['duration']} and "
        f"{est['ranges']['effort']}, costing roughly {est['ranges']['cost']} in {_cost_parts(est)}."
    )
    return lines
