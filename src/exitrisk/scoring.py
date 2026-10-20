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
from .catalog import Catalog, load_catalog
from .estimate import TARGET_LABELS, TYPICAL_COUNTS, Questionnaire, build_estimate, service_effort
from .filtering import AccountFilter
from .issues import Issue

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
    unclassified: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    negative_lines: int = 0


def _aggregate(costs: list[dict], in_scope: dict, catalog: Catalog) -> _Spend:
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
                f"{_plural(sp.negative_lines, 'negative cost line')} (credits/refunds not caught "
                "by the record-type filter) were ignored",
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
        inv_totals = (inventory.get(aid) or {}).get("totals", {})
        top = []
        for svc, amt in svc_totals.items():
            info = catalog.lookup(svc)
            m = amt / n_months
            tier_spend[info.tier] += m
            if m >= q.materiality:
                probe = TYPICAL_COUNTS.get(info.service)
                count = inv_totals.get(probe[0]) if probe else None
                effort_by_tier[info.tier] += service_effort(info.effort_weeks, m, count, probe[1] if probe else None)
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

    sp = _aggregate(scan.get("costs", []), in_scope, catalog)
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
        "excluded_billing_monthly": round(sp.excluded / n_months, 2),
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
    summary["coverage"] = _coverage_notes(scan, summary, list(all_accounts.values()), account_filter, issues)
    summary["narrative"] = _narrative(summary, accounts_out, estimate, questionnaire)
    summary["executive"] = _executive_summary(summary, accounts_out, estimate, questionnaire, scan, bool(inventory))

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
        "trend": [
            {"month": m, "tier_spend": {t: round(sp.trend[m][t], 2) for t in range(1, 6)}} for m in months_in_data
        ],
        "growth": growth,
        "estimate": estimate,
        "issues": issues,
        "issue_counts": {s: sum(1 for i in issues if i.get("severity") == s) for s in sev_order},
    }


def _coverage_notes(scan: dict, summary: dict, all_accounts: list, account_filter, issues: list) -> list[str]:
    """Plain warnings for the top of the report when it covers less than the reader would assume."""
    notes = []
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
    return notes


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
}


def _executive_summary(
    summary: dict, accounts: list[dict], est: dict, q: Questionnaire, scan: dict, deep_scan: bool
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
    findings = _findings(summary, accounts)
    exit_facts, exit_line = _exit(est, q, defaults)
    actions = _actions(summary, accounts, defaults, deep_scan)
    confidence, reasons = _confidence(summary, scan, defaults, deep_scan)
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
    }


def _headline(s: dict, est: dict, defaults: bool) -> str:
    """Rating, what kind of exit it is, and what it would take: one sentence."""
    by_spend, empty = s["score_by_spend"], est.get("empty")
    if by_spend >= 55:
        kind = "leaving AWS would be a re-engineering programme, not a migration"
    elif by_spend >= 40:
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
            " Cost and time are not yet estimated for your organisation: answer the delivery questions in section 5."
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


def _exit(est: dict, q: Questionnaire, defaults: bool) -> tuple[list[dict], str]:
    """The exit as tiles (window, cost, effort, target) and as one sentence; nothing when there is no spend."""
    if est.get("empty"):
        return [], ""
    rg, target = est["ranges"], TARGET_LABELS[q.target]
    pct = rg.get("pct_of_annual_spend")
    facts = [
        {"label": "Exit window", "value": rg["duration"], "note": f"bound by {est['duration']['constrained_by']}"},
        {
            "label": "One-off cost",
            "value": rg["cost"],
            "note": (f"{pct} of a year's AWS spend; " if pct else "") + "engineering and parallel running",
        },
        {"label": "Engineering", "value": rg["effort"], "note": "plus parallel running"},
        {"label": "Target", "value": target, "note": "assumed exit destination"},
    ]
    for f in facts[:3]:
        f["provisional"] = defaults
    line = (
        f"Exit window: roughly {rg['duration']} to move everything to {target}. One-off cost: {rg['cost']}"
        + (f", {pct} of a year's AWS spend" if pct else "")
        + f"; {rg['effort']} of engineering plus parallel running."
    )
    return facts, line


def _actions(s: dict, accounts: list[dict], defaults: bool, deep_scan: bool) -> list[dict]:
    top, _ = _pace_setters(accounts)
    lockin = [x["display"] for x in s["top_lockin_services"][:3]]
    actions = []
    if defaults:
        actions.append(
            {
                "lead": "Answer the delivery questions in section 5",
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


def _confidence(s: dict, scan: dict, defaults: bool, deep_scan: bool) -> tuple[str, list[str]]:
    reasons, level = [], 3
    if scan.get("mode") == "demo":
        reasons.append("Synthetic demo data.")
        level = 1
    if s["coverage"]:
        reasons.append("Partial coverage of the estate (see the note at the top).")
        level = min(level, 2)
    if defaults:
        reasons.append("Cost and time use default delivery answers, not yours.")
        level = min(level, 2)
    if not deep_scan:
        reasons.append("Spend data only; no resource counts.")
        level = min(level, 2)
    if s["unclassified_services"]:
        reasons.append(f"{_plural(s['unclassified_services'], 'service')} not in the catalog, scored as Moderate.")
    if not reasons:
        reasons.append("Full scan, answered questionnaire, every service classified.")
    return {1: "Low", 2: "Medium", 3: "High"}[level], reasons


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
    lines.append(
        f"A full exit to {TARGET_LABELS[q.target]} would take roughly {est['ranges']['duration']} and "
        f"{est['ranges']['effort']}, costing roughly {est['ranges']['cost']} in engineering and parallel running."
    )
    return lines
