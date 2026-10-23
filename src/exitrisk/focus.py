"""Areas of focus: the accounts and programme themes that will decide how the exit goes.

The score and estimate say how big the exit is. This module says where it will go wrong: the
specific accounts whose complexity or risk needs attention, why, and how to tackle each one during
the project (which phase, what to do first). Everything is derived from the report itself, so it
needs no extra AWS calls and stays deterministic: the same scan always gives the same list.

An account becomes an area of focus when one or more concerns apply:

* **platform** - a Critical-tier service with material spend (contact centre, BI, payment HSMs):
  replacing it is a product selection and business change, not a migration;
* **lockin** - most of the account's spend is on AWS-only services;
* **effort** - a large share of the programme's engineering effort sits in this one account;
* **integrations** - many AWS-only integrations (event sources, EventBridge targets, API Gateway);
* **data** - enough stored data that the copy itself takes days or weeks;
* **critical** - marked critical, so the cutover needs a rehearsed fallback;
* **evidence** - material but sized from spend only (no deep scan), so its estimate is weakest;
* **owner** - material but no owner tag, so nobody is accountable for its move.

Accounts are ranked by a composite of their share of the effort, their spend on AWS-only services
and the weight of their concerns. Programme-level themes (a service in many accounts, commitments
running past the exit, unowned spend) follow the accounts.
"""

from __future__ import annotations

MAX_ACCOUNTS = 12
LOCKIN_PCT = 50.0  # share of the account's spend on High/Critical services
PLATFORM_MONTHLY = 1_000.0  # a Critical-tier service at least this big in one account
EFFORT_SHARE = 0.03  # 3% of all account effort in one account (and twice the average)
INTEGRATIONS_HARD = 20
DATA_TB = 50.0
EVIDENCE_TOP = 20  # the biggest accounts by spend should rest on a deep scan
SHARED_ACCOUNTS = 10  # a Moderate-or-harder service in this many accounts is a shared pattern

# Concern weights for ranking, and the phase each concern is dealt with in.
WEIGHT = {
    "platform": 30,
    "critical": 20,
    "integrations": 15,
    "data": 15,
    "lockin": 10,
    "effort": 10,
    "evidence": 8,
    "owner": 5,
}
LEVEL = {"platform": "high", "critical": "high", "integrations": "high", "data": "medium", "lockin": "medium"}
PHASE_ORDER = ("Before mobilisation", "Mobilise", "Wave 1", "Wave 2", "Wave 3", "Cutover")


def _tb(x: float) -> str:
    return f"{x:,.0f} TB" if x >= 10 else f"{x:,.1f} TB"


def _money(x: float) -> str:
    if x >= 1e6:
        return f"${x / 1e6:,.1f}m"
    if x >= 1e3:
        return f"${x / 1e3:,.0f}k"
    return f"${x:,.0f}"


def _wave(row: dict) -> str:
    tiers = [int(t) for t, w in (row.get("effort_by_tier") or {}).items() if w > 0]
    hardest = max(tiers or [max((x["tier"] for x in row.get("top_lockin") or []), default=1)])
    return "Wave 3" if hardest >= 4 else "Wave 2" if hardest == 3 else "Wave 1"


def _concerns(row: dict, ctx: dict) -> list[dict]:
    out = []
    by_display = ctx["by_display"]
    wave = _wave(row)
    platforms = [x for x in row.get("top_lockin") or [] if x["tier"] >= 5 and x["monthly_spend"] >= PLATFORM_MONTHLY]
    for x in platforms[:2]:
        info = by_display.get(x["service"])
        out.append(
            {
                "key": "platform",
                "title": f"{x['service']}: no like-for-like target",
                "detail": f"{_money(x['monthly_spend'])} a month on a Critical-tier service. "
                + (info.why if info and info.why else "")
                + (f" Typical duration {info.duration}." if info and info.duration else ""),
                "action": (info.migration if info and info.migration else "Choose the target first.")
                + " Decide the target design during mobilisation: it is the long pole of this account.",
                "phase": "Mobilise",
            }
        )
    if row.get("critical"):
        out.append(
            {
                "key": "critical",
                "title": "Critical service",
                "detail": "Marked critical"
                + (f" ({row['critical_source']})" if row.get("critical_source") else "")
                + ": an outage during cutover is a regulatory incident.",
                "action": "Move it last in its wave, after a rehearsed cutover and rollback; run in parallel until the "
                "target has passed a failover test, and agree the notification with the regulator up front.",
                "phase": "Cutover",
            }
        )
    hard = row.get("integrations_hard") or 0
    if hard >= INTEGRATIONS_HARD:
        out.append(
            {
                "key": "integrations",
                "title": f"{hard:,} AWS-only integrations",
                "detail": f"{row.get('integrations', hard):,} integrations found by the dependency scan, "
                f"{hard:,} of them "
                "between AWS-only services (event sources, EventBridge targets, API Gateway, Step Functions).",
                "action": "Map the event flows with the team early, and put a portable messaging layer (Kafka, "
                "CloudEvents over HTTP) between producers and consumers before moving either side.",
                "phase": "Wave 1",
            }
        )
    data_tb = row.get("data_tb") or 0
    if data_tb >= DATA_TB:
        days = data_tb * 1e3 / (0.8 * 86400)  # one 10 Gbps link at 80%: 1 GB/s
        copy = f"{days:,.0f} days" if days >= 2 else "a day or two"
        out.append(
            {
                "key": "data",
                "title": f"{_tb(data_tb)} of data to move",
                "detail": f"About {copy} of copy on one 10 Gbps link, before any change-data capture and validation.",
                "action": "Start the bulk copy early in the programme and keep it in sync with change-data "
                f"capture, so the {wave} cutover only moves the last changes. Prune and archive first.",
                "phase": "Wave 1",
            }
        )
    lockin = row.get("high_risk_pct") or 0
    if lockin >= LOCKIN_PCT and not platforms:
        names = ", ".join(x["service"] for x in (row.get("top_lockin") or [])[:3])
        out.append(
            {
                "key": "lockin",
                "title": f"{lockin:.0f}% of spend on AWS-only services",
                "detail": f"Mostly {names}." if names else "Most of the spend is on High or Critical services.",
                "action": "Treat it as a re-architecture, not a rehost: design the target first and prove it with one "
                "workload before planning the rest.",
                "phase": wave,
            }
        )
    share = (row.get("effort_weeks") or 0) / ctx["effort_total"] if ctx["effort_total"] else 0
    if share >= max(EFFORT_SHARE, 2 / ctx["accounts"]):  # and at least twice the average account
        out.append(
            {
                "key": "effort",
                "title": f"{share * 100:.0f}% of the programme's effort",
                "detail": f"About {row['effort_weeks']:,.0f} engineer-weeks in this one account.",
                "action": "Give it a dedicated squad with the account's own engineers, and split it into workloads "
                "that can move separately.",
                "phase": wave,
            }
        )
    if not row.get("deep_scanned") and ctx["selective"] and row["id"] in ctx["top_spend"]:
        out.append(
            {
                "key": "evidence",
                "title": "Sized from spend only",
                "detail": "One of the largest accounts, but no resource inventory was read, so its effort is the "
                "weakest figure in the plan.",
                "action": "Run a dependency scan on it (New scan, Dependency scan, only material accounts) before "
                "the plan is committed.",
                "phase": "Before mobilisation",
            }
        )
    if not (row.get("owner") or row.get("executive")) and ctx["owners_tagged"]:
        out.append(
            {
                "key": "owner",
                "title": "No owner",
                "detail": "No owner or executive tag, so nobody is accountable for this account's move.",
                "action": "Name an accountable owner before mobilisation (and tag the account).",
                "phase": "Before mobilisation",
            }
        )
    for c in out:
        c["level"] = LEVEL.get(c["key"], "low")
    return out


def _themes(summary: dict, accounts: list[dict], services: list[dict], resilience: dict, timing: dict) -> list[dict]:
    out = []
    shared = [s for s in services if s["tier"] >= 3 and s.get("accounts", 0) >= SHARED_ACCOUNTS and s["effort_weeks"]]
    shared.sort(key=lambda s: -s["effort_weeks"])
    if shared:
        names = ", ".join(f"{s['display']} ({s['accounts']} accounts)" for s in shared[:4])
        out.append(
            {
                "key": "shared",
                "title": "The same services in many accounts",
                "detail": f"In the most accounts, by effort: {names}. Solving each once, as a pattern, is cheaper than "
                "solving it per account.",
                "action": "Build a migration factory: a reference target, tooling and runbook per service, proven in "
                "one account, then reused. Most of the repeat discount in the estimate depends on it.",
                "phase": "Mobilise",
            }
        )
    platforms = [s for s in services if s["tier"] >= 5 and s["monthly_spend"] >= PLATFORM_MONTHLY]
    if platforms:
        out.append(
            {
                "key": "platforms",
                "title": "Critical-tier services set the critical path",
                "detail": f"{', '.join(s['display'] for s in platforms[:5])}: no like-for-like target, so each needs "
                "a target decision (a product, or a redesign) before any build starts.",
                "action": "Start each decision in the first quarter with the business owner: product selection, "
                "contracts, data-model redesign and retention rules usually take longer than the build.",
                "phase": "Mobilise",
            }
        )
    d = resilience.get("data") or {}
    if d.get("available") and not d.get("empty") and d.get("move_tb", 0) >= DATA_TB:
        o = (d.get("migration_links") or {}).get("options") or []
        quick = f" {o[-1]['days']:,.0f} to {o[0]['days']:,.0f} days on new links." if o else ""
        out.append(
            {
                "key": "data",
                "title": f"{_tb(d['move_tb'])} of data to move",
                "detail": f"Live and archived data across the estate.{quick}",
                "action": "Order the links in mobilisation (carrier lead times run to months), and agree retention "
                "first: data that can be deleted or left archived does not need to move.",
                "phase": "Mobilise",
            }
        )
    c = (timing or {}).get("commitments") or {}
    stranded = c.get("stranded") or [0, 0]
    if c.get("available") and stranded[1]:
        out.append(
            {
                "key": "commitments",
                "title": "Commitments run past the exit",
                "detail": f"{c.get('stranded_range') or _money(stranded[1])} of Savings Plans and reservations is "
                "still owed when the exit is due to finish.",
                "action": "Stop buying 3-year terms now and let the rest run off; buy 1-year terms only before "
                f"{(c.get('buy_by') or {}).get('1yr', 'the buy-by date')}.",
                "phase": "Before mobilisation",
            }
        )
    owners = resilience.get("owners") or {}
    with_spend, tagged = owners.get("accounts_with_spend", 0), owners.get("tagged_accounts", 0)
    if with_spend and tagged < with_spend:
        out.append(
            {
                "key": "ownership",
                "title": f"{with_spend - tagged:,} of {with_spend:,} accounts have no owner",
                "detail": f"{_money(owners.get('untagged_monthly', 0))} a month runs in accounts with no owner or "
                "executive tag.",
                "action": "Tag an owner on every account (AWS Organizations tags) before planning waves; the wave "
                "plan is agreed with owners, not with accounts.",
                "phase": "Before mobilisation",
            }
        )
    depth = summary.get("scan_depth", "quick")
    if depth != "dependency":
        out.append(
            {
                "key": "evidence",
                "title": "The estimate rests on "
                + ("billing data only" if depth == "quick" else "resource counts without integrations"),
                "detail": f"{summary.get('deep_scan_pct', 0):.0f}% of spend was deep scanned. Integrations between "
                "services drive most of the hard work and are not yet counted.",
                "action": "Run a dependency scan on the material accounts (New scan, Dependency scan) before "
                "committing a budget; the cost and time ranges narrow when it has run.",
                "phase": "Before mobilisation",
            }
        )
    return out


def build_focus(
    summary: dict, accounts: list[dict], services: list[dict], resilience: dict, timing: dict, catalog
) -> dict:
    """Accounts that need attention, each with concerns and how to tackle them, plus programme themes."""
    spending = [a for a in accounts if a["monthly_spend"] > 0]
    by_spend = sorted(spending, key=lambda a: -a["monthly_spend"])
    ctx = {
        "by_display": {s.display: s for s in catalog.services},
        "accounts": len(spending) or 1,
        "effort_total": sum(a.get("effort_weeks") or 0 for a in spending),
        "top_spend": {a["id"] for a in by_spend[:EVIDENCE_TOP]},
        "owners_tagged": (resilience.get("owners") or {}).get("tagged_accounts", 0) > 0,
        # Per-account "sized from spend only" only when some accounts were deep scanned; otherwise it is a theme.
        "selective": summary.get("deep_scan_pct", 0) > 0,
    }
    max_effort = max((a.get("effort_weeks") or 0 for a in spending), default=0) or 1
    max_risk = max((a.get("spend_at_risk") or 0 for a in spending), default=0) or 1
    rows = []
    for a in spending:
        concerns = _concerns(a, ctx)
        # Owner and evidence gaps alone do not make an account an area of focus: they are themes.
        if not any(c["key"] not in ("owner", "evidence") for c in concerns):
            continue
        priority = (
            40 * (a.get("effort_weeks") or 0) / max_effort
            + 30 * (a.get("spend_at_risk") or 0) / max_risk
            + sum(WEIGHT[c["key"]] for c in concerns)
        )
        concerns.sort(key=lambda c: (PHASE_ORDER.index(c["phase"]), -WEIGHT[c["key"]]))
        rows.append(
            {
                "id": a["id"],
                "name": a["name"],
                "ou_path": a.get("ou_path", ""),
                "monthly_spend": a["monthly_spend"],
                "rating": a.get("rating"),
                "score": a.get("score"),
                "effort_weeks": a.get("effort_weeks") or 0,
                "critical": bool(a.get("critical")),
                "owner": a.get("owner") or a.get("executive") or "",
                "wave": _wave(a),
                "priority": round(priority, 1),
                "level": "high" if any(c["level"] == "high" for c in concerns) else "medium",
                "concerns": concerns,
            }
        )
    rows.sort(key=lambda r: -r["priority"])
    top = rows[:MAX_ACCOUNTS]
    counts: dict[str, int] = {}
    for r in rows:
        for c in r["concerns"]:
            counts[c["key"]] = counts.get(c["key"], 0) + 1
    return {
        "accounts": top,
        "accounts_total": len(rows),
        "effort_pct": round(100 * sum(r["effort_weeks"] for r in top) / ctx["effort_total"], 1)
        if ctx["effort_total"]
        else 0.0,
        "spend_pct": round(100 * sum(r["monthly_spend"] for r in top) / sum(a["monthly_spend"] for a in spending), 1)
        if spending
        else 0.0,
        "concern_counts": counts,
        "themes": _themes(summary, accounts, services, resilience, timing),
    }
