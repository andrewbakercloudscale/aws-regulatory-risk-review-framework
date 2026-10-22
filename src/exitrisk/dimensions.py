"""Exit difficulty measured on its own terms: three headline measures and five dimensions.

Spend answers "how exposed are we?" (financial concentration, commitments, exit economics). It does
not answer "how hard is it to leave?". This module reports that separately, so neither hides the
other:

* three measures: **technical portability** (0-100, weighted by engineering effort, not spend),
  **exit effort** (engineer-days) and **exit window** (months);
* five dimensions kept visible on their own: service portability, dependency complexity, data
  gravity, engineering effort and operational criticality;
* **critical-account readiness**, so many easy moves cannot hide one immovable critical account;
* the **scan depth** each figure rests on: billing only, resource inventory, or dependencies.
"""

from __future__ import annotations

from .collectors.dependencies import EDGE_SOURCES, NOT_DISCOVERED
from .estimate import COST_RANGE, count_range

SCAN_DEPTHS = {
    "quick": "Quick scan (billing only)",
    "inventory": "Inventory scan (resource counts)",
    "dependency": "Dependency scan (resources and integrations)",
}
# Critical-account readiness: portability at or above READY is broadly movable; below HARD it is not.
READY, HARD = 60.0, 40.0
DAYS_PER_WEEK = 5


def scan_depth(inventory: dict) -> str:
    if not inventory:
        return "quick"
    return "dependency" if any("dependencies" in v for v in inventory.values()) else "inventory"


def _portability(by_tier: dict, tier_score) -> float | None:
    total = sum(by_tier.values())
    if total <= 0:
        return None
    return round(100 - sum(w * tier_score(int(t)) for t, w in by_tier.items()) / total, 1)


def _pct(part: float, whole: float) -> float:
    return round(100 * part / whole, 1) if whole else 0.0


def _integrations(accounts: list[dict], inventory: dict, catalog) -> dict:
    """Totals across the dependency-scanned accounts, the most common kinds, and what was not seen."""
    from .resource_effort import integration_days

    edges: dict[str, int] = {}
    kinds: set[str] | None = None
    scanned = 0
    for a in accounts:
        inv = inventory.get(a["id"]) or {}
        if "dependencies" not in inv:
            continue
        scanned += 1
        for e, n in inv["dependencies"].items():
            edges[e] = edges.get(e, 0) + n
        got = set(inv.get("dependency_kinds") or [])
        kinds = got if kinds is None else kinds & got
    rows = integration_days(edges, catalog)
    return {
        "measured": scanned > 0,
        "accounts": scanned,
        "total": sum(r["count"] for r in rows),
        "hard": sum(r["count"] for r in rows if r["tier"] >= 4),
        "top": [{**{k: r[k] for k in ("edge", "count", "tier")}, "label": edge_label(r["edge"])} for r in rows[:8]],
        "sources": [EDGE_SOURCES[k] for k in sorted(kinds or [])],
        "missing_sources": [v for k, v in EDGE_SOURCES.items() if scanned and k not in (kinds or set())],
        "not_discovered": NOT_DISCOVERED,
    }


_EDGE_NAMES = {
    "lambda": "Lambda",
    "sqs": "SQS",
    "sns": "SNS",
    "dynamodb": "DynamoDB",
    "kinesis": "Kinesis",
    "eventbridge": "EventBridge",
    "stepfunctions": "Step Functions",
    "apigateway": "API Gateway",
    "msk": "MSK",
    "kafka": "Kafka",
    "s3": "S3",
    "http": "HTTP endpoint",
    "email": "e-mail",
    "sms": "SMS",
    "mobile": "mobile push",
}


def edge_label(edge: str) -> str:
    """'sqs>lambda' -> 'SQS to Lambda'."""
    src, _, dst = edge.partition(">")
    return f"{_EDGE_NAMES.get(src, src)} to {_EDGE_NAMES.get(dst, dst)}"


def _readiness(a: dict, factor: float) -> dict:
    blockers = a.get("blockers", [])
    p = a.get("portability")
    if p is None:
        status = "Not estimated"
    elif p < HARD or blockers:
        status = "Hard to move"
    elif p < READY:
        status = "Needs work"
    else:
        status = "Ready"
    return {
        "id": a["id"],
        "name": a["name"],
        "portability": p,
        "status": status,
        "effort_days": round(a["effort_weeks"] * factor * DAYS_PER_WEEK),
        "integrations": a.get("integrations", 0) if a.get("dependency_scanned") else None,
        "integrations_hard": a.get("integrations_hard", 0) if a.get("dependency_scanned") else None,
        "data_tb": a.get("data_tb"),
        "blockers": blockers,
        "lockin": [s["service"] for s in a.get("top_lockin", [])],
        "monthly_spend": a["monthly_spend"],
    }


def build_dimensions(
    summary: dict, accounts: list[dict], estimate: dict, resilience: dict, inventory: dict, catalog
) -> dict:
    """Everything the dashboard needs for the measures, dimensions and critical readiness."""
    by_tier = {t: sum(a["effort_by_tier"][t] for a in accounts) for t in range(1, 6)}
    effort = sum(by_tier.values())
    basis = {k: sum(a["effort_basis"][k] for a in accounts) for k in ("resources", "integrations", "spend")}
    portability = _portability(by_tier, catalog.tier_score)
    depth = scan_depth(inventory)
    integrations = _integrations(accounts, inventory, catalog)
    factor = (estimate.get("factors") or {}).get("combined", 1.0)
    empty = estimate.get("empty") or not effort

    total_weeks = estimate["effort"]["total_weeks"]
    days = (total_weeks * DAYS_PER_WEEK * COST_RANGE[0], total_weeks * DAYS_PER_WEEK * COST_RANGE[1])
    effort_range = None if empty else count_range(*days) + " engineer-days"
    measures = {
        "portability": {
            "score": portability,
            # The same bands as the exit-risk score, read the other way round.
            "rating": _difficulty(portability),
            "basis": "effort" if not empty else None,
        },
        "effort": {"range": effort_range, "low_days": round(days[0]), "high_days": round(days[1])},
        "duration": (estimate.get("ranges") or {}).get("duration"),
        "provisional": estimate.get("provisional", True),
        "basis_pct": {k: _pct(v, effort) for k, v in basis.items()},
    }

    crit = [a for a in accounts if a.get("critical")]
    readiness = sorted(
        (_readiness(a, factor) for a in crit), key=lambda r: (r["portability"] is None, r["portability"] or 0)
    )
    data = resilience.get("data") or {}
    hard_pct = _pct(by_tier[4] + by_tier[5], effort)

    dims = [
        {
            "key": "portability",
            "label": "Service portability",
            "measured": portability is not None,
            "value": f"{portability:.0f}/100" if portability is not None else "n/a",
            "detail": f"{hard_pct:.0f}% of the work is on High or Critical (AWS-only) services",
            "evidence": "Service catalog tiers, weighted by engineering effort rather than spend",
        },
        {
            "key": "dependencies",
            "label": "Dependency complexity",
            "measured": integrations["measured"],
            "value": f"{integrations['total']:,} integrations" if integrations["measured"] else "Not measured",
            "detail": (
                "most: "
                + ", ".join(f"{t['label']} ({t['count']:,})" for t in integrations["top"][:2])
                + f"; {integrations['accounts']} account{'s' if integrations['accounts'] != 1 else ''} scanned"
                if integrations["measured"] and integrations["top"]
                else "None found in the scanned accounts; undiscovered is not the same as independent"
                if integrations["measured"]
                else "Run a dependency scan to count the integrations between services"
            ),
            "evidence": "Declared configuration: event source mappings, rule targets, subscriptions, "
            "API integrations, workflow tasks",
        },
        {
            "key": "data",
            "label": "Data gravity",
            "measured": bool(data.get("available") and not data.get("empty")),
            "value": f"{data['move_tb']:,.0f} TB to move" if data.get("available") and not data.get("empty") else "n/a",
            "detail": (
                f"{data.get('dynamodb_tb', 0):,.0f} TB in DynamoDB, {data.get('critical_tb', 0):,.0f} TB in "
                "critical accounts"
                if data.get("available") and not data.get("empty")
                else data.get("reason") or "No stored data found"
            ),
            "evidence": "Cost Explorer storage usage (GB-months); no data is read",
        },
        {
            "key": "effort",
            "label": "Engineering effort",
            "measured": not empty,
            "value": effort_range or "n/a",
            "detail": (
                f"{measures['basis_pct']['resources']:.0f}% sized from counted resources, "
                f"{measures['basis_pct']['integrations']:.0f}% integration redesign, "
                f"{measures['basis_pct']['spend']:.0f}% sized from spend"
                if not empty
                else "No spend in scope"
            ),
            "evidence": "Resource inventory where deep-scanned, otherwise the catalog sized by spend",
        },
        {
            "key": "criticality",
            "label": "Operational criticality",
            "measured": bool(crit),
            "value": f"{len(crit)} critical account{'s' if len(crit) != 1 else ''}" if crit else "Not classified",
            "detail": (
                f"Least ready: {readiness[0]['name']} ({readiness[0]['status'].lower()})"
                if readiness
                else "Tag accounts with Criticality, or name them under Exit model: infrastructure cannot tell"
            ),
            "evidence": "Account tags or your list; a business judgement, not inferred from resources",
        },
    ]
    return {
        "scan_depth": depth,
        "scan_depth_label": SCAN_DEPTHS[depth],
        "measures": measures,
        "dimensions": dims,
        "integrations": integrations,
        "critical_readiness": readiness,
        "effort_by_tier": {t: round(w * factor, 1) for t, w in by_tier.items()},
    }


def _difficulty(portability: float | None) -> str | None:
    from .scoring import rating

    return None if portability is None else rating(100 - portability)


def hard_part(summary: dict, tiers: list[dict], dims: dict, money) -> str | None:
    """'The estate costs $X a month. The hard part of leaving is not ...' when there is evidence for it."""
    if not summary["monthly_spend"]:
        return None
    parts = []
    crit = [r for r in dims["critical_readiness"] if r["status"] == "Hard to move"]
    if crit:
        parts.append(f"{len(crit)} critical account{'s that are' if len(crit) != 1 else ' that is'} hard to move")
    if dims["integrations"]["measured"] and dims["integrations"]["total"]:
        parts.append(f"{dims['integrations']['total']:,} AWS-specific integrations")
    data = next((d for d in dims["dimensions"] if d["key"] == "data"), None)
    if data and data["measured"]:
        parts.append(data["value"].replace(" to move", " of data to move"))
    if not parts:
        return None
    portable = sum(t["monthly_spend"] for t in tiers if t["tier"] <= 2)
    joined = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
    return (
        f"The estate costs {money(summary['monthly_spend'])} a month. The hard part of leaving is not the "
        f"{money(portable)} a month on portable services; it is {joined}."
    )
