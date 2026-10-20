"""Resilience view: which accounts are critical, how much data would move, how concentrated the
critical estate is, and what could move in a hurry.

The exit score answers "how hard is a planned exit". Regulators also ask two harder questions:
what happens to critical services when the provider (or one region) fails, and what could be
moved under stress, in weeks rather than years. This module answers them from the same scan:

* criticality comes from account tags (``Criticality: Tier1``) or name patterns the user gives;
* data held comes from Cost Explorer storage usage (GB-months), not from reading any data;
* concentration is the share of critical spend in its dominant region (correlated failure);
* the stressed exit splits critical spend by how fast its services could be rehosted.

Every figure here is an insight, not part of the exit score or the cost estimate. See
docs/METHODOLOGY.md, "Resilience".
"""

from __future__ import annotations

import math
import re
from collections import defaultdict

from .estimate import Questionnaire
from .multiregion import GLOBAL_REGIONS, load_region_data

# Tag keys are compared lowercased with spaces, dashes and underscores removed.
CRITICALITY_KEYS = ("criticality", "businesscriticality", "tier", "servicetier", "workloadtier", "critical")
CHANNEL_KEYS = ("channel", "businesschannel", "customerchannel")
# Tag values (lowercased, letters and digits only) that mark an account as critical.
CRITICAL_VALUES = {
    "critical",
    "tier1",
    "t1",
    "1",
    "tier0",
    "t0",
    "0",
    "missioncritical",
    "businesscritical",
    "cif",
    "criticalorimportant",
    "p1",
    "high",
    "gold",
    "platinum",
    "true",
    "yes",
}

# Data transfer for the sizing: the link speed is the user's, half of it is assumed usable.
LINK_EFFICIENCY = 0.5
# AWS waives data transfer out for customers leaving AWS, once approved, for transfers completed
# within 60 days: https://aws.amazon.com/blogs/aws/free-data-transfer-out-to-internet-when-moving-out-of-aws/
EXIT_CREDIT_DAYS = 60
# List-price internet egress if the credit does not apply, USD per GB (volume tiers to Cape Town rates).
EGRESS_PER_GB = (0.05, 0.15)
# DynamoDB import from S3 takes up to 15 TB per job in these regions and 1 TB elsewhere.
DYNAMODB_BIG_IMPORT_REGIONS = ("us-east-1", "us-west-2", "eu-west-1")

# Cost Explorer usage-type prefixes. No prefix means us-east-1.
USAGE_PREFIX_REGIONS = {
    "AFS1": "af-south-1",
    "APE1": "ap-east-1",
    "APN1": "ap-northeast-1",
    "APN2": "ap-northeast-2",
    "APN3": "ap-northeast-3",
    "APS1": "ap-southeast-1",
    "APS2": "ap-southeast-2",
    "APS3": "ap-south-1",
    "APS4": "ap-southeast-3",
    "APS5": "ap-south-2",
    "APS6": "ap-southeast-4",
    "CAN1": "ca-central-1",
    "CPT": "af-south-1",
    "EU": "eu-west-1",
    "EUC1": "eu-central-1",
    "EUC2": "eu-central-2",
    "EUN1": "eu-north-1",
    "EUS1": "eu-south-1",
    "EUS2": "eu-south-2",
    "EUW2": "eu-west-2",
    "EUW3": "eu-west-3",
    "ILC1": "il-central-1",
    "MEC1": "me-central-1",
    "MES1": "me-south-1",
    "SAE1": "sa-east-1",
    "USE1": "us-east-1",
    "USE2": "us-east-2",
    "USW1": "us-west-1",
    "USW2": "us-west-2",
}

# How fast spend could move in a stressed exit, by portability tier.
STRESSED_BUCKETS = (
    ("weeks", (1, 2), "Weeks: rehost as is", "Open-standard services: lift and shift to the target."),
    ("months", (3,), "Months: rework", "Managed equivalents exist but need configuration and testing."),
    (
        "none",
        (4, 5),
        "No rapid exit",
        "AWS-only services: needs a pre-built fallback, a manual workaround or a stand-in process.",
    ),
)
STRESSED_ACCOUNT_SHARE = 25.0  # % of an account's spend on tiers 4-5 before it is listed


def _norm(text: str) -> str:
    return re.sub(r"[\s_\-]", "", text.strip().lower())


def _patterns(text: str) -> list[str]:
    return [p.strip().lower() for p in (text or "").split(",") if p.strip()]


def classify(account: dict, patterns: list[str]) -> tuple[bool, str, str]:
    """(critical, source, channel) for an account, from its tags or the user's name patterns."""
    tags = {_norm(k): v for k, v in (account.get("tags") or {}).items()}
    channel = next((tags[k].strip() for k in CHANNEL_KEYS if tags.get(k, "").strip()), "")
    for key in CRITICALITY_KEYS:
        value = re.sub(r"[^a-z0-9]", "", tags.get(key, "").lower())
        if value in CRITICAL_VALUES:
            return True, "tag", channel
    name = account.get("name", "").lower()
    if any(p in name for p in patterns):
        return True, "name", channel
    return False, "", channel


def _tb(gb: float) -> float:
    return round(gb / 1024, 1)


def _days(tb: float, gbps: float) -> float:
    """Days to move ``tb`` terabytes over a ``gbps`` link at LINK_EFFICIENCY."""
    if gbps <= 0:
        return 0.0
    return tb * 1024 * 8 / (gbps * LINK_EFFICIENCY) / 86400


def usage_region(usage_type: str) -> str:
    head = usage_type.split("-", 1)[0] if "-" in usage_type else ""
    if head in USAGE_PREFIX_REGIONS:
        return USAGE_PREFIX_REGIONS[head]
    # An unknown region code (letters then a digit) is kept; anything else is an unprefixed us-east-1 line.
    return head if re.fullmatch(r"[A-Z]{2,4}\d", head) else "us-east-1"


def _region_name(code: str, regions: dict) -> str:
    r = regions.get(code)
    return r["name"] if r else code


def _data(storage: list[dict] | None, rows: dict[str, dict], q: Questionnaire, regions: dict) -> dict:
    if storage is None:
        return {"available": False, "reason": "This scan predates data sizing; run a new scan."}
    by_kind: dict[str, float] = defaultdict(float)
    by_service: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    by_account: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    by_region: dict[str, float] = defaultdict(float)
    dynamo_live: dict[str, float] = defaultdict(float)
    for r in storage:
        if r["account_id"] not in rows:
            continue
        by_kind[r["kind"]] += r["gb"]
        by_service[r["service"]][r["kind"]] += r["gb"]
        by_account[r["account_id"]][r["kind"]] += r["gb"]
        by_region[usage_region(r["usage_type"])] += r["gb"]
        if r["service"] == "Amazon DynamoDB" and r["kind"] == "live":
            dynamo_live[r["account_id"]] += r["gb"]
    total = sum(by_kind.values())
    if not total:
        return {"available": True, "empty": True, "total_tb": 0.0}
    # Copies (snapshots, backups) are rebuilt at the target; live data and archives must move.
    move_tb = _tb(by_kind["live"] + by_kind["archive"])
    days = _days(move_tb, q.transfer_gbps)
    accounts = sorted(
        (
            {
                "id": aid,
                "name": rows[aid]["name"],
                "critical": rows[aid].get("critical", False),
                "live_tb": _tb(k["live"]),
                "copy_tb": _tb(k["copy"]),
                "archive_tb": _tb(k["archive"]),
                "total_tb": _tb(sum(k.values())),
            }
            for aid, k in by_account.items()
        ),
        key=lambda a: -a["total_tb"],
    )
    services = sorted(
        (
            {
                "service": svc,
                "live_tb": _tb(k["live"]),
                "copy_tb": _tb(k["copy"]),
                "archive_tb": _tb(k["archive"]),
                "total_tb": _tb(sum(k.values())),
            }
            for svc, k in by_service.items()
        ),
        key=lambda s: -s["total_tb"],
    )
    region_rows = sorted(
        (
            {"region": c, "name": _region_name(c, regions), "tb": _tb(gb), "pct": round(100 * gb / total, 1)}
            for c, gb in by_region.items()
            if gb >= 50
        ),
        key=lambda x: -x["tb"],
    )
    dynamo_tb = _tb(sum(dynamo_live.values()))
    largest = max(dynamo_live.items(), key=lambda kv: kv[1], default=(None, 0.0))
    egress = tuple(round(move_tb * 1024 * p) for p in EGRESS_PER_GB)
    critical_tb = _tb(sum(sum(k.values()) for aid, k in by_account.items() if rows[aid].get("critical")))
    return {
        "available": True,
        "empty": False,
        "total_tb": _tb(total),
        "live_tb": _tb(by_kind["live"]),
        "copy_tb": _tb(by_kind["copy"]),
        "archive_tb": _tb(by_kind["archive"]),
        "move_tb": move_tb,
        "critical_tb": critical_tb,
        "transfer_gbps": q.transfer_gbps,
        "transfer_days": round(days, 1),
        "fits_credit_window": days <= EXIT_CREDIT_DAYS,
        "credit_days": EXIT_CREDIT_DAYS,
        "egress_list_usd": list(egress),
        "dynamodb_tb": dynamo_tb,
        "dynamodb_largest_tb": _tb(largest[1]),
        "dynamodb_largest_account": rows[largest[0]]["name"] if largest[0] else "",
        "dynamodb_imports_small_region": math.ceil(largest[1] / 1024) if largest[1] else 0,
        "services": services[:10],
        "accounts": accounts[:10],
        "regions": region_rows[:8],
    }


def _dominant(spend: dict[str, float]) -> tuple[str, float]:
    regional = {k: v for k, v in spend.items() if k not in GLOBAL_REGIONS and k != "global"}
    total = sum(regional.values())
    if not total:
        return "", 0.0
    region, top = max(regional.items(), key=lambda kv: kv[1])
    return region, 100 * top / total


def _concentration(region_costs: list[dict] | None, population: dict[str, dict], basis: str, regions: dict) -> dict:
    if not region_costs:
        return {"available": False, "reason": "This scan has no spend by region; run a new scan."}
    per_account: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    global_spend = 0.0
    for r in region_costs:
        if r["account_id"] in population:
            if r["region"] in GLOBAL_REGIONS:
                global_spend += r["monthly"]
            else:
                per_account[r["account_id"]][r["region"]] += r["monthly"]
    combined: dict[str, float] = defaultdict(float)
    for spend in per_account.values():
        for k, v in spend.items():
            combined[k] += v
    region, share = _dominant(combined)
    if not region:
        return {"available": False, "reason": "No regional spend for these accounts."}
    level = "High" if share >= 90 else "Elevated" if share >= 70 else "Moderate"
    total_regional = sum(combined.values())
    channels: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for aid, spend in per_account.items():
        ch = population[aid].get("channel")
        if ch:
            for k, v in spend.items():
                channels[ch][k] += v
    channel_rows = []
    for ch, spend in channels.items():
        reg, sh = _dominant(spend)
        channel_rows.append({"channel": ch, "region": reg, "name": _region_name(reg, regions), "pct": round(sh, 1)})
    channel_rows.sort(key=lambda c: (c["region"], c["channel"]))
    shared: dict[str, list[str]] = defaultdict(list)
    for c in channel_rows:
        shared[c["region"]].append(c["channel"])
    no_anti_affinity = [
        {"region": reg, "name": _region_name(reg, regions), "channels": chs}
        for reg, chs in shared.items()
        if len(chs) > 1
    ]
    accounts = []
    for aid, spend in per_account.items():
        reg, sh = _dominant(spend)
        accounts.append(
            {
                "id": aid,
                "name": population[aid]["name"],
                "channel": population[aid].get("channel", ""),
                "monthly_spend": round(sum(spend.values()), 2),
                "region": reg,
                "pct": round(sh, 1),
            }
        )
    accounts.sort(key=lambda a: -a["monthly_spend"])
    return {
        "available": True,
        "basis": basis,
        "score": round(share),
        "level": level,
        "region": region,
        "region_name": _region_name(region, regions),
        "pct": round(share, 1),
        "regions": sorted(
            (
                {"region": k, "name": _region_name(k, regions), "pct": round(100 * v / total_regional, 1)}
                for k, v in combined.items()
                if v / total_regional >= 0.005
            ),
            key=lambda x: -x["pct"],
        ),
        "global_pct": round(100 * global_spend / (global_spend + total_regional), 1),
        "channels": channel_rows,
        "no_anti_affinity": no_anti_affinity,
        "accounts": accounts[:15],
    }


def _stressed(population: dict[str, dict], basis: str) -> dict:
    total = sum(a["monthly_spend"] for a in population.values())
    buckets = []
    for key, tiers, label, note in STRESSED_BUCKETS:
        spend = sum(a["tier_spend"][t] for a in population.values() for t in tiers)
        buckets.append(
            {
                "key": key,
                "label": label,
                "note": note,
                "monthly_spend": round(spend, 2),
                "pct": round(100 * spend / total, 1) if total else 0.0,
            }
        )
    stuck = sorted(
        (
            {
                "id": a["id"],
                "name": a["name"],
                "monthly_spend": a["monthly_spend"],
                "pct": a["high_risk_pct"],
                "services": [s["service"] for s in a["top_lockin"]],
            }
            for a in population.values()
            if a["high_risk_pct"] >= STRESSED_ACCOUNT_SHARE and a["monthly_spend"] > 0
        ),
        key=lambda a: -a["monthly_spend"] * a["pct"],
    )
    return {"basis": basis, "monthly_spend": round(total, 2), "buckets": buckets, "accounts": stuck[:15]}


def build_resilience(scan: dict, accounts: list[dict], q: Questionnaire) -> dict:
    """Mark critical accounts on the report rows (in place) and build the resilience view."""
    patterns = _patterns(q.critical_accounts)
    scan_accounts = {a["id"]: a for a in scan.get("accounts", [])}
    tagged = sum(1 for a in scan_accounts.values() if a.get("tags"))
    has_tags = any("tags" in a for a in scan_accounts.values())
    for row in accounts:
        critical, source, channel = classify(scan_accounts.get(row["id"], {}), patterns)
        row["critical"], row["critical_source"], row["channel"] = critical, source, channel
    rows = {a["id"]: a for a in accounts}
    critical = {aid: a for aid, a in rows.items() if a["critical"]}
    population = critical or {aid: a for aid, a in rows.items() if a["monthly_spend"] > 0}
    basis = "critical" if critical else "all"
    regions = load_region_data()["regions"]
    crit_spend = sum(a["monthly_spend"] for a in critical.values())
    total_spend = sum(a["monthly_spend"] for a in rows.values())
    return {
        "criticality": {
            "tags_read": has_tags,
            "tagged_accounts": tagged,
            "patterns": patterns,
            "critical_accounts": len(critical),
            "by_tag": sum(1 for a in critical.values() if a["critical_source"] == "tag"),
            "by_name": sum(1 for a in critical.values() if a["critical_source"] == "name"),
            "monthly_spend": round(crit_spend, 2),
            "pct_spend": round(100 * crit_spend / total_spend, 1) if total_spend else 0.0,
            "channels": sorted({a["channel"] for a in rows.values() if a["channel"]}),
        },
        "data": _data(scan.get("storage"), rows, q, regions),
        "concentration": _concentration(scan.get("region_costs"), population, basis, regions),
        "stressed_exit": _stressed(population, basis),
    }
