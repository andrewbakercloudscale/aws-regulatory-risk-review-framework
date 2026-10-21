"""Cost Explorer: amortised spend per account per service per month.

One query from the management (payer) account covers every member account, so the core
score needs no access to member accounts at all. Spend is AmortizedCost - upfront
Reserved Instance and Savings Plan payments are spread over the months they cover, which
is the fairest measure of how much each workload actually costs to run.
"""

from __future__ import annotations

import re
import sys
from datetime import date

import boto3
from botocore.exceptions import ClientError

from ..aws_session import BOTO_CONFIG
from ..logging_config import get_logger
from ..parallel import pmap

log = get_logger("cost")

MARKETPLACE_SERVICE = "AWS Marketplace (third-party)"
# Third-party models on Bedrock (Anthropic Claude, ...) bill through Marketplace as "<model> (Amazon Bedrock Edition)".
# They are Bedrock usage, not bought-in software, so they score as Bedrock.
BEDROCK_SERVICE = "Amazon Bedrock"
_BEDROCK_SUFFIX = "(Amazon Bedrock Edition)"
_EXCLUDED_RECORD_TYPES = ["Credit", "Refund", "Tax", "Support"]
_MAX_ACCOUNTS_PER_FILTER = 100
# Region lines under this (USD/month) are baseline noise (Config, GuardDuty in idle regions) and are dropped.
_MIN_REGION_MONTHLY = 0.1


def month_window(months: int, today: date | None = None) -> tuple[str, str]:
    """[start, end) covering the last ``months`` complete calendar months."""
    today = today or date.today()
    end = today.replace(day=1)
    y, m = end.year, end.month - months
    while m <= 0:
        m += 12
        y -= 1
    return date(y, m, 1).isoformat(), end.isoformat()


def _query(client, start: str, end: str, account_ids: list[str], billing_entity: str) -> list[dict]:
    rows: list[dict] = []
    filt = {
        "And": [
            {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": account_ids}},
            {"Dimensions": {"Key": "BILLING_ENTITY", "Values": [billing_entity]}},
            {"Not": {"Dimensions": {"Key": "RECORD_TYPE", "Values": _EXCLUDED_RECORD_TYPES}}},
        ]
    }
    token = None
    pages = 0
    while True:
        kwargs = {
            "TimePeriod": {"Start": start, "End": end},
            "Granularity": "MONTHLY",
            "Metrics": ["AmortizedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}, {"Type": "DIMENSION", "Key": "SERVICE"}],
            "Filter": filt,
        }
        if token:
            kwargs["NextPageToken"] = token
        resp = client.get_cost_and_usage(**kwargs)
        pages += 1
        for period in resp["ResultsByTime"]:
            month = period["TimePeriod"]["Start"][:7]
            for g in period.get("Groups", []):
                account_id, service = g["Keys"]
                amount = float(g["Metrics"]["AmortizedCost"]["Amount"])
                # Thousands of rows repeat a few hundred names: share one copy of each.
                row = {
                    "month": month,
                    "account_id": sys.intern(account_id),
                    "service": sys.intern(service),
                    "amount": amount,
                }
                if billing_entity == "AWS Marketplace":
                    # One catalog entry for all third-party software; keep the product so the report can name it.
                    billed_as = BEDROCK_SERVICE if service.endswith(_BEDROCK_SUFFIX) else MARKETPLACE_SERVICE
                    row.update(service=billed_as, product=service)
                rows.append(row)
        token = resp.get("NextPageToken")
        if not token:
            break
    log.info("cost explorer %s: %d rows, %d page(s), %d account(s)", billing_entity, len(rows), pages, len(account_ids))
    return rows


def _grouped(client, start: str, end: str, filt: dict, group_by: list[str]) -> dict[tuple, float]:
    """Total AmortizedCost over [start, end) for each combination of the ``group_by`` dimensions."""
    out: dict[tuple, float] = {}
    token = None
    while True:
        kwargs = {
            "TimePeriod": {"Start": start, "End": end},
            "Granularity": "MONTHLY",
            "Metrics": ["AmortizedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": k} for k in group_by],
            "Filter": filt,
        }
        if token:
            kwargs["NextPageToken"] = token
        resp = client.get_cost_and_usage(**kwargs)
        for period in resp["ResultsByTime"]:
            for g in period.get("Groups", []):
                key = tuple(g["Keys"])
                out[key] = out.get(key, 0.0) + float(g["Metrics"]["AmortizedCost"]["Amount"])
        token = resp.get("NextPageToken")
        if not token:
            return out


def fetch_region_costs(session: boto3.Session, account_ids: list[str], months: int) -> list[dict]:
    """Average monthly spend per account, service and region, for the multi-region estimate.

    Cost Explorer groups by at most two dimensions, so this asks which regions carry spend,
    then for each of them asks account x service. A handful of regions in use means a handful
    of queries per 100 accounts (US$0.01 each). Marketplace is left out: it is not regional.
    """
    client = session.client("ce", region_name="us-east-1", config=BOTO_CONFIG)
    start, end = month_window(months)
    rows: list[dict] = []
    for i in range(0, len(account_ids), _MAX_ACCOUNTS_PER_FILTER):
        chunk = account_ids[i : i + _MAX_ACCOUNTS_PER_FILTER]
        base = [
            {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": chunk}},
            {"Dimensions": {"Key": "BILLING_ENTITY", "Values": ["AWS"]}},
            {"Not": {"Dimensions": {"Key": "RECORD_TYPE", "Values": _EXCLUDED_RECORD_TYPES}}},
        ]
        regions = _grouped(client, start, end, {"And": base}, ["REGION"])
        used = [r for (r,), total in sorted(regions.items(), key=lambda kv: -kv[1]) if total > 0]

        def by_region(region: str, base=base) -> dict[tuple, float]:
            filt = {"And": [*base, {"Dimensions": {"Key": "REGION", "Values": [region]}}]}
            return _grouped(client, start, end, filt, ["LINKED_ACCOUNT", "SERVICE"])

        for region, spend in zip(used, pmap(by_region, used), strict=True):
            for (account_id, service), amount in spend.items():
                if amount / months >= _MIN_REGION_MONTHLY:
                    rows.append(
                        {
                            "account_id": sys.intern(account_id),
                            "service": sys.intern(service),
                            "region": sys.intern(region or "NoRegion"),
                            "monthly": round(amount / months, 4),
                        }
                    )
    log.info("cost explorer by region: %d rows, %d account(s)", len(rows), len(account_ids))
    return rows


# Services that hold data, and the storage usage types that are copies (snapshots, backups, PITR,
# Multi-AZ mirrors) or archives (Glacier, Deep Archive) rather than live data.
STORAGE_SERVICES = (
    "Amazon Simple Storage Service",
    "EC2 - Other",
    "Amazon DynamoDB",
    "Amazon Relational Database Service",
    "Amazon Elastic File System",
    "Amazon Redshift",
    "Amazon OpenSearch Service",
    "Amazon DocumentDB (with MongoDB compatibility)",
    "Amazon FSx",
    "AWS Backup",
)
_COPY_MARKERS = ("Snapshot", "Backup", "PITR", "Mirror")
_ARCHIVE_MARKERS = ("Glacier", "GDA", "GIR", "DeepArchive")
# Billed in GB-months but not data held: early-deletion fees for archive tiers.
_NOT_HELD = ("EarlyDelete",)


def storage_kind(service: str, usage_type: str) -> str:
    """'live', 'copy' (snapshot, backup, PITR, mirror) or 'archive' (Glacier tiers)."""
    if service == "AWS Backup" or any(m in usage_type for m in _COPY_MARKERS):
        return "copy"
    if any(m in usage_type for m in _ARCHIVE_MARKERS):
        return "archive"
    return "live"


def fetch_storage(session: boto3.Session, account_ids: list[str], services: set[str]) -> list[dict]:
    """GB stored per account, service and usage type, averaged over the last complete month.

    Storage is billed in GB-months, so the usage quantity of a GB-month line is the average
    number of GB held. One query per storage service the scan saw spend on, per 100 accounts.
    """
    client = session.client("ce", region_name="us-east-1", config=BOTO_CONFIG)
    start, end = month_window(1)
    queries = [
        (service, account_ids[i : i + _MAX_ACCOUNTS_PER_FILTER])
        for service in STORAGE_SERVICES
        if service in services
        for i in range(0, len(account_ids), _MAX_ACCOUNTS_PER_FILTER)
    ]

    def one(query: tuple[str, list[str]]) -> list[dict]:
        service, chunk = query
        rows: list[dict] = []
        filt = {
            "And": [
                {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": chunk}},
                {"Dimensions": {"Key": "SERVICE", "Values": [service]}},
            ]
        }
        token = None
        while True:
            kwargs = {
                "TimePeriod": {"Start": start, "End": end},
                "Granularity": "MONTHLY",
                "Metrics": ["UsageQuantity"],
                "GroupBy": [
                    {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
                    {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
                ],
                "Filter": filt,
            }
            if token:
                kwargs["NextPageToken"] = token
            resp = client.get_cost_and_usage(**kwargs)
            for period in resp["ResultsByTime"]:
                for g in period.get("Groups", []):
                    usage = g["Metrics"]["UsageQuantity"]
                    gb = float(usage["Amount"])
                    account_id, usage_type = g["Keys"]
                    if usage.get("Unit") not in ("GB-Mo", "GB-Month") or gb < 1:
                        continue
                    if any(m in usage_type for m in _NOT_HELD):
                        continue
                    rows.append(
                        {
                            "account_id": account_id,
                            "service": service,
                            "usage_type": usage_type,
                            "kind": storage_kind(service, usage_type),
                            "gb": round(gb, 1),
                        }
                    )
            token = resp.get("NextPageToken")
            if not token:
                break
        return rows

    rows = [r for found in pmap(one, queries) for r in found]
    log.info("cost explorer storage: %d rows, %d account(s), month %s", len(rows), len(account_ids), start[:7])
    return rows


DIRECT_CONNECT_SERVICE = "AWS Direct Connect"
# Port usage types: <region>-<location>-PortUsage:10G (dedicated), HCPortUsage:1G (hosted) and
# FlatRatePortUsage:10G-Tier1 (flat rate). Usage is in port-hours, so hours / hours in the month = ports.
_PORT_RE = re.compile(
    r"^(?P<region>[A-Z0-9]+)-(?P<loc>[A-Za-z0-9]+)-(?P<kind>HC|FlatRate)?PortUsage:(?P<speed>\d+(?:\.\d+)?)(?P<unit>[GM])(?P<pair>-Pair)?"
)


def parse_port(usage_type: str) -> dict | None:
    """Location code, kind, speed (Gbps) and ports per line of a Direct Connect port usage type, or None."""
    m = _PORT_RE.match(usage_type)
    if not m:
        return None
    speed = float(m["speed"]) / (1000 if m["unit"] == "M" else 1)
    kind = {"HC": "hosted", "FlatRate": "flat rate"}.get(m["kind"] or "", "dedicated")
    # A "Pair" is two ports (for redundancy) billed as one line.
    return {"location": m["loc"], "kind": kind, "gbps": speed, "ports": 2 if m["pair"] else 1}


def fetch_direct_connect(session: boto3.Session, account_ids: list[str]) -> dict:
    """Direct Connect ports and data out per account, for the last complete month.

    Ports are counted from port-hours (a port connected all month bills every hour). Data out is the
    GB sent over Direct Connect, with what it cost. One query per 100 accounts.
    """
    client = session.client("ce", region_name="us-east-1", config=BOTO_CONFIG)
    start, end = month_window(1)
    hours = (date.fromisoformat(end) - date.fromisoformat(start)).days * 24
    chunks = [
        account_ids[i : i + _MAX_ACCOUNTS_PER_FILTER] for i in range(0, len(account_ids), _MAX_ACCOUNTS_PER_FILTER)
    ]

    def one(chunk: list[str]) -> list[dict]:
        rows: list[dict] = []
        filt = {
            "And": [
                {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": chunk}},
                {"Dimensions": {"Key": "SERVICE", "Values": [DIRECT_CONNECT_SERVICE]}},
            ]
        }
        token = None
        while True:
            kwargs = {
                "TimePeriod": {"Start": start, "End": end},
                "Granularity": "MONTHLY",
                "Metrics": ["UsageQuantity", "UnblendedCost"],
                "GroupBy": [
                    {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
                    {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
                ],
                "Filter": filt,
            }
            if token:
                kwargs["NextPageToken"] = token
            resp = client.get_cost_and_usage(**kwargs)
            for period in resp["ResultsByTime"]:
                for g in period.get("Groups", []):
                    account_id, usage_type = g["Keys"]
                    usage = g["Metrics"]["UsageQuantity"]
                    rows.append(
                        {
                            "account_id": account_id,
                            "usage_type": usage_type,
                            "unit": usage.get("Unit", ""),
                            "quantity": round(float(usage["Amount"]), 2),
                            "cost": round(float(g["Metrics"]["UnblendedCost"]["Amount"]), 2),
                        }
                    )
            token = resp.get("NextPageToken")
            if not token:
                break
        return rows

    rows = [r for found in pmap(one, chunks) for r in found]
    log.info("cost explorer direct connect: %d rows, month %s", len(rows), start[:7])
    return {"month": start[:7], "hours": hours, "rows": rows}


def fetch_costs(session: boto3.Session, account_ids: list[str], months: int) -> tuple[list[dict], dict]:
    """Return (rows, period). Each Cost Explorer request costs US$0.01; a typical scan makes a handful."""
    client = session.client("ce", region_name="us-east-1", config=BOTO_CONFIG)
    start, end = month_window(months)
    rows: list[dict] = []
    for i in range(0, len(account_ids), _MAX_ACCOUNTS_PER_FILTER):
        chunk = account_ids[i : i + _MAX_ACCOUNTS_PER_FILTER]
        rows += _query(client, start, end, chunk, "AWS")
        rows += _query(client, start, end, chunk, "AWS Marketplace")
    merged: dict[tuple, float] = {}
    for r in rows:
        key = (r["month"], r["account_id"], r["service"], r.get("product"))
        merged[key] = merged.get(key, 0.0) + r["amount"]
    out = [
        {"month": k[0], "account_id": k[1], "service": k[2], "amount": round(v, 4)}
        | ({"product": k[3]} if k[3] else {})
        for k, v in merged.items()
    ]
    return out, {"start": start, "end": end, "months": months}


# Services sold with reserved capacity. Each is queried on its own and the results merged, so a
# service with no reservations (or none in this organisation) costs one empty call.
RESERVATION_SERVICES = (
    "Amazon Elastic Compute Cloud - Compute",
    "Amazon Relational Database Service",
    "Amazon ElastiCache",
    "Amazon Redshift",
    "Amazon OpenSearch Service",
    "Amazon MemoryDB",
)
# Reservations that cannot be queried for a service (not offered, no data) are skipped, not fatal.
_SKIPPABLE = ("DataUnavailableException", "ValidationException")


def _attrs(raw: dict | None) -> dict[str, str]:
    """Commitment attributes with case-insensitive keys: AWS returns ``EndDateTime`` and ``endDateTime``."""
    return {k.lower(): v for k, v in (raw or {}).items()}


def _term(a: dict[str, str]) -> str:
    """``1yr`` or ``3yr``: from the term attribute ("3yr", "3 Year", "1 year"), else from the start and end dates."""
    raw = a.get("purchaseterm") or a.get("leaseterm") or a.get("term") or ""
    m = re.match(r"\s*(\d+)\s*(yr|year)", raw, re.I)
    if m:
        return f"{m.group(1)}yr"
    start, end = _day(a.get("startdatetime")), _day(a.get("enddatetime"))
    if start and end:
        return f"{max(1, round((end - start).days / 365))}yr"
    return raw.strip()


def _day(v: str | None) -> date | None:
    try:
        return date.fromisoformat((v or "")[:10])
    except ValueError:
        return None


def _end(a: dict[str, str], term: str) -> str:
    """The end date as YYYY-MM-DD; worked out from the start date and term when AWS leaves it out."""
    end = _day(a.get("enddatetime"))
    if not end and (start := _day(a.get("startdatetime"))) and (m := re.match(r"(\d+)yr$", term)):
        end = start.replace(year=start.year + int(m.group(1)))
    return end.isoformat() if end else ""


def fetch_commitments(session: boto3.Session) -> list[dict]:
    """Savings Plans and reservations active in the last complete month, with their end dates.

    ``monthly`` is the amortised commitment for that month (upfront fees spread over the term), so
    the remaining obligation is ``monthly`` times the months left. Commitments are bought in one
    account and shared across the organisation, so this is organisation-wide, not per OU.
    """
    client = session.client("ce", region_name="us-east-1", config=BOTO_CONFIG)
    start, end = month_window(1)
    period = {"Start": start, "End": end}
    out: list[dict] = []
    keys_seen: set[str] = set()  # attribute names, logged if an end date is missing

    token = None
    while True:
        kwargs = {"TimePeriod": period, **({"NextToken": token} if token else {})}
        try:
            resp = client.get_savings_plans_utilization_details(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in _SKIPPABLE:
                log.info("no Savings Plans data: %s", exc)
                break
            raise
        for d in resp.get("SavingsPlansUtilizationDetails", []):
            a = _attrs(d.get("Attributes"))
            keys_seen.update(a)
            out.append(
                {
                    "kind": "savings_plan",
                    "id": d.get("SavingsPlanArn", "").rsplit("/", 1)[-1],
                    "type": a.get("savingsplanstype", "Savings Plan"),
                    "service": "",
                    "account_id": a.get("accountid", ""),
                    "region": a.get("region", ""),
                    "term": (term := _term(a)),
                    "payment": a.get("paymentoption", ""),
                    "end": _end(a, term),
                    "monthly": round(float((d.get("AmortizedCommitment") or {}).get("TotalAmortizedCommitment", 0)), 2),
                    "utilization_pct": _pct((d.get("Utilization") or {}).get("UtilizationPercentage")),
                }
            )
        token = resp.get("NextToken")
        if not token:
            break

    def reservations(service: str) -> list[dict]:
        groups: list[dict] = []
        token = None
        while True:
            kwargs = {
                "TimePeriod": period,
                "GroupBy": [{"Type": "DIMENSION", "Key": "SUBSCRIPTION_ID"}],
                "Filter": {"Dimensions": {"Key": "SERVICE", "Values": [service]}},
                **({"NextPageToken": token} if token else {}),
            }
            try:
                resp = client.get_reservation_utilization(**kwargs)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in _SKIPPABLE:
                    log.info("no reservation data for %s: %s", service, exc)
                    return groups
                raise
            groups += [g for p in resp.get("UtilizationsByTime", []) for g in p.get("Groups", [])]
            token = resp.get("NextPageToken")
            if not token:
                return groups

    seen: set[str] = set()
    for service, groups in zip(RESERVATION_SERVICES, pmap(reservations, RESERVATION_SERVICES), strict=True):
        for g in groups:
            rid = g.get("Value") or _attrs(g.get("Attributes")).get("subscriptionid", "")
            if rid in seen:
                continue
            seen.add(rid)
            a = _attrs(g.get("Attributes"))
            keys_seen.update(a)
            u = g.get("Utilization") or {}
            out.append(
                {
                    "kind": "reservation",
                    "id": rid,
                    "type": "Reserved " + (a.get("instancetype") or "capacity"),
                    "service": service,
                    "account_id": a.get("accountid", ""),
                    "region": a.get("region", ""),
                    "term": (term := _term(a)),
                    "payment": a.get("subscriptiontype", "") or a.get("paymentoption", ""),
                    "end": _end(a, term),
                    "monthly": round(float(u.get("TotalAmortizedFee", 0) or 0), 2),
                    "utilization_pct": _pct(u.get("UtilizationPercentage")),
                }
            )
    undated = [c for c in out if not c["end"]]
    if undated:
        # Timing cannot place these; the attribute names show what AWS sent instead.
        log.warning(
            "%d commitment(s) have no end date, e.g. %s; Timing counts them but cannot date them. Attributes: %s",
            len(undated),
            undated[0]["id"] or undated[0]["type"],
            ", ".join(sorted(keys_seen)) or "none",
        )
    log.info(
        "commitments: %d savings plan(s), %d reservation(s), month %s",
        sum(1 for c in out if c["kind"] == "savings_plan"),
        sum(1 for c in out if c["kind"] == "reservation"),
        start[:7],
    )
    return out


def _pct(v) -> float | None:
    try:
        return round(float(v), 1)
    except (TypeError, ValueError):
        return None
