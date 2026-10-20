"""Cost Explorer: amortised spend per account per service per month.

One query from the management (payer) account covers every member account, so the core
score needs no access to member accounts at all. Spend is AmortizedCost - upfront
Reserved Instance and Savings Plan payments are spread over the months they cover, which
is the fairest measure of how much each workload actually costs to run.
"""

from __future__ import annotations

from datetime import date

import boto3

from ..aws_session import BOTO_CONFIG
from ..logging_config import get_logger

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
                row = {"month": month, "account_id": account_id, "service": service, "amount": amount}
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
        for (region,), total in sorted(regions.items(), key=lambda kv: -kv[1]):
            if total <= 0:
                continue
            filt = {"And": [*base, {"Dimensions": {"Key": "REGION", "Values": [region]}}]}
            for (account_id, service), amount in _grouped(
                client, start, end, filt, ["LINKED_ACCOUNT", "SERVICE"]
            ).items():
                if amount / months >= _MIN_REGION_MONTHLY:
                    rows.append(
                        {
                            "account_id": account_id,
                            "service": service,
                            "region": region or "NoRegion",
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
    rows: list[dict] = []
    for service in (s for s in STORAGE_SERVICES if s in services):
        for i in range(0, len(account_ids), _MAX_ACCOUNTS_PER_FILTER):
            filt = {
                "And": [
                    {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": account_ids[i : i + _MAX_ACCOUNTS_PER_FILTER]}},
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
    log.info("cost explorer storage: %d rows, %d account(s), month %s", len(rows), len(account_ids), start[:7])
    return rows


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
