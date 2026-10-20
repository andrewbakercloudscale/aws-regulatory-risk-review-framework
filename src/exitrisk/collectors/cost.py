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
_EXCLUDED_RECORD_TYPES = ["Credit", "Refund", "Tax", "Support"]
_MAX_ACCOUNTS_PER_FILTER = 100


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
                if billing_entity == "AWS Marketplace":
                    service = MARKETPLACE_SERVICE
                rows.append({"month": month, "account_id": account_id, "service": service, "amount": amount})
        token = resp.get("NextPageToken")
        if not token:
            break
    log.info("cost explorer %s: %d rows, %d page(s), %d account(s)", billing_entity, len(rows), pages, len(account_ids))
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
        key = (r["month"], r["account_id"], r["service"])
        merged[key] = merged.get(key, 0.0) + r["amount"]
    out = [{"month": k[0], "account_id": k[1], "service": k[2], "amount": round(v, 4)} for k, v in merged.items()]
    return out, {"start": start, "end": end, "months": months}
