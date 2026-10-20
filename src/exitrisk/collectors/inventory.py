"""Optional resource inventory inside member accounts ("deep scan").

Spend tells us *how much* of a service an account uses; the inventory tells us *how
many things* would have to be migrated - 400 Lambda functions at $300/month is a bigger
exit job than the spend suggests. It needs a read-only role in each member account
(see docs/IAM_PERMISSIONS.md). Every failed call becomes an Issue; the scan carries on.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import BOTO_CONFIG
from ..issues import Issue, describe_exception
from ..logging_config import get_logger

log = get_logger("inventory")


def _paged_count(client, op: str, key: str, **kwargs) -> int:
    return sum(len(page.get(key, [])) for page in client.get_paginator(op).paginate(**kwargs))


def _rds(client) -> dict:
    engines: Counter = Counter()
    for page in client.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            engines[db["Engine"]] += 1
    return dict(engines)


# (key, Cost Explorer service it evidences, boto3 client, counter)
PROBES: list[tuple[str, str, str, Callable]] = [
    ("lambda_functions", "AWS Lambda", "lambda", lambda c: _paged_count(c, "list_functions", "Functions")),
    ("dynamodb_tables", "Amazon DynamoDB", "dynamodb", lambda c: _paged_count(c, "list_tables", "TableNames")),
    (
        "step_functions",
        "AWS Step Functions",
        "stepfunctions",
        lambda c: _paged_count(c, "list_state_machines", "stateMachines"),
    ),
    ("kinesis_streams", "Amazon Kinesis", "kinesis", lambda c: _paged_count(c, "list_streams", "StreamNames")),
    ("sqs_queues", "Amazon Simple Queue Service", "sqs", lambda c: _paged_count(c, "list_queues", "QueueUrls")),
    ("sns_topics", "Amazon Simple Notification Service", "sns", lambda c: _paged_count(c, "list_topics", "Topics")),
    ("eventbridge_rules", "Amazon EventBridge", "events", lambda c: len(c.list_rules(Limit=100).get("Rules", []))),
    ("api_gateway_rest", "Amazon API Gateway", "apigateway", lambda c: _paged_count(c, "get_rest_apis", "items")),
    ("api_gateway_http", "Amazon API Gateway", "apigatewayv2", lambda c: len(c.get_apis().get("Items", []))),
    (
        "cognito_user_pools",
        "Amazon Cognito",
        "cognito-idp",
        lambda c: _paged_count(c, "list_user_pools", "UserPools", MaxResults=60),
    ),
    ("glue_jobs", "AWS Glue", "glue", lambda c: _paged_count(c, "get_jobs", "Jobs")),
    ("redshift_clusters", "Amazon Redshift", "redshift", lambda c: _paged_count(c, "describe_clusters", "Clusters")),
    (
        "cloudformation_stacks",
        "AWS CloudFormation",
        "cloudformation",
        lambda c: _paged_count(
            c,
            "list_stacks",
            "StackSummaries",
            StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE"],
        ),
    ),
    (
        "eks_clusters",
        "Amazon Elastic Kubernetes Service",
        "eks",
        lambda c: _paged_count(c, "list_clusters", "clusters"),
    ),
    (
        "ecs_clusters",
        "Amazon Elastic Container Service",
        "ecs",
        lambda c: _paged_count(c, "list_clusters", "clusterArns"),
    ),
    ("rds_engines", "Amazon Relational Database Service", "rds", _rds),
]


def enabled_regions(session: boto3.Session, wanted: list[str] | None) -> list[str]:
    regions = [
        r["RegionName"]
        for r in session.client("ec2", region_name="us-east-1", config=BOTO_CONFIG).describe_regions()["Regions"]
    ]
    return [r for r in regions if not wanted or r in wanted]


def _probe_region(session: boto3.Session, account_id: str, region: str) -> tuple[dict, list[Issue]]:
    counts: dict = {}
    issues: list[Issue] = []
    for key, service, client_name, fn in PROBES:
        try:
            value = fn(session.client(client_name, region_name=region, config=BOTO_CONFIG))
        except (ClientError, BotoCoreError) as exc:
            code, msg, hint = describe_exception(exc)
            if (
                code in ("OptInRequired", "UnrecognizedClientException", "InvalidClientTokenId")
                and region != "us-east-1"
            ):
                continue  # region not usable by this account; nothing to count
            issues.append(
                Issue(
                    "warning",
                    "inventory",
                    f"{key} in {region}: {msg}",
                    hint,
                    account_id=account_id,
                    service=service,
                    region=region,
                    error_code=code,
                )
            )
            log.warning(
                "inventory %s %s %s failed: %s",
                account_id,
                region,
                key,
                code,
                extra={"account_id": account_id, "region": region, "error_code": code},
            )
            continue
        counts[key] = value
    return counts, issues


def inventory_account(
    session: boto3.Session, account_id: str, regions: list[str] | None, workers: int = 6
) -> tuple[dict, list[Issue]]:
    """Return ({totals, by_region}, issues) for one account."""
    issues: list[Issue] = []
    try:
        region_list = enabled_regions(session, regions)
    except (ClientError, BotoCoreError) as exc:
        code, msg, hint = describe_exception(exc)
        return {}, [
            Issue("error", "inventory", f"could not list regions: {msg}", hint, account_id=account_id, error_code=code)
        ]

    totals: dict = {}
    by_region: dict = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda r: (r, *_probe_region(session, account_id, r)), region_list)
        for region, counts, region_issues in results:
            issues += region_issues
            nonzero = {k: v for k, v in counts.items() if v}
            if nonzero:
                by_region[region] = nonzero
            for k, v in counts.items():
                if isinstance(v, dict):
                    agg = totals.setdefault(k, {})
                    for engine, n in v.items():
                        agg[engine] = agg.get(engine, 0) + n
                else:
                    totals[k] = totals.get(k, 0) + v
    return {"regions_scanned": region_list, "totals": totals, "by_region": by_region}, issues
