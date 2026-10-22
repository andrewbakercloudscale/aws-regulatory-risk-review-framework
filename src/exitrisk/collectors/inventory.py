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
from dataclasses import replace

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import BOTO_CONFIG
from ..issues import Issue, describe_exception
from ..logging_config import get_logger
from . import dependencies as dependencies_mod

log = get_logger("inventory")


def _paged_count(client, op: str, key: str, **kwargs) -> int:
    return sum(len(page.get(key, [])) for page in client.get_paginator(op).paginate(**kwargs))


def _count(key: str, op: str, page_key: str, **kwargs) -> Callable:
    return lambda c: {key: _paged_count(c, op, page_key, **kwargs)}


def _rds(client) -> dict:
    engines: Counter = Counter()
    for page in client.get_paginator("describe_db_instances").paginate():
        for db in page.get("DBInstances", []):
            engines[db.get("Engine") or "unknown"] += 1
    return {"rds_engines": dict(engines)}


def _lambda(client) -> dict:
    """Function count and runtimes: custom and end-of-support runtimes are more work to move."""
    runtimes: Counter = Counter()
    for page in client.get_paginator("list_functions").paginate():
        for fn in page.get("Functions", []):
            runtimes[fn.get("Runtime") or ("container" if fn.get("PackageType") == "Image" else "unknown")] += 1
    return {"lambda_functions": sum(runtimes.values()), "lambda_runtimes": dict(runtimes)}


def _ec2(client) -> dict:
    n = 0
    for page in client.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}]
    ):
        n += sum(len(r.get("Instances", [])) for r in page.get("Reservations", []))
    return {"ec2_instances": n}


def _ecs(client) -> dict:
    clusters = [a for page in client.get_paginator("list_clusters").paginate() for a in page.get("clusterArns", [])]
    services = sum(_paged_count(client, "list_services", "serviceArns", cluster=arn) for arn in clusters)
    return {"ecs_clusters": len(clusters), "ecs_services": services}


# (Cost Explorer service the counts evidence, boto3 client, counter returning {key: value})
PROBES: list[tuple[str, str, Callable]] = [
    ("AWS Lambda", "lambda", _lambda),
    ("Amazon Elastic Compute Cloud - Compute", "ec2", _ec2),
    ("Amazon DynamoDB", "dynamodb", _count("dynamodb_tables", "list_tables", "TableNames")),
    ("AWS Step Functions", "stepfunctions", _count("step_functions", "list_state_machines", "stateMachines")),
    ("Amazon Kinesis", "kinesis", _count("kinesis_streams", "list_streams", "StreamNames")),
    ("Amazon Simple Queue Service", "sqs", _count("sqs_queues", "list_queues", "QueueUrls")),
    ("Amazon Simple Notification Service", "sns", _count("sns_topics", "list_topics", "Topics")),
    ("Amazon EventBridge", "events", _count("eventbridge_rules", "list_rules", "Rules")),
    ("Amazon API Gateway", "apigateway", _count("api_gateway_rest", "get_rest_apis", "items")),
    ("Amazon API Gateway", "apigatewayv2", lambda c: {"api_gateway_http": len(c.get_apis().get("Items", []))}),
    ("Amazon Cognito", "cognito-idp", _count("cognito_user_pools", "list_user_pools", "UserPools", MaxResults=60)),
    ("AWS Glue", "glue", _count("glue_jobs", "get_jobs", "Jobs")),
    ("Amazon Redshift", "redshift", _count("redshift_clusters", "describe_clusters", "Clusters")),
    (
        "AWS CloudFormation",
        "cloudformation",
        _count(
            "cloudformation_stacks",
            "list_stacks",
            "StackSummaries",
            StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE"],
        ),
    ),
    ("Amazon Elastic Kubernetes Service", "eks", _count("eks_clusters", "list_clusters", "clusters")),
    ("Amazon Elastic Container Service", "ecs", _ecs),
    ("Amazon Relational Database Service", "rds", _rds),
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
    for service, client_name, fn in PROBES:
        try:
            values = fn(session.client(client_name, region_name=region, config=BOTO_CONFIG))
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
                    f"{service} ({client_name}) in {region}: {msg}",
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
                client_name,
                code,
                extra={"account_id": account_id, "region": region, "error_code": code},
            )
            continue
        counts.update(values)
    return counts, issues


def _s3_buckets(session: boto3.Session, account_id: str) -> tuple[dict, list[Issue]]:
    """Buckets are global: one call per account, not per region."""
    try:
        buckets = session.client("s3", region_name="us-east-1", config=BOTO_CONFIG).list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError) as exc:
        code, msg, hint = describe_exception(exc)
        log.warning(
            "inventory %s s3 failed: %s", account_id, code, extra={"account_id": account_id, "error_code": code}
        )
        return {}, [
            Issue(
                "warning",
                "inventory",
                f"Amazon Simple Storage Service (s3): {msg}",
                hint,
                account_id=account_id,
                service="Amazon Simple Storage Service",
                error_code=code,
            )
        ]
    return {"s3_buckets": len(buckets)}, []


def _collapse(issues: list[Issue]) -> list[Issue]:
    """One dependency warning per kind and error per account, not one per region: a missing
    permission otherwise repeats in every enabled region."""
    out: list[Issue] = []
    groups: dict[tuple, list[Issue]] = {}
    for i in issues:
        if i.category == "dependencies" and i.severity == "warning":
            groups.setdefault((i.message.split(" in ", 1)[0], i.error_code), []).append(i)
        else:
            out.append(i)
    for (kind, _), items in groups.items():
        if len(items) == 1:
            out.append(items[0])
            continue
        first = items[0]
        regions = sorted(i.region for i in items if i.region)
        detail = first.message.split(": ", 1)[1] if ": " in first.message else first.message
        out.append(
            replace(first, message=f"{kind} in {len(regions)} regions ({', '.join(regions)}): {detail}", region=None)
        )
    return out


def inventory_account(
    session: boto3.Session,
    account_id: str,
    regions: list[str] | None,
    workers: int = 6,
    dependencies: bool = False,
) -> tuple[dict, list[Issue]]:
    """Return ({totals, by_region[, dependencies]}, issues) for one account.

    With ``dependencies`` the integrations between services are counted too (see
    collectors/dependencies.py): ``dependencies`` holds {edge: count} and ``dependency_kinds`` the
    kinds of edge read in every region, so a refused call is never mistaken for "no edges".
    """
    issues: list[Issue] = []
    try:
        region_list = enabled_regions(session, regions)
    except (ClientError, BotoCoreError) as exc:
        code, msg, hint = describe_exception(exc)
        return {}, [
            Issue("error", "inventory", f"could not list regions: {msg}", hint, account_id=account_id, error_code=code)
        ]

    totals, s3_issues = _s3_buckets(session, account_id)
    issues += s3_issues
    by_region: dict = {}
    edges: Counter = Counter()
    kinds_done = set(k for k, _ in dependencies_mod.DISCOVERIES) if dependencies else set()

    def region_work(r):
        counts, probe_issues = _probe_region(session, account_id, r)
        if not dependencies:
            return r, counts, probe_issues, {}, set()
        found, done, dep_issues = dependencies_mod.discover_region(session, account_id, r)
        return r, counts, probe_issues + dep_issues, found, set(done)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for region, counts, region_issues, found, done in pool.map(region_work, region_list):
            issues += region_issues
            edges.update(found)
            kinds_done &= done
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
    issues = _collapse(issues)
    out = {"regions_scanned": region_list, "totals": totals, "by_region": by_region}
    if dependencies:
        out["dependencies"] = dict(edges)
        out["dependency_kinds"] = sorted(kinds_done)
    return out, issues
