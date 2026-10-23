"""Migration effort from the resources themselves, not from the bill.

Spend measures financial exposure; it says little about how much work an exit is. A $20 Lambda
function wired to four queues is more work to move than a $10,000 EC2 instance. When the deep scan
reached an account, each service's effort is built from what was counted there:

    effort (engineer-days) = baseline days per resource x complexity x repeat discount

* **baseline** - ``RESOURCES`` below, per resource type;
* **complexity** - observable configuration: custom or end-of-support Lambda runtimes, Aurora or
  commercial database engines (``lambda_complexity``, ``RDS_DAYS``);
* **repeat discount** - after the first ``REPEAT_FULL`` resources of a type in an account, each
  further one is mostly repeat work (templated, scripted) and costs ``REPEAT_SHARE`` of the baseline.

The dependency scan adds **integration redesign**: each AWS-specific integration discovered between
services (an SQS queue feeding a function, an EventBridge rule starting a state machine) costs
``INTEGRATION_DAYS``, with the same repeat discount per kind of integration. Integrations are counted
once each, as their own line, rather than as a multiplier on both ends, so no work is counted twice.

Automation (CI/CD and infrastructure-as-code), the exit target, regulation and AI coding agents are
applied afterwards by the estimate, exactly as for spend-sized effort.

Every coefficient is an assumption to calibrate against completed migrations; the report quotes
ranges and lists these figures so they can be challenged. Services the deep scan cannot count (S3
data, CloudFront, Connect...) and accounts it did not reach stay sized from spend, and the report
shows how much of the effort rests on each basis.
"""

from __future__ import annotations

import re

from .catalog import Catalog
from .collectors.baseline import platform_edge

DAYS_PER_WEEK = 5.0
REPEAT_FULL = 20
REPEAT_SHARE = 0.35

# resource key -> (catalog service, baseline engineer-days each, label)
RESOURCES: dict[str, tuple[str, float, str]] = {
    "ec2_instances": ("Amazon Elastic Compute Cloud - Compute", 0.5, "EC2 instances"),
    "lambda_functions": ("AWS Lambda", 2.0, "Lambda functions"),
    "dynamodb_tables": ("Amazon DynamoDB", 6.0, "DynamoDB tables"),
    "step_functions": ("AWS Step Functions", 4.0, "Step Functions state machines"),
    "kinesis_streams": ("Amazon Kinesis", 3.0, "Kinesis streams"),
    "sqs_queues": ("Amazon Simple Queue Service", 0.5, "SQS queues"),
    "sns_topics": ("Amazon Simple Notification Service", 0.5, "SNS topics"),
    "eventbridge_rules": ("Amazon EventBridge", 1.0, "EventBridge rules"),
    "api_gateway_rest": ("Amazon API Gateway", 3.0, "API Gateway REST APIs"),
    "api_gateway_http": ("Amazon API Gateway", 2.0, "API Gateway HTTP APIs"),
    "cognito_user_pools": ("Amazon Cognito", 15.0, "Cognito user pools"),
    "glue_jobs": ("AWS Glue", 3.0, "Glue jobs"),
    "redshift_clusters": ("Amazon Redshift", 20.0, "Redshift clusters"),
    "cloudformation_stacks": ("AWS CloudFormation", 1.0, "CloudFormation stacks"),
    "eks_clusters": ("Amazon Elastic Kubernetes Service", 10.0, "EKS clusters"),
    "ecs_clusters": ("Amazon Elastic Container Service", 2.0, "ECS clusters"),
    "ecs_services": ("Amazon Elastic Container Service", 2.0, "ECS services"),
    "s3_buckets": ("Amazon Simple Storage Service", 0.5, "S3 buckets"),
}
RDS_SERVICE = "Amazon Relational Database Service"
# Engineer-days per database instance by engine family: open-source engines move like for like,
# commercial engines carry licensing, Aurora's storage and features have no direct equivalent.
RDS_DAYS = {"open": 3.0, "commercial": 5.0, "aurora": 6.0}

# Lambda runtimes: a custom runtime ("provided") is bespoke packaging; an end-of-support runtime
# must be upgraded as part of the move; a container image is already portable.
CUSTOM_RUNTIME_FACTOR = 1.5
OLD_RUNTIME_FACTOR = 1.3
CONTAINER_FACTOR = 0.7
_OLD_RUNTIME = re.compile(
    r"^(python2\.7|python3\.[0-8]|nodejs(\d+\.\d+|[4-9]\.\d+|1[0-6]\.x)?|java8|dotnetcore.*|dotnet[56]|go1\.x|ruby2\..*)$"
)

# Engineer-days per AWS-specific integration, by the kind of thing it calls. An e-mail or SMS
# subscription is a small change; an HTTP backend behind API Gateway keeps its code.
INTEGRATION_DAYS = 1.0
INTEGRATION_DAYS_BY_TARGET = {"email": 0.25, "sms": 0.25, "mobile": 0.5, "http": 0.5}

# Short names used in dependency edges -> catalog services, to rate how locked-in an integration is.
EDGE_SERVICES = {
    "lambda": "AWS Lambda",
    "sqs": "Amazon Simple Queue Service",
    "sns": "Amazon Simple Notification Service",
    "dynamodb": "Amazon DynamoDB",
    "kinesis": "Amazon Kinesis",
    "firehose": "Amazon Kinesis Firehose",
    "eventbridge": "Amazon EventBridge",
    "stepfunctions": "AWS Step Functions",
    "apigateway": "Amazon API Gateway",
    "msk": "Amazon Managed Streaming for Apache Kafka",
    "s3": "Amazon Simple Storage Service",
    "ecs": "Amazon Elastic Container Service",
    "glue": "AWS Glue",
    "batch": "AWS Batch",
    "sagemaker": "Amazon SageMaker",
    "bedrock": "Amazon Bedrock",
    "athena": "Amazon Athena",
    "logs": "AmazonCloudWatch",
    "mq": "Amazon MQ",
    "ssm": "AWS Systems Manager",
}
# Edge ends outside AWS: they do not raise an integration's tier.
OUTSIDE_AWS = {"http", "email", "sms", "mobile", "kafka", "aws"}


def repeat_count(n: float) -> float:
    """Resources after the first REPEAT_FULL of a type count at REPEAT_SHARE of the work."""
    return min(n, REPEAT_FULL) + max(n - REPEAT_FULL, 0) * REPEAT_SHARE


def lambda_complexity(runtimes: dict[str, int]) -> float:
    """The mean complexity factor across an account's functions (1.0 when runtimes were not read)."""
    n = sum(runtimes.values())
    if not n:
        return 1.0
    weighted = 0.0
    for rt, k in runtimes.items():
        rt = rt.lower()
        if rt.startswith("provided"):
            f = CUSTOM_RUNTIME_FACTOR
        elif rt == "container":
            f = CONTAINER_FACTOR
        elif _OLD_RUNTIME.match(rt):
            f = OLD_RUNTIME_FACTOR
        else:
            f = 1.0
        weighted += f * k
    return weighted / n


def rds_family(engine: str) -> str:
    e = engine.lower()
    if e.startswith("aurora"):
        return "aurora"
    if e.startswith(("oracle", "sqlserver", "db2")):
        return "commercial"
    return "open"


def resource_days(totals: dict) -> dict[str, dict]:
    """{catalog service: {"days", "resources", "items": [{label, count, days}]}} from inventory totals."""
    out: dict[str, dict] = {}

    def add(service: str, label: str, count: float, days: float) -> None:
        if count <= 0:
            return
        row = out.setdefault(service, {"days": 0.0, "resources": 0, "items": []})
        row["days"] += days
        row["resources"] += int(count)
        row["items"].append({"label": label, "count": int(count), "days": round(days, 1)})

    for key, (service, base, label) in RESOURCES.items():
        n = totals.get(key) or 0
        if not isinstance(n, (int, float)):
            continue
        factor = lambda_complexity(totals.get("lambda_runtimes") or {}) if key == "lambda_functions" else 1.0
        add(service, label, n, repeat_count(n) * base * factor)
    engines = totals.get("rds_engines") or {}
    by_family: dict[str, int] = {}
    for engine, n in engines.items():
        by_family[rds_family(engine)] = by_family.get(rds_family(engine), 0) + n
    for family, n in sorted(by_family.items()):
        add(RDS_SERVICE, f"RDS instances ({family})", n, repeat_count(n) * RDS_DAYS[family])
    return out


def edge_tier(edge: str, catalog: Catalog) -> int:
    """An integration is as hard to replace as the more locked-in AWS service at either end."""
    tiers = [
        catalog.lookup(EDGE_SERVICES.get(end, end)).tier for end in edge.split(">", 1) if end and end not in OUTSIDE_AWS
    ]
    return max(tiers, default=3)


def integration_days(edges: dict[str, int], catalog: Catalog) -> list[dict]:
    """One row per kind of integration: {edge, source service, count, tier, days}."""
    rows = []
    for edge, n in sorted(edges.items(), key=lambda kv: -kv[1]):
        if n <= 0 or platform_edge(edge):  # AWS's own security wiring, in scans saved before it was left out
            continue
        src, _, dst = edge.partition(">")
        per = INTEGRATION_DAYS_BY_TARGET.get(dst, INTEGRATION_DAYS)
        rows.append(
            {
                "edge": edge,
                "service": EDGE_SERVICES.get(src, src),
                "count": int(n),
                "tier": edge_tier(edge, catalog),
                "days": round(repeat_count(n) * per, 2),
            }
        )
    return rows


def assumptions() -> list[str]:
    """The coefficients in words, for the estimate's list of assumptions."""
    per = ", ".join(f"{label} {base:g}" for _, (_, base, label) in RESOURCES.items())
    return [
        "Effort from resources (deep-scanned accounts): engineer-days per resource: "
        f"{per}; RDS instances {RDS_DAYS['open']:g} (open-source engine), {RDS_DAYS['commercial']:g} "
        f"(Oracle, SQL Server, Db2), {RDS_DAYS['aurora']:g} (Aurora). Lambda functions on a custom runtime "
        f"x{CUSTOM_RUNTIME_FACTOR:g}, on an end-of-support runtime x{OLD_RUNTIME_FACTOR:g}, packaged as "
        f"containers x{CONTAINER_FACTOR:g}. After the first {REPEAT_FULL} of a type in an account, each further "
        f"one counts {REPEAT_SHARE:.0%} (repeat work). Uncalibrated planning assumptions: challenge them with "
        "your own migration history.",
        f"Integration redesign (dependency scan): {INTEGRATION_DAYS:g} engineer-day per AWS-specific "
        "integration (event source mappings, EventBridge targets, SNS subscriptions, API Gateway integrations, "
        "Step Functions tasks), less for e-mail, SMS and HTTP endpoints, with the same repeat discount; each "
        "counted once, so shared resources are not counted twice.",
    ]
