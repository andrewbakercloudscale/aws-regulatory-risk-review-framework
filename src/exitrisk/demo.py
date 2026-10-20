"""Synthetic organisation for demos, screenshots and tests - no AWS access needed.

The numbers are invented but shaped like a real mid-sized regulated estate: a few large
production accounts carry most of the spend, serverless and analytics accounts carry most
of the lock-in, and a long tail of dev/sandbox accounts carries little of either.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone

from . import store
from .collectors.cost import month_window
from .issues import Issue

# (name, ou, {service: monthly USD}, inventory totals)
_ARCHETYPES = [
    (
        "payments-core-prod",
        "Workloads / Production",
        {
            "Amazon Elastic Kubernetes Service": 4200,
            "Amazon Elastic Compute Cloud - Compute": 38000,
            "Amazon Relational Database Service": 26000,
            "EC2 - Other": 9000,
            "Amazon ElastiCache": 3800,
            "Amazon Managed Streaming for Apache Kafka": 7200,
            "Amazon Simple Storage Service": 4100,
            "Amazon Elastic Load Balancing": 2100,
            "AmazonCloudWatch": 3300,
            "AWS Key Management Service": 900,
            "Amazon DynamoDB": 2500,
            "AWS Lambda": 1100,
        },
        {
            "lambda_functions": 38,
            "dynamodb_tables": 6,
            "eks_clusters": 3,
            "rds_engines": {"aurora-postgresql": 6, "postgres": 2},
            "cloudformation_stacks": 12,
        },
    ),
    (
        "cards-processing-prod",
        "Workloads / Production",
        {
            "AWS Lambda": 21000,
            "Amazon DynamoDB": 31000,
            "AWS Step Functions": 6400,
            "Amazon API Gateway": 8800,
            "Amazon Kinesis": 7600,
            "Amazon Simple Queue Service": 2900,
            "Amazon EventBridge": 1500,
            "Amazon Simple Storage Service": 3900,
            "AmazonCloudWatch": 4400,
            "AWS Key Management Service": 1300,
            "Amazon Cognito": 2200,
        },
        {
            "lambda_functions": 412,
            "dynamodb_tables": 57,
            "step_functions": 41,
            "kinesis_streams": 18,
            "sqs_queues": 96,
            "api_gateway_rest": 14,
            "cognito_user_pools": 2,
            "cloudformation_stacks": 188,
        },
    ),
    (
        "data-platform-prod",
        "Workloads / Production",
        {
            "Amazon Redshift": 58000,
            "AWS Glue": 14500,
            "Amazon Athena": 6200,
            "Amazon Simple Storage Service": 21000,
            "Amazon Elastic MapReduce": 9800,
            "Amazon Kinesis Firehose": 2400,
            "AWS Lake Formation": 600,
            "Amazon QuickSight": 4800,
            "Amazon Managed Workflows for Apache Airflow": 1900,
            "EC2 - Other": 3500,
        },
        {"glue_jobs": 340, "redshift_clusters": 4, "lambda_functions": 22},
    ),
    (
        "digital-channels-prod",
        "Workloads / Production",
        {
            "Amazon Elastic Container Service": 9500,
            "Amazon Elastic Compute Cloud - Compute": 7200,
            "Amazon CloudFront": 6800,
            "AWS WAF": 1400,
            "Amazon Relational Database Service": 8900,
            "Amazon Cognito": 5100,
            "AWS AppSync": 3900,
            "AWS Amplify": 1200,
            "Amazon Simple Notification Service": 1700,
            "Amazon Pinpoint": 2600,
            "Amazon Simple Storage Service": 2300,
        },
        {"ecs_clusters": 4, "cognito_user_pools": 3, "lambda_functions": 64, "rds_engines": {"aurora-mysql": 3}},
    ),
    (
        "contact-centre-prod",
        "Workloads / Production",
        {
            "Amazon Connect": 19000,
            "Amazon Lex": 2800,
            "AWS Lambda": 2100,
            "Amazon DynamoDB": 1600,
            "Amazon Transcribe": 3100,
            "Amazon Simple Storage Service": 1400,
            "Amazon Kinesis": 1200,
        },
        {"lambda_functions": 71, "dynamodb_tables": 9, "kinesis_streams": 4},
    ),
    (
        "ml-platform-prod",
        "Workloads / Production",
        {
            "Amazon SageMaker": 17500,
            "Amazon Bedrock": 9400,
            "Amazon Elastic Compute Cloud - Compute": 6000,
            "Amazon Simple Storage Service": 3800,
            "Amazon Textract": 2700,
            "Amazon OpenSearch Service": 4300,
            "Amazon Bedrock AgentCore": 1100,
            "AWS Transform": 450,
        },
        {"lambda_functions": 19},
    ),
    (
        "core-banking-prod",
        "Workloads / Production",
        {
            "Amazon Elastic Compute Cloud - Compute": 52000,
            "EC2 - Other": 14000,
            "Amazon Relational Database Service": 31000,
            "Amazon FSx": 5200,
            "AWS Backup": 3100,
            "Amazon Elastic Load Balancing": 1800,
            "AWS Direct Connect": 4200,
            "Amazon MQ": 1300,
        },
        {"rds_engines": {"oracle-ee": 4, "sqlserver-ee": 2}, "cloudformation_stacks": 6},
    ),
    (
        "shared-network-prod",
        "Infrastructure",
        {
            "Amazon Virtual Private Cloud": 11000,
            "EC2 - Other": 7600,
            "AWS Network Firewall": 4800,
            "AWS Direct Connect": 6100,
            "Amazon Route 53": 900,
            "AWS Global Accelerator": 700,
        },
        {},
    ),
    (
        "identity-prod",
        "Infrastructure",
        {
            "AWS Directory Service": 2100,
            "Amazon Elastic Compute Cloud - Compute": 3200,
            "AWS Secrets Manager": 600,
            "AWS Certificate Manager": 1500,
        },
        {},
    ),
    (
        "security-audit",
        "Security",
        {
            "Amazon GuardDuty": 4800,
            "AWS Security Hub": 2200,
            "AWS Config": 3600,
            "AWS CloudTrail": 2900,
            "Amazon Inspector": 1100,
            "Amazon Simple Storage Service": 1800,
        },
        {},
    ),
    (
        "log-archive",
        "Security",
        {"Amazon Simple Storage Service": 6800, "Amazon Glacier": 2400, "Amazon OpenSearch Service": 3900},
        {},
    ),
    (
        "payments-core-uat",
        "Workloads / Non-production",
        {
            "Amazon Elastic Kubernetes Service": 1400,
            "Amazon Elastic Compute Cloud - Compute": 9200,
            "Amazon Relational Database Service": 6100,
            "Amazon Managed Streaming for Apache Kafka": 1900,
            "EC2 - Other": 2100,
        },
        {},
    ),
    (
        "cards-processing-uat",
        "Workloads / Non-production",
        {
            "AWS Lambda": 2600,
            "Amazon DynamoDB": 3900,
            "AWS Step Functions": 800,
            "Amazon API Gateway": 900,
            "Amazon Kinesis": 1100,
        },
        {"lambda_functions": 405, "dynamodb_tables": 55},
    ),
    (
        "data-platform-dev",
        "Workloads / Non-production",
        {"Amazon Redshift": 7400, "AWS Glue": 2900, "Amazon Athena": 900, "Amazon Simple Storage Service": 2100},
        {},
    ),
    (
        "digital-channels-dev",
        "Workloads / Non-production",
        {
            "Amazon Elastic Container Service": 1900,
            "Amazon CloudFront": 400,
            "Amazon Relational Database Service": 1500,
            "Amazon Cognito": 300,
            "AWS AppSync": 600,
        },
        {},
    ),
    (
        "fraud-analytics-prod",
        "Workloads / Production",
        {
            "Amazon Neptune": 6200,
            "Amazon Kinesis Analytics": 3300,
            "AWS Lambda": 900,
            "Amazon DynamoDB": 2400,
            "Amazon Timestream": 1800,
            "Amazon SageMaker": 3900,
        },
        {"lambda_functions": 33, "dynamodb_tables": 7},
    ),
    (
        "treasury-reporting-prod",
        "Workloads / Production",
        {
            "AWS Lambda": 480,
            "Amazon DynamoDB": 900,
            "AWS Step Functions": 260,
            "Amazon QuickSight": 700,
            "Amazon Simple Storage Service": 200,
        },
        {"lambda_functions": 54, "dynamodb_tables": 12, "step_functions": 9},
    ),
    (
        "sandbox-innovation",
        "Sandbox",
        {
            "Amazon Bedrock": 2100,
            "AWS Lambda": 300,
            "Amazon DynamoDB": 220,
            "Amazon Elastic Compute Cloud - Compute": 900,
        },
        {},
    ),
    (
        "sandbox-platform-team",
        "Sandbox",
        {"Amazon Elastic Kubernetes Service": 300, "Amazon Elastic Compute Cloud - Compute": 1200},
        {},
    ),
    (
        "legacy-batch-prod",
        "Workloads / Production",
        {
            "Amazon Elastic Compute Cloud - Compute": 2400,
            "AWS Batch": 0.01,
            "Amazon Simple Workflow Service": 650,
            "AWS Data Pipeline": 300,
            "Amazon Simple Storage Service": 500,
        },
        {},
    ),
    ("suspended-old-crm", "Suspended", {}, {}),
]


def _seasonality(month_index: int, rng: random.Random) -> float:
    # gentle growth with noise, as in most estates
    return (0.9 + 0.035 * month_index) * rng.uniform(0.95, 1.05)


def build_demo_scan(months: int = 6, seed: int = 7) -> dict:
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data, not security
    start, end = month_window(months)
    y, m = int(start[:4]), int(start[5:7])
    month_keys = []
    for _ in range(months):
        month_keys.append(f"{y:04d}-{m:02d}")
        m += 1
        if m > 12:
            m, y = 1, y + 1

    accounts, costs, inventory = [], [], {}
    for i, (name, ou, services, inv) in enumerate(_ARCHETYPES):
        aid = f"{rng.randint(10**11, 10**12 - 1)}"
        accounts.append(
            {
                "id": aid,
                "name": name,
                "email": f"aws+{name}@example.com",
                "status": "SUSPENDED" if ou == "Suspended" else "ACTIVE",
                "ou_id": f"ou-demo-{i:02d}",
                "ou_path": f"Root / {ou}",
            }
        )
        for mi, month in enumerate(month_keys):
            factor = _seasonality(mi, rng)
            for svc, amt in services.items():
                costs.append(
                    {
                        "month": month,
                        "account_id": aid,
                        "service": svc,
                        "amount": round(amt * factor * rng.uniform(0.97, 1.03), 2),
                    }
                )
            if services:
                costs.append(
                    {
                        "month": month,
                        "account_id": aid,
                        "service": "Tax",
                        "amount": round(sum(services.values()) * 0.15 * factor, 2),
                    }
                )
        if inv:
            inventory[aid] = {
                "regions_scanned": ["eu-west-1", "eu-west-2", "us-east-1"],
                "totals": inv,
                "by_region": {},
            }

    by_name = {a["name"]: a["id"] for a in accounts}
    issues = [
        Issue(
            "error",
            "inventory",
            "cannot assume ExitRiskReadOnly in sandbox-innovation: User is not authorized to perform: sts:AssumeRole",
            "Deploy the read-only role from docs/IAM_PERMISSIONS.md.",
            account_id=by_name["sandbox-innovation"],
            error_code="AccessDenied",
        ).to_dict(),
        Issue(
            "warning",
            "inventory",
            "eventbridge_rules in ap-southeast-2: Rate exceeded",
            "AWS throttled the request after retries. Re-run, or lower EXITRISK_MAX_WORKERS.",
            account_id=by_name["data-platform-prod"],
            region="ap-southeast-2",
            error_code="ThrottlingException",
        ).to_dict(),
        Issue(
            "info",
            "organizations",
            "account suspended-old-crm is SUSPENDED; its spend is still included if any was billed",
            account_id=by_name["suspended-old-crm"],
        ).to_dict(),
        Issue(
            "info",
            "cost",
            "no spend recorded for suspended-old-crm in the period",
            account_id=by_name["suspended-old-crm"],
        ).to_dict(),
    ]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "id": store.new_scan_id(),
        "label": "Demo organisation (synthetic data)",
        "mode": "demo",
        "created_at": now,
        "finished_at": now,
        "status": "complete",
        "params": {
            "profile": "demo",
            "ou_id": "r-demo",
            "months": months,
            "role_name": "ExitRiskReadOnly",
            "inventory": True,
            "regions": None,
            "label": "Demo",
        },
        "identity": {"account_id": "111111111111", "arn": "arn:aws:iam::111111111111:role/demo"},
        "org": {"id": "o-demo1234", "management_account_id": "111111111111"},
        "ou": {"id": "r-demo", "name": "Root", "path": "Root"},
        "accounts": accounts,
        "costs": costs,
        "period": {"start": start, "end": end, "months": months},
        "inventory": inventory,
        "issues": issues,
    }


def create_demo_scan(months: int = 6) -> dict:
    scan = build_demo_scan(months)
    store.save_scan(scan)
    return scan
