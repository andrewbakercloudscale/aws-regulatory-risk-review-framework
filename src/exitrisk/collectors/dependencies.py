"""Dependency discovery inside member accounts (the "dependency scan").

The inventory counts *things*; this module counts the *wiring between them* that an exit has to
rebuild: a Lambda function fed by an SQS queue, an EventBridge rule that starts a state machine,
an API Gateway route that calls Lambda. Each is an AWS-specific integration with no like-for-like
equivalent elsewhere, whatever the bill says. One low-cost function can sit in the middle of five.

What is recorded is a count per edge, ``"sqs>lambda": 12``, never an ARN, a name or a definition.
Every edge comes from declared configuration (the evidence source is named per edge kind in
``EDGE_SOURCES``). Calls made inside code (an SDK call from a function to DynamoDB) and network
traffic are not visible here, so an account with no discovered edges is *unmeasured*, not
independent: the report says so.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import BOTO_CONFIG
from ..issues import Issue, describe_exception
from ..logging_config import get_logger

log = get_logger("dependencies")

# Per-region caps on the calls made once per resource, so one huge account cannot stall a scan.
# When a cap is hit the edges found so far are kept and an info issue says the count is a floor.
MAX_RULES = 300
MAX_REST_APIS = 100
MAX_HTTP_APIS = 100
MAX_STATE_MACHINES = 200

# ARN service prefix -> the short name used in edge keys. Anything else keeps its own prefix.
_ARN_SERVICE = {"states": "stepfunctions", "execute-api": "apigateway", "kafka": "msk", "events": "eventbridge"}

# Where each kind of edge is read from: shown on the report as the evidence for the count.
EDGE_SOURCES = {
    "lambda_trigger": "Lambda event source mappings (lambda:ListEventSourceMappings)",
    "eventbridge_target": "EventBridge rule targets (events:ListTargetsByRule)",
    "sns_subscription": "SNS subscriptions (sns:ListSubscriptions)",
    "apigateway_integration": "API Gateway integrations (apigateway:GET)",
    "stepfunctions_task": "Step Functions task states (states:DescribeStateMachine; definitions are not stored)",
}

# What the dependency scan cannot see. Listed on every report that uses it.
NOT_DISCOVERED = [
    "SDK calls made inside code (for example a function writing to DynamoDB)",
    "S3 event notifications and Lambda resource-policy triggers",
    "network traffic between workloads (VPC Flow Logs, X-Ray or OpenTelemetry would show it)",
]


def _service_of(arn: str) -> str:
    """'arn:aws:sqs:eu-west-1:1:q' -> 'sqs'; anything that is not an ARN is outside AWS ('http')."""
    parts = arn.split(":")
    if len(parts) < 3 or parts[0] != "arn":
        return "http"
    return _ARN_SERVICE.get(parts[2], parts[2])


def _lambda_triggers(session, region: str, edges: Counter, notes: list[str]) -> None:
    c = session.client("lambda", region_name=region, config=BOTO_CONFIG)
    for page in c.get_paginator("list_event_source_mappings").paginate():
        for m in page.get("EventSourceMappings", []):
            src = _service_of(m.get("EventSourceArn", "")) if m.get("EventSourceArn") else "kafka"
            edges[f"{src}>lambda"] += 1


def _eventbridge_targets(session, region: str, edges: Counter, notes: list[str]) -> None:
    c = session.client("events", region_name=region, config=BOTO_CONFIG)
    seen = 0
    for page in c.get_paginator("list_rules").paginate():
        for rule in page.get("Rules", []):
            if seen >= MAX_RULES:
                notes.append(f"EventBridge: targets read for the first {MAX_RULES} rules only")
                return
            seen += 1
            targets = c.list_targets_by_rule(Rule=rule["Name"], EventBusName=rule.get("EventBusName", "default"))
            for t in targets.get("Targets", []):
                edges[f"eventbridge>{_service_of(t.get('Arn', ''))}"] += 1


def _sns_subscriptions(session, region: str, edges: Counter, notes: list[str]) -> None:
    c = session.client("sns", region_name=region, config=BOTO_CONFIG)
    for page in c.get_paginator("list_subscriptions").paginate():
        for s in page.get("Subscriptions", []):
            proto = (s.get("Protocol") or "").lower()
            target = {"https": "http", "email-json": "email", "application": "mobile"}.get(proto, proto)
            if s.get("SubscriptionArn", "").startswith("arn:"):  # skip PendingConfirmation
                edges[f"sns>{target}"] += 1


def _integration_target(kind: str, uri: str, subtype: str = "") -> str | None:
    """The service an API Gateway integration calls, or None for mocks."""
    kind = kind.upper()
    if kind == "MOCK":
        return None
    if kind.startswith("HTTP"):
        return "http"
    if subtype:  # HTTP API first-class integrations, "SQS-SendMessage"
        return subtype.split("-", 1)[0].lower()
    if ":lambda:" in uri:
        return "lambda"
    # REST "AWS" integrations: arn:aws:apigateway:{region}:{service}:action/...
    parts = uri.split(":")
    svc = parts[4] if len(parts) > 4 and parts[2] == "apigateway" else "aws"
    return _ARN_SERVICE.get(svc, svc)


def _apigateway(session, region: str, edges: Counter, notes: list[str]) -> None:
    rest = session.client("apigateway", region_name=region, config=BOTO_CONFIG)
    apis = [a["id"] for page in rest.get_paginator("get_rest_apis").paginate() for a in page.get("items", [])]
    if len(apis) > MAX_REST_APIS:
        notes.append(f"API Gateway: integrations read for the first {MAX_REST_APIS} REST APIs only")
    for api_id in apis[:MAX_REST_APIS]:
        for page in rest.get_paginator("get_resources").paginate(restApiId=api_id, embed=["methods"]):
            for res in page.get("items", []):
                for method in (res.get("resourceMethods") or {}).values():
                    integ = method.get("methodIntegration") or {}
                    target = _integration_target(integ.get("type", ""), integ.get("uri", ""))
                    if target:
                        edges[f"apigateway>{target}"] += 1
    http = session.client("apigatewayv2", region_name=region, config=BOTO_CONFIG)
    items = http.get_apis().get("Items", [])
    if len(items) > MAX_HTTP_APIS:
        notes.append(f"API Gateway: integrations read for the first {MAX_HTTP_APIS} HTTP APIs only")
    for api in items[:MAX_HTTP_APIS]:
        for integ in http.get_integrations(ApiId=api["ApiId"]).get("Items", []):
            target = _integration_target(
                integ.get("IntegrationType", ""), integ.get("IntegrationUri", ""), integ.get("IntegrationSubtype", "")
            )
            if target:
                edges[f"apigateway>{target}"] += 1


def _task_targets(definition: dict) -> list[str]:
    """The services a state machine's Task states call, walking Parallel and Map branches."""
    out = []

    def walk(states: dict) -> None:
        for st in (states or {}).values():
            res = st.get("Resource", "")
            if st.get("Type") == "Task" and res:
                # arn:aws:states:::dynamodb:putItem, arn:aws:states:::aws-sdk:s3:getObject, or a Lambda ARN
                parts = res.split(":")
                if res.startswith("arn:aws:states:::"):
                    svc = parts[6] if len(parts) > 6 and parts[5] == "aws-sdk" else parts[5]
                    svc = svc.split(".")[0]
                    out.append(_ARN_SERVICE.get(svc, svc))
                else:
                    out.append(_service_of(res))
            for branch in st.get("Branches", []):
                walk(branch.get("States", {}))
            walk((st.get("Iterator") or st.get("ItemProcessor") or {}).get("States", {}))

    walk(definition.get("States", {}))
    return out


def _stepfunctions(session, region: str, edges: Counter, notes: list[str]) -> None:
    c = session.client("stepfunctions", region_name=region, config=BOTO_CONFIG)
    machines = [
        m["stateMachineArn"]
        for page in c.get_paginator("list_state_machines").paginate()
        for m in page.get("stateMachines", [])
    ]
    if len(machines) > MAX_STATE_MACHINES:
        notes.append(f"Step Functions: definitions read for the first {MAX_STATE_MACHINES} state machines only")
    for arn in machines[:MAX_STATE_MACHINES]:
        try:
            definition = json.loads(c.describe_state_machine(stateMachineArn=arn).get("definition") or "{}")
        except ValueError:
            continue  # not JSON: nothing to count, and the definition itself is never kept
        for target in _task_targets(definition):
            edges[f"stepfunctions>{target}"] += 1


# (edge kind, discovery function). Each runs on its own so one refusal loses only its edges.
DISCOVERIES: list[tuple[str, Callable]] = [
    ("lambda_trigger", _lambda_triggers),
    ("eventbridge_target", _eventbridge_targets),
    ("sns_subscription", _sns_subscriptions),
    ("apigateway_integration", _apigateway),
    ("stepfunctions_task", _stepfunctions),
]


def discover_region(session: boto3.Session, account_id: str, region: str) -> tuple[dict, list[str], list[Issue]]:
    """({edge: count}, kinds discovered, issues) for one region of one account."""
    edges: Counter = Counter()
    notes: list[str] = []
    issues: list[Issue] = []
    done: list[str] = []
    for kind, fn in DISCOVERIES:
        try:
            fn(session, region, edges, notes)
            done.append(kind)
        except (ClientError, BotoCoreError) as exc:
            code, msg, hint = describe_exception(exc)
            if (
                code in ("OptInRequired", "UnrecognizedClientException", "InvalidClientTokenId")
                and region != "us-east-1"
            ):
                done.append(kind)  # region not usable by this account; nothing to discover
                continue
            issues.append(
                Issue(
                    "warning",
                    "dependencies",
                    f"{kind} in {region}: {msg}",
                    hint or "Grant the dependency-scan actions in iam/member-account-role-policy.json.",
                    account_id=account_id,
                    region=region,
                    error_code=code,
                )
            )
            log.warning(
                "dependencies %s %s %s failed: %s",
                account_id,
                region,
                kind,
                code,
                extra={"account_id": account_id, "region": region, "error_code": code},
            )
    for note in notes:
        issues.append(
            Issue(
                "info",
                "dependencies",
                f"{note} in {region}; the count is a floor",
                account_id=account_id,
                region=region,
            )
        )
    return dict(edges), done, issues
