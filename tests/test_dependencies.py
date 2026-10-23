"""Dependency scan, resource-based effort and the five dimensions: no network, no credentials."""

import json

import pytest
from botocore.exceptions import ClientError

from exitrisk.catalog import load_catalog
from exitrisk.collectors import dependencies as dep
from exitrisk.demo import build_demo_scan
from exitrisk.dimensions import edge_label, scan_depth
from exitrisk.estimate import Questionnaire
from exitrisk.resource_effort import (
    REPEAT_FULL,
    REPEAT_SHARE,
    integration_days,
    lambda_complexity,
    rds_family,
    repeat_count,
    resource_days,
)
from exitrisk.scanner import material_accounts
from exitrisk.scoring import build_report

CATALOG = load_catalog()


class _Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_):
        return iter(self.pages)


class _Client:
    """Just enough of a boto3 client: paginators return fixed pages, calls return fixed responses."""

    def __init__(self, pages=None, calls=None, error=None):
        self.pages, self.calls, self.error = pages or {}, calls or {}, error

    def get_paginator(self, name):
        if self.error:
            raise self.error
        return _Pager(self.pages.get(name, [{}]))

    def __getattr__(self, name):
        if name in self.calls:
            return self.calls[name]
        raise AttributeError(name)


class _Session:
    def __init__(self, clients):
        self.clients = clients

    def client(self, name, **_):
        return self.clients.get(name) or _Client()


DEFINITION = {
    "States": {
        "Charge": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke"},
        "Save": {"Type": "Task", "Resource": "arn:aws:states:::dynamodb:putItem"},
        "Fan": {
            "Type": "Parallel",
            "Branches": [{"States": {"Put": {"Type": "Task", "Resource": "arn:aws:states:::aws-sdk:s3:putObject"}}}],
        },
        "Each": {
            "Type": "Map",
            "ItemProcessor": {
                "States": {"Run": {"Type": "Task", "Resource": "arn:aws:states:::glue:startJobRun.sync"}}
            },
        },
        "Wait": {"Type": "Wait", "Seconds": 1},
    }
}


def _sessions(denied_sns=False):
    sqs = "arn:aws:sqs:eu-west-1:1:q"
    clients = {
        "lambda": _Client(
            {
                "list_event_source_mappings": [
                    {"EventSourceMappings": [{"EventSourceArn": sqs}, {"EventSourceArn": sqs}]},
                    {"EventSourceMappings": [{"EventSourceArn": "arn:aws:kinesis:eu-west-1:1:stream/s"}, {}]},
                ]
            }
        ),
        "events": _Client(
            {"list_rules": [{"Rules": [{"Name": "r1"}, {"Name": "r2", "EventBusName": "bus"}]}]},
            {
                "list_targets_by_rule": lambda Rule, EventBusName: {
                    "Targets": [{"Arn": "arn:aws:states:eu-west-1:1:stateMachine:m"}]
                    if Rule == "r1"
                    else [{"Arn": "arn:aws:lambda:eu-west-1:1:function:f"}, {"Arn": sqs}]
                }
            },
        ),
        "sns": _Client(
            {
                "list_subscriptions": [
                    {
                        "Subscriptions": [
                            {"Protocol": "lambda", "SubscriptionArn": "arn:aws:sns:x"},
                            {"Protocol": "email", "SubscriptionArn": "arn:aws:sns:y"},
                            {"Protocol": "sqs", "SubscriptionArn": "PendingConfirmation"},
                        ]
                    }
                ]
            },
            error=ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListSubscriptions")
            if denied_sns
            else None,
        ),
        "apigateway": _Client(
            {
                "get_rest_apis": [{"items": [{"id": "a"}]}],
                "get_resources": [
                    {
                        "items": [
                            {
                                "resourceMethods": {
                                    "GET": {
                                        "methodIntegration": {
                                            "type": "AWS_PROXY",
                                            "uri": "arn:aws:apigateway:eu-west-1:lambda:path/functions/f",
                                        }
                                    },
                                    "POST": {
                                        "methodIntegration": {
                                            "type": "AWS",
                                            "uri": "arn:aws:apigateway:eu-west-1:sqs:path/1/q",
                                        }
                                    },
                                    "OPTIONS": {"methodIntegration": {"type": "MOCK"}},
                                }
                            },
                            {
                                "resourceMethods": {
                                    "ANY": {"methodIntegration": {"type": "HTTP_PROXY", "uri": "https://x"}}
                                }
                            },
                        ]
                    }
                ],
            }
        ),
        "apigatewayv2": _Client(
            calls={
                "get_apis": lambda: {"Items": [{"ApiId": "h"}]},
                "get_integrations": lambda ApiId: {
                    "Items": [{"IntegrationType": "AWS_PROXY", "IntegrationSubtype": "SQS-SendMessage"}]
                },
            }
        ),
        "stepfunctions": _Client(
            {"list_state_machines": [{"stateMachines": [{"stateMachineArn": "m1"}, {"stateMachineArn": "m2"}]}]},
            {
                "describe_state_machine": lambda stateMachineArn: {
                    "definition": json.dumps(DEFINITION) if stateMachineArn == "m1" else "not json"
                }
            },
        ),
    }
    return _Session(clients)


def test_discover_region_counts_edges_by_kind_and_never_keeps_names():
    edges, done, issues = dep.discover_region(_sessions(), "111", "eu-west-1")
    assert edges == {
        "sqs>lambda": 2,
        "kinesis>lambda": 1,
        "kafka>lambda": 1,  # a mapping with no ARN is a self-managed Kafka source
        "eventbridge>stepfunctions": 1,
        "eventbridge>lambda": 1,
        "eventbridge>sqs": 1,
        "sns>lambda": 1,
        "sns>email": 1,
        "apigateway>lambda": 1,
        "apigateway>sqs": 2,
        "apigateway>http": 1,
        "stepfunctions>lambda": 1,
        "stepfunctions>dynamodb": 1,
        "stepfunctions>s3": 1,
        "stepfunctions>glue": 1,
    }
    assert set(done) == set(dep.EDGE_SOURCES)
    assert issues == []
    assert "arn" not in json.dumps(edges)


def test_discover_region_refusal_loses_only_that_kind():
    edges, done, issues = dep.discover_region(_sessions(denied_sns=True), "111", "eu-west-1")
    assert "sns_subscription" not in done and len(done) == len(dep.DISCOVERIES) - 1
    assert not any(k.startswith("sns>") for k in edges) and edges["sqs>lambda"] == 2
    assert [(i.severity, i.category, i.error_code) for i in issues] == [("warning", "dependencies", "AccessDenied")]


def test_discover_region_caps_rules_and_says_the_count_is_a_floor(monkeypatch):
    monkeypatch.setattr(dep, "MAX_RULES", 1)
    _, _, issues = dep.discover_region(_sessions(), "111", "eu-west-1")
    assert [i.severity for i in issues] == ["info"] and "floor" in issues[0].message


def test_repeat_discount():
    assert repeat_count(5) == 5
    assert repeat_count(REPEAT_FULL + 10) == pytest.approx(REPEAT_FULL + 10 * REPEAT_SHARE)


def test_lambda_runtimes_and_rds_engines_change_effort():
    assert lambda_complexity({}) == 1.0
    assert lambda_complexity({"python3.12": 2}) == 1.0
    assert lambda_complexity({"python3.8": 1}) > 1.0 and lambda_complexity({"nodejs16.x": 1}) > 1.0
    assert lambda_complexity({"provided.al2023": 1}) > lambda_complexity({"python3.8": 1})
    assert lambda_complexity({"container": 1}) < 1.0
    assert [rds_family(e) for e in ("aurora-postgresql", "oracle-ee", "sqlserver-se", "postgres", "mysql")] == [
        "aurora",
        "commercial",
        "commercial",
        "open",
        "open",
    ]
    days = resource_days({"rds_engines": {"aurora-mysql": 1, "postgres": 1}})
    assert days["Amazon Relational Database Service"]["days"] > 0
    assert len(days["Amazon Relational Database Service"]["items"]) == 2


def test_integrations_take_the_harder_end_and_cheap_targets_cost_less():
    rows = {r["edge"]: r for r in integration_days({"sqs>lambda": 3, "sns>email": 4, "dynamodb>lambda": 1}, CATALOG)}
    assert rows["dynamodb>lambda"]["tier"] == CATALOG.lookup("Amazon DynamoDB").tier
    assert rows["sqs>lambda"]["tier"] == max(CATALOG.lookup("AWS Lambda").tier, CATALOG.lookup("Amazon SQS").tier)
    assert rows["sns>email"]["days"] < rows["sqs>lambda"]["days"]
    assert edge_label("stepfunctions>dynamodb") == "Step Functions to DynamoDB"


def _scan(account_spend, inventory):
    """One deep-scanned account with the given monthly spend per service."""
    costs = [
        {"month": "2026-01", "account_id": "111111111111", "service": svc, "amount": amt}
        for svc, amt in account_spend.items()
    ]
    return {
        "id": "20260101-000000-abcd",
        "params": {"inventory": bool(inventory)},
        "accounts": [{"id": "111111111111", "name": "app"}],
        "costs": costs,
        "period": {"start": "2026-01-01", "end": "2026-02-01", "months": 1},
        "inventory": {"111111111111": inventory} if inventory else {},
        "issues": [],
    }


def test_twenty_dollar_lambda_outweighs_ten_thousand_dollar_ec2():
    scan = _scan(
        {"AWS Lambda": 20.0, "Amazon Elastic Compute Cloud - Compute": 10_000.0},
        {"totals": {"lambda_functions": 3, "ec2_instances": 2}, "by_region": {}},
    )
    report = build_report(scan, questionnaire=Questionnaire(confirmed=True, materiality=100))
    svc = {s["service"]: s for s in report["services"]}
    assert svc["AWS Lambda"]["effort_weeks"] > svc["Amazon Elastic Compute Cloud - Compute"]["effort_weeks"]
    acct = report["accounts"][0]
    assert acct["effort_basis"]["resources"] > 0 and acct["effort_basis"]["spend"] == 0
    assert report["summary"]["scan_depth"] == "inventory"


def test_dependency_scan_adds_integration_effort_and_lowers_portability():
    inv = {"totals": {"lambda_functions": 3, "ec2_instances": 2}, "by_region": {}}
    deep = {**inv, "dependencies": {"dynamodb>lambda": 30}, "dependency_kinds": list(dep.EDGE_SOURCES)}
    spend = {"AWS Lambda": 20.0, "Amazon Elastic Compute Cloud - Compute": 10_000.0}
    q = Questionnaire(confirmed=True, materiality=100)
    before = build_report(_scan(spend, inv), questionnaire=q)
    after = build_report(_scan(spend, deep), questionnaire=q)
    a, b = after["accounts"][0], before["accounts"][0]
    assert a["integrations"] == 30 and a["integrations_hard"] == 30
    assert a["effort_weeks"] > b["effort_weeks"] and a["portability"] < b["portability"]
    assert a["score"] == b["score"]  # the spend-weighted exposure score does not move
    s = after["summary"]
    assert s["scan_depth"] == "dependency" and s["integrations"]["total"] == 30
    assert s["integrations"]["not_discovered"] == dep.NOT_DISCOVERED


def test_quick_scan_does_not_claim_measured_dimensions():
    scan = _scan({"AWS Lambda": 5000.0}, {})
    s = build_report(scan, questionnaire=Questionnaire(confirmed=True))["summary"]
    assert s["scan_depth"] == "quick"
    dims = {d["key"]: d for d in s["dimensions"]}
    assert not dims["dependencies"]["measured"]
    assert s["measures"]["basis_pct"]["spend"] == 100


def test_inventory_scan_without_dependencies_lowers_confidence():
    scan = _scan({"AWS Lambda": 5000.0}, {"totals": {"lambda_functions": 3}, "by_region": {}})
    e = build_report(scan, questionnaire=Questionnaire(confirmed=True))["summary"]["executive"]
    assert e["confidence"] != "High"
    assert any("integrations" in r for r in e["confidence_reasons"])


def test_demo_dimensions_and_critical_readiness():
    report = build_report(build_demo_scan(), questionnaire=Questionnaire(confirmed=True))
    s = report["summary"]
    assert [d["key"] for d in s["dimensions"]] == ["portability", "dependencies", "data", "effort", "criticality"]
    assert all(d["measured"] for d in s["dimensions"])
    assert 0 < s["measures"]["portability"]["score"] < 100
    assert s["measures"]["effort"]["low_days"] < s["measures"]["effort"]["high_days"]
    assert sum(s["measures"]["basis_pct"].values()) == pytest.approx(100, abs=0.5)
    ready = s["critical_readiness"]
    assert ready and all(r["status"] in ("Ready", "Needs work", "Hard to move", "Not estimated") for r in ready)
    assert ready == sorted(ready, key=lambda r: (r["portability"] is None, r["portability"] or 0))
    assert "hard part" in s["hard_part"] and s["hard_part"] in s["narrative"]


def test_report_without_spend_still_has_dimensions():
    s = build_report(_scan({}, {}))["summary"]
    assert s["scan_depth"] == scan_depth({}) == "quick"
    assert s["measures"]["portability"]["score"] is None


def test_material_accounts_keep_the_spend_and_the_lock_in():
    costs = [
        {"account_id": "big", "service": "Amazon Elastic Compute Cloud - Compute", "month": "m", "amount": 9000},
        {"account_id": "mid", "service": "Amazon EC2", "month": "m", "amount": 900},
        {"account_id": "tiny-locked", "service": "AWS Lambda", "month": "m", "amount": 150},
        {"account_id": "tiny", "service": "Amazon Simple Storage Service", "month": "m", "amount": 5},
    ]
    keep = material_accounts(costs, 1)
    assert {"big", "tiny-locked"} <= keep and "tiny" not in keep


def test_inventory_account_counts_resources_and_collapses_repeated_refusals():
    from exitrisk.collectors import inventory

    base = _sessions(denied_sns=True).clients
    clients = {
        **base,
        "ec2": _Client(
            {"describe_instances": [{"Reservations": [{"Instances": [{}, {}]}, {"Instances": [{}]}]}]},
            {"describe_regions": lambda: {"Regions": [{"RegionName": "eu-west-1"}, {"RegionName": "eu-west-2"}]}},
        ),
        "s3": _Client(calls={"list_buckets": lambda: {"Buckets": [{}, {}]}}),
        "ecs": _Client(
            {"list_clusters": [{"clusterArns": ["c1", "c2"]}], "list_services": [{"serviceArns": ["s1", "s2"]}]}
        ),
    }
    lam = clients["lambda"]
    lam.pages["list_functions"] = [
        {"Functions": [{"Runtime": "python3.12"}, {"Runtime": "python3.8"}, {"PackageType": "Image"}]}
    ]
    out, issues = inventory.inventory_account(_Session(clients), "111", None, workers=2, dependencies=True)
    t = out["totals"]
    assert t["ec2_instances"] == 6 and t["s3_buckets"] == 2  # buckets once per account, not per region
    assert t["ecs_clusters"] == 4 and t["ecs_services"] == 8
    assert t["lambda_functions"] == 6 and t["lambda_runtimes"] == {"python3.12": 2, "python3.8": 2, "container": 2}
    assert out["dependencies"]["sqs>lambda"] == 4
    assert "sns_subscription" not in out["dependency_kinds"]
    dep_issues = [i for i in issues if i.category == "dependencies"]
    assert len(dep_issues) == 1 and "2 regions" in dep_issues[0].message


def test_the_landing_zone_baseline_is_not_counted_as_integrations():
    from collections import Counter

    read = []
    rules = [
        {"Name": "DO-NOT-DELETE-AmazonInspectorEc2ManagedRule", "ManagedBy": "inspector2.amazonaws.com"},
        {"Name": "SIRGuardDutyRule", "ManagedBy": "triage.security-ir.amazonaws.com"},
        {"Name": "aws-controltower-ConfigComplianceChangeEventRule"},
        {"Name": "orders-to-billing"},
    ]
    events = _Client(
        {"list_rules": [{"Rules": rules}]},
        {"list_targets_by_rule": lambda Rule, **_: read.append(Rule) or {"Targets": [{"Arn": "arn:aws:sqs:r:1:q"}]}},
    )
    edges: Counter = Counter()
    dep._eventbridge_targets(_Session({"events": events}), "eu-west-1", edges, [])
    assert edges == {"eventbridge>sqs": 1} and read == ["orders-to-billing"]  # AWS's rules are not even read

    subs = [
        {
            "TopicArn": "arn:aws:sns:r:1:aws-controltower-SecurityNotifications",
            "Protocol": "lambda",
            "SubscriptionArn": "arn:aws:sns:r:1:x",
        },
        {"TopicArn": "arn:aws:sns:r:1:orders", "Protocol": "sqs", "SubscriptionArn": "arn:aws:sns:r:1:y"},
    ]
    edges = Counter()
    dep._sns_subscriptions(
        _Session({"sns": _Client({"list_subscriptions": [{"Subscriptions": subs}]})}), "r", edges, []
    )
    assert edges == {"sns>sqs": 1}

    # Scans saved before: AWS's security wiring is dropped when the report is built.
    rows = integration_days(
        {"eventbridge>inspector2": 90, "eventbridge>controltower-eu-west-1": 16, "sqs>lambda": 3}, CATALOG
    )
    assert [r["edge"] for r in rows] == ["sqs>lambda"]


def test_a_function_called_from_several_states_is_one_integration():
    fn = "arn:aws:lambda:r:1:function:enrich"
    definition = {
        "States": {
            "A": {"Type": "Task", "Resource": fn},
            "B": {"Type": "Task", "Resource": fn},
            "C": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "Parameters": {"FunctionName": fn}},
            "D": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": "other"},
            },
            "E": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "Parameters": {"FunctionName": fn}},
        }
    }
    assert dep._task_targets(definition) == ["lambda", "lambda", "lambda"]


def test_inventory_counts_leave_out_the_baseline():
    from exitrisk.collectors import inventory

    lam = _Client(
        {
            "list_functions": [
                {
                    "Functions": [
                        {"FunctionName": "aws-controltower-NotificationForwarder", "Runtime": "python3.12"},
                        {"FunctionName": "orders", "Runtime": "python3.12"},
                    ]
                }
            ]
        }
    )
    assert inventory._lambda(lam) == {
        "lambda_functions": 1,
        "lambda_runtimes": {"python3.12": 1},
        "baseline_lambda_functions": 1,
    }
    rules = _Client(
        {"list_rules": [{"Rules": [{"Name": "x", "ManagedBy": "inspector2.amazonaws.com"}, {"Name": "y"}]}]}
    )
    assert inventory._rules(rules) == {"eventbridge_rules": 1, "baseline_eventbridge_rules": 1}
    stacks = dict((k, f) for _, k, f in inventory.PROBES)["cloudformation"]
    cf = _Client(
        {
            "list_stacks": [
                {
                    "StackSummaries": [
                        {"StackName": "StackSet-AWSControlTowerBP-BASELINE-CONFIG-1"},
                        {"StackName": "payments"},
                    ]
                }
            ]
        }
    )
    assert stacks(cf) == {"cloudformation_stacks": 1, "baseline_cloudformation_stacks": 1}
