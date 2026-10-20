"""Collectors against botocore Stubber - no network, no credentials."""

from datetime import date

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import ANY, Stubber

from exitrisk.collectors import cost, organizations
from exitrisk.issues import describe_exception, is_fatal_auth_error


def _session():
    return boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1")


def test_month_window():
    assert cost.month_window(3, date(2026, 10, 20)) == ("2026-07-01", "2026-10-01")
    assert cost.month_window(12, date(2026, 1, 5)) == ("2025-01-01", "2026-01-01")


def test_fetch_costs_paginates_and_keeps_marketplace_products(monkeypatch):
    client = boto3.client("ce", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    stub = Stubber(client)

    def group(acct, svc, amt):
        return {"Keys": [acct, svc], "Metrics": {"AmortizedCost": {"Amount": str(amt), "Unit": "USD"}}}

    period = {"TimePeriod": {"Start": "2026-09-01", "End": "2026-10-01"}, "Estimated": False}
    stub.add_response(
        "get_cost_and_usage",
        {"ResultsByTime": [{**period, "Groups": [group("1", "AWS Lambda", 10)]}], "NextPageToken": "t"},
        {**{k: ANY for k in ("TimePeriod", "Granularity", "Metrics", "GroupBy", "Filter")}},
    )
    stub.add_response(
        "get_cost_and_usage",
        {"ResultsByTime": [{**period, "Groups": [group("1", "AWS Lambda", 5)]}]},
        {k: ANY for k in ("TimePeriod", "Granularity", "Metrics", "GroupBy", "Filter", "NextPageToken")},
    )
    stub.add_response(
        "get_cost_and_usage",
        {
            "ResultsByTime": [
                {
                    **period,
                    "Groups": [group("1", "Some SaaS", 7), group("1", "Claude Opus 4.6 (Amazon Bedrock Edition)", 3)],
                }
            ]
        },
        {k: ANY for k in ("TimePeriod", "Granularity", "Metrics", "GroupBy", "Filter")},
    )
    session = _session()
    monkeypatch.setattr(session, "client", lambda *a, **k: client)
    with stub:
        rows, period_out = cost.fetch_costs(session, ["1"], 1)
    by_svc = {(r["service"], r.get("product")): r["amount"] for r in rows}
    assert by_svc == {
        ("AWS Lambda", None): 15.0,
        (cost.MARKETPLACE_SERVICE, "Some SaaS"): 7.0,
        # Third-party models on Bedrock bill through Marketplace but are Bedrock usage.
        (cost.BEDROCK_SERVICE, "Claude Opus 4.6 (Amazon Bedrock Edition)"): 3.0,
    }
    assert period_out["months"] == 1


def test_list_accounts_recurses_ou_tree(monkeypatch):
    client = boto3.client("organizations", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    stub = Stubber(client)
    mgmt = {"Accounts": [{"Id": "111111111111", "Name": "mgmt", "Email": "a@example.com", "Status": "ACTIVE"}]}
    app = {"Accounts": [{"Id": "222222222222", "Name": "app-prod", "Email": "b@example.com", "Status": "ACTIVE"}]}
    stub.add_response("list_roots", {"Roots": [{"Id": "r-ab12", "Name": "Root"}]})
    # Building the tree counts each node's accounts, then lists its child OUs.
    stub.add_response("list_accounts_for_parent", mgmt, {"ParentId": "r-ab12"})
    stub.add_response(
        "list_organizational_units_for_parent",
        {"OrganizationalUnits": [{"Id": "ou-ab12-abcd1234", "Name": "Prod"}]},
        {"ParentId": "r-ab12"},
    )
    stub.add_response("list_accounts_for_parent", app, {"ParentId": "ou-ab12-abcd1234"})
    stub.add_response(
        "list_organizational_units_for_parent", {"OrganizationalUnits": []}, {"ParentId": "ou-ab12-abcd1234"}
    )
    stub.add_response("list_accounts_for_parent", mgmt, {"ParentId": "r-ab12"})
    stub.add_response("list_accounts_for_parent", app, {"ParentId": "ou-ab12-abcd1234"})
    session = _session()
    monkeypatch.setattr(session, "client", lambda *a, **k: client)
    with stub:
        tree = organizations.list_ou_tree(session)
        accts = organizations.list_accounts_under(session, tree)
    assert tree["children"][0]["path"] == "Root / Prod"
    assert (tree["accounts"], tree["children"][0]["accounts"]) == (1, 1)
    assert {a.name: a.ou_path for a in accts} == {"mgmt": "Root", "app-prod": "Root / Prod"}
    assert organizations.find_ou(tree, "ou-ab12-abcd1234")["name"] == "Prod"


@pytest.mark.parametrize("code,fatal", [("AccessDeniedException", False), ("ExpiredToken", True)])
def test_describe_exception(code, fatal):
    exc = ClientError({"Error": {"Code": code, "Message": "nope"}}, "Op")
    got_code, msg, hint = describe_exception(exc)
    assert got_code == code and msg == "nope" and hint
    assert is_fatal_auth_error(code) is fatal


def test_fetch_storage_keeps_gb_months_and_classifies(monkeypatch):
    client = boto3.client("ce", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    stub = Stubber(client)

    def group(acct, usage, gb, unit="GB-Mo"):
        return {"Keys": [acct, usage], "Metrics": {"UsageQuantity": {"Amount": str(gb), "Unit": unit}}}

    period = {"TimePeriod": {"Start": "2026-09-01", "End": "2026-10-01"}, "Estimated": False}
    stub.add_response(
        "get_cost_and_usage",
        {
            "ResultsByTime": [
                {
                    **period,
                    "Groups": [
                        group("111111111111", "EUW2-TimedStorage-ByteHrs", 2048),
                        group("111111111111", "EUW2-TimedStorage-GlacierByteHrs", 1024),
                        group("111111111111", "EUW2-EarlyDelete-GDA", 500),  # a fee, not data held
                        group("111111111111", "EUW2-Requests-Tier1", 9999, unit="Requests"),
                    ],
                }
            ]
        },
    )
    stub.add_response(
        "get_cost_and_usage",
        {"ResultsByTime": [{**period, "Groups": [group("111111111111", "EUW2-EBS:SnapshotUsage", 300)]}]},
    )
    session = _session()
    monkeypatch.setattr(session, "client", lambda *a, **k: client)
    with stub:
        rows = cost.fetch_storage(
            session, ["111111111111"], {"Amazon Simple Storage Service", "EC2 - Other", "AWS Lambda"}
        )
    assert [(r["usage_type"], r["kind"], r["gb"]) for r in rows] == [
        ("EUW2-TimedStorage-ByteHrs", "live", 2048.0),
        ("EUW2-TimedStorage-GlacierByteHrs", "archive", 1024.0),
        ("EUW2-EBS:SnapshotUsage", "copy", 300.0),
    ]


def test_fetch_account_tags_trims_keys(monkeypatch):
    client = boto3.client("organizations", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    stub = Stubber(client)
    stub.add_response(
        "list_tags_for_resource",
        {"Tags": [{"Key": "Criticality ", "Value": " Tier 1"}]},
        {"ResourceId": "222222222222"},
    )
    session = _session()
    monkeypatch.setattr(session, "client", lambda *a, **k: client)
    with stub:
        assert organizations.fetch_account_tags(session, ["222222222222"]) == {
            "222222222222": {"Criticality": "Tier 1"}
        }
