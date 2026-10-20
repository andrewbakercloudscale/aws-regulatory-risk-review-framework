"""Scanner failure handling: errors become issues and the scan document is still saved."""

import pytest
from botocore.exceptions import ClientError

from exitrisk import scanner, store
from exitrisk.scanner import ScanJob, ScanParams


def test_params_validation():
    with pytest.raises(ValueError):
        ScanParams(months=0).validate()
    with pytest.raises(ValueError):
        ScanParams(inventory=True).validate()


def test_auth_failure_is_recorded_and_saved(monkeypatch):
    def boom(_session):
        raise ClientError({"Error": {"Code": "ExpiredToken", "Message": "token expired"}}, "GetCallerIdentity")

    monkeypatch.setattr(scanner, "caller_identity", boom)
    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    job = ScanJob(id=store.new_scan_id(), params=ScanParams(profile="p"))
    scanner._run_safely(job)
    assert job.status == "failed"
    saved = store.load_scan(job.id)
    assert saved["status"] == "failed"
    assert any(i["severity"] == "critical" and i["error_code"] == "ExpiredToken" for i in saved["issues"])
    assert any("Touch ID" in i["hint"] for i in saved["issues"])


def test_organizations_unavailable_falls_back_to_single_account(monkeypatch):
    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "123456789012", "arn": "arn:x"})

    def no_org(_s):
        raise ClientError({"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "no org"}}, "Describe")

    monkeypatch.setattr(scanner.organizations, "describe_org", no_org)
    monkeypatch.setattr(
        scanner.cost,
        "fetch_costs",
        lambda s, ids, m: (
            [{"month": "2026-09", "account_id": ids[0], "service": "AWS Lambda", "amount": 10.0}],
            {"start": "2026-09-01", "end": "2026-10-01", "months": 1},
        ),
    )
    job = ScanJob(id=store.new_scan_id(), params=ScanParams())
    doc = scanner.run_scan(job)
    assert doc["status"] == "complete"
    assert doc["accounts"][0]["id"] == "123456789012"
    assert any(i["category"] == "organizations" for i in doc["issues"])


def test_member_account_fallback_names_management_account(monkeypatch):
    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "222222222222", "arn": "arn:x"})
    monkeypatch.setattr(
        scanner.organizations, "describe_org", lambda s: {"id": "o-1", "management_account_id": "111111111111"}
    )

    def denied(_s):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListRoots")

    monkeypatch.setattr(scanner.organizations, "list_ou_tree", denied)
    monkeypatch.setattr(
        scanner.cost, "fetch_costs", lambda s, ids, m: ([], {"start": "2026-09-01", "end": "2026-10-01", "months": 1})
    )
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    org_issue = next(i for i in doc["issues"] if i["category"] == "organizations")
    assert "111111111111" in org_issue["message"] and "111111111111" in org_issue["hint"]
    assert doc["ou"]["name"] == "Single member account"


def test_several_ous_scan_each_account_once(monkeypatch):
    def node(i, name, path, children=()):
        return {"id": i, "name": name, "path": path, "children": list(children)}

    child = node("ou-a-kid", "kid", "Root / A / kid")
    tree = node("r-1", "Root", "Root", [node("ou-a", "A", "Root / A", [child]), node("ou-b", "B", "Root / B")])
    members = {"ou-a": ["1", "2"], "ou-a-kid": ["2"], "ou-b": ["3"]}  # account 2 sits under A and its child

    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "111111111111", "arn": "arn:x"})
    monkeypatch.setattr(
        scanner.organizations, "describe_org", lambda s: {"id": "o-1", "management_account_id": "111111111111"}
    )
    monkeypatch.setattr(scanner.organizations, "list_ou_tree", lambda s: tree)
    monkeypatch.setattr(
        scanner.organizations,
        "list_accounts_under",
        lambda s, ou: [
            scanner.organizations.Account(i, f"acct-{i}", "", "ACTIVE", ou["id"], ou["path"]) for i in members[ou["id"]]
        ],
    )
    monkeypatch.setattr(
        scanner.cost, "fetch_costs", lambda s, ids, m: ([], {"start": "2026-09-01", "end": "2026-10-01", "months": 1})
    )
    params = ScanParams(ou_ids=["ou-a", "ou-a-kid", "ou-b"])
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=params))
    assert sorted(a["id"] for a in doc["accounts"]) == ["1", "2", "3"]
    assert doc["ou"]["name"] == "A + kid + B"
    assert [o["id"] for o in doc["ous"]] == ["ou-a", "ou-a-kid", "ou-b"]

    with pytest.raises(scanner.ScanFailed, match="ou-zzz"):
        scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams(ou_ids=["ou-zzz"])))


def _single_account(monkeypatch):
    monkeypatch.setattr(scanner, "make_session", lambda profile: object())
    monkeypatch.setattr(scanner, "caller_identity", lambda s: {"account_id": "123456789012", "arn": "arn:x"})

    def no_org(_s):
        raise ClientError({"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "no org"}}, "Describe")

    monkeypatch.setattr(scanner.organizations, "describe_org", no_org)
    monkeypatch.setattr(
        scanner.cost,
        "fetch_costs",
        lambda s, ids, m: (
            [{"month": "2026-09", "account_id": ids[0], "service": "AWS Lambda", "amount": 10.0}],
            {"start": "2026-09-01", "end": "2026-10-01", "months": 1},
        ),
    )


def test_spend_by_region_is_saved(monkeypatch):
    _single_account(monkeypatch)
    rows = [{"account_id": "123456789012", "service": "AWS Lambda", "region": "eu-west-1", "monthly": 10.0}]
    monkeypatch.setattr(scanner.cost, "fetch_region_costs", lambda s, ids, m: rows)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    assert doc["region_costs"] == rows
    assert store.load_scan(doc["id"])["region_costs"] == rows


@pytest.mark.parametrize(
    "error",
    [
        ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "GetCostAndUsage"),
        KeyError("Groups"),  # a bug, not an AWS refusal: still never fails the scan
    ],
)
def test_spend_by_region_failure_is_an_issue_not_a_failed_scan(monkeypatch, caplog, error):
    _single_account(monkeypatch)

    def boom(*_a):
        raise error

    monkeypatch.setattr(scanner.cost, "fetch_region_costs", boom)
    doc = scanner.run_scan(ScanJob(id=store.new_scan_id(), params=ScanParams()))
    assert doc["status"] == "complete" and not doc["region_costs"]
    issue = next(i for i in doc["issues"] if "spend by region" in i["message"])
    assert issue["severity"] == "warning" and "one region" in issue["hint"]
    if isinstance(error, KeyError):
        assert any(r.exc_info for r in caplog.records if "unexpected" in r.getMessage())
