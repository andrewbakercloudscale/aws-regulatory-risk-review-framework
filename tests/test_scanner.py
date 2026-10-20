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
