import json
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.stub import Stubber
from fastapi.testclient import TestClient

from exitrisk import preflight
from exitrisk.server import create_app

ROOT = Path(__file__).resolve().parents[1]
SSO_ARN = "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_CTO-Read_0123456789abcdef/me@example.com"


class FakeSession:
    """Hands out pre-stubbed clients by service name."""

    def __init__(self, clients):
        self.clients = clients

    def client(self, name, **_kw):
        return self.clients[name]


def _stubbed(service, responses):
    c = boto3.client(service, region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    stub = Stubber(c)
    for op, resp in responses:
        if isinstance(resp, str):
            stub.add_client_error(op, resp)
        else:
            stub.add_response(op, resp)
    stub.activate()
    return c


def _session(monkeypatch, arn, org_responses, ce_response):
    sts = _stubbed("sts", [("get_caller_identity", {"Account": arn.split(":")[4], "Arn": arn, "UserId": "u"})])
    org = _stubbed("organizations", org_responses)
    ce = _stubbed(
        "ce",
        [
            ("get_cost_and_usage", ce_response),
            (
                "get_savings_plans_utilization_details",
                {"SavingsPlansUtilizationDetails": [], "TimePeriod": {"Start": "2026-09-01", "End": "2026-10-01"}},
            ),
            ("get_reservation_utilization", {"UtilizationsByTime": []}),
        ],
    )
    monkeypatch.setattr(preflight, "make_session", lambda p: FakeSession({"sts": sts, "organizations": org, "ce": ce}))


FULL_ORG = [
    ("list_roots", {"Roots": [{"Id": "r-1"}]}),
    ("list_organizational_units_for_parent", {"OrganizationalUnits": [{"Id": "ou-1"}]}),
    ("list_accounts_for_parent", {"Accounts": [{"Id": "222222222222"}]}),
    ("list_tags_for_resource", {"Tags": []}),
]


def _org(mgmt):
    return {"Organization": {"Id": "o-abc", "MasterAccountId": mgmt}}


def _ce(n):
    groups = [
        {"Keys": [str(i).zfill(12), region], "Metrics": {"AmortizedCost": {"Amount": "1", "Unit": "USD"}}}
        for i in range(n)
        for region in ("eu-west-1", "global")
    ]
    return {"ResultsByTime": [{"Groups": groups}]}


def test_policy_files_match_the_built_in_policy():
    assert json.loads((ROOT / "iam/management-account-policy.json").read_text()) == preflight.MANAGEMENT_POLICY

    class Loader(yaml.SafeLoader):
        pass

    Loader.add_multi_constructor("!", lambda loader, suffix, node: None)
    cfn = yaml.load((ROOT / "iam/identity-center/cloudformation/permission-set.yaml").read_text(), Loader=Loader)
    assert cfn["Resources"]["PermissionSet"]["Properties"]["InlinePolicy"] == preflight.MANAGEMENT_POLICY


def test_management_account_with_full_access_is_ready(monkeypatch):
    _session(
        monkeypatch,
        SSO_ARN,
        [
            ("describe_organization", _org("111111111111")),
            *FULL_ORG,
        ],
        _ce(40),
    )
    monkeypatch.setattr(preflight.sso, "profile_permission_set", lambda p: None)
    r = preflight.run_checks("p")
    assert r["ready"] and r["permission_set"] == "CTO-Read"
    assert r["verdict"].startswith("Ready: a scan will cover")
    assert [c["id"] for c in r["checks"]] == [cid for cid, _ in preflight.STEPS]
    assert [c["status"] for c in r["checks"]] == ["ok"] * 7 + ["skip"] * 4
    cost = next(c for c in r["checks"] if c["id"] == "cost")
    assert "40 accounts in 1 region " in cost["detail"]  # one call proves the multi-region data too


def test_member_account_is_flagged_and_admin_request_is_specific(monkeypatch):
    _session(
        monkeypatch,
        SSO_ARN.replace("111111111111", "333333333333"),
        [("describe_organization", _org("111111111111")), ("list_roots", "AccessDeniedException")],
        _ce(1),
    )
    monkeypatch.setattr(preflight.sso, "profile_permission_set", lambda p: None)
    r = preflight.run_checks("p")
    status = {c["id"]: c["status"] for c in r["checks"]}
    assert not r["ready"] and not r["partial"]
    assert status == {
        "identity": "ok", "organization": "warn", "ou_tree": "fail", "accounts": "skip", "account_tags": "skip",
        "cost": "warn", "commitments": "ok", "deep_scan": "skip", "inventory_reads": "skip",
        "dependency_reads": "skip", "assignments": "skip",
    }  # fmt: skip
    org = next(c for c in r["checks"] if c["id"] == "organization")
    assert "111111111111" in org["fix"]
    text = r["admin_request"]
    assert "management account, 111111111111" in text
    assert "organizations:ListRoots" in text and "'CTO-Read'" in text and '"ce:GetCostAndUsage"' in text


class MemberSession:
    """A member-account session whose calls are refused for the listed methods and allowed otherwise."""

    def __init__(self, refused):
        self.refused = refused
        self.calls = []

    def client(self, name, **_kw):
        outer = self

        class C:
            def __getattr__(self, method):
                def call(**kw):
                    outer.calls.append((name, method, kw))
                    if method in outer.refused:
                        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, method)
                    if method in ("list_services", "list_targets_by_rule", "describe_state_machine"):
                        raise ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": "-"}}, method)
                    return {}

                return call

        return C()


def _deep(monkeypatch, refused, ce_refused=()):
    _session(monkeypatch, SSO_ARN, [("describe_organization", _org("111111111111")), *FULL_ORG], _ce(40))
    member = MemberSession(refused)
    monkeypatch.setattr(preflight, "member_session", lambda s, p, a, r, j: member)
    return member


def test_every_member_account_call_is_checked_and_refusals_named(monkeypatch):
    member = _deep(monkeypatch, {"describe_instances", "list_event_source_mappings", "list_subscriptions"})
    monkeypatch.setattr(preflight.sso, "profile_permission_set", lambda p: None)
    r = preflight.run_checks("p", "ExitRiskReadOnly")
    checks = {c["id"]: c for c in r["checks"]}
    assert r["ready"] and "2 optional check(s)" in r["verdict"]
    assert checks["deep_scan"]["status"] == "ok"
    inv, dep = checks["inventory_reads"], checks["dependency_reads"]
    assert inv["status"] == "warn" and inv["needs"] == "ec2:DescribeInstances"
    assert dep["status"] == "warn" and dep["needs"] == "lambda:ListEventSourceMappings, sns:ListSubscriptions"
    # "not found" for a made-up rule or state machine proves the call is allowed
    assert "events:ListTargetsByRule" not in dep["needs"] and "states:DescribeStateMachine" not in dep["needs"]
    assert len(member.calls) == len(preflight.INVENTORY_PROBES) + len(preflight.DEPENDENCY_PROBES)
    arn = next(kw for _, m, kw in member.calls if m == "describe_state_machine")["stateMachineArn"]
    assert ":222222222222:" in arn
    text = r["admin_request"]
    assert "ExitRiskReadOnly in the member accounts" in text
    assert "  - ec2:DescribeInstances" in text and "  - sns:ListSubscriptions" in text


def _sso(monkeypatch, roles, assigned, reachable):
    """An Identity Center profile: ``roles`` per account, and what the bulk count reports."""
    monkeypatch.setattr(preflight.sso, "profile_permission_set", lambda p: ("corp", "CTO-Read"))
    monkeypatch.setattr(preflight.sso, "portal_account_ids", lambda s: list(reachable))
    monkeypatch.setattr(preflight.sso, "list_roles", lambda s, a: roles.get(a, []))
    seen = []

    def count(s, r, progress=None):
        for i in range(len(reachable)):
            if progress:
                progress(i + 1, len(reachable))
            seen.append(i + 1)
        return list(assigned), list(reachable)

    monkeypatch.setattr(preflight.sso, "accounts_with_role", count)
    return seen


def test_sso_profile_deep_scans_with_its_own_permission_set(monkeypatch):
    _deep(monkeypatch, set())
    accts = ["111111111111", "222222222222"]
    _sso(monkeypatch, {"222222222222": ["CTO-Read"]}, accts, accts)
    progress = []
    r = preflight.run_checks("p", on_progress=progress.append)
    checks = {c["id"]: c for c in r["checks"]}
    assert checks["deep_scan"]["status"] == "ok" and "permission set CTO-Read" in checks["deep_scan"]["detail"]
    assert checks["inventory_reads"]["status"] == checks["dependency_reads"]["status"] == "ok"
    assert checks["assignments"]["status"] == "ok" and "all 2 accounts" in checks["assignments"]["detail"]
    assert progress == [{"id": "assignments", "done": 1, "total": 2}, {"id": "assignments", "done": 2, "total": 2}]
    assert r["verdict"].startswith("Ready: a scan will cover")


def test_permission_set_not_assigned_in_member_is_a_warning(monkeypatch):
    _deep(monkeypatch, set())
    _sso(monkeypatch, {"222222222222": ["Other"]}, ["111111111111"], ["111111111111", "222222222222"])
    r = preflight.run_checks("p")
    checks = {c["id"]: c for c in r["checks"]}
    assert checks["deep_scan"]["status"] == "warn" and "not assigned" in checks["deep_scan"]["detail"]
    assert checks["inventory_reads"]["status"] == "skip"
    assert checks["assignments"]["status"] == "warn"  # still counted: shows how far the gap goes


def test_permission_set_missing_in_some_accounts_is_counted(monkeypatch):
    _deep(monkeypatch, set())
    # Not in the org's first member account, so another account the portal shows is used.
    _sso(monkeypatch, {"333333333333": ["CTO-Read"]}, ["333333333333"], ["333333333333", "444444444444"])
    r = preflight.run_checks("p")
    checks = {c["id"]: c for c in r["checks"]}
    assert checks["deep_scan"]["status"] == "ok" and "member account 333333333333" in checks["deep_scan"]["detail"]
    a = checks["assignments"]
    assert a["status"] == "warn" and "1 of the 2 accounts" in a["detail"]
    assert "CTO-Read in 1 more account" in r["admin_request"]


def test_refused_tags_and_commitments_are_warnings(monkeypatch):
    sts = _stubbed("sts", [("get_caller_identity", {"Account": "111111111111", "Arn": SSO_ARN, "UserId": "u"})])
    org = _stubbed("organizations", [("describe_organization", _org("111111111111")), *FULL_ORG[:3]])
    ce = _stubbed(
        "ce",
        [
            ("get_cost_and_usage", _ce(5)),
            ("get_savings_plans_utilization_details", "AccessDeniedException"),
            ("get_reservation_utilization", {"UtilizationsByTime": []}),
        ],
    )
    monkeypatch.setattr(preflight, "make_session", lambda p: FakeSession({"sts": sts, "organizations": org, "ce": ce}))
    monkeypatch.setattr(preflight.sso, "profile_permission_set", lambda p: None)
    r = preflight.run_checks("p")
    checks = {c["id"]: c for c in r["checks"]}
    assert checks["commitments"]["status"] == "warn"
    assert checks["commitments"]["needs"] == "ce:GetSavingsPlansUtilizationDetails"
    assert "ce:GetSavingsPlansUtilizationDetails" in r["admin_request"]


def test_no_credentials_stops_early(monkeypatch):
    def broken(_p):
        raise NoCredentialsError()

    monkeypatch.setattr(preflight, "make_session", broken)
    r = preflight.run_checks("nobody")
    assert r["checks"][0]["status"] == "fail" and "AWS sign-in" in r["checks"][0]["fix"]
    assert all(c["status"] == "skip" for c in r["checks"][1:]) and not r["ready"]


def test_access_check_endpoint(monkeypatch):
    monkeypatch.setattr(preflight, "run_checks", lambda p, r: {"ready": True, "profile": p, "role": r})
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    assert c.post("/api/access-check", json={"profile": "x"}).status_code == 403
    r = c.post("/api/access-check", json={"profile": "x", "role_name": ""}, headers={"X-ExitRisk": "1"})
    assert r.json() == {"ready": True, "profile": "x", "role": None}


def test_access_check_streams_each_check(monkeypatch):
    """?stream=1 sends the step list, then each check as it finishes, then the full result."""

    def fake(profile, role, on_check=None, on_progress=None):
        for cid, label in preflight.STEPS:
            on_check({"id": cid, "label": label, "status": "ok"})
        return {"ready": True, "profile": profile}

    monkeypatch.setattr(preflight, "run_checks", fake)
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    r = c.post("/api/access-check?stream=1", json={"profile": "x"}, headers={"X-ExitRisk": "1"})
    assert r.status_code == 200
    lines = [json.loads(x) for x in r.text.splitlines() if x]
    assert [s["id"] for s in lines[0]["steps"]] == [cid for cid, _ in preflight.STEPS]
    assert [x["check"]["id"] for x in lines[1:-1]] == [cid for cid, _ in preflight.STEPS]
    assert lines[-1] == {"result": {"ready": True, "profile": "x"}}
