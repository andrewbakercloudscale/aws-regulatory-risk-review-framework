import json
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import NoCredentialsError
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
    ce = _stubbed("ce", [("get_cost_and_usage", ce_response)])
    monkeypatch.setattr(preflight, "make_session", lambda p: FakeSession({"sts": sts, "organizations": org, "ce": ce}))


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
            ("list_roots", {"Roots": [{"Id": "r-1"}]}),
            ("list_accounts_for_parent", {"Accounts": [{"Id": "222222222222"}]}),
        ],
        _ce(40),
    )
    r = preflight.run_checks("p")
    assert r["ready"] and r["permission_set"] == "CTO-Read"
    assert [c["status"] for c in r["checks"]] == ["ok", "ok", "ok", "ok", "ok", "skip"]
    cost = next(c for c in r["checks"] if c["id"] == "cost")
    assert "40 account(s) in 1 region(s)" in cost["detail"]  # one call proves the multi-region data too


def test_member_account_is_flagged_and_admin_request_is_specific(monkeypatch):
    _session(
        monkeypatch,
        SSO_ARN.replace("111111111111", "333333333333"),
        [("describe_organization", _org("111111111111")), ("list_roots", "AccessDeniedException")],
        _ce(1),
    )
    r = preflight.run_checks("p")
    status = {c["id"]: c["status"] for c in r["checks"]}
    assert not r["ready"] and not r["partial"]
    assert status == {
        "identity": "ok", "organization": "warn", "ou_tree": "fail", "accounts": "skip", "cost": "warn",
        "deep_scan": "skip",
    }  # fmt: skip
    org = next(c for c in r["checks"] if c["id"] == "organization")
    assert "111111111111" in org["fix"]
    text = r["admin_request"]
    assert "management account, 111111111111" in text
    assert "organizations:ListRoots" in text and "'CTO-Read'" in text and '"ce:GetCostAndUsage"' in text


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
