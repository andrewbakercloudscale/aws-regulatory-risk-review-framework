"""Cloud Assurance Framework: catalogue, member checks, organisation checks, report, rulesets, API."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from exitrisk import assurance, rulesets
from exitrisk.collectors import assurance as checks
from exitrisk.collectors import assurance_org
from exitrisk.demo import build_demo_scan
from exitrisk.scanner import ScanParams, _busiest_regions
from exitrisk.server import create_app

H = {"X-ExitRisk": "1"}
REPORT_TIME = {
    "account_tags_missing", "admin_direct_user", "admin_holders", "ai_unapproved", "central_root_off",
    "data_location", "misplaced_account", "owner_missing", "owner_not_found", "scp_guardrails", "scp_region_deny",
    "sensitive_human_write", "sensitive_no_data_events", "sensitive_no_kms", "sensitive_no_lock",
    "sensitive_no_replication", "sensitive_no_versioning", "single_region",
}  # fmt: skip


def _denied(op="Call"):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "not allowed"}}, op)


class FakeClient:
    """Answers the methods given; every other call is refused, as with a role missing permissions."""

    def __init__(self, answers=None):
        self.answers = answers or {}

    def can_paginate(self, _op):
        return False

    def __getattr__(self, name):
        if name in self.answers:
            a = self.answers[name]
            return a if callable(a) else (lambda **_kw: a)

        def refuse(**_kw):
            raise _denied(name)

        return refuse


class FakeSession:
    def __init__(self, clients=None):
        self.clients = clients or {}

    def client(self, name, region_name=None, config=None):
        return self.clients.get((name, region_name)) or self.clients.get(name) or FakeClient()


# ---------------------------------------------------------------------------------- catalogue


def test_catalogue_is_consistent_with_the_collector():
    cat = checks.catalog()
    ids = [c["id"] for c in cat["checks"]]
    assert len(ids) == len(set(ids)) and len(ids) >= 130
    for c in cat["checks"]:
        assert c["area"] in cat["areas"], c["id"]
        assert c["severity"] in cat["points"], c["id"]
        assert c.get("scope", "all") in ("all", "production", "non_edge", "sensitive"), c["id"]
        assert c["title"] and c["why"] and c["fix"] and "source" in c, c["id"]
        assert "–" not in c["why"] + c["fix"] + c["title"] and "—" not in c["why"] + c["fix"] + c["title"]
    measured = {cid for t in checks.GLOBAL_TASKS + checks.REGION_TASKS for cid in t[1]}
    assert measured <= set(ids)
    assert set(ids) - measured == REPORT_TIME  # every rule is measured somewhere


# ---------------------------------------------------------------------------------- policy reading


def test_policy_reading():
    allow_all = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    s3_write = {"Statement": {"Effect": "Allow", "Action": ["s3:Put*"], "Resource": "arn:aws:s3:::pay-*/*"}}
    deny = {"Statement": [{"Effect": "Deny", "Action": "s3:PutObject", "Resource": "*"}]}
    arn = "arn:aws:s3:::pay-files/x"
    assert checks.is_admin(allow_all) and not checks.is_admin(s3_write)
    assert checks.allows([s3_write], "s3:PutObject", arn)
    assert not checks.allows([s3_write], "s3:PutObject", "arn:aws:s3:::other/x")
    assert not checks.allows([s3_write, deny], "s3:PutObject", arn)
    trust = {
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": {"AWS": "888888888888"}, "Action": "sts:AssumeRole",
             "Condition": {"StringEquals": {"sts:ExternalId": "abc"}}},
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
             "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}},
        ]
    }  # fmt: skip
    assert checks._trusted_accounts(trust) == [("999999999999", False), ("888888888888", True)]
    stale = {
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "AROAQ3EGT6ODK4EXO3PTM"}, "Action": "sts:AssumeRole"}]
    }
    assert checks._trusted_accounts(stale) == [("deleted", False)]
    cover = checks.s3_write_cover(
        {
            "AdvancedEventSelectors": [
                {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]},
                                    {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                                    {"Field": "resources.ARN", "StartsWith": ["arn:aws:s3:::pay-files/"]}]}
            ]
        }
    )  # fmt: skip
    assert cover == {"all": False, "prefixes": ["arn:aws:s3:::pay-files/"]}
    assert assurance._covered("pay-files", cover) and not assurance._covered("pay-files-2", cover)


def test_network_acl_rule_order():
    deny_first = {"Entries": [
        {"RuleNumber": 50, "Protocol": "6", "PortRange": {"From": 22, "To": 22}, "CidrBlock": "0.0.0.0/0",
         "RuleAction": "deny"},
        {"RuleNumber": 100, "Protocol": "-1", "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"},
    ]}  # fmt: skip
    assert checks._nacl_admin_open(deny_first)  # 3389 still reaches the allow-all rule
    deny_first["Entries"].insert(0, {"RuleNumber": 60, "Protocol": "6", "PortRange": {"From": 3389, "To": 3389},
                                     "CidrBlock": "0.0.0.0/0", "RuleAction": "deny"})  # fmt: skip
    assert not checks._nacl_admin_open(deny_first)


# ---------------------------------------------------------------------------------- member checks


def _ctx(clients, info=None, regions=("eu-west-1",)):
    return checks.Ctx(FakeSession(clients), "111111111111", list(regions), info or {})


def test_ssh_open_on_a_public_instance_is_critical_evidence():
    ec2 = FakeClient({
        "describe_security_groups": {"SecurityGroups": [
            {"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            {"GroupId": "sg-2", "GroupName": "spare", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
        ]},
        "describe_network_interfaces": {"NetworkInterfaces": [
            {"NetworkInterfaceId": "eni-1", "Association": {"PublicIp": "1.2.3.4"},
             "Attachment": {"InstanceId": "i-1"}, "Groups": [{"GroupId": "sg-1"}]}]},
        "describe_network_acls": {"NetworkAcls": []},
        "describe_instances": {"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "InstanceType": "t2.micro", "MetadataOptions": {"HttpTokens": "optional"},
             "Placement": {"AvailabilityZone": "eu-west-1a"}, "ImageId": "ami-1"}]}]},
        "describe_images": {"Images": [{"ImageId": "ami-1", "CreationDate": "2020-01-01T00:00:00.000Z"}]},
    })  # fmt: skip
    ctx = _ctx({"ec2": ec2})
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "ec2-network"), "eu-west-1")
    out = ctx.r.finish()
    assert out["admin_ports_public"]["status"] == "fail" and "i-1" in out["admin_ports_public"]["ev"][0]
    assert out["admin_ports_open"]["status"] == "fail" and "sg-2" in out["admin_ports_open"]["ev"][0]
    assert out["db_ports_public"]["status"] == "pass"
    assert out["imdsv2"]["status"] == "fail" and out["ec2_previous_generation"]["status"] == "fail"
    assert out["ami_outdated"]["status"] == "fail" and out["ec2_one_az"]["status"] == "fail"


def test_a_refused_call_is_never_a_pass():
    regions = FakeClient({"describe_regions": {"Regions": [{"RegionName": "eu-west-1"}]}})
    session = FakeSession({("ec2", "us-east-1"): regions})
    out, issues = checks.account_checks(session, "111111111111", ["eu-west-1"], {"services": None})
    statuses = {v["status"] for v in out["checks"].values()}
    assert "pass" not in statuses and "fail" not in statuses
    assert out["checks"]["root_mfa"]["status"] == "unknown"
    assert issues and all(i.category == "assurance" for i in issues)


def test_services_not_billed_are_not_applicable():
    ctx = _ctx({}, {"services": ["Amazon Elastic Compute Cloud - Compute"]})
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "rds"), "eu-west-1")
    assert ctx.r.finish()["rds_single_az"]["status"] == "na"


def test_rds_resilience_and_end_of_support():
    rds = FakeClient({
        "describe_db_instances": {"DBInstances": [
            {"DBInstanceIdentifier": "pay", "MultiAZ": False, "StorageEncrypted": True, "BackupRetentionPeriod": 3,
             "DeletionProtection": True, "Engine": "postgres", "EngineVersion": "11.22"},
            {"DBInstanceIdentifier": "ok", "MultiAZ": True, "StorageEncrypted": True, "BackupRetentionPeriod": 14,
             "DeletionProtection": True, "Engine": "postgres", "EngineVersion": "16.4"},
        ]},
        "describe_db_clusters": {"DBClusters": []},
    })  # fmt: skip
    ctx = _ctx({"rds": rds})
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "rds"), "eu-west-1")
    out = ctx.r.finish()
    assert out["rds_single_az"]["ev"] == ["pay (eu-west-1)"]
    assert out["rds_backup_short"]["status"] == "fail" and out["rds_engine_eol"]["status"] == "fail"
    assert out["rds_no_deletion_protection"]["status"] == "pass"


def test_bucket_writers_and_workload_admin_from_iam():
    now = datetime.now(timezone.utc)
    admin = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    details = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "Policies": [],
        "RoleDetailList": [
            {"RoleName": "AWSReservedSSO_PaymentsSupport_0123456789abcdef", "Arn": "arn:aws:iam::1:role/sso",
             "Path": "/aws-reserved/", "CreateDate": now,
             "AssumeRolePolicyDocument": {"Statement": []},
             "RolePolicyList": [{"PolicyName": "w", "PolicyDocument": {"Statement": [
                 {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::pay-files/*"}]}}]},
            {"RoleName": "app", "Arn": "arn:aws:iam::1:role/app", "Path": "/", "CreateDate": now,
             "AssumeRolePolicyDocument": {"Statement": []},
             "RolePolicyList": [{"PolicyName": "a", "PolicyDocument": admin}],
             "InstanceProfileList": [{"Arn": "arn:aws:iam::1:instance-profile/app"}]},
        ],
    }  # fmt: skip
    ctx = _ctx({})
    checks._authorization(ctx, details)
    ctx.r.fact("buckets", [{"name": "pay-files"}, {"name": "logs"}])
    ctx.r.fact("instance_profiles", {"i-9": "arn:aws:iam::1:instance-profile/app"}, "eu-west-1")
    checks._finish(ctx)
    buckets = {b["name"]: b["writers"] for b in ctx.r.facts["buckets"]}
    assert buckets == {"pay-files": ["permission set PaymentsSupport"], "logs": []}
    out = ctx.r.finish()
    assert out["workload_admin"]["ev"] == ["i-9 (eu-west-1)"]
    assert out["admin_policy"]["ev"] == ["role app (inline)"]


def test_trusted_advisor_needs_a_support_plan():
    err = ClientError({"Error": {"Code": "SubscriptionRequiredException", "Message": "Business Support needed"}}, "x")
    ta = FakeClient({"list_recommendations": lambda **_k: (_ for _ in ()).throw(err)})
    ctx = _ctx({"trustedadvisor": ta})
    checks._run(ctx, next(t for t in checks.GLOBAL_TASKS if t[0] == "trustedadvisor"), None)
    assert ctx.r.finish()["trusted_advisor_red"]["status"] == "na"


# ---------------------------------------------------------------------------------- organisation


def test_scp_guardrails_follow_the_ou_path():
    deny = {"Statement": [{"Effect": "Deny", "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
                                                         "organizations:LeaveOrganization"], "Resource": "*"},
                          {"Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*",
                           "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["af-south-1"]}}}]}  # fmt: skip
    org = FakeClient({
        "list_policies": {"Policies": [{"Id": "p-1"}]},
        "describe_policy": {"Policy": {"Content": json.dumps(deny)}},
        "list_targets_for_policy": {"Targets": [{"TargetId": "ou-prod"}]},
    })  # fmt: skip
    tree = {"id": "r-1", "children": [{"id": "ou-prod", "children": [{"id": "ou-pay", "children": []}]}]}
    out = assurance_org.scp_guardrails(FakeSession({"organizations": org}), tree,
                                       [{"id": "1", "ou_id": "ou-pay"}, {"id": "2", "ou_id": "r-1"}])  # fmt: skip
    assert out["1"]["region_deny"] and not out["2"]["region_deny"]
    assert "CloudTrail kept on" not in out["1"]["missing"] and "CloudTrail kept on" in out["2"]["missing"]
    # The region deny's NotAction covers GuardDuty too: a Deny of everything outside the region counts.
    assert "GuardDuty kept on" not in out["1"]["missing"]


def test_org_checks_record_refusals_without_failing():
    facts, issues = assurance_org.org_checks(FakeSession(), None, [{"id": "1"}], None, "eu-west-1")
    assert "root" in facts["unavailable"] and issues


# ---------------------------------------------------------------------------------- report


@pytest.fixture(scope="module")
def demo():
    return build_demo_scan()


def test_demo_report_scores_and_coverage(demo):
    r = assurance.build_assurance(demo)
    assert r["available"] and r["summary"]["accounts"] == len(r["accounts"]) > 30
    for a in r["accounts"]:
        assert 0 <= a["score"] <= 100 and 0 <= a["coverage"] <= 100
        if a["fails"]["critical"]:
            assert a["score"] >= assurance.CRITICAL_FLOOR
    assert [a["score"] for a in r["accounts"]] == sorted((a["score"] for a in r["accounts"]), reverse=True)
    assert r["not_checked"] == [{"id": x["id"], "name": "sandbox-innovation"} for x in demo["accounts"]
                                if x["name"] == "sandbox-innovation"]  # fmt: skip
    assert r["rules"][0]["fail"] and r["rules"][0]["severity"] == "critical"


def test_scopes_apply_to_production_and_edge(demo):
    r = assurance.build_assurance(demo)
    dev = next(a for a in r["accounts"] if not a["production"])
    assert any(n["id"] == "rds_single_az" for n in dev["not_applicable"])
    edge = next(a for a in r["accounts"] if a["edge"])
    assert any(n["id"] == "igw_present" for n in edge["not_applicable"])


def test_sensitive_buckets_and_human_writers(demo):
    r = assurance.build_assurance(demo)
    pay = next(a for a in r["accounts"] if a["name"] == "payments-gateway-prod" or "payments" in a["name"]
               and a["sensitive_buckets"])  # fmt: skip
    ids = {f["id"]: f for f in pay["findings"]}
    assert ids["sensitive_human_write"]["status"] == "fail"
    assert ids["sensitive_no_data_events"]["status"] == "fail"
    other = next(a for a in r["accounts"] if not a["sensitive_buckets"])
    assert any(n["id"] == "sensitive_no_versioning" for n in other["not_applicable"])


def test_rulesets_choose_the_rules_and_severity(demo):
    full = assurance.build_assurance(demo)
    res = assurance.build_assurance(demo, a=assurance.AssuranceAnswers(ruleset="Resilience and disaster recovery"))
    assert {x["area"] for x in res["rules"]} == {"resilience"} and res["summary"]["score"] < full["summary"]["score"]
    pick = assurance.AssuranceAnswers(rules=["owner_missing"], severity={"owner_missing": "critical"})
    one = assurance.build_assurance(demo, a=pick)
    assert [x["id"] for x in one["rules"]] == ["owner_missing"] and one["ruleset"]["custom"]
    failing = [a for a in one["accounts"] if a["fails"]["critical"]]
    assert failing and all(a["score"] >= 80 for a in failing)


def test_answers_change_the_result_without_a_scan(demo):
    a = assurance.AssuranceAnswers(production_patterns="nothing-matches", allowed_locations="IE,GB,US")
    r = assurance.build_assurance(demo, a=a)
    assert not any(x["production"] for x in r["accounts"] if "prod" not in x["name"])
    loc = next(x for x in r["rules"] if x["id"] == "data_location")
    assert loc["fail"] == 0


def test_scan_without_assurance_says_so():
    r = assurance.build_assurance({"id": "x", "accounts": [{"id": "1", "name": "a"}], "params": {}})
    assert not r["available"] and "did not run" in r["reason"]


def test_ownership_proposals_and_export(demo):
    r = assurance.build_assurance(demo)
    rows = r["ownership"]["rows"]
    todo = [x for x in rows if x["status"] == "missing"]
    assert todo and any(x["proposal"] for x in todo)
    target = todo[0]
    out = assurance.ownership_export(r, {target["id"]: "new.owner@example.com", "999": "x"}, "Owner")
    assert out["count"] == 1 and "new.owner@example.com" in out["csv"]
    assert f"--resource-id {target['id']} --tags 'Key=Owner,Value=new.owner@example.com'" in out["commands"]


def test_evidence_hash_is_stable(demo):
    r = assurance.build_assurance(demo)
    a, b = assurance.evidence(r), assurance.evidence({**r, "build_ms": 999})
    assert a["sha256"] == b["sha256"] and len(a["sha256"]) == 64


# ---------------------------------------------------------------------------------- rulesets and API


def test_rulesets_save_list_delete():
    with pytest.raises(ValueError):
        rulesets.save(rulesets.Ruleset(name="All rules", rules=["root_mfa"]))
    with pytest.raises(ValueError):
        rulesets.save(rulesets.Ruleset(name="Bad", rules=["no_such_rule"]))
    saved = rulesets.save(rulesets.Ruleset(name="Payments prod", rules=["root_mfa", "root_mfa", "rds_single_az"],
                                           severity={"rds_single_az": "critical"}))  # fmt: skip
    assert saved["rules"] == ["root_mfa", "rds_single_az"]
    assert rulesets.get("Payments prod")["severity"] == {"rds_single_az": "critical"}
    assert rulesets.delete("payments PROD") and rulesets.get("Payments prod")["name"] == "All rules"
    assert not rulesets.delete("All rules")


def test_assurance_api_roundtrip():
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    scan_id = c.post("/api/scans/demo", headers=H).json()["id"]
    cat = c.get("/api/assurance/catalog").json()
    assert len(cat["checks"]) >= 130 and cat["points"]["critical"] == 40
    put = c.put(
        "/api/rulesets", headers=H, json={"name": "Exposure only", "rules": ["admin_ports_public", "s3_public_bucket"]}
    )
    assert put.status_code == 200
    assert any(s["name"] == "Exposure only" for s in c.get("/api/rulesets").json()["rulesets"])
    r = c.post("/api/assurance", headers=H, json={"scan_id": scan_id, "filter": {"include": "prod"},
                                                   "answers": {"ruleset": "Exposure only"}}).json()  # fmt: skip
    assert r["ruleset"]["rules"] == 2 and all("prod" in a["name"] for a in r["accounts"])
    ev = c.post("/api/assurance/evidence", headers=H, json={"scan_id": scan_id})
    assert ev.status_code == 200 and "attachment" in ev.headers["content-disposition"] and ev.json()["sha256"]
    aid = r["accounts"][0]["id"]
    exp = c.post("/api/assurance/ownership-export", headers=H,
                 json={"scan_id": scan_id, "approved": {aid: "a@example.com"}}).json()  # fmt: skip
    assert exp["count"] in (0, 1)
    assert c.delete("/api/rulesets/Exposure only", headers=H).status_code == 200
    assert c.delete("/api/rulesets/All rules", headers=H).status_code == 404
    assert c.post("/api/assurance", headers=H, json={"scan_id": "20200101-000000-zzzz"}).status_code == 404


# ---------------------------------------------------------------------------------- scanner


def test_assurance_scan_needs_member_access(monkeypatch):
    from exitrisk import scanner

    monkeypatch.setattr(scanner.sso, "profile_permission_set", lambda p: None)
    with pytest.raises(ValueError, match="assurance"):
        ScanParams(assurance=True).validate()
    ScanParams(assurance=True, role_name="ExitRiskReadOnly").validate()


def test_busiest_region_per_account():
    class Job:
        data = {"region_costs": [
            {"account_id": "1", "region": "eu-west-1", "monthly": 5.0},
            {"account_id": "1", "region": "af-south-1", "monthly": 9.0},
            {"account_id": "1", "region": "global", "monthly": 99.0},
        ]}  # fmt: skip

    assert _busiest_regions(Job()) == {"1": "af-south-1"}


def test_old_findings_age_is_read_from_strings():
    now = datetime.now(timezone.utc)
    assert checks._age_days((now - timedelta(days=10)).isoformat(), now) == pytest.approx(10, abs=0.01)
    assert checks._age_days("N/A", now) is None


def test_combined_throttle_codes_are_retried_with_backoff():
    from botocore.exceptions import ClientError

    from exitrisk.aws_session import is_throttle, with_backoff

    def throttled(code="ThrottlingException, TooManyRequestsException", status=429):
        err = {"Error": {"Code": code, "Message": "Too Many Requests"}, "ResponseMetadata": {"HTTPStatusCode": status}}
        return ClientError(err, "ListOrganizationRecommendations")

    assert is_throttle(throttled())
    assert not is_throttle(ClientError({"Error": {"Code": "AccessDeniedException"}}, "op"))
    calls, waits = [], []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise throttled()
        return "ok"

    assert with_backoff(flaky, sleep=waits.append) == "ok"
    assert len(calls) == 3 and len(waits) == 2 and waits[0] <= 1.0 < waits[1] * 2 + 1
    calls.clear()
    with pytest.raises(ClientError):
        with_backoff(lambda: calls.append(1) or (_ for _ in ()).throw(throttled()), attempts=3, sleep=lambda s: None)
    assert len(calls) == 3


def test_access_denied_is_not_retried():
    from botocore.exceptions import ClientError

    from exitrisk.aws_session import with_backoff

    calls = []

    def denied():
        calls.append(1)
        raise ClientError({"Error": {"Code": "AccessDeniedException"}}, "op")

    with pytest.raises(ClientError):
        with_backoff(denied, sleep=lambda s: None)
    assert len(calls) == 1


def test_many_buckets_are_read_in_parallel_without_sharing_a_context():
    import time

    buckets = [{"Name": f"b{i}", "CreationDate": "2024-01-01"} for i in range(40)]

    def slow(**_kw):  # buckets overlap in time, as with real calls
        time.sleep(0.01)
        raise _denied("GetBucketVersioning")

    clients = {"s3control": FakeClient({"get_public_access_block": {"PublicAccessBlockConfiguration": {}}}),
               "s3": FakeClient({"list_buckets": {"Buckets": buckets}, "get_bucket_versioning": slow})}  # fmt: skip
    ctx = _ctx(clients)
    checks._run(ctx, next(t for t in checks.GLOBAL_TASKS if t[0] == "s3"), None)
    out = ctx.r.finish()
    assert not any("RuntimeError" in str(v) for v in out.values())
    assert out["s3_account_bpa"]["status"] == "fail"


def test_an_api_not_offered_to_the_account_in_a_region_is_not_an_issue():
    def refused(**_kw):
        raise ClientError({"Error": {"Code": "AccessDeniedException",
                                     "Message": "Your account is not authorized to invoke this API operation."}},
                          "ListGuardrails")  # fmt: skip

    ctx = _ctx({"bedrock": FakeClient({"list_guardrails": refused})}, regions=("af-south-1",))
    ctx.billed = lambda *_a: True
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "bedrock-guardrails"), "af-south-1")
    assert not ctx.issues


def test_a_task_that_hits_a_server_error_runs_again(monkeypatch):
    monkeypatch.setattr("exitrisk.aws_session.time.sleep", lambda _s: None)
    calls = []

    def flaky(**_kw):
        calls.append(1)
        if len(calls) == 1:
            raise ClientError({"Error": {"Code": "InternalFailure"}, "ResponseMetadata": {"HTTPStatusCode": 503}},
                              "GetModelInvocationLoggingConfiguration")  # fmt: skip
        return {"loggingConfig": {"textDataDeliveryEnabled": True}}

    ctx = _ctx({"bedrock": FakeClient({"get_model_invocation_logging_configuration": flaky})})
    ctx.billed = lambda *_a: True
    checks._run(ctx, next(t for t in checks.REGION_TASKS if t[0] == "bedrock"), "eu-west-1")
    assert len(calls) == 2 and not ctx.issues
    assert ctx.r.finish()["bedrock_no_logging"]["status"] == "pass"
