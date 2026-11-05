# ruff: noqa: E501
"""The Developer Compromise checks: every call against AWS's API models, and the report's judgement."""

from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.validate import ParamValidator
from test_outage_reads import _Pages, wrap

from exitrisk.collectors import compromise as collector
from exitrisk.compromise import build_compromise, catalog

NOW = datetime.now(timezone.utc)
ACCT = "111111111111"
SSO_DEV = f"arn:aws:iam::{ACCT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Developer_0123456789abcdef"
DEV_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:*", "dynamodb:PutItem", "kms:Sign", "secretsmanager:GetSecretValue",
                                       "lambda:UpdateFunctionCode", "cloudtrail:StopLogging", "sts:AssumeRole"],
         "Resource": "*"},
    ],
}  # fmt: skip
OPEN_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
         "Principal": {"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
         "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}},
    ],
}  # fmt: skip
DEPLOY_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"}}],
}
CRED = (
    "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,"
    "mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,"
    "access_key_2_last_rotated,access_key_2_last_used_date\n"
    f"deployer,arn:aws:iam::{ACCT}:user/deployer,2024-01-01T00:00:00+00:00,true,N/A,N/A,N/A,false,true,"
    f"{(NOW - timedelta(days=400)).isoformat()},{NOW.isoformat()},false,N/A,N/A\n"
)

ANSWERS = {
    "iam": {
        "get_account_authorization_details": {
            "RoleDetailList": [
                {"RoleName": "AWSReservedSSO_Developer_0123456789abcdef", "Arn": SSO_DEV, "RoleId": "AROA1",
                 "Path": "/aws-reserved/sso.amazonaws.com/", "CreateDate": NOW, "AssumeRolePolicyDocument": "%7B%7D",
                 "RolePolicyList": [{"PolicyName": "dev", "PolicyDocument": DEV_POLICY}]},
                {"RoleName": "github-deploy", "Arn": f"arn:aws:iam::{ACCT}:role/github-deploy", "RoleId": "AROA2",
                 "Path": "/", "CreateDate": NOW, "AssumeRolePolicyDocument": OPEN_TRUST,
                 "RolePolicyList": [{"PolicyName": "deploy", "PolicyDocument": DEV_POLICY}]},
                {"RoleName": "deploy-admin", "Arn": f"arn:aws:iam::{ACCT}:role/deploy-admin", "RoleId": "AROA3",
                 "Path": "/", "CreateDate": NOW, "AssumeRolePolicyDocument": DEPLOY_TRUST,
                 "RolePolicyList": [{"PolicyName": "deploy", "PolicyDocument": DEV_POLICY}]},
            ],
            "UserDetailList": [
                {"UserName": "deployer", "Arn": f"arn:aws:iam::{ACCT}:user/deployer", "UserId": "AIDA1",
                 "Path": "/", "CreateDate": NOW,
                 "UserPolicyList": [{"PolicyName": "dev", "PolicyDocument": DEV_POLICY}]},
            ],
            "GroupDetailList": [],
            "Policies": [],
        },
        "list_roles": {"Roles": [{"RoleName": "AWSReservedSSO_Developer_0123456789abcdef", "Arn": SSO_DEV, "Path": "/",
                                  "RoleId": "AROA1", "CreateDate": NOW, "MaxSessionDuration": 43200}]},
        "generate_credential_report": {"State": "COMPLETE"},
        "get_credential_report": {"Content": CRED.encode(), "ReportFormat": "text/csv"},
        "get_account_summary": {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
    },
    "s3": {
        "list_buckets": {"Buckets": [{"Name": "payments-outbound", "CreationDate": NOW},
                                     {"Name": "app-access-logs", "CreationDate": NOW}]},
        "get_bucket_location": {"LocationConstraint": "eu-west-1"},
        "get_bucket_versioning": {},
        "get_object_lock_configuration": {"ObjectLockConfiguration": {}},
        "get_bucket_policy": {"Policy": '{"Statement": []}'},
        "get_bucket_tagging": {"TagSet": [{"Key": "team", "Value": "payments"}]},
        "get_bucket_notification_configuration": {},
    },
    "dynamodb": {
        "list_tables": {"TableNames": ["ledger"]},
        "describe_table": {"Table": {"TableName": "ledger", "TableArn": f"arn:aws:dynamodb:eu-west-1:{ACCT}:table/ledger"}},
        "get_resource_policy": {"Policy": '{"Statement": []}'},
        "describe_continuous_backups": {"ContinuousBackupsDescription": {"ContinuousBackupsStatus": "DISABLED",
                                        "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "DISABLED"}}},
    },
    "rds": {
        "describe_db_clusters": {"DBClusters": []},
        "describe_db_instances": {"DBInstances": [
            {"DBInstanceIdentifier": "payments-db", "DBInstanceArn": f"arn:aws:rds:eu-west-1:{ACCT}:db:payments-db",
             "Engine": "postgres", "DbiResourceId": "db-ABC", "IAMDatabaseAuthenticationEnabled": True,
             "PubliclyAccessible": True, "Endpoint": {"Port": 5432},
             "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-db", "Status": "active"}], "MasterUserSecret": {"SecretArn": f"arn:aws:secretsmanager:eu-west-1:{ACCT}:secret:rds!db-1"}},
        ]},
    },
    "ec2": {
        "describe_security_groups": {"SecurityGroups": [
            {"GroupId": "sg-db", "GroupName": "payments-db", "OwnerId": ACCT, "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                 "IpRanges": [{"CidrIp": "165.225.10.0/24", "Description": "zscaler"}, {"CidrIp": "10.20.0.0/16"}],
                 "UserIdGroupPairs": [{"GroupId": "sg-app", "UserId": ACCT}, {"GroupId": "sg-proxy", "UserId": ACCT}]},
            ]},
        ]},
        "describe_network_interfaces": {"NetworkInterfaces": [
            {"NetworkInterfaceId": "eni-1", "InterfaceType": "lambda", "Groups": [{"GroupId": "sg-app"}]},
            {"NetworkInterfaceId": "eni-2", "Attachment": {"InstanceId": "i-1"}, "Groups": [{"GroupId": "sg-proxy"}]},
        ]},
    },
    "lambda": {
        "list_functions": {"Functions": [{"FunctionName": "pay-out", "FunctionArn": f"arn:aws:lambda:eu-west-1:{ACCT}:function:pay-out",
                                          "Runtime": "python3.12"}]},
        "get_function_code_signing_config": {"CodeSigningConfigArn": "", "FunctionName": "pay-out"},
        "list_function_url_configs": {"FunctionUrlConfigs": [{"FunctionUrl": "https://x", "FunctionArn": "arn:f",
                                                              "AuthType": "NONE", "CreationTime": "t",
                                                              "LastModifiedTime": "t"}]},
        "get_policy": {"Policy": '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction"}]}'},
    },
    "ecs": {
        "list_clusters": {"clusterArns": [f"arn:aws:ecs:eu-west-1:{ACCT}:cluster/c"]},
        "list_services": {"serviceArns": [f"arn:aws:ecs:eu-west-1:{ACCT}:service/c/payments-api"]},
        "describe_services": {"services": [{"serviceName": "payments-api", "taskDefinition": "td:1",
                                            "serviceArn": f"arn:aws:ecs:eu-west-1:{ACCT}:service/c/payments-api"}]},
        "describe_task_definition": {"taskDefinition": {"containerDefinitions": [{"image": "repo:latest"}]}},
    },
    "ecr": {
        "describe_repositories": {"repositories": [{"repositoryName": "payments-api", "imageTagMutability": "MUTABLE",
                                                    "repositoryArn": f"arn:aws:ecr:eu-west-1:{ACCT}:repository/payments-api"}]},
        "get_repository_policy": {"policyText": '{"Statement": []}'},
    },
    "secretsmanager": {
        "list_secrets": {"SecretList": [{"ARN": f"arn:aws:secretsmanager:eu-west-1:{ACCT}:secret:partner-api",
                                         "Name": "payments/partner-api", "RotationEnabled": False}]},
        "get_resource_policy": {},
    },
    "kms": {
        "list_keys": {"Keys": [{"KeyId": "k1"}]},
        "describe_key": {"KeyMetadata": {"KeyId": "k1", "Arn": f"arn:aws:kms:eu-west-1:{ACCT}:key/k1",
                                         "KeyManager": "CUSTOMER", "KeyState": "Enabled", "KeyUsage": "SIGN_VERIFY",
                                         "KeySpec": "ECC_SECG_P256K1", "Description": "wallet signer"}},
        "get_key_policy": {"Policy": f'{{"Statement": [{{"Effect": "Allow", "Principal": {{"AWS": "arn:aws:iam::{ACCT}:root"}}, "Action": "kms:*", "Resource": "*"}}]}}'},
    },
    "apigateway": {
        "get_rest_apis": {"items": [{"id": "a1", "name": "payments", "endpointConfiguration": {"types": ["REGIONAL"]}}]},
        "get_resources": {"items": [{"id": "r", "path": "/pay", "resourceMethods": {
            "POST": {"httpMethod": "POST", "authorizationType": "NONE", "apiKeyRequired": False},
            "OPTIONS": {"httpMethod": "OPTIONS", "authorizationType": "NONE"}}}]},
        "get_stages": {"item": [{"stageName": "prod"}]},
    },
    "apigatewayv2": {"get_apis": {"Items": []}},
    "cloudtrail": {
        "describe_trails": {"trailList": [{"Name": "org", "TrailARN": "arn:aws:cloudtrail:eu-west-1:2:trail/org",
                                           "HomeRegion": "eu-west-1", "IsOrganizationTrail": True,
                                           "IsMultiRegionTrail": True}]},
        "get_trail_status": {"IsLogging": True},
        "get_event_selectors": {"EventSelectors": [{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True,
                                                    "DataResources": []}]},
        "lookup_events": {"Events": [
            {"EventName": "UpdateFunctionCode20150331v2", "EventSource": "lambda.amazonaws.com", "EventTime": NOW,
             "Resources": [{"ResourceName": "pay-out"}],
             "CloudTrailEvent": '{"userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/'
                                'AWSReservedSSO_Developer_0123456789abcdef/a@b"}, "userAgent": "aws-cli/2.15 Python",'
                                ' "sourceIPAddress": "1.2.3.4"}'},
        ]},
    },
    "guardduty": {"list_detectors": {"DetectorIds": ["d1"]},
                  "get_detector": {"Status": "ENABLED", "ServiceRole": "r", "Features": []}},
    "events": {"list_rules": {"Rules": []}},
}  # fmt: skip  # noqa: E501


class Client:
    def __init__(self, name, region, log):
        self.real = boto3.client(name, region_name=region, aws_access_key_id="x", aws_secret_access_key="x")
        self.name, self.log = name, log

    def can_paginate(self, op):
        return False

    def get_paginator(self, op):
        return _Pages(getattr(self, op))

    def __getattr__(self, op):
        mapping = self.real.meta.method_to_api_mapping
        if op not in mapping:
            raise AttributeError(op)
        api = self.real.meta.service_model.operation_model(mapping[op])

        def call(**kwargs):
            where = f"{self.name}.{op}"
            self.log["calls"].add(where)
            report = ParamValidator().validate(kwargs, api.input_shape) if api.input_shape else None
            if report and report.has_errors():
                self.log["wrong"].append(f"{where}: {report.generate_report()}")
            if op == "simulate_principal_policy":
                answer = _simulated(kwargs)
            else:
                answer = ANSWERS.get(self.name, {}).get(op, {})
            return wrap(answer, api.output_shape, where, self.log["wrong"]) if api.output_shape else answer

        return call


def _simulated(kwargs):
    """What the developer policy allows is allowed, except StopLogging, which an SCP denies."""
    out = []
    for action in kwargs["ActionNames"]:
        allowed = collector.may_allow([DEV_POLICY], action)
        scp = action == "cloudtrail:StopLogging"
        denied = scp or not allowed
        specific = [
            {"EvalResourceName": r, "EvalResourceDecision": "implicitDeny" if denied else "allowed",
             "MatchedStatements": [{"SourcePolicyId": "dev"}]}
            for r in kwargs["ResourceArns"]
        ]  # fmt: skip
        out.append({"EvalActionName": action, "EvalResourceName": kwargs["ResourceArns"][0],
                    "EvalDecision": "implicitDeny" if denied else "allowed",
                    "OrganizationsDecisionDetail": {"AllowedByOrganizations": not scp},
                    "ResourceSpecificResults": specific})  # fmt: skip
    return {"EvaluationResults": out, "IsTruncated": False}


class Session:
    region_name = "eu-west-1"

    def __init__(self):
        self.log = {"calls": set(), "wrong": []}

    def client(self, name, region_name="eu-west-1", config=None):
        return Client(name, region_name, self.log)


@pytest.fixture(scope="module")
def read():
    session = Session()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("exitrisk.collectors.inventory.enabled_regions", lambda s, r: ["eu-west-1"])
        out, issues = collector.account_checks(session, ACCT, ["eu-west-1"], {"home": "eu-west-1", "org_ids": [ACCT]})
    return out, issues, session.log


def test_every_call_and_field_is_in_the_api(read):
    _, _, log = read
    assert not sorted(set(log["wrong"]))


def test_no_task_failed(read):
    out, issues, _ = read
    assert not [i for i in issues if i.severity in ("error", "warning")], [i.message for i in issues]
    assert {k for k, v in out["checks"].items() if v["status"] == "unknown"} == set()


def test_principals_are_people_pipelines_and_the_roles_people_reach(read):
    out, _, _ = read
    kinds = {p["label"]: p for p in out["principals"]}
    assert kinds["permission set Developer"]["kind"] == "person"
    assert "any GitHub project" in kinds["pipeline role github-deploy (GitHub)"]["weak"]
    assert kinds["pipeline role deploy-admin"]["reached_by"] == ["permission set Developer"]
    assert kinds["IAM user deployer"]["keys"][0]["age"] >= 399


def test_logs_buckets_are_not_assets_and_payment_ones_are(read):
    out, _, _ = read
    names = {a["name"]: a for a in out["assets"]}
    assert "app-access-logs" not in names
    assert names["payments-outbound"]["payment"] and names["wallet signer"]["kind"] == "signing key"


def _report(read):
    out, _, _ = read
    scan = {"id": "s", "accounts": [{"id": ACCT, "name": "prd-payments", "status": "ACTIVE"}],
            "compromise": {"accounts": {ACCT: out}}}  # fmt: skip
    return build_compromise(scan)


def test_the_report_names_who_can_change_what_and_whether_anyone_would_see(read):
    r = _report(read)
    by = {}
    for f in r["findings"]:
        by.setdefault(f["rule"], []).append(f)
    write = next(
        f for f in by["person_payment_write"] if f["asset"] == "payments-outbound" and f["action"] == "s3_write"
    )
    assert write["severity"] == "critical" and write["detect"] == "not logged"  # data events are off
    assert "permission set Developer" in write["who"]
    code = next(f for f in by["person_payment_write"] if f["action"] == "fn_code")
    assert code["severity"] == "high" and code["detect"] == "logged"  # a management event, logged, no alert
    assert by["person_sign"][0]["detect"] == "not logged"  # the trail keeps write events only
    assert "person_blind" not in by  # the SCP blocks StopLogging
    assert by["user_keys_write"] and by["pipeline_trust_open"][0]["severity"] == "critical"
    for rule in ("api_open", "fn_url_open", "fn_public_policy", "db_public", "payment_no_versioning", "unsigned_code",
                 "mutable_images", "laptop_changes", "data_events_off", "read_events_off", "no_change_alert",
                 "long_session", "person_db", "guardduty_s3_off", "table_no_pitr", "secret_no_rotation", "api_no_logs",
                 "payment_file_no_alert", "trail_no_validation", "role_assume_no_alert"):  # fmt: skip
        assert rule in by, rule
    assert r["summary"]["laptop_changes"] == 1 and r["changes"][0]["tool"] == "AWS CLI"
    # Pipelines count as compromised too: the open GitHub role is among those who can change the file.
    assert "pipeline role github-deploy (GitHub)" in write["who"]
    flows = {(x["kind"], x["name"]): x for x in r["flows"]}
    assert flows[("bucket", "payments-outbound")]["verdict"] == "neither"
    direct = by["db_direct"][0]
    assert direct["severity"] == "critical" and len(direct["evidence"]) == 2  # Zscaler and the /16, not the groups
    assert any("laptop range" in e for e in direct["evidence"])


def test_a_database_open_only_to_the_proxy_and_known_ranges_is_not_direct(read):
    out, _, _ = read
    scan = {
        "id": "s",
        "accounts": [{"id": ACCT, "name": "prd-payments", "status": "ACTIVE"}],
        "compromise": {"accounts": {ACCT: out}},
    }
    r = build_compromise(scan, {"proxy": ["sg-proxy"], "known": ["10.20.0.0/16", "165.225.10.0/24"]})
    assert not [f for f in r["findings"] if f["rule"] == "db_direct"]
    db = next(x for x in r["flows"] if x["kind"] == "database")
    assert "proxy sg-proxy" in db["immutable_why"]


def test_every_rule_the_report_uses_is_in_the_catalogue():
    ids = {r["id"] for r in catalog()["rules"]}
    import re
    from pathlib import Path

    src = Path(__file__).parents[1] / "src/exitrisk"
    used = set(re.findall(r'_finding\(\s*"(\w+)"', (src / "compromise.py").read_text()))
    used |= set(re.findall(r'expose\(\s*"(\w+)"', (src / "collectors/compromise.py").read_text()))
    assert used <= ids, used - ids


def test_judge_counts_a_path_tied_to_the_network_as_such():
    d, why = collector.judge({"EvalDecision": "allowed", "MissingContextValues": ["aws:SourceVpce"]})
    assert d == "network" and "VPC" in why
    assert collector.judge({"EvalDecision": "implicitDeny", "OrganizationsDecisionDetail":
                            {"AllowedByOrganizations": False}})[0] == "blocked"  # fmt: skip


def test_without_reads_the_report_offers_the_accounts_to_pick():
    scan = {"id": "s", "accounts": [{"id": "1", "name": "payments-prod", "status": "ACTIVE"},
                                    {"id": "2", "name": "sandbox", "status": "ACTIVE"}]}  # fmt: skip
    r = build_compromise(scan)
    assert not r["available"] and r["accounts_to_pick"][0]["suggested"] and not r["accounts_to_pick"][1]["suggested"]


def test_a_deny_that_only_enforces_tls_or_encryption_does_not_need_the_policy_weighed():
    tls = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
                          "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}  # fmt: skip
    who = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "*",
                          "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::1:role/app"}}}]}  # fmt: skip
    assert not collector.has_deny(tls) and collector.has_deny(who)
