"""Developer Compromise checks: what a person, or a pipeline, could change in an account from a laptop.

Read only, in the accounts the analyst picks (payment and channel accounts), with strict rules. A path is
reported only when it is complete: AWS's own policy simulator (iam:SimulatePrincipalPolicy) decides each
one, so identity policies, permission boundaries, organisation guardrails (SCPs) and, where read, the
resource's own policy are all weighed. A path that depends on where the call comes from (a source address
or a VPC endpoint) is labelled so, never counted as open.

It reads:
- who can act: IAM Identity Center permission sets, SAML roles, IAM users, pipeline roles (OIDC, CodeBuild)
  and roles trusted by another account, plus the roles a person can switch into;
- what matters: S3 buckets, DynamoDB tables, databases, Lambda functions, ECS services, ECR repositories,
  secrets, signing keys and APIs;
- what would notice: CloudTrail management and data events, GuardDuty, alert rules;
- what people actually changed by hand in the last 30 days, and with which tool.
"""

from __future__ import annotations

import contextvars
import fnmatch
import json
import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import BOTO_CONFIG, ClientCache, with_backoff
from ..issues import Issue, describe_exception
from ..logging_config import get_logger
from .assurance import (
    NOT_CHANGE_SOURCES,
    NOT_CHANGES,
    Results,
    _code,
    _collapse,
    _credential_report,
    _doc,
    _listify,
    _pages,
    _run,
    _sso_label,
)

log = get_logger("compromise")

WORKERS = 8
MAX_ITEMS = 300  # resources of one kind read per region
MAX_PRINCIPALS = 60  # people, pipelines and outside roles simulated per account
SIM_CHUNK = 50  # resources per simulator call
CHANGE_DAYS = 30
CHANGE_PAGES = 120  # pages of 50 write events read per region (about 2 a second, so a minute)
KEY_DAYS = 90  # an access key older than this is a standing credential

# Names and tags that mark something as money-moving. It raises severity; every asset in a chosen account
# is checked.
PAYMENT = re.compile(
    r"pay|card|ledger|txn|transaction|settle|clearing|eft|debit|credit|swift|wallet|transfer|disburse|remit|"
    r"treasury|signing|signer|hsm|iso8583|pacs|pain0|camt|rpp|rtc|debicheck|money|fund",
    re.I,
)
# Buckets nobody tampers with to move money: access logs and query results.
NOT_ASSET_BUCKET = re.compile(
    r"(^|[-_.])(logs?|logging|access-?logs?|cloudtrail|athena-?(query-?)?results?|ssm-?patching|config-?bucket"
    r"|configbucket)([-_.0-9]|$)",
    re.I,
)
NETWORK_KEYS = {"aws:sourceip", "aws:sourcevpc", "aws:sourcevpce", "aws:vpcsourceip", "aws:viaawsservice"}
OIDC_SUB = {
    "token.actions.githubusercontent.com": "GitHub",
    "gitlab.com": "GitLab",
    "app.terraform.io": "Terraform Cloud",
    "api.bitbucket.org": "Bitbucket",
}
PIPELINE_SERVICES = ("codebuild.amazonaws.com", "codepipeline.amazonaws.com", "codedeploy.amazonaws.com")
PIPELINE_NAME = re.compile(
    r"pipeline|deploy|cicd|ci-cd|github|gitlab|jenkins|terraform|atlantis|spinnaker|argo|tfec|runner|codebuild", re.I
)
# Roles AWS and the organisation's own tooling use across accounts: Control Tower, StackSets, monitoring.
PLATFORM = re.compile(
    r"^(aws-controltower-|AWSControlTower|stacksets-exec-|AmazonGrafana|CloudWatch-CrossAccount|IAMRoleFor|"
    r"WA-Optimization|OrganizationAccountAccessRole|AWSCloudFormationStackSetExecutionRole|NetworkAnalyzerRole)",
    re.I,
)
BREAK_GLASS = re.compile(r"break-?glass|emergency|firecall", re.I)
# Calls a workload makes on the data plane of a service, logged as writes: not someone changing production.
DATA_PLANE = ("kafka-cluster", "s3-outposts", "execute-api", "rds-data", "dynamodb")
NOT_A_CHANGE = {"RefreshCheck", "StartQuery", "GenerateDataKey", "Decrypt", "Encrypt"}
CONSOLE_AGENTS = ("console.amazonaws.com", "signin.amazonaws.com", "AWS Internal")
TOOLS = (
    ("terraform", "Terraform"),
    ("aws-cli", "AWS CLI"),
    ("aws-cdk", "CDK"),
    ("pulumi", "Pulumi"),
    ("boto3", "Python SDK"),
    ("botocore", "Python SDK"),
    ("aws-sdk-java", "Java SDK"),
    ("aws-sdk-js", "JavaScript SDK"),
    ("aws-sdk-go", "Go SDK"),
    ("aws-sdk-dotnet", ".NET SDK"),
    ("aws-toolkit", "IDE toolkit"),
    ("cloudshell", "CloudShell"),
)

# What each attack does, the calls that do it, and how CloudTrail records them: "management" calls are in
# every trail, "data" calls only where data events are switched on for the resource, "read" management calls
# only on a trail that keeps read events, "none" never.
ACTIONS = {
    "s3_write": ("Change or replace a file", ("s3:PutObject",), "data"),
    "s3_erase": (
        "Delete old versions or stop versioning",
        ("s3:DeleteObjectVersion", "s3:PutBucketVersioning"),
        "data",
    ),
    "ddb_write": ("Insert or change a row", ("dynamodb:PutItem", "dynamodb:UpdateItem"), "data"),
    "db_secret": ("Read the database admin password", ("secretsmanager:GetSecretValue",), "read"),
    "db_reset": ("Reset the database admin password", ("rds:ModifyDBInstance", "rds:ModifyDBCluster"), "management"),
    "db_iam": ("Connect to the database with an AWS sign-in", ("rds-db:connect",), "none"),
    "db_data_api": ("Run SQL through the RDS Data API", ("rds-data:ExecuteStatement",), "management"),
    "fn_code": ("Replace a function's code", ("lambda:UpdateFunctionCode",), "management"),
    "fn_config": (
        "Change a function's settings or environment",
        ("lambda:UpdateFunctionConfiguration",),
        "management",
    ),
    "fn_invoke": ("Call a payment function directly", ("lambda:InvokeFunction",), "data"),
    "ecs_deploy": ("Deploy a container", ("ecs:UpdateService",), "management"),
    "ecr_push": ("Replace a container image", ("ecr:PutImage",), "management"),
    "secret_read": ("Read a secret", ("secretsmanager:GetSecretValue",), "read"),
    "key_sign": ("Sign with a signing key", ("kms:Sign", "kms:GenerateMac"), "read"),
    "api_invoke": ("Call an IAM-protected API", ("execute-api:Invoke",), "data"),
    "blind_trail": (
        "Stop or change the audit trail",
        ("cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors"),
        "management",
    ),
    "blind_gd": ("Switch off threat detection", ("guardduty:DeleteDetector", "guardduty:UpdateDetector"), "management"),
    "blind_alerts": (
        "Switch off an alert rule",
        ("events:DisableRule", "events:DeleteRule", "events:RemoveTargets"),
        "management",
    ),
}
_AWS_MANAGED: dict[str, dict] = {}  # AWS managed policy documents are the same in every account
_AWS_MANAGED_LOCK = threading.Lock()


class CompromiseCtx:
    """One account's reads."""

    what = "compromise"

    def __init__(self, session, account_id: str, regions: list[str], info: dict):
        self.session = session
        self.account_id = account_id
        self.regions = regions
        home = info.get("home")
        self.home = home if home in regions else regions[0] if regions else "us-east-1"
        self.org_ids = set(info.get("org_ids") or [])
        self.org_id = info.get("org_id") or ""
        # The account's own name says nothing about a resource: "paydck" in every bucket of the payments
        # account would mark them all money-moving.
        self.noise = [t for t in re.split(r"[-_. ]+", info.get("name") or "") if len(t) >= 3] + [account_id]
        self.services = None
        self.r = Results()
        self.issues: list[Issue] = []
        self._lock = threading.Lock()
        self.now = datetime.now(timezone.utc)
        self.principals: list[dict] = []
        self.assets: list[dict] = []
        self.targets: list[dict] = []  # (asset, action, resource arn, resource policy) to simulate
        self.exposures: list[dict] = []
        self.paths: list[dict] = []
        self.changes: dict[tuple, dict] = {}
        self.detect: dict = {"trails": [], "guardduty": {}, "rules": []}

    def client(self, name: str, region: str = "us-east-1"):
        return self.session.client(name, region_name=region, config=BOTO_CONFIG)

    def billed(self, *services: str) -> bool:
        return True

    def issue(self, issue: Issue) -> None:
        with self._lock:
            self.issues.append(issue)

    def asset(self, kind: str, name: str, region: str, arn: str, tags: dict | None = None, **facts) -> dict:
        text = " ".join([name, *((tags or {}).values()), *((tags or {}).keys())])
        for t in self.noise:
            text = re.sub(re.escape(t), " ", text, flags=re.I)
        a = {
            "id": f"{kind}:{region}:{name}",
            "kind": kind,
            "name": name,
            "region": region,
            "arn": arn,
            "payment": bool(PAYMENT.search(text)),
            "facts": facts,
        }
        with self._lock:
            self.assets.append(a)
        return a

    def target(self, asset: dict, action: str, resource: str, policy: dict | None = None) -> None:
        with self._lock:
            self.targets.append(
                {
                    "asset": asset["id"],
                    "action": action,
                    "resource": resource,
                    "policy": policy,
                    "region": asset["region"],
                }
            )

    def expose(self, rule: str, asset: dict, note: str) -> None:
        with self._lock:
            self.exposures.append({"rule": rule, "asset": asset["id"], "note": note})


# ------------------------------------------------------------------------------------------- policy text
def _matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), str(pattern).lower())


def may_allow(docs: list[dict], action: str) -> bool:
    """True if any Allow statement could cover ``action``, whatever its resource or conditions. False is
    exact: with no Allow at all the answer is no, so the simulator need not be asked."""
    for doc in docs:
        for st in _listify(doc.get("Statement")):
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            if "Action" in st and any(_matches(p, action) for p in _listify(st["Action"])):
                return True
            if "NotAction" in st and not any(_matches(p, action) for p in _listify(st["NotAction"])):
                return True
    return False


def has_deny(policy: dict | None) -> bool:
    return any(isinstance(st, dict) and st.get("Effect") == "Deny" for st in _listify((policy or {}).get("Statement")))


def _principals(st: dict, key: str) -> list[str]:
    p = st.get("Principal")
    if p == "*":
        return ["*"]
    return [str(x) for x in _listify((p or {}).get(key))] if isinstance(p, dict) else []


def _cond_values(st: dict, key: str) -> list[str]:
    """Every value a statement's conditions give ``key`` (case-insensitive), whatever the operator."""
    out = []
    for values in (st.get("Condition") or {}).values():
        for k, v in (values or {}).items():
            if k.lower() == key.lower():
                out.extend(str(x) for x in _listify(v))
    return out


def classify_trust(role: dict, account: str, org_ids: set[str]) -> dict | None:
    """Who can become this role, or None for a role only AWS services use. kind: person, pipeline, outside or
    role (assumable by others in this account). ``weak``: why the trust lets in more than it should."""
    name = role.get("RoleName", "")
    path = role.get("Path", "")
    if path.startswith("/aws-service-role/") or name.startswith("AWSServiceRole"):
        return None
    trust = _doc(role.get("AssumeRolePolicyDocument"))
    sts = [st for st in _listify(trust.get("Statement")) if isinstance(st, dict) and st.get("Effect") == "Allow"]
    if name.startswith("AWSReservedSSO_"):
        return {"kind": "person", "label": _sso_label(name), "weak": None}
    text = json.dumps(trust)
    if "saml-provider" in text or "AssumeRoleWithSAML" in text:
        return {"kind": "person", "label": f"SAML role {name}", "weak": None}
    for st in sts:
        for fed in _principals(st, "Federated"):
            provider = next((v for k, v in OIDC_SUB.items() if k in fed), None)
            if not provider:
                continue
            host = next(k for k in OIDC_SUB if k in fed)
            subs = _cond_values(st, f"{host}:sub")
            if not subs:
                weak = f"{provider} sign-in with no subject condition: any {provider} project can become it"
            elif any(s.strip() in ("*", "repo:*", "project_path:*") for s in subs):
                weak = f"{provider} subject is a wildcard ({', '.join(subs[:2])}): any project can become it"
            elif any(s.endswith(":*") and s.count("/") <= 1 for s in subs):
                weak = f"{provider} subject allows every branch and tag ({', '.join(subs[:2])})"
            else:
                weak = None
            return {"kind": "pipeline", "label": f"pipeline role {name} ({provider})", "weak": weak, "subs": subs[:5]}
    services = [s for st in sts for s in _principals(st, "Service")]
    if any(s in PIPELINE_SERVICES for s in services):
        return {"kind": "pipeline", "label": f"pipeline role {name}", "weak": None}
    aws = [(st, a) for st in sts for a in _principals(st, "AWS")]
    if not aws and services:
        return None  # a workload role: Lambda, ECS tasks, EC2
    outside, other = [], set()
    for st, a in aws:
        acct = a if a.isdigit() else (a.split(":")[4] if a.startswith("arn:") and len(a.split(":")) > 4 else "")
        if a == "*" or (acct and acct != account and acct not in org_ids):
            if not (_cond_values(st, "sts:ExternalId") or _cond_values(st, "aws:PrincipalOrgID")):
                outside.append(a)
        elif acct and acct != account:
            other.add(acct)
    if PLATFORM.search(name):
        return None  # AWS's and the organisation's own tooling, guarded where it is run from
    if outside:
        return {
            "kind": "outside",
            "label": f"role {name} (trusted by an account outside the organisation)",
            "weak": f"trusted by {', '.join(sorted(set(outside))[:3])} with no external ID",
        }
    if other and not PIPELINE_NAME.search(name) and not BREAK_GLASS.search(name):
        # Switched into from another account of the organisation, such as a jump account: people there act
        # here through it. Who can reach it is decided in that account.
        return {
            "kind": "cross",
            "label": f"role {name} (from account {', '.join(sorted(other)[:2])})",
            "weak": None,
            "from": sorted(other),
        }
    if BREAK_GLASS.search(name):
        return {"kind": "person", "label": f"break-glass role {name}", "weak": None}
    if aws:
        kind = "pipeline" if PIPELINE_NAME.search(name) else "role"
        return {
            "kind": kind,
            "label": f"{'pipeline ' if kind == 'pipeline' else ''}role {name}",
            "weak": None,
            "trusts": [
                {
                    "principals": _principals(st, "AWS"),
                    "arns": _cond_values(st, "aws:PrincipalArn"),
                    "conditions": bool(st.get("Condition")),
                }
                for st in sts
                if _principals(st, "AWS")
            ],
        }
    return None


def _reaches(person_arn: str, trusts: list[dict], account: str) -> str | None:
    """How a person's role can switch into a role trusted inside this account: "named" (the trust names it,
    which is enough on its own), "root" (the trust lets the account decide, so the person's own policies must
    allow sts:AssumeRole) or None."""
    for t in trusts:
        for p in t["principals"]:
            if p == person_arn or (p.endswith(":role/" + person_arn.rsplit("/", 1)[-1]) and account in p):
                return "named"
            if p in (account, f"arn:aws:iam::{account}:root"):
                pats = t["arns"]
                if not pats or any(fnmatch.fnmatchcase(person_arn, x) for x in pats):
                    return "root"
    return None


# ----------------------------------------------------------------------------------------- global reads
def _managed_doc(iam, arn: str, local: dict) -> dict:
    if arn in local:
        return local[arn]
    with _AWS_MANAGED_LOCK:
        if arn in _AWS_MANAGED:
            return _AWS_MANAGED[arn]
    pol = with_backoff(iam.get_policy, PolicyArn=arn)["Policy"]
    doc = _doc(
        with_backoff(iam.get_policy_version, PolicyArn=arn, VersionId=pol["DefaultVersionId"])["PolicyVersion"][
            "Document"
        ]
    )
    with _AWS_MANAGED_LOCK:
        _AWS_MANAGED[arn] = doc
    return doc


def task_identities(ctx: CompromiseCtx) -> None:
    """Every principal that is not an AWS service: who it is, its policies, how long its sessions last."""
    iam = ctx.client("iam")
    detail = {"RoleDetailList": [], "UserDetailList": [], "GroupDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate(
        Filter=["Role", "User", "Group", "LocalManagedPolicy"]
    ):
        for k in detail:
            detail[k].extend(page.get(k) or [])
    local = {}
    for p in detail["Policies"]:
        doc = next((v["Document"] for v in p.get("PolicyVersionList") or [] if v.get("IsDefaultVersion")), None)
        local[p["Arn"]] = _doc(doc)
    groups = {g["GroupName"]: g for g in detail["GroupDetailList"]}

    def docs_of(item: dict, kind: str) -> list[dict]:
        inline = "RolePolicyList" if kind == "role" else "UserPolicyList"
        out = [_doc(x.get("PolicyDocument")) for x in item.get(inline) or []]
        out += [_managed_doc(iam, m["PolicyArn"], local) for m in item.get("AttachedManagedPolicies") or []]
        for g in (item.get("GroupList") if kind == "user" else None) or []:
            gd = groups.get(g) or {}
            out += [_doc(x.get("PolicyDocument")) for x in gd.get("GroupPolicyList") or []]
            out += [_managed_doc(iam, m["PolicyArn"], local) for m in gd.get("AttachedManagedPolicies") or []]
        return out

    hours = {r["RoleName"]: r.get("MaxSessionDuration") or 3600 for r in _pages(iam, "list_roles", "Roles")}

    people, roles = [], []
    for role in detail["RoleDetailList"]:
        kind = classify_trust(role, ctx.account_id, ctx.org_ids)
        if not kind:
            continue
        entry = {
            "arn": role["Arn"],
            "name": role["RoleName"],
            **kind,
            "hours": round(hours.get(role["RoleName"], 3600) / 3600, 1),
            "last_used": ((role.get("RoleLastUsed") or {}).get("LastUsedDate") or None),
            "docs": docs_of(role, "role"),
        }
        if entry["last_used"]:
            entry["last_used"] = entry["last_used"].isoformat()
        (people if kind["kind"] == "person" else roles).append(entry)
    report = {row["user"]: row for row in _credential_report(iam)}
    for u in detail["UserDetailList"]:
        row = report.get(u["UserName"]) or {}
        keys = []
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") == "true":
                made = row.get(f"access_key_{n}_last_rotated") or ""
                used = row.get(f"access_key_{n}_last_used_date") or ""
                age = _days(made, ctx.now)
                keys.append({"age": age, "last_used": used if used not in ("N/A", "no_information") else ""})
        console = row.get("password_enabled") == "true"
        people.append(
            {
                "arn": u["Arn"],
                "name": u["UserName"],
                "kind": "user",
                "label": f"IAM user {u['UserName']}",
                "weak": None,
                "keys": keys,
                "console": console,
                "mfa": row.get("mfa_active") == "true",
                "docs": docs_of(u, "user"),
            }
        )
    # The roles a person can switch into become attackers too, as that person.
    reach = [r for r in roles if r["kind"] in ("role", "pipeline") and r.get("trusts")]
    for person in [p for p in people if p["kind"] == "person"]:
        for r in reach:
            how = _reaches(person["arn"], r["trusts"], ctx.account_id)
            if how == "root":
                if not may_allow(person["docs"], "sts:AssumeRole"):
                    continue
                d = _simulate(ctx, person, ["sts:AssumeRole"], [r["arn"]])
                how = "root" if d and d[0]["decision"] in ("allowed", "network") else None
            if how:
                r.setdefault("reached_by", []).append(person["label"])
    kept = list(people) + [r for r in roles if r["kind"] in ("pipeline", "outside", "cross") or r.get("reached_by")]
    ctx.principals = kept[:MAX_PRINCIPALS]
    if len(kept) > MAX_PRINCIPALS:
        ctx.r.unknown("identities", f"{len(kept) - MAX_PRINCIPALS} principals beyond the first {MAX_PRINCIPALS}")
    summary = with_backoff(iam.get_account_summary)["SummaryMap"]
    ctx.r.fact(
        "root", {"mfa": bool(summary.get("AccountMFAEnabled")), "keys": bool(summary.get("AccountAccessKeysPresent"))}
    )
    ctx.r.ok("identities")


def _days(stamp: str, now: datetime) -> int | None:
    try:
        return (now - datetime.fromisoformat(stamp.replace("Z", "+00:00"))).days
    except (ValueError, AttributeError):
        return None


def task_buckets(ctx: CompromiseCtx) -> None:
    s3 = ctx.client("s3")
    for b in (with_backoff(s3.list_buckets).get("Buckets") or [])[:MAX_ITEMS]:
        name = b["Name"]
        if NOT_ASSET_BUCKET.search(name):
            continue
        try:
            region = with_backoff(s3.get_bucket_location, Bucket=name).get("LocationConstraint") or "us-east-1"
        except ClientError:
            continue
        rs3 = ctx.client("s3", region)
        facts = {}
        try:
            v = with_backoff(rs3.get_bucket_versioning, Bucket=name)
            facts["versioning"] = v.get("Status") == "Enabled"
            facts["mfa_delete"] = v.get("MFADelete") == "Enabled"
        except ClientError:
            facts["versioning"] = None
        try:
            lock = with_backoff(rs3.get_object_lock_configuration, Bucket=name)["ObjectLockConfiguration"]
            rule = (lock.get("Rule") or {}).get("DefaultRetention") or {}
            on = lock.get("ObjectLockEnabled") == "Enabled"
            facts["object_lock"] = (rule.get("Mode") or "on, no default retention") if on else ""
        except ClientError as exc:
            facts["object_lock"] = "" if _code(exc) == "ObjectLockConfigurationNotFoundError" else None
        policy = None
        try:
            policy = _doc(with_backoff(rs3.get_bucket_policy, Bucket=name)["Policy"])
        except ClientError:
            pass
        tags = {}
        try:
            tags = {t["Key"]: t["Value"] for t in with_backoff(rs3.get_bucket_tagging, Bucket=name)["TagSet"]}
        except ClientError:
            pass
        try:
            note = with_backoff(rs3.get_bucket_notification_configuration, Bucket=name)
            facts["eventbridge"] = "EventBridgeConfiguration" in note
        except ClientError:
            facts["eventbridge"] = None
        a = ctx.asset("bucket", name, region, f"arn:aws:s3:::{name}", tags, **facts)
        kept = policy if has_deny(policy) else None
        ctx.target(a, "s3_write", f"arn:aws:s3:::{name}/exitrisk-check", kept)
        ctx.target(a, "s3_erase", f"arn:aws:s3:::{name}", kept)  # stop versioning: a bucket call
        ctx.target(a, "s3_erase", f"arn:aws:s3:::{name}/exitrisk-check", kept)  # delete a version: an object call
    ctx.r.ok("buckets")


def task_dynamodb(ctx: CompromiseCtx, region: str) -> None:
    ddb = ctx.client("dynamodb", region)
    for name in _pages(ddb, "list_tables", "TableNames", cap=MAX_ITEMS):
        t = with_backoff(ddb.describe_table, TableName=name)["Table"]
        policy = None
        try:
            policy = _doc(with_backoff(ddb.get_resource_policy, ResourceArn=t["TableArn"])["Policy"])
        except ClientError:
            pass
        a = ctx.asset(
            "table",
            name,
            region,
            t["TableArn"],
            stream=bool((t.get("StreamSpecification") or {}).get("StreamEnabled")),
            protected=bool(t.get("DeletionProtectionEnabled")),
        )
        if a["payment"]:
            try:
                pitr = (
                    with_backoff(ddb.describe_continuous_backups, TableName=name).get("ContinuousBackupsDescription")
                    or {}
                )
                a["facts"]["pitr"] = (pitr.get("PointInTimeRecoveryDescription") or {}).get(
                    "PointInTimeRecoveryStatus"
                ) == "ENABLED"
            except ClientError:
                a["facts"]["pitr"] = None
        ctx.target(a, "ddb_write", t["TableArn"], policy if has_deny(policy) else None)
    ctx.r.ok("dynamodb")


def task_databases(ctx: CompromiseCtx, region: str) -> None:
    rds = ctx.client("rds", region)
    clusters = _pages(rds, "describe_db_clusters", "DBClusters", cap=MAX_ITEMS)
    in_cluster = set()
    for c in clusters:
        in_cluster.update(m["DBInstanceIdentifier"] for m in c.get("DBClusterMembers") or [])
        tags = {t["Key"]: t["Value"] for t in c.get("TagList") or []}
        a = ctx.asset(
            "database",
            c["DBClusterIdentifier"],
            region,
            c["DBClusterArn"],
            tags,
            engine=c.get("Engine"),
            iam_auth=bool(c.get("IAMDatabaseAuthenticationEnabled")),
            data_api=bool(c.get("HttpEndpointEnabled")),
            activity_stream=c.get("ActivityStreamStatus") in ("started", "starting"),
            public=False,
            port=c.get("Port"),
            groups=[g["VpcSecurityGroupId"] for g in c.get("VpcSecurityGroups") or []],
        )
        _database_targets(
            ctx,
            a,
            c.get("MasterUserSecret"),
            c["DBClusterArn"],
            c.get("DbClusterResourceId"),
            c.get("IAMDatabaseAuthenticationEnabled"),
            c.get("HttpEndpointEnabled"),
            region,
        )
    for d in _pages(rds, "describe_db_instances", "DBInstances", cap=MAX_ITEMS):
        if d["DBInstanceIdentifier"] in in_cluster:
            continue
        tags = {t["Key"]: t["Value"] for t in d.get("TagList") or []}
        a = ctx.asset(
            "database",
            d["DBInstanceIdentifier"],
            region,
            d["DBInstanceArn"],
            tags,
            engine=d.get("Engine"),
            iam_auth=bool(d.get("IAMDatabaseAuthenticationEnabled")),
            data_api=False,
            activity_stream=d.get("ActivityStreamStatus") in ("started", "starting"),
            public=bool(d.get("PubliclyAccessible")),
            port=(d.get("Endpoint") or {}).get("Port") or d.get("DbInstancePort"),
            groups=[g["VpcSecurityGroupId"] for g in d.get("VpcSecurityGroups") or []],
        )
        _database_targets(
            ctx,
            a,
            d.get("MasterUserSecret"),
            d["DBInstanceArn"],
            d.get("DbiResourceId"),
            d.get("IAMDatabaseAuthenticationEnabled"),
            False,
            region,
        )
        if d.get("PubliclyAccessible"):
            ctx.expose("db_public", a, "the database has a public address")
    mine = [a for a in ctx.assets if a["kind"] == "database" and a["region"] == region]
    if mine:
        _database_network(ctx, region, mine, rds)
    ctx.r.ok("databases")


def _sources(perm: dict) -> list[dict]:
    out = [{"cidr": r["CidrIp"], "note": r.get("Description", "")} for r in perm.get("IpRanges") or []]
    out += [{"cidr": r["CidrIpv6"], "note": r.get("Description", "")} for r in perm.get("Ipv6Ranges") or []]
    out += [{"pl": r["PrefixListId"], "note": r.get("Description", "")} for r in perm.get("PrefixListIds") or []]
    out += [
        {"sg": r["GroupId"], "owner": r.get("UserId", ""), "note": r.get("Description", "")}
        for r in perm.get("UserIdGroupPairs") or []
    ]
    return out


def _covers_port(perm: dict, port: int | None) -> bool:
    if perm.get("IpProtocol") == "-1" or port is None:
        return True
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    return lo is not None and hi is not None and lo <= port <= hi


def _eni_kind(eni: dict) -> str:
    kind = eni.get("InterfaceType") or ""
    desc = eni.get("Description") or ""
    if kind == "lambda" or desc.startswith("AWS Lambda VPC ENI"):
        return "Lambda function"
    if "arn:aws:ecs" in desc or kind == "branch":
        return "ECS task"
    if desc.startswith("RDSNetworkInterface"):
        return "RDS"
    if kind == "vpc_endpoint" or desc.startswith("VPC Endpoint"):
        return "VPC endpoint"
    if desc.startswith("ELB "):
        return "load balancer"
    if (eni.get("Attachment") or {}).get("InstanceId"):
        return "EC2 instance"
    return kind or "network interface"


def _database_network(ctx: CompromiseCtx, region: str, dbs: list[dict], rds) -> None:
    """Who can reach each database's port: every source in its security groups. A security group used by this
    account's workloads is a known path; an address range (a CIDR or a prefix list) is not, because anything
    behind it, laptops through Zscaler or the VPN included, can connect directly."""
    ec2 = ctx.client("ec2", region)
    ids = sorted({g for a in dbs for g in a["facts"].get("groups") or []})
    groups = {
        g["GroupId"]: g
        for at in range(0, len(ids), 100)
        for g in _pages(ec2, "describe_security_groups", "SecurityGroups", GroupIds=ids[at : at + 100])
    }
    refs = set()
    for a in dbs:
        found = []
        for gid in a["facts"].get("groups") or []:
            for perm in (groups.get(gid) or {}).get("IpPermissions") or []:
                if _covers_port(perm, a["facts"].get("port")):
                    for src in _sources(perm):
                        found.append({**src, "via": gid})
                        if src.get("sg"):
                            refs.add(src["sg"])
        a["facts"]["ingress"] = found[:60]
    names, used = {}, {}
    local = sorted(r for r in refs if r not in groups)
    for at in range(0, len(local), 100):
        try:
            for g in _pages(ec2, "describe_security_groups", "SecurityGroups", GroupIds=local[at : at + 100]):
                groups[g["GroupId"]] = g
        except ClientError:
            pass  # a group in another account
    for gid in refs:
        names[gid] = (groups.get(gid) or {}).get("GroupName", "")
    ref_list = sorted(refs)
    for at in range(0, len(ref_list), 150):
        for eni in _pages(
            ec2,
            "describe_network_interfaces",
            "NetworkInterfaces",
            cap=2000,
            Filters=[{"Name": "group-id", "Values": ref_list[at : at + 150]}],
        ):
            kind = _eni_kind(eni)
            for g in eni.get("Groups") or []:
                if g["GroupId"] in refs:
                    used.setdefault(g["GroupId"], Counter())[kind] += 1
    pls = sorted({s["pl"] for a in dbs for s in a["facts"]["ingress"] if s.get("pl")})
    entries = {}
    for pl in pls:
        try:
            entries[pl] = [
                e["Cidr"] for e in _pages(ec2, "get_managed_prefix_list_entries", "Entries", PrefixListId=pl)
            ][:200]
        except ClientError:
            entries[pl] = []
    proxied: dict[str, list[str]] = {}
    try:
        for px in _pages(rds, "describe_db_proxies", "DBProxies", cap=MAX_ITEMS):
            for t in _pages(rds, "describe_db_proxy_targets", "Targets", DBProxyName=px["DBProxyName"]):
                proxied.setdefault(t.get("RdsResourceId") or "", []).append(px["DBProxyName"])
    except ClientError as exc:
        if _code(exc) not in ("AccessDenied", "AccessDeniedException"):
            raise
    for a in dbs:
        for src in a["facts"]["ingress"]:
            if src.get("sg"):
                src["name"] = names.get(src["sg"], "")
                src["attached"] = dict(used.get(src["sg"]) or {})
                src["self"] = src["sg"] in (a["facts"].get("groups") or [])
                src["account"] = src.get("owner") or ctx.account_id
            if src.get("pl"):
                src["cidrs"] = entries.get(src["pl"], [])
        a["facts"]["rds_proxy"] = proxied.get(a["name"], [])


def _database_targets(ctx, a, secret, arn, resource_id, iam_auth, data_api, region) -> None:
    if secret and secret.get("SecretArn"):
        ctx.target(a, "db_secret", secret["SecretArn"])
        a["facts"]["managed_secret"] = True
    ctx.target(a, "db_reset", arn)
    if iam_auth and resource_id:
        ctx.target(a, "db_iam", f"arn:aws:rds-db:{region}:{ctx.account_id}:dbuser:{resource_id}/*")
    if data_api:
        ctx.target(a, "db_data_api", arn)


def task_functions(ctx: CompromiseCtx, region: str) -> None:
    lam = ctx.client("lambda", region)
    for f in _pages(lam, "list_functions", "Functions", cap=MAX_ITEMS):
        name, arn = f["FunctionName"], f["FunctionArn"]
        facts = {"runtime": f.get("Runtime") or f.get("PackageType")}
        a = ctx.asset("function", name, region, arn, **facts)
        ctx.target(a, "fn_code", arn)
        ctx.target(a, "fn_config", arn)
        if a["payment"]:
            ctx.target(a, "fn_invoke", arn)
            try:
                signing = with_backoff(lam.get_function_code_signing_config, FunctionName=name)
                a["facts"]["code_signing"] = bool(signing.get("CodeSigningConfigArn"))
            except ClientError:
                a["facts"]["code_signing"] = None
        for u in _pages(lam, "list_function_url_configs", "FunctionUrlConfigs", FunctionName=name):
            if u.get("AuthType") == "NONE":
                ctx.expose("fn_url_open", a, "a function URL anyone on the internet can call, with no sign-in")
        try:
            policy = _doc(with_backoff(lam.get_policy, FunctionName=name)["Policy"])
        except ClientError:
            policy = None
        for st in _listify((policy or {}).get("Statement")):
            anyone = st.get("Principal") == "*" or "*" in _principals(st, "AWS")
            if st.get("Effect") == "Allow" and anyone and not st.get("Condition"):
                ctx.expose("fn_public_policy", a, "its policy lets anyone call it")
                break
    ctx.r.ok("functions")


def task_containers(ctx: CompromiseCtx, region: str) -> None:
    ecs = ctx.client("ecs", region)
    for cluster in _pages(ecs, "list_clusters", "clusterArns", cap=50):
        arns = _pages(ecs, "list_services", "serviceArns", cap=MAX_ITEMS, cluster=cluster)
        for at in range(0, len(arns), 10):
            for s in with_backoff(ecs.describe_services, cluster=cluster, services=arns[at : at + 10])["services"]:
                td = with_backoff(ecs.describe_task_definition, taskDefinition=s["taskDefinition"])["taskDefinition"]
                images = [c.get("image", "") for c in td.get("containerDefinitions") or []]
                by_tag = [i for i in images if "@sha256:" not in i]
                a = ctx.asset(
                    "service",
                    s["serviceName"],
                    region,
                    s["serviceArn"],
                    cluster=cluster.rsplit("/", 1)[-1],
                    images=images[:4],
                    by_tag=bool(by_tag),
                )
                ctx.target(a, "ecs_deploy", s["serviceArn"])
    ecr = ctx.client("ecr", region)
    for repo in _pages(ecr, "describe_repositories", "repositories", cap=MAX_ITEMS):
        policy = None
        try:
            policy = _doc(with_backoff(ecr.get_repository_policy, repositoryName=repo["repositoryName"])["policyText"])
        except ClientError:
            pass
        a = ctx.asset(
            "repository",
            repo["repositoryName"],
            region,
            repo["repositoryArn"],
            mutable=repo.get("imageTagMutability", "MUTABLE").startswith("MUTABLE"),
            scan=bool((repo.get("imageScanningConfiguration") or {}).get("scanOnPush")),
        )
        ctx.target(a, "ecr_push", repo["repositoryArn"], policy if has_deny(policy) else None)
    ctx.r.ok("containers")


def task_secrets_and_keys(ctx: CompromiseCtx, region: str) -> None:
    sm = ctx.client("secretsmanager", region)
    for s in _pages(sm, "list_secrets", "SecretList", cap=MAX_ITEMS):
        if (s.get("OwningService") or "") == "rds":
            continue  # an RDS admin password: checked with its database
        tags = {t["Key"]: t["Value"] for t in s.get("Tags") or []}
        a = ctx.asset("secret", s["Name"], region, s["ARN"], tags, rotation=bool(s.get("RotationEnabled")))
        policy = None
        if a["payment"]:
            try:
                raw = with_backoff(sm.get_resource_policy, SecretId=s["ARN"]).get("ResourcePolicy")
                policy = _doc(raw) if raw else None
            except ClientError:
                pass
        ctx.target(a, "secret_read", s["ARN"], policy if has_deny(policy) else None)
    kms = ctx.client("kms", region)
    for k in _pages(kms, "list_keys", "Keys", cap=MAX_ITEMS):
        try:
            meta = with_backoff(kms.describe_key, KeyId=k["KeyId"])["KeyMetadata"]
        except ClientError:
            continue
        if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
            continue
        if meta.get("KeyUsage") not in ("SIGN_VERIFY", "GENERATE_VERIFY_MAC"):
            continue
        policy = _doc(with_backoff(kms.get_key_policy, KeyId=k["KeyId"], PolicyName="default")["Policy"])
        a = ctx.asset(
            "signing key",
            meta.get("Description") or k["KeyId"],
            region,
            meta["Arn"],
            usage=meta["KeyUsage"],
            spec=meta.get("KeySpec"),
            delegated=_key_delegates(policy, ctx.account_id),
        )
        a["payment"] = True  # a signing key in a payment account is the money service's key
        ctx.target(a, "key_sign", meta["Arn"], policy)
    ctx.r.ok("secrets")


def _key_delegates(policy: dict, account: str) -> bool:
    """A key policy that lets the account's IAM policies decide (the usual "Enable IAM policies" statement)."""
    for st in _listify(policy.get("Statement")):
        if st.get("Effect") == "Allow" and any(
            p in (account, f"arn:aws:iam::{account}:root") for p in _principals(st, "AWS")
        ):
            return True
    return False


def task_apis(ctx: CompromiseCtx, region: str) -> None:
    """REST and HTTP APIs: a method with no sign-in on an API reachable from the internet is open to a laptop
    anywhere; an IAM-protected one is open to whoever holds the right credentials."""
    apigw = ctx.client("apigateway", region)
    for api in _pages(apigw, "get_rest_apis", "items", cap=MAX_ITEMS):
        types = (api.get("endpointConfiguration") or {}).get("types") or ["EDGE"]
        private = "PRIVATE" in types
        policy = _doc(api["policy"].replace('\\"', '"')) if api.get("policy") else None
        restricted = bool(policy) and any(
            k.lower() in NETWORK_KEYS
            for st in _listify(policy.get("Statement"))
            for c in (st.get("Condition") or {}).values()
            for k in c
        )
        arn = f"arn:aws:execute-api:{region}:{ctx.account_id}:{api['id']}/*"
        a = ctx.asset(
            "api",
            api.get("name") or api["id"],
            region,
            arn,
            private=private,
            restricted=restricted,
            endpoint=", ".join(types),
        )
        open_methods, iam_methods = [], 0
        for res in _pages(apigw, "get_resources", "items", cap=500, restApiId=api["id"], embed=["methods"]):
            for verb, m in (res.get("resourceMethods") or {}).items():
                if verb == "OPTIONS":
                    continue
                kind = m.get("authorizationType") or "NONE"
                if (m.get("methodIntegration") or {}).get("type") == "MOCK":
                    continue
                if kind == "NONE" and not m.get("apiKeyRequired"):
                    open_methods.append(f"{verb} {res.get('path')}")
                elif kind == "AWS_IAM":
                    iam_methods += 1
        a["facts"]["open"] = open_methods[:10]
        stages = _pages(apigw, "get_stages", "item", restApiId=api["id"])
        a["facts"]["logged"] = bool(stages) and all(
            (st.get("accessLogSettings") or {}).get("destinationArn") for st in stages
        )
        a["facts"]["waf"] = any(st.get("webAclArn") for st in stages)
        if open_methods and not private and not restricted:
            ctx.expose("api_open", a, f"{len(open_methods)} method(s) with no sign-in: {', '.join(open_methods[:3])}")
        if iam_methods:
            ctx.target(a, "api_invoke", arn, policy if has_deny(policy) else None)
    v2 = ctx.client("apigatewayv2", region)
    for api in _pages(v2, "get_apis", "Items", cap=MAX_ITEMS):
        arn = f"arn:aws:execute-api:{region}:{ctx.account_id}:{api['ApiId']}/*"
        a = ctx.asset(
            "api",
            api.get("Name") or api["ApiId"],
            region,
            arn,
            private=False,
            restricted=False,
            endpoint=api.get("ProtocolType", "HTTP"),
        )
        routes = _pages(v2, "get_routes", "Items", cap=500, ApiId=api["ApiId"])
        open_routes = [
            r["RouteKey"]
            for r in routes
            if (r.get("AuthorizationType") or "NONE") == "NONE"
            and not r.get("ApiKeyRequired")
            and not r["RouteKey"].startswith("OPTIONS")
        ]
        a["facts"]["open"] = open_routes[:10]
        stages = _pages(v2, "get_stages", "Items", ApiId=api["ApiId"])
        a["facts"]["logged"] = bool(stages) and all(
            (st.get("AccessLogSettings") or {}).get("DestinationArn") for st in stages
        )
        if open_routes and not api.get("DisableExecuteApiEndpoint"):
            ctx.expose("api_open", a, f"{len(open_routes)} route(s) with no sign-in: {', '.join(open_routes[:3])}")
        if any(r.get("AuthorizationType") == "AWS_IAM" for r in routes):
            ctx.target(a, "api_invoke", arn)
    ctx.r.ok("apis")


# ------------------------------------------------------------------------------------------- detection
def _data_selector_covers(trail: dict, rtype: str, arn: str) -> bool:
    """Whether a trail's event selectors log write data events of ``rtype`` for the resource ``arn``."""
    for sel in trail.get("selectors") or []:
        if sel.get("ReadWriteType") == "ReadOnly":
            continue
        for d in sel.get("DataResources") or []:
            if d.get("Type") == rtype and any(
                arn.startswith(v.rstrip("*"))
                or v in ("arn:aws:s3", "arn:aws:s3:::", f"arn:aws:{rtype.split('::')[1].lower()}")
                for v in d.get("Values") or []
            ):
                return True
    for sel in trail.get("advanced") or []:
        f = {x["Field"]: x for x in sel.get("FieldSelectors") or []}
        if (f.get("eventCategory") or {}).get("Equals") != ["Data"]:
            continue
        if rtype not in ((f.get("resources.type") or {}).get("Equals") or []):
            continue
        if (f.get("readOnly") or {}).get("Equals") == ["true"]:
            continue
        r = f.get("resources.ARN") or {}
        if not r:
            return True
        if any(arn.startswith(p) for p in r.get("StartsWith") or []) or arn in (r.get("Equals") or []):
            return True
        if r.get("NotStartsWith") and not any(arn.startswith(p) for p in r["NotStartsWith"]):
            return True
    return False


def _management(trail: dict) -> dict:
    """Which management events a trail keeps: {"write": bool, "read": bool}."""
    out = {"write": False, "read": False}
    for sel in trail.get("selectors") or []:
        if sel.get("IncludeManagementEvents", True):
            rw = sel.get("ReadWriteType", "All")
            out["write"] |= rw in ("All", "WriteOnly")
            out["read"] |= rw in ("All", "ReadOnly")
    for sel in trail.get("advanced") or []:
        f = {x["Field"]: x for x in sel.get("FieldSelectors") or []}
        if (f.get("eventCategory") or {}).get("Equals") == ["Management"]:
            ro = (f.get("readOnly") or {}).get("Equals")
            out["write"] |= ro != ["true"]
            out["read"] |= ro != ["false"]
    return out


def task_trails(ctx: CompromiseCtx) -> None:
    ct = ctx.client("cloudtrail", ctx.home)
    for t in with_backoff(ct.describe_trails, includeShadowTrails=True).get("trailList") or []:
        home = t.get("HomeRegion") or ctx.home
        rct = ctx.client("cloudtrail", home)
        entry = {
            "name": t.get("Name"),
            "org": bool(t.get("IsOrganizationTrail")),
            "multi": bool(t.get("IsMultiRegionTrail")),
            "home": home,
            "logging": None,
            "read": True,
            "arn": t.get("TrailARN"),
            "validation": bool(t.get("LogFileValidationEnabled")),
            "own": (t.get("TrailARN") or "").split(":")[4:5] == [ctx.account_id],
        }
        try:
            entry["logging"] = bool(with_backoff(rct.get_trail_status, Name=t["TrailARN"]).get("IsLogging"))
            sel = with_backoff(rct.get_event_selectors, TrailName=t["TrailARN"])
            entry["selectors"] = sel.get("EventSelectors") or []
            entry["advanced"] = sel.get("AdvancedEventSelectors") or []
            if not entry["selectors"] and not entry["advanced"]:
                entry["selectors"] = [{"ReadWriteType": "All", "IncludeManagementEvents": True}]
        except ClientError:
            entry["read"] = False  # an organisation trail its owner does not let members read
        ctx.detect["trails"].append(entry)
    ctx.r.ok("trails")


def task_detection(ctx: CompromiseCtx, region: str) -> None:
    gd = ctx.client("guardduty", region)
    ids = with_backoff(gd.list_detectors).get("DetectorIds") or []
    state = {"on": False, "features": []}
    if ids:
        d = with_backoff(gd.get_detector, DetectorId=ids[0])
        state["on"] = d.get("Status") == "ENABLED"
        state["features"] = sorted(f["Name"] for f in d.get("Features") or [] if f.get("Status") == "ENABLED")
        state["arn"] = f"arn:aws:guardduty:{region}:{ctx.account_id}:detector/{ids[0]}"
    ctx.detect["guardduty"][region] = state
    ev = ctx.client("events", region)
    for rule in _pages(ev, "list_rules", "Rules", cap=MAX_ITEMS):
        if rule.get("State") != "ENABLED" or not rule.get("EventPattern"):
            continue
        try:
            pattern = json.loads(rule["EventPattern"])
        except json.JSONDecodeError:
            continue
        targets = _pages(ev, "list_targets_by_rule", "Targets", Rule=rule["Name"])
        if not targets:
            continue
        detail = pattern.get("detail") or {}
        ctx.detect["rules"].append(
            {
                "name": rule["Name"],
                "arn": rule.get("Arn"),
                "region": region,
                "sources": [str(s) for s in _listify(pattern.get("source"))],
                "types": [str(s) for s in _listify(pattern.get("detail-type"))],
                "events": [str(s) for s in _listify(detail.get("eventName"))],
                "people": "userIdentity" in json.dumps(detail),
                "roles": [str(x) for x in _listify((detail.get("requestParameters") or {}).get("roleArn"))][:20],
            }
        )
    ctx.r.ok("detection")


# ---------------------------------------------------------------------------------- what people changed
def _tool(agent: str) -> str:
    low = (agent or "").lower()
    if not low or low == "aws internal":
        return ""  # an AWS service acting, not a person at a keyboard
    if any(c.lower() in low for c in CONSOLE_AGENTS) or "mozilla" in low:
        return "Console"
    return next((label for key, label in TOOLS if key in low), "Other tool")


def task_changes(ctx: CompromiseCtx, region: str) -> None:
    """Every write a person made by hand in the window, with the tool they used: a change from a laptop's
    command line or Terraform is what a stolen session looks like."""
    ct = ctx.client("cloudtrail", region)
    start = ctx.now - timedelta(days=CHANGE_DAYS)
    kwargs = {
        "LookupAttributes": [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
        "StartTime": start,
        "EndTime": ctx.now,
        "MaxResults": 50,
    }
    for _ in range(CHANGE_PAGES):
        page = with_backoff(ct.lookup_events, **kwargs)
        for e in page.get("Events") or []:
            name, source = e.get("EventName", ""), e.get("EventSource", "")
            if name in NOT_CHANGES or name in NOT_A_CHANGE or source.startswith(NOT_CHANGE_SOURCES):
                continue
            try:
                raw = json.loads(e.get("CloudTrailEvent") or "{}")
            except json.JSONDecodeError:
                continue
            ident = raw.get("userIdentity") or {}
            kind, arn = ident.get("type"), ident.get("arn", "")
            if kind == "IAMUser":
                who = f"IAM user {ident.get('userName', '')}"
            elif kind == "Root":
                who = "root"
            elif kind == "AssumedRole" and ":assumed-role/AWSReservedSSO_" in arn:
                who = _sso_label(arn.split(":assumed-role/", 1)[1].split("/", 1)[0])
            elif kind == "AssumedRole" and ":assumed-role/" in arn:
                role, _, session = arn.split(":assumed-role/", 1)[1].partition("/")
                who = f"role:{role}" + ("@" if "@" in session else "")  # kept if a person reaches it (see below)
            else:
                continue
            if raw.get("errorCode"):
                continue
            tool = _tool(raw.get("userAgent", ""))
            if not tool or source.startswith(DATA_PLANE):
                continue
            what = f"{source.split('.')[0]}:{name}"
            key = (who, tool, what, region)
            with ctx._lock:
                c = ctx.changes.setdefault(
                    key,
                    {
                        "who": who,
                        "tool": tool,
                        "action": what,
                        "region": region,
                        "count": 0,
                        "last": "",
                        "resource": "",
                        "ips": set(),
                    },
                )
                c["count"] += 1
                when = e["EventTime"].isoformat() if hasattr(e.get("EventTime"), "isoformat") else ""
                if when > c["last"]:
                    c["last"] = when
                    res = (e.get("Resources") or [{}])[0].get("ResourceName", "")
                    c["resource"] = res
                if len(c["ips"]) < 3 and raw.get("sourceIPAddress"):
                    c["ips"].add(raw["sourceIPAddress"])
        if not page.get("NextToken"):
            break
        kwargs["NextToken"] = page["NextToken"]
    ctx.r.ok("changes")


# ------------------------------------------------------------------------------------------- simulate
def _context(ctx: CompromiseCtx, principal: dict, region: str | None = None) -> list[dict]:
    out = [
        {"ContextKeyName": "aws:PrincipalArn", "ContextKeyValues": [principal["arn"]], "ContextKeyType": "string"},
        {"ContextKeyName": "aws:PrincipalAccount", "ContextKeyValues": [ctx.account_id], "ContextKeyType": "string"},
        {"ContextKeyName": "aws:SecureTransport", "ContextKeyValues": ["true"], "ContextKeyType": "boolean"},
    ]
    if ctx.org_id:
        out.append(
            {"ContextKeyName": "aws:PrincipalOrgID", "ContextKeyValues": [ctx.org_id], "ContextKeyType": "string"}
        )
    if region and region != "global":
        out.append({"ContextKeyName": "aws:RequestedRegion", "ContextKeyValues": [region], "ContextKeyType": "string"})
    if principal["kind"] == "user":
        out.append(
            {"ContextKeyName": "aws:MultiFactorAuthPresent", "ContextKeyValues": ["false"], "ContextKeyType": "boolean"}
        )
    return out


def judge(result: dict) -> tuple[str, str]:
    """(decision, why) from one simulator result: allowed, network (it depends on where the call comes
    from), depends (on other context the simulator was not given), or blocked."""
    decision = (
        result["EvalResourceDecision"] if "EvalResourceDecision" in result else result.get("EvalDecision")
    ) or ""
    missing = {k.lower() for k in result.get("MissingContextValues") or []}
    org = (result.get("OrganizationsDecisionDetail") or {}).get("AllowedByOrganizations", True)
    pb = (result.get("PermissionsBoundaryDecisionDetail") or {}).get("AllowedByPermissionsBoundary", True)
    via = ", ".join(
        sorted(
            {
                m.get("SourcePolicyId") or m.get("SourcePolicyType", "")
                for m in result.get("MatchedStatements") or []
                if m
            }
        )
    )[:120]
    if missing & NETWORK_KEYS:
        return "network", f"only from certain addresses or VPC endpoints ({', '.join(sorted(missing & NETWORK_KEYS))})"
    if decision == "allowed":
        if missing:
            return "depends", f"depends on {', '.join(sorted(missing))[:80]}"
        return "allowed", via
    if not org:
        return "blocked", "an organisation guardrail (SCP) denies it"
    if not pb:
        return "blocked", "the permission boundary does not allow it"
    if decision == "explicitDeny":
        return "blocked", f"denied by {via or 'a policy'}"
    return "blocked", "no policy allows it"


def _simulate(
    ctx: CompromiseCtx,
    principal: dict,
    actions: list[str],
    resources: list[str],
    policy: dict | None = None,
    region: str | None = None,
) -> list[dict]:
    iam = ctx.client("iam")
    kwargs = {
        "PolicySourceArn": principal["arn"],
        "ActionNames": actions,
        "ResourceArns": resources,
        "ContextEntries": _context(ctx, principal, region),
    }
    if policy:
        kwargs["ResourcePolicy"] = json.dumps(policy)
        kwargs["ResourceOwner"] = f"arn:aws:iam::{ctx.account_id}:root"
    out = []
    marker = None
    while True:
        page = with_backoff(iam.simulate_principal_policy, **kwargs, **({"Marker": marker} if marker else {}))
        for r in page.get("EvaluationResults") or []:
            specific = r.get("ResourceSpecificResults") or []
            if specific and len(resources) > 1:
                for s in specific:
                    merged = {
                        **r,
                        **s,
                        "MatchedStatements": s.get("MatchedStatements") or r.get("MatchedStatements"),
                        "MissingContextValues": s.get("MissingContextValues") or r.get("MissingContextValues"),
                    }
                    d, why = judge(merged)
                    out.append(
                        {
                            "action": r["EvalActionName"],
                            "resource": s.get("EvalResourceName"),
                            "decision": d,
                            "why": why,
                        }
                    )
            else:
                d, why = judge(r)
                out.append(
                    {
                        "action": r["EvalActionName"],
                        "resource": r.get("EvalResourceName") or resources[0],
                        "decision": d,
                        "why": why,
                    }
                )
        if not page.get("IsTruncated"):
            return out
        marker = page["Marker"]


RANK = {"allowed": 0, "depends": 1, "network": 2, "blocked": 3}


def task_simulate(ctx: CompromiseCtx) -> None:
    """Each principal against each target, by the simulator. A principal with no Allow statement that could
    cover an action is not asked: with nothing allowing it, the answer is no."""
    blind = {
        "id": "account:blind",
        "kind": "account",
        "name": "audit trail, threat detection and alerts",
        "region": "global",
        "arn": "*",
        "payment": False,
        "facts": {},
    }
    ctx.assets.append(blind)
    targets = list(ctx.targets)
    # On the real trail, detector and rules, so a guardrail that names them is weighed; an organisation
    # trail is owned by the management account and cannot be changed from here at all.
    for t in ctx.detect["trails"]:
        if t.get("own") and t.get("arn"):
            targets.append(
                {
                    "asset": blind["id"],
                    "action": "blind_trail",
                    "resource": t["arn"],
                    "policy": None,
                    "region": t.get("home") or ctx.home,
                }
            )
    for region, g in ctx.detect["guardduty"].items():
        if g.get("arn"):
            targets.append(
                {"asset": blind["id"], "action": "blind_gd", "resource": g["arn"], "policy": None, "region": region}
            )
    for r in ctx.detect["rules"][:20]:
        if r.get("arn"):
            targets.append(
                {
                    "asset": blind["id"],
                    "action": "blind_alerts",
                    "resource": r["arn"],
                    "policy": None,
                    "region": r["region"],
                }
            )
    # One call per principal covers every resource that is asked the same calls in the same region, so a
    # function's code and settings, or a bucket's writes, are one call rather than several.
    jobs = []
    for p in ctx.principals:
        per_res: dict[tuple, dict] = {}
        for t in targets:
            calls = [a for a in ACTIONS[t["action"]][1] if may_allow(p["docs"], a)]
            if not calls:
                continue
            key = (t["resource"], t["region"], json.dumps(t["policy"], sort_keys=True) if t["policy"] else "")
            entry = per_res.setdefault(
                key, {"resource": t["resource"], "region": t["region"], "policy": t["policy"], "calls": {}}
            )
            for c in calls:
                entry["calls"][c] = t
        groups: dict[tuple, list[dict]] = {}
        for e in per_res.values():
            if e["policy"]:
                jobs.append((p, [e], e["policy"]))
            else:
                groups.setdefault((e["region"], tuple(sorted(e["calls"]))), []).append(e)
        for items in groups.values():
            for at in range(0, len(items), SIM_CHUNK):
                jobs.append((p, items[at : at + SIM_CHUNK], None))

    def run(job):
        p, items, policy = job
        actions = sorted({c for e in items for c in e["calls"]})
        by_res = {e["resource"]: e for e in items}
        got = _simulate(ctx, p, actions, list(by_res), policy, items[0]["region"])
        best: dict[tuple, dict] = {}
        for g in got:
            e = by_res.get(g["resource"]) or (items[0] if len(items) == 1 else None)
            t = e and e["calls"].get(g["action"])
            if not t:
                continue
            k = (t["asset"], t["action"])
            cur = best.get(k)
            if not cur or RANK[g["decision"]] < RANK[cur["decision"]]:
                best[k] = {**g, "target": t}
        for (asset_id, _), g in best.items():
            if g["decision"] == "blocked" and g["why"] == "no policy allows it":
                continue
            with ctx._lock:
                ctx.paths.append(
                    {
                        "principal": p["label"],
                        "kind": p["kind"],
                        "asset": asset_id,
                        "action": g["target"]["action"],
                        "call": g["action"],
                        "decision": g["decision"],
                        "why": g["why"],
                    }
                )

    with ThreadPoolExecutor(max_workers=6) as pool:  # IAM throttles: a few calls at a time
        list(pool.map(lambda j: contextvars.copy_context().run(run, j), jobs))
    ctx.r.fact("simulated", len(jobs))
    ctx.r.ok("access")


# ------------------------------------------------------------------------------------------- running
GLOBAL_TASKS = [
    ("identities", ("identities",), task_identities, None),
    ("buckets", ("buckets",), task_buckets, None),
    ("trails", ("trails",), task_trails, None),
]
REGION_TASKS = [
    ("dynamodb", ("dynamodb",), task_dynamodb, None),
    ("databases", ("databases",), task_databases, None),
    ("functions", ("functions",), task_functions, None),
    ("containers", ("containers",), task_containers, None),
    ("secrets and keys", ("secrets",), task_secrets_and_keys, None),
    ("apis", ("apis",), task_apis, None),
    ("detection", ("detection",), task_detection, None),
    ("changes by people", ("changes",), task_changes, None),
]


def account_checks(
    session: boto3.Session, account_id: str, regions: list[str] | None, info: dict | None = None
) -> tuple[dict, list[Issue]]:
    """Return ({principals, assets, paths, exposures, changes, detect, checks, facts, ...}, issues)."""
    from .inventory import enabled_regions

    started = time.monotonic()
    session = ClientCache(session)
    try:
        region_list = enabled_regions(session, regions)
    except (ClientError, BotoCoreError) as exc:
        code, msg, hint = describe_exception(exc)
        return {}, [
            Issue("error", "compromise", f"could not list regions: {msg}", hint, account_id=account_id, error_code=code)
        ]
    if regions:
        region_list = [r for r in regions if r in region_list]
    ctx = CompromiseCtx(session, account_id, region_list, info or {})
    jobs = [(t, None) for t in GLOBAL_TASKS] + [(t, r) for r in region_list for t in REGION_TASKS]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for fut in [pool.submit(contextvars.copy_context().run, _run, ctx, t, r) for t, r in jobs]:
            fut.result()
    if ctx.principals:
        _run(ctx, ("simulate access", ("access",), task_simulate, None), None)
    else:
        ctx.r.unknown("access", "the principals could not be read")
    people = {
        p["name"]: p["label"]
        for p in ctx.principals
        if p["kind"] in ("cross", "person") or (p.get("reached_by") and p["kind"] != "outside")
    }
    changes = []
    for c in ctx.changes.values():
        if c["who"].startswith("role:"):
            role = c["who"][5:].rstrip("@")
            if role not in people and not c["who"].endswith("@"):
                continue  # a pipeline or a workload: not a change by hand
            c = {**c, "who": people.get(role, f"role {role} (a person's session)")}
        changes.append(c)
    out = {
        "principals": [{k: v for k, v in p.items() if k not in ("docs", "trusts")} for p in ctx.principals],
        "assets": ctx.assets,
        "paths": ctx.paths,
        "exposures": ctx.exposures,
        "changes": [{**c, "ips": sorted(c["ips"])} for c in sorted(changes, key=lambda c: -c["count"])],
        "detect": ctx.detect,
        "checks": ctx.r.finish(),
        "facts": ctx.r.facts,
        "regions": region_list,
        "read_at": ctx.now.isoformat(timespec="seconds"),
        "seconds": round(time.monotonic() - started, 1),
    }
    out["counts"] = dict(Counter(a["kind"] for a in ctx.assets))
    return out, _collapse(ctx.issues)
