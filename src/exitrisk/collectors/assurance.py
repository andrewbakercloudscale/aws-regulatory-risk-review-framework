"""Cloud Assurance Framework checks inside one member account (the "assurance" scan).

Every check in data/assurance.yaml that is read from the account itself is evaluated here, in one
of four states: pass, fail, unknown (the call was refused or failed, so it was not measured) or na
(nothing to check, for example no RDS billed in the account). A refused call is never read as a pass.

Checks that depend on the answers given in the report (which accounts are production or internet
edge, which buckets hold sensitive data) are judged later, in report/assurance.py, from the facts kept
here: the bucket list with its controls, who can write to each bucket, and so on. Changing an answer
then needs no new scan.

Everything is read-only and nothing is stored but counts, names and settings: no object, log line
or secret value is read. The one exception to "list and describe" is iam:GenerateCredentialReport,
which asks IAM to build the account's credential report (a read-only summary) before reading it.
"""

from __future__ import annotations

import contextvars
import csv
import fnmatch
import io
import json
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from urllib.parse import unquote

import boto3
import yaml
from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import BOTO_CONFIG, ClientCache
from ..issues import Issue, describe_exception
from ..logging_config import get_logger
from . import baseline

log = get_logger("assurance")

# Calls in flight at once inside one account: as for the inventory, the time goes on round trips.
WORKERS = 16
EVIDENCE = 25  # resource names kept per check; the count is kept in full
MAX_BUCKETS = 1000
MAX_ITEMS = 500  # tables, keys, functions... read per region before stopping
FINDING_PAGES = 5  # pages of findings counted per query (100 each)
TRAIL_PAGES = 6  # pages of CloudTrail write events sampled per region (50 each)
OLD_DAYS, UNUSED_DAYS, ROOT_DAYS, TEST_DAYS, CHANGE_DAYS = 90, 45, 90, 90, 7
PATCH_DAYS, AMI_DAYS, CERT_DAYS, BACKUP_DAYS = 30, 180, 30, 7
MAX_LBS = 200  # load balancers whose listeners and attributes are read per region

ADMIN_PORTS = (22, 3389)
DB_PORTS = (1433, 1521, 2483, 3306, 5432, 5439, 6379, 7000, 7001, 9042, 9200, 9300, 11211, 27017, 27018, 50000)
OPEN_CIDRS = ("0.0.0.0/0", "::/0")
WRITE_ACTIONS = ("s3:PutObject", "s3:DeleteObject")
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
SUPPORT_ARN = "arn:aws:iam::aws:policy/AWSSupportAccess"
# Instance families AWS calls previous generation.
OLD_FAMILIES = {"t1", "t2", "m1", "m2", "m3", "m4", "c1", "c3", "c4", "r3", "r4", "i2", "d2", "g2", "g3", "p2", "x1",
                "cc2", "cr1", "hs1"}  # fmt: skip
# Load balancer security policies that still accept TLS 1.0 or 1.1.
OLD_TLS = ("ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-FS-2018-06")
OLD_TLS_MARKS = ("TLS-1-0", "TLS-1-1", "TLS13-1-0", "TLS13-1-1", "FS-1-1")
# Events a security team is expected to be alerted on (CIS section 4), as they appear in an
# EventBridge pattern or a CloudWatch Logs metric filter.
ALERT_MARKS = ("root", "consolelogin", "aws.iam", "iam.amazonaws.com", "aws.cloudtrail", "cloudtrail.amazonaws.com",
               "stoplogging", "deletetrail", "putuserpolicy", "attachrolepolicy", "createaccesskey")  # fmt: skip
# Bucket tag keys that carry a data classification, compared lowercased with letters only.
CLASSIFICATION_KEYS = ("classification", "dataclassification", "confidentiality", "datasensitivity", "sensitivity")
# Services whose spend means the account holds data worth backing up.
STATEFUL_SERVICES = (
    "Amazon Relational Database Service",
    "Amazon DynamoDB",
    "Amazon Elastic File System",
    "Amazon FSx",
    "Amazon DocumentDB (with MongoDB compatibility)",
    "Amazon Neptune",
    "EC2 - Other",
)
# Write events that are sign-in or session plumbing, not a change to the account.
NOT_CHANGES = {
    "ConsoleLogin", "CheckMfa", "GetSigninToken", "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
    "StartSession", "ResumeSession", "TerminateSession", "SendSSHPublicKey", "CreateSession", "SwitchRole",
    "ExitRole", "RenewRole", "Federate", "Logout", "GetRoleCredentials", "CredentialChallenge",
    "CredentialVerification", "UserAuthentication", "StartQuery", "StopQuery", "StartQueryExecution",
    "CreateEnvironment", "CreateSavedObject", "PutCredentials", "GetSessionToken",
}  # fmt: skip
NOT_CHANGE_SOURCES = ("signin.", "sso.", "sts.", "cloudshell.", "athena.", "health.", "support.", "notifications.")


@lru_cache(maxsize=1)
def lifecycle_data() -> dict:
    raw = yaml.safe_load(resources.files("exitrisk").joinpath("data/assurance.yaml").read_text(encoding="utf-8"))
    day = lambda v: v if isinstance(v, date) else date.fromisoformat(str(v))  # noqa: E731
    return {
        "lambda": {k: day(v) for k, v in (raw.get("lambda_deprecated") or {}).items()},
        "eks": {str(k): day(v) for k, v in (raw.get("eks_end_of_standard_support") or {}).items()},
        "rds": {str(k): day(v) for k, v in (raw.get("rds_end_of_standard_support") or {}).items()},
    }


class Results:
    """One account's checks as they come in from many threads. A check fails if anything fails it,
    passes if every region measured passes it, and is unknown only if nothing measured it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._c: dict[str, dict] = {}
        self.facts: dict = {}

    def _get(self, cid: str) -> dict:
        return self._c.setdefault(cid, {"fail": 0, "pass": 0, "unknown": [], "na": "", "ev": []})

    def ok(self, cid: str) -> None:
        with self._lock:
            self._get(cid)["pass"] += 1

    def fail(self, cid: str, items: list[str]) -> None:
        """Fail ``cid`` for ``items`` (resource names; the count is len(items)). No items is a pass."""
        if not items:
            self.ok(cid)
            return
        with self._lock:
            c = self._get(cid)
            c["fail"] += len(items)
            room = EVIDENCE - len(c["ev"])
            if room > 0:
                c["ev"].extend(str(i) for i in items[:room])

    def unknown(self, cid: str, why: str) -> None:
        with self._lock:
            c = self._get(cid)
            if why not in c["unknown"] and len(c["unknown"]) < 5:
                c["unknown"].append(why)

    def na(self, cid: str, why: str) -> None:
        with self._lock:
            self._get(cid)["na"] = self._get(cid)["na"] or why

    def fact(self, key: str, value, region: str | None = None) -> None:
        with self._lock:
            if region is None:
                self.facts[key] = value
            else:
                self.facts.setdefault(key, {})[region] = value

    def finish(self) -> dict:
        out = {}
        for cid, c in self._c.items():
            partial = f"not measured in part: {'; '.join(c['unknown'])}" if c["unknown"] else ""
            if c["fail"]:
                out[cid] = {"status": "fail", "n": c["fail"], "ev": c["ev"], "note": partial}
            elif c["pass"]:
                out[cid] = {"status": "pass", "note": partial}
            elif c["unknown"]:
                out[cid] = {"status": "unknown", "note": "; ".join(c["unknown"])}
            else:
                out[cid] = {"status": "na", "note": c["na"]}
        return out


class Ctx:
    """What every task of one account shares."""

    def __init__(self, session, account_id: str, regions: list[str], info: dict):
        self.session = session
        self.account_id = account_id
        self.regions = regions
        self.home = regions[0] if regions else "us-east-1"
        self.r = Results()
        self.org_ids = set(info.get("org_ids") or [])
        services = info.get("services")
        self.services = set(services) if services is not None else None  # None: spend unknown, read everything
        self.ta_org = bool(info.get("ta_org"))
        self.issues: list[Issue] = []
        self._lock = threading.Lock()
        self.now = datetime.now(timezone.utc)
        self.humans: list[tuple[str, list[dict]]] | None = None  # (who, policies) set by the IAM task
        self.admin_roles: set[str] | None = None  # role ARNs with full administrator rights
        self.admin_profiles: set[str] = set()  # instance profile ARNs of those roles

    def client(self, name: str, region: str = "us-east-1"):
        return self.session.client(name, region_name=region, config=BOTO_CONFIG)

    def billed(self, *services: str) -> bool:
        return self.services is None or any(s in self.services for s in services)

    def issue(self, issue: Issue) -> None:
        with self._lock:
            self.issues.append(issue)


def _pages(client, op: str, key: str, cap: int | None = None, **kwargs) -> list:
    """Every item under ``key`` across the pages of ``op``, stopping after ``cap`` items."""
    out: list = []
    if client.can_paginate(op):
        for page in client.get_paginator(op).paginate(**kwargs):
            out.extend(page.get(key) or [])
            if cap and len(out) >= cap:
                return out[:cap]
        return out
    return list(getattr(client, op)(**kwargs).get(key) or [])[:cap]


def _code(exc: Exception) -> str:
    return exc.response.get("Error", {}).get("Code", "") if isinstance(exc, ClientError) else type(exc).__name__


def _age_days(when, now: datetime) -> float | None:
    if isinstance(when, str):
        if not when or when[0] not in "0123456789":
            return None  # "N/A", "no_information", "not_supported"
        when = datetime.fromisoformat(when.replace("Z", "+00:00"))
    if not isinstance(when, datetime):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (now - when).total_seconds() / 86400


# ---------------------------------------------------------------------------------- policy reading


def _doc(raw) -> dict:
    if isinstance(raw, str):
        return json.loads(unquote(raw))
    return raw or {}


def _listify(v) -> list:
    return v if isinstance(v, list) else [v] if v else []


def _like(patterns: list, value: str, fold: bool) -> bool:
    for p in patterns:
        p = str(p).replace("[", "[[]")
        if fnmatch.fnmatchcase(value.lower() if fold else value, p.lower() if fold else p):
            return True
    return False


def _covers(st: dict, action: str, resource: str) -> bool:
    if "Action" in st:
        a_ok = _like(_listify(st["Action"]), action, True)
    else:
        a_ok = "NotAction" in st and not _like(_listify(st["NotAction"]), action, True)
    if "Resource" in st:
        r_ok = _like(_listify(st["Resource"]), resource, False)
    else:
        r_ok = "NotResource" in st and not _like(_listify(st["NotResource"]), resource, False)
    return a_ok and r_ok


def allows(docs: list[dict], action: str, resource: str) -> bool:
    """True when the identity policies allow ``action`` on ``resource``. Conditions are not evaluated:
    an Allow with a condition counts as allowed, a Deny with one does not count (both lean towards
    reporting access that may exist)."""
    allowed = False
    for doc in docs:
        for st in _listify(doc.get("Statement")):
            if not isinstance(st, dict) or not _covers(st, action, resource):
                continue
            if st.get("Effect") == "Deny" and not st.get("Condition"):
                return False
            if st.get("Effect") == "Allow":
                allowed = True
    return allowed


def is_admin(doc: dict) -> bool:
    """An Allow of every action on every resource."""
    for st in _listify(doc.get("Statement")):
        if isinstance(st, dict) and st.get("Effect") == "Allow" and not st.get("Condition"):
            if "*" in _listify(st.get("Action")) and "*" in _listify(st.get("Resource")):
                return True
    return False


def _trusted_accounts(doc: dict) -> list[tuple[str, bool]]:
    """(account id or "*", has external id) for each AWS principal an assume-role policy trusts."""
    out = []
    for st in _listify(doc.get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal")
        aws = (
            ["*"] if principal == "*" else _listify((principal or {}).get("AWS")) if isinstance(principal, dict) else []
        )
        cond = json.dumps(st.get("Condition") or {}).lower()
        external_id = "sts:externalid" in cond
        org_bound = "aws:principalorgid" in cond or "aws:principalorgpaths" in cond
        for p in aws:
            p = str(p)
            acct = "*" if p == "*" else p.split(":")[4] if p.startswith("arn:") and len(p.split(":")) > 4 else p
            if not org_bound:
                out.append((acct, external_id))
    return out


def _human_role(role: dict) -> bool:
    """A role people sign in to: an IAM Identity Center permission set or a SAML-federated role."""
    if role.get("RoleName", "").startswith("AWSReservedSSO_"):
        return True
    trust = _doc(role.get("AssumeRolePolicyDocument"))
    return "saml-provider" in json.dumps(trust) or "sts:AssumeRoleWithSAML" in json.dumps(trust)


def _sso_label(name: str) -> str:
    """AWSReservedSSO_PaymentsAdmin_0123456789abcdef -> permission set PaymentsAdmin."""
    if name.startswith("AWSReservedSSO_"):
        return "permission set " + name[len("AWSReservedSSO_") :].rsplit("_", 1)[0]
    return "role " + name


# ---------------------------------------------------------------------------------- global tasks


def _credential_report(iam) -> list[dict]:
    deadline = time.monotonic() + 40
    while iam.generate_credential_report().get("State") != "COMPLETE":
        if time.monotonic() > deadline:
            raise TimeoutError("the IAM credential report was not ready after 40 s")
        time.sleep(2)
    content = iam.get_credential_report()["Content"]
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    return list(csv.DictReader(io.StringIO(text)))


def task_iam(ctx: Ctx) -> None:
    r, now = ctx.r, ctx.now
    iam = ctx.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    r.fail("root_mfa", [] if summary.get("AccountMFAEnabled") == 1 else ["root user"])
    r.fail("root_keys", ["root user"] if summary.get("AccountAccessKeysPresent", 0) else [])
    r.fact("iam_users", summary.get("Users", 0))

    rows = _credential_report(iam)
    root_used, no_mfa, old_keys, unused, users = [], [], [], [], []
    for row in rows:
        name = row.get("user", "")
        if name == "<root_account>":
            for field in ("password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date"):
                age = _age_days(row.get(field, ""), now)
                if age is not None and age <= ROOT_DAYS:
                    root_used.append(f"root used {row[field][:10]}")
                    break
            continue
        password = row.get("password_enabled") == "true"
        keys = [i for i in ("1", "2") if row.get(f"access_key_{i}_active") == "true"]
        if password or keys:
            users.append(name)
        if password and row.get("mfa_active") != "true":
            no_mfa.append(name)
        created = _age_days(row.get("user_creation_time", ""), now) or 0
        if password:
            last = _age_days(row.get("password_last_used", ""), now)
            if (last if last is not None else created) >= UNUSED_DAYS:
                unused.append(f"{name} (password)")
        for i in keys:
            rotated = _age_days(row.get(f"access_key_{i}_last_rotated", ""), now)
            if rotated is not None and rotated > OLD_DAYS:
                old_keys.append(f"{name} key {i} ({int(rotated)} days)")
            used = _age_days(row.get(f"access_key_{i}_last_used_date", ""), now)
            if (used if used is not None else rotated or 0) >= UNUSED_DAYS:
                unused.append(f"{name} key {i}")
    r.fail("root_used", root_used)
    r.fail("console_no_mfa", no_mfa)
    r.fail("keys_old", old_keys)
    r.fail("creds_unused", unused)
    r.fail("iam_users", users)
    if any(row.get("password_enabled") == "true" for row in rows if row.get("user") != "<root_account>"):
        try:
            pol = iam.get_account_password_policy()["PasswordPolicy"]
            weak = []
            if pol.get("MinimumPasswordLength", 0) < 14:
                weak.append(f"minimum length {pol.get('MinimumPasswordLength', 0)}")
            if pol.get("PasswordReusePrevention", 0) < 24:
                weak.append(f"reuse prevention {pol.get('PasswordReusePrevention', 0)}")
            r.fail("password_policy", weak)
        except ClientError as exc:
            if _code(exc) != "NoSuchEntity":
                raise
            r.fail("password_policy", ["no password policy"])
    else:
        r.na("password_policy", "no IAM user signs in with a password")

    details = {"UserDetailList": [], "RoleDetailList": [], "GroupDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate(
        Filter=["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]
    ):
        for k in details:
            details[k].extend(page.get(k) or [])
    _authorization(ctx, details)


def _authorization(ctx: Ctx, d: dict) -> None:
    r, now = ctx.r, ctx.now
    policies: dict[str, dict] = {}
    local_admin = []
    for p in d["Policies"]:
        version = next((v for v in p.get("PolicyVersionList") or [] if v.get("IsDefaultVersion")), None)
        doc = _doc(version.get("Document")) if version else {}
        policies[p["Arn"]] = doc
        if ":aws:policy/" not in p["Arn"] and p.get("AttachmentCount", 0) and is_admin(doc):
            local_admin.append(p["PolicyName"])

    def docs_of(entity: dict, inline_key: str) -> list[dict]:
        out = [policies.get(a["PolicyArn"], {}) for a in entity.get("AttachedManagedPolicies") or []]
        out += [_doc(i.get("PolicyDocument")) for i in entity.get(inline_key) or []]
        return out

    groups = {g["GroupName"]: docs_of(g, "GroupPolicyList") for g in d["GroupDetailList"]}
    inline_admin, direct, admins, humans = [], [], [], []
    for u in d["UserDetailList"]:
        own = docs_of(u, "UserPolicyList")
        if u.get("AttachedManagedPolicies") or u.get("UserPolicyList"):
            direct.append(u["UserName"])
        if any(is_admin(_doc(i.get("PolicyDocument"))) for i in u.get("UserPolicyList") or []):
            inline_admin.append(f"user {u['UserName']} (inline)")
        all_docs = own + [doc for g in u.get("GroupList") or [] for doc in groups.get(g, [])]
        if any(is_admin(x) for x in all_docs):
            admins.append(f"IAM user {u['UserName']}")
        humans.append((f"IAM user {u['UserName']}", all_docs))

    external, vendors, unused, support = [], [], [], []
    admin_roles, admin_profiles = set(), set()
    for role in d["RoleDetailList"]:
        name, path = role["RoleName"], role.get("Path", "/")
        role_docs = docs_of(role, "RolePolicyList")
        attached = {a["PolicyArn"] for a in role.get("AttachedManagedPolicies") or []}
        if SUPPORT_ARN in attached:
            support.append(name)
        if ADMIN_ARN in attached or any(is_admin(x) for x in role_docs):
            admin_roles.add(role["Arn"])
            admin_profiles.update(p["Arn"] for p in role.get("InstanceProfileList") or [])
        service_linked = path.startswith("/aws-service-role/")
        if not name.startswith("AWSReservedSSO_") and not service_linked:
            if any(is_admin(_doc(i.get("PolicyDocument"))) for i in role.get("RolePolicyList") or []):
                inline_admin.append(f"role {name} (inline)")
        if _human_role(role):
            humans.append((_sso_label(name), role_docs))
            if role["Arn"] in admin_roles:
                admins.append(_sso_label(name))
        for acct, external_id in _trusted_accounts(_doc(role.get("AssumeRolePolicyDocument"))):
            if acct == ctx.account_id or acct in ctx.org_ids:
                continue
            if acct == "*" or not external_id:
                external.append(f"{name} trusts {'anyone' if acct == '*' else acct}")
            else:
                vendors.append(f"{name} ({acct})")
        if service_linked or name.startswith("AWSReservedSSO_") or baseline.is_baseline(name):
            continue
        last = _age_days((role.get("RoleLastUsed") or {}).get("LastUsedDate"), now)
        created = _age_days(role.get("CreateDate"), now) or 0
        if (last if last is not None else created) >= OLD_DAYS:
            unused.append(name)
    r.fail("admin_policy", local_admin + inline_admin)
    r.fail("user_direct_policies", direct)
    r.fail("external_trust", sorted(set(external)))
    r.fail("vendor_roles", sorted(set(vendors)))
    r.fail("roles_unused", unused)
    groups_support = [
        g["GroupName"]
        for g in d["GroupDetailList"]
        if any(a["PolicyArn"] == SUPPORT_ARN for a in g.get("AttachedManagedPolicies") or [])
    ]
    r.fail("support_role", [] if support or groups_support else ["no role with AWSSupportAccess"])
    r.fact("iam_admins", sorted(set(admins)))
    ctx.humans = humans  # read by the bucket writers check at the end
    ctx.admin_roles, ctx.admin_profiles = admin_roles, admin_profiles  # read by workload_admin


def task_s3(ctx: Ctx) -> None:
    r = ctx.r
    s3c = ctx.client("s3control")
    try:
        cfg = s3c.get_public_access_block(AccountId=ctx.account_id)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if _code(exc) != "NoSuchPublicAccessBlockConfiguration":
            raise
        cfg = {}
    keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    account_block = all(cfg.get(k) for k in keys)
    r.fail("s3_account_bpa", [] if account_block else [f"off: {', '.join(k for k in keys if not cfg.get(k))}"])

    s3 = ctx.client("s3")
    buckets = _pages(s3, "list_buckets", "Buckets", cap=MAX_BUCKETS)
    if len(buckets) >= MAX_BUCKETS:
        for cid in ("s3_public_bucket", "s3_versioning_off"):
            r.unknown(cid, f"only the first {MAX_BUCKETS} buckets were read")

    def one(b: dict) -> dict:
        name = b["Name"]
        region = b.get("BucketRegion") or "us-east-1"
        c = ctx.client("s3", region)
        out = {"name": name, "region": region}

        def read(key: str, call: Callable, missing: tuple = ()):
            try:
                out[key] = call()
            except ClientError as exc:
                out[key] = False if _code(exc) in missing else None
            except BotoCoreError:
                out[key] = None

        read("versioning", lambda: c.get_bucket_versioning(Bucket=name).get("Status") == "Enabled")
        read(
            "lock",
            lambda: (
                c.get_object_lock_configuration(Bucket=name).get("ObjectLockConfiguration", {}).get("ObjectLockEnabled")
                == "Enabled"
            ),
            ("ObjectLockConfigurationNotFoundError",),
        )
        read(
            "replicated",
            lambda: any(
                rule.get("Status") == "Enabled"
                for rule in c.get_bucket_replication(Bucket=name).get("ReplicationConfiguration", {}).get("Rules", [])
            ),
            ("ReplicationConfigurationNotFoundError",),
        )
        read(
            "tags",
            lambda: {
                t["Key"]: t["Value"]
                for t in c.get_bucket_tagging(Bucket=name).get("TagSet", [])
                if "".join(ch for ch in t["Key"].lower() if ch.isalpha()) in CLASSIFICATION_KEYS
            },
            ("NoSuchTagSet",),
        )
        read(
            "tls_only",
            lambda: _denies_plain_http(c.get_bucket_policy(Bucket=name).get("Policy")),
            ("NoSuchBucketPolicy",),
        )
        read(
            "acls",
            lambda: all(
                rule.get("ObjectOwnership") != "BucketOwnerEnforced"
                for rule in c.get_bucket_ownership_controls(Bucket=name)["OwnershipControls"].get("Rules", [])
            ),
            ("OwnershipControlsNotFoundError",),
        )
        read(
            "kms",
            lambda: any(
                (rule.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm", "").startswith("aws:kms")
                for rule in c.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"].get("Rules", [])
            ),
            ("ServerSideEncryptionConfigurationNotFoundError",),
        )
        if account_block:
            out["public"] = False
        else:
            read(
                "bucket_block",
                lambda: all(
                    c.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"].get(k)
                    for k in ("BlockPublicPolicy", "RestrictPublicBuckets")
                ),
                ("NoSuchPublicAccessBlockConfiguration",),
            )
            if out.get("bucket_block"):
                out["public"] = False
            else:
                read(
                    "public",
                    lambda: c.get_bucket_policy_status(Bucket=name)["PolicyStatus"].get("IsPublic", False),
                    ("NoSuchBucketPolicy",),
                )
            out.pop("bucket_block", None)
        if out.get("tags") is False:
            out["tags"] = {}
        return out

    with ThreadPoolExecutor(max_workers=8) as pool:
        details = list(pool.map(contextvars.copy_context().run, [one] * len(buckets), buckets)) if buckets else []
    measured = [b for b in details if b.get("public") is not None]
    if details and not measured:
        r.unknown("s3_public_bucket", "bucket policy status refused")
    else:
        r.fail("s3_public_bucket", [b["name"] for b in details if b.get("public")])
    versioned = [b for b in details if b.get("versioning") is not None]
    if details and not versioned:
        r.unknown("s3_versioning_off", "bucket versioning refused")
    else:
        r.fail("s3_versioning_off", [b["name"] for b in versioned if not b["versioning"]])
    for cid, key, bad in (("s3_tls_only", "tls_only", False), ("s3_acls", "acls", True)):
        read_ok = [b for b in details if b.get(key) is not None]
        if details and not read_ok:
            r.unknown(cid, f"bucket {key.replace('_', ' ')} refused")
        else:
            r.fail(cid, [b["name"] for b in read_ok if b[key] is bad])
    r.fact("buckets", details)


def _denies_plain_http(policy: str | None) -> bool:
    """True when the bucket policy denies requests made without TLS (aws:SecureTransport false)."""
    for st in _listify(_doc(policy).get("Statement")):
        if isinstance(st, dict) and st.get("Effect") == "Deny":
            cond = json.dumps(st.get("Condition") or {}).lower()
            if "aws:securetransport" in cond and "false" in cond:
                return True
    return False


def task_cloudtrail(ctx: Ctx) -> None:
    r = ctx.r
    trails = ctx.client("cloudtrail", ctx.home).describe_trails(includeShadowTrails=True).get("trailList", [])
    multi = [t for t in trails if t.get("IsMultiRegionTrail")]
    logging_on, cover = [], []
    for t in multi:
        home = t.get("HomeRegion") or ctx.home
        c = ctx.client("cloudtrail", home)
        try:
            logging_on.append(bool(c.get_trail_status(Name=t["TrailARN"]).get("IsLogging")))
        except (ClientError, BotoCoreError):
            logging_on.append(None)  # an organisation trail's status is read in the management account
        try:
            cover.append(s3_write_cover(c.get_event_selectors(TrailName=t["TrailARN"])))
        except (ClientError, BotoCoreError):
            cover.append(None)
    if not multi:
        r.fail("cloudtrail_off", ["no multi-region trail"])
    elif any(logging_on):
        r.ok("cloudtrail_off")
    elif all(x is False for x in logging_on):
        r.fail("cloudtrail_off", [f"{t['Name']} is not logging" for t in multi])
    else:
        r.ok("cloudtrail_off")  # present; logging read from the management account
    r.fail(
        "cloudtrail_validation",
        [] if any(t.get("LogFileValidationEnabled") for t in multi) else ["off"] if multi else ["no trail"],
    )
    r.fail(
        "cloudtrail_kms",
        [] if any(t.get("KmsKeyId") for t in multi) else ["not encrypted with KMS"] if multi else ["no trail"],
    )
    r.fail(
        "cloudtrail_cwl",
        []
        if any(t.get("CloudWatchLogsLogGroupArn") for t in multi)
        else ["not sent to CloudWatch Logs"]
        if multi
        else ["no trail"],
    )
    r.fact(
        "trails",
        [
            {
                "name": t.get("Name"),
                "org": bool(t.get("IsOrganizationTrail")),
                "home": t.get("HomeRegion"),
                "s3_writes": cv,
            }
            for t, cv in zip(multi, cover, strict=True)
        ],
    )


def s3_write_cover(selectors: dict) -> dict:
    """Which S3 object writes a trail logs as data events: {"all": bool, "prefixes": [ARN prefixes]}."""
    out = {"all": False, "prefixes": []}
    for sel in selectors.get("EventSelectors") or []:
        if sel.get("ReadWriteType") not in ("All", "WriteOnly"):
            continue
        for dr in sel.get("DataResources") or []:
            if dr.get("Type") != "AWS::S3::Object":
                continue
            for v in dr.get("Values") or []:
                if v in ("arn:aws:s3", "arn:aws:s3:::"):
                    out["all"] = True
                else:
                    out["prefixes"].append(v)
    for sel in selectors.get("AdvancedEventSelectors") or []:
        fields = {f.get("Field"): f for f in sel.get("FieldSelectors") or []}
        if "Data" not in (fields.get("eventCategory") or {}).get("Equals", []):
            continue
        if "AWS::S3::Object" not in (fields.get("resources.type") or {}).get("Equals", []):
            continue
        if "true" in (fields.get("readOnly") or {}).get("Equals", []):
            continue
        arn = fields.get("resources.ARN")
        if not arn:
            out["all"] = True
        else:
            out["prefixes"].extend(arn.get("StartsWith", []) + arn.get("Equals", []))
    return out


def task_contact(ctx: Ctx) -> None:
    c = ctx.client("account")
    for kind, cid in (("SECURITY", "security_contact"), ("BILLING", "billing_contact"),
                      ("OPERATIONS", "operations_contact")):  # fmt: skip
        try:
            c.get_alternate_contact(AlternateContactType=kind)
            ctx.r.ok(cid)
        except ClientError as exc:
            if _code(exc) != "ResourceNotFoundException":
                raise
            ctx.r.fail(cid, [f"no {kind.lower()} contact"])


def task_budgets(ctx: Ctx) -> None:
    try:
        budgets = _pages(ctx.client("budgets"), "describe_budgets", "Budgets", cap=50, AccountId=ctx.account_id)
    except ClientError as exc:
        if _code(exc) != "NotFoundException":
            raise
        budgets = []
    ctx.r.fail("budgets_none", [] if budgets else ["no budget"])


def task_macie(ctx: Ctx) -> None:
    try:
        status = ctx.client("macie2", ctx.home).get_macie_session().get("status")
    except ClientError as exc:
        if "not enabled" not in str(exc).lower() and _code(exc) != "ResourceNotFoundException":
            raise
        status = None
    ctx.r.fail("macie_off", [] if status == "ENABLED" else [f"off in {ctx.home}"])


def task_cloudfront(ctx: Ctx) -> None:
    pages = ctx.client("cloudfront").get_paginator("list_distributions").paginate()
    items = [d for page in pages for d in (page.get("DistributionList") or {}).get("Items") or []]
    plain, no_waf = [], []
    for d in items:
        behaviours = [d.get("DefaultCacheBehavior") or {}] + list((d.get("CacheBehaviors") or {}).get("Items") or [])
        if any(b.get("ViewerProtocolPolicy") == "allow-all" for b in behaviours):
            plain.append(f"{d['Id']} ({d.get('DomainName', '')})")
        if not d.get("WebACLId"):
            no_waf.append(f"{d['Id']} ({d.get('DomainName', '')})")
    ctx.r.fail("cloudfront_http", plain)
    ctx.r.fail("cloudfront_no_waf", no_waf)


def task_trusted_advisor(ctx: Ctx) -> None:
    if ctx.ta_org:
        return  # read once for the whole organisation in the management account
    try:
        recs = _pages(ctx.client("trustedadvisor"), "list_recommendations", "recommendationSummaries")
    except ClientError as exc:
        if _code(exc) in ("SubscriptionRequiredException", "AccessDeniedException") and "upport" in str(exc):
            for cid in ("trusted_advisor_red", "trusted_advisor_yellow"):
                ctx.r.na(cid, "needs Business or Enterprise Support")
            return
        raise
    relevant = [x for x in recs if set(x.get("pillars") or []) & {"security", "fault_tolerance"}]
    ctx.r.fail("trusted_advisor_red", [x["name"] for x in relevant if x.get("status") == "error"])
    ctx.r.fail("trusted_advisor_yellow", [x["name"] for x in relevant if x.get("status") == "warning"])


def task_changes(ctx: Ctx) -> None:
    """Write calls by people in the last week, sampled from CloudTrail event history. IAM and other
    global services record in us-east-1, so it is read as well as the account's busiest region."""
    start = ctx.now - timedelta(days=CHANGE_DAYS)
    found: list[str] = []
    sampled = 0
    for region in dict.fromkeys([ctx.home, "us-east-1"]):
        c = ctx.client("cloudtrail", region)
        kwargs = {"LookupAttributes": [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}], "StartTime": start}
        for i, page in enumerate(
            c.get_paginator("lookup_events").paginate(**kwargs, PaginationConfig={"PageSize": 50})
        ):
            for ev in page.get("Events") or []:
                sampled += 1
                who = _human_actor(ev)
                if who:
                    found.append(f"{ev.get('EventTime', '')!s:.10} {ev.get('EventName')} by {who} ({region})")
            if i + 1 >= TRAIL_PAGES:
                break
    ctx.r.fail("manual_changes", found)
    ctx.r.fact("changes_sampled", sampled)


def _human_actor(ev: dict) -> str | None:
    name, source = ev.get("EventName", ""), ev.get("EventSource", "")
    if name in NOT_CHANGES or source.startswith(NOT_CHANGE_SOURCES):
        return None
    try:
        ident = json.loads(ev.get("CloudTrailEvent") or "{}").get("userIdentity") or {}
    except json.JSONDecodeError:
        return None
    kind = ident.get("type")
    if kind == "Root":
        return "root"
    if kind == "IAMUser":
        return f"IAM user {ident.get('userName', '')}"
    arn = ident.get("arn", "")
    if kind == "AssumedRole" and ":assumed-role/AWSReservedSSO_" in arn:
        role = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        return _sso_label(role)
    return None


# ---------------------------------------------------------------------------------- regional tasks


def _open(perm: dict) -> bool:
    return any(x.get("CidrIp") == "0.0.0.0/0" for x in perm.get("IpRanges") or []) or any(
        x.get("CidrIpv6") == "::/0" for x in perm.get("Ipv6Ranges") or []
    )


def _ports(perm: dict, ports: tuple[int, ...]) -> list[int]:
    if perm.get("IpProtocol") == "-1":
        return list(ports)
    if perm.get("IpProtocol") not in ("tcp", "6"):
        return []
    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
    return [p for p in ports if lo <= p <= hi]


def task_ec2_network(ctx: Ctx, region: str) -> None:
    r = ctx.r
    ec2 = ctx.client("ec2", region)
    groups = _pages(ec2, "describe_security_groups", "SecurityGroups")
    enis = _pages(ec2, "describe_network_interfaces", "NetworkInterfaces")
    public_groups: dict[str, list[str]] = {}
    public_instances = set()
    for eni in enis:
        if not (eni.get("Association") or {}).get("PublicIp"):
            continue
        owner = (eni.get("Attachment") or {}).get("InstanceId") or eni.get("Description") or eni["NetworkInterfaceId"]
        if (eni.get("Attachment") or {}).get("InstanceId"):
            public_instances.add(eni["Attachment"]["InstanceId"])
        for g in eni.get("Groups") or []:
            public_groups.setdefault(g["GroupId"], []).append(owner)
    admin_public, db_public, admin_open, default_open, all_public = [], [], [], [], []
    for g in groups:
        gid = g["GroupId"]
        if g.get("GroupName") == "default" and (g.get("IpPermissions") or g.get("IpPermissionsEgress")):
            default_open.append(f"{gid} ({g.get('VpcId', '')} {region})")
        admin = sorted({p for perm in g.get("IpPermissions") or [] if _open(perm) for p in _ports(perm, ADMIN_PORTS)})
        db = sorted({p for perm in g.get("IpPermissions") or [] if _open(perm) for p in _ports(perm, DB_PORTS)})
        attached = public_groups.get(gid, [])
        if attached and any(_open(perm) and _all_ports(perm) for perm in g.get("IpPermissions") or []):
            all_public.append(f"all ports open on {attached[0]} via {gid} ({region})")
        if admin and attached:
            admin_public.append(f"{', '.join(map(str, admin))} open on {attached[0]} via {gid} ({region})")
        elif admin:
            admin_open.append(f"{gid} port {', '.join(map(str, admin))} ({region})")
        if db and attached:
            db_public.append(f"{', '.join(map(str, db))} open on {attached[0]} via {gid} ({region})")
    r.fail("admin_ports_public", admin_public)
    r.fail("db_ports_public", db_public)
    r.fail("admin_ports_open", admin_open)
    r.fail("default_sg_open", default_open)
    r.fail("all_ports_public", all_public)
    nacls = _pages(ec2, "describe_network_acls", "NetworkAcls")
    r.fail("nacl_admin_open", [f"{n['NetworkAclId']} ({region})" for n in nacls if _nacl_admin_open(n)])
    r.fail("ec2_public_ip", [f"{i} ({region})" for i in sorted(public_instances)])

    instances = [
        i
        for res in _pages(
            ec2,
            "describe_instances",
            "Reservations",
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}],
        )
        for i in res.get("Instances") or []
    ]
    r.fail(
        "imdsv2",
        [
            f"{i['InstanceId']} ({region})"
            for i in instances
            if (i.get("MetadataOptions") or {}).get("HttpTokens") != "required"
        ],
    )
    standalone = [
        i
        for i in instances
        if not any(
            t["Key"] in ("aws:autoscaling:groupName", "eks:nodegroup-name", "aws:eks:cluster-name")
            or t["Key"].startswith("kubernetes.io/cluster/")
            for t in i.get("Tags") or []
        )
    ]
    azs = sorted({(i.get("Placement") or {}).get("AvailabilityZone", "") for i in standalone})
    r.fail("ec2_one_az", [f"{len(standalone)} server(s) all in {azs[0]}"] if standalone and len(azs) == 1 else [])
    r.fact("running_instances", [i["InstanceId"] for i in instances], region)
    r.fact("instance_profiles", {i["InstanceId"]: i["IamInstanceProfile"]["Arn"] for i in instances
                                 if i.get("IamInstanceProfile")}, region)  # fmt: skip
    r.fail("ec2_previous_generation", [f"{i['InstanceId']} {i.get('InstanceType')} ({region})" for i in instances
                                       if i.get("InstanceType", "").split(".")[0] in OLD_FAMILIES])  # fmt: skip
    by_image: dict[str, list[str]] = {}
    for i in instances:
        by_image.setdefault(i.get("ImageId", ""), []).append(i["InstanceId"])
    ids = [x for x in by_image if x]
    old = []
    for k in range(0, len(ids), 100):
        for img in ec2.describe_images(ImageIds=ids[k : k + 100], IncludeDeprecated=True).get("Images", []):
            age = _age_days(img.get("CreationDate"), ctx.now)
            if age is not None and age > AMI_DAYS:
                old += [
                    f"{x} on {img['ImageId']} ({int(age)} days, {region})" for x in by_image.get(img["ImageId"], [])
                ]
    r.fail("ami_outdated", old)


def _all_ports(perm: dict) -> bool:
    return perm.get("IpProtocol") == "-1" or (
        perm.get("IpProtocol") in ("tcp", "6") and perm.get("FromPort", 0) <= 1 and perm.get("ToPort", 0) >= 65535
    )


def _nacl_admin_open(nacl: dict) -> bool:
    """The first inbound rule from anywhere that covers port 22 or 3389 allows it."""
    rules = sorted((e for e in nacl.get("Entries") or [] if not e.get("Egress")), key=lambda e: e.get("RuleNumber", 0))
    for port in ADMIN_PORTS:
        for e in rules:
            if e.get("CidrBlock") not in OPEN_CIDRS and e.get("Ipv6CidrBlock") not in OPEN_CIDRS:
                continue
            rng = e.get("PortRange") or {"From": 0, "To": 65535}
            if e.get("Protocol") not in ("-1", "6") or not rng.get("From", 0) <= port <= rng.get("To", 65535):
                continue
            if e.get("RuleAction") == "allow":
                return True
            break
    return False


def task_ec2_vpc(ctx: Ctx, region: str) -> None:
    r = ctx.r
    ec2 = ctx.client("ec2", region)
    igws = [
        g["InternetGatewayId"]
        for g in _pages(ec2, "describe_internet_gateways", "InternetGateways")
        if any(a.get("State") in ("available", "attached") for a in g.get("Attachments") or [])
    ]
    r.fail("igw_present", [f"{g} ({region})" for g in igws])
    nats = _pages(ec2, "describe_nat_gateways", "NatGateways", Filter=[{"Name": "state", "Values": ["available"]}])
    r.fail("nat_present", [f"{n['NatGatewayId']} ({region})" for n in nats])
    subnets = {s["SubnetId"]: s for s in _pages(ec2, "describe_subnets", "Subnets")}
    single = []
    for vpc in sorted({n.get("VpcId") for n in nats if n.get("ConnectivityType", "public") == "public"} - {None}):
        nat_azs = {subnets.get(n.get("SubnetId"), {}).get("AvailabilityZone") for n in nats if n.get("VpcId") == vpc}
        vpc_azs = {s.get("AvailabilityZone") for s in subnets.values() if s.get("VpcId") == vpc}
        if len(vpc_azs) > 1 and len(nat_azs - {None}) == 1:
            single.append(f"{vpc} NAT only in {next(iter(nat_azs - {None}))} ({region})")
    r.fail("nat_single_az", single)
    vpns = [v for v in ec2.describe_vpn_connections().get("VpnConnections", []) if v.get("State") == "available"]
    r.fail("vpn_tunnel_down", [f"{v['VpnConnectionId']} ({region})" for v in vpns
                               if any(t.get("Status") != "UP" for t in v.get("VgwTelemetry") or [])])  # fmt: skip
    vpcs = _pages(ec2, "describe_vpcs", "Vpcs")
    r.fail("default_vpc", [f"{v['VpcId']} ({region})" for v in vpcs if v.get("IsDefault")])
    logged = {f.get("ResourceId") for f in _pages(ec2, "describe_flow_logs", "FlowLogs")}
    r.fail("flow_logs", [f"{v['VpcId']} ({region})" for v in vpcs if v["VpcId"] not in logged])


def task_ec2_storage(ctx: Ctx, region: str) -> None:
    r = ctx.r
    ec2 = ctx.client("ec2", region)
    r.fail(
        "ebs_default_encryption", [] if ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault") else [region]
    )
    snaps = _pages(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"], RestorableByUserIds=["all"])
    r.fail("public_snapshots", [f"{s['SnapshotId']} ({region})" for s in snaps])
    images = ec2.describe_images(Owners=["self"], Filters=[{"Name": "is-public", "Values": ["true"]}]).get("Images", [])
    r.fail("public_amis", [f"{i['ImageId']} ({region})" for i in images])
    vols = _pages(ec2, "describe_volumes", "Volumes", Filters=[{"Name": "encrypted", "Values": ["false"]}])
    r.fail("ebs_unencrypted", [f"{v['VolumeId']} ({region})" for v in vols])


def task_elb(ctx: Ctx, region: str) -> None:
    r = ctx.r
    v2 = ctx.client("elbv2", region)
    public, single, plain, old_tls, no_logs = [], [], [], [], []
    lbs = [lb for lb in _pages(v2, "describe_load_balancers", "LoadBalancers") if lb.get("Type") != "gateway"]
    for lb in lbs:
        name = f"{lb['LoadBalancerName']} ({region})"
        if lb.get("Scheme") == "internet-facing":
            public.append(name)
        if len(lb.get("AvailabilityZones") or []) < 2:
            single.append(name)
    if len(lbs) > MAX_LBS:
        for cid in ("elb_http", "tls_outdated", "elb_access_logs"):
            r.unknown(cid, f"only the first {MAX_LBS} load balancers in {region} were read")
    for lb in lbs[:MAX_LBS]:
        name = f"{lb['LoadBalancerName']} ({region})"
        for ls in _pages(v2, "describe_listeners", "Listeners", LoadBalancerArn=lb["LoadBalancerArn"]):
            redirect = all(a.get("Type") == "redirect" and (a.get("RedirectConfig") or {}).get("Protocol") == "HTTPS"
                           for a in ls.get("DefaultActions") or [{}])  # fmt: skip
            if ls.get("Protocol") == "HTTP" and lb.get("Scheme") == "internet-facing" and not redirect:
                plain.append(f"{name} port {ls.get('Port')}")
            policy = ls.get("SslPolicy") or ""
            if policy and (policy in OLD_TLS or any(m in policy for m in OLD_TLS_MARKS)):
                old_tls.append(f"{name} {policy}")
        attrs = {a["Key"]: a["Value"] for a in v2.describe_load_balancer_attributes(
            LoadBalancerArn=lb["LoadBalancerArn"]).get("Attributes", [])}  # fmt: skip
        if attrs.get("access_logs.s3.enabled") != "true":
            no_logs.append(name)
    classic = ctx.client("elb", region)
    for lb in _pages(classic, "describe_load_balancers", "LoadBalancerDescriptions"):
        name = f"{lb['LoadBalancerName']} (classic, {region})"
        if lb.get("Scheme") == "internet-facing":
            public.append(name)
            if any((d.get("Listener") or {}).get("Protocol") == "HTTP" for d in lb.get("ListenerDescriptions") or []):
                plain.append(name)
        if len(lb.get("AvailabilityZones") or []) < 2:
            single.append(name)
        attrs = classic.describe_load_balancer_attributes(LoadBalancerName=lb["LoadBalancerName"])
        if not (attrs.get("LoadBalancerAttributes") or {}).get("AccessLog", {}).get("Enabled"):
            no_logs.append(name)
    r.fail("public_lb", public)
    r.fail("lb_single_az", single)
    r.fail("elb_http", plain)
    r.fail("tls_outdated", old_tls)
    r.fail("elb_access_logs", no_logs)


def task_waf(ctx: Ctx, region: str) -> None:
    """Public ALBs and REST API stages with no AWS WAF web ACL."""
    waf = ctx.client("wafv2", region)
    covered: set[str] = set()
    for acl in _pages(waf, "list_web_acls", "WebACLs", Scope="REGIONAL"):
        for kind in ("APPLICATION_LOAD_BALANCER", "API_GATEWAY"):
            covered.update(
                waf.list_resources_for_web_acl(WebACLArn=acl["ARN"], ResourceType=kind).get("ResourceArns", [])
            )
    bare = [f"{lb['LoadBalancerName']} ({region})"
            for lb in _pages(ctx.client("elbv2", region), "describe_load_balancers", "LoadBalancers")
            if lb.get("Type") == "application" and lb.get("Scheme") == "internet-facing"
            and lb["LoadBalancerArn"] not in covered]  # fmt: skip
    if ctx.billed("Amazon API Gateway"):
        api = ctx.client("apigateway", region)
        for rest in _pages(api, "get_rest_apis", "items", cap=100):
            if "PRIVATE" in ((rest.get("endpointConfiguration") or {}).get("types") or []):
                continue
            for stage in api.get_stages(restApiId=rest["id"]).get("item", []):
                arn = f"arn:aws:apigateway:{region}::/restapis/{rest['id']}/stages/{stage['stageName']}"
                if arn not in covered and not stage.get("webAclArn"):
                    bare.append(f"API {rest.get('name', rest['id'])} stage {stage['stageName']} ({region})")
    ctx.r.fail("waf_missing", bare)


def task_asg(ctx: Ctx, region: str) -> None:
    groups = _pages(ctx.client("autoscaling", region), "describe_auto_scaling_groups", "AutoScalingGroups")
    ctx.r.fail(
        "asg_single_az",
        [
            f"{g['AutoScalingGroupName']} ({region})"
            for g in groups
            if g.get("DesiredCapacity", 0) > 0 and len(g.get("AvailabilityZones") or []) < 2
        ],
    )


RDS_SERVICES = (
    "Amazon Relational Database Service",
    "Amazon DocumentDB (with MongoDB compatibility)",
    "Amazon Neptune",
)


def task_rds(ctx: Ctx, region: str) -> None:
    r = ctx.r
    rds = ctx.client("rds", region)
    dbs = _pages(rds, "describe_db_instances", "DBInstances")
    clusters = _pages(rds, "describe_db_clusters", "DBClusters")
    single, public, plain, no_backup, unprotected, short, eol = [], [], [], [], [], [], []
    ends, today = lifecycle_data()["rds"], ctx.now.date()

    def past_support(x: dict) -> bool:
        engine, version = x.get("Engine", ""), x.get("EngineVersion", "")
        parts = version.split(".")
        major = ".".join(parts[:2]) if "mysql" in engine else parts[0]
        end = ends.get(f"{engine} {major}")
        return bool(end and end <= today)

    for db in dbs:
        name = f"{db['DBInstanceIdentifier']} ({region})"
        if db.get("PubliclyAccessible"):
            public.append(name)
        if db.get("DBClusterIdentifier"):
            continue  # Aurora, DocumentDB, Neptune members: judged by their cluster
        if not db.get("StorageEncrypted"):
            plain.append(name)
        if db.get("ReadReplicaSourceDBInstanceIdentifier"):
            continue
        if not db.get("MultiAZ"):
            single.append(name)
        if db.get("BackupRetentionPeriod", 1) == 0:
            no_backup.append(name)
        elif db.get("BackupRetentionPeriod", BACKUP_DAYS) < BACKUP_DAYS:
            short.append(f"{name} {db['BackupRetentionPeriod']} days")
        if past_support(db):
            eol.append(f"{name} {db.get('Engine')} {db.get('EngineVersion')}")
        if not db.get("DeletionProtection"):
            unprotected.append(name)
    members: dict[str, set] = {}
    for db in dbs:
        if db.get("DBClusterIdentifier"):
            members.setdefault(db["DBClusterIdentifier"], set()).add(db.get("AvailabilityZone"))
    for c in clusters:
        if c.get("EngineMode") == "serverless":
            continue
        name = f"{c['DBClusterIdentifier']} ({region})"
        if not c.get("MultiAZ") and len(members.get(c["DBClusterIdentifier"], set())) < 2:
            single.append(name)
        if not c.get("StorageEncrypted"):
            plain.append(name)
        if not c.get("DeletionProtection"):
            unprotected.append(name)
        if c.get("BackupRetentionPeriod", BACKUP_DAYS) < BACKUP_DAYS:
            short.append(f"{name} {c['BackupRetentionPeriod']} days")
        if past_support(c):
            eol.append(f"{name} {c.get('Engine')} {c.get('EngineVersion')}")
    r.fail("rds_backup_short", short)
    r.fail("rds_engine_eol", eol)
    r.fail("rds_public", public)
    r.fail("rds_unencrypted", plain)
    r.fail("rds_single_az", single)
    r.fail("rds_no_backups", no_backup)
    r.fail("rds_no_deletion_protection", unprotected)


def task_dynamodb(ctx: Ctx, region: str) -> None:
    ddb = ctx.client("dynamodb", region)
    tables = _pages(ddb, "list_tables", "TableNames", cap=MAX_ITEMS)
    off, unprotected = [], []
    for t in tables:
        desc = ddb.describe_continuous_backups(TableName=t).get("ContinuousBackupsDescription", {})
        if (desc.get("PointInTimeRecoveryDescription") or {}).get("PointInTimeRecoveryStatus") != "ENABLED":
            off.append(f"{t} ({region})")
        if not ddb.describe_table(TableName=t)["Table"].get("DeletionProtectionEnabled"):
            unprotected.append(f"{t} ({region})")
    ctx.r.fail("dynamodb_no_pitr", off)
    ctx.r.fail("dynamodb_no_deletion_protection", unprotected)


def task_elasticache(ctx: Ctx, region: str) -> None:
    c = ctx.client("elasticache", region)
    groups = _pages(c, "describe_replication_groups", "ReplicationGroups")
    bad = [f"{g['ReplicationGroupId']} ({region})" for g in groups if g.get("AutomaticFailover") != "enabled"]
    plain = [g for g in groups if not g.get("AtRestEncryptionEnabled") or not g.get("TransitEncryptionEnabled")]
    ctx.r.fail("elasticache_unencrypted", [f"{g['ReplicationGroupId']} ({region})" for g in plain])
    bad += [
        f"{x['CacheClusterId']} (single node, {region})"
        for x in _pages(c, "describe_cache_clusters", "CacheClusters")
        if not x.get("ReplicationGroupId")
    ]
    ctx.r.fail("elasticache_no_failover", bad)


def task_opensearch(ctx: Ctx, region: str) -> None:
    c = ctx.client("opensearch", region)
    names = [d["DomainName"] for d in c.list_domain_names().get("DomainNames", [])]
    single, public, plain = [], [], []
    for i in range(0, len(names), 5):
        for d in c.describe_domains(DomainNames=names[i : i + 5]).get("DomainStatusList", []):
            name = f"{d['DomainName']} ({region})"
            if not (d.get("ClusterConfig") or {}).get("ZoneAwarenessEnabled"):
                single.append(name)
            if not (d.get("VPCOptions") or {}).get("VPCId"):
                public.append(name)
            if not (d.get("EncryptionAtRestOptions") or {}).get("Enabled") or not (
                d.get("NodeToNodeEncryptionOptions") or {}
            ).get("Enabled"):
                plain.append(name)
    ctx.r.fail("opensearch_single_az", single)
    ctx.r.fail("opensearch_public", public)
    ctx.r.fail("opensearch_unencrypted", plain)


def task_redshift(ctx: Ctx, region: str) -> None:
    clusters = _pages(ctx.client("redshift", region), "describe_clusters", "Clusters")
    ctx.r.fail(
        "redshift_public", [f"{c['ClusterIdentifier']} ({region})" for c in clusters if c.get("PubliclyAccessible")]
    )
    ctx.r.fail(
        "redshift_unencrypted", [f"{c['ClusterIdentifier']} ({region})" for c in clusters if not c.get("Encrypted")]
    )


def task_efs(ctx: Ctx, region: str) -> None:
    fs = _pages(ctx.client("efs", region), "describe_file_systems", "FileSystems")
    ctx.r.fail("efs_one_zone", [f"{f['FileSystemId']} ({region})" for f in fs if f.get("AvailabilityZoneName")])
    ctx.r.fail("efs_unencrypted", [f"{f['FileSystemId']} ({region})" for f in fs if not f.get("Encrypted")])


def task_eks(ctx: Ctx, region: str) -> None:
    c = ctx.client("eks", region)
    ends = lifecycle_data()["eks"]
    today = ctx.now.date()
    old = []
    public = []
    for name in _pages(c, "list_clusters", "clusters"):
        cluster = c.describe_cluster(name=name)["cluster"]
        version = cluster.get("version", "")
        end = ends.get(version)
        if end and end <= today:
            old.append(f"{name} {version} ({region})")
        vpc = cluster.get("resourcesVpcConfig") or {}
        if vpc.get("endpointPublicAccess") and set(vpc.get("publicAccessCidrs") or ["0.0.0.0/0"]) & set(OPEN_CIDRS):
            public.append(f"{name} ({region})")
    ctx.r.fail("eks_unsupported_version", old)
    ctx.r.fail("eks_public_endpoint", public)


def task_lambda(ctx: Ctx, region: str) -> None:
    ends = lifecycle_data()["lambda"]
    today = ctx.now.date()
    fns = _pages(ctx.client("lambda", region), "list_functions", "Functions", cap=MAX_ITEMS * 4)
    ctx.r.fact("function_roles", {f["FunctionName"]: f.get("Role", "") for f in fns}, region)
    ctx.r.fail(
        "lambda_deprecated_runtime",
        [
            f"{f['FunctionName']} {f.get('Runtime')} ({region})"
            for f in fns
            if ends.get(f.get("Runtime", ""), date.max) <= today and not baseline.is_baseline(f["FunctionName"])
        ],
    )


def task_backup(ctx: Ctx, region: str) -> None:
    c = ctx.client("backup", region)
    cross = False
    for plan in _pages(c, "list_backup_plans", "BackupPlansList"):
        rules = c.get_backup_plan(BackupPlanId=plan["BackupPlanId"]).get("BackupPlan", {}).get("Rules", [])
        for rule in rules:
            for copy in rule.get("CopyActions") or []:
                parts = copy.get("DestinationBackupVaultArn", "").split(":")
                if len(parts) > 3 and parts[3] != region:
                    cross = True
    protected = len(_pages(c, "list_protected_resources", "Results", cap=MAX_ITEMS))
    locked = any(v.get("Locked") for v in _pages(c, "list_backup_vaults", "BackupVaultList"))
    restores = c.list_restore_jobs(
        ByCreatedAfter=ctx.now - timedelta(days=TEST_DAYS), ByStatus="COMPLETED", MaxResults=10
    )
    ctx.r.fact(
        "backup",
        {
            "protected": protected,
            "cross_region": cross,
            "restores": len(restores.get("RestoreJobs", [])),
            "locked": locked,
        },
        region,
    )


def task_fis(ctx: Ctx, region: str) -> None:
    runs = _pages(ctx.client("fis", region), "list_experiments", "experiments", cap=200)
    recent = [x for x in runs if (_age_days(x.get("creationTime"), ctx.now) or 1e9) <= TEST_DAYS]
    ctx.r.fact("fis_recent", len(recent), region)


def task_resiliencehub(ctx: Ctx, region: str) -> None:
    ctx.r.fact(
        "resilience_apps", len(_pages(ctx.client("resiliencehub", region), "list_apps", "appSummaries", cap=50)), region
    )


def task_ecs(ctx: Ctx, region: str) -> None:
    c = ctx.client("ecs", region)
    single = []
    for cluster in _pages(c, "list_clusters", "clusterArns", cap=100):
        arns = _pages(c, "list_services", "serviceArns", cap=MAX_ITEMS, cluster=cluster)
        for i in range(0, len(arns), 10):
            for svc in c.describe_services(cluster=cluster, services=arns[i : i + 10]).get("services", []):
                if svc.get("schedulingStrategy", "REPLICA") == "REPLICA" and svc.get("desiredCount") == 1:
                    single.append(f"{svc['serviceName']} in {cluster.rsplit('/', 1)[-1]} ({region})")
    ctx.r.fail("ecs_single_task", single)


def task_directconnect(ctx: Ctx, region: str) -> None:
    conns = ctx.client("directconnect", region).describe_connections().get("connections", [])
    live = [(x["connectionId"], x.get("location", "")) for x in conns if x.get("connectionState") == "available"]
    ctx.r.fact("dx", live, region)


def task_acm(ctx: Ctx, region: str) -> None:
    soon = []
    for cert in _pages(ctx.client("acm", region), "list_certificates", "CertificateSummaryList", cap=MAX_ITEMS):
        left = -(_age_days(cert.get("NotAfter"), ctx.now) or -1e9)
        renews = cert.get("Type") == "AMAZON_ISSUED" and cert.get("RenewalEligibility") == "ELIGIBLE"
        if cert.get("InUse") and left <= CERT_DAYS and not (renews and left > 0):
            soon.append(f"{cert.get('DomainName')} {'expired' if left <= 0 else f'in {int(left)} days'} ({region})")
    ctx.r.fail("acm_expiring", soon)


def task_route53resolver(ctx: Ctx, region: str) -> None:
    vpcs = [v["VpcId"] for v in _pages(ctx.client("ec2", region), "describe_vpcs", "Vpcs")]
    logged = {a.get("ResourceId") for a in _pages(ctx.client("route53resolver", region),
              "list_resolver_query_log_config_associations", "ResolverQueryLogConfigAssociations")}  # fmt: skip
    ctx.r.fail("dns_query_logs", [f"{v} ({region})" for v in vpcs if v not in logged])


def task_logs(ctx: Ctx, region: str) -> None:
    """CloudWatch Logs metric filters that look like the CIS security alarms."""
    filters = _pages(ctx.client("logs", region), "describe_metric_filters", "metricFilters", cap=MAX_ITEMS)
    marks = sorted({m for f in filters for m in ALERT_MARKS if m in (f.get("filterPattern") or "").lower()})
    ctx.r.fact("alert_marks", marks, region)


def task_sagemaker(ctx: Ctx, region: str) -> None:
    c = ctx.client("sagemaker", region)
    open_ = []
    for nb in _pages(c, "list_notebook_instances", "NotebookInstances", cap=100):
        name = nb["NotebookInstanceName"]
        if c.describe_notebook_instance(NotebookInstanceName=name).get("DirectInternetAccess") == "Enabled":
            open_.append(f"{name} ({region})")
    ctx.r.fail("sagemaker_notebook_internet", open_)


def task_bedrock_guardrails(ctx: Ctx, region: str) -> None:
    guardrails = _pages(ctx.client("bedrock", region), "list_guardrails", "guardrails", cap=10)
    ctx.r.fail("bedrock_no_guardrails", [] if guardrails else [region])


def task_guardduty(ctx: Ctx, region: str) -> None:
    r = ctx.r
    c = ctx.client("guardduty", region)
    ids = c.list_detectors().get("DetectorIds", [])
    det = c.get_detector(DetectorId=ids[0]) if ids else None
    if not det or det.get("Status") != "ENABLED":
        r.fail("guardduty_off", [region])
        r.na("guardduty_findings", "GuardDuty is off")
        r.fact("guardduty_s3", False, region)
        return
    r.ok("guardduty_off")
    s3_on = ((det.get("DataSources") or {}).get("S3Logs") or {}).get("Status") == "ENABLED" or any(
        f.get("Name") == "S3_DATA_EVENTS" and f.get("Status") == "ENABLED" for f in det.get("Features") or []
    )
    r.fact("guardduty_s3", s3_on, region)
    features = {f.get("Name"): f.get("Status") for f in det.get("Features") or []}
    off = [n for n in ("S3_DATA_EVENTS", "EBS_MALWARE_PROTECTION") if n in features and features[n] != "ENABLED"]
    r.fail("guardduty_partial", [f"{', '.join(off)} off ({region})"] if off else [])
    criteria = {"Criterion": {"severity": {"Gte": 7}, "service.archived": {"Eq": ["false"]}}}
    found = _pages(
        c, "list_findings", "FindingIds", cap=FINDING_PAGES * 50, DetectorId=ids[0], FindingCriteria=criteria
    )
    r.fail("guardduty_findings", [f"{f} ({region})" for f in found])


def task_securityhub(ctx: Ctx, region: str) -> None:
    r = ctx.r
    c = ctx.client("securityhub", region)
    try:
        c.describe_hub()
    except ClientError as exc:
        if _code(exc) not in ("InvalidAccessException", "ResourceNotFoundException"):
            raise
        r.fail("securityhub_off", [region])
        for cid in ("sh_critical_findings", "sh_high_aged"):
            r.na(cid, "Security Hub is off")
        return
    r.ok("securityhub_off")
    standards = [x.get("StandardsArn", "") for x in _pages(c, "get_enabled_standards", "StandardsSubscriptions")
                 if x.get("StandardsStatus") in ("READY", "INCOMPLETE", "PENDING")]  # fmt: skip
    known = ("aws-foundational-security-best-practices", "cis-aws-foundations-benchmark")
    r.fail("sh_standards_missing", [] if any(k in a for a in standards for k in known) else [region])
    base = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}], "WorkflowStatus": [
        {"Value": "NEW", "Comparison": "EQUALS"}, {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
        "AwsAccountId": [{"Value": ctx.account_id, "Comparison": "EQUALS"}]}  # fmt: skip

    def titles(filters: dict) -> list[str]:
        out = []
        for f in _pages(c, "get_findings", "Findings", cap=FINDING_PAGES * 100, Filters=filters, MaxResults=100):
            if (f.get("Compliance") or {}).get("Status") == "PASSED":
                continue
            out.append(f"{f.get('Title', '')} ({region})")
        return out

    r.fail("sh_critical_findings", titles({**base, "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}]}))
    cutoff = (ctx.now - timedelta(days=OLD_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    r.fail(
        "sh_high_aged",
        titles(
            {
                **base,
                "SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}],
                "FirstObservedAt": [{"Start": "2000-01-01T00:00:00Z", "End": cutoff}],
            }
        ),
    )


def task_config(ctx: Ctx, region: str) -> None:
    r = ctx.r
    c = ctx.client("config", region)
    status = c.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    if not any(s.get("recording") for s in status):
        r.fail("config_off", [region])
        for cid in ("config_noncompliant", "config_partial", "config_rules_none"):
            r.na(cid, "Config is off")
        return
    r.ok("config_off")
    recorders = c.describe_configuration_recorders().get("ConfigurationRecorders", [])
    r.fail("config_partial", [] if any((x.get("recordingGroup") or {}).get("allSupported", True) for x in recorders)
           else [f"selected resource types only ({region})"])  # fmt: skip
    r.fact("config_rules", len(c.describe_config_rules().get("ConfigRules", [])), region)
    rules = _pages(c, "describe_compliance_by_config_rule", "ComplianceByConfigRules", cap=MAX_ITEMS,
                   ComplianceTypes=["NON_COMPLIANT"])  # fmt: skip
    r.fail("config_noncompliant", [f"{x['ConfigRuleName']} ({region})" for x in rules])


def task_inspector(ctx: Ctx, region: str) -> None:
    accounts = (
        ctx.client("inspector2", region).batch_get_account_status(accountIds=[ctx.account_id]).get("accounts", [])
    )
    state = (accounts[0].get("state") or {}).get("status") if accounts else None
    ctx.r.fail("inspector_off", [] if state == "ENABLED" else [f"{region} ({(state or 'off').lower()})"])
    if state != "ENABLED":
        for cid in ("inspector_partial", "vuln_critical", "vuln_high_aged"):
            ctx.r.na(cid, "Inspector is off")
        return
    res = accounts[0].get("resourceState") or {}
    off = [k.upper() for k in ("ecr", "lambda") if (res.get(k) or {}).get("status") != "ENABLED"]
    ctx.r.fail("inspector_partial", [f"{', '.join(off)} scanning off ({region})"] if off else [])
    c = ctx.client("inspector2", region)
    base = {"findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            "awsAccountId": [{"comparison": "EQUALS", "value": ctx.account_id}]}  # fmt: skip

    def found(extra: dict) -> list[str]:
        items = _pages(c, "list_findings", "findings", cap=FINDING_PAGES * 100, filterCriteria={**base, **extra})
        return [f"{f.get('title', '')[:90]} ({region})" for f in items]

    ctx.r.fail("vuln_critical", found({"severity": [{"comparison": "EQUALS", "value": "CRITICAL"}]}))
    cutoff = ctx.now - timedelta(days=PATCH_DAYS)
    ctx.r.fail("vuln_high_aged", found({"severity": [{"comparison": "EQUALS", "value": "HIGH"}],
                                        "firstObservedAt": [{"endInclusive": cutoff}]}))  # fmt: skip


def task_access_analyzer(ctx: Ctx, region: str) -> None:
    c = ctx.client("accessanalyzer", region)
    analyzers = [
        a
        for kind in ("ACCOUNT", "ORGANIZATION")
        for a in _pages(c, "list_analyzers", "analyzers", type=kind)
        if a.get("status") == "ACTIVE"
    ]
    if not analyzers:
        ctx.r.fail("access_analyzer_off", [region])
        ctx.r.na("external_access_findings", "no analyzer in the account")
        return
    ctx.r.ok("access_analyzer_off")
    found = []
    for a in analyzers:
        found += _pages(c, "list_findings_v2", "findings", cap=FINDING_PAGES * 100, analyzerArn=a["arn"],
                        filter={"status": {"eq": ["ACTIVE"]}})  # fmt: skip
    ctx.r.fail("external_access_findings", [f"{f.get('resource', f.get('id'))} ({region})" for f in found])


def task_cloudformation(ctx: Ctx, region: str) -> None:
    live = ["CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "IMPORT_COMPLETE"]
    stacks = _pages(ctx.client("cloudformation", region), "list_stacks", "StackSummaries", StackStatusFilter=live)
    status = [
        (s["StackName"], (s.get("DriftInformation") or {}).get("StackDriftStatus", "NOT_CHECKED")) for s in stacks
    ]
    checked = [x for x in status if x[1] != "NOT_CHECKED"]
    if stacks and not checked:
        ctx.r.unknown("cfn_drift", f"drift detection never run on the {len(stacks)} stack(s) in {region}")
        return
    ctx.r.fail("cfn_drift", [f"{n} ({region})" for n, s in checked if s == "DRIFTED"])


def task_ssm(ctx: Ctx, region: str) -> None:
    c = ctx.client("ssm", region)
    managed = {i["InstanceId"] for i in _pages(c, "describe_instance_information", "InstanceInformationList")}
    ctx.r.fact("ssm_managed", sorted(managed), region)
    missing = _pages(c, "list_resource_compliance_summaries", "ResourceComplianceSummaryItems", cap=MAX_ITEMS,
                     Filters=[{"Key": "ComplianceType", "Values": ["Patch"], "Type": "EQUAL"},
                              {"Key": "Status", "Values": ["NON_COMPLIANT"], "Type": "EQUAL"}])  # fmt: skip
    ctx.r.fail("patch_noncompliant", [f"{x.get('ResourceId')} ({region})" for x in missing])


def task_kms(ctx: Ctx, region: str) -> None:
    c = ctx.client("kms", region)
    off, deleting = [], []
    for k in _pages(c, "list_keys", "Keys", cap=MAX_ITEMS // 5):
        meta = c.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
        if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "PendingDeletion":
            deleting.append(f"{k['KeyId']} on {str(meta.get('DeletionDate', ''))[:10]} ({region})")
        kind = (
            meta.get("KeyManager"),
            meta.get("KeyState"),
            meta.get("KeySpec", "SYMMETRIC_DEFAULT"),
            meta.get("Origin"),
        )
        if kind != ("CUSTOMER", "Enabled", "SYMMETRIC_DEFAULT", "AWS_KMS"):
            continue
        if not c.get_key_rotation_status(KeyId=k["KeyId"]).get("KeyRotationEnabled"):
            off.append(f"{k['KeyId']} ({region})")
    ctx.r.fail("kms_rotation", off)
    ctx.r.fail("kms_pending_deletion", deleting)


def task_secrets(ctx: Ctx, region: str) -> None:
    secrets = _pages(ctx.client("secretsmanager", region), "list_secrets", "SecretList", cap=MAX_ITEMS)
    ctx.r.fail("secrets_no_rotation", [f"{s['Name']} ({region})" for s in secrets if not s.get("RotationEnabled")])


def task_ram(ctx: Ctx, region: str) -> None:
    c = ctx.client("ram", region)
    external = [
        f"{p.get('id')} ({region})"
        for p in _pages(c, "list_principals", "principals", resourceOwner="SELF")
        if p.get("external")
    ]
    ctx.r.fail("ram_external_shares", sorted(set(external)))


def task_events(ctx: Ctx, region: str) -> None:
    rules = _pages(ctx.client("events", region), "list_rules", "Rules")
    patterns = [(x.get("EventPattern") or "").lower() for x in rules if x.get("State") == "ENABLED"]
    ctx.r.fact("s3_rules", [p for p in patterns if '"aws.s3"' in p][:50], region)
    ctx.r.fact("alert_rules", sorted({m for p in patterns for m in ALERT_MARKS if m in p}), region)


def task_bedrock(ctx: Ctx, region: str) -> None:
    cfg = ctx.client("bedrock", region).get_model_invocation_logging_configuration().get("loggingConfig")
    ctx.r.fail("bedrock_no_logging", [] if cfg else [region])


# (name, checks it measures, function, Cost Explorer services that must be billed or None)
GLOBAL_TASKS: list[tuple[str, tuple[str, ...], Callable, tuple[str, ...] | None]] = [
    ("iam", ("root_mfa", "root_keys", "root_used", "console_no_mfa", "keys_old", "creds_unused", "iam_users",
             "admin_policy", "user_direct_policies", "external_trust", "vendor_roles", "roles_unused",
             "password_policy", "support_role", "workload_admin"), task_iam, None),
    ("s3", ("s3_account_bpa", "s3_public_bucket", "s3_versioning_off", "s3_tls_only", "s3_acls"), task_s3, None),
    ("cloudtrail", ("cloudtrail_off", "cloudtrail_validation", "cloudtrail_kms", "cloudtrail_cwl"), task_cloudtrail,
     None),
    ("account", ("security_contact", "billing_contact", "operations_contact"), task_contact, None),
    ("budgets", ("budgets_none",), task_budgets, None),
    ("macie", ("macie_off",), task_macie, None),
    ("cloudfront", ("cloudfront_http", "cloudfront_no_waf"), task_cloudfront, ("Amazon CloudFront",)),
    ("trustedadvisor", ("trusted_advisor_red", "trusted_advisor_yellow"), task_trusted_advisor, None),
    ("cloudtrail-events", ("manual_changes",), task_changes, None),
]  # fmt: skip
REGION_TASKS: list[tuple[str, tuple[str, ...], Callable, tuple[str, ...] | None]] = [
    ("ec2-network", ("admin_ports_public", "db_ports_public", "admin_ports_open", "default_sg_open", "ec2_public_ip",
                     "imdsv2", "ec2_one_az", "all_ports_public", "nacl_admin_open", "ec2_previous_generation",
                     "ami_outdated"), task_ec2_network, None),
    ("ec2-vpc", ("igw_present", "nat_present", "default_vpc", "flow_logs", "nat_single_az", "vpn_tunnel_down"),
     task_ec2_vpc, None),
    ("route53resolver", ("dns_query_logs",), task_route53resolver, None),
    ("ec2-storage", ("ebs_default_encryption", "public_snapshots", "public_amis", "ebs_unencrypted"),
     task_ec2_storage, None),
    ("elb", ("public_lb", "lb_single_az", "elb_http", "tls_outdated", "elb_access_logs"), task_elb, None),
    ("wafv2", ("waf_missing",), task_waf, None),
    ("autoscaling", ("asg_single_az",), task_asg, None),
    ("rds", ("rds_public", "rds_unencrypted", "rds_single_az", "rds_no_backups", "rds_no_deletion_protection",
             "rds_backup_short", "rds_engine_eol"), task_rds, RDS_SERVICES),
    ("dynamodb", ("dynamodb_no_pitr", "dynamodb_no_deletion_protection"), task_dynamodb, ("Amazon DynamoDB",)),
    ("elasticache", ("elasticache_no_failover", "elasticache_unencrypted"), task_elasticache, ("Amazon ElastiCache",)),
    ("opensearch", ("opensearch_single_az", "opensearch_public", "opensearch_unencrypted"), task_opensearch,
     ("Amazon OpenSearch Service",)),
    ("redshift", ("redshift_public", "redshift_unencrypted"), task_redshift, ("Amazon Redshift",)),
    ("efs", ("efs_one_zone", "efs_unencrypted"), task_efs, ("Amazon Elastic File System",)),
    ("ecs", ("ecs_single_task",), task_ecs, ("Amazon Elastic Container Service",)),
    ("directconnect", ("dx_no_redundancy",), task_directconnect, ("AWS Direct Connect",)),
    ("acm", ("acm_expiring",), task_acm, None),
    ("resiliencehub", ("resiliencehub_none",), task_resiliencehub, None),
    ("eks", ("eks_unsupported_version", "eks_public_endpoint"), task_eks,
     ("Amazon Elastic Container Service for Kubernetes", "Amazon Elastic Kubernetes Service")),
    ("lambda", ("lambda_deprecated_runtime",), task_lambda, None),
    ("backup", ("backup_none", "backup_no_cross_region", "restore_untested", "backup_vault_unlocked"), task_backup,
     None),
    ("fis", ("dr_drills_none",), task_fis, None),
    ("guardduty", ("guardduty_off", "guardduty_findings", "guardduty_partial"), task_guardduty, None),
    ("securityhub", ("securityhub_off", "sh_critical_findings", "sh_high_aged", "sh_standards_missing"),
     task_securityhub, None),
    ("config", ("config_off", "config_noncompliant", "config_partial", "config_rules_none"), task_config, None),
    ("inspector2", ("inspector_off", "inspector_partial", "vuln_critical", "vuln_high_aged"), task_inspector, None),
    ("access-analyzer", ("access_analyzer_off", "external_access_findings"), task_access_analyzer, None),
    ("cloudformation", ("cfn_drift",), task_cloudformation, None),
    ("ssm", ("ssm_unmanaged", "patch_noncompliant"), task_ssm, None),
    ("kms", ("kms_rotation", "kms_pending_deletion"), task_kms, None),
    ("secretsmanager", ("secrets_no_rotation",), task_secrets, None),
    ("ram", ("ram_external_shares",), task_ram, None),
    ("events", ("security_alerts_none",), task_events, None),
    ("logs", ("security_alerts_none",), task_logs, None),
    ("bedrock", ("bedrock_no_logging",), task_bedrock, ("Amazon Bedrock",)),
    ("bedrock-guardrails", ("bedrock_no_guardrails",), task_bedrock_guardrails, ("Amazon Bedrock",)),
    ("sagemaker", ("sagemaker_notebook_internet",), task_sagemaker, ("Amazon SageMaker",)),
]  # fmt: skip
# Calls that fail this way mean the service is not offered (or not opted in) in that region.
_NOT_HERE = ("OptInRequired", "UnrecognizedClientException", "InvalidClientTokenId", "EndpointConnectionError",
             "UnsupportedOperation", "InvalidAction", "SubscriptionRequiredException")  # fmt: skip


def _run(ctx: Ctx, task: tuple, region: str | None) -> None:
    name, checks, fn, needs = task
    if needs and not ctx.billed(*needs):
        for cid in checks:
            ctx.r.na(cid, f"no {needs[0].replace('Amazon ', '').replace('AWS ', '')} billed in this account")
        return
    try:
        fn(ctx) if region is None else fn(ctx, region)
    except (ClientError, BotoCoreError, TimeoutError) as exc:
        code = _code(exc)
        where = region or "global"
        if region and region != "us-east-1" and code in _NOT_HERE:
            return  # the service is not offered there: nothing to measure, nothing failed
        code_, msg, hint = describe_exception(exc)
        for cid in checks:
            ctx.r.unknown(cid, f"{code or 'error'} in {where}")
        log.warning("assurance %s %s %s failed: %s", ctx.account_id, where, name, code,
                    extra={"account_id": ctx.account_id, "region": region, "error_code": code})  # fmt: skip
        ctx.issue(Issue("warning", "assurance", f"{name} in {where}: {msg}", hint, account_id=ctx.account_id,
                        region=region, error_code=code_))  # fmt: skip
    except Exception as exc:  # a bug or an odd answer: the other checks still run
        log.exception("assurance %s %s %s failed with an unexpected error", ctx.account_id, region, name)
        for cid in checks:
            ctx.r.unknown(cid, f"{type(exc).__name__} in {region or 'global'}")


def _finish(ctx: Ctx) -> None:
    """Checks that need several tasks' facts: across regions, or IAM together with S3."""
    r, f = ctx.r, ctx.r.facts
    managed = {i for ids in (f.get("ssm_managed") or {}).values() for i in ids}
    if "ssm_managed" in f and "running_instances" in f:
        r.fail(
            "ssm_unmanaged",
            [
                f"{i} ({region})"
                for region, ids in f["running_instances"].items()
                if region in f["ssm_managed"]
                for i in ids
                if i not in managed
            ],
        )
    backup = f.get("backup")
    if backup:
        protected = sum(b["protected"] for b in backup.values())
        if ctx.billed(*STATEFUL_SERVICES) or protected:
            r.fail("backup_none", [] if protected else ["nothing protected by AWS Backup"])
        else:
            r.na("backup_none", "no databases or storage billed")
        if protected:
            r.fail(
                "backup_no_cross_region", [] if any(b["cross_region"] for b in backup.values()) else ["no copy rule"]
            )
            r.fail("restore_untested", [] if sum(b["restores"] for b in backup.values()) else ["no restore job"])
        else:
            r.na("backup_no_cross_region", "nothing backed up")
            r.na("restore_untested", "nothing backed up")
    if backup:
        protected = sum(b["protected"] for b in backup.values())
        if protected:
            r.fail(
                "backup_vault_unlocked", [] if any(b.get("locked") for b in backup.values()) else ["no locked vault"]
            )
        else:
            r.na("backup_vault_unlocked", "nothing backed up")
    if "resilience_apps" in f:
        r.fail("resiliencehub_none", [] if sum(f["resilience_apps"].values()) else ["no application assessed"])
    if "dx" in f:
        conns = [c for items in f["dx"].values() for c in items]
        if not conns:
            r.na("dx_no_redundancy", "no Direct Connect connection")
        elif len(conns) == 1 or len({loc for _, loc in conns}) == 1:
            r.fail("dx_no_redundancy", [f"{len(conns)} connection(s) at {conns[0][1]}"])
        else:
            r.ok("dx_no_redundancy")
    if "config_rules" in f:
        r.fail("config_rules_none", [] if sum(f["config_rules"].values()) else ["no Config rule"])
    marks = {m for key in ("alert_rules", "alert_marks") for ms in (f.get(key) or {}).values() for m in ms}
    if "alert_rules" in f or "alert_marks" in f:
        # Judged against the organisation's central alerting too, in the report; kept here as a fact.
        r.fact("alerts", sorted(marks))
        r.fail("security_alerts_none", [] if marks else ["no alert rule or metric filter found"])
    if ctx.admin_roles is not None:
        bad = [f"{i} ({region})" for region, profiles in (f.get("instance_profiles") or {}).items()
               for i, arn in profiles.items() if arn in ctx.admin_profiles]  # fmt: skip
        bad += [f"function {fn} ({region})" for region, fns in (f.get("function_roles") or {}).items()
                for fn, arn in fns.items() if arn in ctx.admin_roles]  # fmt: skip
        r.fail("workload_admin", bad)
    if "fis_recent" in f:
        r.fail("dr_drills_none", [] if sum(f["fis_recent"].values()) else [f"none in {TEST_DAYS} days"])
    humans = ctx.humans
    for b in f.get("buckets") or []:
        if humans is None:
            b["writers"] = None  # IAM was not readable
            continue
        arn = f"arn:aws:s3:::{b['name']}/exitrisk-check"
        writers = {label for label, docs in humans if any(allows(docs, a, arn) for a in WRITE_ACTIONS)}
        b["writers"] = sorted(writers)[:10]


def account_checks(
    session: boto3.Session, account_id: str, regions: list[str] | None, info: dict | None = None
) -> tuple[dict, list[Issue]]:
    """Return ({checks, facts, regions, read_at, seconds}, issues) for one account.

    ``regions``: where to read regional checks (None: every enabled region). ``info``: org_ids (every
    account in the organisation, to tell outside accounts from our own), services (Cost Explorer
    services billed in the account, to skip services it does not use; None reads all) and ta_org
    (Trusted Advisor already read for the organisation).
    """
    started = time.monotonic()
    session = ClientCache(session)
    from .inventory import enabled_regions  # one definition of "enabled regions"

    try:
        region_list = enabled_regions(session, regions)
    except (ClientError, BotoCoreError) as exc:
        code, msg, hint = describe_exception(exc)
        return {}, [Issue("error", "assurance", f"could not list regions: {msg}", hint, account_id=account_id,
                          error_code=code)]  # fmt: skip
    if regions:  # keep the caller's order: the busiest region first
        region_list = [r for r in regions if r in region_list]
    ctx = Ctx(session, account_id, region_list, info or {})
    jobs = [(t, None) for t in GLOBAL_TASKS] + [(t, r) for r in region_list for t in REGION_TASKS]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(contextvars.copy_context().run, _run, ctx, t, r) for t, r in jobs]
        for fut in futures:
            fut.result()
    _finish(ctx)
    out = {
        "checks": ctx.r.finish(),
        "facts": ctx.r.facts,
        "regions": region_list,
        "read_at": ctx.now.isoformat(timespec="seconds"),
        "seconds": round(time.monotonic() - started, 1),
    }
    return out, _collapse(ctx.issues)


def _collapse(issues: list[Issue]) -> list[Issue]:
    """One warning per failing call and error code, listing its regions, not one per region."""
    groups: dict[tuple, list[Issue]] = {}
    for i in issues:
        groups.setdefault((i.message.split(" in ", 1)[0], i.error_code), []).append(i)
    out = []
    for (what, _), items in groups.items():
        first = items[0]
        if len(items) == 1:
            out.append(first)
            continue
        regions = sorted(i.region or "global" for i in items)
        detail = first.message.split(": ", 1)[1] if ": " in first.message else first.message
        message = f"{what} in {len(regions)} regions ({', '.join(regions)}): {detail}"
        out.append(Issue(first.severity, first.category, message, first.hint, account_id=first.account_id,
                         error_code=first.error_code))  # fmt: skip
    return out
