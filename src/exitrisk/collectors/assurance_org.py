"""Cloud Assurance Framework checks read once, in the management account, for the whole organisation.

Some controls live above the member accounts: service control policies (guardrails), central root
access, Trusted Advisor's organisation view, administrator assignments in IAM Identity Center and the
organisation trail. They are read here once and handed to the report, which applies them to every
account in scope. Each part is optional: a refusal is an issue and leaves its checks not measured.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import BotoCoreError, ClientError

from ..aws_session import BOTO_CONFIG
from ..issues import Issue, describe_exception
from ..logging_config import get_logger
from .assurance import ALERT_MARKS, _like, _listify, _pages, is_admin, s3_write_cover

log = get_logger("assurance")

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
WORKERS = 8
# Trusted Advisor's API allows only a few requests a second: fewer threads, so backoff is rarely needed.
TA_WORKERS = 2
# Guardrails a regulated organisation is expected to set with SCPs: the action an SCP should deny
# and what it protects. A Deny with a condition (an exemption for the platform role) still counts.
GUARDRAILS = {
    "cloudtrail:StopLogging": "CloudTrail kept on",
    "cloudtrail:DeleteTrail": "CloudTrail kept on",
    "guardduty:DeleteDetector": "GuardDuty kept on",
    "config:StopConfigurationRecorder": "AWS Config kept on",
    "securityhub:DisableSecurityHub": "Security Hub kept on",
    "organizations:LeaveOrganization": "accounts cannot leave the organisation",
    "s3:PutAccountPublicAccessBlock": "S3 Block Public Access kept on",
    "iam:CreateUser": "no new IAM users (people sign in through Identity Center)",
}


def _client(session, name: str, region: str = "us-east-1"):
    return session.client(name, region_name=region, config=BOTO_CONFIG)


def _parents(tree: dict) -> dict[str, str]:
    """OU id -> parent OU id, for every OU in the tree."""
    out: dict[str, str] = {}
    stack = [tree]
    while stack:
        node = stack.pop()
        for child in node.get("children") or []:
            out[child["id"]] = node["id"]
            stack.append(child)
    return out


def _ancestors(ou_id: str, parents: dict[str, str]) -> list[str]:
    path = [ou_id]
    while path[-1] in parents:
        path.append(parents[path[-1]])
    return path


def _statements(doc: dict) -> list[dict]:
    st = doc.get("Statement")
    return [s for s in (st if isinstance(st, list) else [st]) if isinstance(s, dict)]


def _denies(statements: list[dict], action: str) -> bool:
    for st in statements:
        if st.get("Effect") != "Deny":
            continue
        if "Action" in st and _like(_listify(st["Action"]), action, True):
            return True
        if "NotAction" in st and not _like(_listify(st["NotAction"]), action, True):
            return True
    return False


def _region_deny(statements: list[dict]) -> bool:
    return any(
        st.get("Effect") == "Deny" and "aws:requestedregion" in json.dumps(st.get("Condition") or {}).lower()
        for st in statements
    )


def scp_guardrails(session, tree: dict, accounts: list[dict]) -> dict:
    """{account id: {"missing": [guardrails not set], "region_deny": bool}} from the SCPs on the
    account, its OUs and the root. Deny statements anywhere on the path apply."""
    org = _client(session, "organizations")
    policies = _pages(org, "list_policies", "Policies", Filter="SERVICE_CONTROL_POLICY")
    content: dict[str, list[dict]] = {}
    targets: dict[str, list[str]] = {}

    def read(p: dict) -> tuple[str, list[dict], list[str]]:
        doc = json.loads(org.describe_policy(PolicyId=p["Id"])["Policy"]["Content"])
        ts = [t["TargetId"] for t in _pages(org, "list_targets_for_policy", "Targets", PolicyId=p["Id"])]
        return p["Id"], _statements(doc), ts

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for pid, sts, ts in pool.map(read, policies):
            content[pid] = sts
            for t in ts:
                targets.setdefault(t, []).append(pid)
    parents = _parents(tree)
    out = {}
    for a in accounts:
        path = [a["id"], *_ancestors(a.get("ou_id") or tree["id"], parents)]
        if tree["id"] not in path:
            path.append(tree["id"])
        sts = [s for node in path for pid in targets.get(node, []) for s in content.get(pid, [])]
        missing = sorted({why for action, why in GUARDRAILS.items() if not _denies(sts, action)})
        out[a["id"]] = {"missing": missing, "region_deny": _region_deny(sts)}
    return out


def root_features(session) -> dict:
    """Central root access management: which features are on for the organisation."""
    feats = _client(session, "iam").list_organizations_features().get("EnabledFeatures", [])
    return {"credentials": "RootCredentialsManagement" in feats, "sessions": "RootSessions" in feats}


def delegated_admins(session) -> list[dict]:
    org = _client(session, "organizations")
    out = []
    for a in _pages(org, "list_delegated_administrators", "DelegatedAdministrators"):
        services = [
            s["ServicePrincipal"]
            for s in _pages(org, "list_delegated_services_for_account", "DelegatedServices", AccountId=a["Id"])
        ]
        out.append({"id": a["Id"], "name": a.get("Name", ""), "services": services})
    return out


def trusted_advisor(session, account_ids: set[str]) -> dict:
    """{account id: {"red": [check names], "yellow": [...]}} for security and fault tolerance, from
    Trusted Advisor's organisation view (needs Business or Enterprise Support and trusted access)."""
    ta = _client(session, "trustedadvisor")
    recs = [
        r
        for r in _pages(ta, "list_organization_recommendations", "organizationRecommendationSummaries")
        if set(r.get("pillars") or []) & {"security", "fault_tolerance"} and r.get("status") in ("error", "warning")
    ]
    out: dict[str, dict] = {a: {"red": [], "yellow": []} for a in account_ids}

    def accounts_of(rec: dict) -> tuple[dict, list[dict]]:
        found = _pages(
            ta, "list_organization_recommendation_accounts", "accountRecommendationLifecycleSummaries",
            organizationRecommendationIdentifier=rec["arn"],
        )  # fmt: skip
        return rec, found

    with ThreadPoolExecutor(max_workers=TA_WORKERS) as pool:
        for rec, found in pool.map(accounts_of, recs):
            for f in found:
                aid = f.get("accountId")
                if aid in out:
                    out[aid]["red" if rec.get("status") == "error" else "yellow"].append(rec.get("name", ""))
    return out


def identity_center_region(session, hint: str | None) -> str | None:
    home = getattr(getattr(session, "session", session), "region_name", None)
    for region in dict.fromkeys([r for r in (hint, home, "us-east-1") if r]):
        try:
            if _client(session, "sso-admin", region).list_instances().get("Instances"):
                return region
        except (ClientError, BotoCoreError):
            continue
    return None


def identity_center(session, region: str, account_ids: set[str], owner_emails: set[str]) -> dict:
    """Who holds administrator permission sets in each account, and which owner emails are users.

    Returns {"admins": {account id: {"people": [...], "direct": [...], "groups": [...]}},
    "owners": {email: True/False}, "admin_sets": [names]}."""
    sso = _client(session, "sso-admin", region)
    inst = sso.list_instances()["Instances"][0]
    arn, store_id = inst["InstanceArn"], inst["IdentityStoreId"]
    ids = _client(session, "identitystore", region)

    def admin_set(ps: str) -> str | None:
        managed = _pages(sso, "list_managed_policies_in_permission_set", "AttachedManagedPolicies",
                         InstanceArn=arn, PermissionSetArn=ps)  # fmt: skip
        inline = sso.get_inline_policy_for_permission_set(InstanceArn=arn, PermissionSetArn=ps).get("InlinePolicy")
        if any(m.get("Arn") == ADMIN_ARN for m in managed) or (inline and is_admin(json.loads(inline))):
            return sso.describe_permission_set(InstanceArn=arn, PermissionSetArn=ps)["PermissionSet"]["Name"]
        return None

    sets = _pages(sso, "list_permission_sets", "PermissionSets", InstanceArn=arn)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        admin_sets = {ps: name for ps, name in zip(sets, pool.map(admin_set, sets), strict=True) if name}

    users: dict[str, str] = {}
    members: dict[str, list[str]] = {}
    groups: dict[str, str] = {}

    def user_name(uid: str) -> str:
        if uid not in users:
            try:
                u = ids.describe_user(IdentityStoreId=store_id, UserId=uid)
            except ClientError as exc:  # removed from the directory but still assigned or in a group
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
                u = {"DisplayName": f"deleted user {uid}"}
            users[uid] = u.get("DisplayName") or u.get("UserName") or uid
        return users[uid]

    def group_members(gid: str) -> list[str]:
        if gid not in members:
            try:
                found = _pages(ids, "list_group_memberships", "GroupMemberships", IdentityStoreId=store_id,
                               GroupId=gid)  # fmt: skip
                members[gid] = [m["MemberId"]["UserId"] for m in found if "UserId" in (m.get("MemberId") or {})]
                groups[gid] = ids.describe_group(IdentityStoreId=store_id, GroupId=gid).get("DisplayName", gid)
            except ClientError as exc:  # removed from the directory but still assigned
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
                members[gid], groups[gid] = [], f"deleted group {gid}"
        return members[gid]

    def assignments(job: tuple[str, str]) -> tuple[str, list[dict]]:
        account, ps = job
        return account, _pages(sso, "list_account_assignments", "AccountAssignments", InstanceArn=arn,
                               AccountId=account, PermissionSetArn=ps)  # fmt: skip

    jobs = []
    for ps in admin_sets:
        for account in _pages(sso, "list_accounts_for_provisioned_permission_set", "AccountIds", InstanceArn=arn,
                              PermissionSetArn=ps):  # fmt: skip
            if account in account_ids:
                jobs.append((account, ps))
    admins: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        found = list(pool.map(assignments, jobs))
    for account, items in found:  # names resolved on one thread: the caches are plain dicts
        a = admins.setdefault(account, {"people": set(), "direct": set(), "groups": set()})
        for item in items:
            if item.get("PrincipalType") == "USER":
                name = user_name(item["PrincipalId"])
                a["people"].add(name)
                a["direct"].add(name)
            elif item.get("PrincipalType") == "GROUP":
                a["people"].update(user_name(u) for u in group_members(item["PrincipalId"]))
                a["groups"].add(groups[item["PrincipalId"]])
    owners = {}
    for email in sorted(owner_emails):
        owners[email] = False
        for path in ("emails.value", "userName"):
            try:
                ids.get_user_id(IdentityStoreId=store_id,
                                AlternateIdentifier={"UniqueAttribute": {"AttributePath": path,
                                                                         "AttributeValue": email}})  # fmt: skip
                owners[email] = True
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
    return {
        "admins": {k: {kk: sorted(vv) for kk, vv in v.items()} for k, v in admins.items()},
        "owners": owners,
        "admin_sets": sorted(admin_sets.values()),
    }


def org_trails(session, home: str) -> list[dict]:
    """Organisation trails seen from the management account: logging, S3 write data events and the
    security alarms on the trail's log group."""
    ct = _client(session, "cloudtrail", home)
    out = []
    for t in ct.describe_trails(includeShadowTrails=True).get("trailList", []):
        if not t.get("IsOrganizationTrail"):
            continue
        c = _client(session, "cloudtrail", t.get("HomeRegion") or home)
        item = {
            "name": t.get("Name"),
            "home": t.get("HomeRegion"),
            "logging": bool(c.get_trail_status(Name=t["TrailARN"]).get("IsLogging")),
            "s3_writes": s3_write_cover(c.get_event_selectors(TrailName=t["TrailARN"])),
            "alerts": [],
        }
        group = t.get("CloudWatchLogsLogGroupArn") or ""
        if group:
            parts = group.split(":")
            name = parts[6] if len(parts) > 6 else ""
            try:
                filters = _pages(_client(session, "logs", parts[3]), "describe_metric_filters", "metricFilters",
                                 logGroupName=name)  # fmt: skip
                item["alerts"] = sorted({m for f in filters for m in ALERT_MARKS
                                         if m in (f.get("filterPattern") or "").lower()})  # fmt: skip
            except (ClientError, BotoCoreError):
                item["alerts"] = None
        out.append(item)
    return out


def org_checks(
    session,
    tree: dict | None,
    accounts: list[dict],
    sso_region: str | None,
    home: str,
    progress: Callable | None = None,
) -> tuple[dict, list[Issue]]:
    """Every organisation-level part, each optional. Returns (facts, issues)."""
    facts: dict = {}
    issues: list[Issue] = []
    ids = {a["id"] for a in accounts}
    emails = {v.strip().lower() for a in accounts for v in (a.get("tags") or {}).values() if "@" in str(v)}

    def part(key: str, what: str, fn: Callable, checks: str) -> None:
        if progress:
            progress(what)
        try:
            facts[key] = fn()
        except (ClientError, BotoCoreError) as exc:
            code, msg, hint = describe_exception(exc)
            facts.setdefault("unavailable", {})[key] = msg
            advice = f"{hint + ' ' if hint else ''}Leaves {checks} not measured."
            issues.append(Issue("warning", "assurance", f"{what} unavailable: {msg}", advice, error_code=code))
        except Exception as exc:  # a bug or an odd answer: the other parts still run
            log.exception("assurance %s failed with an unexpected error", key)
            facts.setdefault("unavailable", {})[key] = type(exc).__name__
            issues.append(Issue("warning", "assurance", f"{what} failed: {type(exc).__name__}"))

    if tree:
        part("scps", "service control policies", lambda: scp_guardrails(session, tree, accounts),
             "the guardrail checks")  # fmt: skip
        part("delegated", "delegated administrators", lambda: delegated_admins(session), "nothing")
    part("root", "central root access", lambda: root_features(session), "the central root check")
    part("trusted_advisor", "Trusted Advisor organisation view", lambda: trusted_advisor(session, ids),
         "nothing (each account is read instead)")  # fmt: skip
    region = identity_center_region(session, sso_region)
    if region:
        part("identity_center", "IAM Identity Center assignments",
             lambda: identity_center(session, region, ids, emails), "the administrator and owner checks")  # fmt: skip
    else:
        facts.setdefault("unavailable", {})["identity_center"] = "no IAM Identity Center instance found"
    part("trails", "organisation trails", lambda: org_trails(session, home), "nothing (each account is read)")
    return facts, issues
