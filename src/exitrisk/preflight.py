"""Check access before a scan, and write the request to send to an AWS administrator.

Each check makes the same read-only call a scan would, so "all green" here means the scan will
see the whole organisation. A failed check carries the exact fix; the admin request turns the
failures into a message that names the account, the identity and the policy to attach.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass

from botocore.exceptions import BotoCoreError, ClientError

from . import sso
from .aws_session import BOTO_CONFIG, ClientCache, make_session, member_session
from .collectors.cost import month_window
from .issues import describe_exception
from .logging_config import get_logger
from .parallel import background, pmap

log = get_logger("preflight")

# Mirrors iam/management-account-policy.json (a test keeps the two identical).
MANAGEMENT_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ReadOrganizationStructure",
            "Effect": "Allow",
            "Action": [
                "organizations:DescribeOrganization",
                "organizations:ListRoots",
                "organizations:ListOrganizationalUnitsForParent",
                "organizations:ListAccountsForParent",
                "organizations:ListTagsForResource",
            ],
            "Resource": "*",
        },
        {
            "Sid": "ReadCostAndUsage",
            "Effect": "Allow",
            "Action": [
                "ce:GetCostAndUsage",
                "ce:GetSavingsPlansUtilizationDetails",
                "ce:GetReservationUtilization",
            ],
            "Resource": "*",
        },
        {
            "Sid": "OptionalCloudAssuranceOrganisation",
            "Effect": "Allow",
            "Action": [
                "organizations:ListPolicies",
                "organizations:DescribePolicy",
                "organizations:ListTargetsForPolicy",
                "organizations:ListDelegatedAdministrators",
                "organizations:ListDelegatedServicesForAccount",
                "iam:ListOrganizationsFeatures",
                "trustedadvisor:ListOrganizationRecommendations",
                "trustedadvisor:ListOrganizationRecommendationAccounts",
                "sso:ListInstances",
                "sso:ListPermissionSets",
                "sso:DescribePermissionSet",
                "sso:ListManagedPoliciesInPermissionSet",
                "sso:GetInlinePolicyForPermissionSet",
                "sso:ListAccountsForProvisionedPermissionSet",
                "sso:ListAccountAssignments",
                "identitystore:DescribeUser",
                "identitystore:DescribeGroup",
                "identitystore:ListGroupMemberships",
                "identitystore:GetUserId",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors",
                "logs:DescribeMetricFilters",
            ],
            "Resource": "*",
        },
        {
            "Sid": "OptionalDeepScanAssumeMemberRole",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/ExitRiskReadOnly",
        },
    ],
}

SSO_ROLE_RE = re.compile(r":assumed-role/AWSReservedSSO_(?P<ps>.+)_[0-9a-f]{16}/")


@dataclass
class Check:
    id: str
    label: str
    status: str  # ok | fail | warn | skip
    detail: str = ""
    fix: str = ""
    needs: str = ""  # IAM action(s) to grant when this fails


def _fail(check_id: str, label: str, exc: Exception, needs: str, fix: str = "") -> Check:
    code, msg, hint = describe_exception(exc)
    # AWS errors are the expected outcome of a check; anything else is a bug and needs its traceback.
    log.warning(
        "access check %s failed: %s %s", check_id, code, msg, exc_info=not isinstance(exc, (ClientError, BotoCoreError))
    )
    return Check(check_id, label, "fail", f"{code}: {msg}", fix or hint, needs)


# Error codes that mean "this identity may not make the call". Anything else (a missing resource,
# a validation error) proves the call itself is allowed.
DENIED = {
    "AccessDenied",
    "AccessDeniedException",
    "AuthorizationError",
    "AuthorizationErrorException",
    "UnauthorizedOperation",
    "UnauthorizedException",
    "Forbidden",
    "ForbiddenException",
}
PROBE_REGION = "us-east-1"  # enabled in every account
_NO_SUCH = "exitrisk-access-check"  # a name that does not exist: the call proves access, reads nothing

# (IAM action, client, method, kwargs): one cheap call per action a deep scan makes in a member account.
INVENTORY_PROBES = [
    ("ec2:DescribeRegions", "ec2", "describe_regions", {}),
    ("ec2:DescribeInstances", "ec2", "describe_instances", {"MaxResults": 5}),
    ("s3:ListAllMyBuckets", "s3", "list_buckets", {}),
    ("lambda:ListFunctions", "lambda", "list_functions", {"MaxItems": 1}),
    ("dynamodb:ListTables", "dynamodb", "list_tables", {"Limit": 1}),
    ("states:ListStateMachines", "stepfunctions", "list_state_machines", {"maxResults": 1}),
    ("kinesis:ListStreams", "kinesis", "list_streams", {"Limit": 1}),
    ("sqs:ListQueues", "sqs", "list_queues", {"MaxResults": 1}),
    ("sns:ListTopics", "sns", "list_topics", {}),
    ("events:ListRules", "events", "list_rules", {"Limit": 1}),
    ("apigateway:GET", "apigateway", "get_rest_apis", {"limit": 1}),
    ("apigateway:GET (HTTP APIs)", "apigatewayv2", "get_apis", {"MaxResults": "1"}),
    ("cognito-idp:ListUserPools", "cognito-idp", "list_user_pools", {"MaxResults": 1}),
    ("glue:GetJobs", "glue", "get_jobs", {"MaxResults": 1}),
    ("redshift:DescribeClusters", "redshift", "describe_clusters", {"MaxRecords": 20}),
    ("cloudformation:ListStacks", "cloudformation", "list_stacks", {}),
    ("eks:ListClusters", "eks", "list_clusters", {"maxResults": 1}),
    ("ecs:ListClusters", "ecs", "list_clusters", {"maxResults": 1}),
    ("ecs:ListServices", "ecs", "list_services", {"cluster": _NO_SUCH, "maxResults": 1}),
    ("rds:DescribeDBInstances", "rds", "describe_db_instances", {"MaxRecords": 20}),
]
DEPENDENCY_PROBES = [
    ("lambda:ListEventSourceMappings", "lambda", "list_event_source_mappings", {"MaxItems": 1}),
    ("events:ListTargetsByRule", "events", "list_targets_by_rule", {"Rule": _NO_SUCH}),
    ("sns:ListSubscriptions", "sns", "list_subscriptions", {}),
    (
        "states:DescribeStateMachine",
        "stepfunctions",
        "describe_state_machine",
        {"stateMachineArn": f"arn:aws:states:{PROBE_REGION}:{{account}}:stateMachine:{_NO_SUCH}"},
    ),
]

# Cloud Assurance Framework checks in a member account: one cheap call per service they read. The
# AWS managed policy SecurityAudit covers all of them; iam/member-account-role-policy.json lists them.
_BUCKET = "exitrisk-access-check-{account}"
ASSURANCE_PROBES = [
    ("iam:GetAccountSummary", "iam", "get_account_summary", {}),
    ("iam:GenerateCredentialReport", "iam", "generate_credential_report", {}),
    ("iam:GetAccountAuthorizationDetails", "iam", "get_account_authorization_details", {"MaxItems": 1}),
    ("iam:GetAccountPasswordPolicy", "iam", "get_account_password_policy", {}),
    ("s3:GetAccountPublicAccessBlock", "s3control", "get_public_access_block", {"AccountId": "{account}"}),
    ("s3:GetBucketVersioning", "s3", "get_bucket_versioning", {"Bucket": _BUCKET}),
    ("cloudtrail:DescribeTrails", "cloudtrail", "describe_trails", {}),
    ("cloudtrail:LookupEvents", "cloudtrail", "lookup_events", {"MaxResults": 1}),
    ("cloudtrail:GetEventSelectors", "cloudtrail", "get_event_selectors", {"TrailName": _NO_SUCH}),
    ("account:GetAlternateContact", "account", "get_alternate_contact", {"AlternateContactType": "SECURITY"}),
    ("ec2:DescribeSecurityGroups", "ec2", "describe_security_groups", {"MaxResults": 5}),
    ("ec2:DescribeNetworkInterfaces", "ec2", "describe_network_interfaces", {"MaxResults": 5}),
    ("ec2:DescribeFlowLogs", "ec2", "describe_flow_logs", {"MaxResults": 5}),
    ("ec2:DescribeNetworkAcls", "ec2", "describe_network_acls", {"MaxResults": 5}),
    ("ec2:GetEbsEncryptionByDefault", "ec2", "get_ebs_encryption_by_default", {}),
    ("ec2:DescribeSnapshots", "ec2", "describe_snapshots", {"OwnerIds": ["self"], "MaxResults": 5}),
    ("ec2:DescribeVpnConnections", "ec2", "describe_vpn_connections", {}),
    ("elasticloadbalancing:DescribeLoadBalancers", "elbv2", "describe_load_balancers", {"PageSize": 1}),
    ("wafv2:ListWebACLs", "wafv2", "list_web_acls", {"Scope": "REGIONAL", "Limit": 1}),
    ("guardduty:ListDetectors", "guardduty", "list_detectors", {"MaxResults": 1}),
    ("securityhub:DescribeHub", "securityhub", "describe_hub", {}),
    ("config:DescribeConfigurationRecorderStatus", "config", "describe_configuration_recorder_status", {}),
    ("inspector2:BatchGetAccountStatus", "inspector2", "batch_get_account_status", {"accountIds": ["{account}"]}),
    ("access-analyzer:ListAnalyzers", "accessanalyzer", "list_analyzers", {"maxResults": 1}),
    ("backup:ListBackupPlans", "backup", "list_backup_plans", {"MaxResults": 1}),
    ("ssm:DescribeInstanceInformation", "ssm", "describe_instance_information", {"MaxResults": 5}),
    ("kms:ListKeys", "kms", "list_keys", {"Limit": 1}),
    ("secretsmanager:ListSecrets", "secretsmanager", "list_secrets", {"MaxResults": 1}),
    ("ram:ListPrincipals", "ram", "list_principals", {"resourceOwner": "SELF", "maxResults": 1}),
    ("acm:ListCertificates", "acm", "list_certificates", {"MaxItems": 1}),
    ("logs:DescribeMetricFilters", "logs", "describe_metric_filters", {"limit": 1}),
    ("route53resolver:ListResolverQueryLogConfigAssociations", "route53resolver",
     "list_resolver_query_log_config_associations", {"MaxResults": 1}),
    ("budgets:ViewBudget", "budgets", "describe_budgets", {"AccountId": "{account}", "MaxResults": 1}),
    ("resiliencehub:ListApps", "resiliencehub", "list_apps", {"maxResults": 1}),
    ("fis:ListExperiments", "fis", "list_experiments", {"maxResults": 1}),
    ("dynamodb:DescribeContinuousBackups", "dynamodb", "describe_continuous_backups", {"TableName": _NO_SUCH}),
]  # fmt: skip
# The organisation-level assurance reads, in the management account.
ASSURANCE_ORG_PROBES = [
    ("organizations:ListPolicies", "organizations", "list_policies",
     {"Filter": "SERVICE_CONTROL_POLICY", "MaxResults": 1}),
    ("organizations:ListDelegatedAdministrators", "organizations", "list_delegated_administrators", {"MaxResults": 1}),
    ("iam:ListOrganizationsFeatures", "iam", "list_organizations_features", {}),
    ("trustedadvisor:ListOrganizationRecommendations", "trustedadvisor", "list_organization_recommendations",
     {"maxResults": 1}),
    ("sso:ListInstances", "sso-admin", "list_instances", {"MaxResults": 1}),
    ("cloudtrail:DescribeTrails", "cloudtrail", "describe_trails", {}),
]  # fmt: skip


def probe_actions(session, account_id: str, probes: list) -> tuple[list[str], list[str]]:
    """Make each probe call, several at once; return (denied actions, other failures as "action: code")."""
    if not isinstance(session, ClientCache):  # one session, many threads: clients are made one at a time
        session = ClientCache(session)
    results = pmap(lambda probe: _probe(session, account_id, *probe), probes, workers=len(probes))
    return [a for kind, a in results if kind == "denied"], [a for kind, a in results if kind == "other"]


def _probe(session, account_id: str, action: str, client_name: str, method: str, kwargs: dict) -> tuple[str, str]:
    """("ok" | "denied" | "other", text) for one call."""
    kwargs = {k: v.format(account=account_id) if isinstance(v, str) else v for k, v in kwargs.items()}
    try:
        getattr(session.client(client_name, region_name=PROBE_REGION, config=BOTO_CONFIG), method)(**kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in DENIED:
            return "denied", action
        if code in ("ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId"):
            return "other", f"{action}: {code}"
    except Exception as exc:  # network or client trouble: say so rather than report a false "allowed"
        log.warning("access probe %s failed", action, exc_info=not isinstance(exc, BotoCoreError))
        return "other", f"{action}: {type(exc).__name__}"
    return "ok", action


class _Checks(list):
    """A list of checks that reports each one as it is added, so the console can show live progress."""

    def __init__(self, on_check: Callable[[dict], None] | None):
        super().__init__()
        self.on_check = on_check

    def append(self, check: Check) -> None:
        super().append(check)
        if self.on_check:
            self.on_check(asdict(check))


def run_checks(
    profile: str | None,
    role_name: str | None = None,
    on_check: Callable[[dict], None] | None = None,
    on_progress: Callable[[dict], None] | None = None,
) -> dict:
    """Run every check in STEPS order; on_check gets each result (as a dict) the moment it is known,
    on_progress {id, done, total} while a long check works through the accounts."""
    checks = _Checks(on_check)
    ctx: dict = {"profile": profile, "role_name": role_name}

    def skip(check_id: str, label: str, why: str) -> None:
        checks.append(Check(check_id, label, "skip", why))

    ai = background(_ai_check)  # needs no AWS: test the model while the AWS checks run
    try:
        session = ClientCache(make_session(profile))  # shared by the checks that run at once below
        ident = session.client("sts", config=BOTO_CONFIG).get_caller_identity()
        ctx.update(account_id=ident["Account"], arn=ident["Arn"])
        m = SSO_ROLE_RE.search(ident["Arn"])
        ctx["permission_set"] = m.group("ps") if m else None
        checks.append(Check("identity", "Sign in to AWS", "ok", f"{ident['Arn']} in account {ident['Account']}"))
        # The slowest check, one portal call per account: count while the others run.
        pair = None if role_name else sso.profile_permission_set(profile)
        counted = (
            background(
                lambda: sso.accounts_with_role(
                    pair[0],
                    pair[1],
                    (lambda done, total: on_progress({"id": "assignments", "done": done, "total": total}))
                    if on_progress
                    else None,
                )
            )
            if pair
            else None
        )
    except Exception as exc:
        checks.append(
            _fail(
                "identity",
                "Sign in to AWS",
                exc,
                "",
                "Sign in with AWS sign-in (SSO) at the top, or pick a profile that has credentials.",
            )
        )
        for cid, label in _LATER[:-1]:
            skip(cid, label, "Needs a working sign-in first.")
        checks.append(ai.result())
        return _result(checks, ctx)

    # The Cost Explorer calls depend on nothing: start them now, read them in their turn.
    start, end = month_window(1)
    ce = session.client("ce", region_name="us-east-1", config=BOTO_CONFIG)
    cost_call = background(
        lambda: ce.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["AmortizedCost"],
            # Region too, so the one paid call also proves the multi-region view's data is readable.
            GroupBy=[{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}, {"Type": "DIMENSION", "Key": "REGION"}],
        )
    )
    commit_calls = [
        (action, background(lambda call=call: call(TimePeriod={"Start": start, "End": end})))
        for action, call in (
            ("ce:GetSavingsPlansUtilizationDetails", ce.get_savings_plans_utilization_details),
            ("ce:GetReservationUtilization", ce.get_reservation_utilization),
        )
    ]
    org = session.client("organizations", region_name="us-east-1", config=BOTO_CONFIG)
    try:
        o = org.describe_organization()["Organization"]
        ctx.update(org_id=o["Id"], management_account_id=o["MasterAccountId"])
        is_mgmt = o["MasterAccountId"] == ctx["account_id"]
        checks.append(
            Check(
                "organization",
                "Management account",
                "ok" if is_mgmt else "warn",
                f"Organisation {o['Id']}; management account {o['MasterAccountId']}",
                ""
                if is_mgmt
                else (
                    f"You are in member account {ctx['account_id']}. Sign in to management account "
                    f"{o['MasterAccountId']} (or an Organizations delegated administrator) for the whole estate."
                ),
            )
        )
    except Exception as exc:
        code = describe_exception(exc)[0]
        if code == "AWSOrganizationsNotInUseException":
            checks.append(
                Check("organization", "Management account", "warn", "This account is not in an AWS organisation.")
            )
        else:
            checks.append(_fail("organization", "Management account", exc, "organizations:DescribeOrganization"))

    root_id = None
    try:
        root_id = org.list_roots()["Roots"][0]["Id"]
        ous = org.list_organizational_units_for_parent(ParentId=root_id, MaxResults=20)["OrganizationalUnits"]
        checks.append(
            Check("ou_tree", "Read the OU tree", "ok", f"Root {root_id}; {len(ous)} top-level OU(s) readable")
        )
    except Exception as exc:
        checks.append(
            _fail(
                "ou_tree",
                "Read the OU tree",
                exc,
                "organizations:ListRoots, organizations:ListOrganizationalUnitsForParent",
            )
        )

    member_id = None
    if root_id:
        try:
            accts = org.list_accounts_for_parent(ParentId=root_id, MaxResults=20).get("Accounts", [])
            member_id = next((a["Id"] for a in accts if a["Id"] != ctx.get("account_id")), None)
            checks.append(Check("accounts", "List accounts", "ok", "Account names are readable for the name filter."))
        except Exception as exc:
            checks.append(_fail("accounts", "List accounts", exc, "organizations:ListAccountsForParent"))
    else:
        skip("accounts", "List accounts", "Needs the OU tree.")

    tags_label = "Read account tags"
    if not member_id:
        skip("account_tags", tags_label, "No member account found to test against.")
    else:
        try:
            org.list_tags_for_resource(ResourceId=member_id)
            checks.append(Check("account_tags", tags_label, "ok", "Criticality and product tags are readable."))
        except Exception as exc:
            c = _fail("account_tags", tags_label, exc, "organizations:ListTagsForResource")
            c.status, c.fix = "warn", "Without it, accounts are not grouped by criticality or product tags."
            checks.append(c)

    # The rest at once: the organisation probes and the member account need only what is known by now.
    if ctx.get("management_account_id") == ctx.get("account_id"):
        org_probes = background(lambda: probe_actions(session, ctx["account_id"], ASSURANCE_ORG_PROBES))
    else:
        org_probes = None
    member_checks: list[Check] = []
    member = background(lambda: _member_checks(member_checks, session, profile, role_name, member_id, ctx, counted))

    try:
        resp = cost_call.result()
        groups = resp["ResultsByTime"][0].get("Groups", []) if resp["ResultsByTime"] else []
        n = len({g["Keys"][0] for g in groups})
        n_regions = len({g["Keys"][1] for g in groups if g["Keys"][1] not in ("global", "NoRegion", "")})
        ctx["cost_accounts"] = n
        ctx["cost_regions"] = n_regions
        few = n <= 1 and ctx.get("management_account_id") not in (None, ctx["account_id"])
        checks.append(
            Check(
                "cost",
                "Read Cost Explorer",
                "warn" if few else "ok",
                f"Spend visible for {n} account{'' if n == 1 else 's'} in "
                f"{n_regions} region{'' if n_regions == 1 else 's'} in {start[:7]} (this check cost US$0.01).",
                "A member account sees only its own spend; use the management account." if few else "",
            )
        )
    except Exception as exc:
        code = describe_exception(exc)[0]
        fix = (
            "Turn on Cost Explorer in the management account (Billing and Cost Management > Cost Explorer). "
            "Data appears within 24 hours."
            if code == "DataUnavailableException" or "not enabled" in str(exc).lower()
            else ""
        )
        checks.append(_fail("cost", "Read Cost Explorer", exc, "ce:GetCostAndUsage", fix))

    denied = []
    for action, call in commit_calls:
        try:
            call.result()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in DENIED:
                denied.append(action)
        except Exception:  # not a refusal; the scan treats missing commitment data as "none found"
            log.warning("commitments check %s failed", action, exc_info=True)
    commit_label = "Read Savings Plans and reservations"
    checks.append(
        Check(
            "commitments",
            commit_label,
            "warn" if denied else "ok",
            f"Refused: {', '.join(denied)}" if denied else "Commitment end dates are readable (2 calls, US$0.02).",
            "Without it, the report cannot show commitments that lock spend in." if denied else "",
            ", ".join(denied),
        )
    )

    if org_probes:
        denied, other = org_probes.result()
        what = "The organisation-level assurance checks will show as not measured"
        checks.append(_probe_check("assurance_org", ASSURANCE_ORG_LABEL, ASSURANCE_ORG_PROBES, denied, other,
                                   ctx["account_id"], what, "iam/management-account-policy.json"))  # fmt: skip
    else:
        skip("assurance_org", ASSURANCE_ORG_LABEL, "Only in the management account.")
    member.result()
    for check in member_checks:  # in their order, after the ones above
        checks.append(check)
    checks.append(ai.result())
    return _result(checks, ctx)


def _probe_check(cid, label, probes, denied, other, where, what, policy) -> Check:
    n = len(probes)
    if denied:
        detail = f"{len(denied)} of {n} calls refused in {where}: {', '.join(denied)}"
        fix = f"{what}. Grant them ({policy}), or attach the AWS managed policy SecurityAudit."
    elif other:
        detail, fix = f"Could not finish: {'; '.join(other)}", "Sign in again and re-check."
    else:
        detail, fix = f"All {n} read-only calls allowed in {where}.", ""
    return Check(cid, label, "warn" if denied or other else "ok", detail, fix, ", ".join(denied))


DEEP_LABEL = "Deep scan access (optional)"
INV_LABEL = "Count resources in a member account"
DEP_LABEL = "Read integrations in a member account"
ASSURANCE_LABEL = "Cloud assurance reads in a member account"
ASSURANCE_ORG_LABEL = "Cloud assurance reads in the management account"


ASSIGN_LABEL = "Permission set in every account"
AI_LABEL = "AI review (optional)"


def _member_checks(checks, session, profile, role_name, member_id, ctx, counted=None) -> None:
    """Reach one member account the way a deep scan does, then make every call the scan makes there."""
    pair = None if role_name else sso.profile_permission_set(profile)
    ctx["member_access"] = role_name or (f"permission set {pair[1]}" if pair else None)

    def skip_rest(why: str, assignments: str | None = None) -> None:
        for cid, label in (("inventory_reads", INV_LABEL), ("dependency_reads", DEP_LABEL),
                           ("assurance_reads", ASSURANCE_LABEL)):  # fmt: skip
            checks.append(Check(cid, label, "skip", why))
        if assignments is not None:
            checks.append(Check("assignments", ASSIGN_LABEL, "skip", assignments))
        else:
            _assignment_check(checks, pair, ctx, counted)

    if not role_name and not pair:
        checks.append(
            Check(
                "deep_scan",
                DEEP_LABEL,
                "skip",
                "No member role given; the quick (billing-only) scan does not need one.",
            )
        )
        return skip_rest("Needs deep scan access.", "Only for a deep scan with your own sign-in.")
    try:
        if pair:
            member_id = _member_with_role(pair, member_id, ctx.get("account_id"))
            if not member_id:
                checks.append(
                    Check(
                        "deep_scan",
                        DEEP_LABEL,
                        "warn",
                        f"Permission set {pair[1]} is not assigned to you in the member accounts tried.",
                        f"Assign {pair[1]} in the member accounts to deep-scan, or give a member role to assume.",
                        f"IAM Identity Center assignment of {pair[1]} in member accounts",
                    )
                )
                return skip_rest("Needs deep scan access.")
        elif not member_id:
            checks.append(Check("deep_scan", DEEP_LABEL, "skip", "No member account found to test against."))
            return skip_rest("Needs a member account.", f"Using role {role_name}, not a permission set.")
        member = member_session(session, profile, member_id, role_name, "preflight")
        how = f"Assumed {role_name}" if role_name else f"Signed in with permission set {pair[1]}"
        checks.append(Check("deep_scan", DEEP_LABEL, "ok", f"{how} in member account {member_id}."))
    except Exception as exc:
        checks.append(
            _fail(
                "deep_scan",
                DEEP_LABEL,
                exc,
                f"sts:AssumeRole on arn:aws:iam::*:role/{role_name}" if role_name else "",
                f"Deploy the {role_name} role to member accounts (iam/cloudformation/member-role-stackset.yaml) "
                "and allow sts:AssumeRole on it."
                if role_name
                else "Sign in again with AWS sign-in (SSO) at the top.",
            )
        )
        return skip_rest("Needs deep scan access.", "Needs deep scan access." if role_name else None)

    sets = (
        ("inventory_reads", INV_LABEL, INVENTORY_PROBES, "Inventory scans will miss these"),
        ("dependency_reads", DEP_LABEL, DEPENDENCY_PROBES, "Dependency scans will miss these"),
        ("assurance_reads", ASSURANCE_LABEL, ASSURANCE_PROBES, "The assurance checks will show these as not measured"),
    )
    # The sets at once: every call goes to a different service.
    results = pmap(lambda st: probe_actions(member, member_id, st[2]), sets, workers=len(sets))
    for (cid, label, probes, what), (denied, other) in zip(sets, results, strict=True):
        policy = "iam/member-account-role-policy.json"
        check = _probe_check(cid, label, probes, denied, other, member_id, what, policy)
        if cid != "assurance_reads" and denied:
            check.fix = f"{what}. Grant them ({policy})."
        checks.append(check)
    if role_name:
        checks.append(
            Check(
                "assignments",
                ASSIGN_LABEL,
                "skip",
                f"Using role {role_name}; the scan reports any account where it cannot be assumed.",
            )
        )
    else:
        _assignment_check(checks, pair, ctx, counted)


def _member_with_role(pair: tuple[str, str], preferred: str | None, own: str | None) -> str | None:
    """A member account where the permission set is assigned: the preferred one, else the first of a few."""
    candidates = [preferred] if preferred else []
    candidates += [a for a in sso.portal_account_ids(pair[0]) if a not in (preferred, own)][:10]
    candidates = [a for a in candidates if a]
    has = pmap(lambda a: pair[1] in sso.list_roles(pair[0], a), candidates, workers=max(1, len(candidates)))
    return next((a for a, ok in zip(candidates, has, strict=True) if ok), None)


def _assignment_check(checks, pair, ctx, counted) -> None:
    """Count the accounts where the permission set is assigned: the scan reaches each one with it.
    ``counted`` is that count, started in the background when the checks began."""
    if not pair or counted is None:
        checks.append(Check("assignments", ASSIGN_LABEL, "skip", "Only for a deep scan with your own sign-in."))
        return
    try:
        assigned, reachable = counted.result()
    except Exception as exc:
        checks.append(_fail("assignments", ASSIGN_LABEL, exc, "", "Sign in again and re-check."))
        return
    ctx["permission_set_accounts"] = len(assigned)
    gap = len(reachable) - len(assigned)
    age = sso.role_count_age(pair[0], pair[1])
    when = f" (counted {max(1, round(age / 60))} min ago)" if age and age > 30 else ""
    checks.append(
        Check(
            "assignments",
            ASSIGN_LABEL,
            "warn" if gap else "ok",
            f"{pair[1]} is assigned in {len(assigned)} of the {len(reachable)} accounts your sign-in reaches; "
            f"the other {gap} will not be deep-scanned.{when}"
            if gap
            else f"{pair[1]} is assigned in all {len(assigned)} accounts your sign-in reaches.{when}",
            f"Assign {pair[1]} in the remaining accounts, or give a member role to assume." if gap else "",
            f"IAM Identity Center assignment of {pair[1]} in {gap} more account(s)" if gap else "",
        )
    )


_LATER = [
    ("organization", "Management account"),
    ("ou_tree", "Read the OU tree"),
    ("accounts", "List accounts"),
    ("account_tags", "Read account tags"),
    ("cost", "Read Cost Explorer"),
    ("commitments", "Read Savings Plans and reservations"),
    ("assurance_org", ASSURANCE_ORG_LABEL),
    ("deep_scan", DEEP_LABEL),
    ("inventory_reads", INV_LABEL),
    ("dependency_reads", DEP_LABEL),
    ("assurance_reads", ASSURANCE_LABEL),
    ("assignments", ASSIGN_LABEL),
    ("ai", AI_LABEL),
]
# Checks a quick scan can do without: a failure there is a warning, not "Not ready".
OPTIONAL = {"account_tags", "commitments", "deep_scan", "inventory_reads", "dependency_reads", "assurance_org",
            "assurance_reads", "assignments", "ai"}  # fmt: skip
# Every run reports exactly these checks, in this order (skipped ones included).
STEPS = [("identity", "Sign in to AWS"), *_LATER]


def _ai_check() -> Check:
    """The optional AI review: the saved provider answers the same small reasoning test as in its dialog."""
    from .ai import providers as ai

    fix = "Open AI review in the top bar to change the provider, model or key."
    if not ai.settings_saved():
        return Check("ai", AI_LABEL, "skip", "Not set up. Optional: choose a provider from AI review in the top bar.")
    s = ai.load_settings()
    label = ai.PROVIDERS[s.provider].label
    try:
        got = ai.test_connection(s)
    except Exception as exc:  # any failure here is a warning: the scan itself does not need the AI review
        return Check("ai", AI_LABEL, "warn", f"{label}: {exc}", fix)
    return Check("ai", AI_LABEL, "ok", f"{got['model']} on {label} answered a reasoning test in {got['seconds']} s.")


def _result(checks: list[Check], ctx: dict) -> dict:
    if not any(c.id == "ai" for c in checks):
        checks.append(_ai_check())  # last on every path, whatever happened with AWS
    required = [c for c in checks if c.id not in OPTIONAL]
    ready = all(c.status == "ok" for c in required)
    gaps = [c for c in checks if c.id in OPTIONAL and c.status in ("warn", "fail")]
    partial = not ready and all(c.status in ("ok", "warn") for c in required)
    verdict = (
        f"Ready for a quick scan; {len(gaps)} optional check(s) show missing permissions, listed below."
        if ready and gaps
        else "Ready: a scan will cover the whole organisation."
        if ready
        else "Usable, but the scan will not cover the whole organisation - see the warnings."
        if partial
        else "Not ready: fix the items marked ✗, or send the request below to your AWS administrator."
    )
    log.info("access check for profile %s: %s", ctx.get("profile"), verdict)
    out = {"ready": ready, "partial": partial, "verdict": verdict, "checks": [asdict(c) for c in checks], **ctx}
    out["admin_request"] = admin_request(out)
    return out


def admin_request(result: dict) -> str:
    """Plain-text message for the AWS administrator, specific to what failed."""
    missing = [c for c in result["checks"] if c["status"] in ("fail", "warn") and c["needs"]]
    member_gaps = [c for c in missing if c["id"] in ("inventory_reads", "dependency_reads", "assurance_reads")]
    missing = [c for c in missing if c not in member_gaps]
    wrong_account = any(c["id"] == "organization" and c["status"] == "warn" for c in result["checks"])
    mgmt = result.get("management_account_id") or "<management account id>"
    who = result.get("arn") or "<my identity>"
    ps = result.get("permission_set")
    lines = [
        "Subject: Read-only AWS access for the cloud exit-risk review",
        "",
        "Hi,",
        "",
        "I'm running the AWS exit-risk review (https://github.com/andrewbakercloudscale/"
        "aws-regulatory-risk-review-framework). It is read-only: it reads the account list and Cost Explorer "
        "spend by account and service. It changes nothing and reads no data inside accounts.",
        "",
    ]
    if wrong_account:
        lines += [f"I need access in the organisation's management account, {mgmt}.", ""]
    if missing:
        lines += ["Today these calls are refused for " + who + ":"]
        lines += [f"  - {c['needs']}  ({c['label']})" for c in missing]
        lines += [""]
    if ps:
        lines += [
            "Easiest with IAM Identity Center: add the inline policy below to a permission set (the one I use is "
            f"'{ps}', or a new one such as 'ExitRiskReadOnly') and assign it to me in account {mgmt}.",
            "Alternatively attach the AWS-managed policies AWSOrganizationsReadOnlyAccess and "
            "AWSBillingReadOnlyAccess to that permission set.",
        ]
    else:
        lines += [
            f"Please attach the policy below to my role or user in account {mgmt}, or create an IAM Identity Center "
            "permission set with it and assign it to me there.",
        ]
    lines += [
        "",
        "Policy (also in the repo as iam/management-account-policy.json; Terraform and CloudFormation versions "
        "are in iam/identity-center/):",
        "",
        json.dumps(MANAGEMENT_POLICY, indent=2),
        "",
    ]
    if member_gaps:
        access = result.get("member_access") or "the deep-scan role"
        lines += [
            f"For the deep scan, {access} in the member accounts is refused these read-only calls "
            "(they list and count resources; no data or configuration is stored):",
        ]
        lines += [f"  - {a}" for c in member_gaps for a in c["needs"].split(", ")]
        lines += [
            "Please add them to that role or permission set in every member account. The full member policy is "
            "iam/member-account-role-policy.json (StackSet: iam/cloudformation/member-role-stackset.yaml).",
            "",
        ]
        if any(c["id"] == "assurance_reads" for c in member_gaps):
            lines += [
                "The Cloud Assurance Framework checks read security settings (IAM, S3, CloudTrail, GuardDuty, Security "
                "Hub, Config, backups and more). The simplest grant is the AWS managed policy SecurityAudit "
                "(arn:aws:iam::aws:policy/SecurityAudit) on the same role or permission set; it is read-only.",
                "",
            ]
    lines += [
        "Cost: Cost Explorer API calls are US$0.01 each, about 2 per 100 accounts per scan.",
        "",
        "Thanks",
    ]
    return "\n".join(lines)
