"""Check access before a scan, and write the request to send to an AWS administrator.

Each check makes the same read-only call a scan would, so "all green" here means the scan will
see the whole organisation. A failed check carries the exact fix; the admin request turns the
failures into a message that names the account, the identity and the policy to attach.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass

from .aws_session import BOTO_CONFIG, assume_role_session, make_session
from .collectors.cost import month_window
from .issues import describe_exception
from .logging_config import get_logger

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
            ],
            "Resource": "*",
        },
        {"Sid": "ReadCostAndUsage", "Effect": "Allow", "Action": "ce:GetCostAndUsage", "Resource": "*"},
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
    return Check(check_id, label, "fail", f"{code}: {msg}", fix or hint, needs)


def run_checks(profile: str | None, role_name: str | None = None) -> dict:
    checks: list[Check] = []
    ctx: dict = {"profile": profile, "role_name": role_name}

    def skip(check_id: str, label: str, why: str) -> None:
        checks.append(Check(check_id, label, "skip", why))

    try:
        session = make_session(profile)
        ident = session.client("sts", config=BOTO_CONFIG).get_caller_identity()
        ctx.update(account_id=ident["Account"], arn=ident["Arn"])
        m = SSO_ROLE_RE.search(ident["Arn"])
        ctx["permission_set"] = m.group("ps") if m else None
        checks.append(Check("identity", "Sign in to AWS", "ok", f"{ident['Arn']} in account {ident['Account']}"))
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
        for cid, label in _LATER:
            skip(cid, label, "Needs a working sign-in first.")
        return _result(checks, ctx)

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
                f"Organization {o['Id']}; management account {o['MasterAccountId']}",
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
                Check("organization", "Management account", "warn", "This account is not in an AWS Organization.")
            )
        else:
            checks.append(_fail("organization", "Management account", exc, "organizations:DescribeOrganization"))

    root_id = None
    try:
        root_id = org.list_roots()["Roots"][0]["Id"]
        checks.append(Check("ou_tree", "Read the OU tree", "ok", f"Root {root_id}"))
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

    start, end = month_window(1)
    try:
        resp = session.client("ce", region_name="us-east-1", config=BOTO_CONFIG).get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["AmortizedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}],
        )
        n = len(resp["ResultsByTime"][0].get("Groups", [])) if resp["ResultsByTime"] else 0
        ctx["cost_accounts"] = n
        few = n <= 1 and ctx.get("management_account_id") not in (None, ctx["account_id"])
        checks.append(
            Check(
                "cost",
                "Read Cost Explorer",
                "warn" if few else "ok",
                f"Spend visible for {n} account(s) in {start[:7]} (this check cost US$0.01).",
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

    if not role_name:
        skip("deep_scan", "Deep scan role (optional)", "No member role given; the spend-only scan does not need one.")
    elif not member_id:
        skip("deep_scan", "Deep scan role (optional)", "No member account found to test against.")
    else:
        try:
            assume_role_session(session, member_id, role_name, "preflight")
            checks.append(Check("deep_scan", "Deep scan role (optional)", "ok", f"Assumed {role_name} in {member_id}."))
        except Exception as exc:
            checks.append(
                _fail(
                    "deep_scan",
                    "Deep scan role (optional)",
                    exc,
                    f"sts:AssumeRole on arn:aws:iam::*:role/{role_name}",
                    f"Deploy the {role_name} role to member accounts (iam/cloudformation/member-role-stackset.yaml) "
                    "and allow sts:AssumeRole on it.",
                )
            )
    return _result(checks, ctx)


_LATER = [
    ("organization", "Management account"),
    ("ou_tree", "Read the OU tree"),
    ("accounts", "List accounts"),
    ("cost", "Read Cost Explorer"),
    ("deep_scan", "Deep scan role (optional)"),
]


def _result(checks: list[Check], ctx: dict) -> dict:
    required = [c for c in checks if c.id != "deep_scan"]
    ready = all(c.status == "ok" for c in required)
    partial = not ready and all(c.status in ("ok", "warn") for c in required)
    verdict = (
        "Ready: a scan will cover the whole organisation."
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
    missing = [c for c in result["checks"] if c["status"] == "fail" and c["needs"]]
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
        lines += [f"I need access in the organization's management account, {mgmt}.", ""]
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
        "Cost: Cost Explorer API calls are US$0.01 each, about 2 per 100 accounts per scan.",
        "",
        "Thanks",
    ]
    return "\n".join(lines)
