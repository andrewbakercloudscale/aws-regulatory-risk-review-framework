"""Synthetic Developer Compromise reads for the demo organisation, shaped as collectors/compromise.py writes them."""

from __future__ import annotations

import random

from .collectors.compromise import ACTIONS

DEV = "permission set Developer"
DBA = "permission set DatabaseAdmin"
OPS = "permission set PlatformOps"


def _account(rng: random.Random, name: str, region: str) -> dict:
    acct = name.split("-")[0]
    assets = [
        {
            "id": f"bucket:{region}:{acct}-payment-files",
            "kind": "bucket",
            "name": f"{acct}-payment-files",
            "region": region,
            "arn": f"arn:aws:s3:::{acct}-payment-files",
            "payment": True,
            "facts": {"versioning": rng.random() < 0.6, "object_lock": "", "eventbridge": False},
        },
        {
            "id": f"table:{region}:ledger",
            "kind": "table",
            "name": "ledger",
            "region": region,
            "arn": f"arn:aws:dynamodb:{region}:1:table/ledger",
            "payment": True,
            "facts": {},
        },
        {
            "id": f"database:{region}:{acct}-payments-db",
            "kind": "database",
            "name": f"{acct}-payments-db",
            "region": region,
            "arn": f"arn:aws:rds:{region}:1:db:{acct}-payments-db",
            "payment": True,
            "facts": {
                "engine": "postgres",
                "iam_auth": True,
                "data_api": False,
                "activity_stream": False,
                "public": False,
            },
        },
        {
            "id": f"function:{region}:pay-out",
            "kind": "function",
            "name": "pay-out",
            "region": region,
            "arn": f"arn:aws:lambda:{region}:1:function:pay-out",
            "payment": True,
            "facts": {"code_signing": False},
        },
        {
            "id": f"signing key:{region}:payment signer",
            "kind": "signing key",
            "name": "payment signer",
            "region": region,
            "arn": f"arn:aws:kms:{region}:1:key/k",
            "payment": True,
            "facts": {"usage": "SIGN_VERIFY"},
        },
        {
            "id": f"api:{region}:channel-api",
            "kind": "api",
            "name": "channel-api",
            "region": region,
            "arn": f"arn:aws:execute-api:{region}:1:a/*",
            "payment": False,
            "facts": {"private": False, "restricted": False, "open": ["POST /callback"]},
        },
        {
            "id": "account:blind",
            "kind": "account",
            "name": "audit trail and threat detection",
            "region": "global",
            "arn": "*",
            "payment": False,
            "facts": {},
        },
    ]
    paths = []

    def can(who, asset, action, decision="allowed"):
        paths.append(
            {
                "principal": who,
                "kind": "person",
                "asset": asset,
                "action": action,
                "call": ACTIONS[action][1][0],
                "decision": decision,
                "why": "dev-inline",
            }
        )

    can(DEV, assets[0]["id"], "s3_write")
    can(DEV, assets[3]["id"], "fn_code")
    can(DBA, assets[2]["id"], "db_secret")
    can(DBA, assets[2]["id"], "db_iam", "network" if rng.random() < 0.5 else "allowed")
    if rng.random() < 0.5:
        can(OPS, assets[4]["id"], "key_sign")
    can(OPS, assets[1]["id"], "ddb_write")
    paths.append(
        {
            "principal": OPS,
            "kind": "person",
            "asset": "account:blind",
            "action": "blind",
            "call": "cloudtrail:StopLogging",
            "decision": "blocked",
            "why": "an organisation guardrail (SCP) denies it",
        }
    )
    principals = [
        {"arn": "arn:dev", "name": "Developer", "kind": "person", "label": DEV, "weak": None, "hours": 12.0},
        {"arn": "arn:dba", "name": "DatabaseAdmin", "kind": "person", "label": DBA, "weak": None, "hours": 1.0},
        {"arn": "arn:ops", "name": "PlatformOps", "kind": "person", "label": OPS, "weak": None, "hours": 8.0},
        {
            "arn": "arn:gh",
            "name": "github-deploy",
            "kind": "pipeline",
            "label": "pipeline role github-deploy (GitHub)",
            "weak": "GitHub subject allows every branch and tag (repo:bank/payments:*)" if rng.random() < 0.5 else None,
            "hours": 1.0,
        },
    ]
    changes = [
        {
            "who": OPS,
            "tool": "AWS CLI",
            "action": "lambda:UpdateFunctionConfiguration20150331v2",
            "region": region,
            "count": rng.randint(1, 9),
            "last": "2026-10-30T19:56:00+00:00",
            "resource": "pay-out",
            "ips": [],
        },
        {
            "who": DEV,
            "tool": "Console",
            "action": "s3:PutBucketPolicy",
            "region": region,
            "count": 2,
            "last": "2026-10-21T08:10:00+00:00",
            "resource": f"{acct}-payment-files",
            "ips": [],
        },
    ]
    return {
        "principals": principals,
        "assets": assets,
        "paths": paths,
        "exposures": [
            {"rule": "api_open", "asset": assets[5]["id"], "note": "1 method(s) with no sign-in: POST /callback"}
        ],
        "changes": changes,
        "detect": {
            "trails": [
                {
                    "name": "org-trail",
                    "org": True,
                    "multi": True,
                    "home": region,
                    "logging": True,
                    "read": True,
                    "selectors": [{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}],
                }
            ],
            "guardduty": {region: {"on": True, "features": []}},
            "rules": [],
        },
        "checks": {k: {"status": "pass", "note": ""} for k in ("identities", "buckets", "trails", "access")},
        "facts": {"root": {"mfa": True, "keys": False}},
        "regions": [region],
        "read_at": "",
        "seconds": 1.0,
    }


def build(accounts: list[dict], seed: int = 31) -> dict:
    """Reads for up to five production accounts that look like payment or channel accounts."""
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic data, not security
    picked = [a for a in accounts if "prod" in a["name"] and a.get("status") == "ACTIVE"][:5]
    out = {a["id"]: _account(rng, a["name"], rng.choice(["eu-west-1", "af-south-1"])) for a in picked}
    return {"accounts": out, "selected": sorted(out)}
