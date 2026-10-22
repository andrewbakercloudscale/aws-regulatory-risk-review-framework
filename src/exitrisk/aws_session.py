"""boto3 sessions.

Credentials come from a named profile in ``~/.aws/config``. That includes profiles backed
by a ``credential_process`` such as aws-cli-zsp: boto3 runs the process, the user approves
with Touch ID once, and the 1-hour session it returns is reused for the whole scan. The
tool never reads, stores or logs the keys themselves.
"""

from __future__ import annotations

import boto3
import botocore.session
from botocore.config import Config

from .logging_config import get_logger

log = get_logger("aws")

# Adaptive retries handle Cost Explorer / Organizations throttling without failing the scan.
BOTO_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
    user_agent_extra="aws-regulatory-risk-review-framework",
)


def available_profiles() -> list[str]:
    try:
        return sorted(botocore.session.Session().available_profiles)
    except Exception:  # a malformed ~/.aws/config must not take the console down
        log.exception("could not read AWS profiles")
        return []


def profile_accounts() -> dict[str, str]:
    """Account id per profile where the config states it (SSO profiles carry sso_account_id)."""
    try:
        profiles = botocore.session.Session().full_config.get("profiles", {})
    except Exception:
        log.exception("could not read AWS profiles")
        return {}
    return {name: str(cfg["sso_account_id"]) for name, cfg in profiles.items() if cfg.get("sso_account_id")}


def make_session(profile: str | None, region: str | None = None) -> boto3.Session:
    return boto3.Session(profile_name=profile or None, region_name=region)


def caller_identity(session: boto3.Session) -> dict:
    ident = session.client("sts", config=BOTO_CONFIG).get_caller_identity()
    return {"account_id": ident["Account"], "arn": ident["Arn"]}


def assume_role_session(base: boto3.Session, account_id: str, role_name: str, run_id: str) -> boto3.Session:
    """Session in a member account via a read-only role (e.g. a custom ExitRiskReadOnly role)."""
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    creds = base.client("sts", config=BOTO_CONFIG).assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"exitrisk-{run_id}"[:64],
        DurationSeconds=3600,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def member_session(
    base: boto3.Session, profile: str | None, account_id: str, role_name: str | None, run_id: str
) -> boto3.Session:
    """Session in a member account: assume ``role_name`` if given, else use the profile's own IAM
    Identity Center permission set in that account (it must be assigned there)."""
    if role_name:
        return assume_role_session(base, account_id, role_name, run_id)
    from . import sso  # here, not at import time: sso imports this module

    pair = sso.profile_permission_set(profile)
    if not pair:
        raise ValueError("no member role given and the profile is not an IAM Identity Center profile")
    return sso.role_session(pair[0], account_id, pair[1])
