"""Issues found during a scan, and translation of AWS errors into actionable advice.

A scan never fails silently: every API failure becomes an ``Issue`` that is logged,
stored with the scan and shown on the dashboard's "Data quality & issues" panel, so a
reader can see what the score does *not* cover.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    ProfileNotFound,
    SSOTokenLoadError,
    TokenRetrievalError,
    UnauthorizedSSOTokenError,
)

SEVERITIES = ("info", "warning", "error", "critical")


@dataclass
class Issue:
    severity: str
    category: str
    message: str
    hint: str = ""
    account_id: str | None = None
    service: str | None = None
    region: str | None = None
    error_code: str | None = None
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        return asdict(self)


_HINTS = {
    "AccessDeniedException": "The caller lacks permission for this API. See docs/IAM_PERMISSIONS.md.",
    "AccessDenied": "The caller lacks permission for this API. See docs/IAM_PERMISSIONS.md.",
    "AWSOrganizationsNotInUseException": (
        "This account is not part of an AWS Organization; scanning it as a single account."
    ),
    "DataUnavailableException": (
        "Cost Explorer has no data yet. Enable Cost Explorer in the management account (takes up to 24h)."
    ),
    "ExpiredToken": "The session expired. Re-run the scan; aws-cli-zsp will prompt for Touch ID.",
    "ExpiredTokenException": "The session expired. Re-run the scan; aws-cli-zsp will prompt for Touch ID.",
    "UnrecognizedClientException": (
        "The credentials were rejected. Check the profile with `aws sts get-caller-identity`."
    ),
    "InvalidClientTokenId": "The credentials were rejected. Check the profile with `aws sts get-caller-identity`.",
    "ThrottlingException": (
        "AWS throttled the request after retries. Wait a minute and re-run; for a deep scan, "
        "lower EXITRISK_MAX_WORKERS."
    ),
    "LimitExceededException": "Cost Explorer request limit reached. Wait a minute and re-run.",
    "RequestExpired": "Local clock skew. Check the system time.",
    "OptInRequired": "Region not enabled for this account; skipped.",
}


def describe_exception(exc: BaseException) -> tuple[str, str, str]:
    """Return (error_code, message, hint) for any exception raised by boto3."""
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = err.get("Code", "ClientError")
        return code, err.get("Message", str(exc)), _HINTS.get(code, "")
    if isinstance(exc, ProfileNotFound):
        return "ProfileNotFound", str(exc), "Check the profile name in ~/.aws/config (`aws configure list-profiles`)."
    if isinstance(exc, NoCredentialsError):
        return (
            "NoCredentials",
            str(exc),
            "No credentials resolved for this profile. If you use aws-cli-zsp, check its menu-bar status.",
        )
    if isinstance(exc, (SSOTokenLoadError, UnauthorizedSSOTokenError)):
        return "SSOToken", str(exc), "Not signed in to AWS SSO (or the sign-in expired). Use AWS sign-in at the top."
    if isinstance(exc, TokenRetrievalError):
        return "TokenRetrieval", str(exc), "SSO/credential-process token could not be refreshed; log in again."
    if isinstance(exc, EndpointConnectionError):
        return "EndpointConnection", str(exc), "Network error reaching AWS. Check connectivity / proxy settings."
    name = type(exc).__name__
    text = str(exc)
    if "credential_process" in text or "CredentialRetrievalError" in name:
        return name, text, "The credential process failed or was cancelled (was the Touch ID prompt dismissed?)."
    return name, text, ""


def is_fatal_auth_error(code: str) -> bool:
    return code in {
        "ExpiredToken",
        "ExpiredTokenException",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "NoCredentials",
        "ProfileNotFound",
        "TokenRetrieval",
        "SSOToken",
        "CredentialRetrievalError",
    }
