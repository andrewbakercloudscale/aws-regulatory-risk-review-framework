"""boto3 sessions.

Credentials come from a named profile in ``~/.aws/config``. That includes profiles backed
by a ``credential_process`` such as aws-cli-zsp: boto3 runs the process, the user approves
with Touch ID once, and the 1-hour session it returns is reused for the whole scan. The
tool never reads, stores or logs the keys themselves.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable

import boto3
import botocore.session
from botocore.config import Config
from botocore.exceptions import ClientError

from .logging_config import get_logger

log = get_logger("aws")

# Adaptive retries handle Cost Explorer / Organizations throttling without failing the scan.
BOTO_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
    # One pool per AWS endpoint, shared by every account's clients (ClientCache), so it needs room for
    # the calls of several accounts at once.
    max_pool_connections=64,
    user_agent_extra="aws-regulatory-risk-review-framework",
)


# Throttling that botocore's own retries miss: some services (Trusted Advisor) answer 429 with a
# combined code such as "ThrottlingException, TooManyRequestsException", which matches none of its
# known codes, so the call fails at once. with_backoff retries those with exponential backoff.
_THROTTLE_MARKS = ("throttl", "toomanyrequests", "requestlimitexceeded", "slowdown", "ratelimit")
BACKOFF_ATTEMPTS = 7
BACKOFF_BASE = 1.0
BACKOFF_CAP = 30.0


def is_throttle(exc: BaseException) -> bool:
    if not isinstance(exc, ClientError):
        return False
    err = exc.response.get("Error", {})
    code = str(err.get("Code", "")).replace(" ", "").lower()
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return (
        status == 429
        or any(m in code for m in _THROTTLE_MARKS)
        or "too many requests" in str(err.get("Message", "")).lower()
    )


def with_backoff(fn: Callable, *args, attempts: int = BACKOFF_ATTEMPTS, sleep: Callable = time.sleep, **kwargs):
    """fn(*args, **kwargs), retried on throttling after 1, 2, 4 ... seconds (capped, with jitter)."""
    for attempt in range(attempts):
        try:
            return fn(*args, **kwargs)
        except ClientError as exc:
            if not is_throttle(exc) or attempt == attempts - 1:
                raise
            wait = min(BACKOFF_CAP, BACKOFF_BASE * 2**attempt) * random.uniform(0.5, 1.0)  # noqa: S311 (jitter)
            log.info("throttled (%s), retrying in %.1fs", exc.response.get("Error", {}).get("Code", ""), wait)
            sleep(wait)
    raise AssertionError("unreachable")


class ClientCache:
    """One client per (service, region) of a session, for many threads at once.

    A boto3 session is not thread safe but its clients are, so clients are made under a lock and
    then shared: a deep scan's probes and dependency reads in one region reuse one connection pool.
    Stands in for the session wherever only ``.client()`` is called.
    """

    def __init__(self, session: boto3.Session):
        self.session = session
        self._lock = threading.Lock()
        self._clients: dict[tuple, object] = {}

    def client(self, service: str, region_name: str | None = None, config: Config | None = None):
        with self._lock:
            key = (service, region_name)
            if key not in self._clients:
                client = self.session.client(service, region_name=region_name, config=config or BOTO_CONFIG)
                if config is None:
                    _share_connections(client)
                self._clients[key] = client
            return self._clients[key]


# The connections of every BOTO_CONFIG client in this process. A deep scan makes new clients for each
# account (new credentials), and each client would open its own connections: hundreds of TLS handshakes
# per account, which a TLS-inspecting corporate proxy makes take seconds each. A connection carries no
# identity (every request is signed on its own), so all accounts share one pool per endpoint instead.
_http = None
_http_lock = threading.Lock()


def _share_connections(client) -> None:
    global _http
    endpoint = getattr(client, "_endpoint", None)
    if endpoint is None or not hasattr(endpoint, "http_session"):  # a botocore without it: keep its own
        return
    with _http_lock:
        if _http is None:
            _http = endpoint.http_session  # made from BOTO_CONFIG, the CA bundle and proxy settings
        endpoint.http_session = _http


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
