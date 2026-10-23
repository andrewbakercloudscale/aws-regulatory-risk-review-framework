"""AWS IAM Identity Center (SSO) sign-in from the console.

This does what ``aws sso login`` does, so the analyst never needs a terminal:

1. register a public OIDC client and start the device authorisation for the portal;
2. the browser opens AWS's own approval page (the analyst signs in there, never here);
3. a background thread polls for the token and writes it to the AWS CLI's SSO cache
   (``~/.aws/sso/cache``) in the CLI's own format, so boto3, the AWS CLI and this tool all
   share one sign-in.

The token stays on disk where the CLI keeps it and is never returned to the browser. Profiles
are written to ``~/.aws/config`` only when the analyst asks for one ("Use for scans").
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
import botocore
import botocore.session
from botocore.config import Config
from botocore.exceptions import ClientError

from .aws_session import BOTO_CONFIG
from .logging_config import get_logger
from .parallel import pmap

log = get_logger("sso")

# Regions where IAM Identity Center can live; probed in this order to find a portal's home.
CANDIDATE_REGIONS = [
    "eu-west-1", "us-east-1", "af-south-1", "eu-central-1", "eu-west-2", "us-west-2", "us-east-2",
    "ap-southeast-2", "ap-southeast-1", "ap-northeast-1", "ap-south-1", "ca-central-1", "eu-north-1",
    "eu-west-3", "eu-south-1", "me-south-1", "sa-east-1", "ap-northeast-2", "ap-east-1", "us-west-1",
]  # fmt: skip
SCOPES = ["sso:account:access"]
# Renew the hour-long access token this many minutes before it ends (the AWS CLI uses 15).
REFRESH_MINUTES = 10
_refresh_lock = threading.Lock()
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
START_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(/start)?/?(#.*)?$")
UNSIGNED = Config(signature_version=botocore.UNSIGNED, retries={"max_attempts": 5, "mode": "standard"})


class SSOFailure(RuntimeError):
    """A sign-in step failed; the message is safe to show in the console."""


def config_path() -> Path:
    return Path(os.environ.get("AWS_CONFIG_FILE", "~/.aws/config")).expanduser()


def cache_dir() -> Path:
    return Path(os.environ.get("EXITRISK_SSO_CACHE_DIR", "~/.aws/sso/cache")).expanduser()


def _cache_file(session_name: str) -> Path:
    # Same key the AWS CLI and botocore use for an [sso-session] token.
    return cache_dir() / f"{hashlib.sha1(session_name.encode(), usedforsecurity=False).hexdigest()}.json"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _full_config() -> dict:
    return botocore.session.Session().full_config


def _oidc(region: str):
    return boto3.client("sso-oidc", region_name=region, config=UNSIGNED)


def _portal(region: str):
    return boto3.client("sso", region_name=region, config=UNSIGNED)


# ---------------------------------------------------------------- sessions and tokens


def load_token(session_name: str) -> dict | None:
    """The cached token if it is valid for at least a minute more, else None. An access token lasts
    an hour; one about to expire is renewed with the sign-in's refresh token, as the AWS CLI does, so
    a long deep scan keeps going for as long as the IAM Identity Center session allows."""
    data = _read_token(session_name)
    if data and data["_expires"] > _now() + timedelta(minutes=REFRESH_MINUTES):
        return data
    with _refresh_lock:  # one renewal, however many scan threads find the token stale
        data = _read_token(session_name)
        if data and data["_expires"] <= _now() + timedelta(minutes=REFRESH_MINUTES):
            data = _refresh(session_name, data) or data
    return data if data and data["_expires"] > _now() + timedelta(seconds=60) else None


def _read_token(session_name: str) -> dict | None:
    try:
        data = json.loads(_cache_file(session_name).read_text())
        data["_expires"] = datetime.strptime(data["expiresAt"].replace("UTC", "Z"), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (OSError, ValueError, KeyError):
        return None
    return data


def _refresh(session_name: str, data: dict) -> dict | None:
    """Renew the access token with the refresh token; None when there is none or AWS says no (the
    Identity Center session has ended: sign in again)."""
    if not all(data.get(k) for k in ("refreshToken", "clientId", "clientSecret", "region")):
        return None
    try:
        tok = _oidc(data["region"]).create_token(
            clientId=data["clientId"],
            clientSecret=data["clientSecret"],
            grantType="refresh_token",
            refreshToken=data["refreshToken"],
        )
    except Exception as exc:
        log.info("SSO token for %s could not be renewed: %s", session_name, exc)
        return None
    out = {k: v for k, v in data.items() if k != "_expires"} | {
        "accessToken": tok["accessToken"],
        "expiresAt": _iso(_now() + timedelta(seconds=tok["expiresIn"])),
        "refreshToken": tok.get("refreshToken") or data["refreshToken"],
    }
    _save_token(session_name, out)
    log.info("SSO token for %s renewed until %s", session_name, out["expiresAt"])
    return _read_token(session_name)


def list_sessions() -> list[dict]:
    cfg = _full_config()
    profiles = cfg.get("profiles", {})
    out = []
    for name, s in sorted(cfg.get("sso_sessions", {}).items()):
        token = load_token(name)
        out.append(
            {
                "name": name,
                "start_url": s.get("sso_start_url", ""),
                "region": s.get("sso_region", ""),
                "signed_in": bool(token),
                "expires_at": token["expiresAt"] if token else None,
                "profiles": [
                    {"name": p, "account_id": v.get("sso_account_id"), "role": v.get("sso_role_name")}
                    for p, v in sorted(profiles.items())
                    if v.get("sso_session") == name
                ],
            }
        )
    return out


def _session_config(session_name: str) -> dict:
    s = _full_config().get("sso_sessions", {}).get(session_name)
    if not s or not s.get("sso_start_url") or not s.get("sso_region"):
        raise SSOFailure(f"SSO session {session_name!r} is not configured in {config_path()}")
    return s


def detect_region(start_url: str) -> str:
    """Find the region hosting the portal: only its home region accepts a device authorisation."""
    for region in CANDIDATE_REGIONS:
        try:
            client = _oidc(region)
            reg = client.register_client(clientName="exitrisk-region-probe", clientType="public")
            client.start_device_authorization(
                clientId=reg["clientId"], clientSecret=reg["clientSecret"], startUrl=start_url
            )
            log.info("SSO portal %s is in %s", start_url, region)
            return region
        except ClientError:
            continue
        except Exception as exc:  # network trouble in one region must not stop the search
            log.warning("region probe %s failed: %s", region, exc)
    raise SSOFailure("Could not find the portal's region. Check the start URL (it ends in /start).")


def _append_config(block: str) -> None:
    path = config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    existing = path.read_text() if path.exists() else ""
    sep = "" if not existing or existing.endswith("\n\n") else ("\n" if existing.endswith("\n") else "\n\n")
    with open(path, "a") as fh:
        fh.write(sep + block.strip() + "\n")
    os.chmod(path, 0o600)


def add_session(name: str, start_url: str, region: str | None = None) -> dict:
    """Add an ``[sso-session]`` block, as ``aws configure sso`` would."""
    start_url = start_url.strip().split("#")[0].rstrip("/")
    if not NAME_RE.fullmatch(name):
        raise SSOFailure("Session name: letters, digits, '.', '_' and '-' only.")
    if not START_URL_RE.match(start_url):
        raise SSOFailure("Start URL looks wrong; it is like https://d-1234567890.awsapps.com/start")
    if name in _full_config().get("sso_sessions", {}):
        raise SSOFailure(f"An SSO session called {name!r} already exists.")
    region = region or detect_region(start_url)
    _append_config(
        f"[sso-session {name}]\nsso_start_url = {start_url}\nsso_region = {region}\n"
        f"sso_registration_scopes = {','.join(SCOPES)}"
    )
    log.info("added SSO session %s (%s, %s) to %s", name, start_url, region, config_path())
    return {"name": name, "start_url": start_url, "region": region}


# ---------------------------------------------------------------- device sign-in


@dataclass
class Login:
    id: str
    session: str
    status: str = "pending"  # pending | complete | failed | expired
    verification_uri: str = ""
    user_code: str = ""
    expires_at: float = 0.0
    message: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict:
        with self._lock:
            return {f.name: getattr(self, f.name) for f in fields(self) if not f.name.startswith("_")}


_LOGINS: dict[str, Login] = {}


def get_login(login_id: str) -> Login | None:
    return _LOGINS.get(login_id)


def start_login(session_name: str) -> Login:
    s = _session_config(session_name)
    region, start_url = s["sso_region"], s["sso_start_url"]
    client = _oidc(region)
    try:
        reg = client.register_client(clientName="aws-regulatory-risk-review", clientType="public", scopes=SCOPES)
        auth = client.start_device_authorization(
            clientId=reg["clientId"], clientSecret=reg["clientSecret"], startUrl=start_url
        )
    except ClientError as exc:
        raise SSOFailure(f"AWS refused to start the sign-in: {exc.response['Error'].get('Message', exc)}") from exc
    login = Login(
        id=uuid.uuid4().hex[:12],
        session=session_name,
        verification_uri=auth["verificationUriComplete"],
        user_code=auth["userCode"],
        expires_at=time.time() + auth["expiresIn"],
    )
    _LOGINS[login.id] = login
    threading.Thread(
        target=_poll, args=(login, client, reg, auth, start_url, region), name=f"sso-{login.id}", daemon=True
    ).start()
    log.info("SSO sign-in %s started for session %s", login.id, session_name)
    return login


def _poll(login: Login, client, reg: dict, auth: dict, start_url: str, region: str) -> None:
    interval = auth.get("interval", 5)
    while time.time() < login.expires_at:
        time.sleep(interval)
        try:
            tok = client.create_token(
                clientId=reg["clientId"],
                clientSecret=reg["clientSecret"],
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=auth["deviceCode"],
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AuthorizationPendingException":
                continue
            if code == "SlowDownException":
                interval += 5
                continue
            _finish(login, "failed", f"Sign-in was not completed ({code}).")
            log.warning("SSO sign-in %s failed: %s", login.id, code)
            return
        except Exception as exc:
            _finish(login, "failed", f"Sign-in failed: {exc}")
            log.exception("SSO sign-in %s crashed", login.id)
            return
        try:
            _write_token(login.session, start_url, region, reg, tok)
        except OSError as exc:
            _finish(login, "failed", f"Signed in, but the token could not be saved: {exc.strerror or exc}.")
            log.exception("SSO sign-in %s could not save its token", login.id)
            return
        _finish(login, "complete", "Signed in.")
        log.info("SSO sign-in %s complete for session %s", login.id, login.session)
        return
    _finish(login, "expired", "The sign-in window expired. Start again.")


def _finish(login: Login, status: str, message: str) -> None:
    with login._lock:
        login.status, login.message = status, message


def _write_token(session_name: str, start_url: str, region: str, reg: dict, tok: dict) -> None:
    data = {
        "startUrl": start_url,
        "region": region,
        "accessToken": tok["accessToken"],
        "expiresAt": _iso(_now() + timedelta(seconds=tok["expiresIn"])),
        "clientId": reg["clientId"],
        "clientSecret": reg["clientSecret"],
        "registrationExpiresAt": _iso(datetime.fromtimestamp(reg["clientSecretExpiresAt"], timezone.utc)),
    }
    if tok.get("refreshToken"):
        data["refreshToken"] = tok["refreshToken"]
    _save_token(session_name, data)


def _save_token(session_name: str, data: dict) -> None:
    path = _cache_file(session_name)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")  # 0600, unique per sign-in
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def logout(session_name: str) -> None:
    """Sign out like ``aws sso logout``: end the token at AWS (best effort) and delete the cached copy."""
    path = _cache_file(session_name)
    token = _read_token(session_name)  # no renewal just to sign out
    if token:
        try:
            _portal(token["region"]).logout(accessToken=token["accessToken"])
        except Exception as exc:  # the local token is removed either way
            log.info("SSO logout call for %s failed: %s", session_name, exc)
    path.unlink(missing_ok=True)
    with _role_count_lock:  # a new sign-in may be a different person: count again
        for key in [k for k in _role_counts if k[0] == session_name]:
            del _role_counts[key]


# ---------------------------------------------------------------- accounts and profiles


def _token_or_fail(session_name: str) -> tuple[str, str]:
    s = _session_config(session_name)
    token = load_token(session_name)
    if not token:
        raise SSOFailure(f"Not signed in to {session_name!r}. Use Sign in first.")
    return token["accessToken"], s["sso_region"]


def list_roles(session_name: str, account_id: str) -> list[str]:
    token, region = _token_or_fail(session_name)
    pages = _portal(region).get_paginator("list_account_roles").paginate(accessToken=token, accountId=account_id)
    return sorted(r["roleName"] for p in pages for r in p["roleList"])


def list_accounts(session_name: str) -> dict:
    """Accounts the analyst can reach, and the organization's management account if it can be found."""
    token, region = _token_or_fail(session_name)
    pages = _portal(region).get_paginator("list_accounts").paginate(accessToken=token)
    accounts = sorted(
        ({"id": a["accountId"], "name": a.get("accountName", ""), "email": a.get("emailAddress", "")}
         for p in pages for a in p["accountList"]),
        key=lambda a: a["name"].lower(),
    )  # fmt: skip
    mgmt = _find_management(session_name, accounts)
    return {"accounts": accounts, "management_account_id": mgmt}


# Bulk portal reads (one ListAccountRoles per account). Measured on 338 accounts: 16 threads with standard
# retries read about 19 accounts a second with no throttling; 32 threads earn 429s. Adaptive retries
# were the bottleneck, not the portal: their client-side limiter held it to about 6 a second.
PORTAL_BULK = Config(
    signature_version=botocore.UNSIGNED, retries={"max_attempts": 10, "mode": "standard"}, max_pool_connections=20
)
PORTAL_WORKERS = 16
ROLE_COUNT_SECONDS = 900
_role_counts: dict[tuple[str, str], tuple[float, list[str], list[str]]] = {}
_role_count_lock = threading.Lock()


def portal_account_ids(session_name: str) -> list[str]:
    token, region = _token_or_fail(session_name)
    pages = _portal(region).get_paginator("list_accounts").paginate(accessToken=token)
    return sorted(a["accountId"] for p in pages for a in p["accountList"])


def accounts_with_role(
    session_name: str, role: str, progress: Callable[[int, int], None] | None = None
) -> tuple[list[str], list[str]]:
    """(account ids where ``role`` is assigned to the analyst, all account ids the portal shows them).

    ``progress(done, total)`` is called as each account is checked. The answer is kept for
    ROLE_COUNT_SECONDS: at about 19 portal calls a second a large estate still takes 20 seconds or more.
    """
    key = (session_name, role)
    with _role_count_lock:
        hit = _role_counts.get(key)
    if hit and time.monotonic() - hit[0] < ROLE_COUNT_SECONDS:
        if progress:
            progress(len(hit[2]), len(hit[2]))
        return list(hit[1]), list(hit[2])
    token, region = _token_or_fail(session_name)
    ids = portal_account_ids(session_name)
    client = boto3.client("sso", region_name=region, config=PORTAL_BULK)
    lock, done = threading.Lock(), [0]

    def has_role(account_id: str) -> bool:
        pages = client.get_paginator("list_account_roles").paginate(accessToken=token, accountId=account_id)
        found = any(r["roleName"] == role for p in pages for r in p["roleList"])
        with lock:
            done[0] += 1
            n = done[0]
        if progress:
            progress(n, len(ids))
        return found

    have = pmap(has_role, ids, workers=PORTAL_WORKERS)
    assigned = [a for a, ok in zip(ids, have, strict=True) if ok]
    with _role_count_lock:
        _role_counts[key] = (time.monotonic(), assigned, ids)
    return list(assigned), list(ids)


def role_count_age(session_name: str, role: str) -> float | None:
    """Seconds since accounts_with_role last counted, if its answer is still being reused."""
    with _role_count_lock:
        hit = _role_counts.get((session_name, role))
    age = time.monotonic() - hit[0] if hit else None
    return age if age is not None and age < ROLE_COUNT_SECONDS else None


def _find_management(session_name: str, accounts: list[dict]) -> str | None:
    """DescribeOrganization works from any member account; try a few until one answers."""
    for acct in accounts[:5]:
        try:
            roles = list_roles(session_name, acct["id"])
            if not roles:
                continue
            sess = role_session(session_name, acct["id"], roles[0])
            org = sess.client("organizations", config=BOTO_CONFIG).describe_organization()["Organization"]
            return org["MasterAccountId"]
        except Exception as exc:
            log.info("management-account lookup via %s failed: %s", acct["id"], exc)
    return None


def role_session(session_name: str, account_id: str, role: str) -> boto3.Session:
    token, region = _token_or_fail(session_name)
    # Paced retries: a deep scan asks for credentials once per account, enough to trip the portal's limit.
    portal = boto3.client("sso", region_name=region, config=PORTAL_BULK)
    c = portal.get_role_credentials(roleName=role, accountId=account_id, accessToken=token)["roleCredentials"]
    return boto3.Session(
        aws_access_key_id=c["accessKeyId"],
        aws_secret_access_key=c["secretAccessKey"],
        aws_session_token=c["sessionToken"],
    )


def profile_permission_set(profile: str | None) -> tuple[str, str] | None:
    """(SSO session, permission set) behind an IAM Identity Center profile, else None.

    Lets a deep scan reach member accounts with the analyst's own permission set, no extra role needed.
    """
    try:
        p = _full_config().get("profiles", {}).get(profile or "default") or {}
    except Exception:
        log.exception("could not read AWS profiles")
        return None
    if p.get("sso_session") and p.get("sso_role_name"):
        return p["sso_session"], p["sso_role_name"]
    return None


def ensure_profile(session_name: str, account_id: str, role: str, region: str = "us-east-1") -> str:
    """Return a profile for (session, account, role), adding one to ~/.aws/config if none exists."""
    _session_config(session_name)
    if not re.fullmatch(r"\d{12}", account_id) or not NAME_RE.fullmatch(role):
        raise SSOFailure("Invalid account id or role name.")
    profiles = _full_config().get("profiles", {})
    for name, p in sorted(profiles.items()):
        if (p.get("sso_session"), p.get("sso_account_id"), p.get("sso_role_name")) == (
            session_name,
            account_id,
            role,
        ):
            return name
    name = re.sub(r"[^A-Za-z0-9_.-]", "-", f"{session_name}-{role}").lower()
    if name in profiles:
        name = f"{name}-{account_id}"
    _append_config(
        f"[profile {name}]\nsso_session = {session_name}\nsso_account_id = {account_id}\n"
        f"sso_role_name = {role}\nregion = {region}\noutput = json"
    )
    log.info("added profile %s (%s / %s) to %s", name, account_id, role, config_path())
    return name
