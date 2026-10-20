import json
import threading
import time

import boto3
import pytest
from botocore.stub import Stubber
from fastapi.testclient import TestClient

from exitrisk import sso
from exitrisk.server import create_app

H = {"X-ExitRisk": "1"}
URL = "https://d-1234567890.awsapps.com/start"


@pytest.fixture(autouse=True)
def isolated_aws(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("EXITRISK_SSO_CACHE_DIR", str(tmp_path / "sso-cache"))
    (tmp_path / "config").write_text("[default]\nregion = eu-west-1\n")
    return tmp_path


def _client(service):
    return boto3.client(service, region_name="eu-west-1", config=sso.UNSIGNED)


def _signed_in(name="corp"):
    sso.add_session(name, URL, "eu-west-1")
    path = sso._cache_file(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
    path.write_text(json.dumps({"accessToken": "tok", "expiresAt": expires, "startUrl": URL, "region": "eu-west-1"}))


def test_add_session_writes_config_and_validates(isolated_aws):
    sso.add_session("corp", URL + "/#/", "eu-west-1")
    text = (isolated_aws / "config").read_text()
    assert "[sso-session corp]" in text and f"sso_start_url = {URL}\n" in text and "[default]" in text
    [s] = sso.list_sessions()
    assert s["name"] == "corp" and s["region"] == "eu-west-1" and not s["signed_in"]
    with pytest.raises(sso.SSOFailure):
        sso.add_session("corp", URL, "eu-west-1")
    with pytest.raises(sso.SSOFailure):
        sso.add_session("bad name", URL, "eu-west-1")
    with pytest.raises(sso.SSOFailure):
        sso.add_session("other", "http://evil.example/start", "eu-west-1")


def test_device_login_writes_cli_token_cache(monkeypatch):
    sso.add_session("corp", URL, "eu-west-1")
    oidc = _client("sso-oidc")
    stub = Stubber(oidc)
    reg = {"clientId": "cid", "clientSecret": "sec", "clientSecretExpiresAt": int(time.time()) + 86400}
    stub.add_response("register_client", reg)
    stub.add_response(
        "start_device_authorization",
        {"deviceCode": "dev", "userCode": "ABCD-EFGH", "verificationUri": "https://x", "verificationUriComplete":
         "https://device.sso.eu-west-1.amazonaws.com/?user_code=ABCD-EFGH", "expiresIn": 600, "interval": 1},
    )  # fmt: skip
    stub.add_client_error("create_token", "AuthorizationPendingException", http_status_code=400)
    stub.add_response("create_token", {"accessToken": "tok", "expiresIn": 3600, "refreshToken": "ref"})
    stub.activate()
    monkeypatch.setattr(sso, "_oidc", lambda region: oidc)
    monkeypatch.setattr(sso.time, "sleep", lambda s: None)
    login = sso.start_login("corp")
    assert login.user_code == "ABCD-EFGH" and login.verification_uri.startswith("https://device.")
    for t in threading.enumerate():
        if t.name == f"sso-{login.id}":
            t.join(5)
    assert login.snapshot()["status"] == "complete"
    cached = json.loads(sso._cache_file("corp").read_text())
    assert cached["accessToken"] == "tok" and cached["refreshToken"] == "ref" and cached["startUrl"] == URL
    assert oct(sso._cache_file("corp").stat().st_mode & 0o777) == "0o600"
    assert sso.list_sessions()[0]["signed_in"]


def test_accounts_roles_and_profile(monkeypatch, isolated_aws):
    _signed_in()
    portal = _client("sso")
    stub = Stubber(portal)
    stub.add_response(
        "list_accounts",
        {
            "accountList": [
                {"accountId": "222222222222", "accountName": "b-prd"},
                {"accountId": "111111111111", "accountName": "a-npr"},
            ]
        },
    )
    stub.add_response("list_account_roles", {"roleList": [{"roleName": "CTO-Read", "accountId": "111111111111"}]})
    stub.activate()
    monkeypatch.setattr(sso, "_portal", lambda region: portal)
    monkeypatch.setattr(sso, "_find_management", lambda name, accounts: "222222222222")
    out = sso.list_accounts("corp")
    assert [a["name"] for a in out["accounts"]] == ["a-npr", "b-prd"]
    assert out["management_account_id"] == "222222222222"
    assert sso.list_roles("corp", "111111111111") == ["CTO-Read"]

    name = sso.ensure_profile("corp", "222222222222", "CTO-Read")
    assert name == "corp-cto-read"
    assert sso.ensure_profile("corp", "222222222222", "CTO-Read") == name  # idempotent
    assert (isolated_aws / "config").read_text().count("[profile corp-cto-read]") == 1
    assert sso.list_sessions()[0]["profiles"] == [{"name": name, "account_id": "222222222222", "role": "CTO-Read"}]


def test_not_signed_in_is_a_clear_error():
    sso.add_session("corp", URL, "eu-west-1")
    with pytest.raises(sso.SSOFailure, match="Not signed in"):
        sso.list_accounts("corp")


def test_sso_api(monkeypatch):
    c = TestClient(create_app(), base_url="http://127.0.0.1")
    assert c.get("/api/sso/sessions").json() == {"sessions": []}
    assert (
        c.post("/api/sso/sessions", json={"name": "corp", "start_url": URL, "region": "eu-west-1"}).status_code == 403
    )
    r = c.post("/api/sso/sessions", json={"name": "corp", "start_url": URL, "region": "eu-west-1"}, headers=H)
    assert r.status_code == 200 and r.json()["region"] == "eu-west-1"
    r = c.get("/api/sso/corp/accounts")
    assert r.status_code == 400 and "Not signed in" in r.json()["detail"]
    assert c.get("/api/sso/login/nope").status_code == 404
    r = c.post("/api/sso/profile", json={"session": "corp", "account_id": "12", "role": "x"}, headers=H)
    assert r.status_code == 422
