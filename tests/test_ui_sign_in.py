"""New scan and Check access always lead to the sign-in, and the sign-in can always be tried again.
AWS is answered by the browser test itself. Skipped where Chromium is not installed."""

import json
import socket
import threading
import time

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

SESSIONS = [{"name": "corp", "start_url": "https://d-1.awsapps.com/start", "region": "eu-west-1",
             "signed_in": False, "expires_at": None, "profiles": []}]  # fmt: skip


@pytest.fixture(scope="module")
def console():
    import uvicorn

    from exitrisk.server import create_app

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/"
    server.should_exit = True
    thread.join(10)  # a server left running crashes at interpreter exit


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as exc:  # no browser binary on this machine
            pytest.skip(f"Chromium not available: {exc}")
        yield b
        b.close()


class Aws:
    """What the console's server would answer: signed out until a sign-in completes."""

    def __init__(self):
        self.signed_in = False
        self.login_status = "pending"
        self.logins = 0
        self.org_calls = 0


@pytest.fixture
def aws(browser, console):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    state = Aws()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))

    def reply(route, body, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(body))

    pg.route("**/api/profiles", lambda r: reply(r, {"profiles": ["corp-read"], "accounts": {}}))
    until = lambda: "2030-01-01T10:00:00Z" if state.signed_in else None  # noqa: E731
    pg.route("**/api/sign-in*", lambda r: reply(
        r, {"sso": True, "session": "corp", "signed_in": state.signed_in, "expires_at": until()}))  # fmt: skip
    pg.route("**/api/sso/sessions", lambda r: reply(
        r, {"sessions": [{**SESSIONS[0], "signed_in": state.signed_in, "expires_at": until()}]}))  # fmt: skip

    def org(route):
        state.org_calls += 1
        reply(route, {"tree": {"id": "r", "name": "Root", "accounts": 1, "children": []},
                      "org": {"id": "o-1", "management_account_id": "111111111111"}})  # fmt: skip

    pg.route("**/api/org", org)

    def login(route):
        state.logins += 1
        reply(route, {"id": f"l{state.logins}", "verification_uri": "about:blank", "user_code": "ABCD-1234"})

    pg.route("**/api/sso/login", login)

    def status(route):
        if state.login_status == "complete":
            state.signed_in = True
        reply(route, {"status": state.login_status, "message": "Sign-in was not completed (AccessDenied)."})

    pg.route("**/api/sso/login/*", status)
    pg.route("**/api/sso/corp/accounts", lambda r: reply(r, {"accounts": [], "management_account_id": None}))
    pg.goto(console)
    pg.wait_for_function("() => document.querySelector('#ssoLabel').textContent.includes('Signed')")  # bound and loaded
    yield pg, state, errors
    ctx.close()


def _new_scan(pg):
    pg.evaluate("document.querySelector('#btnNewScan').click()")
    pg.wait_for_selector("#scanDialog[open]")


def test_new_scan_signed_out_opens_the_sign_in_and_reads_nothing(aws):
    pg, state, errors = aws
    _new_scan(pg)
    pg.wait_for_selector("#ssoDialog[open]")
    assert pg.locator("#ssoSession").input_value() == "corp"
    assert "not signed in" in pg.locator("#scanSignInText").inner_text()
    assert pg.locator("#btnStartScan").is_disabled()
    assert state.org_calls == 0  # no OU call that can only fail with a confusing error
    assert not errors


def test_signing_in_returns_to_the_scan_with_the_ous_loaded(aws):
    pg, state, errors = aws
    state.login_status = "complete"
    _new_scan(pg)
    pg.wait_for_selector("#ssoDialog[open]")
    pg.click("#btnSsoLogin")
    pg.wait_for_selector("#ssoDialog:not([open])", state="attached", timeout=8000)
    pg.wait_for_function("() => !document.querySelector('#btnStartScan').disabled")
    assert "Signed in to corp" in pg.locator("#scanSignInText").inner_text()
    assert pg.locator("#scanDialog").evaluate("d => d.open")
    assert state.org_calls >= 1
    assert not errors


def test_closing_the_sign_in_still_says_what_to_do(aws):
    pg, state, errors = aws
    _new_scan(pg)
    pg.wait_for_selector("#ssoDialog[open]")
    pg.locator("#ssoDialog").evaluate("d => d.close()")
    assert pg.locator("#btnStartScan").is_disabled()
    pg.click("#btnScanSignIn")
    pg.wait_for_selector("#ssoDialog[open]")
    assert not errors


def test_sign_in_is_never_locked_while_waiting_or_after_a_failure(aws):
    pg, state, errors = aws
    _new_scan(pg)
    pg.wait_for_selector("#ssoDialog[open]")
    pg.click("#btnSsoLogin")
    pg.wait_for_selector("#ssoPending:not([hidden])")
    assert pg.locator("#btnSsoLogin").is_enabled()
    assert pg.locator("#btnSsoLogin").inner_text() == "Start again"
    pg.click("#btnSsoLogin")  # the AWS page failed: a new code at once
    pg.wait_for_function("() => document.querySelector('#ssoPending') && !document.querySelector('#ssoPending').hidden")
    assert state.logins == 2
    state.login_status = "failed"
    pg.wait_for_function("() => document.querySelector('#ssoError').textContent.includes('try again')", timeout=8000)
    assert pg.locator("#btnSsoLogin").is_enabled()
    assert pg.locator("#btnSsoLogin").inner_text() == "Sign in"
    pg.click("#btnSsoLogin")
    pg.wait_for_function("() => document.querySelector('#ssoPending') && !document.querySelector('#ssoPending').hidden")
    assert state.logins == 3
    pg.locator("#ssoDialog").evaluate("d => d.close()")  # and after closing and coming back
    pg.click("#btnScanSignIn")
    pg.wait_for_selector("#ssoDialog[open]")
    pg.wait_for_function("() => document.querySelector('#btnSsoLogin').textContent === 'Sign in'")
    assert pg.locator("#btnSsoLogin").is_enabled()
    assert not errors


def test_check_access_signed_out_opens_the_sign_in(aws):
    pg, state, errors = aws
    pg.evaluate("document.querySelector('#btnAccess')?.click()")
    if not pg.locator("#accessDialog").evaluate("d => d.open"):
        _new_scan(pg)
        pg.wait_for_selector("#ssoDialog[open]")
        pg.locator("#ssoDialog").evaluate("d => d.close()")
        pg.click("#btnScanCheck")
    pg.wait_for_selector("#accessDialog[open]")
    pg.wait_for_selector("#ssoDialog[open]")
    assert "not signed in" in pg.locator("#aError").inner_text()
    assert not errors


def _on_tab(pg, view):
    pg.evaluate("v => document.querySelector(`.vtab[data-view='${v}']`).click()", view)
    pg.evaluate("document.querySelector('#btnNewScan').click()")
    pg.wait_for_selector("#scanDialog[open]")


def test_the_scan_is_for_the_tab_you_are_on_and_shows_only_what_it_uses(aws):
    pg, state, errors = aws
    state.signed_in = True
    _on_tab(pg, "outage")
    assert pg.locator("#sOutage").is_checked()
    assert not pg.locator("#sRepExit").is_checked() and not pg.locator("#sAssurance").is_checked()
    assert pg.locator("#sTarget").is_hidden()  # no exit target on an outage scan
    assert pg.locator("#sDepth").is_hidden()
    assert pg.locator("#sAiOr").is_visible() and pg.locator("#sAi").is_hidden()
    assert pg.locator("#invOpts").is_visible()  # the member role and regions apply
    pg.check("#sRepExit")  # asked for as well: its options appear
    assert pg.locator("#sTarget").is_visible() and pg.locator("#sDepth").is_visible()
    pg.uncheck("#sRepExit")
    pg.uncheck("#sOutage")
    assert pg.locator("#btnStartScan").is_disabled()
    assert "at least one report" in pg.locator("#scanError").inner_text()
    pg.locator("#btnScanClose", has_text="Cancel").click()
    pg.wait_for_function("() => !document.querySelector('#scanDialog').open")
    assert not errors


def test_a_running_scan_says_hide_not_close(aws):
    pg, state, errors = aws
    state.signed_in = True
    answer = lambda body: lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps(body))  # noqa: E731
    pg.route("**/api/scans", answer({"scans": [], "running": ["20261101-000000-abcd"]}))
    pg.route("**/api/scans/20261101-000000-abcd/status", answer({"status": "running", "progress": 10, "message": "m"}))
    pg.reload()
    pg.wait_for_function("() => document.querySelector('#ssoLabel').textContent.includes('Signed')")
    pg.evaluate("document.querySelector('#btnScanRunning').click()")
    pg.wait_for_selector("#scanDialog[open]")
    pg.wait_for_function("() => document.querySelector('#btnScanClose').textContent.startsWith('Hide')")
    assert pg.locator("#btnStopScan").is_visible() and pg.locator("#scanTitle").inner_text() == "Scan running"
    assert not pg.locator("#scanError").inner_text()
    assert not errors
