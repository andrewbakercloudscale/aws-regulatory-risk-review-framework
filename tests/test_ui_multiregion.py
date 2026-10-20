"""The multi-region tab in a real browser: choices, account selection, and failure handling.

Skipped where Chromium is not installed (`playwright install chromium`); CI's ui job runs it.
"""

import socket
import threading
import time

import pytest

sync_api = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def console():
    import uvicorn

    from exitrisk.demo import create_demo_scan
    from exitrisk.server import create_app

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    scan_id = create_demo_scan(12)["id"]
    yield f"http://127.0.0.1:{port}/?scan={scan_id}&include=prod&view=multiregion"
    server.should_exit = True


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as exc:  # no browser binary on this machine
            pytest.skip(f"Chromium not available: {exc}")
        yield b
        b.close()


@pytest.fixture
def page(browser, console):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.errors = errors
    yield pg
    ctx.close()


def _open(page, url):
    page.goto(url)
    page.wait_for_selector("body[data-ready='1']")
    page.wait_for_selector("#mrContent:not([hidden])")


def _wait_recalc(page, before: str):
    page.wait_for_function("t => document.querySelector('#mrHeadline').textContent !== t", arg=before)


def test_recovery_choice_and_account_selection_recalculate(page, console):
    _open(page, console)
    assert "3 hours" in page.text_content("#mrHeadline")
    before = page.text_content("#mrHeadline")
    page.check("#mrForm input[name=recovery][value=instant]")
    _wait_recalc(page, before)
    assert "instantly" in page.text_content("#mrHeadline")

    rows = page.locator("#mrAcctTable tbody tr")
    assert rows.count() > 3
    spends = page.eval_on_selector_all(
        "#mrAcctTable tbody tr", "rs => rs.map(r => r.querySelector('input[type=checkbox]').checked)"
    )
    assert all(spends)  # every account ticked by default
    before = page.text_content("#mrHeadline")
    page.click("text=Select none")
    _wait_recalc(page, before)
    assert "Pick at least one account" in page.text_content("#mrHeadline")
    before = page.text_content("#mrHeadline")
    page.click("text=Top 10")
    _wait_recalc(page, before)
    assert "Pick at least one account" not in page.text_content("#mrHeadline")
    assert not page.errors


def test_server_error_shows_a_panel_with_retry(page, console):
    _open(page, console)
    calls = {"n": 0}

    def fail_once(route):
        calls["n"] += 1
        if calls["n"] == 1:
            route.fulfill(status=500, json={"error": "internal error - see the log", "request_id": "abc12345"})
        else:
            route.continue_()

    page.route("**/api/multiregion", fail_once)
    page.check("#mrForm input[name=recovery][value=instant]")
    page.wait_for_selector("#mrError:not([hidden])")
    assert "abc12345" in page.text_content("#mrErrorText")
    assert "bug" in page.text_content("#mrErrorHint")
    page.click("#btnMrRetry")
    page.wait_for_selector("#mrError", state="hidden")
    assert "instantly" in page.text_content("#mrHeadline")
    assert not page.errors


def test_first_load_failure_is_not_a_blank_tab(page, console):
    page.route("**/api/multiregion", lambda r: r.fulfill(status=400, json={"detail": "bad include pattern"}))
    page.goto(console)
    page.wait_for_selector("#mrError:not([hidden])")
    assert "bad include pattern" in page.text_content("#mrErrorText")
    assert page.is_hidden("#mrContent")
