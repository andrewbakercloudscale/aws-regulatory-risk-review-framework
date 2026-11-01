"""The Outage Risk Report tab in a real browser. Skipped where Chromium is not installed."""

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
    yield f"http://127.0.0.1:{port}/?scan={scan_id}&view=outage"
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
    pg.goto(console)
    pg.wait_for_selector("#orContent:not([hidden])")
    pg.wait_for_function("document.querySelectorAll('#orTable tbody tr').length > 0")
    yield pg
    ctx.close()


def test_the_report_draws_with_every_section(page):
    assert page.locator(".vtab[data-view='outage']").get_attribute("aria-pressed") == "true"
    assert "critical" in page.locator("#orHeadline").inner_text()
    assert page.locator("#orTiles .tile").count() >= 6
    assert page.locator("#orFocus tbody tr").count() >= 5
    assert page.locator("#orAccounts tbody tr").count() > 0
    assert page.locator("#orClusters tbody tr").count() > 0
    assert page.locator("#orCauses tbody tr a").count() >= 5
    assert "Changes to live systems" in page.locator("#orCauses").inner_text()
    assert not page.errors


def test_changing_the_expected_load_redraws_with_no_new_scan(page):
    before = page.locator("#orHeadline").inner_text()
    page.fill("#orForm [name=peak_multiplier]", "1")
    page.locator("#orForm [name=peak_multiplier]").dispatch_event("change")
    page.wait_for_function("t => document.querySelector('#orHeadline').textContent !== t", arg=before)
    page.evaluate("localStorage.clear()")
    assert not page.errors


def test_selecting_an_area_filters_the_findings(page):
    page.uncheck("#orProd")
    total = page.locator("#orFindCount").inner_text()
    page.locator("#orFocus [data-or-area='msk']").click()
    assert page.locator("#orArea").input_value() == "msk"
    assert page.locator("#orFindCount").inner_text() != total
    assert "MSK" in page.locator("#orTable").inner_text() or "Kafka" in page.locator("#orTable").inner_text()
    assert not page.errors


def test_the_other_tabs_hide_it(page):
    page.locator(".vtab[data-view='exit']").click()
    assert page.locator("#orContent").is_hidden()
    page.locator(".vtab[data-view='outage']").click()
    page.wait_for_selector("#orContent:not([hidden])")
    assert not page.errors
