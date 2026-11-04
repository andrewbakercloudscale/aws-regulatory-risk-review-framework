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
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    scan_id = create_demo_scan(12)["id"]
    yield f"http://127.0.0.1:{port}/?scan={scan_id}&view=outage"
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


def test_the_risk_map_top_risks_coverage_and_reviews_draw(page):
    assert page.locator("#orSvcRisk tbody tr").count() > 0
    assert page.locator("#orSvcRisk tbody tr").first.locator("td").last.inner_text()  # what to do
    assert "US$" not in page.locator("#or-map").inner_text()  # risk, not spend
    assert page.locator("#orMatrix .or-cell button").count() > 0
    assert page.evaluate("Chart.getChart('chOrAccounts').data.datasets[0].data.length") > 5
    assert page.locator("#orExposure .or-bar").count() > 0
    assert page.locator("#orHeat tbody tr").count() > 0
    assert 0 < page.locator("#orTop tbody tr").count() <= 50
    assert "not covered" in page.locator("#orCovHead").inner_text()
    assert page.locator("#orCovTable tbody tr").count() > 10
    first = page.locator("#orReviews details").first
    first.locator("summary").click()
    assert first.locator(".or-review-body h4").first.inner_text() == "What to do"


def test_an_account_on_the_map_opens_its_findings(page):
    name = page.locator("#orExposure [data-or-acct]").first.inner_text()
    page.locator("#orExposure [data-or-acct]").first.click()
    assert page.locator("#orSearch").input_value() == name


def test_a_scan_without_the_checks_opens_the_newest_one_with_them(browser, console):
    """Unless the scan was named in the link: then it stays, with a button to the one that has them."""
    from exitrisk import store
    from exitrisk.demo import build_demo_scan

    base, _, query = console.partition("?")
    demo = dict(p.split("=") for p in query.split("&"))["scan"]
    bare = build_demo_scan(3)
    bare["id"] = "29991231-235959-ffff"  # newer than every other scan
    bare.pop("outage", None)
    store.save_scan(bare)
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    try:
        pg = ctx.new_page()
        pg.goto(f"{base}?view=outage")
        pg.wait_for_selector("#orContent:not([hidden])")
        assert pg.locator("#scanSelect").input_value() == demo
        pg.goto(f"{base}?scan={bare['id']}&view=outage")
        pg.wait_for_selector("#orEmpty:not([hidden])")
        assert pg.locator("#btnOrOpen").is_visible()
        assert pg.locator("#scanSelect").input_value() == bare["id"]
    finally:
        ctx.close()
        store.delete_scan(bare["id"])


def test_a_heat_cell_lists_its_risks_and_what_to_do(page):
    page.locator("#orHeat .or-heat-btn").first.click()
    box = page.locator("#orHeatDetail")
    box.wait_for(state="visible")
    assert "What to do" in box.inner_text()
    assert box.locator("tbody tr").count() >= 1
    assert page.locator("#orTopTitle").inner_text().startswith("Top")
    assert "What to do" in page.locator("#orTable thead").inner_text()
    assert not page.errors


def test_new_scan_ticks_only_the_report_on_screen(page):
    """A remembered AI tick for another report never adds that report to the scan."""
    import json

    settings = {
        "configured": True,
        "settings": {"provider": "bedrock", "model": "m", "mask_names": True, "keys": {}},
        "providers": [{"key": "bedrock", "label": "Bedrock", "recommended": [{"id": "m", "label": "M"}]}],
    }
    page.route(
        "**/api/ai/settings",
        lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps(settings)),
    )
    page.evaluate(
        "localStorage.setItem('exitrisk.aiWithScan.as', '1'); localStorage.setItem('exitrisk.aiWithScan.mr', '1')"
    )
    page.locator("#btnNewScan").click()
    page.wait_for_selector("#scanDialog[open]")
    ticked = {
        i: page.locator(i).is_checked()
        for i in ("#sRepExit", "#sRepMr", "#sAssurance", "#sOutage", "#sAiAs", "#sAiMr", "#sAiOr")
    }
    assert ticked == {
        "#sRepExit": False,
        "#sRepMr": False,
        "#sAssurance": False,
        "#sOutage": True,
        "#sAiAs": False,
        "#sAiMr": False,
        "#sAiOr": True,
    }
    assert not page.errors
