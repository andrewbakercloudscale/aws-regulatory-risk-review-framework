"""Regenerate the README screenshots and the sample PDF from the synthetic demo estate.

    python scripts/screenshots.py            # writes docs/images/*.png and docs/sample-report.pdf

Runs the console on a throwaway data directory, so it never touches your real scans.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "images"
PORT = 8749


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="exitrisk-shots-")
    os.environ["EXITRISK_DATA_DIR"] = tmp  # must be set before exitrisk is imported
    # Never show the author's real AWS profiles or SSO portals in published screenshots.
    fake_cfg = Path(tmp) / "aws-config"
    fake_cfg.write_text(
        "[profile org-management-readonly]\nregion = eu-west-1\n\n[profile sandbox]\nregion = eu-west-1\n\n"
        "[sso-session example]\nsso_start_url = https://d-1234567890.awsapps.com/start\nsso_region = eu-west-1\n"
    )
    os.environ["AWS_CONFIG_FILE"] = str(fake_cfg)
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(Path(tmp) / "aws-credentials")
    os.environ["EXITRISK_SSO_CACHE_DIR"] = str(Path(tmp) / "sso-cache")
    sys.path.insert(0, str(ROOT / "src"))

    import uvicorn
    from playwright.sync_api import sync_playwright

    from exitrisk import preflight
    from exitrisk.demo import create_demo_scan
    from exitrisk.server import create_app

    def example_access_check(profile, role_name=None):
        # A canned result (a member account, refused OU access) so the screenshot needs no AWS.
        arn = "arn:aws:sts::222222222222:assumed-role/AWSReservedSSO_ReadOnly_0123456789abcdef/analyst@example.com"
        C = preflight.Check
        checks = [
            C("identity", "Sign in to AWS", "ok", f"{arn} in account 222222222222"),
            C(
                "organization",
                "Management account",
                "warn",
                "Organization o-example; management account 111111111111",
                "You are in member account 222222222222. Sign in to management account 111111111111 "
                "(or an Organizations delegated administrator) for the whole estate.",
            ),
            C(
                "ou_tree",
                "Read the OU tree",
                "fail",
                "AccessDeniedException: You don't have permissions to access this resource.",
                "The caller lacks permission for this API. See docs/IAM_PERMISSIONS.md.",
                "organizations:ListRoots, organizations:ListOrganizationalUnitsForParent",
            ),
            C("accounts", "List accounts", "skip", "Needs the OU tree."),
            C(
                "cost",
                "Read Cost Explorer",
                "warn",
                "Spend visible for 1 account(s) (this check cost US$0.01).",
                "A member account sees only its own spend; use the management account.",
            ),
            C("deep_scan", "Deep scan role (optional)", "skip", "No member role given."),
        ]
        ctx = {"profile": profile, "role_name": None, "account_id": "222222222222", "arn": arn}
        ctx.update(permission_set="ReadOnly", org_id="o-example", management_account_id="111111111111")
        return preflight._result(checks, ctx)

    preflight.run_checks = example_access_check
    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.1)
    OUT.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []

    def shoot(page, selector: str, name: str) -> None:
        page.locator(selector).screenshot(path=str(OUT / name), animations="disabled")
        print("wrote", OUT / name)

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1360, "height": 900}, device_scale_factor=2, color_scheme="light")
        page = ctx.new_page()
        page.on("console", lambda m: m.type == "error" and errors.append(m.text))
        page.on("pageerror", lambda e: errors.append(str(e)))

        # First run: no scans yet, so the getting-started steps show.
        page.goto(f"http://127.0.0.1:{PORT}/")
        page.wait_for_selector("body[data-ready='1']")
        page.wait_for_timeout(300)
        shoot(page, "#empty", "getting-started.png")
        page.click("#btnGsCheck")
        page.wait_for_selector("#accessDialog[open]")
        page.click("#btnAccessRun")
        page.wait_for_selector("#aAdmin:not([hidden])")
        page.wait_for_timeout(200)
        page.set_viewport_size({"width": 1360, "height": 1500})
        shoot(page, "#accessDialog", "access-check.png")
        page.set_viewport_size({"width": 1360, "height": 900})
        page.keyboard.press("Escape")

        scan_id = create_demo_scan(6)["id"]
        base = f"http://127.0.0.1:{PORT}/?scan={scan_id}"

        page.goto(base + "&include=prod")
        page.wait_for_selector("body[data-ready='1']")
        page.wait_for_timeout(700)
        page.screenshot(path=str(OUT / "dashboard-overview.png"))
        print("wrote", OUT / "dashboard-overview.png")
        # The sticky top bar would otherwise overlap element screenshots.
        page.add_style_tag(content=".topbar { position: static !important; }")
        shoot(page, "#sec-summary", "executive-summary.png")
        shoot(page, "#sec-profile", "risk-profile.png")
        shoot(page, "#sec-accounts", "accounts.png")
        shoot(page, "#sec-services", "services.png")
        shoot(page, "#sec-estimate", "estimate.png")
        shoot(page, "#sec-issues", "issues.png")
        page.locator("#sec-appendix .cat-group").first.screenshot(path=str(OUT / "appendix-catalog.png"))
        print("wrote", OUT / "appendix-catalog.png")

        page.click("#btnNewScan")
        page.wait_for_selector("#scanDialog[open]")
        page.check("#sInventory")
        page.fill("input[name=role_name]", "ExitRiskReadOnly")
        page.wait_for_timeout(200)
        shoot(page, "#scanDialog", "new-scan-dialog.png")
        page.keyboard.press("Escape")

        page.click("#btnSso")
        page.wait_for_selector("#ssoDialog[open]")
        page.wait_for_timeout(200)
        shoot(page, "#ssoDialog", "sso-sign-in.png")
        page.keyboard.press("Escape")

        dark = browser.new_context(viewport={"width": 1360, "height": 900}, device_scale_factor=2, color_scheme="dark")
        dp = dark.new_page()
        dp.goto(base + "&include=prod")
        dp.wait_for_selector("body[data-ready='1']")
        dp.wait_for_timeout(700)
        dp.screenshot(path=str(OUT / "dashboard-dark.png"))
        print("wrote", OUT / "dashboard-dark.png")

        # Lay the print page out near A4 width so charts are drawn at the size they print.
        pp = browser.new_page(viewport={"width": 1000, "height": 1400})
        pp.goto(base + "&include=prod&print=1")
        pp.wait_for_selector("body[data-ready='1']")
        pp.emulate_media(media="print")
        pp.wait_for_timeout(500)
        pdf = ROOT / "docs" / "sample-report.pdf"
        pp.pdf(
            path=str(pdf),
            format="A4",
            print_background=True,
            margin={"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"},
        )
        print("wrote", pdf)
        browser.close()

    server.should_exit = True
    if errors:
        print("browser errors:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
