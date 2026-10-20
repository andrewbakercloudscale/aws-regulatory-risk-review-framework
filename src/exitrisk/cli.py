"""Command line: ``exitrisk serve | scan | demo | report | pdf | catalog``."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import webbrowser
from pathlib import Path

from . import __version__, store
from .config import settings
from .logging_config import configure_logging, get_logger, run_id_var

log = get_logger("cli")


def _serve(args) -> int:
    import uvicorn

    from .server import create_app

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        log.warning(
            "binding to %s exposes a console that uses your AWS credentials to the network; "
            "anyone who can reach it can run scans as you",
            args.host,
        )
    app = create_app(allow_remote=args.host not in ("127.0.0.1", "localhost", "::1"))
    url = f"http://127.0.0.1:{args.port}/"
    log.info("console at %s  (data: %s, log: %s)", url, settings.data_dir, settings.log_file)
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def _scan(args) -> int:
    from .scanner import ScanJob, ScanParams, run_scan

    params = ScanParams(
        profile=args.profile,
        ou_id=args.ou,
        months=args.months,
        role_name=args.role,
        inventory=args.inventory,
        regions=args.regions.split(",") if args.regions else None,
        label=args.label or "",
    )
    params.validate()
    job = ScanJob(id=store.new_scan_id(), params=params)
    token = run_id_var.set(job.id)
    try:
        doc = run_scan(job)
    except Exception as exc:
        log.error("scan failed: %s", exc)
        return 2
    finally:
        run_id_var.reset(token)
    print(
        json.dumps(
            {
                "scan_id": doc["id"],
                "status": doc["status"],
                "accounts": len(doc["accounts"]),
                "issues": len(doc["issues"]),
            },
            indent=2,
        )
    )
    return 0 if doc["status"] == "complete" else 1


def _demo(args) -> int:
    from .demo import create_demo_scan

    scan = create_demo_scan(args.months)
    print(scan["id"])
    return 0


def _report(args) -> int:
    from .estimate import Questionnaire
    from .filtering import AccountFilter
    from .scoring import build_report

    q = Questionnaire(**json.loads(Path(args.questionnaire).read_text())) if args.questionnaire else Questionnaire()
    report = build_report(
        store.load_scan(args.scan_id),
        AccountFilter(include=args.include or "", exclude=args.exclude or "", mode=args.mode),
        q,
    )
    text = json.dumps(report, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text)
        log.info("wrote %s", args.out)
    else:
        print(text)
    return 0


def _pdf(args) -> int:
    """Render the dashboard's print layout to PDF with headless Chromium (pip install '.[pdf]')."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.error(
            "PDF export needs Playwright: pip install 'aws-regulatory-risk-review-framework[pdf]' "
            "&& playwright install chromium"
        )
        return 2
    import urllib.parse

    import uvicorn

    from .server import create_app

    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=args.port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    query = urllib.parse.urlencode(
        {
            k: v
            for k, v in {
                "scan": args.scan_id,
                "include": args.include,
                "exclude": args.exclude,
                "mode": args.mode,
                "print": "1",
            }.items()
            if v
        }
    )
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1000, "height": 1400})  # ~A4 width
            page.on("console", lambda m: m.type == "error" and log.error("page: %s", m.text))
            page.goto(f"http://127.0.0.1:{args.port}/?{query}")
            page.wait_for_selector("body[data-ready='1']", timeout=30000)
            page.emulate_media(media="print")
            page.pdf(
                path=args.out,
                format="A4",
                print_background=True,
                margin={"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"},
            )
            browser.close()
    finally:
        server.should_exit = True
    log.info("wrote %s", args.out)
    return 0


def _catalog(args) -> int:
    from .catalog import load_catalog

    cat = load_catalog()
    for s in sorted(cat.services, key=lambda s: (-s.tier, s.display)):
        if not s.excluded:
            print(f"{s.tier}  {cat.tier_label(s.tier):<9} {s.display:<28} {s.category}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="exitrisk", description="AWS exit-risk review console")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--log-level", default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="run the web console")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8740)
    p.add_argument("--no-browser", action="store_true")
    p.set_defaults(fn=_serve)

    p = sub.add_parser("scan", help="run a scan from the command line")
    p.add_argument("--profile", help="AWS profile (e.g. an aws-cli-zsp profile in the management account)")
    p.add_argument("--ou", help="OU id (ou-xxxx-yyyyyyyy); default: the organization root")
    p.add_argument("--months", type=int, default=3)
    p.add_argument("--inventory", action="store_true", help="also inventory resources in member accounts")
    p.add_argument("--role", help="role name to assume in member accounts for --inventory")
    p.add_argument("--regions", help="comma-separated regions for --inventory (default: all enabled)")
    p.add_argument("--label")
    p.set_defaults(fn=_scan)

    p = sub.add_parser("demo", help="create a synthetic demo scan")
    p.add_argument("--months", type=int, default=6)
    p.set_defaults(fn=_demo)

    for name, fn in (("report", _report), ("pdf", _pdf)):
        p = sub.add_parser(name, help=f"{'JSON report' if name == 'report' else 'PDF report'} for a stored scan")
        p.add_argument("scan_id")
        p.add_argument("--include", help="account-name pattern(s), comma-separated, e.g. 'prod,prd'")
        p.add_argument("--exclude")
        p.add_argument("--mode", default="contains", choices=["contains", "prefix", "suffix", "regex"])
        p.add_argument("--out")
        if name == "report":
            p.add_argument("--questionnaire", help="JSON file with questionnaire answers")
        else:
            p.add_argument("--port", type=int, default=8741)
        p.set_defaults(fn=fn)
    sub.choices["pdf"].set_defaults(out="exit-risk-report.pdf")

    p = sub.add_parser("catalog", help="print the service risk catalog")
    p.set_defaults(fn=_catalog)

    args = parser.parse_args(argv)
    configure_logging(args.log_level)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        log.exception("%s failed: %s", args.cmd, exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
