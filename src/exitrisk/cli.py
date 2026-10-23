"""Command line: ``exitrisk serve | scan | demo | report | pdf | catalog``."""

from __future__ import annotations

import argparse
import json
import re
import signal
import sys
import threading
import time
import webbrowser
from pathlib import Path

from . import __version__, store
from .config import settings
from .estimate import TARGET_LABELS
from .logging_config import configure_logging, get_logger, run_id_var

log = get_logger("cli")


class UsageError(Exception):
    """A problem with what the user passed; reported as one line, without a traceback."""


def _answers(path: str | None, what: str) -> dict | None:
    """Read a --questionnaire / --multiregion answers file as a JSON object, marked as confirmed."""
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise UsageError(f"cannot read the {what} file {path}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise UsageError(f"the {what} file {path} is not valid JSON (line {exc.lineno}, column {exc.colno})") from exc
    if not isinstance(data, dict):
        raise UsageError(f'the {what} file {path} must hold a JSON object of answers, e.g. {{"target": "azure"}}')
    return {"confirmed": True, **data}


def _serve(args) -> int:
    import uvicorn

    from .server import create_app

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        log.warning(
            "binding to %s exposes a console that uses your AWS credentials to the network; "
            "anyone who can reach it can run scans as you",
            args.host,
        )
    if args.replace and not _stop_running_console(args.port):
        return 1
    app = create_app(allow_remote=args.host not in ("127.0.0.1", "localhost", "::1"), scheduler=True)
    url = f"http://127.0.0.1:{args.port}/"
    log.info("console at %s  (data: %s, log: %s)", url, settings.data_dir, settings.log_file)
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    _scan_safe_server(uvicorn.Config(app, host=args.host, port=args.port, log_level="warning")).run()
    return 0


def _scan_safe_server(config):
    import uvicorn

    from .scanner import running_scans

    class ScanSafeServer(uvicorn.Server):
        """Scans run in memory, so stopping mid-scan loses them. A stop signal waits for running
        scans to finish (the console keeps serving meanwhile); a second signal stops at once."""

        _waiting = False

        def handle_exit(self, sig, frame):
            running = running_scans()
            if not running or self._waiting:
                if self._waiting:
                    log.warning("stopping now; scan(s) %s are lost", ", ".join(running) or "none")
                return super().handle_exit(sig, frame)
            self._waiting = True
            log.warning(
                "stop requested while scan(s) %s run; stopping when they finish (signal again to stop now)",
                ", ".join(running),
            )

            def wait():
                while running_scans():
                    time.sleep(2)
                log.info("scans finished; stopping")
                self.should_exit = True

            threading.Thread(target=wait, name="stop-after-scans", daemon=True).start()

    return ScanSafeServer(config)


def _stop_running_console(port: int) -> bool:
    """Stop the console already on this port, after its running scans finish. False if it would not stop."""
    import os
    import urllib.request

    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=3) as resp:
            health = json.load(resp)
    except OSError:
        return True  # nothing listening
    pid = health.get("pid")
    if not pid:
        log.error("the console on port %d is too old to stop safely; stop it yourself when no scan runs", port)
        return False
    if health.get("scans_running"):
        log.warning("waiting for scan(s) %s on the running console to finish", ", ".join(health["scans_running"]))
    os.kill(pid, signal.SIGTERM)
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            log.info("stopped the previous console (pid %d)", pid)
            return True
        time.sleep(1)


def _scan(args) -> int:
    from .scanner import ScanJob, ScanParams, record_failure, run_scan

    params = ScanParams(
        profile=args.profile,
        ou_ids=[o.strip() for o in args.ou.split(",") if o.strip()] if args.ou else None,
        months=args.months,
        role_name=args.role,
        inventory=args.inventory or args.dependencies,
        dependencies=args.dependencies,
        inventory_scope=args.inventory_scope,
        regions=args.regions.split(",") if args.regions else None,
        label=args.label or "",
        target=args.target,
    )
    params.validate()
    job = ScanJob(id=store.new_scan_id(), params=params)
    token = run_id_var.set(job.id)
    try:
        doc = run_scan(job)
    except Exception as exc:
        record_failure(job, exc)
        log.error("partial data saved as scan %s", job.id)
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


def _schedule(args) -> int:
    """`show` prints the monthly scan; `run` runs it if due (for launchd or cron), or at once with --now."""
    from . import schedule
    from .scanner import ScanJob, ScanParams, record_failure, run_scan

    if args.action == "show":
        print(json.dumps(schedule.status(schedule.load()), indent=2))
        return 0
    if not schedule.load():
        log.error("no monthly scan is set: set one in the console (Settings, Monthly scan)")
        return 2
    s = schedule.claim(force=args.now)
    if not s:
        st = schedule.status(schedule.load())
        if st["running"]:
            log.info("the monthly scan is already running (started %s)", st["running"]["started_at"])
        elif st["retry_at"]:
            log.info(
                "the last attempt failed (%s); it retries after %s, or use --now",
                st["schedule"]["last_error"],
                st["retry_at"],
            )
        else:
            log.info("the monthly scan is not due: next run %s", st["next_run"])
        return 0
    job = ScanJob(id=store.new_scan_id(), params=ScanParams(**schedule.scan_params(s)))
    schedule.started(job.id)
    token = run_id_var.set(job.id)
    try:
        doc = run_scan(job)
    except Exception as exc:
        msg = record_failure(job, exc)
        schedule.finished(job.id, "failed", msg)
        log.error("monthly scan failed: %s", msg)
        return 2
    finally:
        run_id_var.reset(token)
    schedule.finished(doc["id"], doc["status"])
    print(json.dumps({"scan_id": doc["id"], "status": doc["status"], "accounts": len(doc["accounts"])}, indent=2))
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

    scan = store.load_scan(args.scan_id)
    if args.questionnaire:
        q = Questionnaire(**_answers(args.questionnaire, "questionnaire"))
    else:  # no answers given: use the exit target chosen when the scan was started
        q = Questionnaire(target=(scan.get("params") or {}).get("target") or "azure")
    flt = AccountFilter(include=args.include or "", exclude=args.exclude or "", mode=args.mode)
    if args.view == "multiregion":
        from .multiregion import MultiRegionAnswers, build_multiregion

        mq = MultiRegionAnswers(**(_answers(args.multiregion, "multi-region answers") or {}))
        report = build_multiregion(scan, flt, q, mq)
    else:
        report = build_report(scan, flt, q, weighting=args.weighting)
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
        from playwright.sync_api import TimeoutError as PlaywrightTimeout
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.error(
            "PDF export needs Playwright: pip install 'aws-regulatory-risk-review-framework[pdf]' "
            "&& playwright install chromium"
        )
        return 2
    import urllib.parse

    import uvicorn

    if args.onepage and args.view == "multiregion":
        raise UsageError("--onepage summarises the exit-risk report; drop --view multiregion")
    if args.onepage and args.out == "exit-risk-report.pdf":
        args.out = "exit-risk-summary.pdf"

    from .server import create_app

    server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=args.port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    else:
        server.should_exit = True
        log.error(
            "the report server did not start on 127.0.0.1:%s within 10s; is the port in use? Try --port %s",
            args.port,
            args.port + 1,
        )
        return 1
    query = urllib.parse.urlencode(
        {
            k: v
            for k, v in {
                "scan": args.scan_id,
                "include": args.include,
                "exclude": args.exclude,
                "mode": args.mode,
                "weighting": args.weighting,
                "min_rating": getattr(args, "min_rating", None),
                "q": json.dumps(_answers(args.questionnaire, "questionnaire")) if args.questionnaire else None,
                "view": "multiregion" if args.view == "multiregion" else None,
                "mr": json.dumps(_answers(args.multiregion, "multi-region answers")) if args.multiregion else None,
                "onepage": "1" if args.onepage else None,
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
            try:
                page.wait_for_selector("body[data-ready='1']", timeout=30000)
            except PlaywrightTimeout:
                log.error(
                    "the report page did not finish loading within 30s (scan %s); check the page errors above "
                    "and the console log, or open the same report in the web console",
                    args.scan_id,
                )
                browser.close()
                return 1
            failed = page.get_attribute("body", "data-error")
            if failed:
                log.error("the report could not be built: %s (see the log above)", failed)
                browser.close()
                return 1
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
    if args.onepage and (pages := _pdf_pages(Path(args.out))) > 1:
        log.warning("the one-page summary ran to %d pages; long account or service names can push it over", pages)
    log.info("wrote %s", args.out)
    return 0


def _pdf_pages(path: Path) -> int:
    """Pages in a PDF Chromium wrote: its page objects, not counting the page tree."""
    data = path.read_bytes()
    return len(re.findall(rb"/Type\s*/Page\b", data))


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
    p.add_argument(
        "--replace",
        action="store_true",
        help="stop the console already on this port first, once its running scans have finished",
    )
    p.set_defaults(fn=_serve)

    p = sub.add_parser("scan", help="run a scan from the command line")
    p.add_argument("--profile", help="AWS profile (e.g. an aws-cli-zsp profile in the management account)")
    p.add_argument("--ou", help="OU id(s), comma-separated (ou-xxxx-yyyyyyyy,...); default: the organization root")
    p.add_argument("--months", type=int, default=3)
    p.add_argument("--inventory", action="store_true", help="also inventory resources in member accounts")
    p.add_argument(
        "--dependencies",
        action="store_true",
        help="also count the integrations between services (dependency scan; implies --inventory)",
    )
    p.add_argument(
        "--inventory-scope",
        choices=["all", "material"],
        default="all",
        help="deep-scan every account, or only material ones (most of the spend, or High/Critical services)",
    )
    p.add_argument("--role", help="role name to assume in member accounts for --inventory")
    p.add_argument("--regions", help="comma-separated regions for --inventory (default: all enabled)")
    p.add_argument("--label")
    p.add_argument(
        "--target",
        choices=list(TARGET_LABELS),
        default="azure",
        help="where you would exit to; seeds the cost and time estimate (default: azure)",
    )
    p.set_defaults(fn=_scan)

    p = sub.add_parser("schedule", help="the monthly scan: show it, or run it when due (for launchd or cron)")
    p.add_argument("action", choices=["show", "run"])
    p.add_argument("--now", action="store_true", help="run even if it is not due yet")
    p.set_defaults(fn=_schedule)

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
        p.add_argument(
            "--weighting",
            default="spend",
            choices=["spend", "equal", "balanced"],
            help="how accounts are weighted in the OU score: spend (default), equal = by number of accounts, "
            "balanced = square root of spend",
        )
        p.add_argument(
            "--questionnaire",
            help="JSON file with the delivery answers (section 6); without it cost and time are marked provisional",
        )
        p.add_argument(
            "--view",
            default="exit",
            choices=["exit", "multiregion"],
            help="exit = the exit-risk report (default); multiregion = the cost of running a second region",
        )
        p.add_argument(
            "--multiregion",
            help="JSON file with the multi-region answers (recovery, residency, accounts, ...); "
            "see docs/MULTI_REGION.md",
        )
        if name == "pdf":
            p.add_argument("--port", type=int, default=8741)
            p.add_argument(
                "--onepage",
                action="store_true",
                help="one A4 page for the executive committee (default file exit-risk-summary.pdf)",
            )
            p.add_argument(
                "--min-rating",
                choices=["Moderate", "High"],
                help="list only accounts at or above this rating in the account ranking (scores still count all)",
            )
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
    except UsageError as exc:
        log.error("%s", exc)
        return 2
    except store.ScanNotFound as exc:
        log.error("no scan with id %s in %s; scan ids are the file names there", exc.args[0], settings.scans_dir)
        return 2
    except Exception as exc:
        log.exception("%s failed: %s", args.cmd, exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
