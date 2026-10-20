"""Scan orchestration: Organizations -> Cost Explorer -> (optional) inventory.

A scan runs in a background thread and reports progress through ``ScanJob``. It is
designed to degrade, not die: a member account that refuses the inventory role, a region
that is not enabled, or a throttled call each become an Issue on the scan, and the score
is computed from whatever was collected. Only an authentication failure or a failed
Cost Explorer query (without which there is no score) fails the scan.
"""

from __future__ import annotations

import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

from botocore.exceptions import BotoCoreError, ClientError

from . import store
from .aws_session import assume_role_session, caller_identity, make_session
from .collectors import cost, inventory, organizations
from .config import settings
from .issues import Issue, describe_exception, is_fatal_auth_error
from .logging_config import get_logger, run_id_var

log = get_logger("scanner")


@dataclass
class ScanParams:
    profile: str | None = None
    ou_id: str | None = None
    ou_ids: list[str] | None = None  # several OUs in one scan; accounts in more than one count once
    months: int = 12
    role_name: str | None = None
    inventory: bool = False
    regions: list[str] | None = None
    label: str = ""
    target: str = "azure"  # exit target asked at scan time; seeds the estimate questionnaire

    @property
    def ous(self) -> list[str]:
        return list(dict.fromkeys([*(self.ou_ids or []), *([self.ou_id] if self.ou_id else [])]))

    def validate(self) -> None:
        if not 1 <= self.months <= 12:
            raise ValueError("months must be between 1 and 12")
        if self.inventory and not self.role_name:
            raise ValueError("a member-account role name is required for the resource inventory")


class ScanFailed(RuntimeError):
    pass


@dataclass
class ScanJob:
    id: str
    params: ScanParams
    phase: str = "queued"
    pct: int = 0
    message: str = ""
    status: str = "running"
    issues: list[Issue] = field(default_factory=list)
    data: dict = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def update(self, phase: str, pct: int, message: str) -> None:
        with self._lock:
            self.phase, self.pct, self.message = phase, pct, message
        log.info("[%s %d%%] %s", phase, pct, message, extra={"phase": phase})

    def add_issue(self, issue: Issue) -> None:
        with self._lock:
            self.issues.append(issue)
        level = {"info": 20, "warning": 30, "error": 40, "critical": 50}[issue.severity]
        log.log(
            level,
            "%s: %s%s",
            issue.category,
            issue.message,
            f" ({issue.hint})" if issue.hint else "",
            extra={k: v for k, v in (("account_id", issue.account_id), ("error_code", issue.error_code)) if v},
        )

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "id": self.id,
                "phase": self.phase,
                "pct": self.pct,
                "message": self.message,
                "status": self.status,
                "issues": len(self.issues),
            }


_jobs: dict[str, ScanJob] = {}
_jobs_lock = threading.Lock()


def get_job(scan_id: str) -> ScanJob | None:
    with _jobs_lock:
        return _jobs.get(scan_id)


def start_scan(params: ScanParams) -> ScanJob:
    params.validate()
    job = ScanJob(id=store.new_scan_id(), params=params)
    with _jobs_lock:
        _jobs[job.id] = job
    threading.Thread(target=_run_safely, args=(job,), name=f"scan-{job.id}", daemon=True).start()
    return job


def _run_safely(job: ScanJob) -> None:
    token = run_id_var.set(job.id)
    try:
        run_scan(job)
    except Exception as exc:  # last line of defence: record it, never lose it
        code, msg, hint = describe_exception(exc)
        job.add_issue(Issue("critical", "scan", f"scan failed: {msg}", hint, error_code=code))
        log.error("scan failed\n%s", traceback.format_exc())
        job.status = "failed"
        job.update("failed", 100, msg)
        store.save_scan(_document(job, job.data, failed=True))
    finally:
        run_id_var.reset(token)


def _document(job: ScanJob, data: dict, failed: bool = False) -> dict:
    return {
        "id": job.id,
        "label": job.params.label,
        "mode": "live",
        "created_at": data.get("created_at", datetime.now(timezone.utc).isoformat(timespec="seconds")),
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "failed" if failed else job.status,
        "params": job.params.__dict__,
        "identity": data.get("identity"),
        "org": data.get("org"),
        "ou": data.get("ou"),
        "ous": data.get("ous"),
        "accounts": data.get("accounts", []),
        "costs": data.get("costs", []),
        "region_costs": data.get("region_costs"),
        "storage": data.get("storage"),
        "period": data.get("period"),
        "inventory": data.get("inventory", {}),
        "issues": [i.to_dict() for i in job.issues],
    }


def run_scan(job: ScanJob) -> dict:
    p = job.params
    data: dict = {"created_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    job.data = data  # kept on the job so a failed scan still saves what it collected
    log.info(
        "scan starting: profile=%s ou=%s months=%d inventory=%s",
        p.profile,
        ",".join(p.ous) or "root",
        p.months,
        p.inventory,
    )

    # 1. Identity. With aws-cli-zsp this is where the Touch ID prompt appears.
    job.update("auth", 5, f"Authenticating with profile '{p.profile or 'default'}' (approve Touch ID if prompted)")
    session = make_session(p.profile)
    try:
        data["identity"] = caller_identity(session)
    except Exception as exc:
        code, msg, hint = describe_exception(exc)
        job.add_issue(Issue("critical", "auth", f"could not authenticate: {msg}", hint, error_code=code))
        raise ScanFailed(msg) from exc
    job.update("auth", 10, f"Authenticated as {data['identity']['arn']}")

    # 2. Organization and accounts.
    job.update("organizations", 15, "Reading the organization's OU tree")
    try:
        data["org"] = organizations.describe_org(session)
        tree = organizations.list_ou_tree(session)
        ous = [organizations.find_ou(tree, i) for i in p.ous] if p.ous else [tree]
        missing = [i for i, ou in zip(p.ous, ous, strict=False) if ou is None]
        if missing:
            raise ScanFailed(f"OU {', '.join(missing)} not found in this organization")
        data["ou"] = {k: " + ".join(ou[k] for ou in ous) for k in ("id", "name", "path")}
        data["ous"] = [{k: ou[k] for k in ("id", "name", "path")} for ou in ous]
        # Nested picks (an OU and one of its children) overlap: keep each account once.
        seen: dict[str, organizations.Account] = {}
        for ou in ous:
            for a in organizations.list_accounts_under(session, ou):
                seen.setdefault(a.id, a)
        accounts = list(seen.values())
        if data["identity"]["account_id"] != data["org"]["management_account_id"]:
            job.add_issue(
                Issue(
                    "warning",
                    "organizations",
                    "Not running in the management account: Cost Explorer only shows this account's "
                    "own spend unless it is a delegated billing administrator.",
                    "Use a profile in the management (payer) account for an OU-wide view.",
                )
            )
    except ClientError as exc:
        code, msg, hint = describe_exception(exc)
        if is_fatal_auth_error(code):
            job.add_issue(Issue("critical", "auth", msg, hint, error_code=code))
            raise ScanFailed(msg) from exc
        acct = data["identity"]["account_id"]
        mgmt = (data.get("org") or {}).get("management_account_id")
        if mgmt and mgmt != acct:
            # describe_org worked, so this is a member account of a known organization.
            message = (
                f"Organizations refused ({code}): this profile is in member account {acct}, and the "
                f"organization's management account is {mgmt}. Scanning account {acct} only."
            )
            hint = f"For an OU-wide view, scan with a profile in management account {mgmt}."
            scope = "Single member account"
        else:
            message = f"Organizations unavailable ({code}); scanning the calling account only."
            scope = "Standalone account"
        job.add_issue(Issue("warning", "organizations", message, hint, error_code=code))
        accounts = [organizations.Account(acct, acct, "", "ACTIVE", "-", scope)]
        data["ou"] = {"id": "-", "name": scope, "path": scope}

    suspended = [a for a in accounts if a.status not in ("ACTIVE", "UNKNOWN")]
    for a in suspended:
        job.add_issue(
            Issue(
                "info",
                "organizations",
                f"account {a.name} is {a.status}; its spend is still included if any was billed",
                account_id=a.id,
            )
        )
    data["accounts"] = [a.to_dict() for a in accounts]
    if not accounts:
        job.add_issue(Issue("error", "organizations", "the selected OU contains no accounts"))
        job.status = "complete"
        job.update("complete", 100, "No accounts to scan")
        doc = _document(job, data)
        store.save_scan(doc)
        return doc
    job.update("organizations", 22, f"{len(accounts)} account(s) in {data['ou']['path']}")

    # 2b. Account tags: business criticality and channel. Optional, so a refusal is a warning.
    if data["ou"]["id"] != "-":
        job.update("organizations", 23, "Reading account tags (criticality, channel)")
        try:
            tags = organizations.fetch_account_tags(session, [a["id"] for a in data["accounts"]])
            for a in data["accounts"]:
                a["tags"] = tags.get(a["id"], {})
        except Exception as exc:  # optional data: never fail a scan for it
            if not isinstance(exc, (ClientError, BotoCoreError)):
                log.exception("account tags failed with an unexpected error")
            code, msg, hint = describe_exception(exc)
            job.add_issue(
                Issue(
                    "warning",
                    "organizations",
                    f"account tags unavailable: {msg}",
                    " ".join(
                        x
                        for x in (
                            hint,
                            "Grant organizations:ListTagsForResource, or name the critical accounts in the console.",
                        )
                        if x
                    ),
                    error_code=code,
                )
            )
    job.update("organizations", 25, f"{len(accounts)} account(s) in {data['ou']['path']}")

    # 3. Spend per account per service. Without this there is no score, so a failure is fatal.
    job.update("cost", 30, f"Querying Cost Explorer for the last {p.months} complete month(s)")
    try:
        data["costs"], data["period"] = cost.fetch_costs(session, [a.id for a in accounts], p.months)
    except (ClientError, BotoCoreError) as exc:
        code, msg, hint = describe_exception(exc)
        job.add_issue(Issue("critical", "cost", f"Cost Explorer query failed: {msg}", hint, error_code=code))
        raise ScanFailed(msg) from exc
    if not data["costs"]:
        job.add_issue(
            Issue(
                "warning",
                "cost",
                "Cost Explorer returned no spend for these accounts in the period",
                "Check the OU and period, and that Cost Explorer is enabled.",
            )
        )
    billed = {r["account_id"] for r in data["costs"]}
    for a in accounts:
        if a.id not in billed:
            job.add_issue(Issue("info", "cost", f"no spend recorded for {a.name} in the period", account_id=a.id))
    job.update("cost", 50, f"{len(data['costs'])} cost line(s) collected")

    # 3b. Spend by region, for the multi-region estimate. Optional: the exit score does not need it.
    job.update("cost", 52, "Querying Cost Explorer for spend by region")
    try:
        data["region_costs"] = cost.fetch_region_costs(session, [a.id for a in accounts], p.months)
    except Exception as exc:  # optional data: never fail a scan for it
        if not isinstance(exc, (ClientError, BotoCoreError)):
            log.exception("spend by region failed with an unexpected error")  # a bug: keep the traceback
        code, msg, hint = describe_exception(exc)
        job.add_issue(
            Issue(
                "warning",
                "cost",
                f"spend by region unavailable: {msg}",
                " ".join(
                    x for x in (hint, "Until then the multi-region view assumes all spend runs in one region.") if x
                ),
                error_code=code,
            )
        )
    job.update("cost", 55, f"{len(data.get('region_costs', []))} region cost line(s) collected")

    # 3c. Data held per account (GB-months of storage), for the data-gravity view. Optional.
    job.update("cost", 57, "Querying Cost Explorer for data stored")
    try:
        data["storage"] = cost.fetch_storage(session, [a.id for a in accounts], {r["service"] for r in data["costs"]})
    except Exception as exc:  # optional data: never fail a scan for it
        if not isinstance(exc, (ClientError, BotoCoreError)):
            log.exception("data stored failed with an unexpected error")
        code, msg, hint = describe_exception(exc)
        job.add_issue(
            Issue(
                "warning",
                "cost",
                f"data stored unavailable: {msg}",
                " ".join(x for x in (hint, "The resilience view will not size the data to move.") if x),
                error_code=code,
            )
        )
    job.update("cost", 58, f"{len(data.get('storage') or [])} storage line(s) collected")

    # 4. Optional deep inventory through a role in each member account.
    if p.inventory:
        data["inventory"] = _run_inventory(job, session, accounts)

    job.status = "complete" if not any(i.severity in ("error", "critical") for i in job.issues) else "partial"
    job.update("complete", 100, f"Scan {job.status}: {len(accounts)} account(s), {len(job.issues)} issue(s)")
    doc = _document(job, data)
    store.save_scan(doc)
    return doc


def _run_inventory(job: ScanJob, session, accounts) -> dict:
    p = job.params
    results: dict = {}
    done = 0
    mgmt = None
    try:
        mgmt = caller_identity(session)["account_id"]
    except Exception:
        log.debug("could not resolve caller account for inventory", exc_info=True)

    def one(account):
        try:
            sess = session if account.id == mgmt else assume_role_session(session, account.id, p.role_name, job.id)
        except (ClientError, BotoCoreError) as exc:
            code, msg, hint = describe_exception(exc)
            return (
                account,
                None,
                [
                    Issue(
                        "error",
                        "inventory",
                        f"cannot assume {p.role_name} in {account.name}: {msg}",
                        hint or "Deploy the read-only role from docs/IAM_PERMISSIONS.md.",
                        account_id=account.id,
                        error_code=code,
                    )
                ],
            )
        inv, issues = inventory.inventory_account(sess, account.id, p.regions)
        return account, inv, issues

    active = [a for a in accounts if a.status in ("ACTIVE", "UNKNOWN")]
    with ThreadPoolExecutor(max_workers=settings.max_workers) as pool:
        for fut in as_completed([pool.submit(one, a) for a in active]):
            account, inv, issues = fut.result()
            for i in issues:
                job.add_issue(i)
            if inv:
                results[account.id] = inv
            done += 1
            job.update(
                "inventory",
                55 + int(40 * done / max(len(active), 1)),
                f"Inventory {done}/{len(active)}: {account.name}",
            )
    return results
