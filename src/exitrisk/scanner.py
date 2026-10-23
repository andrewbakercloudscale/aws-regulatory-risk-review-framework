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

from . import sso, store
from .aws_session import ClientCache, caller_identity, make_session, member_session
from .collectors import cost, inventory, organizations
from .config import settings
from .issues import Issue, describe_exception, is_fatal_auth_error
from .logging_config import get_logger, run_id_var
from .parallel import background

log = get_logger("scanner")


INVENTORY_SCOPES = ("all", "material")
# A "material" deep scan covers the largest accounts holding this share of spend, plus any account
# spending at least MATERIAL_LOCKIN_MONTHLY a month on High or Critical (tier 4 to 5) services.
MATERIAL_SPEND_SHARE = 0.95
MATERIAL_LOCKIN_MONTHLY = 100.0


def material_accounts(costs: list[dict], months: int) -> set[str]:
    """Account ids worth a deep scan when the user asks for a selective one."""
    from .catalog import load_catalog

    catalog = load_catalog()
    spend: dict[str, float] = {}
    lockin: dict[str, float] = {}
    for r in costs:
        spend[r["account_id"]] = spend.get(r["account_id"], 0.0) + r["amount"]
        if catalog.lookup(r["service"]).tier >= 4:
            lockin[r["account_id"]] = lockin.get(r["account_id"], 0.0) + r["amount"]
    total, running, out = sum(spend.values()), 0.0, set()
    for aid, amt in sorted(spend.items(), key=lambda kv: -kv[1]):
        if running >= total * MATERIAL_SPEND_SHARE:
            break
        out.add(aid)
        running += amt
    out |= {aid for aid, amt in lockin.items() if amt / max(months, 1) >= MATERIAL_LOCKIN_MONTHLY}
    return out


@dataclass
class ScanParams:
    profile: str | None = None
    ou_id: str | None = None
    ou_ids: list[str] | None = None  # several OUs in one scan; accounts in more than one count once
    months: int = 12
    role_name: str | None = None
    inventory: bool = False
    # Dependency scan: also count the integrations between services (implies the inventory).
    dependencies: bool = False
    # "all" accounts, or only the "material" ones: those holding most of the spend or any spend on
    # High/Critical services. Deep scans cost time and API calls; selective ones go where it counts.
    inventory_scope: str = "all"
    regions: list[str] | None = None
    label: str = ""
    target: str = "azure"  # exit target asked at scan time; seeds the estimate questionnaire

    @property
    def ous(self) -> list[str]:
        return list(dict.fromkeys([*(self.ou_ids or []), *([self.ou_id] if self.ou_id else [])]))

    def validate(self) -> None:
        if self.dependencies:
            self.inventory = True
        if self.inventory_scope not in INVENTORY_SCOPES:
            raise ValueError(f"inventory_scope must be one of {', '.join(INVENTORY_SCOPES)}")
        if not 1 <= self.months <= 12:
            raise ValueError("months must be between 1 and 12")
        if self.inventory and not self.role_name and not sso.profile_permission_set(self.profile):
            raise ValueError(
                "a member-account role name is required for the resource inventory "
                "(or use an IAM Identity Center profile, whose permission set is then used in each account)"
            )


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
            extra={
                k: getattr(issue, k)
                for k in ("account_id", "region", "service", "error_code")
                if getattr(issue, k, None)
            },
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


def running_scans() -> list[str]:
    """Ids of scans still running in this process; they live in memory and die with it."""
    with _jobs_lock:
        return [j.id for j in _jobs.values() if j.status == "running"]


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
        record_failure(job, exc)
    finally:
        job.data = {}  # saved to disk by now; a large organisation's scan holds tens of MB
        run_id_var.reset(token)


def record_failure(job: ScanJob, exc: Exception) -> str:
    """Mark a scan failed and save what it collected, so a failure is evidence too. Returns the message."""
    code, msg, hint = describe_exception(exc)
    job.add_issue(Issue("critical", "scan", f"scan failed: {msg}", hint, error_code=code))
    if isinstance(exc, (ScanFailed, ClientError, BotoCoreError)):
        log.error("scan failed: %s", msg)
    else:
        log.error("scan failed\n%s", traceback.format_exc())  # a bug: keep the traceback
    job.status = "failed"
    job.update("failed", 100, msg)
    try:
        store.save_scan(_document(job, job.data, failed=True))
    except Exception:
        log.exception("could not save the failed scan %s", job.id)
    return msg


def _document(job: ScanJob, data: dict, failed: bool = False, status: str | None = None) -> dict:
    return {
        "id": job.id,
        "label": job.params.label,
        "mode": "live",
        "created_at": data.get("created_at", datetime.now(timezone.utc).isoformat(timespec="seconds")),
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "failed" if failed else status or job.status,
        "params": job.params.__dict__,
        "identity": data.get("identity"),
        "org": data.get("org"),
        "ou": data.get("ou"),
        "ous": data.get("ous"),
        "accounts": data.get("accounts", []),
        "costs": data.get("costs", []),
        "region_costs": data.get("region_costs"),
        "storage": data.get("storage"),
        "direct_connect": data.get("direct_connect"),
        "commitments": data.get("commitments"),
        "period": data.get("period"),
        "inventory": data.get("inventory", {}),
        "unavailable": data.get("unavailable", {}),
        "issues": [i.to_dict() for i in job.issues],
    }


def _optional(job: ScanJob, data: dict, key: str, what: str, advice: str, fetch, category: str = "cost") -> bool:
    """Collect optional data into data[key]. A refusal never fails the scan, but it is recorded in
    data["unavailable"] so the report says why the section is empty rather than "run a new scan". An
    expired sign-in is an error, so a scan that lost its credentials part-way is saved as partial."""
    try:
        data[key] = fetch()
        return True
    except Exception as exc:
        if not isinstance(exc, (ClientError, BotoCoreError)):
            log.exception("%s failed with an unexpected error", what)  # a bug: keep the traceback
        code, msg, hint = describe_exception(exc)
        severity = "error" if is_fatal_auth_error(code) else "warning"
        job.add_issue(
            Issue(
                severity,
                category,
                f"{what} unavailable: {msg}",
                " ".join(x for x in (hint, advice) if x),
                error_code=code,
            )
        )
        data.setdefault("unavailable", {})[key] = msg
        return False


def run_scan(job: ScanJob) -> dict:
    p = job.params
    data: dict = {"created_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    job.data = data  # kept on the job so a failed scan still saves what it collected
    log.info(
        "scan starting: profile=%s ou=%s months=%d inventory=%s dependencies=%s scope=%s",
        p.profile,
        ",".join(p.ous) or "root",
        p.months,
        p.inventory,
        p.dependencies,
        p.inventory_scope,
    )

    # 1. Identity. With aws-cli-zsp this is where the Touch ID prompt appears.
    job.update("auth", 5, f"Authenticating with profile '{p.profile or 'default'}' (approve Touch ID if prompted)")
    # Shared by the threads below (tags, cost queries, inventory): clients made one at a time.
    session = ClientCache(make_session(p.profile))
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
        # Always read fresh: a scan is evidence, so an OU moved minutes ago must count. The picker's
        # cached copy is refreshed with what the scan saw.
        data["org"] = organizations.describe_org(session)
        known: dict = {}
        tree = organizations.list_ou_tree(
            session,
            known,
            lambda n_ous, n_accts: job.update(
                "organizations", 15, f"Reading the organization's OU tree: {n_ous} OUs, {n_accts} accounts found"
            ),
        )
        organizations.remember_org_and_tree(p.profile, data["org"], tree)
        ous = [organizations.find_ou(tree, i) for i in p.ous] if p.ous else [tree]
        missing = [i for i, ou in zip(p.ous, ous, strict=False) if ou is None]
        if missing:
            raise ScanFailed(f"OU {', '.join(missing)} not found in this organization")
        data["ou"] = {k: " + ".join(ou[k] for ou in ous) for k in ("id", "name", "path")}
        data["ous"] = [{k: ou[k] for k in ("id", "name", "path")} for ou in ous]
        # Nested picks (an OU and one of its children) overlap: keep each account once.
        seen: dict[str, organizations.Account] = {}
        for ou in ous:
            for a in organizations.list_accounts_under(session, ou, known):
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
        doc = _document(job, data, status="complete")
        store.save_scan(doc)  # saved before the status says complete, so the report is there to load
        job.status = "complete"
        job.update("complete", 100, "No accounts to scan")
        return doc
    job.update(
        "organizations", 22, f"{len(accounts)} account{'' if len(accounts) == 1 else 's'} in {data['ou']['path']}"
    )

    # 2b. Account tags: business criticality and channel. Organizations, not Cost Explorer, so they
    # are read alongside the cost queries below and collected at the end.
    tags_read = None
    if data["ou"]["id"] != "-":
        ids = [a["id"] for a in data["accounts"]]
        tags_read = background(lambda: organizations.fetch_account_tags(session, ids))
    job.update(
        "organizations", 25, f"{len(accounts)} account{'' if len(accounts) == 1 else 's'} in {data['ou']['path']}"
    )

    # 3. Spend per account per service. Without this there is no score, so a failure is fatal.
    job.update("cost", 30, f"Querying Cost Explorer for the last {p.months} complete month(s)")
    try:
        data["costs"], data["period"] = cost.fetch_costs(
            session,
            [a.id for a in accounts],
            p.months,
            lambda done, total: job.update(
                "cost", 30 + 20 * done // total, f"Querying Cost Explorer: {done} of {total} accounts read"
            ),
        )
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
    ids = [a.id for a in accounts]
    # Data stored, Direct Connect and commitments are separate queries: read them alongside it.
    services = {r["service"] for r in data["costs"]}
    alongside = {
        "storage": background(lambda: cost.fetch_storage(session, ids, services)),
        "direct_connect": background(lambda: cost.fetch_direct_connect(session, None)),
        "commitments": background(lambda: cost.fetch_commitments(session)),
    }
    job.update("cost", 52, "Querying Cost Explorer for spend by region")
    _optional(
        job,
        data,
        "region_costs",
        "spend by region",
        "Until then the multi-region view assumes all spend runs in one region.",
        lambda: cost.fetch_region_costs(
            session,
            ids,
            p.months,
            lambda done, total: job.update(
                "cost",
                52 + 3 * done // total,
                f"Querying Cost Explorer for spend by region: {done} of {total} accounts",
            ),
        ),
    )
    job.update("cost", 55, f"{len(data.get('region_costs') or [])} region cost line(s) collected")

    # 3c. Data held per account (GB-months of storage), for the data-gravity view. Optional.
    job.update("cost", 57, "Querying Cost Explorer for data stored")
    _optional(
        job,
        data,
        "storage",
        "data stored",
        "The resilience view will not size the data to move.",
        alongside["storage"].result,
    )
    job.update("cost", 58, f"{len(data.get('storage') or [])} storage line(s) collected")

    # 3c2. Direct Connect ports and data out, to size the links an exit would need. Optional. Asked for
    # the whole organisation: the links usually sit in a network account outside the scanned OU.
    job.update("cost", 58, "Querying Cost Explorer for Direct Connect links")
    _optional(
        job,
        data,
        "direct_connect",
        "Direct Connect links",
        "The resilience view will not show the links you have today.",
        alongside["direct_connect"].result,
    )

    # 3d. Savings Plans and reservations with their end dates, to time an exit. Optional.
    job.update("cost", 59, "Querying Cost Explorer for Savings Plans and reservations")
    _optional(
        job,
        data,
        "commitments",
        "Savings Plans and reservations",
        "Grant ce:GetSavingsPlansUtilizationDetails and ce:GetReservationUtilization "
        "to time the exit against commitments.",
        alongside["commitments"].result,
    )

    # Account tags, read in the background since step 2b. Optional, so a refusal is a warning.
    if tags_read:
        job.update("organizations", 60, "Reading account tags (criticality, channel)")
        if _optional(
            job,
            data,
            "tags",
            "account tags",
            "Grant organizations:ListTagsForResource, or name the critical accounts in the console.",
            tags_read.result,
            category="organizations",
        ):
            tags = data.pop("tags")
            for a in data["accounts"]:
                a["tags"] = tags.get(a["id"], {})

    # 4. Optional deep inventory through a role in each member account.
    if p.inventory:
        data["inventory"] = _run_inventory(job, session, accounts, data["identity"]["account_id"])

    status = "complete" if not any(i.severity in ("error", "critical") for i in job.issues) else "partial"
    job.update("saving", 99, "Saving the scan")
    doc = _document(job, data, status=status)
    # Saved before the status says complete: the console loads the report the moment it sees that.
    store.save_scan(doc)
    job.status = status
    job.update("complete", 100, f"Scan {status}: {len(accounts)} account(s), {len(job.issues)} issue(s)")
    return doc


def _run_inventory(job: ScanJob, session, accounts, caller: str) -> dict:
    """Inventory each active account through the scan role; the caller's own account uses the session as is."""
    p = job.params
    results: dict = {}
    done = 0

    pair = None if p.role_name else sso.profile_permission_set(p.profile)
    access = p.role_name or (f"permission set {pair[1]}" if pair else "your sign-in")
    if pair:
        job.add_issue(
            Issue(
                "info",
                "inventory",
                f"Heads up: this deep scan uses your own sign-in ({access}). It can skip accounts if AWS throttles "
                "the sign-in portal or your sign-in expires mid-scan; each skipped account is listed as its own issue.",
                "Sign in just before a long deep scan, or give a member role to assume (ExitRiskReadOnly).",
            )
        )

    def one(account):
        try:
            sess = (
                session if account.id == caller else member_session(session, p.profile, account.id, p.role_name, job.id)
            )
        except Exception as exc:  # AWS refusal, or an expired IAM Identity Center sign-in
            code, msg, hint = describe_exception(exc)
            return (
                account,
                None,
                [
                    Issue(
                        "error",
                        "inventory",
                        f"cannot reach {account.name} as {access}: {msg}",
                        hint
                        or (
                            "Deploy the read-only role from docs/IAM_PERMISSIONS.md."
                            if p.role_name
                            else "Assign your permission set in this account, or give a member role to assume."
                        ),
                        account_id=account.id,
                        error_code=code,
                    )
                ],
            )
        try:
            inv, issues = inventory.inventory_account(sess, account.id, p.regions, dependencies=p.dependencies)
        except Exception as exc:  # one account's odd answer must not lose the other accounts
            if not isinstance(exc, (ClientError, BotoCoreError)):
                log.exception("inventory of %s failed with an unexpected error", account.id)
            code, msg, hint = describe_exception(exc)
            severity = "critical" if is_fatal_auth_error(code) else "error"
            issue = Issue(
                severity,
                "inventory",
                f"inventory of {account.name} failed: {msg}",
                hint,
                account_id=account.id,
                error_code=code,
            )
            return account, None, [issue]
        return account, inv, issues

    active = [a for a in accounts if a.status in ("ACTIVE", "UNKNOWN")]
    if p.inventory_scope == "material":
        keep = material_accounts(job.data.get("costs") or [], p.months)
        log.info(
            "selective deep scan: %d of %d account(s) are material", len(keep & {a.id for a in active}), len(active)
        )
        active = [a for a in active if a.id in keep]
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
                60 + int(38 * done / max(len(active), 1)),
                f"{done} of {len(active)} accounts scanned: {account.name}",
            )
    return results
