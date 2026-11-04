"""Scan orchestration: Organizations -> Cost Explorer -> (optional) inventory.

A scan runs in a background thread and reports progress through ``ScanJob``. It is
designed to degrade, not die: a member account that refuses the inventory role, a region
that is not enabled, or a throttled call each become an Issue on the scan, and the score
is computed from whatever was collected. Only an authentication failure or a failed
Cost Explorer query (without which there is no score) fails the scan.
"""

from __future__ import annotations

import contextvars
import re
import threading
import time
import traceback
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone

from botocore.exceptions import BotoCoreError, ClientError

from . import network, procs, sso, store
from .aws_session import ClientCache, caller_identity, make_session, member_session
from .collectors import assurance, assurance_org, cost, inventory, organizations
from .collectors import outage as outage_checks
from .config import settings
from .issues import Issue, describe_exception, is_fatal_auth_error
from .logging_config import get_logger, run_id_var
from .parallel import background
from .procs import InventoryPool

log = get_logger("scanner")


INVENTORY_SCOPES = ("all", "material")
REGION_SCOPES = ("all", "spend")
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


# A deep scan limited to "regions with spend" reads, in each account, the regions billing at least
# this much a month. Below it sit mostly the landing-zone baseline (Security Hub, CloudTrail, Config
# rules and their Lambda functions); a resource that costs nothing yet is missed, so "all" stays.
SPEND_REGION_MONTHLY = 1.0
_REGION_NAME = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")


def spend_regions(region_costs: list[dict]) -> dict[str, list[str]]:
    """Per account, the regions worth a deep scan: those with spend, busiest first.

    An account whose regional spend is all under the bar keeps its busiest region; an account with
    no regional spend at all is left out, and the caller scans it in every region.
    """
    by_account: dict[str, dict[str, float]] = {}
    for r in region_costs:
        if _REGION_NAME.match(r["region"]):
            regions = by_account.setdefault(r["account_id"], {})
            regions[r["region"]] = regions.get(r["region"], 0.0) + r["monthly"]
    out = {}
    for aid, regions in by_account.items():
        ranked = sorted(regions, key=lambda k: -regions[k])
        out[aid] = [k for k in ranked if regions[k] >= SPEND_REGION_MONTHLY] or ranked[:1]
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
    # "all" enabled regions in every account, or only the regions where each account has "spend".
    region_scope: str = "all"
    # Cloud Assurance Framework checks: governance and control settings in every account, plus the
    # organisation-level controls read in the management account. Independent of the inventory.
    assurance: bool = False
    # Outage risk checks: limits, utilisation, storage and EKS workloads in every account.
    outage: bool = False
    label: str = ""
    target: str = "azure"  # exit target asked at scan time; seeds the estimate questionnaire
    # Complete an earlier scan: read only the accounts it could not read, or read with a failed check, and
    # keep the rest (its organisation, spend and the accounts it read). Saved as a new scan.
    completes: str | None = None
    completes_eks: bool = False  # also read again the accounts with an EKS cluster the earlier scan could not read

    @property
    def ous(self) -> list[str]:
        return list(dict.fromkeys([*(self.ou_ids or []), *([self.ou_id] if self.ou_id else [])]))

    def validate(self) -> None:
        if self.dependencies:
            self.inventory = True
        if self.inventory_scope not in INVENTORY_SCOPES:
            raise ValueError(f"inventory_scope must be one of {', '.join(INVENTORY_SCOPES)}")
        if self.region_scope not in REGION_SCOPES:
            raise ValueError(f"region_scope must be one of {', '.join(REGION_SCOPES)}")
        if not 1 <= self.months <= 12:
            raise ValueError("months must be between 1 and 12")
        if (
            (self.inventory or self.assurance or self.outage)
            and not self.role_name
            and not sso.profile_permission_set(self.profile)
        ):
            raise ValueError(
                "a member-account role name is required for the resource inventory, assurance and outage risk checks "
                "(or use an IAM Identity Center profile, whose permission set is then used in each account)"
            )


# How long a deep scan waits for the user to sign in again when the sign-in ends part-way.
SIGN_IN_WAIT_SECONDS = 15 * 60
SIGN_IN_POLL_SECONDS = 3
# How often one account, or one organisation-wide call, is read again after a lost network.
NETWORK_RETRIES = 6


class ScanFailed(RuntimeError):
    pass


class ScanCancelled(BaseException):
    """Stopped from the console. A BaseException, so no collector's ``except Exception`` swallows it."""


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
    # The per-account step running now and what it has read: (its key in data, accounts read so far).
    step: tuple[str, dict] | None = field(default=None, repr=False)
    # The IAM Identity Center session to sign in to again while a deep scan waits for it, else None.
    needs_sign_in: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _sign_in_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _sign_in_gave_up: bool = False
    finished_at: float | None = field(default=None, repr=False)  # time.monotonic() once finished
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)
    started_at: float = field(default_factory=time.monotonic, repr=False)
    # The time left in the per-account step running now, for the console's ETA: {"step", "done", "total",
    # "seconds_left" (None until a few accounts are done), "then" (a step still to come, or None),
    # "parallel" (accounts read at once)}.
    eta: dict | None = None
    # Completing a scan: per step, the accounts the earlier scan read and this one keeps.
    kept: dict = field(default_factory=dict, repr=False)
    # Lost network: paused until it is back. ``net_epoch`` counts the pauses, so an account read across
    # one is read again; ``paused_seconds`` is left out of the pace behind the ETA.
    paused: bool = False
    net_epoch: int = 0
    paused_seconds: float = 0.0
    _net_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def cancel(self) -> None:
        """Ask the scan to stop: it does within seconds, and keeps what it has read."""
        self._cancel.set()
        log.info("scan %s: stop asked from the console", self.id)

    def check_cancelled(self) -> None:
        if self._cancel.is_set():
            raise ScanCancelled

    def finish(self, status: str, message: str) -> None:
        """Status, phase and message in one step, so a poll never sees "complete" with a stale message."""
        phase = status if status in ("failed", "cancelled") else "complete"
        with self._lock:
            self.status, self.phase, self.pct, self.message = status, phase, 100, message
            self.finished_at = time.monotonic()
        log.info("[%s 100%%] %s", phase, message, extra={"phase": phase})

    def _set_sign_in(self, session_name: str | None) -> None:
        with self._lock:
            self.needs_sign_in = session_name

    def update(self, phase: str, pct: int, message: str, eta: dict | None = None) -> None:
        self.check_cancelled()
        with self._lock:
            self.phase, self.pct, self.message, self.eta = phase, pct, message, eta
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
                "needs_sign_in": self.needs_sign_in,
                "elapsed_seconds": round((self.finished_at or time.monotonic()) - self.started_at),
                "eta": self.eta,
                "paused": self.paused,
            }

    def wait_for_network(self) -> bool:
        """Offline: pause until the connection is back, however long (a laptop shut overnight). Stop still
        works. True if it paused. Threads that find it offline together wait as one."""
        if network.online():
            return False
        with self._net_lock:
            if network.online():
                return True  # another thread waited it out
            with self._lock:
                phase, pct, message, eta = self.phase, self.pct, self.message, self.eta
                self.paused = True
                self.net_epoch += 1
            try:
                waited = network.wait_until_online(
                    lambda s: self.update(phase, pct, network.paused_message(s), eta),
                    stop=self._cancel.is_set,
                )
            except network.Cancelled:
                raise ScanCancelled from None
            finally:
                with self._lock:
                    self.paused = False
            with self._lock:
                self.paused_seconds += waited
            self.update(phase, pct, message, eta)
            return True

    def retry_offline(self, fn, *args):
        """``fn(*args)``, called again after a pause for each time it fails because the network is gone."""
        for attempt in range(NETWORK_RETRIES):
            try:
                return fn(*args)
            except Exception as exc:
                if attempt == NETWORK_RETRIES - 1 or not network.is_network_error(exc) or not self.wait_for_network():
                    raise
                log.info("retrying after the network came back")
        raise AssertionError("unreachable")  # pragma: no cover

    def wait_for_sign_in(self, session_name: str, rejected=None) -> bool:
        """The sign-in ended mid-scan and could not be renewed: wait for the user to sign in again,
        up to SIGN_IN_WAIT_SECONDS, instead of skipping every account left. True once signed in.
        Threads that hit it together wait in turn; once one gives up, the rest skip at once. ``rejected``:
        a token AWS refused though it looks valid here, as when a sign-in is revoked: a new one must replace it."""
        with self._sign_in_lock:
            token = sso.load_token(session_name)
            if token and token != rejected:
                return True  # another thread waited and the user signed in
            if self._sign_in_gave_up:
                return False
            with self._lock:
                phase, pct, message = self.phase, self.pct, self.message
            self._set_sign_in(session_name)
            deadline = time.monotonic() + SIGN_IN_WAIT_SECONDS
            try:
                while time.monotonic() < deadline:
                    if not network.online():  # a token cannot be renewed offline: wait for the network first
                        t_off = time.monotonic()
                        self.wait_for_network()
                        deadline += time.monotonic() - t_off
                        token = sso.load_token(session_name)
                        if token and token != rejected:
                            self.update(phase, pct, message)
                            return True
                    left = max(1, round((deadline - time.monotonic()) / 60))
                    self.update(
                        phase,
                        pct,
                        f"Your AWS sign-in has ended. Sign in again to carry on: the scan waits {left} more min",
                    )
                    time.sleep(SIGN_IN_POLL_SECONDS)
                    token = sso.load_token(session_name)
                    if token and token != rejected:
                        self.update(phase, pct, message)
                        log.info("signed in again; the deep scan carries on")
                        return True
                self._sign_in_gave_up = True
                return False
            finally:
                self._set_sign_in(None)


_jobs: dict[str, ScanJob] = {}
_jobs_lock = threading.Lock()
# A finished scan's job is kept this long for the console's last polls; after that its status comes
# from the saved scan, so a console left running for months does not hold every scan it ran.
JOB_KEEP_SECONDS = 3600


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
    now = time.monotonic()
    with _jobs_lock:
        for old in [k for k, j in _jobs.items() if j.finished_at and now - j.finished_at > JOB_KEEP_SECONDS]:
            del _jobs[old]
        _jobs[job.id] = job
    threading.Thread(target=_run_safely, args=(job,), name=f"scan-{job.id}", daemon=True).start()
    return job


def _run_safely(job: ScanJob) -> None:
    token = run_id_var.set(job.id)
    try:
        run_scan(job)
    except ScanCancelled:
        kept = _save_progress(job)
        job.finish("cancelled", f"Stopped. Saved what was read: {plural(kept, 'account')}." if kept else "Stopped.")
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
    try:
        store.save_scan(_document(job, _with_step(job), failed=True))
    except Exception:
        log.exception("could not save the failed scan %s", job.id)
        msg = f"{msg}. The results could not be saved either: check the disk has room, and the log"
    # After the save: the console opens the scan the moment it sees this.
    job.finish("failed", msg)
    return msg


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _with_step(job: ScanJob) -> dict:
    """The scan's data with what the running per-account step has read so far."""
    if not job.step:
        return job.data
    key, results = job.step
    results = {**job.kept.get(key, {}), **results}
    read = dict(results) if key == "inventory" else {**(job.data.get(key) or {}), "accounts": dict(results)}
    return {**job.data, key: read}


def _save_progress(job: ScanJob) -> int:
    """Save what has been read as an interrupted scan; the accounts in it, 0 if none. Never raises: a full disk
    must not end a scan that could still finish and report it."""
    if not job.data.get("accounts"):
        return 0
    try:
        store.save_scan(_document(job, _with_step(job), status="interrupted"))
    except Exception:
        log.exception("could not save the progress of scan %s", job.id)
        return 0
    return len(job.step[1]) if job.step else len(job.data["accounts"])


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
        "assurance": data.get("assurance"),
        "outage": data.get("outage"),
        "unavailable": data.get("unavailable", {}),
        "completes": data.get("completes"),
        "org_accounts": data.get("org_accounts"),
        "issues": [i.to_dict() for i in job.issues],
    }


def _optional(job: ScanJob, data: dict, key: str, what: str, advice: str, fetch, category: str = "cost") -> bool:
    """Collect optional data into data[key]. A refusal never fails the scan, but it is recorded in
    data["unavailable"] so the report says why the section is empty rather than "run a new scan". An
    expired sign-in is an error, so a scan that lost its credentials part-way is saved as partial."""
    try:
        data[key] = job.retry_offline(fetch)
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
    known: dict = {}  # OU id -> its accounts, for the whole organisation
    tree = None
    try:
        data["identity"] = job.retry_offline(caller_identity, session)
    except Exception as exc:
        code, msg, hint = describe_exception(exc)
        job.add_issue(Issue("critical", "auth", f"could not authenticate: {msg}", hint, error_code=code))
        raise ScanFailed(msg) from exc
    job.update("auth", 10, f"Authenticated as {data['identity']['arn']}")
    if p.completes:
        return _complete(job, session, data)

    # 2. Organisation and accounts.
    job.update("organizations", 15, "Reading the organisation's OU tree")
    try:
        # Always read fresh: a scan is evidence, so an OU moved minutes ago must count. The picker's
        # cached copy is refreshed with what the scan saw.
        data["org"] = job.retry_offline(organizations.describe_org, session)
        tree = job.retry_offline(
            organizations.list_ou_tree,
            session,
            known,
            lambda n_ous, n_accts: job.update(
                "organizations", 15, f"Reading the organisation's OU tree: {n_ous} OUs, {n_accts} accounts found"
            ),
        )
        organizations.remember_org_and_tree(p.profile, data["org"], tree)
        data["org_accounts"] = _org_accounts(tree, known)
        ous = [organizations.find_ou(tree, i) for i in p.ous] if p.ous else [tree]
        missing = [i for i, ou in zip(p.ous, ous, strict=False) if ou is None]
        if missing:
            raise ScanFailed(f"OU {', '.join(missing)} not found in this organisation")
        data["ou"] = {k: " + ".join(ou[k] for ou in ous) for k in ("id", "name", "path")}
        data["ous"] = [{k: ou[k] for k in ("id", "name", "path")} for ou in ous]
        # Nested picks (an OU and one of its children) overlap: keep each account once.
        seen: dict[str, organizations.Account] = {}
        for ou in ous:
            for a in job.retry_offline(organizations.list_accounts_under, session, ou, known):
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
                f"organisation's management account is {mgmt}. Scanning account {acct} only."
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
        job.finish("complete", "No accounts to scan")
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
        data["costs"], data["period"] = job.retry_offline(
            cost.fetch_costs,
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
    caller = data["identity"]["account_id"]
    regions_for = _region_picker(job) if p.inventory or p.assurance or p.outage else None
    steps = [s for s, on in (("inventory", p.inventory), ("assurance", p.assurance), ("outage", p.outage)) if on]

    def span_of(step: str) -> tuple[int, int]:
        at, width = steps.index(step), 38 // len(steps)
        return 60 + at * width, 98 if step == steps[-1] else 60 + (at + 1) * width

    if p.inventory:
        then = STEP_LABELS[steps[1]] if len(steps) > 1 else None
        data["inventory"] = _run_inventory(job, session, accounts, caller, regions_for, span_of("inventory"), then=then)
        job.step = None

    # 5. Optional Cloud Assurance Framework checks: the organisation's controls, then each account.
    if p.assurance:
        data["assurance"] = _run_assurance(
            job, session, accounts, caller, regions_for, tree, known, span_of("assurance")
        )
        job.step = None

    # 6. Optional outage risk checks in each account.
    if p.outage:
        data["outage"] = _run_outage(job, session, accounts, caller, regions_for, span_of("outage"))
        job.step = None

    return _save_finished(job, data, accounts)


def _save_finished(job: ScanJob, data: dict, accounts) -> dict:
    status = "complete" if not any(i.severity in ("error", "critical") for i in job.issues) else "partial"
    job.update("saving", 99, "Saving the scan")
    doc = _document(job, data, status=status)
    # Saved before the status says complete: the console loads the report the moment it sees that.
    store.save_scan(doc)
    by_level = Counter(i.severity for i in job.issues)
    log.info(
        "scan %s: %d accounts, issues %s; outage read %s, assurance read %s, inventory read %s",
        status,
        len(accounts),
        dict(by_level),
        len((data.get("outage") or {}).get("accounts") or {}),
        len((data.get("assurance") or {}).get("accounts") or {}),
        len(data.get("inventory") or {}),
    )
    job.finish(status, f"Scan {status}: {len(accounts)} account(s), {len(job.issues)} issue(s)")
    return doc


def _org_accounts(tree: dict, known: dict) -> dict[str, dict]:
    """Every account in the organisation with its name and OU, so a report can name an account outside the
    scan that the scanned ones depend on (a network or shared-services account)."""
    paths: dict[str, str] = {}
    stack = [tree]
    while stack:
        node = stack.pop()
        paths[node["id"]] = node["path"]
        stack.extend(node.get("children") or [])
    return {
        a["Id"]: {"name": a.get("Name", ""), "ou_path": paths.get(ou, "")}
        for ou, found in known.items()
        for a in found
        if a.get("Id")
    }


STEPS = ("inventory", "assurance", "outage")


def _step_results(scan: dict, key: str) -> dict:
    """The accounts a step read: the inventory is keyed by account, the checks under "accounts"."""
    return (scan.get("inventory") or {}) if key == "inventory" else ((scan.get(key) or {}).get("accounts") or {})


def incomplete_accounts(scan: dict) -> dict[str, dict]:
    """Per per-account step the scan ran, the accounts to read again to complete it: those it could not read
    ("missing"), those it read with a check that failed ("failed"), and for the outage checks those with an EKS
    cluster it could not read ("eks"): worth reading again once the cluster gives the scan an access entry."""
    params = scan.get("params") or {}
    active = {a["id"] for a in scan.get("accounts") or [] if a.get("status") in ("ACTIVE", "UNKNOWN")}
    out: dict[str, dict] = {}
    for key in STEPS:
        if not params.get(key):
            continue
        want = active
        if key == "inventory" and params.get("inventory_scope") == "material":
            want = active & material_accounts(scan.get("costs") or [], int(params.get("months") or 12))
        read = _step_results(scan, key)
        missing = want - set(read)
        failed = {
            i["account_id"]
            for i in scan.get("issues") or []
            if i.get("category") == key
            and i.get("severity") in ("warning", "error", "critical")
            and i.get("account_id")
        }
        eks = set()
        if key == "outage":
            eks = {acct for acct, r in read.items() if any(c.get("access") != "read" for c in r.get("clusters") or [])}
        failed = (failed & want) - missing
        out[key] = {
            "missing": sorted(missing),
            "failed": sorted(failed),
            "eks": sorted((eks & want) - missing - failed),
        }
    return out


def _complete(job: ScanJob, session, data: dict) -> dict:
    """Read again only what an earlier scan could not read, keep the rest, and save the whole as a new scan."""
    p = job.params
    try:
        base = store.load_scan(p.completes)
    except store.ScanNotFound as exc:
        raise ScanFailed(f"scan {p.completes} to complete was not found") from exc
    if (base.get("identity") or {}).get("account_id") != data["identity"]["account_id"]:
        job.add_issue(
            Issue(
                "critical",
                "auth",
                "this sign-in is in a different AWS account from the scan being completed",
                "Sign in with the profile that ran the scan.",
            )
        )
        raise ScanFailed("sign in with the profile that ran the scan to complete it")
    keep = ("org", "ou", "ous", "accounts", "costs", "region_costs", "storage", "direct_connect", "commitments")
    for k in (*keep, "org_accounts"):
        data[k] = base.get(k)
    data["period"] = base.get("period")
    data["unavailable"] = base.get("unavailable") or {}
    data["completes"] = base["id"]
    todo = incomplete_accounts(base)
    redo = {
        k: set(v["missing"]) | set(v["failed"]) | (set(v["eks"]) if p.completes_eks else set()) for k, v in todo.items()
    }
    # The earlier scan's issues stay, except those of the accounts read again: they are read afresh.
    for i in base.get("issues") or []:
        if not (i.get("account_id") and i.get("account_id") in redo.get(i.get("category"), ())):
            job.issues.append(Issue(**{k: i.get(k) for k in Issue.__dataclass_fields__ if k in i}))
    fields = organizations.Account.__dataclass_fields__
    accounts = [organizations.Account(**{k: a.get(k, "") for k in fields}) for a in data["accounts"] or []]
    caller = data["identity"]["account_id"]
    total = sum(len(v) for v in redo.values())
    log.info("completing scan %s: %s", base["id"], {k: len(v) for k, v in redo.items()})
    job.update("organizations", 55, f"Completing scan {base['id']}: {plural(total, 'account')} to read again")
    steps = [k for k in STEPS if redo.get(k)]
    regions_for = _region_picker(job) if steps else None
    for at, key in enumerate(steps):
        width = 40 // len(steps)
        span = (58 + at * width, 98 if key == steps[-1] else 58 + (at + 1) * width)
        subset = [a for a in accounts if a.id in redo[key]]
        kept = {acct: r for acct, r in _step_results(base, key).items() if acct not in redo[key]}
        job.kept[key] = kept
        if key == "inventory":
            data["inventory"] = {**kept, **_run_inventory(job, session, subset, caller, regions_for, span)}
        elif key == "assurance":
            got = _run_assurance(job, session, subset, caller, regions_for, None, {}, span, org=base.get("assurance"))
            data["assurance"] = {**got, "accounts": {**kept, **got["accounts"]}}
        else:
            got = _run_outage(job, session, subset, caller, regions_for, span)
            data["outage"] = {**(base.get("outage") or {}), **got, "accounts": {**kept, **got["accounts"]}}
        job.step = None
        job.kept.pop(key, None)
    for key in STEPS:  # a step with nothing to read again keeps what the earlier scan read
        if key not in steps and key in todo:
            data[key] = base.get(key)
    return _save_finished(job, data, accounts)


# A kill or a reboot at account 300 of 340 must not lose the first 299.
SAVE_EVERY_ACCOUNTS = 25
SAVE_EVERY_SECONDS = 300
WAIT_POLL_SECONDS = 2
STALL_WARN_SECONDS = 600
STEP_LABELS = {"assurance": "Assurance checks", "outage": "Outage risk checks"}


def _region_picker(job: ScanJob):
    """regions_for(account id): the regions a deep read covers in that account, busiest first."""
    p = job.params
    with_spend = None
    if p.region_scope == "spend":
        if job.data.get("region_costs"):
            with_spend = spend_regions(job.data["region_costs"])
            per = [len(v) for v in with_spend.values()]
            job.add_issue(
                Issue(
                    "info",
                    "inventory",
                    f"This deep scan reads only the regions with spend (US${SPEND_REGION_MONTHLY:g} a month or more): "
                    f"{sum(per) / max(len(per), 1):.1f} region(s) per account on average. Resources in the other "
                    "regions, which cost nothing yet, are not counted.",
                    "Scan all regions to count everything, including resources that cost nothing yet.",
                )
            )
        else:
            job.add_issue(
                Issue(
                    "warning",
                    "inventory",
                    "Spend by region is not available, so the deep scan reads every region instead of only "
                    "the regions with spend.",
                    "Grant Cost Explorer access (ce:GetCostAndUsage) to the management account.",
                )
            )

    def regions_for(account_id: str) -> list[str] | None:
        if with_spend is None or account_id not in with_spend:
            return p.regions
        mine = with_spend[account_id]
        return ([r for r in mine if r in p.regions] or p.regions) if p.regions else mine

    return regions_for


def _busiest_regions(job: ScanJob) -> dict[str, str]:
    """Each account's region with the most spend."""
    spend: dict[str, dict[str, float]] = {}
    for r in job.data.get("region_costs") or []:
        region = r.get("region") or ""
        if region and region not in ("global", "NoRegion"):
            acct = spend.setdefault(r["account_id"], {})
            acct[region] = acct.get(region, 0.0) + float(r.get("monthly") or 0)
    return {a: max(v, key=v.get) for a, v in spend.items() if v}


def _run_inventory(
    job: ScanJob, session, accounts, caller: str, regions_for=None, span=(60, 98), then: str | None = None
) -> dict:
    """Inventory each active account through the scan role; the caller's own account uses the session as is."""
    p = job.params
    regions_for = regions_for or _region_picker(job)
    active = [a for a in accounts if a.status in ("ACTIVE", "UNKNOWN")]
    if p.inventory_scope == "material":
        keep = material_accounts(job.data.get("costs") or [], p.months)
        log.info(
            "selective deep scan: %d of %d account(s) are material", len(keep & {a.id for a in active}), len(active)
        )
        active = [a for a in active if a.id in keep]

    def read(workers, sess, account):
        fn = workers.inventory_account if workers else inventory.inventory_account
        return fn(sess, account.id, regions_for(account.id), dependencies=p.dependencies)

    return _each_account(job, session, active, caller, read, "inventory", "scanned", span, then)


def _run_assurance(
    job: ScanJob, session, accounts, caller: str, regions_for, tree, known: dict, span, org: dict | None = None
) -> dict:
    """The organisation-level controls from the management account, then each active account's checks."""
    p = job.params
    active = [a for a in accounts if a.status in ("ACTIVE", "UNKNOWN")]
    rows = job.data.get("accounts") or []
    busiest = _busiest_regions(job)
    org_facts: dict = {}
    mgmt = (job.data.get("org") or {}).get("management_account_id")
    if org is not None:  # completing a scan: the organisation's controls were read by the earlier scan
        org_facts = org.get("org") or {}
    elif mgmt and mgmt == caller:
        pair = sso.profile_permission_set(p.profile)
        try:
            sso_region = sso._session_config(pair[0]).get("sso_region") if pair else None
        except sso.SSOFailure:
            sso_region = None
        org_facts, issues = assurance_org.org_checks(
            session, tree, rows, sso_region, busiest.get(caller) or "us-east-1",
            lambda what: job.update("assurance", span[0], f"Assurance: reading the organisation's {what}"),
        )  # fmt: skip
        for i in issues:
            job.add_issue(i)
    else:
        job.add_issue(
            Issue(
                "warning",
                "assurance",
                "Not running in the management account: guardrails (SCPs), central root access, Identity Center "
                "administrators and owner checks are not measured.",
                "Scan with a profile in the management account for the organisation-level checks.",
            )
        )
    org_ids = sorted({a["id"] for a in rows} | {a["Id"] for found in known.values() for a in found})
    services: dict[str, set[str]] = {}
    for r in job.data.get("costs") or []:
        if float(r.get("amount") or 0) > 0:
            services.setdefault(r["account_id"], set()).add(r["service"])
    ta_org = "trusted_advisor" in org_facts

    def read(workers, sess, account):
        info = {
            "org_ids": org_ids,
            "services": sorted(services[account.id]) if account.id in services else None,
            "ta_org": ta_org,
            "home": busiest.get(account.id),
        }
        fn = workers.assurance_account if workers else assurance.account_checks
        return fn(sess, account.id, regions_for(account.id), info)

    results = _each_account(job, session, active, caller, read, "assurance", "checked", span)
    return {
        "catalog_version": assurance.catalog_version(),
        "org": org_facts,
        "accounts": results,
    }


def _run_outage(job: ScanJob, session, accounts, caller: str, regions_for, span) -> dict:
    """Each active account's limits, utilisation, storage and EKS workloads."""
    active = [a for a in accounts if a.status in ("ACTIVE", "UNKNOWN")]
    busiest = _busiest_regions(job)
    services: dict[str, set[str]] = {}
    for r in job.data.get("costs") or []:
        if float(r.get("amount") or 0) > 0:
            services.setdefault(r["account_id"], set()).add(r["service"])

    def read(workers, sess, account):
        info = {
            "services": sorted(services[account.id]) if account.id in services else None,
            "home": busiest.get(account.id),
        }
        fn = workers.outage_account if workers else outage_checks.account_checks
        return fn(sess, account.id, regions_for(account.id), info)

    return {"accounts": _each_account(job, session, active, caller, read, "outage", "read", span)}


def eta_seconds(elapsed: float, done: int, total: int, parallel: int = 1) -> int | None:
    """Seconds left at the pace so far. Accounts run ``parallel`` at a time, so the first ones all
    finish after a full account's time: the pace means something once that many are done."""
    if done <= 0 or done < min(max(parallel, 3), total):
        return None
    return round(elapsed / done * (total - done))


def _each_account(
    job: ScanJob, session, active, caller: str, read, what: str, verb: str, span, then: str | None = None
) -> dict:
    """``read(workers, session, account) -> (result, issues)`` for each account through the scan role,
    accounts on threads (sign-in and AWS waits) and parsing in worker processes (CPU)."""
    p = job.params
    results: dict = {}
    job.step = (what, results)
    done = 0
    saved_at = time.monotonic()

    pair = None if p.role_name else sso.profile_permission_set(p.profile)
    access = p.role_name or (f"permission set {pair[1]}" if pair else "your sign-in")
    if pair and not any(i.category == "inventory" and i.message.startswith("Heads up") for i in job.issues):
        job.add_issue(
            Issue(
                "info",
                "inventory",
                f"Heads up: this deep scan uses your own sign-in ({access}). It is renewed as the scan runs; if it "
                "ends, the scan waits up to 15 minutes for you to sign in again. Accounts it still cannot reach "
                "(AWS throttling the sign-in portal, or no sign-in in time) are each listed as their own issue.",
                "Give a member role to assume (ExitRiskReadOnly) to avoid depending on your sign-in.",
            )
        )

    def one(account):
        """One account, read again if the network went away part-way: a laptop shut mid-scan picks up
        where it was, with nothing recorded as failed for the time it was offline."""
        for attempt in range(NETWORK_RETRIES):
            job.check_cancelled()  # an account still queued when the scan is stopped is not started
            epoch = job.net_epoch
            account_, out, issues, exc = read_one(account)
            offline = network.is_network_error(exc) or any(i.error_code in network.NETWORK_CODES for i in issues)
            if offline and attempt < NETWORK_RETRIES - 1 and (job.wait_for_network() or job.net_epoch != epoch):
                log.info("%s of %s: reading it again now the network is back", what, account.id)
                continue
            return account_, out, issues
        raise AssertionError("unreachable")  # pragma: no cover

    def read_one(account):
        """(account, result, issues, the exception that stopped it or None)."""
        try:
            try:
                sess = (
                    session
                    if account.id == caller
                    else member_session(session, p.profile, account.id, p.role_name, job.id)
                )
            except sso.SSOFailure:
                if not (pair and job.wait_for_sign_in(pair[0])):
                    raise
                sess = member_session(session, p.profile, account.id, p.role_name, job.id)
            except ClientError as exc:  # looks valid on this machine, but AWS revoked it
                if exc.response.get("Error", {}).get("Code") != "UnauthorizedException" or not pair:
                    raise
                log.warning("AWS refused the sign-in for %s; waiting for a new one", account.id)
                if not job.wait_for_sign_in(pair[0], rejected=sso.load_token(pair[0])):
                    raise
                sess = member_session(session, p.profile, account.id, p.role_name, job.id)
        except Exception as exc:  # AWS refusal, or an expired IAM Identity Center sign-in
            code, msg, hint = describe_exception(exc)
            return (
                account,
                None,
                [
                    Issue(
                        "error",
                        what,
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
                exc,
            )
        try:
            out, issues = read(workers, sess, account)
        except procs.Stopped:
            return account, None, [], None
        except Exception as exc:  # one account's odd answer must not lose the other accounts
            if not isinstance(exc, (ClientError, BotoCoreError)):
                log.exception("%s of %s failed with an unexpected error", what, account.id)
            code, msg, hint = describe_exception(exc)
            severity = "critical" if is_fatal_auth_error(code) else "error"
            issue = Issue(
                severity,
                what,
                f"{what} of {account.name} failed: {msg}",
                hint,
                account_id=account.id,
                error_code=code,
            )
            return account, None, [issue], exc
        return account, out, issues, None

    workers = (
        InventoryPool(min(settings.processes, len(active))) if settings.processes > 1 and len(active) > 1 else None
    )
    pool = ThreadPoolExecutor(max_workers=settings.max_workers)
    label = STEP_LABELS.get(what)
    step = label or "Deep scan"
    t0, paused0 = time.monotonic(), job.paused_seconds
    with workers or nullcontext():
        try:
            # Each account's thread runs in a copy of this context, so its log lines keep the scan's run id.
            waiting = {pool.submit(contextvars.copy_context().run, one, a): a for a in active}
            last_done = warned_at = time.monotonic()
            while waiting:
                finished, _ = wait(waiting, timeout=WAIT_POLL_SECONDS, return_when=FIRST_COMPLETED)
                job.check_cancelled()  # Stop works even while every account in hand is slow
                now = time.monotonic()
                if not finished and not job.paused and now - max(last_done, warned_at) > STALL_WARN_SECONDS:
                    warned_at = now
                    slow = [a.name for f, a in waiting.items() if f.running()]
                    minutes = (now - last_done) / 60
                    log.warning("%s: no account finished for %.0f min; still reading %s", what, minutes, slow)
                for fut in finished:
                    del waiting[fut]
                    account, out, issues = fut.result()
                    last_done = time.monotonic()
                    for i in issues:
                        job.add_issue(i)
                    if out:
                        results[account.id] = out
                    done += 1
                    text = f"{done} of {len(active)} accounts {verb}: {account.name}"
                    left = eta_seconds(time.monotonic() - t0 - (job.paused_seconds - paused0), done, len(active),
                                       settings.max_workers)  # fmt: skip
                    eta = {"step": step, "done": done, "total": len(active), "then": then, "seconds_left": left,
                           "parallel": settings.max_workers}  # fmt: skip
                    job.update(what, span[0] + int((span[1] - span[0]) * done / max(len(active), 1)),
                               f"{label}: {text}" if label else text, eta)  # fmt: skip
                    if done % SAVE_EVERY_ACCOUNTS == 0 or time.monotonic() - saved_at > SAVE_EVERY_SECONDS:
                        _save_progress(job)
                        saved_at = time.monotonic()
        except BaseException:
            # Ctrl+C or a failure: drop the accounts not yet started and stop the workers now, rather
            # than reading every remaining account first.
            pool.shutdown(wait=False, cancel_futures=True)
            if workers:
                workers.terminate()
            raise
        pool.shutdown()
    return results
