"""Health Check Report: what is most likely causing a problem in one or a few accounts, right now.

Runs on its own, not on a scan: pick a profile (an IAM Identity Center sign-in, or an access key saved in
``~/.aws/credentials`` for an account without SSO), tick the accounts, optionally describe the symptoms,
and the collectors in ``collectors/healthcheck.py`` read every check for the chosen window.

The report then ranks likely causes. A *cause* is something that can break a service (a change, an AWS
event, a refused call, capacity, a quota, an expired certificate, a failed deployment); a *symptom* is how
the breakage shows (errors, unhealthy targets, a backed up queue, an alarm). A cause gains weight from the
symptoms that started shortly after it in the same account and region, from sharing a resource name with
them, and from matching the symptoms you typed. A symptom no cause explains is listed as its own guess, so
nothing seen is hidden. Chronic findings (the same a day earlier) rank last: real, but not today's outage.
"""

from __future__ import annotations

import contextvars
import json
import os
import re
import secrets
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError

from . import sso
from .aws_session import BOTO_CONFIG, assume_role_session, caller_identity, make_session
from .collectors import healthcheck as hc
from .config import settings
from .issues import describe_exception
from .logging_config import get_logger

log = get_logger("healthcheck")

MAX_ACCOUNTS = 10
WINDOWS = (1, 3, 6, 12, 24, 72)  # hours offered
LINK_BEFORE = timedelta(minutes=15)  # a symptom this long before a cause can still be its effect (clock, period)
LINK_AFTER = timedelta(hours=3)
SEV = {"critical": 100, "high": 60, "medium": 30, "low": 10}
TOP = 10
_ID_RE = re.compile(r"^hc-[0-9]{8}-[0-9]{6}-[a-z0-9]{4}$")

# Which symptoms a kind of cause can explain.
EXPLAINS = {
    "network": {"app", "elb", "db", "network", "capacity", "platform", "deploy", "aws", "security"},
    "aws": {"app", "elb", "db", "network", "capacity", "platform", "deploy", "aws", "security"},
    "security": {"app", "elb", "db", "platform", "deploy", "security"},
    "capacity": {"app", "elb", "capacity", "platform"},
    "db": {"app", "elb", "db"},
    "deploy": {"app", "elb"},
    "platform": {"app", "elb", "platform", "capacity"},
    "app": {"app", "elb"},
}
# CloudTrail event source to the kind of cause a change there is.
SOURCE_KIND = {
    "ec2": "network", "elasticloadbalancing": "deploy", "route53": "network", "network-firewall": "network",
    "wafv2": "network", "cloudfront": "network", "lambda": "deploy", "ecs": "deploy", "apigateway": "deploy",
    "eks": "platform", "autoscaling": "capacity", "rds": "db", "dynamodb": "db", "elasticache": "db",
    "es": "db", "iam": "security", "kms": "security", "s3": "security", "secretsmanager": "security",
    "ssm": "deploy", "sts": "security", "acm": "security", "states": "deploy", "events": "deploy",
}  # fmt: skip
STOP_WORDS = set(
    "the a an and or is are was were be to of in on for with it its this that we our not no from at by as all any "
    "some since about after before when what why how there here they them have has had can cannot cant dont "
    "down up slow error errors issue issues problem problems outage broken failing fail fails customers users".split()
)


# ------------------------------------------------------------------------------------------ accounts
def reachable_accounts(profile: str | None, role_name: str | None = None) -> dict:
    """The accounts a health check can read with this profile: every account the sign-in reaches (IAM
    Identity Center), else the profile's own account plus, when it may list the organisation and a role
    is given, the organisation's accounts."""
    session = make_session(profile)
    ident = caller_identity(session)
    pair = sso.profile_permission_set(profile)
    out = {"caller": ident, "sso": bool(pair), "accounts": [], "organisation": False}
    if pair:
        found = sso.list_accounts(pair[0])["accounts"]
        out["accounts"] = [{"id": a["id"], "name": a["name"]} for a in found]
        out["organisation"] = True
        return out
    own = {"id": ident["account_id"], "name": _account_alias(session) or ident["account_id"]}
    out["accounts"] = [own]
    try:
        org = session.client("organizations", config=BOTO_CONFIG)
        accounts = [
            {"id": a["Id"], "name": a.get("Name") or a["Id"]}
            for page in org.get_paginator("list_accounts").paginate()
            for a in page["Accounts"]
            if a.get("Status") == "ACTIVE"
        ]
        out["organisation"] = True
        out["accounts"] = sorted(accounts, key=lambda a: (a["id"] != own["id"], a["name"].lower()))
    except (ClientError, BotoCoreError):
        pass  # a key in a member account sees only its own account
    out["needs_role"] = out["organisation"] and not role_name
    return out


def _account_alias(session) -> str | None:
    try:
        names = session.client("iam", config=BOTO_CONFIG).list_account_aliases().get("AccountAliases") or []
        return names[0] if names else None
    except (ClientError, BotoCoreError):
        return None


def _session_for(profile: str | None, base, caller: str, account_id: str, role_name: str | None, run_id: str):
    if account_id == caller:
        return base
    if role_name:
        return assume_role_session(base, account_id, role_name, run_id)
    pair = sso.profile_permission_set(profile)
    if not pair:
        raise ValueError(
            f"account {account_id} is not the profile's own account: give a role to assume in it, "
            "or use an IAM Identity Center profile"
        )
    return sso.role_session(pair[0], account_id, pair[1])


# ------------------------------------------------------------------------------------------ jobs
class Job:
    def __init__(self, run_id: str, req: dict):
        self.id = run_id
        self.req = req
        self.status = "running"
        self.done = 0
        self.total = 0
        self.message = "Starting"
        self.started = time.time()
        self.error: str | None = None
        self.cancelled = False

    def snapshot(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "done": self.done,
            "total": self.total,
            "message": self.message,
            "elapsed": round(time.time() - self.started),
            "error": self.error,
        }


_jobs: dict[str, Job] = {}
_jobs_lock = threading.Lock()


def _dir() -> Path:
    d = settings.data_dir / "health"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _path(run_id: str) -> Path:
    if not _ID_RE.fullmatch(run_id):
        raise KeyError(run_id)
    return _dir() / f"{run_id}.json"


def running() -> list[str]:
    with _jobs_lock:
        return [j.id for j in _jobs.values() if j.status == "running"]


def get_job(run_id: str) -> Job | None:
    with _jobs_lock:
        return _jobs.get(run_id)


def start(
    profile: str | None,
    accounts: list[dict],
    hours: float,
    symptoms: str = "",
    role_name: str | None = None,
    regions: list[str] | None = None,
) -> Job:
    if not accounts or len(accounts) > MAX_ACCOUNTS:
        raise ValueError(f"pick between 1 and {MAX_ACCOUNTS} accounts")
    if hours not in WINDOWS:
        raise ValueError(f"the window must be one of {', '.join(map(str, WINDOWS))} hours")
    run_id = datetime.now().strftime("hc-%Y%m%d-%H%M%S-") + secrets.token_hex(2)
    req = {"profile": profile, "accounts": accounts, "hours": hours, "symptoms": symptoms[:2000],
           "role_name": role_name, "regions": regions}  # fmt: skip
    job = Job(run_id, req)
    with _jobs_lock:
        _jobs[run_id] = job
    threading.Thread(target=contextvars.copy_context().run, args=(_run, job), daemon=True).start()
    return job


def cancel(run_id: str) -> bool:
    job = get_job(run_id)
    if not job or job.status != "running":
        return False
    job.cancelled = True
    return True


def _run(job: Job) -> None:
    req = job.req
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start_t = end - timedelta(hours=req["hours"])
    raw: dict = {"accounts": [], "unreachable": []}
    try:
        base = make_session(req["profile"])
        caller = caller_identity(base)["account_id"]
        ctxs = []
        job.message = "Finding the regions in use"
        for a in req["accounts"]:
            try:
                sess = _session_for(req["profile"], base, caller, a["id"], req["role_name"], job.id)
                regions = hc.active_regions(sess, req.get("regions"))
                ctxs.append((hc.Ctx(sess, a["id"], a.get("name") or a["id"], start_t, end), regions))
            except Exception as exc:  # one account out of reach must not stop the others
                code, msg, hint = describe_exception(exc)
                raw["unreachable"].append({"account": a["id"], "name": a.get("name"), "code": code,
                                           "message": msg[:300], "hint": hint})  # fmt: skip
        tasks = [(ctx, *t) for ctx, regions in ctxs for t in hc.account_tasks(ctx, regions)]
        job.total = len(tasks)

        def one(task):
            ctx, region, name, fn = task
            if job.cancelled:
                return
            job.message = f"{ctx.name}: {hc.CHECK_LABELS.get(name, name)} in {region}"
            hc.run_check(ctx, region, name, fn)
            job.done += 1

        with ThreadPoolExecutor(max_workers=hc.TASK_WORKERS) as pool:
            list(pool.map(lambda t: contextvars.copy_context().run(one, t), tasks))
        raw["accounts"] = [hc.result(ctx, regions) for ctx, regions in ctxs]
        job.status = "cancelled" if job.cancelled else "done"
    except Exception as exc:
        log.exception("health check %s failed", job.id)
        job.error = describe_exception(exc)[1]
        job.status = "failed"
    doc = {
        "id": job.id,
        "created": _iso(datetime.fromtimestamp(job.started, timezone.utc)),
        "finished": _iso(datetime.now(timezone.utc)),
        "status": job.status,
        "error": job.error,
        "request": {k: v for k, v in req.items()},
        "window": {"start": _iso(start_t), "end": _iso(end), "hours": req["hours"]},
        "raw": raw,
    }
    _save(doc)
    job.message = "Finished" if job.status == "done" else job.status.capitalize()


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _save(doc: dict) -> None:
    path = _path(doc["id"])
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, default=str, separators=(",", ":"))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load(run_id: str) -> dict:
    path = _path(run_id)
    if not path.exists():
        raise KeyError(run_id)
    return json.loads(path.read_text(encoding="utf-8"))


def delete(run_id: str) -> None:
    _path(run_id).unlink(missing_ok=True)


def list_runs() -> list[dict]:
    out = []
    for p in sorted(_dir().glob("hc-*.json"), reverse=True):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append({
            "id": d["id"], "created": d.get("created"), "status": d.get("status"),
            "hours": (d.get("window") or {}).get("hours"),
            "accounts": [a.get("name") or a["id"] for a in (d.get("request") or {}).get("accounts") or []],
            "symptoms": ((d.get("request") or {}).get("symptoms") or "")[:120],
        })  # fmt: skip
    return out


# ------------------------------------------------------------------------------------------ report
def _when(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9][a-z0-9-]{2,}", (text or "").lower()) if w not in STOP_WORDS}


def _matches(item: dict, words: set[str]) -> list[str]:
    if not words:
        return []
    hay = " ".join(
        [
            item.get("title", ""),
            item.get("resource", ""),
            item.get("area", ""),
            item.get("evidence", ""),
            item.get("account_name", ""),
            item.get("account", ""),
            " ".join(item.get("keywords") or []),
        ]
    ).lower()
    return sorted(w for w in words if w in hay)


def _overlap(a: str, b: str) -> bool:
    """Do two resource names share a meaningful part (a service or cluster name)?"""
    pa = {p for p in re.split(r"[/:|. _]+", (a or "").lower()) if len(p) >= 5 and not re.fullmatch(r"[0-9a-f-]+", p)}
    pb = {p for p in re.split(r"[/:|. _]+", (b or "").lower()) if len(p) >= 5 and not re.fullmatch(r"[0-9a-f-]+", p)}
    return bool(pa & pb)


def _change_causes(changes: list[dict]) -> list[dict]:
    """Changes as candidate causes: one per (account, region, event, resource), first time kept."""
    groups: dict[tuple, dict] = {}
    for c in changes:
        k = (c["account"], c["region"], c["event"], c["resource"])
        g = groups.get(k)
        if g is None or c["time"] < g["started"]:
            n = (g or {}).get("count", 0)
            groups[k] = {
                "account": c["account"], "account_name": c["account_name"], "region": c["region"],
                "area": "Change", "service": SOURCE_KIND.get(c["service"], "deploy"), "role": "cause",
                "title": f"{c['event']} on {c['resource'] or c['service']} by {c['who'] or 'unknown'}",
                "resource": c["resource"] or c["service"], "severity": "medium" if c["sharp"] else "low",
                "started": c["time"], "ongoing": False, "chronic": False, "count": n + 1,
                "evidence": f"{c['service']} {c['event']} at {c['time']} by {c['who']}",
                "next": "If the timing fits, undo or roll back this change first; it is the cheapest test.",
                "source": "CloudTrail", "check": "change", "sharp": c["sharp"],
            }  # fmt: skip
        else:
            g["count"] += 1
    for g in groups.values():
        if g["count"] > 1:
            g["evidence"] += f" ({g['count']} times in the window)"
    return list(groups.values())


def _close(cause_t: datetime | None, sym_t: datetime | None) -> float:
    """How well a symptom's start fits a cause's time: 1 within 30 minutes after, fading to 0 at 3 hours."""
    if not cause_t or not sym_t:
        return 0.0
    gap = sym_t - cause_t
    if gap < -LINK_BEFORE or gap > LINK_AFTER:
        return 0.0
    if gap <= timedelta(minutes=30):
        return 1.0
    return max(0.3, 1 - (gap - timedelta(minutes=30)) / (LINK_AFTER - timedelta(minutes=30)))


GROUP_AT = 3  # this many of one kind in one place read as one problem with a shared cause


def _group(signals: list[dict]) -> list[dict]:
    """Fold many signals of one kind in one account and region (a dozen throttled functions) into one,
    since they nearly always share a cause and would otherwise fill the top ten with one story."""
    buckets: dict[tuple, list[dict]] = {}
    for s in signals:
        key = (s["account"], s["region"], s.get("check"), bool(s.get("chronic")), s.get("role"))
        buckets.setdefault(key, []).append(s)
    out = []
    for items in buckets.values():
        if len(items) < GROUP_AT or items[0].get("check") in ("change", "health"):
            out += items
            continue
        items.sort(key=lambda s: (-SEV[s["severity"]], s.get("started") or ""))
        first = items[0]
        names = [s.get("resource") or s["title"] for s in items]
        starts = [s["started"] for s in items if s.get("started")]
        out.append({
            **first,
            "title": f"{len(items)} at once: {first['title']} and {len(items) - 1} more like it",
            "resource": ", ".join(names),
            "started": min(starts) if starts else None,
            "evidence": f"{first.get('evidence', '')}. Also: {', '.join(names[1:8])}"
                        + (f" and {len(names) - 8} more" if len(names) > 8 else ""),
            "next": (first.get("next") or "") + " Many at once points to something they share: an account "
                    "limit, a quota, or a common dependency.",
            "members": len(items),
        })  # fmt: skip
    return out


def rank(
    signals: list[dict], changes: list[dict], symptoms_text: str = "", window_start: str | None = None
) -> list[dict]:
    """The likely causes, best first, each with the symptoms it would explain."""
    words = _tokens(symptoms_text)
    ws = _when(window_start)
    signals = _group(signals)

    def at(item):
        # A start at the very edge of the window only means it was already happening: the real start is unknown.
        t = _when(item.get("started"))
        return None if t and ws and t < ws + timedelta(minutes=15) else t

    causes = [s for s in signals if s.get("role") == "cause"] + _change_causes(changes)
    effects = [s for s in signals if s.get("role") != "cause"]
    guesses, explained = [], set()
    for c in causes:
        ct = at(c)
        linked = []
        for i, e in enumerate(effects):
            same_place = e["account"] == c["account"] and (
                e["region"] == c["region"] or "global" in (e["region"], c["region"])
            )
            if not same_place or e.get("service") not in EXPLAINS.get(c.get("service"), set()):
                continue
            fit = _close(ct, at(e))
            named = _overlap(c.get("resource", ""), e.get("resource", ""))
            if c.get("ongoing") and not ct and named:
                fit = max(fit, 0.6)  # a standing condition (a full subnet) named like the failing resource
            if fit or (named and c["check"] != "change"):
                linked.append((fit + (0.5 if named else 0), i, e))
        hits = _matches(c, words)
        if c["check"] == "change" and not linked and not hits:
            continue  # a change with nothing after it is just a change
        score = SEV[c["severity"]] * (0.25 if c.get("chronic") else 1)
        score += min(sum(SEV[e["severity"]] * 0.5 * w for w, _, e in linked if not e.get("chronic")), 150)
        score += 40 * bool(hits) + 10 * bool(c.get("ongoing"))
        if c["check"] == "change" and c.get("sharp"):
            score += 15
        best = max((w for w, _, _ in linked), default=0)
        conf = "high" if best >= 1 else "medium" if linked or hits or c["severity"] == "critical" else "low"
        if c.get("chronic"):
            conf = "low"
        guesses.append(_guess(c, score, conf, [e for _, _, e in sorted(linked, key=lambda x: -x[0])], hits))
        if best >= 0.6:
            explained.update(i for w, i, _ in linked if w >= 0.6)
    for i, e in enumerate(effects):
        if i in explained:
            continue
        hits = _matches(e, words)
        score = SEV[e["severity"]] * (0.2 if e.get("chronic") else 0.7) + 40 * bool(hits) + 5 * bool(e.get("ongoing"))
        guesses.append(_guess(e, score, "low" if e.get("chronic") else "medium" if hits else "low", [], hits,
                              unexplained=True))  # fmt: skip
    guesses.sort(key=lambda g: (-g["score"], g.get("started") or ""))
    for n, g in enumerate(guesses, 1):
        g["rank"] = n
    return guesses


def _guess(item: dict, score: float, conf: str, linked: list[dict], hits: list[str], unexplained=False) -> dict:
    why = item.get("evidence", "")
    if linked:
        names = "; ".join(f"{e['title']} (from {(e.get('started') or '?')[11:16]})" for e in linked[:3])
        why += f". Followed by {len(linked)} symptom{'s' if len(linked) > 1 else ''}: {names}"
    if unexplained:
        why += ". No change or AWS event found that explains it: look at what this resource depends on."
    if hits:
        why += f". Matches your description: {', '.join(hits)}"
    return {
        "score": round(score, 1),
        "confidence": conf,
        "kind": "symptom" if unexplained else item.get("check") == "change" and "change" or "cause",
        "title": item["title"],
        "why": why,
        "account": item["account"],
        "account_name": item.get("account_name"),
        "region": item["region"],
        "resource": item.get("resource"),
        "area": item.get("area"),
        "severity": item["severity"],
        "started": item.get("started"),
        "ongoing": bool(item.get("ongoing")),
        "chronic": bool(item.get("chronic")),
        "next": item.get("next"),
        "source": item.get("source"),
        "members": item.get("members", 1),
        "linked": [{"title": e["title"], "started": e.get("started"), "severity": e["severity"]} for e in linked[:10]],
    }


def build_report(doc: dict) -> dict:
    raw = doc.get("raw") or {}
    accounts = raw.get("accounts") or []
    signals = [s for a in accounts for s in a.get("signals") or []]
    changes = [c for a in accounts for c in a.get("changes") or []]
    gaps = [g for a in accounts for g in a.get("gaps") or []]
    symptoms = (doc.get("request") or {}).get("symptoms") or ""
    guesses = rank(signals, changes, symptoms, (doc.get("window") or {}).get("start"))
    sev = Counter(s["severity"] for s in signals if not s.get("chronic"))
    timeline = sorted(
        [{"time": s.get("started"), "what": s["title"], "kind": s.get("role"), "severity": s["severity"],
          "account": s.get("account_name") or s["account"], "region": s["region"]}
         for s in signals if s.get("started") and not s.get("chronic")]
        + [{"time": c["time"], "what": f"{c['event']} on {c['resource'] or c['service']} by {c['who']}",
            "kind": "change", "severity": "medium" if c["sharp"] else "low",
            "account": c["account_name"], "region": c["region"]} for c in changes],
        key=lambda x: x["time"] or "", reverse=True,
    )  # fmt: skip
    top = [g for g in guesses if not g["chronic"]][:TOP]
    if len(top) < TOP:  # long standing problems only fill spare places, and only the serious ones
        top += [g for g in guesses if g["chronic"] and SEV[g["severity"]] >= SEV["high"]][: TOP - len(top)]
    top = [{**g, "rank": n} for n, g in enumerate(top, 1)]
    return {
        "id": doc["id"],
        "created": doc.get("created"),
        "status": doc.get("status"),
        "error": doc.get("error"),
        "window": doc.get("window"),
        "symptoms": symptoms,
        "accounts": [
            {
                "id": a["account"],
                "name": a.get("name"),
                "regions": a.get("regions") or [],
                "signals": len(a.get("signals") or []),
                "changes": len(a.get("changes") or []),
            }
            for a in accounts
        ],  # fmt: skip
        "unreachable": raw.get("unreachable") or [],
        "summary": {
            "critical": sev.get("critical", 0),
            "high": sev.get("high", 0),
            "medium": sev.get("medium", 0),
            "chronic": sum(1 for s in signals if s.get("chronic")),
            "changes": len(changes),
            "sharp_changes": sum(1 for c in changes if c["sharp"]),
            "gaps": len(gaps),
        },  # fmt: skip
        "top": top,
        "guesses": guesses,
        "signals": sorted(
            signals, key=lambda s: (s.get("chronic", False), -SEV[s["severity"]], s.get("started") or "")
        ),
        "changes": changes,
        "timeline": timeline[:400],
        "gaps": gaps,
        "checks": [hc.CHECK_LABELS[k] for k in hc.CHECK_LABELS],
    }
