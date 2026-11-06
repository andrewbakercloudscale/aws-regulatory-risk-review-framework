"""The Outage Risk Report: what is likely to fail at the next peak, by account, and where to start.

The scan reads measures in each account (collectors/outage.py). This module applies the answers
given in the report and judges each one:

* a capacity measure is critical at the critical threshold now, or if it fills before the peak; high
  if it would pass its limit at the expected peak load (usage that rises with traffic, multiplied by
  the expected load), or fills within 30 days after the peak; medium above the warning threshold;
* an event (throttling, rejected calls, an OOMKill) already happened in the lookback window, and a
  config finding is a setting that fails at load: both carry the rule's own severity;
* outside production everything is one level lower, as the peak is a production event. Filter to
  production with the report's filter to leave the rest out altogether.

Accounts score as in the Cloud Assurance Report: each rule failed adds its severity's points once,
with diminishing returns, and a critical sets the score to at least 80.

Nothing here calls AWS. Changing an answer needs no new scan.
"""

from __future__ import annotations

import csv
import io
import re
import time
from collections import Counter, defaultdict
from datetime import date, timedelta
from functools import lru_cache
from importlib import resources

import yaml
from pydantic import BaseModel, Field

from .assurance import _monthly_spend, _points_score, _rating, is_production
from .filtering import AccountFilter
from .logging_config import get_logger
from .outage_views import build_views
from .resilience import _patterns, owner_of

log = get_logger("outage")

SEVERITIES = ("critical", "high", "medium", "low")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
KEEP_PCT = 30.0  # the collector keeps no measure under this
AFTER_PEAK_DAYS = 30  # filling this soon after the peak is still worth doing before it
MAX_FINDINGS = 4000  # sent to the page, worst first; the counts always cover every finding
NOT_MEASURED = "Not measured"  # no check could read the account: no score, and first in the list, not "Low"
SYSTEM_NS = "kube-system,kube-public,kube-node-lease,amazon-cloudwatch,amazon-guardduty,aws-observability"


@lru_cache(maxsize=1)
def catalog() -> dict:
    """The rules and the published evidence, data/outage.yaml."""
    return yaml.safe_load(resources.files("exitrisk").joinpath("data/outage.yaml").read_text(encoding="utf-8"))


def black_friday(today: date | None = None) -> date:
    """The next Black Friday: the day after the fourth Thursday of November."""
    today = today or date.today()
    for year in (today.year, today.year + 1):
        first = date(year, 11, 1)
        thursday = first + timedelta(days=(3 - first.weekday()) % 7)
        friday = thursday + timedelta(days=22)
        if friday >= today:
            return friday
    raise AssertionError("unreachable")


class OutageAnswers(BaseModel):
    """The questions answered in the report, all optional."""

    # The peak; empty: the next Black Friday.
    peak_date: str = Field("", pattern=r"^(\d{4}-\d{2}-\d{2})?$")
    # Expected peak load as a multiple of the highest hourly load in the last 35 days, which holds a
    # month-end. An assumption until replaced with the measured ratio from last year.
    peak_multiplier: float = Field(2.0, ge=1.0, le=3.0)
    freeze_days: int = Field(14, ge=0, le=90)
    warn_pct: int = Field(70, ge=40, le=95)
    critical_pct: int = Field(90, ge=60, le=100)
    production_patterns: str = Field("prod,prd", max_length=200)
    cpu_request_floor_m: int = Field(100, ge=1, le=4000)
    memory_limit_floor_mi: int = Field(256, ge=1, le=65536)
    ignore_namespaces: str = Field(SYSTEM_NS, max_length=400)
    # When customers use the service, local time, every day: maintenance and backups should miss it.
    busy_hours: str = Field("06:00-22:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-4]):[0-5]\d$")
    utc_offset: float = Field(2.0, ge=-12, le=14)  # hours local time is ahead of UTC (South Africa: 2)


def _lower(sev: str) -> str:
    return SEVERITIES[min(SEV_ORDER[sev] + 1, len(SEVERITIES) - 1)]


def judge_capacity(row: dict, a: OutageAnswers, days_to_peak: int) -> tuple[str | None, float | None, str]:
    """(severity or None, percent at peak, why) of one capacity measure."""
    pct = row.get("pct") or 0.0
    peak = pct * a.peak_multiplier if row.get("load") else pct
    days = row.get("days")
    if days is not None and days <= days_to_peak:
        return "critical", round(peak, 1), f"at its limit in about {days:.0f} days, before the peak"
    if pct >= a.critical_pct:
        return "critical", round(peak, 1), f"at {pct:.0f}% already"
    if row.get("load") and peak >= 100:
        return "high", round(peak, 1), f"{pct:.0f}% now, {peak:.0f}% at {a.peak_multiplier:g}x load"
    if days is not None and days <= days_to_peak + AFTER_PEAK_DAYS:
        return "high", round(peak, 1), f"at its limit in about {days:.0f} days, soon after the peak"
    if peak >= a.warn_pct:
        return (
            "medium",
            round(peak, 1),
            f"{pct:.0f}% now" + (f", {peak:.0f}% at {a.peak_multiplier:g}x load" if row.get("load") else ""),
        )
    return None, round(peak, 1), ""


def judge_burstable(row: dict, a: OutageAnswers) -> tuple[str, str]:
    """(severity, why) of a burstable size, against the expected peak load: high when the peak would
    spend its credits and hold it to its baseline, medium when it bills for the surplus instead or
    nothing says how busy it is, low when it stays under its baseline even at the peak."""
    kind, base, cpu, unlimited = row.get("type", ""), row.get("baseline"), row.get("cpu"), row.get("unlimited")
    mode = {True: "unlimited credits", False: "standard credits"}.get(unlimited, "credit mode not known")
    credits = row.get("credits")
    floor = f" {base:g}%" if base else " its baseline"
    if credits is not None and credits < 5 and unlimited is not True:
        return "high", f"{kind}, {mode}: CPU credits fell to {credits:g}; at zero it is held to{floor} CPU"
    if cpu is None or not base:
        return "medium", f"{kind}, {mode}: no CPU figure to compare with its baseline"
    peak = cpu * a.peak_multiplier
    said = f"{kind}, {mode}: busiest hour {cpu:g}% CPU, {peak:.0f}% at {a.peak_multiplier:g}x load, baseline{floor}"
    if peak <= base:
        return "low", f"{said}; under it, but network and EBS bandwidth still burst"
    if unlimited:
        return "medium", f"{said}; above it, it keeps running and bills the surplus credits"
    return "high", f"{said}; above it the credits drain, then it is held to the baseline"


DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
WEEK = 7 * 1440


def _minute(text: str) -> int:
    h, m = text.split(":")
    return int(h) * 60 + int(m)


def _window_minutes(window: str) -> list[int] | None:
    """UTC minutes of the week a window covers: "sun:23:00-mon:00:30" weekly, "02:00-02:30" every day.
    None for anything not in either form."""
    try:
        start, end = window.strip().lower().split("-")
        if start[:3] in DAYS:
            a = DAYS.index(start[:3]) * 1440 + _minute(start[4:])
            b = DAYS.index(end[:3]) * 1440 + _minute(end[4:])
            span = (b - a) % WEEK or WEEK
            return [(a + i) % WEEK for i in range(span)]
        a, b = _minute(start), _minute(end)
        span = (b - a) % 1440 or 1440
        return [(day * 1440 + a + i) % WEEK for day in range(7) for i in range(span)]
    except (ValueError, IndexError):
        return None


def busy_overlap(window: str, a: OutageAnswers) -> int | None:
    """Minutes of the window in a week that fall in the busy hours, local time; None if unreadable."""
    minutes = _window_minutes(window)
    if minutes is None:
        return None
    s, e = (_minute(x) for x in a.busy_hours.split("-"))
    shift = round(a.utc_offset * 60)
    hit = 0
    for m in minutes:
        local = (m + shift) % 1440
        hit += (s <= local < e) if s <= e else (local >= s or local < e)
    return hit


def _local(window: str, a: OutageAnswers) -> str:
    """The window in local time, for the finding's text: "Sun 01:00 to Sun 01:30", or "04:00 to 04:30"."""
    shift = round(a.utc_offset * 60)

    def one(part: str) -> str:
        part = part.strip().lower()
        if part[:3] in DAYS:
            t = (DAYS.index(part[:3]) * 1440 + _minute(part[4:]) + shift) % WEEK
            return f"{DAYS[t // 1440].title()} {t % 1440 // 60:02d}:{t % 60:02d}"
        t = (_minute(part) + shift) % 1440
        return f"{t // 60:02d}:{t % 60:02d}"

    try:
        start, end = window.split("-")
        return f"{one(start)} to {one(end)}"
    except (ValueError, IndexError):
        return window


def judge_windows(row: dict, a: OutageAnswers) -> str | None:
    """Why the database's maintenance or backup window is in the busy hours, or None when neither is.
    A backup counts only on a single-AZ instance: Multi-AZ backs up from the standby, Aurora continuously."""
    said = []
    tz = f"UTC{a.utc_offset:+g}"
    maint = row.get("maintenance") or ""
    if maint and busy_overlap(maint, a):
        said.append(f"maintenance window {_local(maint, a)} ({tz}), {maint} UTC")
    backup = row.get("backup") or ""
    if backup and not row.get("multi_az") and busy_overlap(backup, a):
        said.append(f"daily backup {_local(backup, a)} ({tz}) on a single-AZ instance")
    if not said:
        return None
    return "; ".join(said) + f"; busy hours {a.busy_hours}"


BURSTABLE_RULES = {"ec2_burstable", "rds_burstable", "cache_burstable", "search_burstable", "msk_burstable"}


def _judge(row: dict, rule: dict, a: OutageAnswers, peak: date, days_to_peak: int, production: bool) -> dict | None:
    """The finding this row makes, or None."""
    if rule.get("prod_only") and not production:
        return None
    at_peak = None
    if rule["kind"] == "capacity":
        sev, at_peak, why = judge_capacity(row, a, days_to_peak)
        if not sev:
            return None
        if rule["id"] == "eks_nodegroup_max" and row.get("min") is not None and row.get("min") == row.get("limit"):
            sev, why = "medium", f"fixed at {row['limit']} node(s): minimum and maximum are the same"
    else:
        sev, why = row.get("sev") or rule["severity"], row.get("note", "")  # a row may know better
        if rule["id"] in BURSTABLE_RULES:
            sev, why = judge_burstable(row, a)
        elif rule["id"] in ("rds_maintenance", "ec2_event"):
            ends = date.fromisoformat(row["ends"])
            if ends > peak + timedelta(days=7):
                return None
            why = f"applies on {row['ends']}: {row.get('note', '')}"
        elif rule["id"] == "rds_busy_window":
            why = judge_windows(row, a)
            if not why:
                return None
        elif rule["id"] in ("cert_expiry", "iam_cert_expiry", "domain_expiry"):
            ends = date.fromisoformat(row["ends"])
            if ends > peak + timedelta(days=7):
                return None
            if row.get("auto"):  # AWS renews it: only worth a look when it has not by now
                if (ends - date.today()).days > 30:
                    return None
                sev = "medium"
            why = f"expires {row['ends']}, {row.get('note', '')}"
        elif row.get("used") is not None and row.get("unit"):
            why = f"{row['used']:,} {row['unit']}" + (f"; {why}" if why else "")
    if not production:
        sev = _lower(sev)
    return {
        "rule": rule["id"],
        "res": row["res"],
        "region": row["region"],
        "severity": sev,
        "why": why,
        "pct": row.get("pct"),
        "at_peak": at_peak,
        "used": row.get("used"),
        "limit": row.get("limit"),
        "unit": row.get("unit", ""),
        "days": row.get("days"),
        "hard": bool(row.get("hard")),
        "note": row.get("note", ""),
    }


def workload_rows(cluster: dict, a: OutageAnswers) -> list[dict]:
    """A cluster's Kubernetes workloads as rows, by the floors answered in the report."""
    name = cluster["name"]
    region = cluster["region"]
    ignore = set(_patterns(a.ignore_namespaces))
    rows: list[dict] = []
    add = lambda rule, w, note="", **kw: rows.append(  # noqa: E731
        {"rule": rule, "res": f"{name}/{w['ns']}/{w['name']}", "region": region, "note": note, **kw}
    )
    # The usual way to scale DNS is the proportional autoscaler, a workload of its own and not an HPA.
    registries: dict[str, list[dict]] = {}  # images from outside ECR, by registry
    always: list[dict] = []  # ... pulled again on every pod start
    dns_scaled = any("dns" in w["name"] and "autoscaler" in w["name"] for w in cluster.get("workloads") or [])
    for w in cluster.get("workloads") or []:
        n = w["replicas"]
        if w["name"] == "coredns" and w["ns"] == "kube-system" and not w.get("hpa_max") and not dns_scaled:
            add("eks_coredns", w, f"{n} replica(s), no autoscaler found in the cluster")
        if str(w["ns"]).lower() in ignore:
            continue
        if w.get("hpa_max"):
            add(
                "eks_hpa_max",
                w,
                pct=100.0 * w.get("current", n) / w["hpa_max"],
                used=w.get("current", n),
                limit=w["hpa_max"],
                load=True,
            )
        elif n == 1:
            add("eks_single_replica", w, f"{w['kind']}, no autoscaler")
        elif w["kind"] == "Deployment":
            add("eks_fixed_replicas", w, f"{n} replicas, no autoscaler")
        cpu, mem_lim, mem_req = w.get("cpu_req"), w.get("mem_lim"), w.get("mem_req")
        if cpu is not None and cpu < a.cpu_request_floor_m:
            add("eks_low_cpu", w, f"{cpu}m requested across the pod, under {a.cpu_request_floor_m}m")
        if mem_lim is not None and mem_lim < a.memory_limit_floor_mi:
            add("eks_low_memory", w, f"{mem_lim} MiB limit across the pod, under {a.memory_limit_floor_mi} MiB")
        if mem_lim is None and mem_req is None:
            add("eks_no_memory_limit", w, "no request or limit on at least one container")
        if w.get("pdb") is False and n > 1:
            add("eks_no_pdb", w, f"{n} replicas")
        if w.get("ready") is False:
            add("eks_no_readiness", w, "at least one container has none")
        if w.get("oom"):
            add("eks_oom", w, f"{w['oom']} container(s) last ended OOMKilled")
        if w.get("pull_failed"):
            add("image_pull_failing", w, f"{w['pull_failed']} container(s) waiting on an image pull that failed")
        for host in w.get("registries") or []:
            registries.setdefault(host, []).append(w)
        if w.get("pull_always"):
            always.append(w)
    for host, found in sorted(registries.items(), key=lambda x: -len(x[1])):
        shown = ", ".join(f"{w['ns']}/{w['name']}" for w in found[:5]) + (
            f" and {len(found) - 5:,} more" if len(found) > 5 else ""
        )
        rows.append({"rule": "image_registry_outside", "res": f"{name} from {host}", "region": region,
                     "used": len(found), "unit": "workloads", "note": shown})  # fmt: skip
    if always:
        shown = ", ".join(f"{w['ns']}/{w['name']}" for w in always[:5]) + (
            f" and {len(always) - 5:,} more" if len(always) > 5 else ""
        )
        rows.append({"rule": "image_pull_always", "res": name, "region": region, "used": len(always),
                     "unit": "workloads", "note": shown})  # fmt: skip
    if cluster.get("pending"):
        rows.append(
            {
                "rule": "eks_pending",
                "res": name,
                "region": region,
                "used": cluster["pending"],
                "unit": "pods pending when read",
            }
        )
    if cluster.get("access") != "read":
        rows.append({"rule": "eks_not_read", "res": name, "region": region, "note": cluster.get("detail", "")})
    return rows


def _region_mismatch(rows: list[dict], values: dict[str, dict[str, float]]) -> list[dict]:
    """A quota whose usage in one region is above its value in another: the second could not take the load."""
    out = []
    for r in rows:
        if not r.get("qcode") or r.get("used") is None or r["region"] == "global":
            continue
        for region, value in (values.get(r["qcode"]) or {}).items():
            if region != r["region"] and r["used"] > value:
                out.append(
                    {
                        "rule": "limit_region_mismatch",
                        "res": r["res"],
                        "region": region,
                        "note": f"{r['used']:,.0f} in use in {r['region']}, limit here {value:,.0f}",
                    }
                )
    return out


def _settled_rds_quotas(raw: dict) -> list[dict]:
    """Saved scans' RDS quotas, read before the fix for counts of resources taken as rates: their usage is 12 times
    too high (AWS gives these an hourly period, and five-minute samples were scaled up to it)."""
    rows = list(raw.get("rows") or [])
    if "profiles" in raw:
        return rows
    out = []
    for r in rows:
        if r.get("qcode") and r["res"].startswith("rds: ") and r.get("load") and not r.get("used", 1) % 12:
            r = {**r, "used": r["used"] / 12, "pct": round(r["pct"] / 12, 1), "load": False}
            if r["pct"] < KEEP_PCT:
                continue
        out.append(r)
    return out


def _one_per_quota(rows: list[dict]) -> list[dict]:
    """RDS reports its limits itself and through Service Quotas, by different names: keep one of each."""
    norm = lambda name: re.sub(r"[^a-z]", "", name.lower())  # noqa: E731
    named = {(r["region"], norm(r["res"])) for r in rows if r.get("qcode") and r["res"].startswith("rds: ")}
    return [
        r
        for r in rows
        if r.get("qcode") or not r["res"].startswith("rds: ") or (r["region"], norm(r["res"])) not in named
    ]


# A resource named for a non-production stage, in a production account: judged as non-production.
NONPROD_RESOURCE = re.compile(r"(?<![a-z0-9])(dev|qa|uat|sit|test|poc|sandbox|sbx)(?![a-z0-9])", re.I)
QUOTA_RULES = {"limit_product", "limit_account", "limit_connect"}
QUOTA_OVER = 110.0  # AWS enforces a quota: usage well past it means the figure is not that quota's usage
DLQ = re.compile(r"dlq|dead[-_ ]?letter|(?<![a-z0-9])dl(?![a-z0-9])", re.I)
SHORT_RETENTION = re.compile(
    r"deleted after 0 hours"
)  # a queue that keeps messages under an hour drops them on purpose
# A queue that holds messages rejected as invalid or failed, kept for a person to look at: like a dead-letter queue
SINK_QUEUE = re.compile(r"(?<![a-z0-9])(invalid|errors?|rejects?|rejected|failed)(?![a-z0-9])", re.I)
READ_API = re.compile(r"\b(Describe|List|Get|Search)[A-Z]\w*|describe .* information rate", re.I)
NO_FREEABLE = ("oracle", "sqlserver", "db2")  # these engines allocate their memory up front
BUFFER_POOL = ("aurora", "mysql", "mariadb")  # these give about 3/4 of memory to their cache at start
BUFFER_SHARE = 0.25  # the share of memory left for connections, sorts and the operating system


def _stat(profile: dict | None, key: str) -> dict:
    return next((s for s in (profile or {}).get("stats") or [] if s.get("k") == key), {})


def _false_positive(row: dict, profiles: dict) -> bool:
    """A reading that cannot be what it claims. profiles: {(svc, res): the resource's review}."""
    facts = {k: p.get("facts") or {} for k, p in profiles.items()}
    rule, pct = row["rule"], row.get("pct") or 0.0
    if rule in QUOTA_RULES and pct > QUOTA_OVER:
        return True  # an enforced limit exceeded: a raised quota the API does not show, or a mismatched metric
    if rule in ("ebs_iops_use", "rds_iops") and pct > QUOTA_OVER:
        return True  # past what is provisioned: the busiest read and write hours do not add up
    if rule == "sqs_backlog" and (DLQ.search(row["res"]) or SHORT_RETENTION.search(row.get("note", ""))):
        return True  # a dead-letter queue holds messages on purpose; a short retention drops stale ones by design
    if rule == "efs_burst":
        f = facts.get(("efs", row["res"])) or {}
        if f.get("Throughput") not in (None, "bursting") or str(f.get("Size", "")).startswith("0.0 "):
            return True  # credits only matter in bursting mode, and an empty file system never earns any
    if rule == "rds_memory":
        engine = str((facts.get(("rds", row["res"])) or {}).get("Engine") or row.get("engine") or "")
        if engine.startswith(NO_FREEABLE):
            return True
    if rule == "no_alarm" and row["res"].startswith("rds: "):
        engine = str((facts.get(("rds", row["res"][5:])) or {}).get("Engine") or "")
        if engine.startswith(("aurora", "docdb", "neptune")):
            return True  # cluster storage grows by itself and has no FreeStorageSpace to alarm on
    return False


SERVERLESS_NOTE = (
    "AWS measures Aurora Serverless v2 CPU against the maximum ACUs, so CPU is the headroom left before the "
    "ceiling. Capacity used is held up by the buffer cache and falls slowly, so it does not grow with load"
)


def _rebase(row: dict, profiles: dict) -> dict:
    """A measure judged against the headroom the engine really has. MySQL, MariaDB and Aurora give about
    three quarters of memory to the buffer pool or cache when they start, by design: low freeable memory
    there is normal, so it is measured against the remaining quarter."""
    if row["rule"] == "aurora_acu" and row.get("pct") is not None:
        cpu = _stat(profiles.get(("rds", row["res"])), "CPU")
        if cpu.get("peak") is None:
            return {**row, "evidence": "thin"}
        used = f"capacity used {row['pct']:.0f}% of the maximum ACUs"
        note = f"{used}, CPU {cpu['peak']:.0f}% of the maximum at the busiest hour. {SERVERLESS_NOTE}"
        return {**row, "pct": round(min(cpu["peak"], 100.0), 1), "note": note, "acu_used": row["pct"]}
    if row["rule"] != "rds_memory" or row.get("pct") is None:
        return row
    engine = str(((profiles.get(("rds", row["res"])) or {}).get("facts") or {}).get("Engine") or "")
    if not engine.startswith(BUFFER_POOL):
        return row
    pct = max(0.0, 100.0 - (100.0 - row["pct"]) / BUFFER_SHARE)
    cache = f"{engine.split()[0]} keeps about three quarters of memory as cache by design, so measured against the rest"
    note = f"{row.get('note', '')}; {cache}"
    return {**row, "pct": round(pct, 1), "note": note.lstrip("; ")}


# Events seen in the lookback window count as an outage sign only when they are a real share of the
# traffic: a handful of errors in 35 days is noise every busy system has.
ERROR_SHARE = 0.01  # of requests, on average
MIN_EVENTS = 100  # in the lookback window
NAT_DROPS = 10_000  # packets in the lookback window; a few dropped packets are retransmitted unnoticed
SQS_BACKLOG = 100  # messages waiting: below it, an old message is a few left unconsumed, not a stalled consumer
# Rated against these traffic figures: {rule: (svc, [(failures, requests)])}
EVENT_RATES = {
    "apigw_5xx": ("apigateway", [("Server errors", "Requests")]),
    "lb_5xx": ("elb", [("Own 5xx errors", "Requests")]),
    "lambda_throttles": ("lambda", [("Throttles", "Invocations")]),
    "lambda_async_dropped": ("lambda", [("Errors", "Invocations")]),
    "ddb_throttles": ("dynamodb", [("Read throttles", "Reads"), ("Write throttles", "Writes")]),
}
# A count of things created, not traffic: at the quota nothing new can be added, but what runs is not hit.
STATIC_QUOTA = re.compile(
    r"phone numbers|queues|flows|users|routing profiles|hours of operation|security profiles|prompts|"
    r"domains|tracking server|serverless endpoints|apps running|notebook|spaces|user profiles",
    re.I,
)
# Amazon Connect API rates. The calls that set up users, queues and hierarchies come from admin or sync tooling;
# the rest follow the contact centre's staff, which is fixed, so the peak multiplier does not apply to them.
CONNECT_RATE = re.compile(r"^connect: Rate of (\w+) API", re.I)
ADMIN_API = re.compile(
    r"^(Update|Create|Delete|Associate|Disassociate|Put|Tag|Untag|Batch|Import|Replicate|Claim|Release)"
)
ANALYST_QUOTA = re.compile(r"^(sagemaker|athena|glue|quicksight|databrew|emr-serverless|bedrock): ", re.I)
# Build, CI and housekeeping tooling: when it stops, delivery waits, but customers are not hit.
TOOLING = re.compile(
    r"github-?runner|gitlab-?runner|(?<![a-z0-9])runners?(?![a-z0-9])|jenkins|sonarqube|buildkite|atlantis|"
    r"image-?builder|idle-?reaper|warm-?pool|security-?hub|(?<![a-z0-9])backup-test(?![a-z0-9])|"
    r"(?<![a-z0-9])restore(?![a-z])",
    re.I,
)


LOOKBACK_HOURS = 35 * 24
LAMBDA_RULES = {"lambda_timeout", "lambda_async_dropped", "lambda_throttles", "lambda_reserved", "lambda_pc_util"}
JOB_AVG = 0.005  # calls a second on average (under one every three minutes), and
JOB_PEAK = 0.05  # at the busiest hour (under three a minute): a scheduled or triggered job, not a request path


def _share(prof: dict | None, pairs) -> float | None:
    """The worst share of requests that failed, on average across the window (None: traffic not read).
    Refused calls are not counted in the traffic figure, so they are added to it."""
    shares = []
    for bad, total in pairs:
        b, t = _stat(prof, bad), _stat(prof, total)
        if b and t:
            failed, served = b.get("avg") or 0, (t.get("avg") or 0) * 3600  # failures an hour, requests a second
            if failed + served > 0:
                shares.append(failed / (failed + served))
    return max(shares) if shares else None


def _rare(prof: dict | None, bad: str, total: str) -> str | None:
    """Why a failure count beside a resource is too rare to be an outage sign, or None when it is not."""
    b = _stat(prof, bad)
    count = (b.get("avg") or 0) * LOOKBACK_HOURS
    share = _share(prof, [(bad, total)]) or 0.0
    if count < MIN_EVENTS or share < ERROR_SHARE:
        return f"about {count:,.0f} {bad.lower()} in 35 days, {share:.2%} of calls: too rare to be an outage sign"
    return None


def _lower_to(f: dict, severity: str, why: str) -> None:
    f["severity"] = severity
    f["why"] += f"; {why}"


def _temper(f: dict, row: dict, profiles: dict) -> None:
    """Lower a finding the evidence beside it does not bear out, and say why. Critical and high are kept
    for what is likely to cause an outage at the peak; the rest stays listed, lower, with the reason."""
    if f["severity"] not in ("critical", "high"):
        return
    rule = row["rule"]
    res = row["res"]
    calls = _stat(profiles.get(("lambda", res)), "Invocations") if rule in LAMBDA_RULES else {}
    if calls and (calls.get("avg") or 0) < JOB_AVG and (calls.get("peak") or 0) < JOB_PEAK:
        _lower_to(
            f,
            "medium",
            "a background job (almost never called): it fails its own work, not customer traffic at the peak",
        )
    elif row.get("evidence") == "thin":
        _lower_to(
            f,
            "medium",
            "insufficient evidence: CPU was not read, and capacity used alone does not show the ceiling is near",
        )
    elif rule in QUOTA_RULES and CONNECT_RATE.search(res) and ADMIN_API.match(CONNECT_RATE.search(res).group(1)):
        _lower_to(f, "medium", "an admin API called by setup or sync tooling that retries, not by agents or customers")
    elif rule in QUOTA_RULES and CONNECT_RATE.search(res) and not READ_API.search(res):
        f["at_peak"] = f["pct"]  # staff-bound: the busiest day is about as busy as today
        if (f["pct"] or 0) >= 100:
            _lower_to(
                f,
                "high",
                "judged on today, not at 2x: the contact centre's staff is fixed; past the rate, calls are refused",
            )
        else:
            _lower_to(f, "medium", "judged on today, not at 2x: the contact centre's staff is fixed, so volume is too")
    elif rule in QUOTA_RULES and READ_API.search(res) and row.get("load"):
        _lower_to(f, "medium", "a read API, usually called by tooling that retries, not by customers")
    elif rule in QUOTA_RULES and ANALYST_QUOTA.search(res):
        _lower_to(
            f, "medium", "an analyst or data science service: at the quota work queues or waits, customers are not hit"
        )
    elif rule in QUOTA_RULES and STATIC_QUOTA.search(res) and not row.get("load"):
        _lower_to(
            f, "medium", "a count of things created: at the quota nothing new can be added, what runs keeps working"
        )
    elif rule in EVENT_RATES:
        svc, pairs = EVENT_RATES[rule]
        share = _share(profiles.get((svc, res)), pairs)
        total = row.get("used") or 0
        if share is None:
            _lower_to(
                f, "medium", "insufficient evidence: the traffic beside it was not read, so its share is not known"
            )
        elif total < MIN_EVENTS or share < ERROR_SHARE:
            sev = "medium" if total >= MIN_EVENTS else "low"
            _lower_to(f, sev, f"about {share:.2%} of requests on average: background noise, not a sign of an outage")
        else:
            f["why"] += f"; about {share:.1%} of requests on average"
    elif rule == "nat_drops" and (row.get("used") or 0) < NAT_DROPS:
        sev = "medium" if (row.get("used") or 0) >= MIN_EVENTS else "low"
        _lower_to(f, sev, "a few packets in 35 days: TCP sends them again, so nothing fails")
    elif rule in ("msk_under_replicated", "lb_no_healthy") and not row.get("now"):
        what = (
            "it recovered: brief under-replication is what a broker restart, such as AWS patching, looks like"
            if rule == "msk_under_replicated"
            else "it recovered: a brief gap is usually a deployment or scale-in; check it is not a failing health check"
        )
        _lower_to(f, "medium", what)
    elif rule in ("lambda_reserved", "lambda_pc_util"):
        prof = profiles.get(("lambda", res))
        rare = _rare(prof, "Throttles", "Invocations")
        if rare:
            past = "calls past it run on demand with a cold start, they do not fail" if rule == "lambda_pc_util" else ""
            _lower_to(f, "medium", f"{rare}{'; ' + past if past else ''}")
    elif rule == "lambda_timeout":
        prof = profiles.get(("lambda", res))
        errors = _stat(prof, "Errors").get("peak") or 0
        if (row.get("pct") or 0) > 101 and not errors:
            f["severity"] = "medium"
            f["why"] = (
                "its longest run is longer than today's timeout, so the timeout was lowered in the window; "
                "no errors since"
            )
        elif not errors:
            _lower_to(f, "medium", "no errors recorded, so no run was cut off yet")
        elif rare := _rare(prof, "Errors", "Invocations"):
            _lower_to(f, "medium", rare)
    elif rule == "sqs_backlog" and SINK_QUEUE.search(res.replace("_", "-")):
        _lower_to(f, "medium", "a queue of invalid or failed messages, kept to be looked at: check why they fail")
    elif rule == "sqs_backlog" and row.get("received") == 0:
        sent = row.get("sent") or 0
        if sent:
            _lower_to(
                f,
                "medium",
                f"nobody reads this queue: {sent:,} messages sent in the window and none received, so each expires "
                "unread. Not an outage risk at the peak, it is already so: check whether anything should read it "
                "(if so, data is being lost now) or remove what sends to it",
            )
        else:
            _lower_to(f, "low", "an idle queue: nothing sent or read in the window, so its old messages expire")
    elif rule == "sqs_backlog" and row.get("received") and (row.get("age_now_pct") or 0) < 50:
        _lower_to(
            f,
            "medium",
            f"its consumers read it and have caught up (oldest message now {row['age_now_pct']:.0f}% of its expiry); "
            "it reached its expiry at the busiest time in the window, so check the consumers scale for the peak",
        )
    elif rule == "sqs_backlog":
        waiting = _stat(profiles.get(("sqs", res)), "Messages waiting").get("peak") or 0
        if waiting < SQS_BACKLOG:
            _lower_to(
                f,
                "medium",
                f"at most {waiting:,.0f} messages waiting: a few left unconsumed expire, the queue is not stalled",
            )
    elif rule in ("redshift_cpu", "ebs_iops_use") and f["severity"] == "high" and row.get("load"):
        what = (
            "a data warehouse: at its limit queries queue and reports run late, customers are not hit"
            if rule == "redshift_cpu"
            else "a projection of an hourly average: busy hours on a volume are usually backups or batch jobs"
        )
        _lower_to(f, "medium", what)
    elif rule == "kinesis_iterator":
        behind = _stat(profiles.get(("kinesis", res)), "Reader behind")
        if behind.get("peak") and (behind.get("avg") or 0) < 0.1 * behind["peak"]:
            f["severity"] = "medium"
            f["why"] = (
                f"a reader started from the oldest record once (a restart or a new consumer) and caught up: "
                f"{behind['avg'] / 60:,.0f} minutes behind on average"
            )


NON_PROD_WEIGHT = 0.1  # a non-production account's weight in the overall score


def _accounts_and_findings(scan, accounts, checked, rules, a, peak, days_to_peak) -> tuple[list[dict], list[dict]]:
    points = catalog()["points"]
    prod_p = _patterns(a.production_patterns)
    spend = _monthly_spend(scan)
    table, findings = [], []
    for acct in accounts:
        raw = checked.get(acct["id"])
        if raw is None:
            continue
        production = is_production(acct, prod_p)
        rows = _one_per_quota(_settled_rds_quotas(raw))
        rows += _region_mismatch(rows, raw.get("quota_values") or {})
        for c in raw.get("clusters") or []:
            rows += workload_rows(c, a)
        profiles = {(p["svc"], p["res"]): p for p in raw.get("profiles") or []}
        found = []
        for row in rows:
            rule = rules.get(row["rule"])
            if not rule or _false_positive(row, profiles):
                continue
            named = f"{row['res']} {row.get('note', '')}"
            live = production and not NONPROD_RESOURCE.search(named) and not TOOLING.search(named)
            based = _rebase(row, profiles)
            f = _judge(based, rule, a, peak, days_to_peak, live)
            if f:
                if based.get("acu_used") is not None:
                    f["why"] = f"CPU {f['why']}; capacity used {based['acu_used']:.0f}% of the maximum ACUs"
                _temper(f, based, profiles)
                found.append(
                    {
                        **f,
                        "account": acct["name"],
                        "account_id": acct["id"],
                        "production": live,
                        "area": rule["area"],
                        "title": rule["title"],
                    }
                )
        worst: dict[str, str] = {}
        for f in found:
            if f["rule"] not in worst or SEV_ORDER[f["severity"]] < SEV_ORDER[worst[f["rule"]]]:
                worst[f["rule"]] = f["severity"]
        score = round(_points_score(list(worst.values()), points, 1.0), 1) if worst else 0.0
        counts = Counter(f["severity"] for f in found)
        top = min(found, key=lambda f: (SEV_ORDER[f["severity"]], -(f["at_peak"] or 0)), default=None)
        checks = raw.get("checks") or {}
        # A check that passed in one region and failed to read in another is not measured either.
        unread = [
            k for k, v in checks.items() if v.get("status") == "unknown" or "not measured" in (v.get("note") or "")
        ]
        blind = bool(checks) and not any(v.get("status") in ("pass", "fail") for v in checks.values())
        blind = blind and not found and any(v.get("status") == "unknown" for v in checks.values())
        table.append(
            {
                "id": acct["id"],
                "name": acct["name"],
                "ou_path": acct.get("ou_path", ""),
                "owner": owner_of(acct)[0],
                "production": production,
                "score": score,
                "rating": NOT_MEASURED if blind else _rating(score),
                "monthly_spend": spend.get(acct["id"], 0.0),
                **{s: counts.get(s, 0) for s in SEVERITIES},
                "top": f"{top['title']}: {top['res']}" if top else "",
                "not_measured": unread,
                "regions": raw.get("regions") or [],
                "compared": raw.get("compared", 0),
                "rows_cut": raw.get("rows_cut", 0),
                "metrics_cut": bool((raw.get("facts") or {}).get("metrics_cut")),
            }
        )
        findings += found
    table.sort(
        key=lambda r: (
            r["rating"] != NOT_MEASURED,
            -r["score"],
            not r["production"],
            -r["critical"],
            -r["high"],
            r["name"].lower(),
        )
    )
    findings.sort(
        key=lambda f: (not f["production"], SEV_ORDER[f["severity"]], -(f["at_peak"] or f["pct"] or 0), f["account"])
    )
    return table, findings


def _focus(findings: list[dict], cat: dict, peak: date, freeze: date, today: date) -> list[dict]:
    """The areas, in the order the scan's production findings say to work on them."""
    out = []
    for area, info in cat["areas"].items():
        mine = [f for f in findings if f["area"] == area and f["production"]]
        counts = Counter(f["severity"] for f in mine)
        rules = Counter(f["title"] for f in mine if f["severity"] in ("critical", "high"))
        start = min(freeze, peak) - timedelta(days=info.get("lead_days", 0))
        out.append(
            {
                "area": area,
                "label": info["label"],
                "action": info["action"],
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "accounts": len({f["account_id"] for f in mine}),
                "top": [{"title": t, "count": n} for t, n in rules.most_common(3)],
                "start_by": start.isoformat(),
                "late": start < today,
            }
        )
    out.sort(key=lambda x: (-x["critical"], -x["high"], -x["medium"], x["label"]))
    return out


def _rule_rollup(findings: list[dict], rules: dict) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        grouped[f["rule"]].append(f)
    out = []
    for rid, mine in grouped.items():
        rule = rules[rid]
        counts = Counter(f["severity"] for f in mine)
        out.append(
            {
                "id": rid,
                "title": rule["title"],
                "area": rule["area"],
                "kind": rule["kind"],
                "why": rule["why"],
                "fix": rule["fix"],
                "findings": len(mine),
                "accounts": len({f["account_id"] for f in mine}),
                "production": sum(f["production"] for f in mine),
                **{s: counts.get(s, 0) for s in SEVERITIES},
            }
        )
    out.sort(key=lambda r: (-r["critical"], -r["high"], -r["findings"]))
    return out


def _clusters(accounts: list[dict], checked: dict) -> list[dict]:
    out = []
    for acct in accounts:
        for c in (checked.get(acct["id"]) or {}).get("clusters") or []:
            ws = c.get("workloads") or []
            out.append(
                {
                    "account": acct["name"],
                    "name": c["name"],
                    "region": c["region"],
                    "version": c.get("version", ""),
                    "access": c.get("access"),
                    "detail": c.get("detail", ""),
                    "insights": bool(c.get("insights")),
                    "pods": c.get("pods"),
                    "workloads": c.get("workload_count", len(ws)),
                    "autoscaled": sum(1 for w in ws if w.get("hpa_max")),
                    "single": sum(1 for w in ws if w["replicas"] == 1 and not w.get("hpa_max")),
                    "pods_cut": bool(c.get("pods_cut")),
                }
            )
    out.sort(key=lambda c: (c["access"] == "read", c["account"], c["name"]))
    return out


def _summary(table, findings, clusters, not_checked, a, peak, freeze, today) -> dict:
    prod = [f for f in findings if f["production"]]
    counts = Counter(f["severity"] for f in prod)
    all_counts = Counter(f["severity"] for f in findings)
    limited = [f for f in prod if f["area"] == "limits"]
    # Production accounts carry the score; spend plays no part, as it is only a proxy for importance.
    weights = [(r["score"], 1.0 if r["production"] else NON_PROD_WEIGHT) for r in table if r["rating"] != NOT_MEASURED]
    total = sum(w for _, w in weights)
    score = round(sum(s * w for s, w in weights) / total, 1) if total else 0.0
    checks = sum(r["compared"] for r in table)
    measured = [r for r in table if not r["not_measured"]]
    return {
        "accounts": len(table),
        "not_checked": len(not_checked),
        "accounts_full": len(measured),
        "accounts_blind": sum(1 for r in table if r["rating"] == NOT_MEASURED),
        "accounts_cut": sum(1 for r in table if r["rows_cut"] or r["metrics_cut"]),
        "score": score,
        "rating": _rating(score),
        "critical_accounts": sum(1 for r in table if r["rating"] == "Critical"),
        "high_accounts": sum(1 for r in table if r["rating"] == "High"),
        "production_accounts": sum(1 for r in table if r["production"]),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "all_findings": sum(all_counts.values()),
        "non_production": len(findings) - len(prod),
        "breach_at_peak": sum(1 for f in prod if f["kind_capacity"] and (f["at_peak"] or 0) >= 100),
        "limits_at_risk": sum(1 for f in limited if f["severity"] in ("critical", "high")),
        "hard_limits": sum(1 for f in limited if f["hard"] and f["severity"] in ("critical", "high")),
        "full_before_peak": sum(1 for f in prod if f["days"] is not None and f["days"] <= (peak - today).days),
        "hot_fixed": sum(
            1 for f in prod if f["area"] == "fixed" and f["kind_capacity"] and f["severity"] in ("critical", "high")
        ),
        "msk_at_risk": sum(1 for f in prod if f["area"] == "msk" and f["severity"] in ("critical", "high")),
        "eks_fixed": sum(1 for f in prod if f["rule"] == "eks_fixed_replicas"),
        "eks_single": sum(1 for f in prod if f["rule"] == "eks_single_replica"),
        "clusters": len(clusters),
        "clusters_read": sum(1 for c in clusters if c["access"] == "read"),
        "measures": checks,
        "peak_date": peak.isoformat(),
        "days_to_peak": (peak - today).days,
        "freeze_date": freeze.isoformat(),
        "days_to_freeze": (freeze - today).days,
        "multiplier": a.peak_multiplier,
    }


def build_outage(scan: dict, account_filter: AccountFilter | None = None, a: OutageAnswers | None = None) -> dict:
    started = time.perf_counter()
    account_filter = account_filter or AccountFilter()
    a = a or OutageAnswers()
    cat = catalog()
    rules = {r["id"]: r for r in cat["rules"]}
    data = scan.get("outage") or {}
    checked = data.get("accounts") or {}
    accounts = [x for x in scan.get("accounts", []) if account_filter.matches(x["name"])]
    today = date.today()
    peak = date.fromisoformat(a.peak_date) if a.peak_date else black_friday(today)
    freeze = peak - timedelta(days=a.freeze_days)
    base = {
        "scan_id": scan.get("id"),
        "label": scan.get("label", ""),
        "scan_at": scan.get("created_at"),
        "ou": scan.get("ou"),
        "answers": a.model_dump(),
        "catalog_version": cat.get("version"),
        "filter": account_filter.describe() if account_filter.active else "",
    }
    if not checked:
        return {**base, "available": False, "accounts": [], "reason": _why_empty(scan)}
    table, findings = _accounts_and_findings(scan, accounts, checked, rules, a, peak, (peak - today).days)
    for f in findings:
        f["kind_capacity"] = rules[f["rule"]]["kind"] == "capacity"
    clusters = _clusters(accounts, checked)
    not_checked = [
        {"id": x["id"], "name": x["name"]}
        for x in accounts
        if x["id"] not in checked and x.get("status", "ACTIVE") in ("ACTIVE", "UNKNOWN")
    ]
    focus = _focus(findings, cat, peak, freeze, today)
    views = build_views(scan, accounts, checked, table, findings, rules, cat, peak, freeze, today)
    area_rank = {x["area"]: x for x in focus}

    def found_for(cause: dict) -> dict | None:
        """What this scan found for a cause: its area, or the rules named. None when a scan cannot see it."""
        if cause.get("rules"):
            hits = [f for f in findings if f["rule"] in cause["rules"] and f["production"]]
            return {sev: sum(f["severity"] == sev for f in hits) for sev in ("critical", "high", "medium")}
        return area_rank.get(cause.get("area") or "")

    # The evidence, beside what this scan found for the same cause.
    causes = [{**c, "scan": found_for(c)} for c in cat["causes"]]
    return {
        **base,
        "available": True,
        "summary": _summary(table, findings, clusters, not_checked, a, peak, freeze, today),
        "focus": focus,
        "causes": causes,
        "areas": {k: v["label"] for k, v in cat["areas"].items()},
        "rules": _rule_rollup(findings, rules),
        "findings": findings[:MAX_FINDINGS],
        "findings_total": len(findings),
        "accounts": table,
        "clusters": clusters,
        "not_checked": not_checked,
        **views,
        "build_ms": round((time.perf_counter() - started) * 1000),
    }


def _why_empty(scan: dict) -> str:
    if (scan.get("params") or {}).get("outage"):
        return (
            "This scan was asked for the outage risk checks but could not read any account: "
            "see the issues in section 9 of the Exit Risk Report."
        )
    return "This scan did not run the outage risk checks."


def _cell(value):
    """A resource name is the customer's text: a spreadsheet must not run one that looks like a formula."""
    return f"'{value}" if isinstance(value, str) and value[:1] in ("=", "+", "-", "@") else value


def findings_csv(report: dict) -> str:
    """Every finding sent to the page, for a spreadsheet or a ticket system."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(
        [
            "severity",
            "area",
            "service",
            "finding",
            "account",
            "owner",
            "production",
            "region",
            "resource",
            "percent now",
            "percent at peak",
            "used",
            "limit",
            "unit",
            "days to full",
            "why",
            "note",
            "what to do",
        ]
    )
    areas = report.get("areas") or {}
    owners = {a["id"]: a.get("owner") or "" for a in report.get("accounts") or []}
    fixes = {r["id"]: r.get("fix", "") for r in report.get("rules") or []}
    for f in report.get("findings") or []:
        w.writerow(
            [
                f["severity"],
                areas.get(f["area"], f["area"]),
                f.get("service_label", ""),
                f["title"],
                _cell(f["account"]),
                _cell(owners.get(f.get("account_id"), "")),
                "yes" if f["production"] else "no",
                f["region"],
                _cell(f["res"]),
                f["pct"],
                f["at_peak"],
                f["used"],
                f["limit"],
                f["unit"],
                f["days"],
                _cell(f["why"]),
                _cell(f["note"]),
                _cell(fixes.get(f["rule"], "")),
            ]
        )
    return out.getvalue()
