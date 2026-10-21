"""Multi-region estimate: what a second AWS region would cost to run, to build and to staff.

The same scan that scores the exit risk feeds this view. For the accounts the user picks, every
service's regional spend is scaled by how that kind of service behaves in a second region (a
database is replicated in full, a pay-per-use queue barely costs more) for the chosen recovery
target, then priced for the candidate region. The second region is recommended from service
parity (does every service in use exist there), estimated latency and price. Every coefficient
is in data/regions.yaml and listed in ``assumptions`` so it can be challenged; figures are
quoted as ranges, like the exit estimate. See docs/MULTI_REGION.md.
"""

from __future__ import annotations

import json
import math
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from importlib import resources

import yaml
from pydantic import BaseModel, Field

from .catalog import Catalog, ServiceInfo, load_catalog
from .estimate import (
    CICD_FACTORS,
    COST_RANGE,
    DURATION_RANGE,
    IAC_FACTORS,
    PMO_PCT,
    PRODUCTIVE_PCT,
    REGULATED_FACTOR,
    WEEKS_PER_MONTH,
    Questionnaire,
    duration_range,
    effort_range,
    money_range,
    share_range,
    size_multiplier,
)
from .filtering import AccountFilter
from .logging_config import get_logger


def _n(n: int, one: str, many: str | None = None) -> str:
    """'1 account', '3 accounts'."""
    return f"{n:,} {one if n == 1 else many or one + 's'}"


log = get_logger("multiregion")

RECOVERY = {
    "rto_3h": "Recover within 3 hours of a region-wide event",
    "instant": "On demand: instant, no outage (active-active)",
}
RECOVERY_INDEX = {"rto_3h": 0, "instant": 1}
RESIDENCY = {
    "any": "Anywhere AWS has a region",
    "same_continent": "Same continent as the primary region",
    "same_jurisdiction": "Same jurisdiction (e.g. within the EU)",
    "same_country": "Same country as the primary region",
}
SUPPORT_PLANS = {
    "enterprise": "Enterprise",
    "enterprise_onramp": "Enterprise On-Ramp",
    "business": "Business",
    "none": "None / Developer (no uplift)",
}
GLOBAL_REGIONS = {"global", "NoRegion", ""}
# Inter-region transfer for replication, as a share of the replicated data's (data, storage,
# analytics) spend, per recovery target.
TRANSFER_PCT = (0.06, 0.20)
# Extra people to run a second region, per recovery target.
STAFF_TEAM_UPLIFT = (0.10, 0.35)  # share of the current core cloud team (on-call, patching, two of everything)
STAFF_RESILIENCE = (1.0, 2.5)  # DR testing, game days, regulator evidence
STAFF_PER_25_ACCOUNTS = (0.25, 1.0)  # workload operations as more accounts go multi-region
STAFF_DATA = (0.5, 1.5)  # replication and DBA, scaled by √(data spend / 100k USD a month), max 3x
STAFF_FLOOR = (1.5, 4.0)
STAFF_RANGE = (0.75, 1.4)
WORKING_DAYS = 220
# One-off build, engineer-weeks, per recovery target.
LANDING_ZONE_WEEKS = (8.0, 14.0)  # second-region landing zone: network, inter-region links, security baseline
LANDING_ZONE_PER_ACCOUNT = 0.25
ACCOUNT_WEEKS = (1.0, 2.0)  # per material account: DNS failover, IAM, pipelines to two regions
DR_PROGRAMME_WEEKS = (4.0, 8.0)  # runbooks, failover rehearsals, regulator evidence
DR_PER_ACCOUNT = 0.2
MISSING_SERVICE_FACTOR = 1.0  # a service absent in the second region: re-architect, at catalog exit effort
UNVERIFIED_FACTOR = 1.25
CRITICAL_PATH_WEEKS = (20, 39)
REHEARSAL_WEEKS = 4
RAMP_SHARE = 0.5  # the second region is half built, on average, while the programme runs
EXISTING_FOOTPRINT_PCT = 5.0  # this much spend already in the candidate: its landing zone exists
# Latency estimate: fibre ~200 km/ms, routes ~1.5x the great-circle distance, plus switching.
FIBRE_KM_PER_MS, ROUTE_FACTOR, SWITCHING_MS = 200.0, 1.5, 5.0
SYNC_MAX_MS = 100  # beyond this, synchronous replication between regions is impractical
SCORE_WEIGHTS = {"rto_3h": (0.55, 0.2, 0.25), "instant": (0.45, 0.45, 0.1)}  # parity, latency, price
COUNTRY_NAMES = {
    "US": "the United States", "CA": "Canada", "MX": "Mexico", "BR": "Brazil", "IE": "Ireland",
    "GB": "the United Kingdom", "FR": "France", "DE": "Germany", "CH": "Switzerland", "SE": "Sweden",
    "IT": "Italy", "ES": "Spain", "IL": "Israel", "BH": "Bahrain", "AE": "the UAE", "ZA": "South Africa",
    "IN": "India", "HK": "Hong Kong", "TW": "Taiwan", "JP": "Japan", "KR": "South Korea", "SG": "Singapore",
    "AU": "Australia", "ID": "Indonesia", "MY": "Malaysia", "NZ": "New Zealand", "TH": "Thailand",
}  # fmt: skip
AVAILABILITY_MAX_AGE_DAYS = 180  # older than this, the regional services list misses new launches
SEVERITY_ORDER = {"Low": 0, "Moderate": 1, "High": 2, "Critical": 3}
FAILOVER_LABELS = {
    "native": "AWS replicates and fails over",
    "manual": "Manual or scripted failover",
    "rebuild": "No live replica: restore or re-run",
    "missing": "Not available in the second region",
}


class MultiRegionAnswers(BaseModel):
    recovery: str = Field("rto_3h", pattern="^(rto_3h|instant)$")
    residency: str = Field("any", pattern="^(any|same_continent|same_jurisdiction|same_country)$")
    primary: str = Field("", max_length=30, pattern=r"^[a-z0-9-]*$")  # "" = the region with most spend
    secondary: str = Field("", max_length=30, pattern=r"^[a-z0-9-]*$")  # "" = the recommended region
    support_plan: str = Field("enterprise", pattern="^(enterprise|enterprise_onramp|business|none)$")
    allocation_pct: int = Field(50, ge=5, le=100)
    fte_annual_cost: float = Field(0, ge=0, le=10_000_000)  # 0 = blended day rate x 220 days
    accounts: list[str] | None = Field(None, max_length=5000)  # None = every account in scope
    confirmed: bool = False


@lru_cache(maxsize=1)
def load_region_data() -> dict:
    root = resources.files("exitrisk").joinpath("data")
    cfg = yaml.safe_load(root.joinpath("regions.yaml").read_text(encoding="utf-8"))
    avail = json.loads(root.joinpath("region_services.json").read_text(encoding="utf-8"))
    cfg["availability"] = {k: set(v) for k, v in avail["services"].items()}
    cfg["availability_version"] = avail.get("source_version", "")
    cfg["availability_fetched"] = avail.get("fetched", "")
    return cfg


def _availability_age_days(cfg: dict, today: date | None = None) -> int | None:
    try:
        fetched = date.fromisoformat(str(cfg.get("availability_fetched", ""))[:10])
    except ValueError:
        return None
    return ((today or date.today()) - fetched).days


_logged: set[tuple[str, str]] = set()


def _log_once(scan_id: str, note: dict) -> None:
    """The view recalculates on every change in the page: log each data note once per scan."""
    key = (scan_id, note["text"])
    if key not in _logged:
        _logged.add(key)
        (log.warning if note["level"] == "warning" else log.info)("multi-region %s: %s", scan_id, note["text"])


def latency_ms(a: dict, b: dict, regions: dict | None = None) -> float:
    """Estimated round trip between two regions: great circle, or through the hub a region routes via."""
    regions = regions or load_region_data()["regions"]
    for x, y in ((a, b), (b, a)):
        hub = regions.get(x.get("via") or "")
        if hub and y["continent"] not in (x["continent"], hub["continent"]):
            return _great_circle_ms(x, hub) + _great_circle_ms(hub, y) - SWITCHING_MS
    return _great_circle_ms(a, b)


def _great_circle_ms(a: dict, b: dict) -> float:
    la1, lo1, la2, lo2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    km = 2 * 6371 * math.asin(math.sqrt(h))
    return 2 * km * ROUTE_FACTOR / FIBRE_KM_PER_MS + SWITCHING_MS


def support_fee(monthly: float, plan: str) -> float:
    """AWS Support list price for a month's usage (tiered; contracts and EDPs differ)."""
    tiers = {
        "enterprise": (15000, [(150_000, 0.10), (500_000, 0.07), (1_000_000, 0.05), (math.inf, 0.03)]),
        "enterprise_onramp": (5500, [(math.inf, 0.10)]),
        "business": (100, [(10_000, 0.10), (80_000, 0.07), (250_000, 0.05), (math.inf, 0.03)]),
    }
    if plan not in tiers:
        return 0.0
    minimum, bands = tiers[plan]
    fee, floor = 0.0, 0.0
    for top, rate in bands:
        if monthly > floor:
            fee += (min(monthly, top) - floor) * rate
        floor = top
    return max(fee, minimum)


def _residency_ok(primary: dict, cand: dict, rule: str) -> bool:
    if rule == "same_country":
        return cand["country"] == primary["country"]
    if rule == "same_jurisdiction":
        return cand["jurisdiction"] == primary["jurisdiction"]
    if rule == "same_continent":
        return cand["continent"] == primary["continent"]
    return True


def _severity(failover: str, recovery: str) -> str:
    if failover == "missing":
        return "Critical"
    if failover == "native":
        return "Low"
    if failover == "manual":
        return "High" if recovery == "instant" else "Moderate"
    return "Critical" if recovery == "instant" else "High"


def _money(v: float, cur: str = "USD") -> str:
    sym = "$" if cur == "USD" else f"{cur} "
    for div, unit in ((1e6, "m"), (1e3, "k")):
        if abs(v) >= div:
            return f"{sym}{v / div:,.1f}{unit}"
    return f"{sym}{v:,.0f}"


@dataclass
class _Line:
    """One slice of monthly spend: an account's service in one region."""

    account: str
    info: ServiceInfo
    cls: str  # service class in data/regions.yaml
    regional: str | None  # name in the AWS regional services table, "global", or None if unmapped
    region: str | None  # None until the primary region is known
    monthly: float  # USD


@dataclass
class _Totals:
    """What the selected accounts add up to, for people and build effort."""

    service_weeks: float = 0.0
    material: int = 0
    data_monthly: float = 0.0


def _note(notes: list[dict], level: str, text: str) -> None:
    notes.append({"level": level, "text": text})


def _spend_lines(scan: dict, accounts: dict, catalog: Catalog, cfg: dict, notes: list[dict]) -> tuple[list, int]:
    """Split each account's monthly spend per service across the regions it runs in."""
    n_months = max(len({r["month"] for r in scan.get("costs", [])}), 1)
    spend: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for r in scan.get("costs", []):
        if r["account_id"] not in accounts or r["amount"] <= 0:
            continue
        info = catalog.lookup(r["service"])
        if not info.excluded:
            spend[r["account_id"]][info.service] += r["amount"] / n_months

    shares: dict[tuple, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for r in scan.get("region_costs") or []:
        if r["account_id"] in accounts:
            region = "global" if r["region"] in GLOBAL_REGIONS else r["region"]
            shares[(r["account_id"], catalog.lookup(r["service"]).service)][region] += r["monthly"]

    unmapped: dict[str, float] = defaultdict(float)
    lines = []
    for aid, svcs in spend.items():
        for svc, monthly in svcs.items():
            info = catalog.lookup(svc)
            entry = cfg["services"].get(info.service)
            if entry is None:
                unmapped[info.display] += monthly
            entry = entry or {}
            cls = entry.get("class") or cfg["category_classes"].get(info.category, "compute")
            regional = entry.get("regional")
            split = shares.get((aid, svc))
            total = sum(split.values()) if split else 0.0
            parts = {k: monthly * v / total for k, v in split.items()} if total > 0 else {None: monthly}
            for region, m in parts.items():
                if cls == "global" or regional == "global":
                    region = "global"
                lines.append(_Line(aid, info, cls, regional, region, m))
    if unmapped:
        names = ", ".join(sorted(unmapped, key=lambda k: -unmapped[k])[:5])
        _note(
            notes,
            "warning",
            f"{_n(len(unmapped), 'service has', 'services have')} no multi-region profile ({names}): "
            "costed by their catalog category, and their availability in other regions is not verified.",
        )
    return lines, n_months


def _primary_region(lines: list[_Line], mq: MultiRegionAnswers, regions: dict, notes: list[dict]) -> tuple:
    """(primary, detected): the region with most spend, unless the user chose one."""
    known: dict[str, float] = defaultdict(float)
    unknown: dict[str, float] = defaultdict(float)
    for ln in lines:
        if ln.region not in (None, "global"):
            (known if ln.region in regions else unknown)[ln.region] += ln.monthly
    if unknown:
        _note(
            notes,
            "warning",
            f"Spend in region(s) this version does not know ({', '.join(sorted(unknown))}): priced at "
            "the primary region's rates and not offered as a second region. Upgrade exitrisk for them.",
        )
    detected = max(known, key=known.get) if known else None
    if mq.primary in regions:
        primary = mq.primary
    elif detected:
        primary = detected
    else:
        primary = "us-east-1"
        if lines:
            _note(
                notes,
                "warning",
                "The primary region is unknown, so US East (N. Virginia) is assumed: choose the right one "
                "under Primary region in section 2.",
            )
    for ln in lines:
        if ln.region is None:
            ln.region = primary  # no region data for this line: assume it runs in the primary region
    return primary, detected


def _availability(avail: dict, regional: str | None, region: str) -> str:
    if regional == "global":
        return "global"
    if regional is None or regional not in avail:
        return "unverified"
    return "available" if region in avail[regional] else "missing"


def _run_cost(sel: list[_Line], region: str, regions: dict, classes: dict, ri: int) -> tuple[float, dict, float]:
    """Monthly USD in ``region``: (infrastructure, by class, replication transfer)."""
    price = regions[region]["price"]
    infra, by_class, replicated = 0.0, defaultdict(float), 0.0
    for ln in sel:
        src_price = regions.get(ln.region, {}).get("price", 1.0)
        c = ln.monthly * classes[ln.cls]["run"][ri] * price / src_price
        infra += c
        by_class[ln.cls] += c
        if ln.cls in ("data", "storage", "analytics"):
            replicated += ln.monthly
    return infra, dict(by_class), replicated * TRANSFER_PCT[ri]


def _service_totals(sel: list[_Line]) -> dict[str, dict]:
    svc_spend: dict[str, dict] = {}
    for ln in sel:
        s = svc_spend.setdefault(
            ln.info.service,
            {"service": ln.info.service, "display": ln.info.display, "class": ln.cls, "regional": ln.regional,
             "monthly_spend": 0.0, "accounts": set()},
        )  # fmt: skip
        s["monthly_spend"] += ln.monthly
        s["accounts"].add(ln.account)
    return svc_spend


def _candidates(
    sel: list[_Line], svc_spend: dict, by_region: dict, primary: str, mq: MultiRegionAnswers, cfg: dict
) -> list[dict]:
    """Every other region, scored on service parity, latency and price; residency-allowed first."""
    regions, avail, ri = cfg["regions"], cfg["availability"], RECOVERY_INDEX[mq.recovery]
    p = regions[primary]
    weights = SCORE_WEIGHTS[mq.recovery]
    regional_total = max(sum(v for k, v in by_region.items() if k != "global"), 1e-9)
    out = []
    for code, r in regions.items():
        if code == primary:
            continue
        status = {k: _availability(avail, s["regional"], code) for k, s in svc_spend.items()}
        avail_spend = sum(s["monthly_spend"] for k, s in svc_spend.items() if status[k] in ("available", "global"))
        missing = [svc_spend[k] for k in status if status[k] == "missing"]
        missing_spend = sum(s["monthly_spend"] for s in missing)
        checked = avail_spend + missing_spend
        parity = 100 * avail_spend / checked if checked else 100.0
        rtt = round(latency_ms(p, r, regions) / 5) * 5
        price_ratio = r["price"] / p["price"]
        existing = 100 * by_region.get(code, 0.0) / regional_total
        infra, _, transfer = _run_cost(sel, code, regions, cfg["classes"], ri)
        score = (
            weights[0] * (parity / 100) ** 6  # a missing service is a re-architecture: penalise steeply
            + weights[1] * max(0.0, 1 - max(rtt - 10, 0) / 250)
            + weights[2] * min(max(1.5 - price_ratio, 0), 1)
            + (0.05 if existing >= 1 else 0)
        )
        notes = []
        if mq.recovery == "instant" and rtt > SYNC_MAX_MS:
            score *= 0.7
            notes.append(f"~{rtt:.0f} ms is too far for synchronous replication")
        if existing >= 1:
            notes.append(f"{existing:.0f}% of spend already runs here")
        out.append(
            {
                "region": code,
                "name": r["name"],
                "country": r["country"],
                "residency_ok": _residency_ok(p, r, mq.residency),
                "latency_ms": rtt,
                "parity_pct": round(parity, 1),
                "missing": [{"display": s["display"], "monthly_spend": round(s["monthly_spend"], 2)} for s in missing],
                "missing_spend": round(missing_spend, 2),
                "unverified": [svc_spend[k]["display"] for k in status if status[k] == "unverified"],
                "price_index": round(price_ratio, 2),
                "existing_pct": round(existing, 1),
                "monthly_run": round(infra + transfer, 2),
                "score": round(100 * score, 1),
                "notes": notes,
            }
        )
    out.sort(key=lambda c: (not c["residency_ok"], -c["score"]))
    return out


def _account_risks(
    accounts: dict, lines: list[_Line], chosen: set, secondary: str | None, mq: MultiRegionAnswers,
    q: Questionnaire, cfg: dict,
) -> tuple[list[dict], _Totals]:  # fmt: skip
    """Per account: each service's failover risk and build effort, sorted by spend."""
    regions, classes, ri = cfg["regions"], cfg["classes"], RECOVERY_INDEX[mq.recovery]
    risk_cfg = cfg.get("risks") or {}
    by_account: dict[str, list[_Line]] = defaultdict(list)
    for ln in lines:
        by_account[ln.account].append(ln)
    totals = _Totals()
    out = []
    for aid, acct in accounts.items():
        a_lines = by_account.get(aid, [])
        a_regional: dict[str, float] = defaultdict(float)
        a_info: dict[str, _Line] = {}
        for ln in a_lines:
            if ln.region != "global":
                a_regional[ln.info.service] += ln.monthly
                a_info[ln.info.service] = ln
        risks = []
        weeks = 0.0
        for svc, m in sorted(a_regional.items(), key=lambda kv: -kv[1]):
            ln = a_info[svc]
            rc = risk_cfg.get(svc) or {}
            failover = rc.get("failover") or classes[ln.cls]["failover"]
            note = rc.get("note") or classes[ln.cls]["note"]
            st = _availability(cfg["availability"], ln.regional, secondary) if secondary else "unverified"
            if secondary and (quota := rc.get("quota")):
                text = quota["inside" if secondary in quota["regions"] else "outside"]
                note = f"{note} {text.format(region=regions[secondary]['name'])}"
            if st == "missing":
                failover = "missing"
                note = f"Not offered in {regions[secondary]['name']}: re-architect onto another service there. " + note
            w = 0.0
            if m >= q.materiality:
                w = classes[ln.cls]["build_weeks"][ri] * size_multiplier(m)
                if st == "missing":
                    w += ln.info.effort_weeks * size_multiplier(m) * MISSING_SERVICE_FACTOR
                elif st == "unverified":
                    w *= UNVERIFIED_FACTOR
            weeks += w
            if ln.cls != "global" and m >= 1:
                risks.append(
                    {
                        "service": ln.info.display,
                        "monthly_spend": round(m, 2),
                        "class": ln.cls,
                        "failover": failover,
                        "failover_label": FAILOVER_LABELS[failover],
                        "severity": _severity(failover, mq.recovery),
                        "availability": st,
                        "note": note,
                    }
                )
        risks.sort(key=lambda x: (-SEVERITY_ORDER[x["severity"]], -x["monthly_spend"]))
        selected = aid in chosen
        if selected:
            totals.service_weeks += weeks
            totals.material += 1 if sum(a_regional.values()) >= q.materiality else 0
            totals.data_monthly += sum(m for s, m in a_regional.items() if a_info[s].cls in ("data", "analytics"))
        worst = max((SEVERITY_ORDER[r["severity"]] for r in risks if r["monthly_spend"] >= q.materiality), default=None)
        out.append(
            {
                "id": aid,
                "name": acct["name"],
                "ou_path": acct.get("ou_path", ""),
                "monthly_spend": round(sum(ln.monthly for ln in a_lines), 2),
                "regional_spend": round(sum(a_regional.values()), 2),
                "selected": selected,
                "readiness": next((k for k, v in SEVERITY_ORDER.items() if v == worst), "Low") if risks else None,
                "risk_counts": {k: sum(1 for r in risks if r["severity"] == k) for k in SEVERITY_ORDER},
                "build_weeks": round(weeks, 1),
                "risks": risks,
            }
        )
    out.sort(key=lambda a: -a["monthly_spend"])
    return out, totals


def _people(q: Questionnaire, ri: int, totals: _Totals, any_selected: bool) -> tuple[dict, float]:
    """Extra FTE to run two regions, by role, and the total."""
    parts = {
        "Platform and SRE: on-call and operations for two regions": STAFF_TEAM_UPLIFT[ri] * q.cloud_team_size,
        "Resilience: DR testing, failover rehearsals, regulator evidence": STAFF_RESILIENCE[ri],
        "Workload operations across multi-region accounts": STAFF_PER_25_ACCOUNTS[ri] * totals.material / 25,
        "Data replication and database operations": STAFF_DATA[ri]
        * min(math.sqrt(max(totals.data_monthly, 0) / 100_000), 3.0),
    }
    fte = max(sum(parts.values()), STAFF_FLOOR[ri]) if any_selected else 0.0
    return parts, fte


def build_multiregion(
    scan: dict,
    account_filter: AccountFilter | None = None,
    q: Questionnaire | None = None,
    mq: MultiRegionAnswers | None = None,
    catalog: Catalog | None = None,
) -> dict:
    started = time.perf_counter()
    catalog = catalog or load_catalog()
    account_filter = account_filter or AccountFilter()
    q = q or Questionnaire()
    mq = mq or MultiRegionAnswers()
    cfg = load_region_data()
    regions, classes = cfg["regions"], cfg["classes"]
    ri = RECOVERY_INDEX[mq.recovery]
    notes: list[dict] = []

    accounts = {a["id"]: a for a in scan.get("accounts", []) if account_filter.matches(a["name"])}
    has_region_data = bool(scan.get("region_costs"))
    if not has_region_data:
        _note(
            notes,
            "warning",
            "This scan has no spend-by-region data (scans made before v0.3.0 did not collect it, or the "
            "scan could not read it), so all spend is assumed to run in the primary region. Run a new scan.",
        )
    stale = _availability_age_days(cfg)
    if stale is not None and stale > AVAILABILITY_MAX_AGE_DAYS:
        _note(
            notes,
            "info",
            f"The AWS regional services list is {stale} days old: upgrade exitrisk, or run "
            "scripts/refresh_region_services.py, for services launched since.",
        )
    lines, n_months = _spend_lines(scan, accounts, catalog, cfg, notes)
    primary, detected = _primary_region(lines, mq, regions, notes)
    by_region: dict[str, float] = defaultdict(float)
    for ln in lines:
        by_region[ln.region] += ln.monthly

    # Which accounts go multi-region.
    chosen = set(mq.accounts) & set(accounts) if mq.accounts is not None else set(accounts)
    if mq.accounts is not None and len(chosen) < len(set(mq.accounts)):
        log.info("multi-region: %d chosen account(s) are not in scope", len(set(mq.accounts)) - len(chosen))
    sel = [ln for ln in lines if ln.account in chosen and ln.region != "global"]
    sel_monthly = sum(ln.monthly for ln in lines if ln.account in chosen)
    regional_monthly = sum(ln.monthly for ln in sel)
    svc_spend = _service_totals(sel)

    candidates = _candidates(sel, svc_spend, by_region, primary, mq, cfg)
    allowed = [c for c in candidates if c["residency_ok"]]
    recommended = allowed[0]["region"] if allowed else None
    secondary = mq.secondary if mq.secondary in regions and mq.secondary != primary else recommended
    if mq.secondary and secondary != mq.secondary:
        _note(notes, "warning", f"Second region {mq.secondary!r} is not usable here; using the recommended one.")
    target = next((c for c in candidates if c["region"] == secondary), None)

    # ------------------------------------------------------------------ cost to run
    cur, fx = q.currency, q.fx_per_usd
    if target:
        infra, by_class, transfer = _run_cost(sel, secondary, regions, classes, ri)
        status = {k: _availability(cfg["availability"], s["regional"], secondary) for k, s in svc_spend.items()}
    else:
        infra, by_class, transfer, status = 0.0, {}, 0.0, {}
    # AWS Support is billed on the payer's whole bill: price the uplift on top of the scan's total.
    scan_monthly = sum(r["amount"] for r in scan.get("costs", []) if r["amount"] > 0) / n_months
    support = support_fee(scan_monthly + infra + transfer, mq.support_plan) - support_fee(scan_monthly, mq.support_plan)

    acct_out, totals = _account_risks(accounts, lines, chosen, secondary, mq, q, cfg)
    fte_parts, fte = _people(q, ri, totals, bool(sel))
    fte_cost = mq.fte_annual_cost or q.day_rate * WORKING_DAYS
    staff_annual = fte * fte_cost  # in ``cur``

    # ------------------------------------------------------------------ cost and time to build
    material = totals.material
    factor = CICD_FACTORS[q.cicd] * IAC_FACTORS[q.iac] * (REGULATED_FACTOR if q.regulated else 1.0)
    existing_pct = target["existing_pct"] if target else 0.0
    lz = (LANDING_ZONE_WEEKS[ri] + LANDING_ZONE_PER_ACCOUNT * material) * (
        0.5 if existing_pct >= EXISTING_FOOTPRINT_PCT else 1.0
    )
    delivery = (totals.service_weeks + ACCOUNT_WEEKS[ri] * material) * factor
    dr = (DR_PROGRAMME_WEEKS[ri] + DR_PER_ACCOUNT * material) * (REGULATED_FACTOR if q.regulated else 1.0)
    pmo = (delivery + lz + dr) * PMO_PCT
    base = delivery + lz + dr + pmo
    contingency = base * q.contingency_pct / 100
    total_weeks = base + contingency if sel else 0.0
    capacity = max(q.cloud_team_size * mq.allocation_pct / 100 + q.app_engineers_fte, 0.5)
    effort_bound = total_weeks / (capacity * PRODUCTIVE_PCT)
    calendar_weeks = math.ceil(max(effort_bound, CRITICAL_PATH_WEEKS[ri]) + REHEARSAL_WEEKS) if sel else 0
    infra_annual_fx = (infra + transfer) * 12 * fx
    support_annual_fx = support * 12 * fx
    labour = total_weeks * 5 * q.day_rate
    ramp = infra_annual_fx * (calendar_weeks / 52) * RAMP_SHARE
    build_cost = labour + ramp
    run_annual = infra_annual_fx + support_annual_fx + staff_annual
    sel_annual_fx = sel_monthly * 12 * fx
    p = regions[primary]

    def mr(lo: float, hi: float) -> str:
        return money_range(lo, hi, cur) if hi > 0 else "–"

    ranges = {
        "run_annual": mr(run_annual * COST_RANGE[0], run_annual * COST_RANGE[1]),
        "infra_annual": mr(infra_annual_fx * COST_RANGE[0], infra_annual_fx * COST_RANGE[1]),
        "support_annual": mr(support_annual_fx * COST_RANGE[0], support_annual_fx * COST_RANGE[1]),
        "staff_annual": mr(staff_annual * STAFF_RANGE[0], staff_annual * STAFF_RANGE[1]),
        "uplift_pct": share_range(run_annual * COST_RANGE[0], run_annual * COST_RANGE[1], sel_annual_fx)
        if sel_annual_fx > 0 and run_annual > 0
        else None,
        "build_cost": mr(build_cost * COST_RANGE[0], build_cost * COST_RANGE[1]),
        "build_duration": duration_range(
            calendar_weeks * DURATION_RANGE[0] / WEEKS_PER_MONTH, calendar_weeks * DURATION_RANGE[1] / WEEKS_PER_MONTH
        )
        if calendar_weeks
        else "–",
        "build_effort": effort_range(
            total_weeks / WEEKS_PER_MONTH * COST_RANGE[0], total_weeks / WEEKS_PER_MONTH * COST_RANGE[1]
        )
        if total_weeks
        else "–",
        "staff": f"{math.floor(fte * STAFF_RANGE[0]):,.0f} to {math.ceil(fte * STAFF_RANGE[1]):,.0f}" if fte else "–",
    }

    selected_risks = [r for a in acct_out if a["selected"] for r in a["risks"] if r["monthly_spend"] >= q.materiality]
    blocked = [a for a in acct_out if a["selected"] and a["readiness"] in ("High", "Critical")]
    sev_counts = {k: sum(1 for r in selected_risks if r["severity"] == k) for k in SEVERITY_ORDER}
    parity = [
        {
            "service": s["display"],
            "class": s["class"],
            "class_label": classes[s["class"]]["label"],
            "monthly_spend": round(s["monthly_spend"], 2),
            "accounts": len(s["accounts"]),
            "availability": status.get(k, "unverified"),
        }
        for k, s in sorted(svc_spend.items(), key=lambda kv: -kv[1]["monthly_spend"])
    ]
    same_country = [c for c in candidates if c["country"] == p["country"]]
    summary = {
        "primary": primary,
        "primary_name": p["name"],
        "primary_detected": primary == detected,
        "has_region_data": has_region_data,
        "secondary": secondary,
        "secondary_name": regions[secondary]["name"] if secondary else None,
        "recommended": recommended,
        "recommended_name": regions[recommended]["name"] if recommended else None,
        "target": target,
        "accounts_in_scope": len(accounts),
        "accounts_selected": len(chosen),
        "monthly_spend_selected": round(sel_monthly, 2),
        "regional_monthly": round(regional_monthly, 2),
        "by_region": [
            {
                "region": k,
                "name": regions.get(k, {}).get("name", "Global (not regional)" if k == "global" else k),
                "monthly_spend": round(v, 2),
            }
            for k, v in sorted(by_region.items(), key=lambda kv: -kv[1])
        ],  # fmt: skip
        "run": {
            "infra_monthly": round(infra, 2),
            "transfer_monthly": round(transfer, 2),
            "support_monthly": round(support, 2),
            "by_class": [
                {"class": k, "label": classes[k]["label"], "monthly": round(v, 2)}
                for k, v in sorted(by_class.items(), key=lambda kv: -kv[1])
                if v > 0
            ],
            "staff_annual": round(staff_annual),
            "annual_total": round(run_annual),
            "currency": cur,
        },
        "staff": {
            "fte": round(fte, 1),
            "parts": [{"role": k, "fte": round(v, 1)} for k, v in fte_parts.items()],
            "fte_annual_cost": round(fte_cost),
        },
        "build": {
            "total_weeks": round(total_weeks, 1),
            "parts": [
                {"part": "Second-region landing zone", "weeks": round(lz, 1)},
                {"part": "Workloads made multi-region", "weeks": round(totals.service_weeks * factor, 1)},
                {
                    "part": "Per-account failover, DNS, IAM, pipelines",
                    "weeks": round(ACCOUNT_WEEKS[ri] * material * factor, 1),
                },
                {"part": "DR runbooks, rehearsals and evidence", "weeks": round(dr, 1)},
                {"part": "Programme management", "weeks": round(pmo, 1)},
                {"part": "Contingency", "weeks": round(contingency, 1)},
            ],  # fmt: skip
            "calendar_weeks": calendar_weeks,
            "capacity_fte": round(capacity, 1),
            "constrained_by": "team capacity" if effort_bound >= CRITICAL_PATH_WEEKS[ri] else "critical path",
            "labour": round(labour),
            "ramp": round(ramp),
            "material_accounts": material,
        },
        "severity_counts": sev_counts,
        "accounts_blocked": len(blocked),
        "country_name": COUNTRY_NAMES.get(p["country"], p["country"]),
        "no_second_region_in_country": not same_country,
        "ranges": ranges,
    }
    summary["executive"] = _executive(summary, candidates, mq, q, p)
    for n in notes:
        _log_once(scan.get("id", ""), n)
    log.info(
        "multi-region %s: %s %d/%d account(s), %s -> %s, run %.0f %s/yr, build %.0f weeks, %d note(s), %.0f ms",
        scan.get("id", "?"), mq.recovery, len(chosen), len(accounts), primary, secondary or "none",
        run_annual, cur, total_weeks, len(notes), (time.perf_counter() - started) * 1000,
    )  # fmt: skip
    return {
        "notes": notes,
        "answers": mq.model_dump(),
        "labels": {"recovery": RECOVERY, "residency": RESIDENCY, "support_plan": SUPPORT_PLANS},
        "regions": {k: v["name"] for k, v in regions.items()},
        "summary": summary,
        "candidates": candidates,
        "parity": parity,
        "accounts": acct_out,
        "assumptions": _assumptions(mq, q, cfg, factor, fte_cost),
        "provisional": not mq.confirmed,
    }


def _executive(s: dict, candidates: list, mq: MultiRegionAnswers, q: Questionnaire, p: dict) -> dict:
    rg = s["ranges"]
    t = s["target"]
    findings, actions = [], []
    if not s["accounts_selected"] or not t:
        return {"headline": "Pick at least one account, and a region the residency rule allows, to estimate.",
                "findings": [], "actions": []}  # fmt: skip
    recov = "recover within 3 hours" if mq.recovery == "rto_3h" else "fail over instantly (active-active)"
    headline = (
        f"To {recov}, a second region in {s['secondary_name']} for {_n(s['accounts_selected'], 'account')} would add "
        f"roughly {rg['run_annual']} a year to run"
        + (f" ({rg['uplift_pct']} of their spend)" if rg["uplift_pct"] else "")
        + f", cost {rg['build_cost']} and take {rg['build_duration']} to build, and need {rg['staff']} more people."
    )
    regional = s["regional_monthly"] or 1
    in_primary = next((r["monthly_spend"] for r in s["by_region"] if r["region"] == s["primary"]), 0)
    others = [
        r
        for r in s["by_region"]
        if r["region"] not in (s["primary"], "global") and r["monthly_spend"] >= 0.01 * regional
    ]
    all_regional = max(sum(r["monthly_spend"] for r in s["by_region"] if r["region"] != "global"), 1)
    also = ""
    if others:
        verb = "carries" if len(others) == 1 else "carry"
        also = f"; {', '.join(r['name'] for r in others[:3])} already {verb} some"
    findings.append(
        {
            "lead": "Today.",
            "text": f"{100 * in_primary / all_regional:.0f}% of regional spend runs in {s['primary_name']}{also}."
            + ("" if s["has_region_data"] else " (This scan has no region split: re-scan for it.)"),
        }
    )
    rec = s["recommended_name"]
    findings.append(
        {
            "lead": "Recommended region.",
            "text": (
                f"{rec}: {t['parity_pct']:.0f}% of spend is on services available there, about "
                f"{t['latency_ms']} ms from {s['primary_name']}, prices about "
                f"{round(100 * (t['price_index'] - 1)):+d}% against it."
            )
            if s["secondary"] == s["recommended"]
            else (
                f"{rec} scores best; you chose {s['secondary_name']} "
                f"({t['parity_pct']:.0f}% parity, ~{t['latency_ms']} ms)."
            ),
        }
    )
    if t["missing"]:
        names = ", ".join(f"{m['display']} ({_money(m['monthly_spend'])}/month)" for m in t["missing"][:4])
        findings.append(
            {
                "lead": "Service gaps.",
                "text": f"Not offered in {s['secondary_name']}: {names}. These must be re-architected.",
            }
        )
    if s["accounts_blocked"]:
        findings.append(
            {
                "lead": "Failover risk.",
                "text": f"{s['accounts_blocked']} of {_n(s['accounts_selected'], 'chosen account')} run a material "
                "service that cannot meet the target as built "
                + (
                    "(no automatic failover, or no live replica)."
                    if mq.recovery == "instant"
                    else "(no live replica: restore takes hours)."
                ),
            }
        )
    if s["no_second_region_in_country"]:
        findings.append(
            {
                "lead": "Data residency.",
                "text": f"AWS has no second region in {s['country_name']}: any second region moves data "
                "across a border, which needs regulator and data-protection sign-off.",
            }
        )
    if mq.recovery == "instant" and t["latency_ms"] > SYNC_MAX_MS:
        findings.append(
            {
                "lead": "Latency.",
                "text": f"At ~{t['latency_ms']} ms, synchronous replication is impractical: instant failover will "
                "lose the last seconds of writes unless applications are designed for it.",
            }
        )
    findings.append(
        {"lead": "People.", "text": f"About {rg['staff']} extra FTE to run two regions ({rg['staff_annual']} a year)."}
    )
    if s["no_second_region_in_country"]:
        actions.append(
            {
                "lead": "Settle residency first.",
                "text": "Agree with the regulator which data may sit outside the country.",
            }
        )
    actions.append(
        {
            "lead": "Tier the workloads.",
            "text": "Not every account needs the same target: keep instant failover for the few systems whose "
            "outage is a systemic event, and 3-hour recovery for the rest.",
        }
    )
    actions.append(
        {
            "lead": "Fix the hardest services first.",
            "text": "Start with services that have no live replica or are missing in the second region; "
            "they set the timeline.",
        }
    )
    actions.append(
        {"lead": "Rehearse.", "text": "Prove failover with a scheduled region-evacuation test and keep the evidence."}
    )
    return {"headline": headline, "findings": findings, "actions": actions}


def _assumptions(mq: MultiRegionAnswers, q: Questionnaire, cfg: dict, factor: float, fte_cost: float) -> list[str]:
    ri = RECOVERY_INDEX[mq.recovery]
    return [
        f"Recovery target: {RECOVERY[mq.recovery]}. Each service's spend in the chosen accounts is multiplied by "
        "its class's second-region share (data/regions.yaml): "
        + "; ".join(f"{c['label']} {c['run'][ri]:.0%}" for k, c in cfg["classes"].items() if k != "global")
        + ".",
        f"Replication traffic: {TRANSFER_PCT[ri]:.0%} of database, storage and analytics spend.",
        "Second-region prices use an indicative regional price index (EC2 on-demand list prices against us-east-1).",
        f"AWS Support: {SUPPORT_PLANS[mq.support_plan]} list-price tiers applied to the whole scanned bill plus "
        "the new region; enterprise agreements and discounts differ.",
        f"Latency is estimated from distance (fibre ~{FIBRE_KM_PER_MS:.0f} km/ms, routes {ROUTE_FACTOR}x the great "
        "circle): measure before committing.",
        "Service availability: AWS's public regional services table, version "
        f"{cfg['availability_version']} (fetched {cfg['availability_fetched']}). Services not listed there are "
        "'not verified' and their effort is raised 25%.",
        f"Region score: parity {SCORE_WEIGHTS[mq.recovery][0]:.0%}, latency {SCORE_WEIGHTS[mq.recovery][1]:.0%}, "
        f"price {SCORE_WEIGHTS[mq.recovery][2]:.0%}, plus a bonus where the estate already runs.",
        f"People: {STAFF_TEAM_UPLIFT[ri]:.0%} of the core cloud team ({q.cloud_team_size}) + {STAFF_RESILIENCE[ri]:g} "
        f"resilience + {STAFF_PER_25_ACCOUNTS[ri]:g} per 25 material accounts + data operations scaled by data "
        f"spend; at least {STAFF_FLOOR[ri]:g}. Cost per FTE {fte_cost:,.0f} {q.currency} a year.",
        f"Build: catalog-style engineer-weeks per service and account × delivery factor {factor:.2f} (CI/CD × IaC"
        + (" × regulated" if q.regulated else "")
        + f"), plus a second-region landing zone (halved where {EXISTING_FOOTPRINT_PCT:g}%+ of spend already runs "
        f"there), DR programme, {PMO_PCT:.0%} programme management and {q.contingency_pct}% contingency.",
        f"Duration: the longer of effort ÷ capacity ({mq.allocation_pct}% of the cloud team + application "
        f"engineers, {PRODUCTIVE_PCT:.0%} productive) and a {CRITICAL_PATH_WEEKS[ri]}-week critical path, plus "
        f"{REHEARSAL_WEEKS} weeks of failover rehearsal. Build cost includes running the half-built region meanwhile.",
        "Figures are ranges (−25% / +50% on cost, −20% / +40% on time), widened to round numbers.",
    ]
