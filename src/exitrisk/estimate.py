"""Migration cost and time estimate.

The estimate is deliberately simple enough to explain to an executive committee in one
slide, and every coefficient is listed in ``assumptions`` on the report so it can be
challenged. Engineering effort is built bottom-up from the services each account uses
(``effort_weeks`` in the catalog, scaled by spend and, when the deep scan ran, by how many
resources exist), then adjusted by the organisation's delivery maturity - the answers to
the questionnaire on the dashboard.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Annotated

from pydantic import BaseModel, Field

from .catalog import AGENTIC_FACTORS
from .resource_effort import assumptions as resource_assumptions

CICD_FACTORS = {"standard": 0.85, "partial": 1.0, "manual": 1.3}
IAC_FACTORS = {"terraform_current": 0.8, "terraform_drift": 1.1, "cloudformation": 1.25, "none": 1.5}
# Every managed service AWS ran becomes something you run: the further from a hyperscaler, the more work.
TARGET_FACTORS = {"azure": 1.0, "gcp": 1.0, "oci": 1.1, "sovereign": 1.2, "onprem": 1.35, "datacenter": 1.5}
TARGET_LABELS = {
    "azure": "Microsoft Azure",
    "gcp": "Google Cloud",
    "oci": "Oracle Cloud",
    "sovereign": "Sovereign / local cloud",
    "onprem": "On-premises platform you already run (Kubernetes / VMs)",
    "datacenter": "Physical data centre (your own hardware)",
}
# How a target reads mid-sentence: "a full exit to your own data centre".
TARGET_PHRASES = {**TARGET_LABELS, "onprem": "an on-premises platform", "datacenter": "your own data centre"}
TARGET_PATTERN = "^(" + "|".join(TARGET_LABELS) + ")$"

# Physical data centre: the facility and hardware must exist before workloads can move.
DC_FACILITY_LABELS = {
    "existing": "Space and power in a data centre you already run",
    "colocation": "Colocation: rent space and power, buy the hardware",
    "build": "Build a new data centre",
}
# Weeks before the first production workload can land: contracts, procurement, racking, network.
DC_LEAD_WEEKS = {"existing": 16, "colocation": 26, "build": 104}
# One-off hardware (servers, storage, network) for production capacity with headroom, as months of
# the AWS bill being exited; a disaster-recovery site adds a share of that again.
DC_HARDWARE_MONTHS = 9
DC_DR_HARDWARE_SHARE = 0.6
# One-off facility cost as months of the AWS bill: cage build-out and connectivity, or a new building.
DC_FACILITY_MONTHS = {"existing": 0, "colocation": 2, "build": 12}
CICD_LABELS = {
    "standard": "One standard CI/CD pipeline",
    "partial": "Several, partially standard pipelines",
    "manual": "Mostly manual / ad-hoc deployment",
}
IAC_LABELS = {
    "terraform_current": "Terraform, current with production",
    "terraform_drift": "Terraform with significant drift",
    "cloudformation": "CloudFormation / CDK",
    "none": "Little or no infrastructure-as-code",
}
REGULATED_FACTOR = 1.15
PMO_PCT = 0.12
PRODUCTIVE_PCT = 0.8
# Target landing zone: a floor for any estate, growing with sqrt(spend) to a cap for large ones.
LANDING_ZONE_MIN_WEEKS, LANDING_ZONE_MAX_WEEKS = 4.0, 24.0
LANDING_ZONE_REFERENCE_SPEND = 100_000.0
LANDING_ZONE_PER_ACCOUNT = 0.5
ACCOUNT_OVERHEAD_WEEKS = 1.0
DECOMMISSION_WEEKS = 4
CRITICAL_PATH_WEEKS = {5: 26, 4: 16, 3: 10, 2: 8, 1: 6}
PARALLEL_RUN_OVERLAP = 0.5
SIZE_MULT_MIN, SIZE_MULT_MAX = 0.25, 8.0
REFERENCE_MONTHLY_SPEND = 1000.0
WEEKS_PER_MONTH = 4.33
# Early-stage estimation cone: the report quotes ranges, never a single figure.
COST_RANGE = (0.75, 1.5)
DURATION_RANGE = (0.8, 1.4)


class Questionnaire(BaseModel):
    cicd: str = Field("partial", pattern="^(standard|partial|manual)$")
    iac: str = Field("terraform_drift", pattern="^(terraform_current|terraform_drift|cloudformation|none)$")
    cloud_team_size: int = Field(10, ge=1, le=2000)
    cloud_team_allocation_pct: int = Field(50, ge=5, le=100)
    app_engineers_fte: float = Field(10, ge=0, le=5000)
    target: str = Field("azure", pattern=TARGET_PATTERN)
    # Only used when target is "datacenter".
    dc_facility: str = Field("colocation", pattern="^(existing|colocation|build)$")
    dc_dr_site: bool = True
    day_rate: float = Field(750, ge=0, le=100000)
    currency: str = Field("USD", pattern="^[A-Z]{3}$")
    # AWS bills in USD; the labour rate is in ``currency``. Units of ``currency`` per 1 USD.
    fx_per_usd: float = Field(1.0, gt=0, le=100000)
    contingency_pct: int = Field(25, ge=0, le=100)
    parallel_run_months: int = Field(6, ge=0, le=36)
    regulated: bool = True
    # AI coding agents translate code and templates: each service's weeks shrink by its catalog
    # ``agentic`` rating (see catalog.AGENTIC_FACTORS). Off until the organisation says it uses them.
    ai_agents: bool = False
    # AWS products the organisation leaves out of the score and the estimate (catalog service names),
    # for example Marketplace software it re-contracts anyway, or a service it already plans to retire.
    exclude_services: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=300
    )
    materiality: float = Field(25, ge=0, le=1_000_000)
    # Timing (not the estimate): the months you would have to exit (supplier notice, regulator
    # expectation; 0 = not set), and an enterprise discount agreement's end month and yearly commit.
    exit_deadline_months: int = Field(0, ge=0, le=240)
    edp_end: str = Field("", pattern=r"^(\d{4}-(0[1-9]|1[0-2]))?$")
    edp_annual_commit: float = Field(0, ge=0, le=1e11)
    # Resilience view only (not the estimate): accounts to treat as critical when they carry no
    # criticality tag (comma-separated, name contains).
    critical_accounts: str = Field("", max_length=200)
    # What your carrier charges a month for each new 10 Gbps migration link (circuit and cross-connect),
    # in USD. 0 = not known: the link costs then cover AWS only, and say so.
    migration_circuit_monthly: float = Field(0, ge=0, le=1_000_000)
    # True once someone has answered (or confirmed) these questions. Until then the cost and time
    # figures rest on defaults, and the report labels them provisional instead of headlining them.
    confirmed: bool = False


def _round_step(v: float) -> float:
    """A coarse step for ``v`` (1-2-5 style), so ranges read as approximations: 7m, 16m, 300."""
    mag = 10 ** math.floor(math.log10(v))
    lead = v / mag
    return mag / 5 if lead < 2 else mag / 2 if lead < 5 else mag


def _rough(lo: float, hi: float) -> tuple[float, float]:
    """Widen [lo, hi] outward to round numbers: never narrower than the estimate."""
    if hi <= 0:
        return 0.0, 0.0
    lo_step = _round_step(lo) if lo > 0 else _round_step(hi)
    hi_step = _round_step(hi)
    return max(math.floor(lo / lo_step) * lo_step, lo_step), math.ceil(hi / hi_step) * hi_step


def _short(v: float) -> str:
    for div, unit in ((1e9, "bn"), (1e6, "m"), (1e3, "k")):
        if v >= div:
            return f"{v / div:,.3g}{unit}"
    return f"{v:,.0f}"


def money_range(lo: float, hi: float, currency: str = "USD") -> str:
    """'$7m to $15m'."""
    sym = "$" if currency == "USD" else f"{currency} "
    a, b = _rough(lo, hi)
    return f"{sym}{_short(a)} to {sym}{_short(b)}"


def duration_bounds(lo_months: float, hi_months: float) -> tuple[float, float]:
    """The range as shown, in months, rounded outward: whole months below a year, quarters below two
    years, half-years above. Anything compared with the shown range (a deadline) uses these bounds."""
    if hi_months < 12:
        # Quarters would turn 5.9 to 10.4 months into "3 to 12": too wide to plan with.
        a = max(math.floor(lo_months), 1)
        return a, max(math.ceil(hi_months), a + 1)
    if hi_months < 24:
        a = max(math.floor(lo_months / 3) * 3, 1)
        return a, max(math.ceil(hi_months / 3) * 3, a + 1)
    return max(math.floor(lo_months / 6) * 6, 6), math.ceil(hi_months / 6) * 6


def duration_range(lo_months: float, hi_months: float) -> str:
    """'5 to 11 months' (months), '9 to 15 months' (quarters) or '2.5 to 5 years' (half-years)."""
    a, b = duration_bounds(lo_months, hi_months)
    if hi_months < 24:
        return f"{a} to {b} months"
    return f"{a / 12:g} to {b / 12:g} years"


def count_range(lo: float, hi: float) -> str:
    """'300 to 700'."""
    a, b = _rough(lo, hi)
    fmt = lambda x: f"{x:,.0f}" if x >= 10 else f"{x:g}"  # noqa: E731
    return f"{fmt(a)} to {fmt(b)}"


def share_range(lo: float, hi: float, base: float) -> str:
    """'35 to 100%': [lo, hi] as a share of base, taken from the rounded money range so the two agree."""
    a, b = _rough(lo, hi)
    return count_range(100 * a / base, 100 * b / base) + "%"


def effort_range(lo_months: float, hi_months: float) -> str:
    """'300 to 700 person-months', or person-years once the low end is two years or more (easier to grasp)."""
    if lo_months >= 24:
        return count_range(lo_months / 12, hi_months / 12) + " person-years"
    return count_range(lo_months, hi_months) + " person-months"


def size_multiplier(monthly_spend: float, count: int | None = None, typical: int | None = None) -> float:
    """sqrt scaling: 4x the spend is ~2x the work. Clamped so tiny and huge lines stay sane."""
    spend_mult = math.sqrt(max(monthly_spend, 0.0) / REFERENCE_MONTHLY_SPEND)
    count_mult = math.sqrt(count / typical) if count and typical else 0.0
    return min(max(spend_mult, count_mult, SIZE_MULT_MIN), SIZE_MULT_MAX)


def service_effort(
    base_weeks: float, monthly_spend: float, count: int | None = None, typical: int | None = None
) -> float:
    return base_weeks * size_multiplier(monthly_spend, count, typical)


@dataclass
class Estimate:
    inputs: dict
    factors: dict
    effort: dict
    team: dict
    duration: dict
    cost: dict
    datacenter: dict | None
    waves: list
    assumptions: list
    ranges: dict

    def to_dict(self) -> dict:
        return asdict(self)


def _datacenter(q: Questionnaire, monthly_spend: float) -> dict:
    """One-off hardware and facility cost, and lead time, of exiting to your own data centre (else zeros)."""
    if q.target != "datacenter":
        return {"lead_weeks": 0, "hardware": 0.0, "facility": 0.0, "assumptions": []}
    sites = 2 if q.dc_dr_site else 1
    hardware_months = DC_HARDWARE_MONTHS * (1 + (DC_DR_HARDWARE_SHARE if q.dc_dr_site else 0))
    # An existing estate is assumed to have its DR site already; a new facility needs one per site.
    facility_months = DC_FACILITY_MONTHS[q.dc_facility] * (sites if q.dc_facility != "existing" else 1)
    fx_spend = monthly_spend * q.fx_per_usd
    lead = DC_LEAD_WEEKS[q.dc_facility]
    return {
        "facility_type": q.dc_facility,
        "facility_label": DC_FACILITY_LABELS[q.dc_facility],
        "dr_site": q.dc_dr_site,
        "lead_weeks": lead,
        "hardware": hardware_months * fx_spend,
        "facility": facility_months * fx_spend,
        "assumptions": [
            f"Physical data centre ({DC_FACILITY_LABELS[q.dc_facility].lower()}): {lead} weeks before the first "
            "production workload can land (contracts, procurement, racking, network), added to the critical path.",
            f"Hardware: {DC_HARDWARE_MONTHS} months of the current AWS bill for production capacity with headroom"
            + (f", plus {DC_DR_HARDWARE_SHARE:.0%} for a disaster-recovery site" if q.dc_dr_site else "")
            + "; facility: "
            + (
                "none (existing space and power)."
                if not facility_months
                else f"{facility_months:g} months of the AWS bill"
                + (" across two sites." if sites == 2 and q.dc_facility != "existing" else ".")
            ),
            "Excluded for the data centre: running it after exit (power, cooling, facility and hardware staff, "
            "maintenance contracts) and hardware refresh every 4 to 6 years.",
        ],
    }


def build_estimate(q: Questionnaire, accounts: list[dict], monthly_spend: float) -> dict:
    """``accounts`` are report account rows carrying ``effort_by_tier`` (unadjusted engineer-weeks)."""
    by_tier = {t: 0.0 for t in range(1, 6)}
    for a in accounts:
        for t, w in a["effort_by_tier"].items():
            by_tier[int(t)] += w
    service_weeks = sum(by_tier.values())
    agentic_saved = sum(a.get("agentic_saved_weeks", 0.0) for a in accounts)
    material_accounts = sum(1 for a in accounts if a["monthly_spend"] >= q.materiality)
    account_weeks = ACCOUNT_OVERHEAD_WEEKS * material_accounts

    factor = CICD_FACTORS[q.cicd] * IAC_FACTORS[q.iac] * TARGET_FACTORS[q.target]
    if q.regulated:
        factor *= REGULATED_FACTOR
    delivery = (service_weeks + account_weeks) * factor
    lz_base = min(
        LANDING_ZONE_MIN_WEEKS + 12 * math.sqrt(max(monthly_spend, 0) / LANDING_ZONE_REFERENCE_SPEND),
        LANDING_ZONE_MAX_WEEKS,
    )
    landing_zone = (lz_base + LANDING_ZONE_PER_ACCOUNT * material_accounts) * TARGET_FACTORS[q.target]
    pmo = (delivery + landing_zone) * PMO_PCT
    base_total = delivery + landing_zone + pmo
    contingency = base_total * q.contingency_pct / 100
    total = base_total + contingency

    capacity = q.cloud_team_size * q.cloud_team_allocation_pct / 100 + q.app_engineers_fte
    capacity = max(capacity, 0.5)
    effort_bound = total / (capacity * PRODUCTIVE_PCT)
    highest_tier = max((t for t, w in by_tier.items() if w > 0), default=1)
    dc = _datacenter(q, monthly_spend)
    critical_path = CRITICAL_PATH_WEEKS[highest_tier] + lz_base / 2 + dc["lead_weeks"]
    build_weeks = max(effort_bound, critical_path)
    calendar_weeks = math.ceil(build_weeks + DECOMMISSION_WEEKS)

    labour = total * 5 * q.day_rate
    parallel = q.parallel_run_months * monthly_spend * PARALLEL_RUN_OVERLAP * q.fx_per_usd
    total_cost = labour + parallel + dc["hardware"] + dc["facility"]

    # Waves: landing zone first, then easiest to hardest so the team learns on portable workloads.
    mobilise = max(6.0, landing_zone * (1 + PMO_PCT) / (capacity * PRODUCTIVE_PCT))
    mobilise = max(min(mobilise, build_weeks * 0.35), dc["lead_weeks"])
    remaining = build_weeks - mobilise
    wave_effort = {"w1": by_tier[1] + by_tier[2], "w2": by_tier[3], "w3": by_tier[4] + by_tier[5]}
    wave_total = sum(wave_effort.values()) or 1.0
    first = "Mobilise, data centre & hardware" if dc["lead_weeks"] else "Mobilise & target landing zone"
    waves = [{"name": first, "start": 0.0, "weeks": round(mobilise, 1), "tiers": []}]
    cursor = mobilise
    for key, name, tiers in (
        ("w1", "Wave 1: portable (tiers 1 and 2)", [1, 2]),
        ("w2", "Wave 2: moderate (tier 3)", [3]),
        ("w3", "Wave 3: high & critical (tiers 4 and 5)", [4, 5]),
    ):
        if wave_effort[key] <= 0:
            continue
        weeks = remaining * wave_effort[key] / wave_total
        waves.append(
            {
                "name": name,
                "start": round(cursor, 1),
                "weeks": round(weeks, 1),
                "tiers": tiers,
                "effort_weeks": round(wave_effort[key] * factor, 1),
            }
        )
        cursor += weeks
    waves.append(
        {
            "name": "Decommission AWS & evidence exit",
            "start": round(cursor, 1),
            "weeks": float(DECOMMISSION_WEEKS),
            "tiers": [],
        }
    )

    annual_fx = monthly_spend * 12 * q.fx_per_usd
    return Estimate(
        inputs=q.model_dump(),
        factors={
            "cicd": CICD_FACTORS[q.cicd],
            "iac": IAC_FACTORS[q.iac],
            "target": TARGET_FACTORS[q.target],
            "regulated": REGULATED_FACTOR if q.regulated else 1.0,
            "combined": round(factor, 3),
        },
        effort={
            "service_weeks": round(service_weeks, 1),
            "account_weeks": round(account_weeks, 1),
            "delivery_weeks": round(delivery, 1),
            "landing_zone_weeks": round(landing_zone, 1),
            "pmo_weeks": round(pmo, 1),
            "contingency_weeks": round(contingency, 1),
            "total_weeks": round(total, 1),
            "person_months": round(total / WEEKS_PER_MONTH, 1),
            "by_tier": {t: round(w * factor, 1) for t, w in by_tier.items()},
            "material_accounts": material_accounts,
            "agentic_saved_weeks": round(agentic_saved * factor, 1),
        },
        team={
            "capacity_fte": round(capacity, 1),
            "cloud_team_fte": round(capacity - q.app_engineers_fte, 1),
            "app_fte": q.app_engineers_fte,
        },
        duration={
            "calendar_weeks": calendar_weeks,
            "calendar_months": round(calendar_weeks / WEEKS_PER_MONTH, 1),
            "effort_bound_weeks": round(effort_bound, 1),
            "critical_path_weeks": round(critical_path, 1),
            "constrained_by": "team capacity" if effort_bound >= critical_path else "critical path",
            "low_months": round(calendar_weeks * DURATION_RANGE[0] / WEEKS_PER_MONTH, 1),
            "high_months": round(calendar_weeks * DURATION_RANGE[1] / WEEKS_PER_MONTH, 1),
        },
        cost={
            "currency": q.currency,
            "labour": round(labour),
            "parallel_run": round(parallel),
            "hardware": round(dc["hardware"]),
            "facility": round(dc["facility"]),
            "total": round(total_cost),
            "low": round(total_cost * COST_RANGE[0]),
            "high": round(total_cost * COST_RANGE[1]),
            # One-off exit cost against a year of the AWS bill being exited, in the same currency.
            "pct_of_annual_spend": round(100 * total_cost / (monthly_spend * 12 * q.fx_per_usd), 1)
            if monthly_spend > 0
            else None,
        },
        datacenter=dc if q.target == "datacenter" else None,
        waves=waves,
        assumptions=[
            "Service effort, where an account was not deep-scanned: catalog engineer-weeks per workload × "
            f"√(monthly spend / {REFERENCE_MONTHLY_SPEND:,.0f} USD), clamped to {SIZE_MULT_MIN} to "
            f"{SIZE_MULT_MAX}×. In material deep-scanned accounts effort comes from resource counts instead "
            "(below), so a cheap but complex service weighs more than a large portable one.",
            *resource_assumptions(),
            f"Services under {q.materiality:,.0f} USD/month in an account are scored but not estimated "
            "(immaterial); the cut-off applies per service per account.",
            f"{ACCOUNT_OVERHEAD_WEEKS:g} engineer-week per material account for network, IAM and decommissioning.",
            f"Target landing zone: {lz_base:.0f} weeks ({LANDING_ZONE_MIN_WEEKS:g} + 12 × √(spend / "
            f"{LANDING_ZONE_REFERENCE_SPEND:,.0f} USD), max {LANDING_ZONE_MAX_WEEKS:g}) + "
            f"{LANDING_ZONE_PER_ACCOUNT:g} per material account.",
            f"Delivery factor {factor:.2f} = CI/CD {CICD_FACTORS[q.cicd]} × IaC {IAC_FACTORS[q.iac]} × target "
            f"{TARGET_FACTORS[q.target]}" + (f" × regulated {REGULATED_FACTOR}" if q.regulated else "") + ".",
            f"Programme management and assurance {PMO_PCT:.0%}; contingency {q.contingency_pct}%.",
            f"Engineers are {PRODUCTIVE_PCT:.0%} productive on migration work; duration is the longer of effort ÷ "
            "capacity and the critical path of the hardest tier present, plus decommissioning.",
            f"Parallel running: {q.parallel_run_months} months at {PARALLEL_RUN_OVERLAP:.0%} of current AWS spend "
            "(target ramps up as AWS ramps down)"
            + (f", converted at {q.fx_per_usd:g} {q.currency}/USD." if q.currency != "USD" else "."),
            *(
                [
                    "AI coding agents: each service's weeks are cut by its catalog rating: high "
                    f"{1 - AGENTIC_FACTORS['high']:.0%} (Lambda, API Gateway, Step Functions, CloudFormation), medium "
                    f"{1 - AGENTIC_FACTORS['medium']:.0%}, low {1 - AGENTIC_FACTORS['low']:.0%}, none for data "
                    f"moves, hardware and managed-service redesign. Saved {agentic_saved:,.0f} engineer-weeks before "
                    "the delivery factor; agents still need engineers to review and test their changes."
                ]
                if q.ai_agents
                else []
            ),
            *(
                [f"Left out of the score and estimate at your request: {', '.join(q.exclude_services)}."]
                if q.exclude_services
                else []
            ),
            *dc["assumptions"],
            "Excluded: target-cloud run cost after exit, licence changes, AWS commitments still owed after the "
            "exit (EDP, Savings Plans, RIs; shown under Timing), and the cost of copying the data out: Direct "
            "Connect ports and data-out fees are sized under Resilience, Links for the migration. Since March 2024 "
            "AWS credits internet egress (not Direct Connect) for customers leaving AWS, on request to AWS Support "
            "and subject to approval, for a move completed within about 60 days.",
            "Figures are quoted as ranges, widened to round numbers: −25% / +50% on cost and effort, "
            "−20% / +40% on duration (early-stage estimation cone). The model's single figures are "
            "planning midpoints, not forecasts.",
        ],
        ranges={
            "cost": money_range(total_cost * COST_RANGE[0], total_cost * COST_RANGE[1], q.currency),
            "duration": duration_range(
                calendar_weeks * DURATION_RANGE[0] / WEEKS_PER_MONTH,
                calendar_weeks * DURATION_RANGE[1] / WEEKS_PER_MONTH,
            ),
            "effort": effort_range(total / WEEKS_PER_MONTH * COST_RANGE[0], total / WEEKS_PER_MONTH * COST_RANGE[1]),
            "pct_of_annual_spend": share_range(total_cost * COST_RANGE[0], total_cost * COST_RANGE[1], annual_fx)
            if annual_fx > 0
            else None,
        },
    ).to_dict()
