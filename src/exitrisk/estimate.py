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

from pydantic import BaseModel, Field

CICD_FACTORS = {"standard": 0.85, "partial": 1.0, "manual": 1.3}
IAC_FACTORS = {"terraform_current": 0.8, "terraform_drift": 1.1, "cloudformation": 1.25, "none": 1.5}
TARGET_FACTORS = {"azure": 1.0, "gcp": 1.0, "oci": 1.1, "sovereign": 1.2, "onprem": 1.35}
TARGET_LABELS = {
    "azure": "Microsoft Azure",
    "gcp": "Google Cloud",
    "oci": "Oracle Cloud",
    "sovereign": "Sovereign / local cloud",
    "onprem": "On-premises (Kubernetes / VMs)",
}
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

# Resource counts that evidence a "typical workload" of a service, for the deep scan.
TYPICAL_COUNTS = {
    "AWS Lambda": ("lambda_functions", 25),
    "Amazon DynamoDB": ("dynamodb_tables", 10),
    "AWS Step Functions": ("step_functions", 10),
    "Amazon Kinesis": ("kinesis_streams", 5),
    "Amazon Simple Queue Service": ("sqs_queues", 20),
    "Amazon Simple Notification Service": ("sns_topics", 20),
    "Amazon EventBridge": ("eventbridge_rules", 20),
    "Amazon Cognito": ("cognito_user_pools", 1),
    "AWS Glue": ("glue_jobs", 10),
    "Amazon Redshift": ("redshift_clusters", 1),
    "AWS CloudFormation": ("cloudformation_stacks", 30),
    "Amazon Elastic Kubernetes Service": ("eks_clusters", 1),
    "Amazon Elastic Container Service": ("ecs_clusters", 2),
}


class Questionnaire(BaseModel):
    cicd: str = Field("partial", pattern="^(standard|partial|manual)$")
    iac: str = Field("terraform_drift", pattern="^(terraform_current|terraform_drift|cloudformation|none)$")
    cloud_team_size: int = Field(10, ge=1, le=2000)
    cloud_team_allocation_pct: int = Field(50, ge=5, le=100)
    app_engineers_fte: float = Field(10, ge=0, le=5000)
    target: str = Field("azure", pattern="^(azure|gcp|oci|sovereign|onprem)$")
    day_rate: float = Field(750, ge=0, le=100000)
    currency: str = Field("USD", pattern="^[A-Z]{3}$")
    # AWS bills in USD; the labour rate is in ``currency``. Units of ``currency`` per 1 USD.
    fx_per_usd: float = Field(1.0, gt=0, le=100000)
    contingency_pct: int = Field(25, ge=0, le=100)
    parallel_run_months: int = Field(6, ge=0, le=36)
    regulated: bool = True
    materiality: float = Field(25, ge=0, le=1_000_000)
    # True once someone has answered (or confirmed) these questions. Until then the cost and time
    # figures rest on defaults, and the report labels them provisional instead of headlining them.
    confirmed: bool = False


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
    waves: list
    assumptions: list

    def to_dict(self) -> dict:
        return asdict(self)


def build_estimate(q: Questionnaire, accounts: list[dict], monthly_spend: float) -> dict:
    """``accounts`` are report account rows carrying ``effort_by_tier`` (unadjusted engineer-weeks)."""
    by_tier = {t: 0.0 for t in range(1, 6)}
    for a in accounts:
        for t, w in a["effort_by_tier"].items():
            by_tier[int(t)] += w
    service_weeks = sum(by_tier.values())
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
    critical_path = CRITICAL_PATH_WEEKS[highest_tier] + lz_base / 2
    build_weeks = max(effort_bound, critical_path)
    calendar_weeks = math.ceil(build_weeks + DECOMMISSION_WEEKS)

    labour = total * 5 * q.day_rate
    parallel = q.parallel_run_months * monthly_spend * PARALLEL_RUN_OVERLAP * q.fx_per_usd
    total_cost = labour + parallel

    # Waves: landing zone first, then easiest to hardest so the team learns on portable workloads.
    mobilise = max(6.0, landing_zone * (1 + PMO_PCT) / (capacity * PRODUCTIVE_PCT))
    mobilise = min(mobilise, build_weeks * 0.35)
    remaining = build_weeks - mobilise
    wave_effort = {"w1": by_tier[1] + by_tier[2], "w2": by_tier[3], "w3": by_tier[4] + by_tier[5]}
    wave_total = sum(wave_effort.values()) or 1.0
    waves = [{"name": "Mobilise & target landing zone", "start": 0.0, "weeks": round(mobilise, 1), "tiers": []}]
    cursor = mobilise
    for key, name, tiers in (
        ("w1", "Wave 1: portable (tiers 1–2)", [1, 2]),
        ("w2", "Wave 2: moderate (tier 3)", [3]),
        ("w3", "Wave 3: high & critical (tiers 4–5)", [4, 5]),
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
            "low_months": round(calendar_weeks * 0.8 / WEEKS_PER_MONTH, 1),
            "high_months": round(calendar_weeks * 1.4 / WEEKS_PER_MONTH, 1),
        },
        cost={
            "currency": q.currency,
            "labour": round(labour),
            "parallel_run": round(parallel),
            "total": round(total_cost),
            "low": round(total_cost * 0.75),
            "high": round(total_cost * 1.5),
            # One-off exit cost against a year of the AWS bill being exited, in the same currency.
            "pct_of_annual_spend": round(100 * total_cost / (monthly_spend * 12 * q.fx_per_usd), 1)
            if monthly_spend > 0
            else None,
        },
        waves=waves,
        assumptions=[
            "Service effort: catalog engineer-weeks per workload × √(monthly spend / "
            f"{REFERENCE_MONTHLY_SPEND:,.0f} USD), clamped {SIZE_MULT_MIN}–{SIZE_MULT_MAX}×; "
            "resource counts from the deep scan raise it where higher.",
            f"Services under {q.materiality:,.0f} USD/month are scored but not estimated (immaterial).",
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
            "Excluded: target-cloud run cost after exit, licence changes, early-termination of AWS commitments "
            "(EDP, Savings Plans, RIs), and data-transfer-out fees (AWS waives egress for customers leaving AWS on "
            "request to AWS Support, since March 2024).",
            "Range shown is −25% / +50% on cost and −20% / +40% on duration (early-stage estimation cone).",
        ],
    ).to_dict()
