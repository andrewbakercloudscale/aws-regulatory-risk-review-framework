# Methodology

This document defines exactly how the report's numbers are produced, so that a reviewer, an auditor
or a regulator can reproduce them from the scan file. Every coefficient lives in code in one place
(`src/exitrisk/scoring.py`, `src/exitrisk/estimate.py`, `src/exitrisk/data/service_catalog.yaml`) and
is printed on the report's assumptions list.

## 1. Data collected

| Source | API | What | Where it runs |
|---|---|---|---|
| AWS Organizations | `ListRoots`, `ListOrganizationalUnitsForParent`, `ListAccountsForParent`, `DescribeOrganization` | OU tree; accounts under the chosen OU, recursively; account name, status, OU path | Management account |
| Cost Explorer | `GetCostAndUsage` | **Amortised** cost, monthly, grouped by `LINKED_ACCOUNT` × `SERVICE`, for the last *N* complete months | Management account |
| Deep scan (optional) | List/describe calls in every enabled region | Counts of Lambda functions, DynamoDB tables, state machines, Kinesis streams, SQS queues, SNS topics, EventBridge rules, API Gateway APIs, Cognito user pools, Glue jobs, Redshift clusters, CloudFormation stacks, EKS/ECS clusters, RDS instances by engine | Each member account via `ExitRiskReadOnly` |

Cost Explorer filters:

- `RECORD_TYPE` excludes `Credit`, `Refund`, `Tax`, `Support` — the score reflects the cost of running
  workloads, not discounts or overheads.
- `BILLING_ENTITY = AWS` for AWS services; a second query for `AWS Marketplace` groups all third-party
  software under one line, *AWS Marketplace (third-party)*, tier 2.
- `AmortizedCost` spreads upfront Reserved Instance and Savings Plan payments over the months they
  cover, so a workload bought on a 3-year all-upfront RI is not invisible.
- Lines of exactly zero (free tier) are ignored; negative lines that escape the filter are ignored and
  counted on the data-quality panel. Billing-only services (tax, support plans, Savings Plan fees,
  billing tools) are marked `excluded` in the catalog and reported separately.

Spend is averaged per month over the months present in the data.

## 2. Service tiers

Each Cost Explorer service name is looked up in the catalog (exact name, then aliases, then
case-insensitive). The five tiers are defined by **how much of a workload must change to leave AWS**:

| Tier | Label | Score | Test applied |
|---|---|---|---|
| 1 | Portable | 10 | An open standard or commodity primitive; the workload moves without code change |
| 2 | Low | 30 | A managed flavour of an open engine or de-facto standard API; data and configuration migrate, code changes are incidental |
| 3 | Moderate | 50 | AWS-specific API with a close equivalent on every major cloud; code changes at integration points |
| 4 | High | 75 | Proprietary programming or data model; the workload must be redesigned |
| 5 | Critical | 95 | No equivalent outside AWS; rebuild, re-platform or replace with a product |

Scores are deliberately not linear in tier: moving from "re-point" (3) to "redesign" (4) is a larger
step in cost and risk than moving from 1 to 2. No service scores zero, because every migration has a
cost. A service not in the catalog scores as tier 3 and raises a warning on the report.

## 3. Scores

For account *a* with monthly spend *s<sub>a,i</sub>* on service *i* whose tier score is *t<sub>i</sub>*:

```
inherent_risk(a)  = Σ_i s(a,i) · t(i) / Σ_i s(a,i)          0–100, how hard this account is to move
weight(a)         = f(S(a)) / Σ_b f(S(b))                    S(a) = Σ_i s(a,i), monthly spend of the account
contribution(a)   = inherent_risk(a) · weight(a)             points of the OU score this account carries
OU score          = Σ_a contribution(a)
spend_at_risk(a)  = monthly_spend(a) · inherent_risk(a) / 100  USD a month; the account ranking sorts by this
```

The report gives **two headline scores**, because they answer different questions:

| Score | f(S) | Question it answers |
|---|---|---|
| **By spend** (default weighting) | S | "How much of our business is hard to move?" A small account full of proprietary services adds little. |
| **By number of accounts** | 1 | "How many of our workloads are hard to move?" One very large account cannot dominate. |
| Blend (optional) | √S | A compromise between the two; selectable, not a headline. |

**Why both.** Spend weighting keeps the original rule — a $2k/month account built entirely on
DynamoDB (inherent risk 95) appears in red on the account chart but adds 0.3 points — yet it lets a
single large account set the whole score: a contact centre on Amazon Connect at 20% of the bill moves
it by ten points on its own. Any single compromise weighting (such as √S) fixes the second problem by
weakening the first. Showing both, side by side, keeps each honest:

- spend score well **above** account score → risk is concentrated in a few large accounts;
- account score well **above** spend score → risk is spread across many smaller accounts;
- similar → risk is spread in line with spend.

The weighting selector (console *Score weighting*, CLI `--weighting spend|equal|balanced`) only chooses
which view drives the per-account weights, contributions and bubble sizes; both headline scores are
always reported.

**Breadth view.** Alongside the scores, the report counts accounts per rating and sets the share of
accounts against the share of spend (section 3). *Portable* accounts are those rated Low or Moderate;
*higher-risk* accounts are High or Critical. "10 of 145 accounts are High/Critical but hold 25% of
spend" is a concentration to manage, not an estate-wide problem — and the chart makes that visible.

Ratings: Low < 25 ≤ Moderate < 40 ≤ Elevated < 55 ≤ High < 70 ≤ Critical. An estate entirely on tier-1
services scores 10; entirely on tier-2, 30.

**Spend is a proxy for size.** Where the deep scan ran, the resource counts are shown per account and
feed the estimate (below), but they do not change the score — the score stays a pure, auditable
function of the bill.

**Bespoke services.** "Bespoke (AWS-only) services" counts distinct High or Critical (tier 4–5) services
with at least $1/month of in-scope spend: the services with no direct equivalent outside AWS.

**Spend growth.** Change in amortised monthly spend from the first to the last complete month scanned,
overall, for High/Critical services, and per catalog category ("product type"). With 6+ months an
annualised rate, (last/first)^(12/(months−1)) − 1, is also shown; shorter windows show the change only,
because annualising two or three months magnifies noise.

## 4. Exit estimate

### Inputs from the questionnaire

Until someone answers (or confirms) these questions, the estimate runs on defaults and describes a
made-up organisation. The report then marks cost, exit window and effort **Provisional**, keeps them out
of the bottom line, and makes "answer the delivery questions" the first recommendation. Changing any
answer in section 5, or pressing *These answers are right*, makes the figures the organisation's own;
on the command line, `--questionnaire answers.json` does the same.

| Question | Options → delivery factor |
|---|---|
| Standard CI/CD pipeline used to create assets? | One standard 0.85 · Several, partially standard 1.0 · Mostly manual 1.3 |
| Terraform used, and current? | Terraform current 0.8 · Terraform with drift 1.1 · CloudFormation/CDK 1.25 · Little or none 1.5 |
| Target platform | Azure 1.0 · Google Cloud 1.0 · Oracle Cloud 1.1 · Sovereign/local cloud 1.2 · On-premises 1.35 |
| Regulated entity | Yes 1.15 (exit-plan evidence, regulator notification, assurance testing) · No 1.0 |
| Core cloud team size, % allocated; application engineer FTE | Capacity, not effort |
| Blended day rate, currency, FX per USD, contingency %, parallel-run months, materiality | Cost |

Why these questions: infrastructure-as-code that matches production lets the platform be re-created
on the target by changing providers and modules rather than reverse-engineering consoles; a standard
pipeline means one deployment pattern to retarget instead of dozens. CloudFormation/CDK estates score
worse than "Terraform with drift" because the IaC itself must be rewritten.

### Effort (engineer-weeks)

```
service effort   = catalog effort_weeks × size multiplier            for every service ≥ materiality, per account
size multiplier  = clamp( max( √(monthly spend / 1,000 USD), √(resource count / typical count) ), 0.25, 8 )
account overhead = 1 week per account with material spend           (network, IAM, decommissioning)
delivery         = (Σ service effort + account overhead) × CI/CD × IaC × target × regulated
landing zone     = (clamp(4 + 12 × √(monthly spend / 100,000), 4, 24) + 0.5 × accounts) × target
programme mgmt   = 12% × (delivery + landing zone)
contingency      = contingency% × (delivery + landing zone + programme mgmt)
```

The square-root size multiplier encodes economies of scale: four times the spend is roughly twice the
work, because the design, tooling and testing approach are reused. Typical counts used with the deep
scan include 25 Lambda functions, 10 DynamoDB tables, 10 state machines and 30 CloudFormation stacks
per "typical workload" (`TYPICAL_COUNTS` in `estimate.py`).

### Duration

```
capacity (FTE)   = cloud team × allocation% + application engineers
effort-bound     = total effort / (capacity × 80% productive)
critical path    = {tier 5: 26, 4: 16, 3: 10, 2: 8, 1: 6} weeks for the hardest tier present + landing zone / 2
calendar         = max(effort-bound, critical path) + 4 weeks decommissioning
```

Adding people shortens the programme only until the critical path binds; the report says which one
constrains it. Waves are sequenced easiest first (tiers 1–2, then 3, then 4–5) so the team builds the
target platform and its patterns on low-risk workloads.

### Cost

```
labour        = total effort × 5 days × day rate
parallel run  = parallel-run months × monthly AWS spend × 50% × FX       (target ramps up as AWS ramps down)
total         = labour + parallel run;   range −25% / +50%;   duration range −20% / +40%
% of annual   = total / (monthly AWS spend × 12 × FX)                    one-off exit cost vs a year of the bill
```

**The report quotes ranges, never single figures.** Cost, effort and duration are shown as the
range above, widened outward to round numbers (e.g. "$7m–$16m", "2.5–5 years", "300–700
person-months"). The model's single figures are planning midpoints and appear only in the JSON
output; an early-stage estimate quoted to the nearest $100k would claim precision it does not have.

The calendar duration is reported as the **exit window**: how long it would take to leave AWS.

The asymmetric ranges reflect that early estimates of migrations are far more often under than over.

## 5. Limitations

- **Spend understates small-but-complex services.** A $300/month Step Functions estate can orchestrate
  the whole bank. Run the deep scan for resource counts, and read the account drill-down, not only the score.
- **One RDS line.** Cost Explorer reports RDS and Aurora together. Aurora-specific features (Global
  Database, Babelfish, Serverless v2 scaling) and commercial engines (Oracle, SQL Server licensing) are
  visible in the deep scan's engine breakdown.
- **Not in the estimate:** target-cloud run cost after exit; licence changes; early termination of AWS
  commitments (EDP, Savings Plans, RIs — let them run off); data-transfer-out fees (since March 2024 AWS
  credits egress for customers leaving AWS, on request to AWS Support and subject to approval; the move
  must complete within about 60 days, so a multi-year exit pays egress outside that window); organisational change.
- **Catalog tiers are expert judgement.** They are published, versioned and open to challenge through
  pull requests; quote the catalog version with any score.
- **Indicative only.** The estimate is an order-of-magnitude figure to support an executive decision and
  a regulatory exit plan. A delivery commitment needs workload-level discovery.

## 6. Reproducibility

Each scan is stored as JSON (`~/.exitrisk/scans/<id>.json`) with the raw Cost Explorer lines, accounts,
inventory and issues. `exitrisk report <id> --include prod --questionnaire answers.json` regenerates
the full report deterministically; the report footer carries the tool version, catalog version and scan id.

## Multi-region

The cost of a second region (run, build, staff, region choice, failover risks) has its own model: see
[MULTI_REGION.md](MULTI_REGION.md).
