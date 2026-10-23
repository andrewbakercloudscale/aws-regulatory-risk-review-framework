# Methodology

This document defines exactly how the report's numbers are produced, so that a reviewer, an auditor
or a regulator can reproduce them from the scan file. Every coefficient lives in code in one place
(`src/exitrisk/scoring.py`, `src/exitrisk/estimate.py`, `src/exitrisk/data/service_catalog.yaml`) and
is printed on the report's assumptions list.

## 1. Data collected

| Source | API | What | Where it runs |
|---|---|---|---|
| AWS Organizations | `ListRoots`, `ListOrganizationalUnitsForParent`, `ListAccountsForParent`, `DescribeOrganization` | OU tree; accounts under the chosen OU, recursively; account name, status, OU path | Management account |
| AWS Organizations (optional) | `ListTagsForResource` | Account tags, for business criticality and channel (resilience view) | Management account |
| Cost Explorer (optional) | `GetCostAndUsage` | `UsageQuantity` in GB-months for the last complete month, by `LINKED_ACCOUNT` × `USAGE_TYPE`, for each storage service in use: data held (resilience view) | Management account |
| Cost Explorer | `GetCostAndUsage` | **Amortised** cost, monthly, grouped by `LINKED_ACCOUNT` × `SERVICE`, for the last *N* complete months | Management account |
| Deep scan (optional) | List/describe calls in every enabled region | Counts of Lambda functions, DynamoDB tables, state machines, Kinesis streams, SQS queues, SNS topics, EventBridge rules, API Gateway APIs, Cognito user pools, Glue jobs, Redshift clusters, CloudFormation stacks, EKS/ECS clusters, RDS instances by engine | Each member account via `ExitRiskReadOnly` |

Cost Explorer filters:

- `RECORD_TYPE` excludes `Credit`, `Refund`, `Tax`, `Support`; the score reflects the cost of running
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
inherent_risk(a)  = Σ_i s(a,i) · t(i) / Σ_i s(a,i)          0 to 100, how hard this account is to move
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

**Why both.** Spend weighting keeps the original rule: a $2k/month account built entirely on
DynamoDB (inherent risk 95) appears in red on the account chart but adds 0.3 points, yet it lets a
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
accounts against the share of spend (section 4). *Portable* accounts are those rated Low or Moderate;
*higher-risk* accounts are High or Critical. "10 of 145 accounts are High/Critical but hold 25% of
spend" is a concentration to manage, not an estate-wide problem, and the chart makes that visible.

Ratings: Low < 25 ≤ Moderate < 40 ≤ Elevated < 55 ≤ High < 70 ≤ Critical. An estate entirely on tier-1
services scores 10; entirely on tier-2, 30.

**Spend is a proxy for size.** Where the deep scan ran, the resource counts are shown per account and
feed the estimate (below), but they do not change the score; the score stays a pure, auditable
function of the bill.

**Bespoke services.** "AWS-only services" counts distinct High or Critical (tier 4 to 5) services
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
answer under Exit model, or pressing *These answers are right*, makes the figures the organisation's own;
on the command line, `--questionnaire answers.json` does the same.

| Question | Options → delivery factor |
|---|---|
| Standard CI/CD pipeline used to create assets? | One standard 0.85 · Several, partially standard 1.0 · Mostly manual 1.3 |
| Terraform used, and current? | Terraform current 0.8 · Terraform with drift 1.1 · CloudFormation/CDK 1.25 · Little or none 1.5 |
| Target platform | Azure 1.0 · Google Cloud 1.0 · Oracle Cloud 1.1 · Sovereign/local cloud 1.2 · On-premises platform you already run 1.35 · Physical data centre 1.5 |
| Physical data centre only: where the hardware goes, and a second site for DR? | Existing space · Colocation · Build new; DR site yes/no → lead time and one-off hardware and facility cost (below) |
| Regulated entity | Yes 1.15 (exit-plan evidence, regulator notification, assurance testing) · No 1.0 |
| Core cloud team size, % allocated; application engineer FTE | Capacity, not effort |
| Blended day rate, currency, FX per USD, contingency %, parallel-run months, materiality | Cost |

Why these questions: infrastructure-as-code that matches production lets the platform be re-created
on the target by changing providers and modules rather than reverse-engineering consoles; a standard
pipeline means one deployment pattern to retarget instead of dozens. CloudFormation/CDK estates score
worse than "Terraform with drift" because the IaC itself must be rewritten.

### Effort (engineer-weeks)

```
service effort   = catalog effort_weeks × size multiplier × AI agent factor × tool factor   for every service ≥ materiality, per account
size multiplier  = clamp( √(monthly spend / 1,000 USD), 0.25, 8 )
  or, in a material deep-scanned account, for every service the inventory counted (whatever it costs):
service effort   = Σ resources (days per resource × complexity × repeat discount) ÷ 5 × AI agent factor × tool factor
integrations     = Σ integrations (days per integration × repeat discount) ÷ 5   (dependency scan)
account overhead = 1 week per account with material spend           (network, IAM, decommissioning)
data migration   = 0.04 weeks per TB moved + 1 week per account holding ≥ 1 TB   (change-data capture,
                   validation, reconciliation; TB = live + archived storage from Cost Explorer)
delivery         = (Σ service effort + account overhead + data migration) × CI/CD × IaC × target × regulated
landing zone     = (clamp(4 + 12 × √(monthly spend / 100,000), 4, 24) + 0.5 × accounts) × target
programme mgmt   = 12% × (delivery + landing zone)
contingency      = contingency% × (delivery + landing zone + programme mgmt)
```

The square-root size multiplier encodes economies of scale: four times the spend is roughly twice the
work, because the design, tooling and testing approach are reused. Where the deep scan reached an
account, spend no longer sizes the work: see [Effort from resources](#effort-from-resources-and-integrations).

**AI coding agents.** When the Exit model says teams use AI coding agents, each service's weeks are
multiplied by its catalog `agentic` rating: high 0.5 (code and templates an agent can translate:
Lambda, API Gateway, Step Functions, CloudFormation, CI/CD), medium 0.75 (config and integration
rewrites: EKS manifests, networking, AI services), low 0.9 (mostly rehosting or re-pointing: EC2, RDS,
S3, DynamoDB redesign with its data move), none 1.0 (data moves, hardware, contracts: EFS, Glacier,
Direct Connect, Marketplace). The factor applies before the delivery factor, so engineers reviewing
and testing the agents' changes are still counted. It shortens the work, not the lock-in: the score
does not change. The rating per service is in [SERVICE_CATALOG.md](SERVICE_CATALOG.md).

**Migration tools.** When the Exit model says migration tools will be used, each service's weeks are
also multiplied by its catalog `tooling` rating, on the same scale: high 0.5 where replication or import
tools do the move (servers with Azure Migrate or Migrate to Virtual Machines, databases with native
replication or a Database Migration Service, object storage with AzCopy or Storage Transfer Service,
Kafka with MirrorMaker 2, DNS zone import), medium 0.75 where they carry part of it (DynamoDB export and
streams, OpenAPI import for API Gateway), low 0.9. Integration redesign gets no tool factor. Agents and
tools overlap, so together they never cut a service below 30% of its work. The report names the tools
for the chosen target for the services with the most work (section 4, Tools that shorten the move), and
the Agentic Risk Review is asked to name the ones that fit.

**Developer-portal templates.** When services are built from templates (golden paths, for example
Backstage), the templates are changed once for the target and re-run: the repeat discount on resources
and integrations drops from 35% to 15% of the work for each one after the first 20 of a type.

**The move into AWS.** The Exit model asks how long the move into AWS took and with how many people.
It does not change the estimate: the report shows the exit beside it ("about 7 times that") as a sense
check. An exit is usually bigger than the move in, because it carries everything built on AWS since.

**Products left out.** **Exclusions** in the top bar can leave named AWS products out (for example Marketplace
software re-contracted anyway, or a service being retired). Their spend is removed from the score,
the tiers, the estimate and the trend, and the report says what was left out and how much it spends
a month at the top of the report.

### Duration

```
capacity (FTE)   = cloud team × allocation% + application engineers
effort-bound     = total effort / (capacity × 80% productive) + 12 weeks × 50%   (team ramp-up)
service path     = {tier 5: 26, 4: 16, 3: 10, 2: 8, 1: 6} weeks for the hardest tier present + landing zone / 2
                   + data-centre lead time (physical data centre only)
data path        = 12 weeks to order links + bulk copy (TB on 2 × 10 Gbps at 80%) + 8 weeks final sync and cutover
calendar         = max(effort-bound, service path, data path) + 4 weeks decommissioning
```

Adding people shortens the programme only until the critical path binds; the report says which one
constrains it. Waves are sequenced easiest first (tiers 1 to 2, then 3, then 4 to 5) so the team builds the
target platform and its patterns on low-risk workloads.

### Cost

```
labour        = total effort × 5 days × day rate
parallel run  = parallel-run months × monthly AWS spend × 50% × FX       (target ramps up as AWS ramps down)
platform      = 2% × monthly AWS spend × FX × months from end of mobilisation to end of exit
                (target landing zone, network, security tooling and connectivity running during the exit)
total         = labour + parallel run + platform + hardware + facility
% of annual   = total / (monthly AWS spend × 12 × FX)                    one-off exit cost vs a year of the bill
```

#### Exit to a physical data centre

Leaving AWS for your own data centre is a different programme from moving to another cloud: every
managed service AWS ran (databases, queues, load balancers, identity, backup) becomes software and
hardware you buy, rack and operate, and nothing can move until the facility and hardware exist.

```
delivery factor  = 1.5 for the target                       (vs 1.35 for an on-premises platform you already run)
lead time        = existing space 16 · colocation 26 · build new 104 weeks   on the critical path, before wave 1
hardware         = 9 months of the AWS bill × FX × (1.6 with a DR site, else 1.0)
facility         = existing 0 · colocation 2 · build new 12 months of the AWS bill per site × FX
```

Hardware is sized from the bill because it is the only capacity signal the scan has; AWS prices include
the managed-service premium, so treat it as an order of magnitude and replace it with a sizing exercise.
Running the data centre after exit (power, cooling, facility and hardware staff, maintenance contracts,
refresh every 4 to 6 years) is not in the one-off cost.

**The range narrows as the evidence improves.**

| Scan depth | Cost and effort | Duration |
|---|---|---|
| Quick (billing only) | −30% / +70% | −20% / +50% |
| Inventory (resource counts) | −25% / +50% | −20% / +40% |
| Dependency (resources and integrations) | −20% / +35% | −15% / +30% |

Commitments written off (Savings Plans, reservations, EDP shortfall) stay a separate figure beside the
exit cost, under Timing, so they are never counted twice.

**The report quotes ranges, never single figures.** Cost, effort and duration are shown as the
range above, widened outward to round numbers (e.g. "$7m to $16m", "2.5 to 5 years", "300 to 700
person-months"; effort switches to person-years once the low end is two years or more, e.g. "35 to 90
person-years"). The model's single figures are planning midpoints and appear only in the JSON
output; an early-stage estimate quoted to the nearest $100k would claim precision it does not have.

The calendar duration is reported as the **exit window**: how long it would take to leave AWS.

The asymmetric ranges reflect that early estimates of migrations are far more often under than over.

### Effort from resources and integrations

Spend measures **financial exposure**: concentration, commitments and the economics of an exit. It does
not measure how hard an exit is. A $20 Lambda function wired to four queues is more work to move than a
$10,000 EC2 instance, and the report should say so. In every material account the deep scan reached,
each service the inventory counted is sized from its resources instead of its spend
(`resource_effort.py`):

| Resource | Engineer-days each | Resource | Engineer-days each |
|---|---|---|---|
| EC2 instance | 0.5 | SQS queue, SNS topic, S3 bucket | 0.5 |
| Lambda function | 2 | EventBridge rule, CloudFormation stack | 1 |
| DynamoDB table | 6 | API Gateway REST / HTTP API | 3 / 2 |
| Step Functions state machine | 4 | Glue job, Kinesis stream | 3 |
| ECS cluster, ECS service | 2 | EKS cluster | 10 |
| RDS instance: open-source / commercial / Aurora | 3 / 5 / 6 | Cognito user pool | 15 |
| Redshift cluster | 20 | | |

- **Complexity**: Lambda functions on a custom runtime ×1.5, on an end-of-support runtime ×1.3, packaged
  as containers ×0.7. RDS by engine family, as in the table.
- **Repeat discount**: after the first 20 of a type in an account, each further one counts 35% (templated,
  scripted work), or 15% when services are built from developer-portal templates.
- **CloudFormation stacks** are counted but carry no effort of their own: a stack packages resources
  already counted, and rewriting templates is the infrastructure-as-code factor.
- **The landing-zone baseline is left out.** AWS Control Tower, Amazon Inspector and AWS Security
  Incident Response put the same rules, topics, functions and stacks into every account and region
  (names starting `aws-controltower-`, `AWSControlTower`, `StackSet-AWSControlTower`,
  `DO-NOT-DELETE-AmazonInspector`, or rules marked `ManagedBy` an AWS service). They are counted apart
  (`baseline_*`) and carry no effort, and integrations into AWS-run security and governance services
  (Inspector, Security Incident Response, Control Tower, GuardDuty, Security Hub, Config, Auto Scaling)
  are not counted: the target platform's own landing zone replaces them.
- **Integrations** (Dependency scan only): 1 engineer-day per AWS-specific integration (0.25 for e-mail
  and SMS subscriptions, 0.5 for HTTP and mobile targets), with the same repeat discount. Each integration
  is its own line, rated by the harder end (SQS to Lambda is High; DynamoDB streams to Lambda is
  Critical), so no work is counted twice.
- Services the inventory cannot count (S3 data, CloudFront, Connect...), accounts it did not reach, and
  accounts under the materiality cut-off stay sized from spend. The report shows the share of effort on
  each basis.

These coefficients are uncalibrated planning assumptions: calibrate them against your own completed
migrations. Delivery factors, programme management and contingency then apply exactly as above.

### Measures, dimensions and scan depth

The spend-weighted score stays as the measure of **exposure**. Beside it, section 1 reports exit
difficulty on its own terms:

- **Technical portability** (0 to 100, higher is easier) = 100 − the tier score weighted by engineering
  effort instead of spend. Its difficulty rating uses the same bands as the exit-risk score.
- **Exit effort** in engineer-days, and the **exit window**, from the estimate.
- **Five dimensions**, each shown on its own so none hides another: service portability, dependency
  complexity (integrations counted), data gravity (TB to move, from Cost Explorer storage usage),
  engineering effort (and how much of it rests on counted resources, integrations or spend) and
  operational criticality (critical accounts, from tags or your list: a business judgement, not inferred).
- **Critical-account readiness**: each critical account judged alone. Ready: portability 60 or more and
  no Critical (tier 5) service with work to do. Hard to move: portability under 40, or a Critical service
  to replace.

**Scan depth** decides what the figures rest on and caps confidence:

| Depth | Reads | Confidence |
|---|---|---|
| Quick scan | Billing and accounts (management account only) | Effort sized from spend |
| Inventory scan | Plus resource counts in each member account | At most Medium |
| Dependency scan | Plus the integrations between services | Can be High |

The dependency scan reads Lambda event source mappings, EventBridge rule targets, SNS subscriptions,
API Gateway integrations and Step Functions task states, and stores only counts per kind of edge
("SQS to Lambda: 12"), never names, ARNs or definitions. It cannot see SDK calls made inside code,
S3 event notifications, Lambda resource-policy triggers or network traffic. **Missing evidence is not
evidence of independence**: an account with no integrations found is unmeasured on that dimension, not
free of them. Large accounts are capped (300 EventBridge rules, 100 REST and 100 HTTP APIs, 200 state
machines per region); a capped count is reported as a floor.

**Selective deep scan**: "Only material accounts" deep-scans the accounts that make up 95% of spend plus
any spending $100 a month or more on High or Critical services; the rest stay sized from spend.
"Only regions with spend" reads, in each account, only the regions billing $1 a month or more (an account
under that keeps its busiest region; one with no regional spend is read everywhere). Workloads are counted
the same; resources in regions that cost nothing yet are not. It is on by default in the console (most
accounts bill in 3 or 4 regions); untick it, or leave out `--spend-regions` on the command line, to read
every enabled region.

## 5. Limitations

- **Spend understates small-but-complex services.** A $300/month Step Functions estate can orchestrate
  the whole bank. The spend score is exposure, not difficulty: run a Dependency scan so effort and
  technical portability come from resources and integrations, and read critical-account readiness.
- **One RDS line.** Cost Explorer reports RDS and Aurora together. Aurora-specific features (Global
  Database, Babelfish, Serverless v2 scaling) and commercial engines (Oracle, SQL Server licensing) are
  visible in the deep scan's engine breakdown.
- **Not in the estimate:** target-cloud run cost after exit; licence changes; early termination of AWS
  commitments (EDP, Savings Plans, RIs; let them run off); the cost of copying the data out (Direct
  Connect ports and data-out fees, sized under Resilience and shown beside the one-off cost; since March
  2024 AWS credits internet egress, not Direct Connect, for customers leaving AWS, on request to AWS Support
  and subject to approval, for a move completed within about 60 days); organisational change.
- **Materiality is per account.** A service under the materiality cut-off in an account is scored but
  adds no effort for that account, even if it runs in many accounts.
- **Catalog tiers are expert judgement.** They are published, versioned and open to challenge through
  pull requests; quote the catalog version with any score.
- **Indicative only.** The estimate is an order-of-magnitude figure to support an executive decision and
  a regulatory exit plan. A delivery commitment needs workload-level discovery.

## 6. Reproducibility

Each scan is stored as JSON (`~/.exitrisk/scans/<id>.json`) with the raw Cost Explorer lines, accounts,
inventory and issues. `exitrisk report <id> --include prod --questionnaire answers.json` regenerates
the full report deterministically; the report footer carries the tool version, catalog version and scan id.

## Timing (report section 6)

The estimate gives an exit window; this part asks whether the window fits, and what AWS is still owed
when it closes. None of it changes the score or the estimate.

**Deadline.** A notice period typed under Exit model (`exit_deadline_months`; 0 means none), measured from
today. *Fits* when even the slow end of the duration range finishes inside it, *At risk* when only the
fast end does, *Does not fit* when neither does.

**Savings Plans and reservations.** Read from Cost Explorer for the last complete month
(`GetSavingsPlansUtilizationDetails`, and `GetReservationUtilization` grouped by subscription for EC2,
RDS, ElastiCache, Redshift, OpenSearch and MemoryDB), with each commitment's end date and amortised
monthly cost, so upfront fees are already spread over the term. Commitments are bought in one account
and shared, so they cover the whole organisation, not just the filtered accounts. *Still to run* is
the monthly cost times the months left. *Written off* is the part still owed after the exit finishes,
paid for but no longer used: from the slow end (least) to the fast end (most). A planned exit that
outlasts every commitment writes off nothing; leaving in a hurry would owe everything still to run,
which is shown instead. The total, with any enterprise discount shortfall, is a key figure in the
executive summary. A chart shows each month's commitments to the last end date, with the exit window
shaded, and a line of what would be written off if the exit finished at the end of each month (the sum
of everything billed after it). The view also gives the last date a new 1-year or 3-year term can start
and still end before the fastest exit.

**Enterprise discount (EDP or PPA).** No AWS API exposes it, so its end month and annual commitment are
typed under Exit model. The shortfall is the commitment from the exit finishing to the agreement's end:
spend stops when the exit finishes. Savings Plan and reservation fees keep being billed after the exit
and count towards the commitment, so the shortfall is only the part of each month they do not cover;
the same dollars are never counted twice. Real agreements often allow the shortfall to roll forward or be
renegotiated; treat the figure as the opening position for that discussion.

## Resilience (report section 7)

The exit score answers how hard a *planned* exit is. Section 7 answers the regulator's harder
questions: what one failure would take down, and what could move under stress. None of it changes
the score or the estimate.

**Which accounts are critical.** An account is critical when a tag says so, or when its name contains
one of the patterns typed in section 7 (`critical_accounts` in the answers file). Tag keys are matched
ignoring case, spaces, dashes and underscores: `Criticality`, `BusinessCriticality`, `Tier`,
`ServiceTier`, `WorkloadTier`, `Critical`. Values that mark an account critical: Tier 1 / T1 / 1,
Tier 0, Critical, Mission critical, Business critical, CIF, Critical or important, P1, High, Gold,
Platinum, True, Yes. A `Channel` (or `BusinessChannel`, `CustomerChannel`) tag names the customer
channel the account serves. When no account is critical, every figure below covers all in-scope
accounts and says so.

**Correlated failure.** The share of critical spend in its dominant region, from Cost Explorer spend
by region (global services excluded and shown separately). 90% or more is *High*, 70% to 90%
*Elevated*, below that *Moderate*. Each channel's dominant region is shown; two or more channels with
the same dominant region have no anti-affinity: one regional event takes them all down together, and
a card rail with stand-in processing gains nothing from it if the mobile app fails with it.

**Stressed exit.** Critical spend split by how fast it could move if AWS stopped serving you with
little notice: tiers 1 to 2 in weeks (rehost as is), tier 3 in months (rework), tiers 4 to 5 not at
all without a pre-built fallback, a manual workaround or a stand-in process. Critical accounts with a
quarter or more of their spend on tiers 4 to 5 are listed.

**Data held.** Cost Explorer bills storage in GB-months, so the usage quantity of a storage line is the
average data held over the month; nothing is read from the data itself. Lines are classed as copies
(snapshots, backups, point-in-time recovery, Multi-AZ mirrors, AWS Backup), archives (Glacier tiers)
or live data; early-deletion fees are dropped. Live data and archives must move; copies are rebuilt at
the target. Egress to the internet at list price is $0.05 to $0.15 per GB; AWS credits it for
customers leaving AWS, on approval, for a move completed within 60 days, so the view says what internet
capacity that window would need. The region of each line comes
from its usage-type prefix (`EUW2-` London, `AFS1-` Cape Town, no prefix us-east-1). DynamoDB's
largest account is sized against the 1 TB per import job limit outside us-east-1, us-west-2 and
eu-west-1.

**Links for the migration.** Direct Connect ports in use today are counted from Cost Explorer
port-hours for the last complete month (`<region>-<location>-PortUsage:10G`, hosted `HCPortUsage`,
flat-rate `FlatRatePortUsage`; a `-Pair` line is two ports): hours divided by the hours in the month.
Those links carry production and are left alone. The copy gets new dedicated 10 Gbps links, in three
options: Cheap (1 link), Medium (2) and Urgent (4). Time assumes half the line rate is usable. Cost is
AWS list price from `data/direct_connect.json` (refreshed by `scripts/refresh_direct_connect.py` from
AWS's public Direct Connect price list): port-hours for the copy plus one month to commission, test
and run the final sync, and data out per GB from each region holding data to a Direct Connect location
in the country of the primary region (where today's links are, or else the region with most spend).
Data out is the same for every option. Your carrier's circuit and cross-connect are added only when
entered under Exit model. The view also notes the cheapest flat-rate port (no per-GB charge) in the
region, as something to ask AWS about; it is not used in the figures.

## Multi-region

The cost of a second region (run, build, staff, region choice, failover risks) has its own model: see
[MULTI_REGION.md](MULTI_REGION.md).
