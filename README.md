# AWS Regulatory Risk Review Framework

**How hard would it be to leave AWS?** This tool answers that for an entire AWS Organizational
Unit, in a form an executive committee can act on: one exit-risk score, weighted by where the money
is actually spent, the services and accounts that drive it, and an indicative cost and time to exit.

> **Risk without transparency is just fear and anxiety.** Every bank board has heard "we are locked
> into AWS". Few can say by how much, where, or what it would cost to get out. This framework turns
> that worry into a number, a ranked list and a plan.

## Why this exists: Regulatory Risk, the missing pillar

The [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/) has six
pillars: Operational Excellence, Security, Reliability, Performance Efficiency, Cost Optimization and
Sustainability. They describe a workload that runs well **on AWS**. None of them asks the question a
regulator asks first: **could you leave if you had to?**

For regulated entities (banks, insurers, payment providers, market infrastructure, healthcare) that
question is not optional. Running material workloads in the cloud is outsourcing, and outsourcing
rules require a documented, credible and tested exit strategy:

| Regulation | What it expects |
|---|---|
| EU [**DORA**](https://eur-lex.europa.eu/eli/reg/2022/2554/oj) (Art. 28) | Exit strategies for ICT third-party services supporting critical or important functions, tested and documented |
| [**EBA** Guidelines on outsourcing](https://www.eba.europa.eu/sites/default/files/document_library/875331/EBA%20GL%202019%2002%20-%20CT%20GLs%20on%20outsourcing%20arrangements_0.pdf) (EBA/GL/2019/02) | Documented exit plans, with an assessment of how complex and costly exit would be |
| UK [**PRA SS2/21**](https://www.bankofengland.co.uk/prudential-regulation/publication/2021/march/outsourcing-and-third-party-risk-management-ss) | Stressed exit plans for material outsourcing, including alternative providers and timelines |
| [**APRA CPS 230**](https://www.apra.gov.au/operational-risk-management) | Exit plans for material service providers, so critical operations continue if the provider fails or the arrangement ends |
| **SARB Prudential Authority** [Directive 3/2018](https://www.resbank.co.za/en/home/publications/publication-detail-pages/prudential-authority/pa-deposit-takers/banks-directives/2018/8749) and [Guidance Note G5/2018](https://www.resbank.co.za/en/home/publications/publication-detail-pages/prudential-authority/pa-deposit-takers/banks-guidance-notes/2018/8747) (cloud computing and offshoring of data) | Exit and contingency arrangements for material cloud usage |

This framework proposes **Regulatory Risk as the seventh pillar**: the measured degree to which your
architecture keeps you free to exit, change providers, or bring workloads back in house. Like the
other pillars, it is a design property you can measure, track and improve:

- **Measure** it: a spend-weighted 0 to 100 exit-risk score per OU and per account, from your own billing
  data, against an open [catalog](docs/SERVICE_CATALOG.md) of 120 AWS services ranked by portability.
- **Explain** it: which services (Connect, Redshift, DynamoDB, Lambda…) and which accounts drive the
  score, why each service is hard to move, the migration path, and how long it typically takes.
- **Plan** it: indicative effort, duration and cost of a full exit, adjusted for your delivery maturity
  (CI/CD, Terraform, team size), ready for the exit plan your regulator asks to see.
- **Track** it: rescan each quarter, so new lock-in shows up as it is adopted, not when the exit is
  needed. Choosing a proprietary service can still be the right call; this makes it a known,
  priced choice rather than an accident.

The aim is not to discourage AWS. It is to replace "we are locked in" (fear) with "38/100, with three accounts holding 57% of the spend at risk and roughly 2.5 to 5 years to
exit" (a fact a board can govern).

![Dashboard overview](docs/images/dashboard-overview.png)

## What it does

- **Scores every account** by the spend-weighted exit difficulty of the AWS services it uses.
  EKS, EC2 and Postgres/Aurora score low; DynamoDB, Lambda, Step Functions, Redshift and Connect score
  high. 120 services are classified in an open, reviewable [catalog](docs/SERVICE_CATALOG.md).
- **Two headline scores: by spend and by number of accounts.** Weighted by spend, a small account full
  of proprietary services is flagged without distorting the number; counted per account, one very
  large account (e.g. a contact centre on Connect) cannot set the whole picture. The gap between the
  two tells you whether risk is concentrated or widespread.
- **Counts portable vs higher-risk accounts**: how many accounts sit in each rating, against the share
  of spend they hold.
- **Filters to production** (or anything else) by account name: contains / starts with / ends with /
  regex, plus exclusions, e.g. `prod, prd` excluding `sandbox`.
- **Estimates the exit**: engineer effort, calendar duration and cost, adjusted by a questionnaire on
  the page: standard CI/CD? Terraform up to date? How big is the core cloud team?
- **Costs a second region** (Multi-region tab): extra cost to run, cost and time to achieve, extra
  staff, the recommended second region (service parity, latency, price), for a 3-hour recovery or
  instant failover, for the accounts you pick, with each account's failover risks (e.g. EC2 needs
  manual failover). See [MULTI_REGION.md](docs/MULTI_REGION.md).
- **Times the exit** (section 5): whether it fits a regulator or board notice period you enter, which
  Savings Plans and reservations run off before it finishes and what would still be owed, the last
  date a 3-year term stays inside the window, and any EDP shortfall.
- **Tests resilience** (section 6): which accounts are critical (from account tags such as
  `Criticality = Tier1`, or names you give), how much of the critical estate one regional event would
  take down, whether tier 1 channels are isolated from each other (anti-affinity), what could move in
  weeks under a stressed exit, and how many terabytes an exit has to move and how long that takes.
- **Exports a board-ready PDF** with charts, an executive narrative, a data-quality section, and an
  appendix explaining every service's tier, recommended migration path and typical duration.
- **Never fails silently**: every AWS API error becomes an issue on the report with a fix, and is
  written to a structured log.

Everything is read-only. The core score needs only Organizations and Cost Explorer read access in the
management (payer) account; the optional deep scan counts resources through a list-only role.

## Quick start

**1. Install** (Python 3.10+; one command, no virtual environment to manage):

```bash
uv tool install git+https://github.com/andrewbakercloudscale/aws-regulatory-risk-review-framework
# or: pipx install git+https://github.com/andrewbakercloudscale/aws-regulatory-risk-review-framework
exitrisk serve              # opens http://127.0.0.1:8740
```

**2. Follow the three steps on the first screen:**

| Step | What happens |
|---|---|
| **Connect to AWS** | **AWS sign-in** for SSO / IAM Identity Center (paste your portal's start URL once), or any AWS CLI profile already on the machine, including aws-cli-zsp. Use the **management (payer) account**. |
| **Check access** | Tests the five read-only calls a scan needs and shows ✓ / ✗ with the fix for each. If anything is missing it writes the **request to send your AWS administrator**: your identity, the account, the policy, ready to copy or download. |
| **Scan and report** | Seconds for hundreds of accounts. Type `prod` in the filter bar, answer the questionnaire in section 5, **Export PDF**. |

No AWS access yet? **Load demo data** shows a synthetic bank estate (49 accounts, made-up numbers).

**What your AWS administrator grants** (read-only, in the management account): an IAM Identity Center
permission set with [this inline policy](iam/management-account-policy.json), or the AWS-managed
`AWSOrganizationsReadOnlyAccess` + `AWSBillingReadOnlyAccess`, ready-made in
[Terraform](iam/identity-center/terraform/main.tf) and [CloudFormation](iam/identity-center/cloudformation/permission-set.yaml).
Details: [docs/IAM_PERMISSIONS.md](docs/IAM_PERMISSIONS.md).

For development: `git clone …`, `python3 -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'`.
Scripted PDFs need `pip install '.[pdf]'` and `playwright install chromium`.

### Credentials, including aws-cli-zsp

The scanner uses standard AWS profiles from `~/.aws/config`, so anything boto3 supports works: SSO,
`credential_process`, assumed roles. With [aws-cli-zsp](https://github.com/andrewbakercloudscale/aws-cli-zsp)
the first API call of a scan triggers one Touch ID approval and the resulting 1-hour session is reused
for the whole scan. The tool never reads, stores or logs keys.

**AWS SSO (IAM Identity Center), no terminal needed.** Click **AWS sign-in** in the console header, add
your access portal's start URL once (its region is found automatically), and approve the sign-in on
AWS's own page. The console lists every account you can reach, preselects the organization's
management account, and **Use for a new scan** creates (or reuses) a matching SSO profile in
`~/.aws/config`. The token goes to the AWS CLI's own cache, so `aws` and `exitrisk scan --profile …`
share the sign-in; it is never sent to the browser.

### Command line

```bash
exitrisk scan --profile mgmt --ou ou-ab12-cdef3456 --months 3          # spend-only scan (--ou a,b for several OUs)
exitrisk scan --profile mgmt --inventory --role ExitRiskReadOnly        # plus resource counts
exitrisk scan --profile mgmt --target gcp                               # exit target: azure (default), gcp, oci, sovereign, onprem, datacenter
exitrisk pdf <scan-id> --include prod --questionnaire answers.json --out board-pack.pdf  # PDF without a browser
exitrisk pdf <scan-id> --include prod --onepage                      # one-page ExCo summary
exitrisk report <scan-id> --include prod --questionnaire answers.json   # JSON for other tools
exitrisk catalog                                                        # list service tiers
```

## Screenshots

**Executive summary**: Bottom line, findings, exit cost and time as ranges, recommendations, confidence; then scores and key figures.

![Executive summary](docs/images/executive-summary.png)

**Risk profile**: Spend by tier and its trend, and which product types are growing.

![Risk profile](docs/images/risk-profile.png)

**Accounts**: How many accounts are portable vs higher risk; risk vs spend; ranking by spend at risk (spend × risk).

![Accounts](docs/images/accounts.png)

**Services**: The AWS-only services that drive lock-in.

![Services](docs/images/services.png)

**Exit estimate**: Your answers (CI/CD, Terraform, team size), the exit timeline and where the effort goes.

![Exit estimate](docs/images/estimate.png)

**Timing**: The exit window against your notice period, Savings Plans and reservations running off, and the EDP.

![Timing](docs/images/timing.png)

**Resilience**: Critical accounts, correlated failure by region and channel, a stressed exit and the data to move.

![Resilience](docs/images/resilience.png)

**Data quality**: What the report does not cover, and why.

![Data quality](docs/images/issues.png)

**Appendix**: Each service's tier, rationale, migration path and typical duration.

![Appendix](docs/images/appendix-catalog.png)

**Multi-region**: The cost of a second region: run, build, people, and where to put it.

![Multi-region summary](docs/images/multiregion-summary.png)

**Multi-region accounts**: Sorted by spend; choose which go multi-region; each service's failover risk.

![Multi-region accounts](docs/images/multiregion-accounts.png)

**Second region**: Candidates ranked by service parity, latency and price.

![Second region](docs/images/multiregion-region.png)

**Getting started**: Connect, check access, scan.

![Getting started](docs/images/getting-started.png)

**Check access**: ✓/✗ per permission, and the request to send your AWS administrator.

![Check access](docs/images/access-check.png)

**AWS sign-in**: SSO / IAM Identity Center from the header.

![AWS sign-in](docs/images/sso-sign-in.png)

**New scan**: Profile, one or more OUs, deep scan.

![New scan](docs/images/new-scan-dialog.png)

**One-page ExCo summary**: score, headline, six tiles, tier bar, top findings and decisions, and the
accounts that drive the exit, on one A4 page. **One-page PDF** in the header, or `exitrisk pdf --onepage`.

![One-page summary](docs/images/one-page-summary.png)

**Dark mode**

![Dark mode](docs/images/dashboard-dark.png)

Complete sample reports generated from the demo data: [exit risk](docs/sample-report.pdf),
[one-page summary](docs/sample-summary.pdf), [multi-region](docs/sample-multiregion.pdf).

## How the score works

| Tier | Label | Score | Example services |
|---|---|---|---|
| 1 | Portable | 10 | EC2, EKS, EFS, ElastiCache, MSK, OpenSearch, Route 53 |
| 2 | Low | 30 | S3, RDS/Aurora, ECS, DocumentDB, KMS, CloudFront |
| 3 | Moderate | 50 | SQS, SNS, API Gateway, Athena, SageMaker, Bedrock |
| 4 | High | 75 | Lambda, Redshift, Glue, Kinesis, Step Functions, EventBridge, Cognito |
| 5 | Critical | 95 | DynamoDB, Connect, Greengrass, SWF, QLDB |

- **Inherent risk** of an account = spend-weighted mean of its services' scores (0 to 100).
- **Weight** = the account's share of in-scope spend (or 1/N when counting by number of accounts).
- **Contribution** = inherent risk × weight.
- **OU exit-risk score** = sum of contributions, reported both **by spend** and **by number of accounts**.
- **Spend at risk** = monthly spend × risk / 100. The account ranking sorts by it, so large, hard-to-move accounts come first.
- Ratings: Low < 25 ≤ Moderate < 40 ≤ Elevated < 55 ≤ High < 70 ≤ Critical.

Full detail, including the estimate model and its limitations: [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Documentation

| Document | For |
|---|---|
| [METHODOLOGY.md](docs/METHODOLOGY.md) | Scoring, weighting and estimate formulas; assumptions; limitations |
| [MULTI_REGION.md](docs/MULTI_REGION.md) | The multi-region view: run and build cost, staff, region choice, failover risks |
| [SERVICE_CATALOG.md](docs/SERVICE_CATALOG.md) | Every service's tier, rationale, migration path, equivalents, duration |
| [IAM_PERMISSIONS.md](docs/IAM_PERMISSIONS.md) | Exact permissions; StackSet / Terraform for the member role |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flow, security model, logging and error handling |
| [OPERATIONS.md](docs/OPERATIONS.md) | Running scans, logs, troubleshooting every known error |
| [EXCO_GUIDE.md](docs/EXCO_GUIDE.md) | How to read and present the report to an executive committee |
| [PLAN.md](docs/PLAN.md) | Project plan, delivery phases and roadmap |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Changing the catalog, development setup, tests |
| [SECURITY.md](SECURITY.md) | Threat model and how to report a vulnerability |

## Contributing

The catalog is the heart of the project and the easiest place to help: a new service, a better
migration path, or a challenge to a tier. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Apache 2.0. The estimate is an order-of-magnitude planning figure for an executive decision, not a
delivery quote. AWS is a trademark of Amazon.com, Inc.; this project is not affiliated with or endorsed by AWS.
