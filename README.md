# AWS Regulatory Risk Review Framework

**How hard would it be to leave AWS?** This tool answers that for an entire AWS Organizational
Unit, in a form an executive committee can act on: one exit-risk score, weighted by where the money
is actually spent, the services and accounts that drive it, and an indicative cost and time to exit.

Regulators increasingly expect a credible, tested exit plan for material cloud outsourcing
(EU DORA Art. 28, EBA outsourcing guidelines, PRA SS2/21, APRA CPS 230, SARB Directive 3/2018 among
others). This framework gives that plan an evidence base drawn from your own billing data rather
than a workshop opinion.

![Dashboard overview](docs/images/dashboard-overview.png)

## What it does

- **Scores every account** by the spend-weighted exit difficulty of the AWS services it uses.
  EKS, EC2 and Postgres/Aurora score low; DynamoDB, Lambda, Step Functions, Redshift and Connect score
  high. 112 services are classified in an open, reviewable [catalog](docs/SERVICE_CATALOG.md).
- **Two headline scores: by spend and by number of accounts.** Weighted by spend, a small account full
  of proprietary services is flagged without distorting the number; counted per account, one very
  large account (e.g. a contact centre on Connect) cannot set the whole picture. The gap between the
  two tells you whether risk is concentrated or widespread.
- **Counts portable vs higher-risk accounts**: how many accounts sit in each rating, against the share
  of spend they hold.
- **Filters to production** (or anything else) by account name: contains / starts with / ends with /
  regex, plus exclusions, e.g. `prod, prd` excluding `sandbox`.
- **Estimates the exit**: engineer effort, calendar duration and cost, adjusted by a questionnaire on
  the page — standard CI/CD? Terraform up to date? How big is the core cloud team?
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

No AWS access yet? **Load demo data** shows a synthetic 21-account bank.

**What your AWS administrator grants** (read-only, in the management account): an IAM Identity Center
permission set with [this inline policy](iam/management-account-policy.json) — or the AWS-managed
`AWSOrganizationsReadOnlyAccess` + `AWSBillingReadOnlyAccess` — ready-made in
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
exitrisk scan --profile mgmt --ou ou-ab12-cdef3456 --months 3          # spend-only scan
exitrisk scan --profile mgmt --inventory --role ExitRiskReadOnly        # plus resource counts
exitrisk pdf <scan-id> --include prod --out board-pack.pdf              # PDF without a browser
exitrisk report <scan-id> --include prod --questionnaire answers.json   # JSON for other tools
exitrisk catalog                                                        # list service tiers
```

## Screenshots

| | |
|---|---|
| ![Executive summary](docs/images/executive-summary.png) **Executive summary** — score, KPIs, key messages | ![Risk profile](docs/images/risk-profile.png) **Risk profile** — spend by tier and trend |
| ![Accounts](docs/images/accounts.png) **Accounts** — risk vs spend; ranking by weighted contribution | ![Services](docs/images/services.png) **Services** — what drives lock-in |
| ![Estimate](docs/images/estimate.png) **Exit estimate** — questionnaire, timeline, effort | ![Issues](docs/images/issues.png) **Data quality** — what the report does not cover |
| ![Appendix](docs/images/appendix-catalog.png) **Appendix** — tier, rationale, migration path, duration | ![Dark mode](docs/images/dashboard-dark.png) **Dark mode** |
| ![Getting started](docs/images/getting-started.png) **Getting started** — connect, check access, scan | ![Check access](docs/images/access-check.png) **Check access** — ✓/✗ per permission and the request for your AWS admin |
| ![AWS sign-in](docs/images/sso-sign-in.png) **AWS sign-in** — SSO / Identity Center from the header | ![New scan](docs/images/new-scan-dialog.png) **New scan** — profile, OU, deep scan |

A complete sample report generated from the demo data: [docs/sample-report.pdf](docs/sample-report.pdf).

## How the score works

| Tier | Label | Score | Example services |
|---|---|---|---|
| 1 | Portable | 10 | EC2, EKS, EFS, ElastiCache, MSK, OpenSearch, Route 53 |
| 2 | Low | 30 | S3, RDS/Aurora, ECS, DocumentDB, KMS, CloudFront |
| 3 | Moderate | 50 | SQS, SNS, API Gateway, Athena, SageMaker, Bedrock |
| 4 | High | 75 | Lambda, Redshift, Glue, Kinesis, Step Functions, EventBridge, Cognito |
| 5 | Critical | 95 | DynamoDB, Connect, Greengrass, SWF, QLDB |

- **Inherent risk** of an account = spend-weighted mean of its services' scores (0–100).
- **Weight** = the account's share of in-scope spend (or 1/N when counting by number of accounts).
- **Contribution** = inherent risk × weight.
- **OU exit-risk score** = sum of contributions, reported both **by spend** and **by number of accounts**.
- Ratings: Low < 25 ≤ Moderate < 40 ≤ Elevated < 55 ≤ High < 70 ≤ Critical.

Full detail, including the estimate model and its limitations: [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Documentation

| Document | For |
|---|---|
| [METHODOLOGY.md](docs/METHODOLOGY.md) | Scoring, weighting and estimate formulas; assumptions; limitations |
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
