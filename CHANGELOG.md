# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [semantic versioning](https://semver.org/). The service catalog carries its own
`version` (YYYY.MM) because tier changes alter scores: quote both versions when comparing reports.

## [Unreleased]

### Added
- **One-page ExCo summary**: score, headline, six tiles, tier bar, top three findings and decisions,
  and the five accounts that drive the exit on one A4 page. **One-page PDF** button, or
  `exitrisk pdf <scan-id> --onepage` (warns if long names push it to a second page). Sample in
  `docs/sample-summary.pdf`.

### Changed
- Ranges read "$7m to $16m" and "2.5 to 5.5 years"; no dashes in report text or docs.
- Phone layout: no sideways scroll at 390px; wide tables scroll inside their card.

### Fixed
- Commitments: term and end date are read from other Cost Explorer attributes (lease term, purchase
  term, start date plus term) when the usual ones are missing. Undated commitments are counted and
  shown in Timing instead of being dropped silently.

## [0.5.0] - 2026-10-20

### Added
- **Timing** (report section 5): the exit window against a regulator or board notice period you enter
  (Fits, At risk, Does not fit), and the AWS commitments still running.
  - **Savings Plans and reservations** from Cost Explorer: amortised monthly cost, end date, what is
    still to run, run-off by quarter, and what would be stranded after the exit finishes. The last date
    a new 1-year or 3-year term can start and still end inside the exit window.
  - **Enterprise discount (EDP)**: end month and annual commitment typed on the page; the shortfall if
    the agreement outlasts the exit.
  - Findings for a missed deadline and for commitments still owed, and an action to keep new terms
    inside the exit window. The demo scan carries Savings Plans and reservations.
- IAM: `ce:GetSavingsPlansUtilizationDetails` and `ce:GetReservationUtilization` (read only; a refusal
  is a warning on the report, not a failed scan).

### Fixed
- The console no longer blanks a select (e.g. the data-centre facility) when a saved answer is one the
  page does not offer, which made the report fail with a validation error.

## [0.4.0] - 2026-10-20

### Added
- **Resilience view** (report section 6; data quality moves to section 7). It measures the risks the
  exit score does not: correlated failure and a stressed exit.
  - **Critical accounts** from account tags (`Criticality`, `Tier`, `BusinessCriticality`... with values
    such as Tier 1, Critical, Mission critical) or name patterns typed in section 6. Critical accounts
    carry a badge in the account ranking. A `Channel` tag names the customer channel.
  - **Correlated failure**: share of critical spend in its dominant region (High at 90% or more), each
    channel's region, and channels that share a region (no anti-affinity).
  - **Stressed exit**: critical spend that could move in weeks (tiers 1 to 2), months (tier 3) or not
    without a pre-built fallback (tiers 4 to 5), and the critical accounts stuck on AWS-only services.
  - **Data held**: terabytes of live data, archives and copies by service, account and region, from
    Cost Explorer storage usage; the time to move it at your link speed, whether it fits AWS's 60-day
    free data transfer out window for leaving AWS, list-price egress otherwise, and DynamoDB against the
    1 TB per import job limit outside the three large regions.
  - One finding (correlated failure) and one action (tag critical accounts, or pre-build a stressed-exit
    fallback) in the executive summary.
- Scans read account tags (`organizations:ListTagsForResource`, added to the policy, permission set and
  access check) and storage usage (`ce:GetCostAndUsage`, already granted). Both are optional: a refusal
  is a warning and the scan completes.
- Answers file: `critical_accounts` (comma-separated name patterns) and `transfer_gbps` (default 10).

## [0.3.5] - 2026-10-20

### Added
- Multi-region: DynamoDB's failover note now names the second region's import from S3 quota (15 TB at a
  time in us-east-1, us-west-2 and eu-west-1, 1 TB elsewhere) and the 10 TB a day replica backfill quota.
  Region-specific notes are a new `quota` field under `risks` in `regions.yaml` (version 2026.10.3).

## [0.3.4] - 2026-10-20

### Added
- **Physical data centre as an exit target** (`datacenter`; `exitrisk scan --target datacenter`). It asks
  where the hardware goes (existing space, colocation or a new build) and whether to buy a second site for
  disaster recovery. The estimate adds the facility lead time to the critical path (16, 26 or 104 weeks
  before the first workload lands), one-off hardware (9 months of the AWS bill, +60% for a DR site) and
  facility cost (0, 2 or 12 months of the bill per site), and a 1.5 delivery factor because every managed
  service becomes something you run. The timeline, cost split, executive summary and assumptions name the
  hardware; running the data centre after exit is listed as excluded. Method in METHODOLOGY.md.

### Changed
- "On-premises" is now "On-premises platform you already run (Kubernetes / VMs)" to separate it from
  building a data centre; its factor (1.35) is unchanged.

## [0.3.3] - 2026-10-20

### Catalog 2026.10.3 (120 services)
- Added AWS Elastic Disaster Recovery (Low), AWS Fault Injection Simulator / Service (Low), AWS Payment
  Cryptography (High: key ceremonies and scheme sign-off) and AWS CloudShell (Portable). They were
  previously scored as unclassified (Moderate) and had no multi-region profile.
- Lifecycle facts: Amazon Pinpoint engagement features reach end of support on 30 October 2026 (SMS, voice
  and push continue as AWS End User Messaging); AWS App Mesh support ended on 30 September 2026; CodeCommit
  reopened to new customers in November 2025.

### Multi-region
- Region data 2026.10.2: the four new services have regional availability and class; Elastic Disaster
  Recovery and Payment Cryptography have specific failover notes. Region availability refreshed (107
  services).

### Added
- `exitrisk scan --target azure|gcp|oci|sovereign|onprem` sets the exit target from the command line, as
  the console's New scan dialog does.

### Changed
- Internal: `build_report` and the executive summary split into small, named steps (aggregation, accounts,
  ratings, tiers, services; headline, context, findings, exit, actions, confidence). Output is identical
  on 144 scenarios (demo and live scans, filters, questionnaires, weightings).
- New CLI tests (bad answers files, unknown scan, report JSON, scan target) and catalog lifecycle tests.

## [0.3.2] - 2026-10-20

Exit analysis review ahead of wider circulation.

### Fixed
- AWS spend in the executive summary (named bespoke services, "N others", biggest monthly rises) is always
  quoted in USD; it was labelled with the labour currency when that was not USD.
- Ratings follow the score as displayed (whole number, rounded half up), so a 39.5 can no longer show as
  "Moderate · 40".
- Single-account and no-High/Critical wording: "1 of 1 account is portable", no "The 0 High or Critical
  accounts hold 0%", no "across 1 accounts".
- The headline no longer says "most workloads would move with modest change" when the exit costs half a
  year's AWS spend or more.
- An empty scope has no cost/time ranges (they were "$0–$0" internally).
- Egress: the exclusion now states AWS's conditions (request to AWS Support, approval, move completed
  within about 60 days) instead of an unconditional waiver.
- README: 116 classified services (not 120); APRA CPS 230 and SARB citations corrected (PA Directive
  3/2018 and Guidance Note G5/2018).

### Improved
- The dashboard catches rendering errors: a clear message and toast instead of a half-drawn report; PDF
  export fails with that message instead of hanging.
- CLI: unreadable or invalid `--questionnaire` / `--multiregion` files, unknown scan ids, a report server
  that does not start, and a PDF page that does not finish loading all give one clear line and exit code,
  not a traceback.
- Logging: failed access checks are logged; unexpected (non-AWS) errors in access checks, SSO and OU-tree
  calls are logged with their traceback; unreadable scan files are logged instead of skipped silently.
- Executive summary and narrative share one "accounts that set the pace" helper.

## [0.3.1] - 2026-10-20

### Added
- Multi-region data notes: the view says (and logs once per scan) what it had to assume: no
  spend-by-region data, unknown primary region, regions this version does not know, services with
  no multi-region profile, an unusable second region, an old AWS regional services list.
- A failed multi-region calculation shows an error panel with the request id, **Try again** and
  **Open the log**, instead of a blank tab and a toast. PDF export exits non-zero with the reason
  when the report cannot be built, instead of waiting 30 seconds.
- Check access confirms spend by region is readable (same call, no extra cost).
- One structured log line per multi-region calculation; unexpected errors reading spend by region
  are logged with a traceback.
- Browser tests for the multi-region tab (choices, account selection, error panel and retry), run in CI.

### Fixed
- Spend in a region missing from the region table could silently make US East the primary region.

### Changed
- The multi-region model is split into small, tested steps (no change to any figure: verified
  against the previous version on 20 scenarios).

## [0.3.0] - 2026-10-20

### Added
- **Multi-region view** (new tab): what a second AWS region would cost to run (infrastructure,
  replication traffic, AWS Support uplift, extra staff), cost and time to achieve, and which region
  to use (service parity, latency, price, data residency). Choose **Recover within 3 hours**
  (systemic risk event) or **On demand: instant**; pick the accounts (sorted by spend); each
  account lists its services' multi-region risks (e.g. EC2: manual failover). Figures are ranges and
  provisional until the answers are confirmed. See docs/MULTI_REGION.md.
- Scans collect spend by region (Cost Explorer `REGION` grouping; no new permission).
- `data/regions.yaml` (regions, service classes, failover notes) and `data/region_services.json`
  (AWS regional services list; refresh with `scripts/refresh_region_services.py`).
- CLI: `exitrisk report|pdf --view multiregion --multiregion answers.json`; API `POST /api/multiregion`.
- Sample multi-region PDF and screenshots.

### Changed
- **Exit cost, effort and time are quoted as approximate ranges, never single figures** (e.g.
  "$7m–$16m", "2.5–5 years", "300–700 person-months"), rounded outward, everywhere: key figures,
  bottom line, findings, section 5 and the PDF. JSON keeps the midpoints and adds `estimate.ranges`.

### Fixed
- The bottom line could say 38/100 while the score tile said 39/100 (38.5 rounded two ways); both
  now round half up.

### Documentation
- README explains why regulated entities need this: Regulatory Risk as the proposed seventh pillar of
  the AWS Well-Architected Framework, and the exit-plan rules it supports (DORA, EBA, PRA, APRA, SARB).

## [0.2.4] - 2026-10-20

### Added
- **Scan several OUs at once.** The scan dialog's OU list is now a tick-box tree (nesting indented,
  account count per OU); ticking a parent covers its children; nothing ticked scans the whole
  organisation. CLI: `exitrisk scan --ou ou-a,ou-b`. Accounts are counted once.

### Fixed
- Nested OUs looked like top-level ones in the old drop-down (macOS ignores the indent), so a nested
  `prod` OU with 2 accounts was easy to pick instead of the top-level `Prod` OU.
- Static files are revalidated on every load, so an upgraded console never runs stale JavaScript.
- A scan lost because the console restarted mid-scan now says so instead of "scan not found".

### Changed
- Demo estate (made-up numbers): 40 production accounts including a long tail of small workloads,
  12 months of history, Marketplace products and third-party Bedrock models; screenshots, sample PDF
  and the exco guide figures regenerated from it.

## [0.2.3] - 2026-10-20

### Changed
- **Account ranking sorts by criticality: spend × risk** ("spend at risk", USD a month), so large,
  hard-to-move accounts come first. The column replaces "Contribution"; the "accounts set the pace"
  finding uses the same measure.
- **"Accounts listed" filter** (scope bar; `exitrisk pdf --min-rating Moderate|High`): hide Low-risk
  accounts, or show High & Critical only, in the account ranking. Display only: scores, charts and totals
  still count every account.
- Account table: Risk, Rating and High/Critical % merge into one Risk column (rating · score, with the
  High/Critical share beneath).

## [0.2.2] - 2026-10-20

### Added
- **Specifics behind the numbers.** The bespoke-services finding names each of the largest services with
  its annual spend and account count; the growth finding names the biggest rises. Growth by product type
  names the service (or product) behind each bar, and the table lists the services in each type. The
  High & Critical services table gains a Change column.
- **Third-party products.** Scans keep the Marketplace product name instead of one "Marketplace" line; a
  new table lists them. Third-party models on Bedrock (billed via Marketplace as "... (Amazon Bedrock
  Edition)") now score as Bedrock (AI/ML, tier 3), not as Marketplace. Re-scan to see product names.

### Changed
- Catalog 2026.10.2: Marketplace moves from "Business apps" to its own "Third-party software" category.

## [0.2.1] - 2026-10-20

### Changed
- **Report formatting overhaul.** Executive summary rebuilt: a one-sentence bottom line, a lighter context
  line with both scores, an exit-facts strip, and findings and recommendations that each lead with a bold
  phrase. Months read "Oct 2025", ranges use one unit ("6.3–10.9 years"), money uses `$`, plurals are
  real ("1 account", not "account(s)"). Tier donut sits beside its table; growth chart and table line up;
  account ranking shows the top 15 (button for all; top 25 in the PDF) on one line per account; bubble
  labels no longer overlap; effort is in person-months everywhere; the timeline axis reads in years or
  months without collisions; catalog columns are balanced. PDF: key figures stay with the summary, and the
  appendix no longer leaves a blank page.
- Methodology appendix describes both headline scores.

### Fixed
- **Cost and time no longer headline the report while they rest on default answers.** Until the delivery
  questions are answered or confirmed, the figures are marked *Provisional*, the bottom line says they are
  not yet estimated, and an "Answer the questions" button jumps to section 5. JSON: `estimate.provisional`,
  `summary.executive.provisional`; questionnaire field `confirmed`. `exitrisk pdf` now takes
  `--questionnaire` too.

## [0.2.0] - 2026-10-20

### Changed
- **Two headline scores: exit risk by spend and by number of accounts**, side by side with a one-line
  reading of the gap (concentrated vs widespread). Spend stays the default weighting for contributions;
  per-account and a √spend blend are selectable (console *Score weighting*, CLI `--weighting`).

### Added
- **Spend growth by product type** (section 2): first-to-last-month change per catalog category, with the
  share of each on High/Critical services, total vs lock-in growth ("is lock-in growing faster than the
  estate?"), and an annual rate when 6+ months are scanned. Also in the JSON as `growth`.
- **Exit target asked when starting a scan** ("Where would you exit to?"); stored with the scan and used
  for its estimate. New scans default to 12 months of history so growth is meaningful.
- Key figures: **High/Critical accounts (N of M)**, **Bespoke (AWS-only) services** in use, **Spend growth**,
  exit cost as **% of annual AWS spend**, and duration relabelled **Exit window (time to leave AWS)** in years.
- **Written executive summary at the start of the report**: a bottom-line verdict, what we found, what
  leaving would take, numbered recommendations and a confidence rating with its reasons (default
  questionnaire answers, spend-only scan, partial coverage, demo data). Also in the JSON as
  `summary.executive`. Replaces the "Key messages" list.
- Breadth view: accounts per rating vs share of spend (section 3), "Portable accounts X of N" KPI tile and
  a key message counting portable vs High/Critical accounts.

### Fixed
- **OU picker with a member-account profile**: the scan dialog now preselects the profile that last read
  the OU tree (else one named like *mgmt/management/payer*), and when OUs are denied it explains why and
  links the local profile that is in the management account.
- **Check access** offers a one-click switch to the local profile in the management account when the
  selected one is a member account (profiles map to accounts via `sso_account_id`).
- **OU list was slow and looked flat**: the tree is read level by level in parallel, cached per profile
  for 15 minutes (↻ refreshes; a passing access check warms it), shows a loading state, and nested OUs
  are indented under their parent.

### Fixed
- Billing lines of one service (e.g. Connect, Contact Lens, Connect telephony) are merged per account: they no
  longer repeat in the lock-in column or multiply that service's migration effort.

### Added
- **AWS sign-in (IAM Identity Center / SSO) in the console header**: add a portal by start URL (region
  auto-detected), approve on AWS's page, pick account and role, and scan. Tokens are written to the AWS
  CLI's SSO cache in its own format; profiles are added to `~/.aws/config` only on request.
- **Getting started** first screen (connect → check access → scan) and a **Check access** dialog that
  makes each read-only call a scan needs, shows the fix for each failure, and writes the request for
  the AWS administrator (copy or download).
- IAM Identity Center permission set in Terraform and CloudFormation (`iam/identity-center/`).
- Install with `uv tool install` / `pipx install` from GitHub.
- Report banner explaining partial views (member-account fallback) and filters that match no account.

### Changed
- New scan: OUs load automatically and sit with the account-name filter under **What to include**.
- Tier table shows how many accounts use each tier (≥ $1/month).
- With no spend in scope the estimate shows "–" instead of a fixed landing-zone figure.
- Catalog 2026.10.1: Amazon Connect billing lines (Contact Lens, Customer Profiles, Contact Center
  Telecommunications) map to Connect; new entries for AppFlow, Service Catalog, IAM Access Analyzer and
  WorkSpaces Applications (AppStream); aliases for third-party fee lines and `CodeBuild`.

## [0.1.0] - 2026-10-20

### Added
- Web console (`exitrisk serve`) with executive summary, tier profile, spend-weighted account ranking,
  service lock-in view, exit cost and time estimate, data-quality panel and two appendices.
- Organisation questionnaire on the dashboard (CI/CD maturity, Terraform state, cloud team size,
  application engineers, target platform, day rate, FX, contingency, parallel run, regulated entity).
- Scanner: AWS Organizations OU tree, Cost Explorer amortised spend by account x service x month,
  optional deep scan of resource counts through a read-only member-account role.
- Account-name filter (contains / starts with / ends with / regex, plus exclusions).
- PDF export: browser print layout and scripted `exitrisk pdf` (headless Chromium).
- Service catalog of 112 AWS services (catalog version 2026.10) with tier, rationale, migration path,
  Azure / Google Cloud / cloud-neutral equivalents and typical duration.
- Structured JSON-lines logging with per-scan run ids and secret redaction; every AWS error becomes an
  issue on the report with a remediation hint.
- Synthetic demo organisation, IAM policies, CloudFormation StackSet and Terraform for the member role,
  CI (lint, tests, catalog doc freshness).
