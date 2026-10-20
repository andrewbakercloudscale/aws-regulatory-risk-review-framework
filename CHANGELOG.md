# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [semantic versioning](https://semver.org/). The service catalog carries its own
`version` (YYYY.MM) because tier changes alter scores: quote both versions when comparing reports.

## [Unreleased]

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
