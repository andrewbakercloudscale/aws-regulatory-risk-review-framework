# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [semantic versioning](https://semver.org/). The service catalog carries its own
`version` (YYYY.MM) because tier changes alter scores: quote both versions when comparing reports.

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
