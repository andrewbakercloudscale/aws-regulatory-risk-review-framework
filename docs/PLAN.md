# Project plan

## Goal

Give an executive committee a defensible, repeatable answer to "how hard would it be to leave AWS?"
for a whole Organizational Unit — a single spend-weighted exit-risk score, the accounts and services
that drive it, an indicative cost and time to exit, and a board-ready PDF — as an open-source tool
any AWS customer can run in an afternoon.

## Requirements and how they are met

| Requirement | Delivered by |
|---|---|
| Difficulty / risk score for an entire OU | `scoring.py`: spend-weighted OU score from Organizations + Cost Explorer |
| Rank AWS-only services by portability (EKS/Postgres low; Lambda/Redshift high) | 112-service catalog, 5 tiers, rationale per service |
| Account score weighted by spend / size | Inherent risk × weight = contribution; bubble chart and ranking |
| Filter by name prefix / substring (production only) | Filter bar: contains / starts with / ends with / regex + exclusions |
| Graphs and charts | Tier donut, tier trend, risk-vs-spend bubble chart, top services, effort, timeline |
| Exportable to PDF | Print stylesheet + `exitrisk pdf` (headless Chromium) |
| Appendix: which service is which risk, why, migration path, duration | Appendix A (generated from the catalog) + docs/SERVICE_CATALOG.md |
| Cost and time estimate, informed by CI/CD, Terraform, team size | Questionnaire on the dashboard drives `estimate.py` |
| Top quality: log issues and information, catch and log errors | Issue model on every failure, JSON logs with run ids, data-quality section, tests |
| Works with aws-cli-zsp keys | Standard boto3 profiles (`credential_process`); one Touch ID per scan |
| Open source, documented, screenshots | Apache 2.0, docs/, generated screenshots and sample PDF, CI |

## Delivery phases

| Phase | Scope | Status |
|---|---|---|
| 1. Foundations | Catalog schema and first 112 services; scoring; filter; tests | Done (v0.1.0) |
| 2. Collection | Organizations, Cost Explorer, deep-scan inventory; error model; logging | Done (v0.1.0) |
| 3. Console | Dashboard, questionnaire, scan dialog, log viewer, dark mode | Done (v0.1.0) |
| 4. Reporting | Print/PDF layout, appendix, methodology, narrative | Done (v0.1.0) |
| 5. Open-source launch | Docs, screenshots, IAM templates, CI, contribution process | Done locally; GitHub publication pending owner approval |
| 6. Hardening with real estates | Calibrate effort coefficients against completed migrations; catalog review by practitioners | Next |

## Roadmap (candidate issues)

1. **Calibrate the estimate** against two or three real exit or migration programmes; publish the
   calibration data set (anonymised).
2. **CUR 2.0 / Data Exports input** as an alternative to Cost Explorer for organisations that already
   land cost data in Athena — adds usage-type detail (e.g. Aurora vs RDS PostgreSQL, Lambda@Edge).
3. **Per-account drill-down page** with service list, inventory by region and recommended first moves.
4. **Scenario comparison** — save questionnaire answers as named scenarios and show them side by side.
5. **Trend across scans** — compare this quarter's scan with last quarter's for the risk-appetite KPI.
6. **Policy-as-code guardrail** — emit an SCP / Config rule pack flagging new tier-5 adoption.
7. **Target-specific estimates** — vary per-service effort by destination (e.g. Kinesis → Event Hubs Kafka API is cheaper than → Pub/Sub).
8. **Multi-payer support** — combine scans from several organisations into one report.
9. **Container image and GitHub Action** to run the spend-only scan on a schedule and publish the PDF.
10. **Localisation of currency and regulatory references** (DORA, PRA, APRA, SARB, MAS) in the report text.

## Effort to build (for reference)

Version 0.1.0 represents roughly 4–6 engineer-weeks of work for a senior cloud engineer with an
architect reviewing the catalog. Ongoing: about 1 day a quarter to review new AWS services into the
catalog, and 1–2 days per scan cycle to run, review and present the report.
