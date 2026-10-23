# Architecture

A single Python process serves a local web console and runs scans in background threads. There is no
database and no cloud deployment: scans are JSON files in a private directory on the analyst's machine.

```
 Browser (dashboard, print/PDF)                                 AWS
 ┌──────────────────────────────┐                   ┌──────────────────────────────┐
 │ index.html · app.js · Chart.js│   JSON over HTTP  │ Management (payer) account    │
 │ questionnaire · filter bar   │◀────────────────▶ │  Organizations (read)         │
 └──────────────────────────────┘   127.0.0.1:8740   │  Cost Explorer (read)         │
              │                                     └──────────────┬───────────────┘
 ┌────────────▼─────────────────────────────────┐   sts:AssumeRole │ (deep scan only)
 │ exitrisk (FastAPI + uvicorn)                  │                  ▼
 │  server.py   API, host/CSRF guard, headers    │   ┌──────────────────────────────┐
 │  scanner.py  scan jobs, progress, issues      │──▶│ Member accounts               │
 │  collectors/ organizations · cost · inventory │
 │              · dependencies (integrations)    │
 │  resource_effort  effort from resources       │
 │  dimensions  measures, dimensions, readiness  │   │  ExitRiskReadOnly (list-only) │
 │  scoring.py  report: scores, ranking, trend   │   └──────────────────────────────┘
 │  estimate.py questionnaire → effort/cost/time │
 │  resilience  criticality · data · stress test │
 │  catalog.py  service_catalog.yaml             │
 │  store.py    ~/.exitrisk/scans/<id>.json      │
 │  logging     ~/.exitrisk/logs/exitrisk.log    │
 └───────────────────────────────────────────────┘
```

## Design decisions

| Decision | Reason |
|---|---|
| Score computed from Cost Explorer in the payer account | One read-only permission set covers every account; no agent or role needed for the headline number |
| Scan once, report many times | The raw lines are stored; filters and questionnaire answers re-compute the report instantly (`POST /api/report`) without touching AWS again |
| Catalog in YAML, not code | Reviewable by architects and risk teams who do not write Python; versioned separately because tier changes move scores |
| Local web app, not a SaaS | The data (every account name and its spend) is sensitive; it never leaves the analyst's machine |
| Vanilla JS + vendored Chart.js | No build step, no CDN at runtime (works offline and behind proxies), strict CSP possible |
| Print stylesheet for PDF | The PDF is the same page the analyst checked on screen; `exitrisk pdf` renders it headlessly for automation |

## Request flow

1. `POST /api/scans` validates parameters and starts a `ScanJob` thread; the browser polls
   `GET /api/scans/{id}/status` once a second for phase, percent and message.
2. The job authenticates (`sts:GetCallerIdentity`, where aws-cli-zsp asks for Touch ID), reads the OU
   tree and accounts, queries Cost Explorer, optionally inventories member accounts in parallel, and
   saves the scan atomically (`tempfile` + `os.replace`, mode 0600).
3. `POST /api/report {scan_id, filter, questionnaire}` loads the scan and builds the report: scores,
   rankings, trend, estimate, narrative and issues. The browser renders charts and tables from it.

## Error handling and logging

The rule is **degrade, never die silently**:

| Failure | Behaviour |
|---|---|
| Bad/expired credentials, cancelled Touch ID | Scan fails fast with a *critical* issue and a hint ("re-run; aws-cli-zsp will prompt") |
| Organizations refused / not in use | *Warning*; scan continues for the calling account only |
| Cost Explorer fails | Scan fails (*critical*): without spend there is no score |
| Cannot assume the member role | *Error* for that account; its spend is still scored |
| One API in one region fails or is throttled | *Warning* for that call; the rest of the inventory continues |
| Service not in the catalog | *Warning* on the report; scored as tier 3 |
| Unhandled exception anywhere | Logged with traceback; the scan document is still saved with what was collected and status `failed` |

Throttling is absorbed by botocore's adaptive retry mode (10 attempts). Every issue has severity,
category, account, region, AWS error code, message and a remediation hint, and is stored with the scan
and shown in report section 8.

Logs go to the console (human) and `~/.exitrisk/logs/exitrisk.log` (JSON lines, rotated at 5 MB × 5).
Each record carries the scan's `run_id`, so `jq 'select(.run_id=="<id>")'` extracts one scan; the console's
**Settings → Application log** shows the same view. A redaction filter strips anything shaped like an AWS secret or
access key id before it is written; the code never logs credentials in the first place.

## Security model

- Binds to `127.0.0.1` by default; binding elsewhere logs a warning because the console acts with your AWS identity.
- Requests whose `Host` is not a loopback name are refused (DNS-rebinding defence).
- State-changing requests need an `X-ExitRisk: 1` header, which a foreign web page cannot send without
  a CORS preflight that is never granted (CSRF defence).
- Strict Content-Security-Policy (`script-src 'self'`, `frame-ancestors 'none'`); every API value is
  HTML-escaped in the client because account names and AWS error messages are not trusted markup.
- Scan ids are validated against a fixed pattern before being used in a file path.
- The data directory is created `0700` and scan files `0600`.

See [SECURITY.md](../SECURITY.md) for the threat model.
