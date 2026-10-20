# Operations and troubleshooting

## Running a scan

1. `exitrisk serve` and open http://127.0.0.1:8740.
2. **New scan** → choose the profile for the management account → **Load OUs** (first AWS call; with
   aws-cli-zsp, approve Touch ID) → pick an OU or leave the root → months of history (3 is a good
   default; 6–12 shows trend) → optionally tick **Deep scan** and give the member role name.
3. Watch the progress bar. A spend-only scan of a few hundred accounts takes seconds; a deep scan takes
   roughly 2–5 seconds per account per enabled region, in parallel (`EXITRISK_MAX_WORKERS`, default 8).
4. Filter to production in the bar at the top, answer the questionnaire in section 5, check section 6,
   and **Export PDF** (browser print → Save as PDF) or `exitrisk pdf <scan-id> --include prod`.

Scans are kept until deleted (`DELETE /api/scans/<id>` or remove the file). Re-scan quarterly to show
whether lock-in is growing; the trend chart covers the months in each scan.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `EXITRISK_DATA_DIR` | `~/.exitrisk` | Scans (`scans/`) and logs (`logs/`) |
| `EXITRISK_LOG_LEVEL` | `INFO` | `DEBUG` adds per-call detail |
| `EXITRISK_MAX_WORKERS` | `8` | Parallel accounts in a deep scan; lower it if throttled |
| `AWS_PROFILE`, `AWS_CONFIG_FILE` | standard | Honoured by boto3 as usual |

## Logs

- Console: one human-readable line per event, prefixed with the scan id.
- File: `~/.exitrisk/logs/exitrisk.log`, JSON lines, rotated at 5 MB, five generations kept.
- In the UI: **Log** (top right) shows recent records, filtered to the current scan by default.

```bash
jq -r 'select(.run_id=="20261020-131932-c34f") | "\(.ts) \(.level) \(.msg)"' ~/.exitrisk/logs/exitrisk.log
jq -r 'select(.level=="ERROR" or .level=="WARNING")' ~/.exitrisk/logs/exitrisk.log | tail
```

## Known errors

| Message / code | Cause | Fix |
|---|---|---|
| `ExpiredToken`, `ExpiredTokenException` | Session older than its lifetime | Re-run; aws-cli-zsp prompts for Touch ID again |
| `credential_process` failed / cancelled | Touch ID prompt dismissed or the ZSP helper not running | Re-run and approve; check the aws-cli-zsp menu-bar status |
| `ProfileNotFound` | Typo in the profile | `aws configure list-profiles` |
| `AccessDeniedException` on Organizations | Not the management account, or missing permissions | Use the payer account profile; see IAM_PERMISSIONS.md. The scan continues for the calling account only |
| `AWSOrganizationsNotInUseException` | Standalone account | Expected; the report covers that one account |
| `DataUnavailableException` | Cost Explorer not enabled | Enable it in the Billing console; data appears within 24 hours |
| `AccessDenied` on `sts:AssumeRole` | Member role missing or trust wrong | Deploy the StackSet; check the trust names your scanner account |
| `ThrottlingException`, `Rate exceeded` | API limits during a deep scan | Already retried 10× adaptively; lower `EXITRISK_MAX_WORKERS` and re-run |
| `OptInRequired` | Region not enabled for the account | Skipped automatically |
| `'X' is not in the service catalog` | New or rare AWS service | Scored as tier 3; add it to the catalog (CONTRIBUTING.md) |
| `address already in use` on serve | Port 8740 taken | `exitrisk serve --port 8750` |
| PDF command: `needs Playwright` | Optional dependency missing | `pip install '.[pdf]' && playwright install chromium` |

Report anything else as a GitHub issue with the scan's log lines (they contain account ids and service
names but never credentials — redact account names if they are sensitive).
