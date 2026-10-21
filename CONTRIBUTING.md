# Contributing

Thank you for helping. The catalog of AWS services is the most valuable part of this project and
the easiest to improve; code contributions are welcome too.

## Changing the service catalog

The catalog is `src/exitrisk/data/service_catalog.yaml`. Each entry has the exact Cost Explorer
`SERVICE` name (find it in Cost Explorer → Group by Service, or in a scan's "not in the service
catalog" warning), any older names as `aliases`, and:

- `tier` 1–5, using the test in docs/METHODOLOGY.md §2: *how much of a workload must change to leave AWS?*
- `why`: factual, one to three sentences, naming the specific proprietary parts (APIs, data model,
  integrations). Avoid opinions about AWS.
- `migration`: the recommended path, actionable, preferring cloud-neutral destinations where they exist.
- `targets`: `azure`, `gcp`, `other` (cloud-neutral / self-managed).
- `effort_weeks`: engineer-weeks for one typical workload at ~US$1k/month; compare with neighbouring
  services in the same tier.
- `duration`: elapsed time for one workload, as a range.

Then:

```bash
python scripts/gen_catalog_doc.py       # regenerate docs/SERVICE_CATALOG.md
pytest                                  # catalog validation tests
```

A pull request that **changes a tier** must explain the reasoning in its description and bump the
catalog `version` (YYYY.MM), because it changes scores in existing reports.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]' && playwright install chromium
pytest                                  # unit tests (no AWS access needed; botocore Stubber)
ruff check src tests scripts && ruff format --check src tests scripts
exitrisk serve                          # Load demo data to work on the UI
python scripts/screenshots.py           # regenerate docs/images and docs/sample-report.pdf
python scripts/refresh_direct_connect.py   # refresh Direct Connect list prices (data/direct_connect.json)
python scripts/refresh_region_services.py  # refresh services by region (data/region_services.json)
```

Guidelines:

- Every AWS failure must become an `Issue` with a hint, and be logged; never swallow an exception.
- Never log credentials, and never send scan data anywhere: the tool is local by design.
- Every value rendered in the browser goes through `esc()`.
- Keep coefficients in one place (`estimate.py` constants) and list them in `assumptions`.
- New charts follow the existing palette and must have a tooltip and an accessible label.

## Reporting bugs

Open an issue with the command, the error, and the relevant log lines from
`~/.exitrisk/logs/exitrisk.log` (filter with `jq 'select(.run_id=="<scan id>")'`). Remove account
names you consider sensitive. Security problems: see SECURITY.md.
