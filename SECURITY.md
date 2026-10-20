# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's **Security → Report a vulnerability** on this
repository rather than in a public issue. Expect an acknowledgement within five working days.

## Threat model

The tool runs on an analyst's workstation with that analyst's AWS identity, and produces a report
that names every account and its spend.

| Asset | Threat | Control |
|---|---|---|
| AWS credentials | Leaked through logs or files | Uses the profile's session via boto3; never reads, stores or logs keys; log redaction of anything key-shaped; aws-cli-zsp keeps keys sealed behind Touch ID |
| AWS identity | A malicious web page drives the local console (CSRF, DNS rebinding) | Loopback bind; `Host` allow-list; custom header required on writes; no CORS; strict CSP |
| AWS environment | Tool changes something | Read-only APIs only; member role is list-only and cannot read data |
| Scan data (accounts, spend) | Disclosure | Stays local; data dir `0700`, files `0600`; `.gitignore` excludes scans and PDFs; no telemetry |
| Report integrity | Account names or AWS error text injected as HTML | All rendered values escaped; CSP blocks inline script |
| Path traversal | Crafted scan id | Scan ids validated against a strict pattern before use in paths |

Binding the console to a non-loopback address (`--host 0.0.0.0`) disables the Host check and lets
anyone who can reach the port run scans as you; the tool logs a warning when you do this. Do not do it
on shared networks.

## Supported versions

Security fixes are made on the latest minor release.
