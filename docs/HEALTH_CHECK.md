# Health Check Report

The sixth report. Use it when something is wrong right now, or to give one account a thorough check
up: pick one to ten accounts, and it reads every part of them it can reach over the last hours and returns
the **top issues**, ranked by severity and by how likely each is to cause, or already be, an outage users
feel. Symptoms are optional; with none it simply looks for anything that is not healthy.

It is not tied to a scan, so it works with an access key in an account outside your organisation.

## Running it

1. Open the console and choose **Health check** in the top bar (or go to `/health`).
2. **Sign in**:
   - **SSO**: the portal lists every account you can reach;
   - **Access key**: the console reads `~/.aws/credentials` and `~/.aws/config` and lists each profile with
     its kind (SSO, access key, session key, role, credential process) and the key masked as `AKIA…1234`.
     Secrets are never shown or sent to the browser. With a key, the list holds the key's own account, plus
     the organisation's accounts when the key may read them; a **role name** is then needed to reach the others.
3. **Find the accounts**: type an account number, name or owner and tick up to 10. Owners come from the
   owner and executive tags read by the last saved scans, so they show only once a scan has run.
4. **Look back**: 1, 3, 6, 12, 24 or 72 hours (24 by default). **Symptoms** (optional): plain words such as
   "card payments failing since 14:00"; they lift the issues that match.
5. **Check access** (optional) tries each read once in each ticked account and gives a policy for any
   that is refused. **Run health check** starts the run; a blue panel shows progress, and the report opens
   with a green "New report" banner when it finishes. An earlier report is marked with a yellow banner.

A run takes a few minutes; accounts and regions are read in parallel. Runs are saved in `~/.exitrisk/health/`.

## What is read

In every region with recent activity, plus us-east-1:

| Area | What it looks for |
|---|---|
| Metrics | Errors, throttles, latency, unhealthy hosts, queue age, saturation, for every service in use; each compared with the same hours a day earlier |
| Alarms | CloudWatch alarms in ALARM, and when they started |
| Changes (CloudTrail) | Write calls that can affect availability, refused calls and bursts of AccessDenied |
| Compute | ECS stopped tasks and services short of tasks, EKS clusters and node groups, Auto Scaling failures, EC2 status checks and scheduled events, Lambda state |
| Load balancers | Target groups with unhealthy targets and why: stale IP registrations, an inner load balancer with no targets |
| Data | RDS status and events, ElastiCache events |
| Network | VPN tunnels, transit gateway attachments, Direct Connect, subnets short of IP addresses, rejected traffic in VPC flow logs |
| DNS | Route 53 health checks, Resolver endpoints, failing lookups in Resolver query logs |
| Logs | Error spikes in the busiest application log groups (Logs Insights) |
| Quotas | Quotas close to their limit, from AWS/Usage metrics |
| Other | Certificates in use that expire, AWS Health events, and the Outage Risk checks |

## Reading the report

- **Top issues**: the most important findings, new ones first. Each has a severity, an **outage
  likelihood** with the reason in plain words, when it started, and the next step. A cause (a change, a
  quota) is linked to the symptoms that follow it within three hours.
- **Chronic** means it was the same a day earlier: real, but probably not today's outage, so it ranks lower.
- **Changes in the window**: tagged **risky** (a delete, a stop, a revoked permission, a route or DNS change,
  a failover), **routine** (housekeeping, or a cluster controller such as Karpenter doing its normal work),
  or untagged. Repeats of one action by one actor share a row with a count (×20). Changes by AWS itself
  are left out.
- **Turn on to see more**: logging that is off (flow logs, Resolver query logs) and would have helped.
- **Coverage / could not check**: every check that was refused or failed, so nothing missed is hidden.

Export PDF prints the whole report with every section open.

## Permissions

The AWS managed **ReadOnlyAccess** policy covers every read. For a narrower key, run **Check access**: it
lists each refused action and a policy with exactly those. Notes:

- **AWS Health** needs a Business, Enterprise On-Ramp or Enterprise support plan; without one it shows
  under Coverage, not as a fault.
- **EKS** node and pod detail needs an EKS access entry (AmazonEKSViewPolicy) for the role.

## Cost

Everything is read only. The one charged part is CloudWatch Logs Insights, about US$0.005 a GB scanned:
each log check is capped at 60 GB a region (about US$0.30), and a log group too large for the window is
listed instead of read. The report says how much was scanned.
