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
| Metrics | About 140 probes: errors, throttles, latency, unhealthy hosts, queue age, saturation, for every service in use; each compared with the same hours a day earlier, and spikes also with a week earlier so a weekly peak is not taken for a fault |
| Alarms | CloudWatch alarms in ALARM, and when they started |
| Changes (CloudTrail) | Write calls that can affect availability, refused calls and bursts of AccessDenied |
| Compute | ECS stopped tasks and services short of tasks, EKS clusters and node groups, Auto Scaling failures, EC2 status checks and scheduled events, Lambda state |
| Load balancers | Target groups with unhealthy targets and why: stale IP registrations, an inner load balancer with no targets |
| RDS and Aurora | Status and events; replica, Aurora and global lag; memory and swap; read and write latency and queue depth; the instance class or volume over its IOPS or throughput (the EBS "exceeded" checks), IO and burst balance; transaction ID age (vacuum falling behind), replication slot lag, transaction logs; deadlocks; buffer cache hit ratio; commit latency; connections against max_connections worked out from the parameter group; provisioned IOPS and throughput against what is used; free storage and the autoscaling ceiling; autovacuum switched off; RDS Proxy errors |
| Inside the database | Performance Insights, where on: load against vCPUs, the top wait events with what each means (I/O, locks, CPU, commit), and the heaviest SQL. Database log warnings (vacuum, deadlocks, out of memory, too many connections) through Logs Insights |
| Storage | EBS volume status and IOPS or throughput over its limit; EC2 instances over their EBS limit; EFS burst credits, IO limit and throughput, state and mount targets; FSx state, free space and CPU; disk and memory from the CloudWatch agent where installed |
| Queues and streams | SQS backlog age and messages in flight, and queues nothing reads; Kinesis read throttles; MSK offline partitions, controller, under replicated and below min ISR partitions, disk, CPU, heap, file descriptors, produce time and consumer lag |
| DynamoDB | Throttles on tables and indexes, latency, global table replication, provisioned capacity in use, table status |
| Caches and search | ElastiCache evictions, swap, replication lag, connections, bandwidth and connection tracking allowances, serverless throttles, cluster status; OpenSearch JVM, storage, rejected writes, 5xx |
| Load balancers and APIs | ALB p99 latency, rejected connections, target connection and TLS errors, 4xx spikes; NLB resets, port allocation, security group blocks, fail open; API Gateway latency and 4xx; CloudFront 4xx; WAF blocks |
| Functions | Lambda timeouts, account concurrency, dropped async events, event age, dead letter and destination failures, stream iterator age, recursive loops, event source mappings in error |
| Kubernetes | EKS add ons; pods crashing, unable to pull images, missing secrets, unschedulable or killed for memory, and nodes not ready or under pressure, grouped by workload (needs an EKS access entry) |
| Network | VPN tunnels, transit gateway attachments and blackholed routes, VPC route tables with blackholes, VPC endpoints not available, Direct Connect, subnets short of IP addresses, Network Firewall; rejected traffic in VPC flow logs, with the security groups and network ACLs on the refused destinations so a change to them links to the rejects |
| Traces and canaries | X-Ray services with faults (last 6 hours of the window) and CloudWatch Synthetics canaries failing |
| DNS | Route 53 health checks, Resolver endpoints, failing lookups in Resolver query logs |
| Logs | Error spikes in the busiest application log groups (Logs Insights) |
| Quotas | Quotas close to their limit, from AWS/Usage metrics |
| Other | Certificates in use that expire, AWS Health events, and the Outage Risk checks |

## Shared network accounts

Many organisations run the transit gateway, shared VPCs, Resolver rules and private DNS zones in a separate
network account. With **Also check the accounts that own the shared network** ticked (the default), the
check finds which accounts own what the ticked accounts use and reads the network checks there too (up to
three). A fault in a shared account can then explain symptoms in the accounts it serves. The report names
each one and why it was read; one it cannot reach is listed under Coverage.

## Flow logs kept only in S3

Flow logs sent to CloudWatch Logs are read with Logs Insights. Flow logs sent only to S3 need Athena, which
creates database `exitrisk_healthcheck` and a table over the log location in that account and writes query
results to the Athena result location (about US$5 a TB read). It is off by default: tick **Read flow logs
kept only in S3 with Athena** to allow it. Without it, the report lists those flow logs under Turn on to see more.

## What cannot be seen read only

- **Dead tuples, bloat and missing indexes** need a login to the database. The check covers them
  indirectly: transaction ID age and autovacuum settings for vacuum, and Performance Insights waits, the
  heaviest SQL, buffer cache hit ratio and read latency for index problems.
- **Kafka topic detail** needs a Kafka client; MSK is judged from its CloudWatch metrics.

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
- **EKS** node and pod detail needs an EKS access entry (AmazonEKSViewPolicy) for the role; without one
  the report says so under Turn on to see more.
- **Performance Insights** needs `pi:GetResourceMetrics` and `pi:DescribeDimensionKeys` (in ReadOnlyAccess).
- **Athena**, only if ticked: `athena:StartQueryExecution`, `athena:GetQueryExecution`,
  `athena:GetQueryResults`, `glue:CreateDatabase`, `glue:CreateTable`, `glue:GetTable`, and read access to
  the flow log bucket and write access to the Athena result location.

## Cost

Everything is read only. The one charged part is CloudWatch Logs Insights, about US$0.005 a GB scanned:
each log check is capped at 60 GB a region (about US$0.30), and a log group too large for the window is
listed instead of read. The report says how much was scanned.
