# Outage Risk Report

What could fail at a peak such as Black Friday, in every account, and where to start. It compares what is running against the limits it will hit, and sets that beside the published evidence on what causes outages.

## Running it

- Console: **New scan**, tick **Run the outage risk checks**, then open the **Outage Risk Report** tab.
- CLI: `exitrisk scan --profile mgmt --outage --spend-regions`, then `exitrisk pdf <scan-id> --view outage --outage answers.json`.
- Permissions: section 4 of [IAM_PERMISSIONS.md](IAM_PERMISSIONS.md). **Check access** tests them. EKS workloads need a read only access entry on each cluster.

## What is checked

| Area | Checks |
|---|---|
| Account and product limits | Service Quotas with a usage metric, in each region. IAM roles and policies, Route 53 zones, RDS instances and storage, load balancers, target groups, Lambda concurrency and code storage, S3 buckets, S3 request rate against the per prefix limit, Amazon Connect concurrent calls and instance limits |
| Busy fixed capacity | EC2 outside an Auto Scaling group, RDS, ElastiCache, OpenSearch, Redshift, ECS without scaling, provisioned DynamoDB, burstable instances out of credits, autoscalers near their maximum |
| Storage | EBS provisioned beyond what the instance can deliver, RDS replica smaller than its source, burst credits, volumes asking for more than provisioned, time to full on RDS, OpenSearch, EFS, FSx and instance disks (with the CloudWatch agent) |
| MSK | Broker disk and time to full, brokers out of balance, no storage autoscaling, CPU against AWS's advice of 60%, partitions per broker |
| EKS | CPU request or memory limit under a floor, no limit, fixed replica counts, one replica, autoscaler at maximum, recent OOM kills, Pending pods, CoreDNS that cannot scale, node groups at maximum, subnet addresses |
| Network | Subnets running out of addresses, NAT and load balancer port errors, rejected connections, Direct Connect bandwidth, transit gateway attachments in one zone or missing a zone, blackhole routes and attachments per gateway (in the account that owns it) |
| Shared network and DNS | Which accounts own the transit gateways, shared subnets and DNS forwarding rules the scanned accounts use, and whether they were scanned. Forwarding rules with one target server, failover records with no health check, health checks failing now on records in use |
| End of life software | RDS and Aurora engines against AWS's published standard and Extended Support dates (high when AWS forces the major upgrade within 180 days), Redis OSS 4 and 5 in ElastiCache Extended Support, MSK on a deprecated Kafka version, EKS versions AWS will upgrade itself, EKS node groups on Amazon Linux 2, operating systems Systems Manager reports against the vendor's end of support (instances it does not manage are counted, not guessed) |
| Container images | EKS workloads pulling from a registry other than ECR, pulling on every start (Always, latest or no tag), or waiting on a failed pull; ECS services with images outside ECR and tasks stopped because the pull failed. EKS needs a read only access entry for the scan identity |
| Per service reviews | See [Service coverage](#service-coverage). Live settings, peak against average, limits with a forecast, resilience, CloudWatch alarms on what fails first, and what cannot be seen. |
| Change and certificates | ECS deployments with no circuit breaker, certificates expiring before the peak that will not renew by themselves, ACM renewals that have stalled (validation record missing), private CAs, IAM server certificates, CloudFront's certificates in us-east-1, Route 53 domains expiring with auto renew off |

Every rule is in [`data/outage.yaml`](../src/exitrisk/data/outage.yaml).

## Service coverage

The report states for every billed service how far it is checked, with its spend. Anything billed that is
not in [`data/outage_services.yaml`](../src/exitrisk/data/outage_services.yaml) is shown as not covered, so a
new service cannot go unseen.

| Level | Means | Services |
|---|---|---|
| Reviewed | Settings, peak against average, limits and resilience for each resource | MSK, RDS and Aurora, EKS, ElastiCache, DynamoDB, Lambda, OpenSearch, Kinesis, SQS, API Gateway, EC2 and EBS, ECS |
| Part reviewed | Some settings or events for each resource | Connect, S3, Redshift, load balancers, VPC and NAT, Transit Gateway, VPN, Direct Connect, CloudFront, EFS, FSx, Amazon MQ, SNS, Step Functions, EventBridge, Cognito, Bedrock, ACM |
| Quotas only | Service Quotas with a usage metric; the resources are not looked at | Route 53, KMS, Secrets Manager, ECR, CloudFormation, CloudWatch and Logs, IAM, WAF, Systems Manager, Firehose, Glue, Athena, SageMaker, SES, EMR, Batch, AppSync |
| Not covered | Nothing is read | Everything else billed, listed with its spend in the report |

Each review says what it read and what it cannot see. Even a Reviewed service does not show drift from
Terraform or CloudFormation, Kafka topic detail (which needs Kafka admin access), or the price of another
design.

## Services most at risk

Section 1 lists the services most likely to cause an outage, ranked by how likely one is and how far it would
spread. Spend plays no part: it is only a proxy for importance.

- **Likely**: production findings, one per risk per account, a critical counting ten highs and a high ten mediums.
- **Spread**: each service has an impact in `data/outage_services.yaml`, our judgement. **Shared** (network, DNS,
  certificates, sign in, load balancers, CloudFront, API Gateway, EKS, MSK, Connect) stops many workloads at once
  and counts three times. **Data** (databases, caches, queues, streams, storage) stops the workloads that use it
  and counts twice. **One workload** (EC2, ECS, Lambda, Step Functions, Bedrock) counts once.

Each row names the worst risk, where it is, and what to do.

## Risk map

The report opens with Immediate attention: the production findings that need someone now (at or past a limit,
failed in the last 35 days, failing now, filling before the peak, or a change AWS will make in the next two weeks),
each with why now, the account and its owner, what to do and the date to do it by.

Accounts are ranked by what was found in them: 100 points per critical, 10 per high, 1 per medium, one per risk
however many copies, and a non production finding a tenth. The map shows accounts by rating in production and
non production, every account with a finding as a bubble (up = its outage risk score, right = how far an outage
would spread, from one workload to data to shared services, size = its risk points), the 20 accounts with the most
risk, severity by account and service (each cell opens its risks and what to do), and what reaches a limit
first. An account that could not be read at all is rated Not measured, listed first, and left out of the score.

## Acting on it

- **Actions by owner** (section 9): production critical and high findings, one action per finding type for each
  owner, with the resources and accounts it covers and when to start. The owner comes from the account's owner
  tag; accounts with none are one group, so tag them to route their actions.
- **Export table to PDF** on Immediate attention, Top risks and Actions by owner prints just that table, to send
  to the team that owns it.
- **Complete the scan** reads again only the accounts that could not be read, or had a check refused or failing,
  and keeps the rest. It saves a new scan, so the partial one stays in the history.
- **Shared network and DNS** (section 4) names the accounts that own the transit gateways, shared subnets and
  forwarding rules the scanned accounts depend on, and says when those accounts were not scanned.

## How severity is set

Measures are collected at scan time and judged when the report is built, so changing an answer needs no new scan.

- **Now** is the highest hourly average of the last 35 days, which holds a month end. API rate quotas use five minute figures over 14 days.
- **At peak** multiplies usage that rises with traffic by the expected load, default 2x. **This is an assumption**: replace it with last year's measured ratio of peak to normal. Counts of things someone creates, and storage, are not multiplied.
- **Critical**: at or past the critical threshold (90%) now, or full before the peak. **High**: past 100% at peak, or full within 30 days after it. **Medium**: past the warning threshold (70%) at peak. Events and settings carry the severity set in the rule.
- Outside production everything is one level lower, and some rules do not apply.
- **Score**: 0 to 100, higher is worse, same diminishing formula as the Cloud Assurance Report. The overall score is the average of the accounts' scores, a non production account counting a tenth; spend plays no part.
- **Start by** is the change freeze less a lead time per area. Those lead times are our judgement: AWS publishes none for quota increases. Ask your Technical Account Manager.

## The evidence

The report's "What causes outages" section shows each cause with its source and limits. In short:

- **Change is the largest measured trigger.** Google: "roughly 70% of outages are due to changes in a live system". Across thousands of postmortems from 2010 to 2017: binary push 37%, configuration push 31%, user behaviour change 9%, processing pipeline 6%, service provider change 5%, performance decay 5%, capacity management 5%, hardware 2%.
- **Limits and capacity are smaller on an average day**, and matter more at a peak. Nobody publishes how much more. AWS's Well-Architected guidance suggests a buffer such as 15% and warns to expect a wait for a quota increase.
- **What this evidence is not.** Google's figures are one company's own systems, not AWS customers or banks. We found no published prevalence figure for OOM kills, API throttling, IP exhaustion or quota related incidents, and no bank specific data. The order of the report's areas is our judgement.

So: hold the freeze and rollback first, then fix what the scan finds. A scan measures capacity far better than it measures change, so a report full of capacity findings does not mean capacity is the bigger risk.

## What is not measured

- **Short spikes.** Hourly averages hide them, so real headroom is lower than shown. Aurora Serverless is also read at its hourly maximum, to show time spent at its maximum ACUs.
- **Paid extended support for operating systems** (Windows ESU, RHEL ELS, Ubuntu Pro): the finding names the vendor date and says it may be covered.
- **Every metric is read.** One CloudWatch call returns at most 500 series, so reads are split until each fits; a metric that still cannot be read whole marks the check as not measured, never as a pass.
- **Database connections where `max_connections` is a formula with `log()`.** Numbers and `LEAST` formulas are compared.
- **S3 request rates** need request metrics on the bucket, and compare the whole bucket against a per prefix limit: well spread keys have far more room than shown.
- **Quotas with no usage metric**, and Trusted Advisor's own limit checks.
- **Whether the system survives the load**: a load test does that. So do DNS and connection tracking limits on instances, runbooks and rollback rehearsals.
- **Clusters that could not be read.** Shown as not read, never as a pass. Container Insights, where on, still gives memory and CPU against limits.
- **The rate of change**; regional dependence is in the Multi-Region Report, change controls in the Cloud Assurance Report.

## Answers file

```json
{"peak_date": "2026-11-27", "peak_multiplier": 2.0, "freeze_days": 14, "warn_pct": 70, "critical_pct": 90,
 "production_patterns": "prod,prd", "cpu_request_floor_m": 100, "memory_limit_floor_mi": 256}
```
