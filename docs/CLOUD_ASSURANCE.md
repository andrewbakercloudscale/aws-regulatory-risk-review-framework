# Cloud Assurance Framework Report

The Cloud Assurance Framework Report scores every account against the controls a regulator, auditor or
board asks about: who holds administrator access, what is reachable from the internet, whether changes
are logged, alerted and made through pipelines, whether production survives the loss of a data centre
or region and is restored in tests, whether sensitive data is protected against silent change, and who
owns each account. It is a separate report from the exit-risk review, in the same console and the same
scan.

It answers questions such as:

- Can people in the payments team change payment files in S3 without anyone being alerted?
- Is any host reachable over SSH or RDP from the internet?
- Which production databases, load balancers and server groups run in one availability zone?
- Are backups copied to a second region, locked against deletion, and restored in tests?
- Which accounts have no owner, or an owner who has left?
- Which accounts hold open GuardDuty, Security Hub, Inspector or Trusted Advisor findings?

## Running it

1. **Check access** in the console tests the extra read permissions (two optional checks: "Cloud
   assurance reads in the management account" and "... in a member account"). See
   [IAM_PERMISSIONS.md](IAM_PERMISSIONS.md#3-cloud-assurance-framework-checks).
2. **New scan**, tick **Run the Cloud Assurance Framework checks**. It runs with any scan depth and uses
   the same member role or permission set as the deep scan, and the same region choice ("Only regions
   with spend" reads each account's billed regions). From the command line:
   `exitrisk scan --profile mgmt --assurance --spend-regions` (add `--role ExitRiskReadOnly` if you do
   not use your own permission set).
3. Open the **Cloud assurance** tab. Choose the ruleset and answer the settings in section 2. Export the
   PDF from Export PDF, or `exitrisk pdf <scan-id> --view assurance --include prod`.

Changing the ruleset or any setting rebuilds the report at once: the scan reads every rule it can, and
the selection is applied when the report is built. No new scan is needed.

## Rules and rulesets

The catalogue, [`src/exitrisk/data/assurance.yaml`](../src/exitrisk/data/assurance.yaml), holds 139 rules
in 13 areas. Each has a severity, an optional scope (production only, accounts that are not
the internet edge, or accounts holding sensitive data), why it matters, how to fix it, public references
(CIS AWS Foundations Benchmark v3.0 and the AWS Foundational Security Best Practices controls) and the
read-only calls it is evaluated from.

**Choose rules** in section 2 shows every rule, searchable by name, id or reference, filterable by area,
severity and framework. Tick the rules that apply to the OU or accounts in the report, change a rule's
severity if your policy rates it differently, then:

- **Apply without saving** to see the effect, or
- **Save ruleset** under a name (for example "Payments production"). Saved rulesets are kept in
  `~/.exitrisk/rulesets.json` (or `$EXITRISK_DATA_DIR`), appear in the Ruleset list for every scan, and
  can be deleted from there.

Built-in rulesets: All rules, Regulator essentials (critical and high), CIS AWS Foundations, AWS
Foundational Security Best Practices, Resilience and disaster recovery, Sensitive data, Identity and
access. They follow the catalogue and cannot be changed; save a copy to adapt one.

Rulesets are also available over the API: `GET /api/rulesets`, `PUT /api/rulesets` (name, description,
rules, severity), `DELETE /api/rulesets/<name>`.

## Settings (section 2)

| Setting | Default | Used by |
|---|---|---|
| Production accounts | `prod,prd` (name or OU path; an `Environment` tag wins) | Rules scoped to production: Multi-AZ, backups, restore tests, manual changes... |
| Internet edge accounts | `edge,network,ingress,egress,dmz,perimeter` | Public IPs, internet and NAT gateways and public load balancers are expected there and not counted |
| Sensitive buckets | `payment,card,pci,eft,pii,customer,statement` (bucket name); classification tags (`DataClassification` and similar, values such as Confidential, Restricted, PCI, PII) always count | Sensitive data rules and Macie |
| Critical accounts | criticality tags, plus names given here | Points count 1.5 times |
| Administrators per account | 5 | Too many people with administrator access |
| Allowed data locations | the jurisdiction of the region with most spend | Data held outside the allowed locations (storage and database spend by region) |
| Required account tags | none (rule not checked) | Required account tags missing |
| Accounts approved for AI | none | AI services used where not approved |

## Scoring

- Pass, Fail, Not measured, Not applicable. A call that is refused or fails makes the rule **Not
  measured**: never a pass. Coverage (the share of applicable checks measured) is shown beside every
  score.
- Each failing rule adds its severity's points once, however many resources fail it: Critical 40,
  High 15, Medium 5, Low 1. Points combine with diminishing returns:
  `score = 100 x (1 - product of (1 - points / 100))`, so it stays between 0 and 100.
- A critical account counts its points 1.5 times. Any failing Critical rule sets the score to at least 80.
- Ratings: Critical 80 and above, High 50 to 79, Medium 20 to 49, Low below 20.
- The OU score is the accounts' scores weighted by monthly spend, with the plain average by number of
  accounts beside it.

Points and severities are in the catalogue and can be changed there.

## Where the results come from

Every call is read-only (list, describe, get). Nothing is stored but counts, names and settings: no
object, log line, item or secret value is read. The checks read each service directly, so they hold
whether or not Security Hub is on; the findings AWS itself reports are separate rules (open GuardDuty
findings, critical Security Hub findings, high findings older than 90 days, Inspector vulnerabilities,
Access Analyzer external access, AWS Config non-compliant rules, Trusted Advisor red and yellow checks).

Organisation-level controls are read once, in the management account:

- **Service control policies**: for each account, the SCPs on the account, every OU above it and the
  root. A guardrail counts when a Deny covers the action (with or without an exemption condition):
  CloudTrail, GuardDuty, Config and Security Hub kept on, S3 Block Public Access kept on, accounts
  cannot leave the organisation, no new IAM users, and a region restriction (`aws:RequestedRegion`).
- **Central root access management** (`iam:ListOrganizationsFeatures`). When it is on, root without MFA
  in a member account is not applicable.
- **IAM Identity Center**: administrator permission sets (AdministratorAccess, or an inline policy
  allowing everything), who holds them in each account (groups expanded to people), assignments made
  to people directly, and whether each owner email on an account is a current user.
- **Trusted Advisor organisation view** when available (Business or Enterprise Support with trusted
  access); otherwise each account's own Trusted Advisor.
- **Organisation trails**: logging, S3 write data events, and the CIS metric filters on the trail's
  log group (which count as the security alerts for every account).

Sensitive data: who can write to a sensitive bucket is worked out from the identity policies of people's
roles (Identity Center permission sets, SAML roles and IAM users) against `s3:PutObject` and
`s3:DeleteObject` on the bucket. Conditions and permission boundaries are not evaluated, so the result
leans towards reporting access that may exist. A write is "alerted" when the bucket's object writes are
logged as CloudTrail data events and either GuardDuty S3 protection or an EventBridge rule on S3 events
watches the bucket's region.

Change management: write calls by people (root, IAM users, Identity Center sessions) in the last seven
days are sampled from CloudTrail event history in the account's busiest region and us-east-1 (up to 300
events each).

## Ownership

Section 5 lists accounts with no owner tag, or an owner email not found in IAM Identity Center. For each
it proposes the owner most related accounts have (the same name without the environment, for example
`payments-dev` from `payments-prod`), or else the most common owner in its OU. Edit the proposal,
tick **Approve**, and export the approved changes as a CSV or as AWS CLI commands
(`aws organizations tag-resource ...`) for an administrator to review and run. The console never
changes AWS.

## Evidence

**Download evidence** (section 7) saves the report as JSON with a SHA-256 of its canonical form (sorted
keys, no spaces). Keep it with the risk register: recomputing the hash shows the file is unchanged. Each
report names the catalogue version and the scan id.

## Limits

- Organisation-level checks need a scan from the management account; from a member account they show as
  not measured.
- Access Analyzer run as an organisation analyzer in a delegated administrator account is credited to
  every account (it is not read inside that account).
- Policy conditions, permission boundaries and resource policies are not evaluated for the writer and
  administrator rules.
- Very large accounts are sampled: the first 1000 buckets, 500 tables, keys or functions per region, 500
  findings per query and 200 load balancers per region. A rule cut short says so in its note.

## All rules

### Internet exposure (25)

Hosts, data and services reachable from the internet that should not be.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| SSH or RDP reachable from the internet | `admin_ports_public` | Critical | All | CIS 5.2, CIS 5.3, FSBP EC2.13, FSBP EC2.14 |
| Database or cache ports reachable from the internet | `db_ports_public` | High | All | FSBP EC2.19 |
| Security groups open to the internet on SSH or RDP | `admin_ports_open` | Medium | All | CIS 5.2, CIS 5.3 |
| Instances with a public IP outside the internet edge | `ec2_public_ip` | Medium | Not edge | FSBP EC2.9 |
| Internet gateway outside the internet edge | `igw_present` | Medium | Not edge |   |
| NAT gateway outside the internet edge | `nat_present` | Low | Not edge |   |
| Internet-facing load balancers outside the internet edge | `public_lb` | Low | Not edge |   |
| Databases marked publicly accessible | `rds_public` | High | All | CIS 2.3.3, FSBP RDS.2 |
| Disk snapshots shared with everyone | `public_snapshots` | Critical | All | FSBP EC2.1 |
| Machine images shared with everyone | `public_amis` | High | All |   |
| S3 Block Public Access not on for the account | `s3_account_bpa` | High | All | CIS 2.1.4, FSBP S3.1 |
| Public S3 buckets | `s3_public_bucket` | Critical | All | FSBP S3.2, FSBP S3.3, FSBP S3.8 |
| Instances that allow IMDSv1 | `imdsv2` | Medium | All | CIS 5.6, FSBP EC2.8 |
| Default security groups allow traffic | `default_sg_open` | Low | All | CIS 5.4, FSBP EC2.2 |
| Default VPC still present | `default_vpc` | Low | All |   |
| Every port reachable from the internet | `all_ports_public` | Critical | All | CIS 5.2, FSBP EC2.18 |
| Network ACLs open to the internet on SSH or RDP | `nacl_admin_open` | Low | All | CIS 5.1, FSBP EC2.21 |
| Kubernetes API open to the internet | `eks_public_endpoint` | High | All | FSBP EKS.1 |
| OpenSearch domains outside a VPC | `opensearch_public` | High | All | FSBP Opensearch.2 |
| Redshift clusters marked publicly accessible | `redshift_public` | High | All | FSBP Redshift.1 |
| Load balancers serving plain HTTP | `elb_http` | Medium | All | FSBP ELB.1 |
| Load balancers allowing TLS 1.0 or 1.1 | `tls_outdated` | Medium | All | FSBP ELB.8 |
| Internet-facing applications without a web firewall | `waf_missing` | Medium | All | FSBP APIGateway.4, FSBP WAF.10 |
| CloudFront serving plain HTTP | `cloudfront_http` | Medium | All | FSBP CloudFront.3 |
| CloudFront without a web firewall | `cloudfront_no_waf` | Low | All | FSBP CloudFront.6 |

### Identity and privileged access (20)

Who holds administrator rights, root and long-lived credentials, segregation of duties.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| Root user without MFA | `root_mfa` | Critical | All | CIS 1.5, FSBP IAM.9 |
| Root user has access keys | `root_keys` | Critical | All | CIS 1.4, FSBP IAM.4 |
| Root user used in the last 90 days | `root_used` | High | All | CIS 1.7 |
| IAM users who sign in without MFA | `console_no_mfa` | High | All | CIS 1.10, FSBP IAM.5 |
| Access keys older than 90 days | `keys_old` | Medium | All | CIS 1.14, FSBP IAM.3 |
| Credentials unused for 45 days or more | `creds_unused` | Medium | All | CIS 1.12, FSBP IAM.8 |
| IAM users with passwords or keys | `iam_users` | Low | All |   |
| Custom policies granting full administrator access | `admin_policy` | High | All | CIS 1.16, FSBP IAM.1 |
| Permissions attached directly to IAM users | `user_direct_policies` | Low | All | CIS 1.15, FSBP IAM.2 |
| Too many people with administrator access | `admin_holders` | Medium | All |   |
| Roles that accounts outside the organisation can assume | `external_trust` | High | All |   |
| Roles unused for 90 days or more | `roles_unused` | Low | All |   |
| IAM Access Analyzer not watching for external access | `access_analyzer_off` | Medium | All | CIS 1.20 |
| Missing organisation guardrails (SCPs) | `scp_guardrails` | Medium | All |   |
| Weak IAM password policy | `password_policy` | Low | All | CIS 1.8, CIS 1.9, FSBP IAM.7 |
| No role for AWS Support | `support_role` | Low | All | CIS 1.17, FSBP IAM.18 |
| Servers or functions running as administrator | `workload_admin` | High | All | FSBP IAM.1 |
| Administrator access assigned to people directly | `admin_direct_user` | Medium | All |   |
| Root credentials not centrally managed | `central_root_off` | Medium | All | FSBP IAM.6 |
| No region restriction | `scp_region_deny` | Low | All |   |

### Audit trail (11)

Complete, tamper-evident records of who changed what, kept as evidence.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| No multi-region CloudTrail logging | `cloudtrail_off` | High | All | CIS 3.1, FSBP CloudTrail.1 |
| CloudTrail log file validation off | `cloudtrail_validation` | Medium | All | CIS 3.2, FSBP CloudTrail.4 |
| AWS Config not recording | `config_off` | High | All | CIS 3.3, FSBP Config.1 |
| VPCs without flow logs | `flow_logs` | Medium | All | CIS 3.7, FSBP EC2.6 |
| S3 buckets without versioning | `s3_versioning_off` | Low | All | FSBP S3.14 |
| CloudTrail logs not encrypted with a KMS key | `cloudtrail_kms` | Low | All | CIS 3.5, FSBP CloudTrail.2 |
| CloudTrail not sent to CloudWatch Logs | `cloudtrail_cwl` | Low | All | FSBP CloudTrail.5 |
| No alerts on root use, IAM or CloudTrail changes | `security_alerts_none` | Medium | All | CIS 4.1, CIS 4.3, CIS 4.4, CIS 4.5 |
| AWS Config not recording every resource type | `config_partial` | Low | All | FSBP Config.1 |
| Load balancers without access logs | `elb_access_logs` | Low | Production | FSBP ELB.5 |
| VPCs without DNS query logging | `dns_query_logs` | Low | All |   |

### Threat detection and open findings (16)

Security services switched on, and the issues AWS itself reports being closed.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| GuardDuty off | `guardduty_off` | High | All | FSBP GuardDuty.1 |
| Security Hub off | `securityhub_off` | Medium | All | CIS 4.16 |
| Inspector vulnerability scanning off | `inspector_off` | Medium | All | FSBP Inspector.1 |
| Open high-severity GuardDuty findings | `guardduty_findings` | High | All |   |
| Open critical Security Hub findings | `sh_critical_findings` | Critical | All |   |
| High Security Hub findings open for more than 90 days | `sh_high_aged` | Medium | All |   |
| Open IAM Access Analyzer external access findings | `external_access_findings` | High | All |   |
| AWS Config rules out of compliance | `config_noncompliant` | Medium | All |   |
| Trusted Advisor action recommended (red) | `trusted_advisor_red` | High | All |   |
| Trusted Advisor investigation recommended (yellow) | `trusted_advisor_yellow` | Low | All |   |
| GuardDuty protection plans off | `guardduty_partial` | Low | All | FSBP GuardDuty.5, FSBP GuardDuty.6 |
| Security Hub without a security standard | `sh_standards_missing` | Low | All |   |
| Inspector not scanning containers or functions | `inspector_partial` | Low | All | FSBP Inspector.2, FSBP Inspector.3 |
| Open critical vulnerabilities | `vuln_critical` | Critical | All |   |
| High vulnerabilities open for more than 30 days | `vuln_high_aged` | Medium | All |   |
| Macie off where sensitive data is held | `macie_off` | Low | Sensitive data |   |

### Data protection and location (13)

Encryption, key management, and where data actually sits.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| EBS encryption by default off | `ebs_default_encryption` | Medium | All | CIS 2.2.1, FSBP EC2.7 |
| Unencrypted EBS volumes | `ebs_unencrypted` | Medium | All | FSBP EC2.3 |
| Unencrypted databases | `rds_unencrypted` | High | All | CIS 2.3.1, FSBP RDS.3 |
| Customer KMS keys without rotation | `kms_rotation` | Low | All | CIS 3.6, FSBP KMS.4 |
| Secrets without rotation | `secrets_no_rotation` | Low | All | FSBP SecretsManager.1 |
| Data held outside the allowed locations | `data_location` | Medium | All |   |
| S3 buckets that accept unencrypted connections | `s3_tls_only` | Low | All | FSBP S3.5 |
| S3 buckets still using ACLs | `s3_acls` | Low | All | FSBP S3.12 |
| Unencrypted file systems | `efs_unencrypted` | Medium | All | FSBP EFS.1 |
| Unencrypted Redshift clusters | `redshift_unencrypted` | High | All | FSBP Redshift.10 |
| Caches without encryption | `elasticache_unencrypted` | Medium | All | FSBP ElastiCache.4, FSBP ElastiCache.5 |
| OpenSearch domains without encryption | `opensearch_unencrypted` | Medium | All | FSBP Opensearch.1, FSBP Opensearch.3 |
| KMS keys scheduled for deletion | `kms_pending_deletion` | Medium | All | FSBP KMS.3 |

### Sensitive data controls (6)

Payment and customer files protected against change, deletion and silent tampering.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| People can change sensitive files with no alert | `sensitive_human_write` | High | All | CIS 3.8 |
| Sensitive buckets without versioning | `sensitive_no_versioning` | High | All | FSBP S3.14 |
| Sensitive buckets without object-level logging | `sensitive_no_data_events` | Medium | All | CIS 3.8 |
| Sensitive buckets without Object Lock | `sensitive_no_lock` | Medium | All | FSBP S3.15 |
| Sensitive buckets not replicated | `sensitive_no_replication` | Low | Production | FSBP S3.7 |
| Sensitive buckets not encrypted with a KMS key | `sensitive_no_kms` | Medium | All | FSBP S3.17 |

### Change management (5)

Production changed through pipelines, not by hand; configuration kept in its approved state.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| Changes made by hand in production | `manual_changes` | Medium | Production |   |
| CloudFormation stacks drifted from their templates | `cfn_drift` | Medium | All |   |
| Instances not managed by Systems Manager | `ssm_unmanaged` | Low | All | FSBP SSM.1 |
| Instances missing patches | `patch_noncompliant` | Medium | All | FSBP SSM.2 |
| No AWS Config rules | `config_rules_none` | Low | All |   |

### Resilience and disaster recovery (23)

Production survives the loss of a data centre (AZ) or region, and recovery is tested.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| Production databases in one availability zone | `rds_single_az` | High | Production | FSBP RDS.5 |
| Production databases without automated backups | `rds_no_backups` | High | Production | FSBP RDS.11 |
| Production databases without deletion protection | `rds_no_deletion_protection` | Low | Production | FSBP RDS.8 |
| Auto Scaling groups in one availability zone | `asg_single_az` | High | Production | FSBP AutoScaling.2 |
| Load balancers in one availability zone | `lb_single_az` | Medium | Production | FSBP ELB.10, FSBP ELB.13 |
| Stand-alone servers all in one availability zone | `ec2_one_az` | Medium | Production |   |
| Caches without automatic failover | `elasticache_no_failover` | Medium | Production | FSBP ElastiCache.3 |
| OpenSearch domains in one availability zone | `opensearch_single_az` | Medium | Production |   |
| One Zone file systems in production | `efs_one_zone` | Medium | Production |   |
| DynamoDB tables without point-in-time recovery | `dynamodb_no_pitr` | Medium | Production | FSBP DynamoDB.2 |
| No AWS Backup protection | `backup_none` | Medium | Production |   |
| Backups not copied to a second region | `backup_no_cross_region` | Medium | Production |   |
| No restore tested in 90 days | `restore_untested` | Medium | Production |   |
| No failure tests in 90 days | `dr_drills_none` | Low | Production |   |
| Production in one region only | `single_region` | Low | Production |   |
| Database backups kept less than 7 days | `rds_backup_short` | Low | Production | FSBP RDS.26 |
| DynamoDB tables without deletion protection | `dynamodb_no_deletion_protection` | Low | Production | FSBP DynamoDB.6 |
| Internet access through one availability zone | `nat_single_az` | Medium | Production |   |
| Site-to-site VPN without a working second tunnel | `vpn_tunnel_down` | Medium | All |   |
| Direct Connect without redundancy | `dx_no_redundancy` | High | All |   |
| Container services running one copy | `ecs_single_task` | Medium | Production |   |
| Backups that can be deleted | `backup_vault_unlocked` | Medium | Production |   |
| No resilience assessment | `resiliencehub_none` | Low | Production |   |

### Technology lifecycle (6)

Runtimes and platform versions past their end of support.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| Lambda functions on runtimes past end of support | `lambda_deprecated_runtime` | Medium | All | FSBP Lambda.2 |
| EKS clusters past standard support | `eks_unsupported_version` | Medium | All | FSBP EKS.2 |
| Databases past end of standard support | `rds_engine_eol` | Medium | All |   |
| Servers on previous-generation instance types | `ec2_previous_generation` | Low | All |   |
| Servers built from images older than 180 days | `ami_outdated` | Low | All |   |
| Certificates expiring within 30 days | `acm_expiring` | Medium | All | FSBP ACM.1 |

### Third-party and external access (2)

Resources and roles shared with accounts outside the organisation.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| Resources shared outside the organisation | `ram_external_shares` | Medium | All |   |
| Roles for outside vendors | `vendor_roles` | Low | All |   |

### Ownership and accountability (7)

Every account has a current, reachable owner and security contact.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| No owner tagged on the account | `owner_missing` | Medium | All |   |
| Owner not found in the directory | `owner_not_found` | High | All |   |
| No security contact on the account | `security_contact` | Low | All | FSBP Account.1 |
| Non-production account in a production OU | `misplaced_account` | Low | All |   |
| No billing contact on the account | `billing_contact` | Low | All |   |
| No operations contact on the account | `operations_contact` | Low | All |   |
| Required account tags missing | `account_tags_missing` | Low | All |   |

### Cost control (1)

Spend is planned, watched and owned.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| No budget on the account | `budgets_none` | Low | All |   |

### AI services (4)

AI model use is logged and governed.

| Rule | Id | Severity | Applies to | References |
|---|---|---|---|---|
| Bedrock used without invocation logging | `bedrock_no_logging` | Low | All |   |
| Bedrock used without guardrails | `bedrock_no_guardrails` | Low | All |   |
| SageMaker notebooks with direct internet access | `sagemaker_notebook_internet` | Medium | All | FSBP SageMaker.2 |
| AI services used where not approved | `ai_unapproved` | Low | All |   |
