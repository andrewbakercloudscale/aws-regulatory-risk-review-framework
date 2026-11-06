# Developer Compromise Report

The fifth report. Its premise: **developers' laptops and the pipelines are already compromised**, as in
the 2026 Binance attack, where a tampered developer tool on one engineer's laptop led to a deployment token
on another's, a container deployed by hand, and the wallet signing service signing the attacker's
transactions. So no money moving flow may rest on trusting who changes it. Each must be:

- **immutable**: it cannot be changed, or every change can be undone and proven (Object Lock in compliance
  mode, Lambda code signing, immutable image tags, point in time recovery); or
- **observable**: every change is recorded by CloudTrail and raises an alert.

It runs only in the accounts you pick, with strict rules.

## Running it

1. Open a live scan of the organisation (any scan; it needs the accounts list).
2. Choose **Developer Compromise**. The picker lists every account in the organisation:
   - on a scan with no checks yet, production accounts whose names look like payment or channel accounts are
     ticked to start with;
   - on a scan that already has checks, the accounts checked last time are ticked, so **Run the checks** reads
     them all again. Untick one to keep its earlier result; tick a new one to add it;
   - **Clear all** unticks everything, and the count line says how many accounts are read again, new and kept;
   - up to 40 accounts in one run. **Back to the report** leaves the picker without running.
3. A new scan is saved: the earlier scan's other reports are kept, with the checks for the picked accounts
   added. Each account takes a few minutes.

PDF: `exitrisk pdf <scan-id> --view compromise`.

## Reading the report

- **Executive summary**: how many money moving flows have a gap, the worst accounts, and what to fix first.
- **Where to focus**: four charts (accounts by risk, gaps by account, gaps by kind of resource and findings by
  control area). Select an account in any of them to narrow every table to it; **Show all accounts** clears it.
- **Show only critical** hides everything below critical.
- **Money moving resources with a gap** lists only what needs action: **Unseen** (nothing prevents a change and
  nothing records it) and **Recorded, no alert** (CloudTrail records it but nobody is told). Resources that are
  immutable or alerted are counted, not listed.
- Rules AWS services create for themselves (Inspector, Auto Scaling and others marked as managed) never count as
  alerts: they watch for their own purposes, not for a person changing a payment flow.
- **Export table to PDF** prints the flows table on its own.

## How a path is decided

Every "who can do what" is decided by AWS's own policy simulator (`iam:SimulatePrincipalPolicy`), so
identity policies, permission boundaries, organisation guardrails (SCPs) and, where read, the resource's own
policy are all weighed. The scan supplies the principal, account, organisation and region as context. A path
that depends on where the call comes from (a source address or VPC endpoint) is shown as "only from certain
networks", never as open. A principal with no Allow statement that could cover an action is not asked: with
nothing allowing it, the answer is no.

Who is counted: IAM Identity Center permission sets, SAML roles, IAM users, roles switched into from another
account of the organisation (such as a jump account), pipeline roles (OIDC, CodeBuild, CodePipeline,
runners) and roles trusted by an account outside the organisation. AWS's and the organisation's own tooling
(Control Tower, StackSets, monitoring roles) is left out. Pipelines count as compromised too.

Switching off the trail, GuardDuty or an alert rule is simulated on the real trail, detector and rule, so an
SCP that names them is weighed. An organisation trail cannot be changed from a member account at all.

## What is checked

| Area | Checks |
|---|---|
| Who can change money moving resources | Write S3 objects, delete versions or stop versioning; write DynamoDB items; read the database admin password, reset it, connect with IAM auth, run SQL through the Data API; replace function code or settings; call a payment function; deploy an ECS service; push an image; read a secret; sign with a KMS signing key; call an IAM protected API |
| Credentials on a laptop | IAM user access keys that can change production, console users without MFA, root keys or no MFA, sign in sessions over 4 hours for people with write access |
| Pipelines | OIDC trust with no subject, a wildcard subject or every branch; outside accounts with no external ID; payment functions without code signing; mutable image tags where services deploy by tag |
| Open to a laptop | APIs with methods that need no sign in, function URLs with no auth, function policies open to anyone, public databases |
| Observability | No trail; trail log file validation off; data events off for payment buckets and tables; read events off (secret reads, signatures); GuardDuty and its S3 protection; alerts on changes by people; alerts on becoming a high risk role; alerts on payment file changes; API access logs |
| Tamper evidence | Payment buckets without versioning or Object Lock; payment tables without point in time recovery; payment databases without activity streams; payment secrets not rotated |
| Changes by hand | Writes by people's own sessions in the last 30 days, from CloudTrail, with the tool: CLI, SDK and Terraform from a laptop stand out from the console |

"Money moving" is decided from names and tags (payment, card, ledger, settlement, EFT, DebiCheck, SWIFT,
wallet, signer and similar), with the account's own name taken out first. Every resource in a picked
account is checked; money moving raises the severity. Access logs and Athena results are left out.

## Databases: the proxy and the known paths

Only known paths may reach a database directly; everything else is treated like a laptop and must go
through the database proxy. For each database the scan reads every source its security groups let reach
its port:

- a security group used by this account's workloads (Lambda, ECS tasks, EC2 instances) is a **known** path;
- the proxy's security group is the **proxy**. Nothing has to be set: the proxy is always in the same
  account, and the scan finds it by itself as an RDS Proxy, a load balancer target group whose name carries
  pg-proxy, PgBouncer, Pgpool or PgCat (Kubernetes shortens it, for example `gkpgprox`) with the groups of the
  instances or addresses behind it, an ECS service running such an image, or a security group with such a
  name that compute uses (the group of the proxy's own cache or database does not count). Any other proxy
  group can be added in the settings;
- every address range (a CIDR or a prefix list), a group in another account, or a group nothing here uses is
  **unknown**: anything behind it, laptops through Zscaler or the VPN included, can connect directly. A range
  can be listed as known in the settings, with its reason.

Zscaler's published egress ranges (from config.zscaler.com, cached for a day) and any dedicated ranges you
add label an unknown range as a laptop range. An open port to an unknown source on a payment database is
critical; the finding says which proxy already runs in the account, so the fix is to route access through
it, or that no proxy was found. When a database is reachable only by the proxy and known workloads, a person's IAM or password
path to it is lowered one level.

## How severity is set

The rule's severity (data/compromise.yaml) is lowered one level when CloudTrail records the action, two when
an alert in the account fires on it, and one more when the path works only from certain networks. Findings
for the same change, by the same principals, with the same detection, are one line naming the resources.

## What it cannot see

Grants inside databases, the network path from a laptop (VPN, office), the laptops themselves, payment file
control totals, Kubernetes RBAC, alerts in a central security account, roles in a jump account, and who is
assigned each permission set. These are listed in the report's last section, never shown as passed.
