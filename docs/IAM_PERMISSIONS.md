# IAM permissions

Everything the tool does is read-only. There are two levels.

## 1. Spend-only scan (management account)

Enough for the full score, account ranking, charts and estimate. Attach
[`iam/management-account-policy.json`](../iam/management-account-policy.json) to the identity your AWS
profile uses in the **management (payer) account**:

| Action | Why |
|---|---|
| `organizations:DescribeOrganization` | Organisation id and management account id for the report header |
| `organizations:ListRoots`, `ListOrganizationalUnitsForParent` | Build the OU tree for the OU picker (with `ListAccountsForParent` for the account count per OU) |
| `organizations:ListAccountsForParent` | Accounts under the chosen OU, recursively, with names (for the name filter) |
| `ce:GetCostAndUsage` | Amortised spend by account × service × month |

Cost Explorer must be enabled in the management account (Billing console → Cost Explorer). Each
`GetCostAndUsage` request costs US$0.01; a scan makes two per 100 accounts plus pagination.

**Not the management account?** Organizations calls are refused, the scan falls back to the calling
account only, and the report says so on its data-quality panel. A member account that is a
[delegated administrator](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_delegate_policies.html)
for Organizations, with Cost Explorer access to linked accounts, also works.

### With IAM Identity Center (SSO) — the usual setup

Most organisations grant access through permission sets rather than IAM users. Ask the Identity
Center administrator to create a permission set, assign it to you **in the management account**, and
attach either:

- the inline policy [`iam/management-account-policy.json`](../iam/management-account-policy.json)
  (least privilege), or
- the AWS-managed policies `AWSOrganizationsReadOnlyAccess` and `AWSBillingReadOnlyAccess` (broader
  read-only, often already approved).

Ready to apply in the Identity Center administration account:
[Terraform](../iam/identity-center/terraform/main.tf) (`management_account_id`, optional
`principal_id`) or [CloudFormation](../iam/identity-center/cloudformation/permission-set.yaml).
An existing read-only permission set that already includes these actions (many organisations have a
"ReadOnly" or "CTO-Read" set) works as it is.

### Check before you scan

**Check access** in the console (or on the first screen) makes each call above once and shows
✓ / ✗ with the fix. When something is refused it writes the request for your administrator: your
identity, the management account id, the missing actions, and the policy, ready to copy or download.

## 2. Deep scan (member accounts)

Adds resource counts per account (Lambda functions, DynamoDB tables, state machines, CloudFormation
stacks, RDS engines…) which sharpen the effort estimate. The scanner assumes a role in each member account:

- Management-side permission: `sts:AssumeRole` on `arn:aws:iam::*:role/ExitRiskReadOnly`
  (included in the management policy above as `OptionalDeepScanAssumeMemberRole`; delete that statement
  if you will never deep-scan).
- Member role: **list-only** actions, [`iam/member-account-role-policy.json`](../iam/member-account-role-policy.json).
  The role cannot read data, objects, items, secrets or configuration — only enumerate and count.
- Trust: the scanner account (optionally one principal), and only sessions named `exitrisk-*`.

Deploy the role to every account in an OU with CloudFormation **StackSets** (service-managed
permissions, auto-deployment on):

```bash
aws cloudformation create-stack-set --stack-set-name exit-risk-readonly \
  --template-body file://iam/cloudformation/member-role-stackset.yaml \
  --parameters ParameterKey=ScannerAccountId,ParameterValue=111111111111 \
  --capabilities CAPABILITY_NAMED_IAM --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false

aws cloudformation create-stack-instances --stack-set-name exit-risk-readonly \
  --deployment-targets OrganizationalUnitIds=ou-ab12-cdef3456 --regions us-east-1
```

or with Terraform from your account-vending pipeline: [`iam/terraform`](../iam/terraform/main.tf).

Already have a read-only role everywhere (e.g. one with `ReadOnlyAccess` or `ViewOnlyAccess`)? Enter its
name in the scan dialog instead; any role that grants the list actions above works.

The management account itself is scanned with the profile's own credentials, not the role.

## What the tool does not need

No write permissions anywhere, no access to data plane APIs (S3 objects, DynamoDB items, secrets),
no CloudTrail, no Config aggregator, no CUR bucket. The tool holds no long-lived credentials: it uses
your profile's session, and member-account sessions last at most one hour.
