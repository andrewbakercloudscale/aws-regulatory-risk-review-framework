# IAM Identity Center permission set for aws-regulatory-risk-review-framework.
# Apply in the Identity Center administration account (the management account or its delegated
# administrator). It creates a read-only permission set and, if principal_id is given, assigns it
# in the management account so the user can pick it in the console's "AWS sign-in".

variable "management_account_id" {
  description = "Organization management (payer) account the scan runs in"
  type        = string
}

variable "principal_id" {
  description = "Optional: Identity Store user or group id to assign the permission set to"
  type        = string
  default     = ""
}

variable "principal_type" {
  description = "USER or GROUP"
  type        = string
  default     = "GROUP"
}

variable "permission_set_name" {
  type    = string
  default = "ExitRiskReadOnly"
}

data "aws_ssoadmin_instances" "this" {}

locals {
  instance_arn = tolist(data.aws_ssoadmin_instances.this.arns)[0]
}

resource "aws_ssoadmin_permission_set" "exit_risk" {
  name             = var.permission_set_name
  description      = "Read-only: Organizations structure and Cost Explorer spend for the AWS exit-risk review"
  instance_arn     = local.instance_arn
  session_duration = "PT4H"
}

resource "aws_ssoadmin_permission_set_inline_policy" "exit_risk" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.exit_risk.arn
  inline_policy      = file("${path.module}/../../management-account-policy.json")
}

resource "aws_ssoadmin_account_assignment" "management" {
  count              = var.principal_id != "" ? 1 : 0
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.exit_risk.arn
  principal_id       = var.principal_id
  principal_type     = var.principal_type
  target_id          = var.management_account_id
  target_type        = "AWS_ACCOUNT"
}

output "permission_set_arn" {
  value = aws_ssoadmin_permission_set.exit_risk.arn
}
