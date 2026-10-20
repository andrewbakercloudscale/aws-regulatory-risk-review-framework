# List-only role for aws-regulatory-risk-review-framework deep scans.
# Apply once per member account (e.g. from your account-vending pipeline with a provider
# alias per account), or use iam/cloudformation/member-role-stackset.yaml with StackSets.

variable "scanner_account_id" {
  description = "Account the scanner runs from (normally the management account)"
  type        = string
}

variable "scanner_principal_arn" {
  description = "Optional: restrict trust to one role/user ARN in the scanner account"
  type        = string
  default     = ""
}

variable "role_name" {
  type    = string
  default = "ExitRiskReadOnly"
}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.scanner_principal_arn != "" ? var.scanner_principal_arn : "arn:${data.aws_partition.current.partition}:iam::${var.scanner_account_id}:root"]
    }
    condition {
      test     = "StringLike"
      variable = "sts:RoleSessionName"
      values   = ["exitrisk-*"]
    }
  }
}

resource "aws_iam_role" "exit_risk_read_only" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "inventory" {
  name   = "ExitRiskInventoryListOnly"
  role   = aws_iam_role.exit_risk_read_only.id
  policy = file("${path.module}/../member-account-role-policy.json")
}

output "role_arn" {
  value = aws_iam_role.exit_risk_read_only.arn
}
