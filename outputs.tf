#region OIDC and IAM Outputs

output "role_arn" {
  description = "ARN of the IAM role for GitHub Actions to assume"
  value       = aws_iam_role.github_actions.arn
}

output "oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC identity provider"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}

output "role_name" {
  description = "Name of the IAM role for GitHub Actions"
  value       = aws_iam_role.github_actions.name
}

#endregion

#region Bedrock Outputs

output "bedrock_policy_arn" {
  description = "ARN of the IAM policy for Bedrock access"
  value       = aws_iam_policy.bedrock_access.arn
}

output "allowed_models" {
  description = "List of Bedrock model IDs that the role has access to"
  value       = var.allowed_models
}

output "guardrail_id" {
  description = "ID of the Bedrock Guardrail (if enabled)"
  value       = var.enable_bedrock_guardrails ? aws_bedrock_guardrail.quorum[0].guardrail_id : null
}

output "guardrail_arn" {
  description = "ARN of the Bedrock Guardrail (if enabled)"
  value       = var.enable_bedrock_guardrails ? aws_bedrock_guardrail.quorum[0].guardrail_arn : null
}

output "guardrail_version" {
  description = "Version of the Bedrock Guardrail (if enabled)"
  value       = var.enable_bedrock_guardrails ? aws_bedrock_guardrail.quorum[0].version : null
}

#endregion

#region Storage Outputs

output "dynamodb_table_name" {
  description = "Name of the DynamoDB metrics table"
  value       = aws_dynamodb_table.quorum_metrics.name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB metrics table"
  value       = aws_dynamodb_table.quorum_metrics.arn
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for raw model outputs"
  value       = aws_s3_bucket.quorum_outputs.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket for raw model outputs"
  value       = aws_s3_bucket.quorum_outputs.arn
}

output "kms_key_arn" {
  description = "ARN of the KMS key for storage encryption (if enabled)"
  value       = var.enable_kms_encryption ? aws_kms_key.quorum[0].arn : null
}

output "kms_key_id" {
  description = "ID of the KMS key for storage encryption (if enabled)"
  value       = var.enable_kms_encryption ? aws_kms_key.quorum[0].key_id : null
}

#endregion

#region Observability Outputs

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for review logs"
  value       = var.enable_observability ? aws_cloudwatch_log_group.quorum[0].name : null
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch Log Group for review logs"
  value       = var.enable_observability ? aws_cloudwatch_log_group.quorum[0].arn : null
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alert notifications (if enabled)"
  value       = var.enable_alerts ? aws_sns_topic.quorum_alerts[0].arn : null
}

output "budget_name" {
  description = "Name of the AWS Budget for cost tracking (if enabled)"
  value       = var.enable_alerts ? aws_budgets_budget.quorum[0].name : null
}

output "dashboard_name" {
  description = "Name of the CloudWatch Dashboard (if enabled)"
  value       = var.enable_dashboard && var.enable_observability ? aws_cloudwatch_dashboard.quorum[0].dashboard_name : null
}

output "dashboard_url" {
  description = "URL to access the CloudWatch Dashboard (if enabled)"
  value       = var.enable_dashboard && var.enable_observability ? "https://${data.aws_region.current.id}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.id}#dashboards:name=${var.project_name}-${var.environment}" : null
}

output "metrics_namespace" {
  description = "CloudWatch metrics namespace for Quorum metrics"
  value       = var.enable_observability ? "Quorum/${var.environment}" : null
}

#endregion
