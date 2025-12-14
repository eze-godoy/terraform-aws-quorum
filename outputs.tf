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
