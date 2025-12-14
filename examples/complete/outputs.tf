#region Outputs

output "role_arn" {
  description = "ARN of the IAM role for GitHub Actions"
  value       = module.quorum.role_arn
}

output "oidc_provider_arn" {
  description = "ARN of the OIDC identity provider"
  value       = module.quorum.oidc_provider_arn
}

output "role_name" {
  description = "Name of the IAM role"
  value       = module.quorum.role_name
}

output "bedrock_policy_arn" {
  description = "ARN of the Bedrock access policy"
  value       = module.quorum.bedrock_policy_arn
}

output "allowed_models" {
  description = "List of Bedrock models the role can invoke"
  value       = module.quorum.allowed_models
}

output "guardrail_id" {
  description = "Bedrock Guardrail ID (if enabled)"
  value       = module.quorum.guardrail_id
}

#endregion
