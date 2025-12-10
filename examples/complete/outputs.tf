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

#endregion
