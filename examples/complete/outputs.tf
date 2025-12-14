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

output "dynamodb_table_name" {
  description = "DynamoDB metrics table name"
  value       = module.quorum.dynamodb_table_name
}

output "s3_bucket_name" {
  description = "S3 bucket name for raw outputs"
  value       = module.quorum.s3_bucket_name
}

output "kms_key_arn" {
  description = "KMS key ARN (if enabled)"
  value       = module.quorum.kms_key_arn
}

#endregion
