#region Complete Example - Quorum AI Code Review Infrastructure

# This example demonstrates a complete deployment of the terraform-aws-quorum
# module with all available options configured.

module "quorum" {
  source = "../.."

  # GitHub OIDC Configuration
  github_org   = "eze-godoy"
  github_repos = ["*"] # Or specify multiple: ["terraform-aws-quorum", "quorum-action"]

  # Bedrock Model Access (required)
  # Run 'aws bedrock list-foundation-models' to see available models in your region
  allowed_models = [
    "anthropic.claude-3-7-sonnet-20250219-v1:0",
    "anthropic.claude-haiku-4-5-20251001-v1:0",
    "openai.gpt-oss-120b-1:0"
  ]

  # Bedrock Guardrails
  # Uncomment to enable content filtering:
  # enable_bedrock_guardrails = true
  # guardrail_config = {
  #   name = "quorum-guardrail"
  #   blocked_input_messaging  = "Your input contains content that is not allowed."
  #   blocked_output_messaging = "The model response was filtered due to content policy."
  # }

  # Storage Configuration
  raw_outputs_retention_days    = 30   # S3 Standard-IA transition in days
  enable_kms_encryption         = true # Use dedicated KMS key (recommended)
  enable_point_in_time_recovery = true # DynamoDB PITR for data protection

  environment = "dev"

  tags = {
    Project   = "quorum"
    Owner     = "eze-godoy"
    ManagedBy = "terraform"
    Example   = "complete"
  }
}

#endregion
