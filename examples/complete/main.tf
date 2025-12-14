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
  s3_bucket_suffix              = "eze-godoy-dev" # Required: unique suffix for S3 bucket name
  raw_outputs_retention_days    = 30              # S3 Standard-IA transition in days
  enable_kms_encryption         = true            # Use dedicated KMS key (recommended)
  enable_point_in_time_recovery = true            # DynamoDB PITR for data protection

  # Observability Configuration
  enable_observability = true # CloudWatch log group and metric filters
  log_retention_days   = 30   # Log retention: 7, 14, 30, 60, 90, 180, 365

  # Alerting Configuration
  enable_alerts      = true
  monthly_budget_usd = 30                   # Monthly cost threshold in USD
  alert_email        = "alerts@example.com" # Email for notifications (requires confirmation)
  alarm_config = {
    error_rate_threshold     = 5     # Errors per minute threshold
    latency_p95_threshold_ms = 30000 # P95 latency threshold in milliseconds
    evaluation_periods       = 3     # Number of periods for alarm evaluation
  }

  # Dashboard Configuration
  enable_dashboard = true

  # General Configuration
  environment  = "dev"
  project_name = "quorum" # Used for tagging and AWS Budget cost filtering

  tags = {
    Owner     = "eze-godoy"
    ManagedBy = "terraform"
    Example   = "complete"
  }
}

#endregion
