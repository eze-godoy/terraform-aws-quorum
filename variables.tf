#region GitHub OIDC Configuration

variable "github_org" {
  description = "GitHub organization name for OIDC trust policy"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", var.github_org))
    error_message = "GitHub organization name must be valid (alphanumeric with hyphens, not starting/ending with hyphen)."
  }
}

variable "github_repos" {
  description = "List of GitHub repository names for OIDC trust policy. Use [\"*\"] for all repos, or specify multiple repos like [\"repo1\", \"repo2\"]"
  type        = list(string)

  validation {
    condition     = length(var.github_repos) > 0
    error_message = "At least one GitHub repository must be specified."
  }
}

#endregion

#region Bedrock Configuration

variable "allowed_models" {
  description = "List of Bedrock model IDs to allow access to. Run 'aws bedrock list-foundation-models' to see available models in your region."
  type        = list(string)

  validation {
    condition     = length(var.allowed_models) > 0
    error_message = "At least one Bedrock model must be specified."
  }
}

variable "enable_bedrock_guardrails" {
  description = "Enable Bedrock Guardrails for content filtering (enterprise feature)"
  type        = bool
  default     = false
}

variable "guardrail_config" {
  description = "Configuration for Bedrock Guardrails when enabled"
  type = object({
    name                     = optional(string, "quorum-guardrail")
    blocked_input_messaging  = optional(string, "Your input contains content that is not allowed.")
    blocked_output_messaging = optional(string, "The model response was filtered due to content policy.")
    content_filters_config = optional(list(object({
      type            = string
      input_strength  = string
      output_strength = string
    })), [])
  })
  default = {}
}

#endregion

#region Storage Configuration

variable "raw_outputs_retention_days" {
  description = "Number of days before transitioning raw outputs from Standard to Standard-IA storage"
  type        = number
  default     = 30

  validation {
    condition     = var.raw_outputs_retention_days >= 1 && var.raw_outputs_retention_days <= 365
    error_message = "Raw outputs retention must be between 1 and 365 days."
  }
}

variable "enable_kms_encryption" {
  description = "Enable dedicated KMS key for DynamoDB and S3 encryption (if false, uses AWS managed keys)"
  type        = bool
  default     = true
}

variable "enable_point_in_time_recovery" {
  description = "Enable DynamoDB point-in-time recovery for data protection"
  type        = bool
  default     = true
}

variable "s3_bucket_suffix" {
  description = "Unique suffix for S3 bucket name (required for global uniqueness). Example: 'myorg-prod' results in 'quorum-outputs-myorg-prod'"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.s3_bucket_suffix)) && length(var.s3_bucket_suffix) >= 3 && length(var.s3_bucket_suffix) <= 40
    error_message = "S3 bucket suffix must be 3-40 characters, lowercase alphanumeric with hyphens, not starting/ending with hyphen."
  }
}

#endregion

#region General Configuration

variable "environment" {
  description = "Environment name for resource tagging"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project_name" {
  description = "Project name for resource tagging and AWS Budget cost filtering"
  type        = string
  default     = "quorum"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", var.project_name)) && length(var.project_name) >= 2 && length(var.project_name) <= 32
    error_message = "Project name must be 2-32 characters, lowercase alphanumeric with hyphens, starting with a letter."
  }
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

#endregion

#region Observability Configuration

variable "enable_observability" {
  description = "Enable CloudWatch observability features (log group, metric filters)"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Log Group retention period in days"
  type        = number
  default     = 30

  validation {
    condition     = contains([7, 14, 30, 60, 90, 180, 365], var.log_retention_days)
    error_message = "Log retention must be one of: 7, 14, 30, 60, 90, 180, 365 days."
  }
}

variable "enable_alerts" {
  description = "Enable budget alerts and SNS notifications"
  type        = bool
  default     = false

  validation {
    condition     = var.enable_alerts == false || var.alert_email != ""
    error_message = "alert_email is required when enable_alerts is true."
  }
}

variable "monthly_budget_usd" {
  description = "Monthly budget threshold in USD for cost alerts"
  type        = number
  default     = 100

  validation {
    condition     = var.monthly_budget_usd >= 1 && var.monthly_budget_usd <= 100000
    error_message = "Monthly budget must be between 1 and 100,000 USD."
  }
}

variable "alert_email" {
  description = "Email address for budget and alarm notifications (required when enable_alerts is true)"
  type        = string
  default     = ""

  validation {
    condition     = var.alert_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.alert_email))
    error_message = "Alert email must be a valid email address or empty string."
  }
}

variable "enable_dashboard" {
  description = "Enable CloudWatch Dashboard for metrics visualization"
  type        = bool
  default     = false
}

variable "alarm_config" {
  description = "Configuration for CloudWatch alarms"
  type = object({
    error_rate_threshold     = optional(number, 5)     # Errors per minute threshold
    latency_p95_threshold_ms = optional(number, 30000) # P95 latency threshold in milliseconds
    evaluation_periods       = optional(number, 3)     # Number of periods for alarm evaluation
  })
  default = {}
}

#endregion
