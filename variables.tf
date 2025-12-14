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

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

#endregion
