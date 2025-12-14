#region OIDC Identity Provider

# Creates an OpenID Connect identity provider for GitHub Actions
# This enables secure, credential-free authentication from GitHub to AWS
# Reference: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services

data "tls_certificate" "github_actions" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github_actions.certificates[0].sha1_fingerprint]

  tags = var.tags
}

#endregion

#region IAM Role

# Creates an IAM role that GitHub Actions can assume via OIDC
# The trust policy is scoped to specific repositories using StringLike condition

data "aws_iam_policy_document" "github_actions_assume_role" {
  statement {
    sid     = "GitHubActionsOIDC"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [for repo in var.github_repos : "repo:${var.github_org}/${repo}:*"]
    }
  }
}

resource "aws_iam_role" "github_actions" {
  name               = "quorum-github-actions-${var.environment}"
  description        = "IAM role for GitHub Actions OIDC authentication (Quorum)"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume_role.json

  tags = var.tags
}

#endregion

#region Bedrock Access Policy

# IAM policy granting Bedrock model invocation permissions
# Scoped to specific models for least-privilege access

data "aws_region" "current" {}

data "aws_iam_policy_document" "bedrock_access" {
  statement {
    sid    = "BedrockModelInvocation"
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream"
    ]
    resources = [
      for model in var.allowed_models :
      "arn:aws:bedrock:${data.aws_region.current.id}::foundation-model/${model}"
    ]
  }

  # Allow listing models for discovery
  # Note: bedrock:ListFoundationModels does not support resource-level permissions per AWS Service Authorization Reference
  # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonbedrock.html
  statement {
    sid       = "BedrockListModels"
    effect    = "Allow"
    actions   = ["bedrock:ListFoundationModels"]
    resources = ["*"]
  }

  # Allow getting details for specific allowed models
  statement {
    sid     = "BedrockGetModel"
    effect  = "Allow"
    actions = ["bedrock:GetFoundationModel"]
    resources = [
      for model in var.allowed_models :
      "arn:aws:bedrock:${data.aws_region.current.id}::foundation-model/${model}"
    ]
  }

  # Guardrail permissions (only if guardrails are enabled)
  dynamic "statement" {
    for_each = var.enable_bedrock_guardrails ? [1] : []
    content {
      sid    = "BedrockGuardrailAccess"
      effect = "Allow"
      actions = [
        "bedrock:ApplyGuardrail",
        "bedrock:GetGuardrail"
      ]
      resources = [
        aws_bedrock_guardrail.quorum[0].guardrail_arn
      ]
    }
  }
}

resource "aws_iam_policy" "bedrock_access" {
  name        = "quorum-bedrock-access-${var.environment}"
  description = "IAM policy for Quorum Bedrock model access"
  policy      = data.aws_iam_policy_document.bedrock_access.json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "bedrock_access" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.bedrock_access.arn
}

#endregion

#region Bedrock Guardrails (Optional)

# Bedrock Guardrails for content filtering - enterprise feature
# Demonstrates production-readiness and security consciousness

resource "aws_bedrock_guardrail" "quorum" {
  count = var.enable_bedrock_guardrails ? 1 : 0

  name                      = "${var.guardrail_config.name}-${var.environment}"
  description               = "Content filtering guardrail for Quorum AI code review"
  blocked_input_messaging   = var.guardrail_config.blocked_input_messaging
  blocked_outputs_messaging = var.guardrail_config.blocked_output_messaging

  # Content policy configuration (uses defaults if none specified)
  content_policy_config {
    dynamic "filters_config" {
      for_each = length(var.guardrail_config.content_filters_config) > 0 ? var.guardrail_config.content_filters_config : [
        { type = "HATE", input_strength = "HIGH", output_strength = "HIGH" },
        { type = "INSULTS", input_strength = "HIGH", output_strength = "HIGH" },
        { type = "SEXUAL", input_strength = "HIGH", output_strength = "HIGH" },
        { type = "VIOLENCE", input_strength = "HIGH", output_strength = "HIGH" },
        { type = "MISCONDUCT", input_strength = "HIGH", output_strength = "HIGH" },
        { type = "PROMPT_ATTACK", input_strength = "HIGH", output_strength = "NONE" }
      ]
      content {
        type            = filters_config.value.type
        input_strength  = filters_config.value.input_strength
        output_strength = filters_config.value.output_strength
      }
    }
  }

  tags = var.tags
}

#endregion
