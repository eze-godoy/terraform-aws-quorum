#region Locals

locals {
  # Common tags applied to all resources
  # Ensures Project tag is always present for AWS Budget cost filtering
  common_tags = merge(var.tags, {
    Project = var.project_name
  })
}

#endregion

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

  tags = local.common_tags
}

#endregion

#region Data Sources

data "aws_caller_identity" "current" {}

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

  tags = local.common_tags
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

  # DynamoDB table access for metrics storage
  statement {
    sid    = "DynamoDBTableAccess"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem"
    ]
    resources = [aws_dynamodb_table.quorum_metrics.arn]
  }

  # DynamoDB GSI access for flexible queries
  statement {
    sid       = "DynamoDBGSIAccess"
    effect    = "Allow"
    actions   = ["dynamodb:Query"]
    resources = ["${aws_dynamodb_table.quorum_metrics.arn}/index/*"]
  }

  # S3 bucket access for raw model outputs
  statement {
    sid    = "S3BucketAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.quorum_outputs.arn,
      "${aws_s3_bucket.quorum_outputs.arn}/*"
    ]
  }

  # KMS access for encryption/decryption (only if KMS enabled)
  dynamic "statement" {
    for_each = var.enable_kms_encryption ? [1] : []
    content {
      sid    = "KMSAccess"
      effect = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ]
      resources = [aws_kms_key.quorum[0].arn]
    }
  }

  # CloudWatch Logs access for publishing review logs (only if observability enabled)
  dynamic "statement" {
    for_each = var.enable_observability ? [1] : []
    content {
      sid    = "CloudWatchLogsAccess"
      effect = "Allow"
      actions = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ]
      resources = [
        "${aws_cloudwatch_log_group.quorum[0].arn}:*"
      ]
    }
  }

  # CloudWatch Metrics access for publishing custom metrics (only if observability enabled)
  dynamic "statement" {
    for_each = var.enable_observability ? [1] : []
    content {
      sid    = "CloudWatchMetricsAccess"
      effect = "Allow"
      actions = [
        "cloudwatch:PutMetricData"
      ]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "cloudwatch:namespace"
        values   = ["Quorum/${var.environment}"]
      }
    }
  }
}

resource "aws_iam_policy" "bedrock_access" {
  name        = "quorum-bedrock-access-${var.environment}"
  description = "IAM policy for Quorum Bedrock model access"
  policy      = data.aws_iam_policy_document.bedrock_access.json

  tags = local.common_tags
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

  tags = local.common_tags
}

#endregion

#region KMS Encryption (Optional)

# Dedicated KMS key for encrypting DynamoDB and S3 data
# Provides more control over key rotation and access policies

resource "aws_kms_key" "quorum" {
  count = var.enable_kms_encryption ? 1 : 0

  description             = "KMS key for Quorum storage encryption (DynamoDB and S3)"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  # Key policy granting root account full access and enabling IAM policies
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ]
        Resource = "*"
      }
      ],
      # CloudWatch Logs encryption permission (only if observability enabled)
      var.enable_observability ? [
        {
          Sid    = "AllowCloudWatchLogsEncryption"
          Effect = "Allow"
          Principal = {
            Service = "logs.${data.aws_region.current.id}.amazonaws.com"
          }
          Action = [
            "kms:Encrypt*",
            "kms:Decrypt*",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:Describe*"
          ]
          Resource = "*"
          Condition = {
            ArnLike = {
              "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:log-group:/quorum/*"
            }
          }
        }
    ] : [])
  })

  tags = merge(local.common_tags, {
    Name = "quorum-${var.environment}"
  })
}

resource "aws_kms_alias" "quorum" {
  count = var.enable_kms_encryption ? 1 : 0

  name          = "alias/quorum-${var.environment}"
  target_key_id = aws_kms_key.quorum[0].key_id
}

#endregion

#region DynamoDB Metrics Table

# Single-table design for storing all Quorum metrics
# Supports flexible access patterns via GSIs:
# - GSI1: Model performance and date-based queries
# - GSI2: Entity type queries (REVIEW, FINDING, CONSENSUS)
# - GSI3: Category-based queries for future flexibility

resource "aws_dynamodb_table" "quorum_metrics" {
  name         = "quorum-metrics-${var.environment}"
  billing_mode = "PAY_PER_REQUEST" # On-demand for unpredictable workloads
  hash_key     = "PK"
  range_key    = "SK"

  # Primary key attributes
  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  # GSI1 attributes (Model/Date queries)
  attribute {
    name = "GSI1PK"
    type = "S"
  }

  attribute {
    name = "GSI1SK"
    type = "S"
  }

  # GSI2 attributes (Type-based queries)
  attribute {
    name = "GSI2PK"
    type = "S"
  }

  attribute {
    name = "GSI2SK"
    type = "S"
  }

  # GSI3 attributes (Flexible queries)
  attribute {
    name = "GSI3PK"
    type = "S"
  }

  attribute {
    name = "GSI3SK"
    type = "S"
  }

  # GSI1: Model performance comparison and date-based queries
  # PK patterns: MODEL#{model_id} or DATE#{YYYY-MM-DD}
  global_secondary_index {
    name            = "GSI1"
    hash_key        = "GSI1PK"
    range_key       = "GSI1SK"
    projection_type = "ALL"
  }

  # GSI2: Entity type queries (all reviews, all findings by severity)
  # PK patterns: TYPE#REVIEW, TYPE#FINDING#{severity}, TYPE#CONSENSUS
  global_secondary_index {
    name            = "GSI2"
    hash_key        = "GSI2PK"
    range_key       = "GSI2SK"
    projection_type = "ALL"
  }

  # GSI3: Category-based and future flexible queries
  # PK patterns: CATEGORY#{category}, USER#{username}
  global_secondary_index {
    name            = "GSI3"
    hash_key        = "GSI3PK"
    range_key       = "GSI3SK"
    projection_type = "ALL"
  }

  # TTL for automatic cleanup based on retention policy
  ttl {
    enabled        = true
    attribute_name = "ttl"
  }

  # Point-in-time recovery for data protection
  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  # Server-side encryption (KMS or AWS managed)
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.enable_kms_encryption ? aws_kms_key.quorum[0].arn : null
  }

  tags = merge(local.common_tags, {
    Name      = "quorum-metrics-${var.environment}"
    Component = "metrics-storage"
  })
}

#endregion

#region S3 Raw Outputs Bucket

# S3 bucket for storing raw model outputs (JSON responses)
# Object key structure: {repo}/{pr_number}/{model}/{timestamp}.json
#
# Checkov skips (tracked as backlog issues for optional future implementation)

resource "aws_s3_bucket" "quorum_outputs" {
  # checkov:skip=CKV_AWS_144:S3 cross-region replication
  # checkov:skip=CKV_AWS_18:S3 access logging
  # checkov:skip=CKV2_AWS_62:S3 event notifications
  bucket = "quorum-outputs-${var.s3_bucket_suffix}"

  tags = merge(local.common_tags, {
    Name      = "quorum-outputs-${var.environment}"
    Component = "raw-outputs-storage"
  })
}

resource "aws_s3_bucket_versioning" "quorum_outputs" {
  bucket = aws_s3_bucket.quorum_outputs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle policy for cost optimization
# Standard -> Standard-IA (configurable) -> Glacier (90d)
resource "aws_s3_bucket_lifecycle_configuration" "quorum_outputs" {
  bucket = aws_s3_bucket.quorum_outputs.id

  rule {
    id     = "transition-to-ia-and-glacier"
    status = "Enabled"

    filter {
      prefix = "" # Apply to all objects
    }

    transition {
      days          = var.raw_outputs_retention_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    # Handle noncurrent versions (due to versioning)
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = 60
      storage_class   = "GLACIER"
    }
  }

  # Abort incomplete multipart uploads after 7 days
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {
      prefix = "" # Apply to all objects
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Server-side encryption (KMS or AES-256)
resource "aws_s3_bucket_server_side_encryption_configuration" "quorum_outputs" {
  bucket = aws_s3_bucket.quorum_outputs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.enable_kms_encryption ? "aws:kms" : "AES256"
      kms_master_key_id = var.enable_kms_encryption ? aws_kms_key.quorum[0].arn : null
    }
    bucket_key_enabled = var.enable_kms_encryption
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "quorum_outputs" {
  bucket = aws_s3_bucket.quorum_outputs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#endregion

#region CloudWatch Observability

# CloudWatch Log Group for Quorum review logs
# GitHub Actions will publish structured JSON logs here for metric extraction
resource "aws_cloudwatch_log_group" "quorum" {
  # checkov:skip=CKV_AWS_338:CloudWatch Log retention is managed by user requirement
  count = var.enable_observability ? 1 : 0

  name              = "/quorum/reviews/${var.environment}"
  retention_in_days = var.log_retention_days

  # Use KMS encryption if enabled
  kms_key_id = var.enable_kms_encryption ? aws_kms_key.quorum[0].arn : null

  tags = merge(local.common_tags, {
    Name      = "quorum-reviews-${var.environment}"
    Component = "observability"
  })
}

#endregion

#region CloudWatch Metric Filters

# Metric Filter: Review Count
# Counts completed reviews from log events
resource "aws_cloudwatch_log_metric_filter" "review_count" {
  count = var.enable_observability ? 1 : 0

  name           = "quorum-review-count-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.quorum[0].name
  pattern        = "{ $.event_type = \"REVIEW_COMPLETED\" }"

  metric_transformation {
    name          = "QuorumReviewCount"
    namespace     = "Quorum/${var.environment}"
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

# Metric Filter: Tokens Used
# Extracts total token count from review events
resource "aws_cloudwatch_log_metric_filter" "tokens_used" {
  count = var.enable_observability ? 1 : 0

  name           = "quorum-tokens-used-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.quorum[0].name
  pattern        = "{ $.event_type = \"REVIEW_COMPLETED\" && $.tokens_used = * }"

  metric_transformation {
    name          = "QuorumTokensUsed"
    namespace     = "Quorum/${var.environment}"
    value         = "$.tokens_used"
    default_value = "0"
    unit          = "Count"
  }
}

# Metric Filter: Estimated Cost
# Extracts estimated cost in USD from review events
resource "aws_cloudwatch_log_metric_filter" "cost_usd" {
  count = var.enable_observability ? 1 : 0

  name           = "quorum-cost-usd-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.quorum[0].name
  pattern        = "{ $.event_type = \"REVIEW_COMPLETED\" && $.cost_usd = * }"

  metric_transformation {
    name          = "QuorumCostUSD"
    namespace     = "Quorum/${var.environment}"
    value         = "$.cost_usd"
    default_value = "0"
    unit          = "None"
  }
}

# Metric Filter: Latency
# Extracts review latency in milliseconds for P95 calculations
resource "aws_cloudwatch_log_metric_filter" "latency" {
  count = var.enable_observability ? 1 : 0

  name           = "quorum-latency-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.quorum[0].name
  pattern        = "{ $.event_type = \"REVIEW_COMPLETED\" && $.latency_ms = * }"

  metric_transformation {
    name          = "QuorumLatencyMs"
    namespace     = "Quorum/${var.environment}"
    value         = "$.latency_ms"
    default_value = "0"
    unit          = "Milliseconds"
  }
}

# Metric Filter: Error Count
# Counts review errors for error rate calculations
resource "aws_cloudwatch_log_metric_filter" "error_count" {
  count = var.enable_observability ? 1 : 0

  name           = "quorum-error-count-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.quorum[0].name
  pattern        = "{ $.event_type = \"REVIEW_ERROR\" }"

  metric_transformation {
    name          = "QuorumErrorCount"
    namespace     = "Quorum/${var.environment}"
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

#endregion

#region SNS Alert Topic (Optional)

# SNS Topic for alert notifications
resource "aws_sns_topic" "quorum_alerts" {
  count = var.enable_alerts ? 1 : 0

  name = "quorum-alerts-${var.environment}"

  # KMS encryption for SNS (if enabled)
  kms_master_key_id = var.enable_kms_encryption ? aws_kms_key.quorum[0].id : null

  tags = merge(local.common_tags, {
    Name      = "quorum-alerts-${var.environment}"
    Component = "alerting"
  })
}

# SNS Topic Policy (allows CloudWatch and Budgets to publish)
resource "aws_sns_topic_policy" "quorum_alerts" {
  count = var.enable_alerts ? 1 : 0

  arn = aws_sns_topic.quorum_alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchAlarms"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.quorum_alerts[0].arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:cloudwatch:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:alarm:quorum-*"
          }
        }
      },
      {
        Sid    = "AllowBudgetsNotifications"
        Effect = "Allow"
        Principal = {
          Service = "budgets.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.quorum_alerts[0].arn
      }
    ]
  })
}

# Email subscription for alerts
resource "aws_sns_topic_subscription" "email" {
  count = var.enable_alerts && var.alert_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.quorum_alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

#endregion

#region AWS Budget (Optional)

# AWS Budget for Quorum monthly cost tracking
# Uses AWS Budgets API for accurate cost tracking
# Filters costs by Project tag to track only Quorum-related resources
resource "aws_budgets_budget" "quorum" {
  count = var.enable_alerts ? 1 : 0

  name         = "quorum-monthly-${var.environment}"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Filter costs by Quorum Project tag
  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Project$${var.project_name}"]
  }

  # Notification at 80% of budget (actual spend)
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.quorum_alerts[0].arn]
  }

  # Notification at 100% of budget (actual spend)
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.quorum_alerts[0].arn]
  }

  # Forecasted notification at 100%
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_sns_topic_arns = [aws_sns_topic.quorum_alerts[0].arn]
  }

  tags = merge(local.common_tags, {
    Name      = "quorum-monthly-${var.environment}"
    Component = "cost-management"
  })
}

#endregion

#region CloudWatch Alarms (Optional)

# Alarm: High Error Rate
# Triggers when error count exceeds threshold within evaluation period
resource "aws_cloudwatch_metric_alarm" "error_rate" {
  count = var.enable_alerts && var.enable_observability ? 1 : 0

  alarm_name          = "quorum-high-error-rate-${var.environment}"
  alarm_description   = "Quorum review error rate exceeded threshold"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = var.alarm_config.evaluation_periods
  metric_name         = "QuorumErrorCount"
  namespace           = "Quorum/${var.environment}"
  period              = 60
  statistic           = "Sum"
  threshold           = var.alarm_config.error_rate_threshold
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.quorum_alerts[0].arn]
  ok_actions    = [aws_sns_topic.quorum_alerts[0].arn]

  tags = merge(local.common_tags, {
    Name      = "quorum-high-error-rate-${var.environment}"
    Component = "alerting"
  })
}

# Alarm: High Latency (P95)
# Triggers when P95 latency exceeds threshold
resource "aws_cloudwatch_metric_alarm" "high_latency" {
  count = var.enable_alerts && var.enable_observability ? 1 : 0

  alarm_name          = "quorum-high-latency-${var.environment}"
  alarm_description   = "Quorum review P95 latency exceeded threshold"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = var.alarm_config.evaluation_periods
  metric_name         = "QuorumLatencyMs"
  namespace           = "Quorum/${var.environment}"
  period              = 300
  extended_statistic  = "p95"
  threshold           = var.alarm_config.latency_p95_threshold_ms
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.quorum_alerts[0].arn]
  ok_actions    = [aws_sns_topic.quorum_alerts[0].arn]

  tags = merge(local.common_tags, {
    Name      = "quorum-high-latency-${var.environment}"
    Component = "alerting"
  })
}

#endregion

#region CloudWatch Dashboard (Optional)

# CloudWatch Dashboard for Quorum metrics visualization
# Shows: reviews/day, error rate, cost/day, tokens/day, P95 latency
resource "aws_cloudwatch_dashboard" "quorum" {
  count = var.enable_dashboard && var.enable_observability ? 1 : 0

  dashboard_name = "quorum-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      # Row 1: Reviews per day and Errors
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Reviews per Day"
          view   = "timeSeries"
          region = data.aws_region.current.id
          metrics = [
            ["Quorum/${var.environment}", "QuorumReviewCount", { stat = "Sum", period = 86400 }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Error Rate"
          view   = "timeSeries"
          region = data.aws_region.current.id
          metrics = [
            ["Quorum/${var.environment}", "QuorumErrorCount", { stat = "Sum", period = 300, color = "#d62728" }]
          ]
        }
      },
      # Row 2: Cost per day and Tokens Used
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Estimated Cost per Day (USD)"
          view   = "timeSeries"
          region = data.aws_region.current.id
          metrics = [
            ["Quorum/${var.environment}", "QuorumCostUSD", { stat = "Sum", period = 86400 }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Tokens Used per Day"
          view   = "timeSeries"
          region = data.aws_region.current.id
          metrics = [
            ["Quorum/${var.environment}", "QuorumTokensUsed", { stat = "Sum", period = 86400 }]
          ]
        }
      },
      # Row 3: P95 Latency
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 24
        height = 6
        properties = {
          title  = "Review Latency (P95)"
          view   = "timeSeries"
          region = data.aws_region.current.id
          metrics = [
            ["Quorum/${var.environment}", "QuorumLatencyMs", { stat = "p95", period = 300 }]
          ]
          yAxis = {
            left = {
              label     = "Milliseconds"
              showUnits = false
            }
          }
        }
      },
      # Row 4: Summary stats (30-day totals)
      {
        type   = "metric"
        x      = 0
        y      = 18
        width  = 6
        height = 6
        properties = {
          title  = "Total Reviews (30d)"
          view   = "singleValue"
          region = data.aws_region.current.id
          period = 2592000
          metrics = [
            ["Quorum/${var.environment}", "QuorumReviewCount", { stat = "Sum" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 6
        y      = 18
        width  = 6
        height = 6
        properties = {
          title  = "Total Cost (30d)"
          view   = "singleValue"
          region = data.aws_region.current.id
          period = 2592000
          metrics = [
            ["Quorum/${var.environment}", "QuorumCostUSD", { stat = "Sum" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 18
        width  = 6
        height = 6
        properties = {
          title  = "Avg Latency (30d)"
          view   = "singleValue"
          region = data.aws_region.current.id
          period = 2592000
          metrics = [
            ["Quorum/${var.environment}", "QuorumLatencyMs", { stat = "Average" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 18
        width  = 6
        height = 6
        properties = {
          title  = "Total Errors (30d)"
          view   = "singleValue"
          region = data.aws_region.current.id
          period = 2592000
          metrics = [
            ["Quorum/${var.environment}", "QuorumErrorCount", { stat = "Sum", color = "#d62728" }]
          ]
        }
      }
    ]
  })
}

#endregion
