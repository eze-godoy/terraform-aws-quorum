# Terraform-AWS-Quorum

Terraform module for Quorum AI code review infrastructure. OIDC federation, Bedrock access, DynamoDB metrics, S3 storage, CloudWatch observability - zero static credentials.

[![Terraform CI](https://github.com/eze-godoy/terraform-aws-quorum/actions/workflows/terraform-ci.yml/badge.svg)](https://github.com/eze-godoy/terraform-aws-quorum/actions/workflows/terraform-ci.yml)
[![Release](https://github.com/eze-godoy/terraform-aws-quorum/actions/workflows/release.yml/badge.svg)](https://github.com/eze-godoy/terraform-aws-quorum/actions/workflows/release.yml)

## Features

- **OIDC Federation**: Secure GitHub Actions to AWS authentication without static credentials
- **IAM Role**: Least-privilege role scoped to specific repositories
- **Bedrock Access**: Pre-configured model access for AI code review
- **Optional Storage**: S3 bucket and DynamoDB table for future analytics (disabled by default)
- **CloudWatch**: Comprehensive logging, metrics, and alarms
- **Enterprise Ready**: KMS encryption, budget alerts, guardrails

## Usage

### Minimal Deployment (Recommended)

By default, only IAM role and Bedrock permissions are created - no S3 or DynamoDB:

```hcl
module "quorum" {
  source = "github.com/eze-godoy/terraform-aws-quorum?ref=v1.0.0"

  github_org   = "your-org"
  github_repos = ["repo1", "repo2"]  # Or use ["*"] for all repos

  allowed_models = [
    "anthropic.claude-sonnet-4-20250514-v1:0"
  ]
}
```

### Full Deployment (With Storage)

Enable S3 and DynamoDB for future cost tracking and analytics features:

```hcl
module "quorum" {
  source = "github.com/eze-godoy/terraform-aws-quorum?ref=v1.0.0"

  github_org   = "your-org"
  github_repos = ["repo1", "repo2"]

  allowed_models = [
    "anthropic.claude-sonnet-4-20250514-v1:0"
  ]

  # Enable optional storage
  enable_storage   = true
  s3_bucket_suffix = "your-org-prod"  # Optional: auto-generated if not provided
}
```

### GitHub Actions Integration

```yaml
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
```
