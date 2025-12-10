# Terraform-AWS-Quorum

Terraform module for Quorum AI code review infrastructure. OIDC federation, Bedrock access, DynamoDB metrics, S3 storage, CloudWatch observability - zero static credentials.

[![Terraform CI](https://github.com/eze-godoy/terraform-aws-quorum/actions/workflows/terraform-ci.yml/badge.svg)](https://github.com/eze-godoy/terraform-aws-quorum/actions/workflows/terraform-ci.yml)
[![Release](https://github.com/eze-godoy/terraform-aws-quorum/actions/workflows/release.yml/badge.svg)](https://github.com/eze-godoy/terraform-aws-quorum/actions/workflows/release.yml)

## Features

- **OIDC Federation**: Secure GitHub Actions to AWS authentication without static credentials
- **IAM Role**: Least-privilege role scoped to specific repositories
- **Bedrock Access**: Pre-configured model access for AI code review
- **DynamoDB Metrics**: Single-table design for review metrics with TTL
- **S3 Storage**: Raw outputs with lifecycle policies (Standard → IA → Glacier)
- **CloudWatch**: Comprehensive logging, metrics, and alarms
- **Enterprise Ready**: VPC endpoints, KMS encryption, budget alerts

## Usage

```hcl
module "quorum" {
  source = "github.com/eze-godoy/terraform-aws-quorum?ref=v1.0.0"

  github_org  = "your-org"
  github_repo = "your-repo"  # Supports wildcards: "repo-*"

  environment       = "prod"
  monthly_budget_usd = 10
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
