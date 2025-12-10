# Complete Example

This example demonstrates a complete deployment of the `terraform-aws-quorum` module.

## Usage

```bash
# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Apply changes
terraform apply
```

## What This Creates

- GitHub Actions OIDC identity provider
- IAM role for GitHub Actions with trust policy scoped to `eze-godoy/terraform-aws-quorum`

## After Deployment

1. Copy the `role_arn` output
2. Add it as a secret `AWS_ROLE_ARN` in your GitHub repository
3. Configure your GitHub Actions workflow to use OIDC authentication

## Cleanup

```bash
terraform destroy
```
