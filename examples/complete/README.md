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

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.0 |

## Providers

No providers.

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_quorum"></a> [quorum](#module\_quorum) | ../.. | n/a |

## Resources

No resources.

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_allowed_models"></a> [allowed\_models](#output\_allowed\_models) | List of Bedrock models the role can invoke |
| <a name="output_bedrock_policy_arn"></a> [bedrock\_policy\_arn](#output\_bedrock\_policy\_arn) | ARN of the Bedrock access policy |
| <a name="output_dynamodb_table_name"></a> [dynamodb\_table\_name](#output\_dynamodb\_table\_name) | DynamoDB metrics table name |
| <a name="output_guardrail_id"></a> [guardrail\_id](#output\_guardrail\_id) | Bedrock Guardrail ID (if enabled) |
| <a name="output_kms_key_arn"></a> [kms\_key\_arn](#output\_kms\_key\_arn) | KMS key ARN (if enabled) |
| <a name="output_oidc_provider_arn"></a> [oidc\_provider\_arn](#output\_oidc\_provider\_arn) | ARN of the OIDC identity provider |
| <a name="output_role_arn"></a> [role\_arn](#output\_role\_arn) | ARN of the IAM role for GitHub Actions |
| <a name="output_role_name"></a> [role\_name](#output\_role\_name) | Name of the IAM role |
| <a name="output_s3_bucket_name"></a> [s3\_bucket\_name](#output\_s3\_bucket\_name) | S3 bucket name for raw outputs |
<!-- END_TF_DOCS -->
