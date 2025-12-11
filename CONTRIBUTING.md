# Contributing to Terraform-AWS-Quorum

Thank you for your interest in contributing to this project! This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- [Terraform](https://www.terraform.io/downloads) >= 1.9.0
- [TFLint](https://github.com/terraform-linters/tflint) >= 0.54.0
- [Terraform-docs](https://terraform-docs.io/) >= 0.18.0
- [pre-commit](https://pre-commit.com/) >= 3.0.0
- [Trivy](https://trivy.dev/) >= 0.57.0
- [Checkov](https://www.checkov.io/) >= 3.0.0

### Quick Start

```bash
# Clone the repository
git clone https://github.com/eze-godoy/terraform-aws-quorum.git
cd terraform-aws-quorum

# Install pre-commit hooks
pre-commit install
pre-commit install --hook-type commit-msg

# Run all pre-commit checks
pre-commit run --all-files
```

## Development Workflow

### Branch Naming

Use descriptive branch names following this pattern:

- `feat/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `chore/description` - Maintenance tasks

### Commit Messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/). All commits must follow this format:

```text
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**

| Type | Description |
| ---- | ----------- |
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Formatting, missing semicolons, etc. |
| `refactor` | Code refactoring |
| `perf` | Performance improvements |
| `test` | Adding or updating tests |
| `build` | Build system or dependencies |
| `ci` | CI/CD configuration |
| `chore` | Maintenance tasks |
| `revert` | Reverting changes |

**Examples:**

```bash
feat(oidc): add support for multiple GitHub repositories
fix(iam): correct trust policy condition for wildcards
docs: update README with usage examples
ci: add security scanning to CI pipeline
```

### Pull Requests

1. Create a feature branch from `main`
2. Make your changes following the coding standards
3. Ensure all pre-commit hooks pass
4. Update documentation if needed
5. Submit a PR with a clear description

## Coding Standards

### Terraform Style Guide

- Use `terraform fmt` for consistent formatting
- Follow [HashiCorp's Terraform Style Conventions](https://developer.hashicorp.com/terraform/language/syntax/style)
- Use meaningful variable and resource names
- Include descriptions for all variables and outputs
- Group related resources logically

### Variable Naming

```hcl
# Good
variable "github_org" {
  description = "GitHub organization name"
  type        = string
}

# Bad
variable "org" {
  type = string
}
```

### Resource Naming

```hcl
# Use descriptive names with underscores
resource "aws_iam_role" "github_actions" { ... }

# Not
resource "aws_iam_role" "role1" { ... }
```

### Documentation

- Keep `README.md` updated with Terraform-docs
- Add inline comments for complex logic
- Document all variables with descriptions and examples

## Testing

### Local Validation

```bash
# Format check
terraform fmt -check -recursive

# Validate configuration
terraform init -backend=false
terraform validate

# Run TFLint
tflint --recursive

# Security scan
trivy config .
checkov -d .
```

### Pre-commit Checks

All the above checks run automatically via pre-commit. Ensure they pass before pushing:

```bash
pre-commit run --all-files
```

## Security

- Never commit sensitive values (API keys, passwords, etc.)
- Use AWS IAM best practices (least privilege)
- Report security vulnerabilities privately via GitHub Security Advisories

## Questions?

If you have questions, feel free to open an issue for discussion.

---

Thank you for contributing!
