#region Complete Example - Quorum AI Code Review Infrastructure

# This example demonstrates a complete deployment of the terraform-aws-quorum
# module with all available options configured.

module "quorum" {
  source = "../.."

  github_org   = "eze-godoy"
  github_repos = ["*"] # Or specify multiple: ["terraform-aws-quorum", "quorum-action"]

  environment = "dev"

  tags = {
    Project   = "quorum"
    Owner     = "eze-godoy"
    ManagedBy = "terraform"
    Example   = "complete"
  }
}

#endregion
