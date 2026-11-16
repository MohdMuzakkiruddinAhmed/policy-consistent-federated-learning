terraform {
  backend "local" {}
  required_version = "= 1.17.2"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.73.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "= 2.8.1"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.expected_account_id]
  default_tags {
    tags = { Project = var.project_id, Environment = "research", ManagedBy = "terraform", Stage = "runtime" }
  }
}
