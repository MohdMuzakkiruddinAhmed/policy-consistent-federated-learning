data "aws_partition" "current" {}

locals {
  org_ids               = ["org_01", "org_02", "org_03", "org_04", "org_05", "org_06", "org_07", "org_08"]
  task_names            = concat(local.org_ids, ["coordinator", "governance", "evaluator"])
  policy_partition_keys = [for org in local.org_ids : "POLICY#${org}"]
  trust_policy = templatefile("${path.module}/policies/task-trust.json.tftpl", {
    account_id = var.expected_account_id
    region     = var.aws_region
    partition  = data.aws_partition.current.partition
  })
}

resource "terraform_data" "deployment_gate" {
  input = { account = var.expected_account_id, region = var.aws_region, budget = var.budget_usd }
  lifecycle {
    precondition {
      condition     = var.resource_creation_enabled
      error_message = "Resource creation is disabled. Configure account, region and budget before explicitly enabling a reviewed plan."
    }
  }
}

resource "aws_s3_bucket" "research" {
  bucket        = "${var.project_id}-${var.expected_account_id}-${var.aws_region}"
  force_destroy = false
  depends_on    = [terraform_data.deployment_gate]
}

resource "aws_s3_bucket_public_access_block" "research" {
  bucket                  = aws_s3_bucket.research.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "research" {
  bucket = aws_s3_bucket.research.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "research" {
  bucket = aws_s3_bucket.research.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "research" {
  bucket = aws_s3_bucket.research.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.research.id
  policy = templatefile("${path.module}/policies/bucket-tls.json.tftpl", {
    bucket_arn = aws_s3_bucket.research.arn
  })
  depends_on = [aws_s3_bucket_public_access_block.research]
}

resource "aws_s3_bucket_lifecycle_configuration" "research" {
  bucket = aws_s3_bucket.research.id
  rule {
    id     = "abort-incomplete-multipart-only"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_dynamodb_table" "state" {
  name                        = "${var.project_id}-state"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "PK"
  range_key                   = "SK"
  deletion_protection_enabled = var.state_deletion_protection
  attribute {
    name = "PK"
    type = "S"
  }
  attribute {
    name = "SK"
    type = "S"
  }
  server_side_encryption {
    enabled = true
  }
  point_in_time_recovery {
    enabled = true
  }
  depends_on = [terraform_data.deployment_gate]
}

resource "aws_ecr_repository" "runtime" {
  for_each             = toset(["client", "coordinator", "governance"])
  name                 = "${var.project_id}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  encryption_configuration {
    encryption_type = "AES256"
  }
  image_scanning_configuration {
    scan_on_push = true
  }
  depends_on = [terraform_data.deployment_gate]
}

resource "aws_cloudwatch_log_group" "runtime" {
  for_each          = toset(local.task_names)
  name              = "/${var.project_id}/${each.key}"
  retention_in_days = var.log_retention_days
  depends_on        = [terraform_data.deployment_gate]
}

resource "aws_budgets_budget" "account" {
  account_id   = var.expected_account_id
  name         = "${var.project_id}-account-monitor"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_usd)
  limit_unit   = "USD"
  time_unit    = var.budget_time_unit

  dynamic "notification" {
    for_each = var.budget_alert_email == null ? [] : [var.budget_alert_email]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 80
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [notification.value]
    }
  }
  depends_on = [terraform_data.deployment_gate]
}
