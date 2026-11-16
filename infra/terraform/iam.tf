resource "aws_iam_role" "client" {
  for_each           = toset(local.org_ids)
  name               = "${var.project_id}-${each.key}"
  assume_role_policy = local.trust_policy
  depends_on         = [terraform_data.deployment_gate]
}

resource "aws_iam_role_policy" "client_data" {
  for_each = toset(local.org_ids)
  name     = "own-partitions-only"
  role     = aws_iam_role.client[each.key].id
  policy = templatefile("${path.module}/policies/client-data.json.tftpl", {
    bucket_arn = aws_s3_bucket.research.arn
    org_id     = each.key
  })
}

resource "aws_iam_role" "service" {
  for_each           = toset(["coordinator", "governance", "evaluator"])
  name               = "${var.project_id}-${each.key}"
  assume_role_policy = local.trust_policy
  depends_on         = [terraform_data.deployment_gate]
}

resource "aws_iam_role_policy" "coordinator" {
  name = "guarded-publication"
  role = aws_iam_role.service["coordinator"].id
  policy = templatefile("${path.module}/policies/coordinator.json.tftpl", {
    bucket_arn            = aws_s3_bucket.research.arn
    table_arn             = aws_dynamodb_table.state.arn
    policy_partition_keys = jsonencode(local.policy_partition_keys)
  })
}

resource "aws_iam_role_policy" "governance" {
  name = "policy-authority"
  role = aws_iam_role.service["governance"].id
  policy = templatefile("${path.module}/policies/governance.json.tftpl", {
    bucket_arn            = aws_s3_bucket.research.arn
    table_arn             = aws_dynamodb_table.state.arn
    policy_partition_keys = jsonencode(concat(local.policy_partition_keys, ["AUTHORITY"]))
  })
}

resource "aws_iam_role_policy" "evaluator" {
  name = "holdout-and-evidence-read"
  role = aws_iam_role.service["evaluator"].id
  policy = templatefile("${path.module}/policies/evaluator.json.tftpl", {
    bucket_arn            = aws_s3_bucket.research.arn
    table_arn             = aws_dynamodb_table.state.arn
    policy_partition_keys = jsonencode(concat(local.policy_partition_keys, ["RUN#*", "AUTHORITY"]))
  })
}

resource "aws_iam_role" "task_execution" {
  name               = "${var.project_id}-task-execution"
  assume_role_policy = local.trust_policy
  depends_on         = [terraform_data.deployment_gate]
}

resource "aws_iam_role_policy" "task_execution" {
  name = "image-pull-and-bounded-logs"
  role = aws_iam_role.task_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EcrAuthentication"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid      = "ProjectImagesOnly"
        Effect   = "Allow"
        Action   = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = [for repository in aws_ecr_repository.runtime : repository.arn]
      },
      {
        Sid      = "ExistingProjectLogGroupsOnly"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = [for group in aws_cloudwatch_log_group.runtime : "${group.arn}:*"]
      }
    ]
  })
}
