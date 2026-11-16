locals {
  trust = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole",
  Condition = { StringEquals = { "aws:SourceAccount" = var.expected_account_id }, ArnLike = { "aws:SourceArn" = "arn:aws:ecs:${var.aws_region}:${var.expected_account_id}:*" } } }] })
  execution_secrets = { for name, task in local.tasks : name => distinct(flatten([
    for container in task.containerDefinitions : [for secret in try(container.secrets, []) : secret.valueFrom]
  ])) }
}
resource "aws_iam_role" "auxiliary" {
  for_each           = toset(["opa", "operator"])
  name               = "${var.project_id}-runtime-${each.key}"
  assume_role_policy = local.trust
  depends_on         = [terraform_data.gate]
}
# OPA intentionally has no data policies. Its execution role pulls the image,
# writes bounded logs, and materializes only OPA's own injected config secret.
resource "aws_iam_role_policy" "operator" {
  name = "aggregate-evidence-and-schema-only"
  role = aws_iam_role.auxiliary["operator"].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = ["${local.bucket_arn}/metadata/*", "${local.bucket_arn}/evidence/*", "${local.bucket_arn}/models/candidates/*"] },
    { Effect = "Allow", Action = ["s3:PutObject"], Resource = ["${local.bucket_arn}/evidence/operator/*"] },
    { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:Query"], Resource = local.table_arn,
    Condition = { "ForAllValues:StringLike" = { "dynamodb:LeadingKeys" = ["POLICY#*", "AUTHORITY", "RUN#*"] }, Null = { "dynamodb:LeadingKeys" = "false" } } }
  ] })
}
resource "aws_iam_role_policy" "coordinator_bucket_metadata" {
  name = "runtime-versioned-model-bucket-metadata"
  role = element(reverse(split("/", var.foundation.service_task_role_arns["coordinator"])), 0)
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:GetBucketVersioning"], Resource = local.bucket_arn },
    { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = "${local.bucket_arn}/metadata/*" }
  ] })
  depends_on = [terraform_data.gate]
}
resource "aws_iam_role_policy" "governance_scenario_control" {
  name = "read-only-fixed-scenario-barrier-attributes"
  role = element(reverse(split("/", var.foundation.service_task_role_arns["governance"])), 0)
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["dynamodb:GetItem"], Resource = local.table_arn,
    Condition = {
      "ForAllValues:StringLike"   = { "dynamodb:LeadingKeys" = ["RUN#*"] },
      "ForAllValues:StringEquals" = { "dynamodb:Attributes" = ["PK", "SK", "scenario_id", "ready"] },
      Null                        = { "dynamodb:LeadingKeys" = "false", "dynamodb:Attributes" = "false" }
    }
  }] })
  depends_on = [terraform_data.gate]
}
resource "aws_iam_role" "execution" {
  for_each           = local.tasks
  name               = "${var.project_id}-runtime-exec-${each.key}"
  assume_role_policy = local.trust
  depends_on         = [terraform_data.gate]
}
resource "aws_iam_role_policy" "execution" {
  for_each = local.tasks
  name     = "own-image-log-and-injected-secrets"
  role     = aws_iam_role.execution[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat([
    { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
    { Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
    Resource = distinct([for container in each.value.containerDefinitions : "arn:aws:ecr:${var.aws_region}:${var.expected_account_id}:repository/${split("@", join("/", slice(split("/", container.image), 1, length(split("/", container.image)))))[0]}"]) },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.runtime[each.key].arn}:*" }
    ], length(local.execution_secrets[each.key]) == 0 ? [] : [
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = local.execution_secrets[each.key] }
  ]) })
}
resource "aws_secretsmanager_secret" "runtime" {
  for_each                = var.secret_names
  name                    = "${var.project_id}/runtime/${each.key}"
  description             = "Private runtime material populated outside Terraform; never output secret values"
  recovery_window_in_days = var.secret_recovery_days
  depends_on              = [terraform_data.gate]
}
