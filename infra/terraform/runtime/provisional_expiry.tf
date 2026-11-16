# Armed before paid interface endpoints. This graph contains NO endpoint IDs.
# DeleteVpcEndpoints has no ec2:Vpc IAM condition in AWS's action reference.
# Bind the recorded VPC through its creation-time tag and independently check
# the actual VpcId in code; permit only the five regional service names.
locals {
  provisional_inventory = {
    provisional               = true, account_id = var.expected_account_id, region = var.aws_region,
    project_id                = var.project_id, hard_expiry_utc = var.hard_expiry_utc,
    cluster_arn               = aws_ecs_cluster.runtime.arn, service_arns = local.cleanup_service_arns,
    vpc_id                    = aws_vpc.runtime.id,
    allowed_endpoint_services = [for name in local.interfaces : "com.amazonaws.${var.aws_region}.${name}"]
  }
}
resource "aws_cloudwatch_log_group" "provisional_expiry" {
  name              = "/aws/lambda/${var.project_id}-provisional-expiry"
  retention_in_days = 7
  depends_on        = [terraform_data.gate]
}
resource "aws_iam_role" "provisional_expiry" {
  name = "${var.project_id}-provisional-expiry"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow",
  Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  depends_on = [terraform_data.gate]
}
resource "aws_iam_role_policy" "provisional_expiry" {
  name = "only-bound-vpc-tagged-runtime-cost-resources"
  role = aws_iam_role.provisional_expiry.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["ecs:UpdateService"], Resource = local.cleanup_service_arns,
    Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.runtime.arn } } },
    { Effect = "Allow", Action = ["ecs:ListTasks"], Resource = "*",
    Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.runtime.arn } } },
    { Effect = "Allow", Action = ["ecs:StopTask"], Resource = "arn:aws:ecs:${var.aws_region}:${var.expected_account_id}:task/${var.project_id}-runtime/*",
    Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.runtime.arn } } },
    { Effect = "Allow", Action = ["ec2:DescribeVpcEndpoints"], Resource = "*" },
    { Effect = "Allow", Action = ["ec2:DeleteVpcEndpoints"], Resource = "arn:aws:ec2:${var.aws_region}:${var.expected_account_id}:vpc-endpoint/*",
      Condition = { StringEquals = { "aws:ResourceTag/Project" = var.project_id, "aws:ResourceTag/Stage" = "runtime",
        "aws:ResourceTag/RuntimeVpcId" = aws_vpc.runtime.id,
    "ec2:VpceServiceName" = [for name in local.interfaces : "com.amazonaws.${var.aws_region}.${name}"] } } },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.provisional_expiry.arn}:*" },
    { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.cleanup_failures.arn },
    { Effect = "Allow", Action = ["ecs:DescribeClusters", "ecs:ListTagsForResource"], Resource = aws_ecs_cluster.runtime.arn }
  ] })
}
resource "aws_lambda_function" "provisional_expiry" {
  function_name    = "${var.project_id}-provisional-expiry"
  role             = aws_iam_role.provisional_expiry.arn
  handler          = "expiry_cleanup.handler"
  runtime          = "python3.12"
  timeout          = 180
  memory_size      = 128
  filename         = data.archive_file.expiry.output_path
  source_code_hash = data.archive_file.expiry.output_base64sha256
  environment { variables = { PCFL_CLEANUP_INVENTORY_JSON = jsonencode(local.provisional_inventory) } }
  depends_on = [aws_iam_role_policy.provisional_expiry, aws_cloudwatch_log_group.provisional_expiry]
}
resource "aws_lambda_function_event_invoke_config" "provisional_expiry" {
  function_name                = aws_lambda_function.provisional_expiry.function_name
  maximum_event_age_in_seconds = 21600
  maximum_retry_attempts       = 2
  destination_config {
    on_failure { destination = aws_sqs_queue.cleanup_failures.arn }
  }
}
resource "aws_iam_role_policy" "provisional_schedule" {
  name = "invoke-only-prearmed-runtime-expiry"
  role = aws_iam_role.schedule.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = aws_lambda_function.provisional_expiry.arn },
    { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.cleanup_failures.arn }
  ] })
}
resource "aws_scheduler_schedule" "provisional_expiry" {
  name                         = "${var.project_id}-provisional-expiry"
  group_name                   = "default"
  action_after_completion      = "DELETE"
  schedule_expression          = "at(${trimsuffix(var.hard_expiry_utc, "Z")})"
  schedule_expression_timezone = "UTC"
  flexible_time_window { mode = "OFF" }
  target {
    arn      = aws_lambda_function.provisional_expiry.arn
    role_arn = aws_iam_role.schedule.arn
    input    = jsonencode({ kind = "pcfl-prearmed-runtime-expiry" })
    retry_policy {
      maximum_event_age_in_seconds = 21600
      maximum_retry_attempts       = 185
    }
    dead_letter_config { arn = aws_sqs_queue.cleanup_failures.arn }
  }
  depends_on = [aws_iam_role_policy.provisional_schedule, aws_lambda_function_event_invoke_config.provisional_expiry]
}
