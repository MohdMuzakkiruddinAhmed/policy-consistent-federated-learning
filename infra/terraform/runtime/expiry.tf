locals {
  cleanup_service_arns  = [for name in local.services : "arn:aws:ecs:${var.aws_region}:${var.expected_account_id}:service/${var.project_id}-runtime/${var.project_id}-${name}"]
  cleanup_endpoint_arns = [for endpoint in aws_vpc_endpoint.interface : "arn:aws:ec2:${var.aws_region}:${var.expected_account_id}:vpc-endpoint/${endpoint.id}"]
  cleanup_inventory = {
    account_id             = var.expected_account_id, region = var.aws_region, project_id = var.project_id,
    hard_expiry_utc        = var.hard_expiry_utc, cluster_arn = aws_ecs_cluster.runtime.arn,
    service_arns           = local.cleanup_service_arns, vpc_id = aws_vpc.runtime.id,
    interface_endpoint_ids = [for endpoint in aws_vpc_endpoint.interface : endpoint.id]
  }
}
data "archive_file" "expiry" {
  type        = "zip"
  source_file = "${path.module}/expiry_cleanup.py"
  output_path = "${path.module}/.terraform/expiry-cleanup.zip"
}
resource "aws_sqs_queue" "cleanup_failures" {
  name                      = "${var.project_id}-runtime-cleanup-failures"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  depends_on                = [terraform_data.gate]
}
resource "aws_cloudwatch_log_group" "expiry" {
  name              = "/aws/lambda/${var.project_id}-runtime-expiry"
  retention_in_days = 7
  depends_on        = [terraform_data.gate]
}
resource "aws_iam_role" "expiry" {
  name = "${var.project_id}-runtime-expiry"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow",
  Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  depends_on = [terraform_data.gate]
}
resource "aws_iam_role_policy" "expiry" {
  name = "only-recorded-runtime-cost-resources"
  role = aws_iam_role.expiry.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["ecs:UpdateService"], Resource = local.cleanup_service_arns,
    Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.runtime.arn } } },
    { Effect = "Allow", Action = ["ecs:ListTasks"], Resource = "*",
    Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.runtime.arn } } },
    { Effect = "Allow", Action = ["ecs:StopTask"], Resource = "arn:aws:ecs:${var.aws_region}:${var.expected_account_id}:task/${var.project_id}-runtime/*",
    Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.runtime.arn } } },
    { Effect = "Allow", Action = ["ec2:DescribeVpcEndpoints"], Resource = "*" },
    { Effect = "Allow", Action = ["ec2:DeleteVpcEndpoints"], Resource = local.cleanup_endpoint_arns,
    Condition = { StringEquals = { "aws:ResourceTag/Project" = var.project_id, "aws:ResourceTag/Stage" = "runtime" } } },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.expiry.arn}:*" },
    { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.cleanup_failures.arn },
    { Effect = "Allow", Action = ["ecs:DescribeClusters", "ecs:ListTagsForResource"], Resource = aws_ecs_cluster.runtime.arn }
  ] })
}
resource "aws_lambda_function" "expiry" {
  function_name    = "${var.project_id}-runtime-expiry"
  role             = aws_iam_role.expiry.arn
  handler          = "expiry_cleanup.handler"
  runtime          = "python3.12"
  timeout          = 180
  memory_size      = 128
  filename         = data.archive_file.expiry.output_path
  source_code_hash = data.archive_file.expiry.output_base64sha256
  environment { variables = { PCFL_CLEANUP_INVENTORY_JSON = jsonencode(local.cleanup_inventory) } }
  depends_on = [aws_iam_role_policy.expiry, aws_cloudwatch_log_group.expiry]
}
resource "aws_lambda_function_event_invoke_config" "expiry" {
  function_name                = aws_lambda_function.expiry.function_name
  maximum_event_age_in_seconds = 21600
  maximum_retry_attempts       = 2
  destination_config {
    on_failure { destination = aws_sqs_queue.cleanup_failures.arn }
  }
}
resource "aws_iam_role" "schedule" {
  name = "${var.project_id}-runtime-expiry-schedule"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow",
    Principal = { Service = "scheduler.amazonaws.com" }, Action = "sts:AssumeRole",
    Condition = { StringEquals = { "aws:SourceAccount" = var.expected_account_id }, ArnEquals = {
  "aws:SourceArn" = "arn:aws:scheduler:${var.aws_region}:${var.expected_account_id}:schedule-group/default" } } }] })
  depends_on = [terraform_data.gate]
}
resource "aws_iam_role_policy" "schedule" {
  name = "invoke-only-runtime-expiry"
  role = aws_iam_role.schedule.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = aws_lambda_function.expiry.arn },
    { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.cleanup_failures.arn }
  ] })
}
resource "aws_scheduler_schedule" "expiry" {
  name                         = "${var.project_id}-runtime-hard-expiry"
  group_name                   = "default"
  action_after_completion      = "DELETE"
  schedule_expression          = "at(${trimsuffix(var.hard_expiry_utc, "Z")})"
  schedule_expression_timezone = "UTC"
  flexible_time_window { mode = "OFF" }
  target {
    arn      = aws_lambda_function.expiry.arn
    role_arn = aws_iam_role.schedule.arn
    input    = jsonencode({ kind = "pcfl-recorded-runtime-expiry" })
    retry_policy {
      maximum_event_age_in_seconds = 21600
      maximum_retry_attempts       = 185
    }
    dead_letter_config { arn = aws_sqs_queue.cleanup_failures.arn }
  }
  depends_on = [aws_iam_role_policy.schedule, aws_lambda_function_event_invoke_config.expiry]
}
