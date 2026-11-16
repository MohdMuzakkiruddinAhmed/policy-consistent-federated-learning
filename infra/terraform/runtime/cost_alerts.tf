# Machine-readable cost alerts supplement the resource/time bounds. Billing
# data and notifications are delayed and never act as a hard spending cap.
resource "aws_sns_topic" "cost_alerts" {
  name       = "${var.project_id}-campaign-cost-alerts"
  depends_on = [terraform_data.gate]
}

resource "aws_sns_topic_policy" "cost_alerts" {
  arn = aws_sns_topic.cost_alerts.arn
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid       = "SameAccountBudgetsPublish", Effect = "Allow",
    Principal = { Service = "budgets.amazonaws.com" }, Action = "SNS:Publish",
    Resource  = aws_sns_topic.cost_alerts.arn,
    Condition = { StringEquals = { "aws:SourceAccount" = var.expected_account_id },
    ArnLike = { "aws:SourceArn" = "arn:aws:budgets::${var.expected_account_id}:*" } }
  }] })
}

resource "aws_sqs_queue" "cost_alerts" {
  name                      = "${var.project_id}-campaign-cost-alerts"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  depends_on                = [terraform_data.gate]
}

resource "aws_sqs_queue_policy" "cost_alerts" {
  queue_url = aws_sqs_queue.cost_alerts.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid    = "OnlyRecordedTopic", Effect = "Allow", Principal = { Service = "sns.amazonaws.com" },
    Action = "sqs:SendMessage", Resource = aws_sqs_queue.cost_alerts.arn,
    Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.cost_alerts.arn },
    StringEquals = { "aws:SourceAccount" = var.expected_account_id } }
  }] })
}

resource "aws_sns_topic_subscription" "cost_alerts" {
  topic_arn            = aws_sns_topic.cost_alerts.arn
  protocol             = "sqs"
  endpoint             = aws_sqs_queue.cost_alerts.arn
  raw_message_delivery = true
  depends_on           = [aws_sqs_queue_policy.cost_alerts]
}

resource "aws_budgets_budget" "campaign" {
  account_id   = var.expected_account_id
  name         = "${var.project_id}-campaign-machine-monitor"
  budget_type  = "COST"
  limit_amount = tostring(var.budget.approved_total_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.cost_alerts.arn]
  }
  depends_on = [aws_sns_topic_policy.cost_alerts, aws_sns_topic_subscription.cost_alerts]
}

output "machine_cost_alerts" {
  value = { budget_name = aws_budgets_budget.campaign.name,
    sns_topic_arn     = aws_sns_topic.cost_alerts.arn, queue_url = aws_sqs_queue.cost_alerts.url,
    threshold_percent = 80, human_notification_configured = false,
  limitation = "Monthly account monitor; not the campaign ledger, a hard spending cap or an observed billing delivery." }
}
