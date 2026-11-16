output "runtime_contract" {
  value = {
    account_id            = var.expected_account_id, region = var.aws_region, namespace = var.namespace,
    vpc_id                = aws_vpc.runtime.id, cluster_arn = aws_ecs_cluster.runtime.arn,
    subnet_ids            = [for subnet in aws_subnet.private : subnet.id],
    security_group_ids    = { for name, group in aws_security_group.task : name => group.id },
    task_definition_arns  = { for name, task in aws_ecs_task_definition.runtime : name => task.arn },
    service_names         = { for name, service in aws_ecs_service.runtime : name => service.name },
    discovery_service_ids = { for name, service in aws_service_discovery_service.runtime : name => service.id },
    service_endpoints = { superlink = "superlink.${var.namespace}:9092", control = "loopback:9093",
    governance = "https://governance.${var.namespace}:8443", opa = "https://opa.${var.namespace}:8443", evaluation = "https://evaluation.${var.namespace}:8443" },
    task_role_arns = merge(var.foundation.client_task_role_arns, var.foundation.service_task_role_arns, {
    evaluation = var.foundation.service_task_role_arns["evaluator"], opa = aws_iam_role.auxiliary["opa"].arn, operator = aws_iam_role.auxiliary["operator"].arn }),
    execution_role_arns       = { for name, role in aws_iam_role.execution : name => role.arn },
    secret_arns               = { for name, secret in aws_secretsmanager_secret.runtime : name => secret.arn },
    log_groups                = { for name, group in aws_cloudwatch_log_group.runtime : name => group.name },
    interface_endpoint_ids    = { for name, endpoint in aws_vpc_endpoint.interface : name => endpoint.id },
    gateway_endpoint_ids      = { s3 = aws_vpc_endpoint.s3.id, dynamodb = aws_vpc_endpoint.dynamodb.id },
    endpoint_az_count         = length(var.private_subnets), maximum_runtime_minutes = var.budget.maximum_runtime_minutes,
    cloud_validation_complete = false,
    automatic_cleanup = {
      hard_expiry_utc          = var.hard_expiry_utc, schedule_arn = aws_scheduler_schedule.expiry.arn,
      function_arn             = aws_lambda_function.expiry.arn, failure_queue_url = aws_sqs_queue.cleanup_failures.url,
      inventory                = local.cleanup_inventory,
      limitation               = "API failures retry and reach the machine-visible failure queue; this is a backstop, not a billing hard cap or human notification."
      provisional_schedule_arn = aws_scheduler_schedule.provisional_expiry.arn
    },
    machine_cost_alerts = { budget_name = aws_budgets_budget.campaign.name, sns_topic_arn = aws_sns_topic.cost_alerts.arn,
      queue_url = aws_sqs_queue.cost_alerts.url, threshold_percent = 80, human_notification_configured = false,
    limitation = "Configured monthly machine alert; no observed billing delivery or hard cap is claimed." },
    evidence_required = ["eight distinct client task ARNs/private IPs/roles", "native TLS and wrong-identity denial",
      "own S3 version read succeeds and seven cross-org reads fail per client role", "coordinator holdout/policy-write denial",
    "isolated evaluator aggregate-only result", "OPA unavailable failure closure", "independent client stop/restart", "teardown and billed-cost reconciliation"]
  }
}
