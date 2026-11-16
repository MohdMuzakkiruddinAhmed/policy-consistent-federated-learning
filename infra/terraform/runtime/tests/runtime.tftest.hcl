# Mocked provider: these plans call no AWS APIs and assert no cloud evidence.
mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/mock-runtime-role" }
  }
  mock_resource "aws_service_discovery_service" {
    defaults = { arn = "arn:aws:servicediscovery:us-east-1:123456789012:service/srv-0123456789abcdef" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:123456789012:function:pcfl-research-runtime-expiry" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-east-1:123456789012:pcfl-research-runtime-cleanup-failures" }
  }
  mock_resource "aws_ecs_cluster" {
    defaults = { arn = "arn:aws:ecs:us-east-1:123456789012:cluster/pcfl-research-runtime" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-1:123456789012:pcfl-research-runtime-cost-alerts" }
  }
}

variables {
  expected_account_id       = "123456789012"
  aws_region                = "us-east-1"
  resource_creation_enabled = true
  hard_expiry_utc           = timeadd(timestamp(), "1h")
  private_subnets           = { "us-east-1a" = "10.73.1.0/24" }
  budget = {
    approved_total_usd  = 10, estimated_total_usd = 2,
    authorization_scope = "eight-client-runtime-smoke", maximum_runtime_minutes = 60
  }
  foundation = {
    bucket_name = "pcfl-research-123456789012-us-east-1", state_table_name = "pcfl-research-state",
    client_task_role_arns = {
      org_01 = "arn:aws:iam::123456789012:role/pcfl-org_01", org_02 = "arn:aws:iam::123456789012:role/pcfl-org_02",
      org_03 = "arn:aws:iam::123456789012:role/pcfl-org_03", org_04 = "arn:aws:iam::123456789012:role/pcfl-org_04",
      org_05 = "arn:aws:iam::123456789012:role/pcfl-org_05", org_06 = "arn:aws:iam::123456789012:role/pcfl-org_06",
      org_07 = "arn:aws:iam::123456789012:role/pcfl-org_07", org_08 = "arn:aws:iam::123456789012:role/pcfl-org_08"
    },
    service_task_role_arns = {
      coordinator = "arn:aws:iam::123456789012:role/pcfl-coordinator",
      governance  = "arn:aws:iam::123456789012:role/pcfl-governance", evaluator = "arn:aws:iam::123456789012:role/pcfl-evaluator"
    },
    image_repositories = { coordinator = "123456789012.dkr.ecr.us-east-1.amazonaws.com/pcfl/coordinator" }
  }
}

run "creation_requires_explicit_operator_opt_in" {
  command = plan
  variables { resource_creation_enabled = false }
  expect_failures = [terraform_data.gate]
}

run "private_infrastructure_does_not_claim_cloud_validation" {
  command = plan
  assert {
    condition     = length(aws_vpc_endpoint.interface) == 5 && alltrue([for endpoint in aws_vpc_endpoint.interface : endpoint.private_dns_enabled])
    error_message = "ECR API/DKR, Logs, Secrets Manager and regional STS private interfaces are required."
  }
  assert {
    condition     = alltrue([for subnet in aws_subnet.private : !subnet.map_public_ip_on_launch])
    error_message = "Private subnets cannot assign public addresses."
  }
  assert {
    condition     = output.runtime_contract.cloud_validation_complete == false
    error_message = "A Terraform plan cannot assert observed G1 evidence."
  }
  assert {
    condition     = length(aws_ecs_task_definition.runtime) == 0 && length(aws_ecs_service.runtime) == 0
    error_message = "Infrastructure bootstrap does not launch application tasks before reviewed inputs exist."
  }
}

run "complete_tasks_preserve_role_secret_and_private_service_boundaries" {
  # Apply targets only the in-process mocked provider; no AWS API is used.
  command = apply
  variables { task_plan_file = "tests/fixtures/task-plan.json" }
  assert {
    condition     = length(aws_ecs_task_definition.runtime) == 13 && length(aws_ecs_service.runtime) == 4
    error_message = "Eight client tasks, four authority/service tasks and optional operator require separate definitions."
  }
  assert {
    condition     = alltrue([for service in aws_ecs_service.runtime : service.desired_count == 0 && !service.network_configuration[0].assign_public_ip])
    error_message = "Service launch is explicit and has no public task IPs."
  }
  assert {
    condition     = aws_ecs_task_definition.runtime["org_01"].task_role_arn == var.foundation.client_task_role_arns["org_01"]
    error_message = "The organization's actual distinct task role must survive renderer import."
  }
  assert {
    condition = (length(jsondecode(aws_iam_role_policy.execution["org_01"].policy).Statement[3].Resource) == 2 &&
    contains(jsondecode(aws_iam_role_policy.execution["org_01"].policy).Statement[3].Resource, "arn:aws:secretsmanager:us-east-1:123456789012:secret:org_01-abcdef"))
    error_message = "A client execution role can retrieve only its own key and the CA."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.execution["opa"].policy).Statement[3].Resource == ["arn:aws:secretsmanager:us-east-1:123456789012:secret:opa-config-abcdef"]
    error_message = "OPA receives only its own private config secret."
  }
  assert {
    condition     = alltrue([for task in aws_ecs_task_definition.runtime : jsondecode(task.container_definitions)[0].readonlyRootFilesystem])
    error_message = "Imported task definitions retain read-only root filesystems."
  }
  assert {
    condition     = aws_scheduler_schedule.expiry.action_after_completion == "DELETE" && aws_scheduler_schedule.expiry.flexible_time_window[0].mode == "OFF"
    error_message = "Cleanup is a one-shot fixed expiry schedule, not an unbounded recurring cost."
  }
  assert {
    condition     = length(jsondecode(aws_iam_role_policy.expiry.policy).Statement[4].Resource) == 5
    error_message = "Cleanup deletion permissions must bind exactly the five recorded interface endpoint ARNs."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.expiry.policy).Statement[1].Condition.ArnEquals["ecs:cluster"] == aws_ecs_cluster.runtime.arn
    error_message = "Cleanup cannot enumerate tasks outside the exact recorded cluster."
  }
  assert {
    condition = (jsondecode(aws_lambda_function.provisional_expiry.environment[0].variables.PCFL_CLEANUP_INVENTORY_JSON).provisional == true &&
    !can(jsondecode(aws_lambda_function.provisional_expiry.environment[0].variables.PCFL_CLEANUP_INVENTORY_JSON).interface_endpoint_ids))
    error_message = "The prearmed guard must not depend on endpoint IDs created later."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.provisional_expiry.policy).Statement[4].Condition.StringEquals["aws:ResourceTag/RuntimeVpcId"] == aws_vpc.runtime.id
    error_message = "Provisional deletion must bind the recorded VPC tag in addition to code-level actual VPC checks."
  }
  assert {
    condition     = output.runtime_contract.machine_cost_alerts.human_notification_configured == false
    error_message = "Machine alert wiring cannot claim notification to an unspecified person."
  }
}
