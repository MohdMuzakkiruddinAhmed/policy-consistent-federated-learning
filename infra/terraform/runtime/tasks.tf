resource "aws_ecs_cluster" "runtime" {
  name = "${var.project_id}-runtime"
  setting {
    name  = "containerInsights"
    value = "disabled"
  }
  depends_on = [terraform_data.gate]
}
resource "aws_cloudwatch_log_group" "runtime" {
  for_each          = local.tasks
  name              = "/${var.project_id}/runtime/${each.key}"
  retention_in_days = 7
  depends_on        = [terraform_data.gate]
}
resource "aws_service_discovery_private_dns_namespace" "runtime" {
  name = var.namespace
  vpc  = aws_vpc.runtime.id
}
resource "aws_service_discovery_service" "runtime" {
  for_each = local.services
  name     = each.key == "coordinator" ? "superlink" : each.key
  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.runtime.id
    routing_policy = "MULTIVALUE"
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
  health_check_custom_config {}
}
resource "aws_ecs_task_definition" "runtime" {
  for_each                 = local.tasks
  family                   = "${var.project_id}-runtime-${each.key}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  task_role_arn            = contains(["opa", "operator"], each.key) ? aws_iam_role.auxiliary[each.key].arn : each.value.taskRoleArn
  execution_role_arn       = aws_iam_role.execution[each.key].arn
  runtime_platform {
    cpu_architecture        = "X86_64"
    operating_system_family = "LINUX"
  }
  volume { name = "runtime" }
  container_definitions = jsonencode([for container in each.value.containerDefinitions : merge(container, {
    logConfiguration = { logDriver = "awslogs", options = {
      "awslogs-group"  = aws_cloudwatch_log_group.runtime[each.key].name,
      "awslogs-region" = var.aws_region, "awslogs-stream-prefix" = "runtime"
    } }
  })])
  depends_on = [aws_iam_role_policy.execution, aws_iam_role_policy.coordinator_bucket_metadata]
}
resource "aws_ecs_service" "runtime" {
  for_each                           = { for name in local.services : name => local.tasks[name] if contains(keys(local.tasks), name) }
  name                               = "${var.project_id}-${each.key}"
  cluster                            = aws_ecs_cluster.runtime.id
  task_definition                    = aws_ecs_task_definition.runtime[each.key].arn
  desired_count                      = lookup(var.service_desired_counts, each.key, 0)
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  enable_execute_command             = false
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  wait_for_steady_state              = true
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets          = [for subnet in aws_subnet.private : subnet.id]
    security_groups  = [aws_security_group.task[each.key].id]
    assign_public_ip = false
  }
  service_registries { registry_arn = aws_service_discovery_service.runtime[each.key].arn }
  depends_on = [aws_vpc_endpoint.interface, aws_vpc_endpoint.s3, aws_vpc_endpoint.dynamodb,
    aws_vpc_security_group_ingress_rule.application, aws_vpc_security_group_egress_rule.application,
    aws_vpc_security_group_ingress_rule.endpoints, aws_vpc_security_group_egress_rule.endpoints,
  aws_vpc_security_group_egress_rule.gateway]
}
