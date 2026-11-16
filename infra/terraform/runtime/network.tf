locals {
  organizations = [for number in range(1, 9) : format("org_%02d", number)]
  services      = toset(["coordinator", "governance", "opa", "evaluation"])
  groups        = toset(concat(local.organizations, ["coordinator", "governance", "opa", "evaluation", "operator", "endpoints"]))
  interfaces    = toset(["ecr.api", "ecr.dkr", "logs", "secretsmanager", "sts"])
  bucket_arn    = "arn:aws:s3:::${var.foundation.bucket_name}"
  table_arn     = "arn:aws:dynamodb:${var.aws_region}:${var.expected_account_id}:table/${var.foundation.state_table_name}"
  plan          = var.task_plan_file == null ? null : jsondecode(file(var.task_plan_file))
  tasks         = try(local.plan.task_definitions, {})
}

resource "terraform_data" "gate" {
  input = { account = var.expected_account_id, region = var.aws_region, budget = var.budget }
  lifecycle {
    precondition {
      condition     = var.resource_creation_enabled
      error_message = "Runtime resource creation is disabled; review complete endpoint/compute/secret costs and opt in explicitly."
    }
    precondition {
      condition = local.plan == null ? true : (try(local.plan.deployment_preflight_ready, false) &&
      local.plan.account_id == var.expected_account_id && local.plan.region == var.aws_region)
      error_message = "A complete same-account renderer deployment preflight is required before task registration."
    }
    precondition {
      condition     = var.foundation.bucket_name == "${var.project_id}-${var.expected_account_id}-${var.aws_region}"
      error_message = "Foundation bucket must belong to the explicit project/account/region."
    }
    precondition {
      condition     = timecmp(var.hard_expiry_utc, plantimestamp()) > 0 && timecmp(var.hard_expiry_utc, timeadd(plantimestamp(), "24h")) <= 0
      error_message = "Automatic cleanup must be in the future and within 24 hours of this plan."
    }
  }
}

resource "aws_vpc" "runtime" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  depends_on           = [terraform_data.gate]
}
resource "aws_subnet" "private" {
  for_each                = var.private_subnets
  vpc_id                  = aws_vpc.runtime.id
  availability_zone       = each.key
  cidr_block              = each.value
  map_public_ip_on_launch = false
}
resource "aws_route_table" "private" { vpc_id = aws_vpc.runtime.id }
resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}
resource "aws_default_security_group" "closed" {
  vpc_id  = aws_vpc.runtime.id
  ingress = []
  egress  = []
}
resource "aws_security_group" "task" {
  for_each    = local.groups
  name_prefix = "${var.project_id}-${each.key}-"
  description = "Explicit private runtime boundary for ${each.key}"
  vpc_id      = aws_vpc.runtime.id
}
resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interfaces
  vpc_id              = aws_vpc.runtime.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [for subnet in aws_subnet.private : subnet.id]
  security_group_ids  = [aws_security_group.task["endpoints"].id]
  tags                = { RuntimeVpcId = aws_vpc.runtime.id }
  depends_on          = [aws_scheduler_schedule.provisional_expiry]
}
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.runtime.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Principal = "*", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::prod-${var.aws_region}-starport-layer-bucket/*"] },
    { Effect = "Allow", Principal = "*", Action = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:ListBucket", "s3:GetBucketVersioning"], Resource = [local.bucket_arn, "${local.bucket_arn}/*"],
    Condition = { StringEquals = { "aws:PrincipalAccount" = var.expected_account_id } } }
  ] })
}
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.runtime.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = "*",
    Action = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem", "dynamodb:TransactWriteItems"],
  Resource = local.table_arn, Condition = { StringEquals = { "aws:PrincipalAccount" = var.expected_account_id } } }] })
}

resource "aws_vpc_security_group_ingress_rule" "endpoints" {
  for_each                     = toset([for group in local.groups : group if group != "endpoints"])
  security_group_id            = aws_security_group.task["endpoints"].id
  referenced_security_group_id = aws_security_group.task[each.key].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}
resource "aws_vpc_security_group_egress_rule" "endpoints" {
  for_each                     = toset([for group in local.groups : group if group != "endpoints"])
  security_group_id            = aws_security_group.task[each.key].id
  referenced_security_group_id = aws_security_group.task["endpoints"].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}
locals {
  gateway_egress = { for pair in setproduct([for group in local.groups : group if group != "endpoints"], ["s3", "dynamodb"]) :
  "${pair[0]}-${pair[1]}" => { group = pair[0], endpoint = pair[1] } }
  # Requests are one-way; security groups allow their established responses.
  application_edges = merge(
    { for org in local.organizations : "${org}-fleet" => { from = org, to = "coordinator", port = 9092 } },
    { operator_governance    = { from = "operator", to = "governance", port = 8443 },
      coordinator_governance = { from = "coordinator", to = "governance", port = 8443 },
      coordinator_opa        = { from = "coordinator", to = "opa", port = 8443 },
      coordinator_evaluation = { from = "coordinator", to = "evaluation", port = 8443 },
      operator_opa           = { from = "operator", to = "opa", port = 8443 },
  operator_evaluation = { from = "operator", to = "evaluation", port = 8443 } })
}
resource "aws_vpc_security_group_egress_rule" "gateway" {
  for_each          = local.gateway_egress
  security_group_id = aws_security_group.task[each.value.group].id
  prefix_list_id    = each.value.endpoint == "s3" ? aws_vpc_endpoint.s3.prefix_list_id : aws_vpc_endpoint.dynamodb.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}
resource "aws_vpc_security_group_egress_rule" "application" {
  for_each                     = local.application_edges
  security_group_id            = aws_security_group.task[each.value.from].id
  referenced_security_group_id = aws_security_group.task[each.value.to].id
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
}
resource "aws_vpc_security_group_ingress_rule" "application" {
  for_each                     = local.application_edges
  security_group_id            = aws_security_group.task[each.value.to].id
  referenced_security_group_id = aws_security_group.task[each.value.from].id
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
}
