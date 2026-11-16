variable "expected_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "Supply the explicit target AWS account."
  }
}
variable "aws_region" { type = string }
variable "project_id" {
  type    = string
  default = "pcfl-research"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,25}$", var.project_id))
    error_message = "Use a 3-26 character lowercase project identifier."
  }
}
variable "resource_creation_enabled" {
  type        = bool
  default     = false
  description = "Explicit reviewed runtime opt-in; default creates no plan successfully."
}
variable "hard_expiry_utc" {
  type        = string
  description = "Required UTC RFC3339 automatic cleanup deadline; reviewed plans expire within 24 hours."
  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.hard_expiry_utc)) && can(timecmp(var.hard_expiry_utc, var.hard_expiry_utc))
    error_message = "Supply an explicit UTC cleanup deadline as YYYY-MM-DDTHH:MM:SSZ."
  }
}
variable "budget" {
  type = object({ approved_total_usd = number, estimated_total_usd = number, authorization_scope = string, maximum_runtime_minutes = number })
  validation {
    condition = (var.budget.approved_total_usd > 0 && var.budget.estimated_total_usd > 0 &&
      var.budget.estimated_total_usd <= var.budget.approved_total_usd &&
      contains(["eight-client-runtime-smoke", "remaining-phases-cloud-campaign-including-replication"], var.budget.authorization_scope) &&
    var.budget.maximum_runtime_minutes >= 1 && var.budget.maximum_runtime_minutes <= (var.budget.authorization_scope == "remaining-phases-cloud-campaign-including-replication" ? 1440 : 120))
    error_message = "Use an approved estimate and deadline: smoke <=120 minutes; remaining-phase campaign <=1440 minutes."
  }
}
variable "foundation" {
  description = "Decoded outputs from the separately reviewed foundation stack; no implicit state or account discovery."
  type = object({
    bucket_name           = string, state_table_name = string,
    client_task_role_arns = map(string), service_task_role_arns = map(string), image_repositories = map(string)
  })
}
variable "private_subnets" {
  description = "Explicit AZ -> private IPv4 CIDR map. A single AZ is the bounded smoke default; no NAT or internet gateway."
  type        = map(string)
  validation {
    condition     = length(var.private_subnets) >= 1 && length(var.private_subnets) <= 2 && alltrue([for cidr in values(var.private_subnets) : can(cidrnetmask(cidr))])
    error_message = "Provide one or two explicitly selected AZs with IPv4 subnet CIDRs."
  }
}
variable "vpc_cidr" {
  type    = string
  default = "10.73.0.0/16"
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "Supply a valid IPv4 VPC CIDR."
  }
}
variable "namespace" {
  type    = string
  default = "pcfl.internal"
  validation {
    condition     = can(regex("^[a-z0-9-]+(\\.[a-z0-9-]+)+$", var.namespace))
    error_message = "Supply a private DNS namespace."
  }
}
variable "task_plan_file" {
  type        = string
  default     = null
  nullable    = true
  description = "Renderer output JSON after actual network/secret/image inputs exist; null prepares infrastructure only."
}
variable "service_desired_counts" {
  type    = map(number)
  default = { coordinator = 0, governance = 0, opa = 0, evaluation = 0 }
  validation {
    condition = (alltrue([for name in keys(var.service_desired_counts) : contains(["coordinator", "governance", "opa", "evaluation"], name)]) &&
    alltrue([for count in values(var.service_desired_counts) : count == 0 || count == 1]))
    error_message = "Services are single-authority 0/1 counts; enable explicitly after secrets and dependencies are healthy."
  }
}
variable "secret_names" {
  type        = set(string)
  default     = []
  description = "Optional names for empty Secrets Manager containers. Populate values through the operator; Terraform never stores private keys."
  validation {
    condition     = alltrue([for name in var.secret_names : can(regex("^[A-Za-z0-9/_+=.@-]{1,128}$", name))])
    error_message = "Use valid Secrets Manager names, without secret values."
  }
}
variable "secret_recovery_days" {
  type    = number
  default = 7
  validation {
    condition     = var.secret_recovery_days >= 7 && var.secret_recovery_days <= 30
    error_message = "Retain a 7-30 day recovery window; secret deletion is deliberate."
  }
}
