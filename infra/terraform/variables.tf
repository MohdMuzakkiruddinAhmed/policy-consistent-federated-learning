variable "expected_account_id" {
  description = "Explicitly selected account; the AWS provider rejects other accounts."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "Provide the intended 12-digit account ID."
  }
}

variable "aws_region" {
  description = "One explicitly selected region. No resources are replicated."
  type        = string
  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.aws_region))
    error_message = "Provide an AWS region identifier."
  }
}

variable "project_id" {
  type    = string
  default = "pcfl-research"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,25}$", var.project_id))
    error_message = "Use 3-26 lowercase alphanumeric/hyphen characters starting with a letter."
  }
}

variable "resource_creation_enabled" {
  description = "Explicit opt-in for reviewing a resource-creating plan; defaults closed."
  type        = bool
  default     = false
}

variable "budget_usd" {
  description = "Concrete authorized account-wide monitoring threshold; not a hard spending cap."
  type        = number
  validation {
    condition     = var.budget_usd > 0
    error_message = "Provide a positive budget amount in USD."
  }
}

variable "budget_time_unit" {
  description = "Explicit DAILY or MONTHLY recurrence. A total smoke-test cap needs separate run accounting."
  type        = string
  validation {
    condition     = contains(["DAILY", "MONTHLY"], var.budget_time_unit)
    error_message = "Choose DAILY or MONTHLY; do not silently translate a total cap into a monthly budget."
  }
}

variable "budget_alert_email" {
  description = "Optional alert recipient. Omit until provided by the account owner; not embedded in source."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = var.budget_alert_email == null ? true : can(regex("^[^ @]+@[^ @]+\\.[^ @]+$", var.budget_alert_email))
    error_message = "Provide an email address or null."
  }
}

variable "log_retention_days" {
  description = "Bounded experiment log retention; no row-level patient records may be logged."
  type        = number
  default     = 14
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30], var.log_retention_days)
    error_message = "Choose a bounded retention of 1, 3, 5, 7, 14, or 30 days."
  }
}

variable "state_deletion_protection" {
  description = "Keep enabled until evidence has been retained and table removal is intentional."
  type        = bool
  default     = true
}
