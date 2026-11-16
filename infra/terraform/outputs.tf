output "foundation_scope" {
  value = "Storage, table, roles, image repositories and budget only; zero ECS tasks or networking resources."
}
output "bucket_name" {
  value = aws_s3_bucket.research.id
}
output "state_table_name" {
  value = aws_dynamodb_table.state.name
}
output "client_task_role_arns" {
  value = { for org, role in aws_iam_role.client : org => role.arn }
}
output "service_task_role_arns" {
  value = { for service, role in aws_iam_role.service : service => role.arn }
}
output "task_execution_role_arn" {
  value = aws_iam_role.task_execution.arn
}
output "image_repositories" {
  value = { for kind, repository in aws_ecr_repository.runtime : kind => repository.repository_url }
}
output "budget_alert_configured" {
  value = var.budget_alert_email != null
}
