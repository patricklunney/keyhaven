output "issuer" {
  description = "OIDC issuer URL. Point your applications at <issuer>/.well-known/openid-configuration."
  value       = local.issuer
}

output "ecr_repository_url" {
  description = "Push the keyhaven image here."
  value       = aws_ecr_repository.this.repository_url
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "service_name" {
  value = aws_ecs_service.app.name
}

output "signing_key_secret_arn" {
  value = aws_secretsmanager_secret.signing_key.arn
}

output "register_client_command" {
  description = "Run a one-off task to register an OIDC client (edit the name and redirect URI)."
  value = join(" ", [
    "aws ecs run-task --region ${var.region} --cluster ${aws_ecs_cluster.this.name}",
    "--launch-type FARGATE --task-definition ${aws_ecs_task_definition.app.family}",
    "--network-configuration 'awsvpcConfiguration={subnets=[${join(",", aws_subnet.private[*].id)}],securityGroups=[${aws_security_group.app.id}]}'",
    "--overrides '{\"containerOverrides\":[{\"name\":\"keyhaven\",\"command\":[\"client\",\"create\",\"--name\",\"My App\",\"--redirect-uri\",\"https://app.example.com/callback\"]}]}'",
  ])
}
