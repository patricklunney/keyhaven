resource "aws_ecs_cluster" "this" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = var.container_insights ? "enabled" : "disabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
}

# ---------------------------------------------------------------- IAM

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:ecs:${var.region}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

# Execution role: used by the ECS agent to pull the image, write logs and inject secrets.
resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_secrets" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.signing_key.arn,
      aws_db_instance.this.master_user_secret[0].secret_arn,
    ]
  }
}

resource "aws_iam_role_policy" "execution_secrets" {
  name   = "secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_secrets.json
}

# Task role: what the application itself may call. Keyhaven needs no AWS APIs at
# runtime, so this role intentionally has no policies.
resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

# ---------------------------------------------------------------- task & service

locals {
  db_secret_arn = aws_db_instance.this.master_user_secret[0].secret_arn
  container_env = [
    { name = "KEYHAVEN_ISSUER", value = local.issuer },
    { name = "KEYHAVEN_RP_DISPLAY_NAME", value = var.rp_display_name },
    { name = "KEYHAVEN_ALLOW_SIGNUP", value = tostring(var.allow_signup) },
    { name = "DB_HOST", value = aws_db_instance.this.address },
    { name = "DB_PORT", value = tostring(aws_db_instance.this.port) },
    { name = "DB_NAME", value = aws_db_instance.this.db_name },
    { name = "DB_SSLMODE", value = "require" },
  ]
  container_secrets = [
    { name = "KEYHAVEN_SIGNING_KEY", valueFrom = aws_secretsmanager_secret.signing_key.arn },
    { name = "DB_USER", valueFrom = "${local.db_secret_arn}:username::" },
    { name = "DB_PASSWORD", valueFrom = "${local.db_secret_arn}:password::" },
  ]
}

resource "aws_ecs_task_definition" "app" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64" # Graviton: build the image with --platform linux/arm64
  }

  container_definitions = jsonencode([{
    name                   = "keyhaven"
    image                  = "${aws_ecr_repository.this.repository_url}:${var.image_tag}"
    essential              = true
    command                = ["serve"]
    readonlyRootFilesystem = true
    linuxParameters        = { capabilities = { drop = ["ALL"] } }
    portMappings           = [{ containerPort = 8080, protocol = "tcp" }]
    environment            = local.container_env
    secrets                = local.container_secrets
    stopTimeout            = 30
    # The image has no shell, so the binary checks itself. ECS uses this to
    # replace unhealthy tasks and to report health to Cloud Map (api_gateway ingress).
    healthCheck = {
      command     = ["CMD", "keyhaven", "healthcheck"] # found via PATH in both Dockerfile and ko images
      interval    = 15
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.app.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "keyhaven"
      }
    }
  }])
}

resource "aws_ecs_service" "app" {
  name                               = var.name
  cluster                            = aws_ecs_cluster.this.id
  task_definition                    = aws_ecs_task_definition.app.arn
  desired_count                      = var.desired_count
  launch_type                        = var.fargate_spot ? null : "FARGATE"
  health_check_grace_period_seconds  = local.use_alb ? 60 : null
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  propagate_tags                     = "SERVICE"

  network_configuration {
    subnets          = local.task_subnet_ids
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = local.task_public_ip
  }

  dynamic "capacity_provider_strategy" {
    for_each = var.fargate_spot ? [1] : []
    content {
      capacity_provider = "FARGATE_SPOT"
      weight            = 1
    }
  }

  dynamic "load_balancer" {
    for_each = local.use_alb ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.app[0].arn
      container_name   = "keyhaven"
      container_port   = 8080
    }
  }

  # API Gateway finds tasks through Cloud Map. It needs SRV records (IP and port).
  dynamic "service_registries" {
    for_each = local.use_api ? [1] : []
    content {
      registry_arn   = aws_service_discovery_service.app[0].arn
      container_name = "keyhaven"
      container_port = 8080
    }
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [desired_count] # managed by autoscaling
  }

  depends_on = [aws_lb_listener.https, aws_secretsmanager_secret_version.signing_key, aws_ecs_cluster_capacity_providers.this]
}

# ---------------------------------------------------------------- autoscaling

resource "aws_appautoscaling_target" "app" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.app.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.desired_count
  max_capacity       = var.max_count
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.name}-cpu"
  service_namespace  = aws_appautoscaling_target.app.service_namespace
  resource_id        = aws_appautoscaling_target.app.resource_id
  scalable_dimension = aws_appautoscaling_target.app.scalable_dimension
  policy_type        = "TargetTrackingScaling"
  target_tracking_scaling_policy_configuration {
    target_value       = 60
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}
