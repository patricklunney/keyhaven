# Low-cost ingress (ingress = "api_gateway"): API Gateway HTTP API -> VPC link
# -> Cloud Map -> Fargate tasks. Replaces the ALB (~$30/month) with
# pay-per-request pricing (~$1 per million requests). HTTP APIs don't support
# AWS WAF, so rate limiting comes from API Gateway throttling instead.

# ---------------------------------------------------------------- service discovery

resource "aws_service_discovery_private_dns_namespace" "this" {
  count       = local.use_api ? 1 : 0
  name        = "${var.name}.internal"
  description = "Service discovery for ${var.name}"
  vpc         = aws_vpc.this.id
}

resource "aws_service_discovery_service" "app" {
  count = local.use_api ? 1 : 0
  name  = "app"

  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.this[0].id
    routing_policy = "MULTIVALUE"
    # API Gateway needs each task's IP and port, which ECS registers only with SRV records.
    dns_records {
      type = "SRV"
      ttl  = 10
    }
  }

  # No Cloud Map health gating: the AWS provider silently drops an empty
  # health_check_custom_config block, so it never takes effect. ECS still
  # replaces any task that fails its container health check.
}

# ---------------------------------------------------------------- VPC link

resource "aws_security_group" "vpc_link" {
  count       = local.use_api ? 1 : 0
  name        = "${var.name}-vpc-link"
  description = "API Gateway VPC link to Keyhaven tasks"
  vpc_id      = aws_vpc.this.id
}

resource "aws_vpc_security_group_egress_rule" "vpc_link_to_app" {
  count                        = local.use_api ? 1 : 0
  security_group_id            = aws_security_group.vpc_link[0].id
  referenced_security_group_id = aws_security_group.app.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "app_from_vpc_link" {
  count                        = local.use_api ? 1 : 0
  security_group_id            = aws_security_group.app.id
  referenced_security_group_id = aws_security_group.vpc_link[0].id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_apigatewayv2_vpc_link" "this" {
  count              = local.use_api ? 1 : 0
  name               = var.name
  subnet_ids         = aws_subnet.private[*].id
  security_group_ids = [aws_security_group.vpc_link[0].id]
}

# ---------------------------------------------------------------- HTTP API

resource "aws_apigatewayv2_api" "this" {
  count         = local.use_api ? 1 : 0
  name          = var.name
  protocol_type = "HTTP"
  # Only the custom domain may reach Keyhaven: the issuer URL must be the one users see.
  disable_execute_api_endpoint = true
}

resource "aws_apigatewayv2_integration" "app" {
  count                  = local.use_api ? 1 : 0
  api_id                 = aws_apigatewayv2_api.this[0].id
  integration_type       = "HTTP_PROXY"
  integration_method     = "ANY"
  integration_uri        = aws_service_discovery_service.app[0].arn
  connection_type        = "VPC_LINK"
  connection_id          = aws_apigatewayv2_vpc_link.this[0].id
  payload_format_version = "1.0"
  timeout_milliseconds   = 29000
  # Private integrations can prefix the stage name to the path; send the path unchanged.
  request_parameters = {
    "overwrite:path" = "$request.path"
  }
}

resource "aws_apigatewayv2_route" "default" {
  count     = local.use_api ? 1 : 0
  api_id    = aws_apigatewayv2_api.this[0].id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.app[0].id}"
}

resource "aws_cloudwatch_log_group" "api_access" {
  count             = local.use_api ? 1 : 0
  name              = "/apigateway/${var.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_apigatewayv2_stage" "default" {
  count       = local.use_api ? 1 : 0
  api_id      = aws_apigatewayv2_api.this[0].id
  name        = "$default"
  auto_deploy = true
  # Access logs record the caller's real IP ($context.identity.sourceIp) as seen by API Gateway.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access[0].arn
    format = jsonencode({
      requestId = "$context.requestId", time = "$context.requestTime", ip = "$context.identity.sourceIp",
      method    = "$context.httpMethod", path = "$context.path", status = "$context.status",
      bytes     = "$context.responseLength", latencyMs = "$context.responseLatency",
      userAgent = "$context.identity.userAgent", integrationError = "$context.integrationErrorMessage"
    })
  }
  default_route_settings {
    throttling_rate_limit  = var.api_rate_limit
    throttling_burst_limit = var.api_burst_limit
  }
}

resource "aws_apigatewayv2_domain_name" "this" {
  count       = local.use_api ? 1 : 0
  domain_name = var.domain_name
  domain_name_configuration {
    certificate_arn = aws_acm_certificate_validation.this.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
}

resource "aws_apigatewayv2_api_mapping" "this" {
  count       = local.use_api ? 1 : 0
  api_id      = aws_apigatewayv2_api.this[0].id
  domain_name = aws_apigatewayv2_domain_name.this[0].id
  stage       = aws_apigatewayv2_stage.default[0].id
}
