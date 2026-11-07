variable "name" {
  description = "Name prefix for all resources."
  type        = string
  default     = "keyhaven"
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "domain_name" {
  description = "Public hostname for the identity provider, e.g. id.example.com. Becomes the OIDC issuer and WebAuthn RP ID."
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID that contains domain_name (used for the ACM certificate and DNS record)."
  type        = string
}

variable "image_tag" {
  description = "Tag of the keyhaven image in the ECR repository created by this module."
  type        = string
  default     = "v0.1.0"
}

variable "rp_display_name" {
  description = "Name shown to users on sign-in pages and in passkey prompts."
  type        = string
  default     = "Keyhaven"
}

variable "allow_signup" {
  description = "Allow anyone to create an account. Set false for invite/admin-only deployments."
  type        = bool
  default     = true
}

variable "desired_count" {
  description = "Baseline number of Fargate tasks. Use 2+ for high availability."
  type        = number
  default     = 2
}

variable "max_count" {
  description = "Maximum number of tasks for CPU-based autoscaling."
  type        = number
  default     = 6
}

variable "task_cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 256
}

variable "task_memory" {
  description = "Fargate task memory (MiB)."
  type        = number
  default     = 512
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "single_nat_gateway" {
  description = "Use one NAT gateway (cheaper) instead of one per AZ (more resilient)."
  type        = bool
  default     = true
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "Initial RDS storage in GiB (autoscales up to 5x)."
  type        = number
  default     = 20
}

variable "db_multi_az" {
  description = "Run RDS in Multi-AZ mode."
  type        = bool
  default     = false
}

variable "deletion_protection" {
  description = "Protect the database and load balancer from accidental deletion."
  type        = bool
  default     = true
}

variable "generate_signing_key" {
  description = "Generate the token signing key with Terraform (stored in state). Set false to populate the secret yourself with `keyhaven genkey`."
  type        = bool
  default     = true
}

variable "enable_waf" {
  description = "Attach an AWS WAF web ACL (managed rule sets + per-IP rate limit) to the load balancer."
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "Maximum requests per IP per 5 minutes before WAF blocks."
  type        = number
  default     = 1000
}

variable "log_retention_days" {
  description = "CloudWatch log retention."
  type        = number
  default     = 30
}
