# ---------------------------------------------------------------- RDS Postgres

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_parameter_group" "this" {
  name   = "${var.name}-pg17"
  family = "postgres17"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "this" {
  identifier     = var.name
  engine         = "postgres"
  engine_version = "17"
  instance_class = var.db_instance_class

  db_name  = "keyhaven"
  username = "keyhaven"
  # The master password is generated and rotated by RDS in Secrets Manager;
  # it never appears in Terraform state.
  manage_master_user_password = true

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_allocated_storage * 5
  storage_type          = "gp3"
  storage_encrypted     = true

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  publicly_accessible    = false
  multi_az               = var.db_multi_az

  backup_retention_period    = 7
  deletion_protection        = var.deletion_protection
  skip_final_snapshot        = !var.deletion_protection
  final_snapshot_identifier  = var.deletion_protection ? "${var.name}-final" : null
  auto_minor_version_upgrade = true
  copy_tags_to_snapshot      = true
}

# ---------------------------------------------------------------- token signing key

resource "aws_secretsmanager_secret" "signing_key" {
  name                    = "${var.name}/signing-key"
  description             = "ES256 private key (PEM) used by Keyhaven to sign ID and access tokens"
  recovery_window_in_days = 7
}

resource "tls_private_key" "signing" {
  count       = var.generate_signing_key ? 1 : 0
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "aws_secretsmanager_secret_version" "signing_key" {
  count         = var.generate_signing_key ? 1 : 0
  secret_id     = aws_secretsmanager_secret.signing_key.id
  secret_string = tls_private_key.signing[0].private_key_pem_pkcs8
}

# ---------------------------------------------------------------- container registry

resource "aws_ecr_repository" "this" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the 20 most recent images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 20 }
      action       = { type = "expire" }
    }]
  })
}
