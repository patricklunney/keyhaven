terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Recommended: keep state in S3 (it contains the generated signing key unless
  # generate_signing_key = false). Uncomment and fill in:
  # backend "s3" {
  #   bucket       = "my-terraform-state"
  #   key          = "keyhaven/terraform.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "keyhaven"
      ManagedBy = "terraform"
      Name      = var.name
    }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

locals {
  azs    = slice(data.aws_availability_zones.available.names, 0, 2)
  issuer = "https://${var.domain_name}"
}
