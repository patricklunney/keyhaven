# Copy to terraform.tfvars and edit.
region          = "us-east-1"
domain_name     = "id.example.com"
hosted_zone_id  = "Z0123456789ABCDEFGHIJ"
image_tag       = "v0.1.0"
rp_display_name = "Example Sign-In"
allow_signup    = true

# Production hardening
desired_count       = 2
db_multi_az         = true
single_nat_gateway  = false
deletion_protection = true
