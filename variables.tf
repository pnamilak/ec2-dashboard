variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "bucket_name" {
  type    = string
  default = ""
}

# CloudFront gates for REAL dashboard
variable "team_cidrs" {
  type    = list(string)
  default = []
}

variable "enable_cf_basic_auth" {
  type    = bool
  default = true
}

# Base64("user:pass") for the REAL dashboard (CloudFront Basic + API Basic fallback)
variable "cf_basic_auth_b64" {
  type    = string
  default = "YWRtaW46UGFzc3dvcmQxMjMh"
}

# OTP settings for ENTRY site
variable "allowed_email_domain" {
  type    = string
  default = "domain.com"
}

variable "ses_sender_email" {
  type    = string
  default = "no-reply@domain.com"
}

variable "otp_ttl_seconds" {
  type    = number
  default = 300
}

variable "jwt_ttl_seconds" {
  type    = number
  default = 3600
}

variable "jwt_secret_param" {
  type    = string
  default = "/ec2-dashboard/auth/jwt_secret"
}

# API basic auth fallback (same as CloudFront basic, so users type once in UI if needed)
variable "auth_fallback" {
  type    = string
  default = "admin:Password123!"
}

# Optional VPC endpoints for SSM
variable "vpc_id" {
  type    = string
  default = null
}

variable "private_subnet_ids" {
  type    = list(string)
  default = []
}

variable "endpoint_sg_id" {
  type    = string
  default = null
}

variable "create_ssm_endpoints" {
  type    = bool
  default = false
}
