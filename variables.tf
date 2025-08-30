variable "project_name" {
  type = string
  default = "ec2-dashboard"
}

variable "aws_region" {
  type = string
  default = "us-east-2"
}

variable "ses_sender_email" {
  type = string
  description = "Verified SES sender email"
}

variable "allowed_email_domain" {
  type = string
  default = "gmail.com"
}

variable "env_names" {
  type = list(string)
  default = ["NAQA1","NAQA2","NAQA3","NAQA6","APQA1","EUQA1"]
}

variable "website_bucket_name" {
  type = string
  default = ""
}

# Map of app users => "password,role,email,name"
# Example: { admin = "P@ssw0rd,admin,me@example.com,Admin Guy", demo = "demo,read,demo@example.com,Demo User" }
variable "app_users" {
  type = map(string)
  default = {}
}

# Attach SSM profile to which set of instances? one of: none|running|stopped|both
variable "assign_profile_target" {
  type = string
  default = "none"
}
