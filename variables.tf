variable "project_name" {
  type        = string
  default     = "ec2-dashboard"
  description = "Prefix for resource names"
}

variable "aws_region" {
  type        = string
  description = "AWS region (e.g., us-east-2)"
}

variable "website_bucket_name" {
  type        = string
  default     = ""
  description = "Optional explicit S3 bucket name for website (leave empty to auto-generate)"
}

variable "env_names" {
  description = "Environment name tokens to match by EC2 Name tag (used for tabs)."
  type        = list(string)
  # Add/adjust here. The UI will show tabs in this order.
  default     = ["NAQA1","NAQA2","NAQA3","NAQA6","APQA1","EQUA1","Dev"]
}

variable "allowed_email_domain" {
  type        = string
  default     = "gmail.com"
}

variable "ses_sender_email" {
  type        = string
  description = "SES-verified sender email (must be verified in the chosen region)"
}

# username => "password,role,email,name"
# e.g. demo = "demo123,read,inf.pranay@gmail.com,Demo User"
variable "app_users" {
  type        = map(string)
  default     = {}
}

variable "assign_profile_target" {
  type        = string
  default     = "none"
  description = "Attach SSM instance profile to: none|running|stopped|both"
  validation {
    condition     = contains(["none","running","stopped","both"], var.assign_profile_target)
    error_message = "assign_profile_target must be one of none|running|stopped|both"
  }
}

