variable "project_name" {
  type    = string
  default = "ec2-dashboard"
}

variable "aws_region" {
  type = string
}

variable "website_bucket_name" {
  type    = string
  default = ""
}

variable "env_names" {
  description = "Environment tokens to match in EC2 Name tag (tabs)."
  type        = list(string)
  default     = ["naqa1","naqa2","naqa3","naqa6","apqa1","euqa1","dm-dev","dm-qa"]
}

variable "allowed_email_domain" {
  type    = string
  default = "gmail.com"
}

variable "ses_sender_email" {
  type = string
}

# username => "password,role,email,name"
variable "app_users" {
  type    = map(string)
  default = {}
}

# Attach SSM instance profile to: none|running|stopped|both
variable "assign_profile_target" {
  type    = string
  default = "none"
  validation {
    condition     = contains(["none","running","stopped","both"], var.assign_profile_target)
    error_message = "assign_profile_target must be one of none|running|stopped|both"
  }
}
