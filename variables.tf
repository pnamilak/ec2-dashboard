variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  description = "Name prefix for resources"
  type        = string
  default     = "ec2-dashboard"
}

variable "allowed_email_domain" {
  description = "Only emails from this domain can request OTP"
  type        = string
  default     = "gmail.com"
}

variable "ses_sender_email" {
  description = "Verified SES sender email address"
  type        = string
}

variable "website_bucket_name" {
  description = "Optional: use an existing bucket name for the site (leave blank to create new)"
  type        = string
  default     = ""
}

variable "app_users" {
  description = "Map of username -> plaintext password (stored as SecureString in SSM). Change after first deploy."
  type        = map(string)
  default = {
    admin = "ChangeMe123!"
  }
}

variable "env_names" {
  description = "Environments shown as tabs"
  type        = list(string)
  default     = ["NAQA1", "NAQA2", "NAQA3", "NAQA6", "APQA1", "EUQA1"]
}

variable "assign_profile_target" {
  description = "Attach SSM instance profile to: none | running | stopped | both"
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none", "running", "stopped", "both"], var.assign_profile_target)
    error_message = "assign_profile_target must be one of: none, running, stopped, both"
  }
}
