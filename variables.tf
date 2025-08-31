variable "project_name" { type = string, default = "ec2-dashboard" }
variable "aws_region"   { type = string }
variable "website_bucket_name" { type = string, default = "" }
variable "env_names" {
  description = "Environment name tokens to match by EC2 Name tag (used for tabs)."
  type        = list(string)
  default     = ["NAQA1","NAQA2","NAQA3","NAQA6","APQA1","EUQA1","Dev"]
}
variable "allowed_email_domain" { type = string, default = "gmail.com" }
variable "ses_sender_email"     { type = string }
variable "app_users"            { type = map(string), default = {} }

# Attach SSM instance profile to: none|running|stopped|both
variable "assign_profile_target" {
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none","running","stopped","both"], var.assign_profile_target)
    error_message = "assign_profile_target must be one of none|running|stopped|both"
  }
}
