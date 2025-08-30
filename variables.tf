variable "project_name" { type = string }
variable "aws_region"   { type = string }

variable "ses_sender_email" {
  description = "Verified SES sender address in this region"
  type        = string
}

variable "allowed_email_domain" {
  description = "Only this domain can request OTP"
  type        = string
  default     = "gmail.com"
}

variable "env_names" {
  description = "Environment tabs"
  type        = list(string)
  default     = ["NAQA1","NAQA2","NAQA3","NAQA6","APQA1","EUQA1"]
}

variable "website_bucket_name" {
  description = "Optional fixed bucket name (otherwise generated)"
  type        = string
  default     = ""
}

variable "assign_profile_target" {
  description = "Attach SSM instance profile: none|running|stopped|both"
  type        = string
  default     = "none"
}

variable "app_users" {
  description = "Map of username => 'password,role,email,name'"
  type        = map(string)
  default     = {
    demo     = "demo,read,demo@example.com,Demo User"
    admin    = "changeme,admin,admin@example.com,Admin"
    pnamilak = "changeme,admin,inf.pranay@gmail.com,Pranay"
  }
}
