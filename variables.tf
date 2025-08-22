variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-2"
}

variable "bucket_name" {
  description = "Optional public S3 website bucket name. Leave empty to auto-generate."
  type        = string
  default     = ""
}

variable "environment" {
  description = "Environment identifier (e.g., mypersonalAWS)"
  type        = string
}

variable "existing_instance_ids" {
  description = "Attach SSM instance profile to these existing EC2 instance IDs (optional, via CLI not TF)."
  type        = list(string)
  default     = []
}

variable "create_ssm_endpoints" {
  type    = bool
  default = false
}

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

# Auto-attach the SSM instance profile to instances Terraform did not create
variable "auto_attach_ssm_profile" {
  description = "If true, associate the created instance profile to matching EC2 instances."
  type        = bool
  default     = true
}

# Which states to target for auto-attach (default = running only)
variable "instance_state_filter" {
  description = "EC2 states to include when auto-attaching the profile."
  type        = list(string)
  default     = ["running"]
}

# Optional tag selector to narrow which instances get the profile, e.g. { Environment = "NAQA1" }
variable "target_tag_selector" {
  description = "Optional key/value tag filter for instances to attach the profile to."
  type        = map(string)
  default     = {}
}
