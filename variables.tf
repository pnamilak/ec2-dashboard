variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "bucket_name" {
  description = "Optional fixed bucket name (blank => account/region-based default)"
  type        = string
  default     = ""
}

variable "auth_fallback" {
  description = "Optional 'user:pass' accepted by authorizer for quick testing. Leave empty in prod."
  type        = string
  default     = ""
}

variable "instance_state_filter" {
  description = "Which EC2 states to consider for auto SSM attach"
  type        = list(string)
  default     = ["running", "stopped"]
}

variable "target_tag_selector" {
  description = "Map of tag key => value to select instances for SSM profile attach"
  type        = map(string)
  default     = {}
}

variable "auto_attach_ssm_profile" {
  description = "If true, associate the SSM instance profile to matching instances"
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "VPC ID (required if create_ssm_endpoints = true)"
  type        = string
  default     = null
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for SSM interface endpoints"
  type        = list(string)
  default     = []
}

variable "endpoint_sg_id" {
  description = "Security group ID for interface endpoints (optional)"
  type        = string
  default     = null
}

variable "create_ssm_endpoints" {
  description = "Create SSM interface endpoints in the provided VPC/subnets"
  type        = bool
  default     = false
}
