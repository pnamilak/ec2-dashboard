variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "bucket_name" {
  description = "Optional fixed bucket name"
  type        = string
  default     = ""
}

variable "instance_state_filter" {
  description = "Which EC2 states to consider for auto SSM attach"
  type        = list(string)
  default     = ["running", "stopped"]
}

variable "target_tag_selector" {
  description = "Optional tag selector for auto attach (key -> value)"
  type        = map(string)
  default     = {}
}

variable "auto_attach_ssm_profile" {
  description = "Try to associate the SSM instance profile to the matched EC2 instances"
  type        = bool
  default     = false
}

variable "create_ssm_endpoints" {
  description = "Create SSM interface endpoints in your VPC"
  type        = bool
  default     = false
}

variable "vpc_id" {
  type        = string
  default     = null
}

variable "private_subnet_ids" {
  type        = list(string)
  default     = []
}

variable "endpoint_sg_id" {
  type        = string
  default     = null
}
