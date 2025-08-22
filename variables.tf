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
