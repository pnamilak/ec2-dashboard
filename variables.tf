variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "us-east-2"
}

variable "website_bucket_name" {
  type        = string
  description = "Optional: existing S3 bucket to reuse. Leave empty to create deterministic name."
  default     = ""
}

variable "name_prefix" {
  type        = string
  description = "Prefix for resources (lambdas, etc.)"
  default     = "ec2-control"
}
