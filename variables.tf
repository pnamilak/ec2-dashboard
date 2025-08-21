variable "aws_region" {
  default = "us-east-2"
}

variable "bucket_name" {
  type        = string
  description = "Optional. Frontend S3 bucket name. Leave empty to auto-generate a unique name."
  default     = ""   # <-- changed from "ec2-manual-dashboard"
}

variable "environment" {
  description = "Environment identifier (e.g., mypersonalAWS)"
  type        = string
}

