variable "aws_region" {
  default = "us-east-2"
}

variable "bucket_name" {
  default = "ec2-manual-dashboard"
}
variable "environment" {
  description = "Environment identifier (e.g., mypersonalAWS)"
  type        = string
}

