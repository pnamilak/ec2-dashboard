variable "aws_region" {
  default = "us-east-2"
}

variable "bucket_name" {
  type        = string
  description = "Optional. Frontend S3 bucket name. Leave empty to auto-generate a unique one."
  default     = ""
}

variable "environment" {
  description = "Environment identifier (e.g., mypersonalAWS)"
  type        = string
}

variable "existing_instance_ids" {
  description = "Attach SSM instance profile to these existing EC2 instance IDs (optional)."
  type        = list(string)
  default     = []
}

variable "create_ssm_endpoints"  { type = bool        default = false }
variable "vpc_id"                { type = string      default = null }
variable "private_subnet_ids"    { type = list(string) default = [] }
variable "endpoint_sg_id"        { type = string      default = null }
