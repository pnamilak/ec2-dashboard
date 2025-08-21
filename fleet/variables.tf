variable "key_name" {
  description = "Existing EC2 key pair name"
  type        = string
}

variable "subnet_id" {
  description = "Subnet to launch instances into"
  type        = string
}

variable "security_group_ids_csv" {
  description = "Comma-separated SG IDs, e.g. sg-1,sg-2 (leave empty for none)"
  type        = string
  default     = ""
}

variable "instance_prefix" {
  description = "Prefix for instance Name tags, e.g. naqa1-win2022-"
  type        = string
  default     = "naqa1-win2022-"
}

variable "instance_count" {
  description = "How many instances to create"
  type        = number
  default     = 10
}

variable "environment" {
  description = "Environment tag value (and makes the dashboard matching easier)"
  type        = string
  default     = "NAQA1"
}

variable "instance_type" {
  type    = string
  default = "t2.medium"
}

variable "root_volume_size" {
  type    = number
  default = 50
}

# ---- Optional: private subnets? Create VPC endpoints for SSM ----
variable "create_ssm_endpoints"  { type = bool         default = false }
variable "vpc_id"                { type = string       default = null }
variable "private_subnet_ids_csv"{ type = string       default = "" }  # comma-separated
variable "endpoint_sg_id"        { type = string       default = null }
