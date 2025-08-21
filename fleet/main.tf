terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {}

data "aws_region" "current" {}

# Convert CSV inputs to lists
locals {
  security_group_ids = length(trimspace(var.security_group_ids_csv)) == 0
    ? []
    : [for s in split(",", var.security_group_ids_csv) : trimspace(s)]

  private_subnet_ids = length(trimspace(var.private_subnet_ids_csv)) == 0
    ? []
    : [for s in split(",", var.private_subnet_ids_csv) : trimspace(s)]
}

# Latest Windows Server 2022 English Full Base (x86_64)
data "aws_ami" "windows2022" {
  most_recent = true
  owners      = ["amazon"]

  filter { name = "name"                 values = ["Windows_Server-2022-English-Full-Base-*"] }
  filter { name = "virtualization-type"  values = ["hvm"] }
  filter { name = "architecture"         values = ["x86_64"] }
  filter { name = "root-device-type"     values = ["ebs"] }
}

# ---- IAM role/profile for SSM on EC2 ----
resource "aws_iam_role" "ec2_ssm_role" {
  name_prefix = "ec2-ssm-core-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_core" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_ssm" {
  name_prefix = "ec2-ssm-"
  role        = aws_iam_role.ec2_ssm_role.name
}

# ---- Optional: VPC Endpoints for SSM (for private subnets) ----
locals { ssm_services = ["ssm", "ssmmessages", "ec2messages"] }

resource "aws_vpc_endpoint" "ssm" {
  count               = var.create_ssm_endpoints ? length(local.ssm_services) : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${local.ssm_services[count.index]}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.private_subnet_ids
  security_group_ids  = var.endpoint_sg_id != null ? [var.endpoint_sg_id] : []
  private_dns_enabled = true
}

# ---- The Windows 2022 fleet ----
resource "aws_instance" "win2022" {
  count                  = var.instance_count
  ami                    = data.aws_ami.windows2022.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = local.security_group_ids
  iam_instance_profile   = aws_iam_instance_profile.ec2_ssm.name
  get_password_data      = true

  root_block_device {
    volume_size = var.root_volume_size
    volume_type = "gp3"
  }

  tags = {
    Name        = "${var.instance_prefix}${format("%02d", count.index + 1)}"
    Environment = var.environment
    OS          = "Windows2022"
    ManagedBy   = "Terraform"
  }

  # small spread if the subnet has AZ variants (optional):
  # placement_group, or nothing – simplest default here.
}
