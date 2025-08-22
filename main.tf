terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
    template = {
      source  = "hashicorp/template"
      version = ">= 2.2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

##########################
# Standardized source paths
##########################
# Place your files like this:
#   lambda/handler.py
#   lambda/authorizer.py
#   html/index.html.tpl
locals {
  lambda_dir = "${path.module}/lambda"
  web_dir    = "${path.module}/html"
}

##########################
# Bucket name resolution
##########################
locals {
  resolved_bucket_name = var.bucket_name != "" ? var.bucket_name : "ec2-dashboard-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
}

##########################
# S3 Bucket for Frontend
##########################
resource "aws_s3_bucket" "frontend" {
  bucket        = local.resolved_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_website_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  index_document {
    suffix = "index.html"
  }
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket                  = aws_s3_bucket.frontend.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "frontend_policy" {
  bucket = aws_s3_bucket.frontend.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = "*",
      Action    = ["s3:GetObject"],
      Resource  = "${aws_s3_bucket.frontend.arn}/*"
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.frontend]
}

##########################
# Package Lambda Code
##########################
# Zips the two Python files from ./lambda
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_payload.zip"

  source {
    content  = file("${local.lambda_dir}/handler.py")
    filename = "handler.py"
  }

  source {
    content  = file("${local.lambda_dir}/authorizer.py")
    filename = "authorizer.py"
  }
}

##########################
# API Gateway (HTTP API v2)
##########################
resource "aws_apigatewayv2_api" "api" {
  name                       = "ec2-control-api"
  protocol_type              = "HTTP"
  route_selection_expression = "$request.method $request.path"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type"]
  }
}

resource "aws_lambda_function" "authorizer" {
  function_name = "ec2-control-authorizer"
  role          = aws_iam_role.lambda_role.arn
  handler       = "authorizer.lambda_handler"
  runtime       = "python3.9"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout     = 5
  memory_size = 128
}

resource "aws_lambda_function" "ec2_handler" {
  function_name = "ec2-control-handler"
  role          = aws_iam_role.lambda_role.arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.9"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout     = 10
  memory_size = 128
}

resource "aws_apigatewayv2_authorizer" "lambda_auth" {
  api_id                            = aws_apigatewayv2_api.api.id
  name                              = "lambda-auth"
  authorizer_type                   = "REQUEST"
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = true
  identity_sources                  = ["$request.header.Authorization"]

  authorizer_uri = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/${aws_lambda_function.authorizer.invoke_arn}/invocations"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  payload_format_version = "2.0"

  integration_uri = aws_lambda_function.ec2_handler.invoke_arn
}

resource "aws_apigatewayv2_route" "instances_route" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "GET /instances"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.lambda_auth.id
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "prod"
  auto_deploy = true
}

##########################
# IAM for Lambda
##########################
resource "aws_iam_role" "lambda_role" {
  name_prefix = "ec2-control-lambda-role-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Action    = "sts:AssumeRole",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# Basic logging
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# EC2 Describe/Start/Stop
resource "aws_iam_policy" "ec2_control_policy" {
  name_prefix = "ec2-control-policy-"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = [
        "ec2:DescribeInstances",
        "ec2:StartInstances",
        "ec2:StopInstances"
      ],
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_ec2" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.ec2_control_policy.arn
}

# If authorizer reads SSM parameters for auth (e.g., /ec2-auth/*)
resource "aws_iam_policy" "ssm_read_auth" {
  name_prefix = "ssm-read-auth-params-"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParameterHistory"],
      Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/ec2-auth/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_ssm" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.ssm_read_auth.arn
}

# ✅ SSM command permissions for service controls
resource "aws_iam_policy" "lambda_ssm_commands" {
  name_prefix = "lambda-ssm-commands-"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:ListCommands",
        "ssm:ListCommandInvocations",
        "ssm:CancelCommand"
      ],
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_ssm_commands" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_ssm_commands.arn
}

##########################
# Lambda invoke permissions from API Gateway
##########################
resource "aws_lambda_permission" "apigw_auth" {
  statement_id  = "AllowExecutionFromAPIGatewayAuth"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/authorizers/*"
}

resource "aws_lambda_permission" "apigw_handler" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ec2_handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}

##########################
# HTML → S3 (templated)
##########################
data "template_file" "html" {
  template = file("${local.web_dir}/index.html.tpl")
  vars = {
    api_url = aws_apigatewayv2_stage.default.invoke_url
  }
}

resource "aws_s3_object" "index_html" {
  bucket       = aws_s3_bucket.frontend.id
  key          = "index.html"
  content      = data.template_file.html.rendered
  content_type = "text/html"
}

##########################
# (Optional) SSM VPC Interface Endpoints
##########################
locals {
  ssm_endpoints = ["ssm", "ssmmessages", "ec2messages"]
}

resource "aws_vpc_endpoint" "ssm_endpoints" {
  count               = var.create_ssm_endpoints ? length(local.ssm_endpoints) : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${local.ssm_endpoints[count.index]}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = var.endpoint_sg_id != null ? [var.endpoint_sg_id] : []
  private_dns_enabled = true
}
