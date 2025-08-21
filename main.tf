terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  resolved_bucket_name = var.bucket_name != "" ? var.bucket_name : "ec2-manual-dashboard-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
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
  bucket = aws_s3_bucket.frontend.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "frontend_policy" {
  bucket = aws_s3_bucket.frontend.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = "*",
        Action    = ["s3:GetObject"],
        Resource  = "${aws_s3_bucket.frontend.arn}/*"
      }
    ]
  })
  depends_on = [
    aws_s3_bucket_public_access_block.frontend
  ]
}

data "template_file" "html" {
  template = file("${path.module}/html/index.html.tpl")

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

##########################################
# IAM Role and Policies for Lambda Access
##########################################
resource "aws_iam_role" "lambda_role" {
  name_prefix = "ec2-control-lambda-role-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "ec2_control_policy" {
  name_prefix = "ec2-control-policy-"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "ssm_read_auth" {
  name_prefix = "ssm-read-auth-params-"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["ssm:GetParameter"],
      Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/ec2-auth/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_ec2" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.ec2_control_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_ssm" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.ssm_read_auth.arn
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

#####################
# Lambda Functions
#####################
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_payload.zip"
  source_dir  = "${path.module}/lambda"
}

resource "aws_lambda_function" "ec2_handler" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "ec2-control-handler"
  role             = aws_iam_role.lambda_role.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.9"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 10
}

resource "aws_lambda_function" "authorizer" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "ec2-control-authorizer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "authorizer.lambda_handler"
  runtime          = "python3.9"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 5
}

############################
# API Gateway (HTTP API)
############################
resource "aws_apigatewayv2_api" "api" {
  name          = "ec2-control-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins  = ["*"]
    allow_methods  = ["GET", "OPTIONS"]
    allow_headers  = ["Authorization", "Content-Type"]
    # optional:
    # expose_headers = ["Content-Type"]
    # max_age        = 3600
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                  = aws_apigatewayv2_api.api.id
  integration_type        = "AWS_PROXY"
  integration_uri         = aws_lambda_function.ec2_handler.invoke_arn
  integration_method      = "POST"
  payload_format_version  = "2.0"
}

resource "aws_apigatewayv2_authorizer" "lambda_auth" {
  api_id                              = aws_apigatewayv2_api.api.id
  authorizer_type                     = "REQUEST"
  name                                = "lambda-auth"
  authorizer_uri                      = aws_lambda_function.authorizer.invoke_arn
  identity_sources                    = ["$request.header.Authorization"]
  authorizer_payload_format_version   = "2.0"
  enable_simple_responses             = true
}

resource "aws_apigatewayv2_route" "instances_route" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "GET /instances"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorizer_id      = aws_apigatewayv2_authorizer.lambda_auth.id
  authorization_type = "CUSTOM" # Required to actually link the Lambda authorizer

  depends_on = [
    aws_lambda_permission.apigw_handler,
    aws_lambda_permission.apigw_auth,
    aws_apigatewayv2_authorizer.lambda_auth
  ]
}


resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "prod"
  auto_deploy = true

  depends_on = [
    aws_apigatewayv2_route.instances_route
  ]
}


resource "aws_lambda_permission" "apigw_handler" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ec2_handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}

resource "aws_lambda_permission" "apigw_auth" {
  statement_id  = "AllowExecutionFromAPIGatewayAuth"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}

# Allow Lambda to run SSM commands on instances
resource "aws_iam_policy" "ssm_commands" {
  name_prefix = "ssm-commands-"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["ssm:SendCommand", "ssm:GetCommandInvocation"],
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_ssm_commands" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.ssm_commands.arn
}

