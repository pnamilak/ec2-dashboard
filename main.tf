locals {
  site_bucket_name = var.website_bucket_name != "" ? var.website_bucket_name : "${var.project_name}-${random_id.site.hex}-site"
  name_filters     = [for e in var.env_names : "*${e}*"]
}

resource "random_id" "site" { byte_length = 3 }

# ----------------------- S3 Website -----------------------
resource "aws_s3_bucket" "website" {
  bucket        = local.site_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_ownership_controls" "site" {
  bucket = aws_s3_bucket.website.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.website.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

# ----------------------- CloudFront (OAC) -----------------------
resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "${var.project_name}-oac"
  description                       = "OAC for S3 website"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  comment             = "${var.project_name} static site"
  default_root_object = "index.html"
  is_ipv6_enabled     = false
  price_class         = "PriceClass_All"
  wait_for_deployment = true

  origin {
    domain_name              = aws_s3_bucket.website.bucket_regional_domain_name
    origin_id                = "s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET","HEAD","OPTIONS"]
    cached_methods         = ["GET","HEAD"]
    target_origin_id       = "s3-origin"
    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true

    forwarded_values {
      query_string = false
      headers      = ["Origin"]
      cookies { forward = "none" }
    }
  }

  restrictions { geo_restriction { restriction_type = "none" } }
  viewer_certificate { cloudfront_default_certificate = true }
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.website.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowCloudFrontServicePrincipal",
      Effect    = "Allow",
      Principal = { Service = "cloudfront.amazonaws.com" },
      Action    = ["s3:GetObject"],
      Resource  = ["${aws_s3_bucket.website.arn}/*"],
      Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.site.arn } }
    }]
  })
  depends_on = [aws_cloudfront_distribution.site]
}

# ----------------------- DynamoDB for OTP -----------------------
resource "aws_dynamodb_table" "otp" {
  name         = "${var.project_name}-otp"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "email"
  attribute { name = "email" type = "S" }
}

# ----------------------- SSM Params -----------------------
resource "random_password" "jwt" { length = 32 special = false }
resource "aws_ssm_parameter" "jwt_secret" {
  name  = "/${var.project_name}/jwt-secret"
  type  = "SecureString"
  value = random_password.jwt.result
}

resource "aws_ssm_parameter" "user_params" {
  for_each = var.app_users
  name     = "/${var.project_name}/users/${each.key}"
  type     = "SecureString"
  value    = each.value
}

# ----------------------- Lambda: API -----------------------
data "archive_file" "api_zip" {
  type        = "zip"
  source_file = "lambda/handler.py"
  output_path = "lambda/handler.zip"
}
data "archive_file" "auth_zip" {
  type        = "zip"
  source_file = "lambda/authorizer.py"
  output_path = "lambda/authorizer.zip"
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.project_name}-lambda-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.project_name}-policy"
  role = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      { Effect="Allow", Action=["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], Resource="*" },
      { Effect="Allow", Action=["ses:SendEmail","ses:SendRawEmail"], Resource="*" },
      { Effect="Allow", Action=[
          "ssm:GetParameter","ssm:GetParameters","ssm:DescribeParameters",
          "ssm:SendCommand","ssm:GetCommandInvocation","ssm:DescribeInstanceInformation"
        ], Resource="*" },
      { Effect="Allow", Action=["dynamodb:PutItem","dynamodb:GetItem","dynamodb:DeleteItem"], Resource=aws_dynamodb_table.otp.arn },
      { Effect="Allow", Action=["ec2:DescribeInstances","ec2:StartInstances","ec2:StopInstances"], Resource="*" }
    ]
  })
}

resource "aws_lambda_function" "api" {
  function_name = "${var.project_name}-api"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.12"
  handler       = "handler.lambda_handler"
  filename      = data.archive_file.api_zip.output_path
  timeout       = 30
  environment {
    variables = {
      REGION            = var.aws_region
      OTP_TABLE         = aws_dynamodb_table.otp.name
      SES_SENDER        = var.ses_sender_email
      ALLOWED_DOMAIN    = var.allowed_email_domain
      PARAM_USER_PREFIX = "/${var.project_name}/users"
      JWT_PARAM         = aws_ssm_parameter.jwt_secret.name
      ENV_NAMES         = join(",", var.env_names)
    }
  }
}

resource "aws_lambda_function" "authorizer" {
  function_name = "${var.project_name}-authorizer"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.12"
  handler       = "authorizer.lambda_handler"
  filename      = data.archive_file.auth_zip.output_path
  timeout       = 10
  environment { variables = { REGION = var.aws_region, JWT_PARAM = aws_ssm_parameter.jwt_secret.name } }
}

# ----------------------- API Gateway -----------------------
resource "aws_apigatewayv2_api" "api" {
  name          = "${var.project_name}-http"
  protocol_type = "HTTP"
  cors_configuration {
    allow_origins = ["*"]
    allow_headers = ["authorization","content-type"]
    allow_methods = ["GET","POST","OPTIONS"]
  }
}

resource "aws_apigatewayv2_integration" "api_lm" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_authorizer" "auth" {
  api_id                             = aws_apigatewayv2_api.api.id
  authorizer_type                    = "REQUEST"
  name                               = "jwt-req-auth"
  authorizer_uri                     = aws_lambda_function.authorizer.invoke_arn
  identity_sources                   = ["$request.header.Authorization"]
  authorizer_payload_format_version  = "2.0"
  enable_simple_responses            = true
  authorizer_result_ttl_in_seconds   = 300
}

# Public routes
resource "aws_apigatewayv2_route" "r_request_otp" { api_id=aws_apigatewayv2_api.api.id route_key="POST /request-otp" target="integrations/${aws_apigatewayv2_integration.api_lm.id}" }
resource "aws_apigatewayv2_route" "r_verify_otp"  { api_id=aws_apigatewayv2_api.api.id route_key="POST /verify-otp"  target="integrations/${aws_apigatewayv2_integration.api_lm.id}" }
resource "aws_apigatewayv2_route" "r_login"       { api_id=aws_apigatewayv2_api.api.id route_key="POST /login"       target="integrations/${aws_apigatewayv2_integration.api_lm.id}" }

# Protected routes
resource "aws_apigatewayv2_route" "r_instances"       { api_id=aws_apigatewayv2_api.api.id route_key="GET /instances"        target="integrations/${aws_apigatewayv2_integration.api_lm.id}" authorization_type="CUSTOM" authorizer_id=aws_apigatewayv2_authorizer.auth.id }
resource "aws_apigatewayv2_route" "r_instance_action" { api_id=aws_apigatewayv2_api.api.id route_key="POST /instance-action"  target="integrations/${aws_apigatewayv2_integration.api_lm.id}" authorization_type="CUSTOM" authorizer_id=aws_apigatewayv2_authorizer.auth.id }
resource "aws_apigatewayv2_route" "r_bulk"            { api_id=aws_apigatewayv2_api.api.id route_key="POST /bulk-action"     target="integrations/${aws_apigatewayv2_integration.api_lm.id}" authorization_type="CUSTOM" authorizer_id=aws_apigatewayv2_authorizer.auth.id }
resource "aws_apigatewayv2_route" "r_services"        { api_id=aws_apigatewayv2_api.api.id route_key="POST /services"        target="integrations/${aws_apigatewayv2_integration.api_lm.id}" authorization_type="CUSTOM" authorizer_id=aws_apigatewayv2_authorizer.auth.id }

resource "aws_apigatewayv2_stage" "default" { api_id = aws_apigatewayv2_api.api.id name="$default" auto_deploy=true }

resource "aws_lambda_permission" "apigw_invoke_api"  { statement_id="AllowAPIGInvoke"     action="lambda:InvokeFunction" function_name=aws_lambda_function.api.function_name        principal="apigateway.amazonaws.com" source_arn="${aws_apigatewayv2_api.api.execution_arn}/*/*" }
resource "aws_lambda_permission" "apigw_invoke_auth" { statement_id="AllowAPIGInvokeAuth" action="lambda:InvokeFunction" function_name=aws_lambda_function.authorizer.function_name principal="apigateway.amazonaws.com" source_arn="${aws_apigatewayv2_api.api.execution_arn}/*/*" }

# ----------------------- SSM Instance Profile (optional attachment) -----------------------
resource "aws_iam_role" "ec2_ssm_role" {
  name = "${var.project_name}-ec2-ssm-role"
  assume_role_policy = jsonencode({
    Version="2012-10-17", Statement=[{ Effect="Allow", Principal={ Service="ec2.amazonaws.com" }, Action="sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy_attachment" "ec2_ssm_core" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "${var.project_name}-ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm_role.name
}

# Discover instances by env token + state
data "aws_instances" "running" {
  instance_state_names = ["running"]
  filter { name = "tag:Name" values = local.name_filters }
}
data "aws_instances" "stopped" {
  instance_state_names = ["stopped"]
  filter { name = "tag:Name" values = local.name_filters }
}

locals {
  running_ids = try(data.aws_instances.running.ids, [])
  stopped_ids = try(data.aws_instances.stopped.ids, [])
  target_ids  = var.assign_profile_target == "running" ? local.running_ids :
                var.assign_profile_target == "stopped" ? local.stopped_ids :
                var.assign_profile_target == "both" ? distinct(concat(local.running_ids, local.stopped_ids)) : []
}

resource "aws_iam_instance_profile_association" "attach" {
  for_each            = { for id in local.target_ids : id => id }
  instance_id         = each.value
  iam_instance_profile = aws_iam_instance_profile.ec2_ssm_profile.name
  replace_existing     = true
}
