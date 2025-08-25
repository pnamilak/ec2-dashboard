terraform {
  required_providers {
    aws      = { source = "hashicorp/aws",      version = "~> 5.0" }
    archive  = { source = "hashicorp/archive",  version = ">= 2.4.0" }
    template = { source = "hashicorp/template", version = ">= 2.2.0" }
  }
}

provider "aws" { region = var.aws_region }

# WAF (CloudFront scope) must be us-east-1
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  lambda_dir           = "${path.module}/lambda"
  web_dir              = "${path.module}/html"
  resolved_bucket_name = var.bucket_name != "" ? var.bucket_name : "ec2-dashboard-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
}

# ---------------- S3 (private) ----------------
resource "aws_s3_bucket" "frontend" {
  bucket        = local.resolved_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket                  = aws_s3_bucket.frontend.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------- Package Lambda code ----------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/dist/lambda.zip"

  source { content = file("${local.lambda_dir}/handler.py");    filename = "handler.py" }
  source { content = file("${local.lambda_dir}/authorizer.py"); filename = "authorizer.py" }
}

# ---------------- API Gateway (HTTP API v2) ----------------
resource "aws_apigatewayv2_api" "api" {
  name                       = "ec2-control-api"
  protocol_type              = "HTTP"
  route_selection_expression = "$request.method $request.path"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type"]
  }
}

resource "aws_lambda_function" "authorizer" {
  function_name    = "ec2-control-authorizer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "authorizer.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 5
  memory_size      = 128
  environment { variables = { AUTH_FALLBACK = var.auth_fallback } }
}

resource "aws_lambda_function" "ec2_handler" {
  function_name    = "ec2-control-handler"
  role             = aws_iam_role.lambda_role.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30
  memory_size      = 256
}

resource "aws_apigatewayv2_authorizer" "lambda_auth" {
  api_id                            = aws_apigatewayv2_api.api.id
  name                              = "lambda-auth"
  authorizer_type                   = "REQUEST"
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = true
  identity_sources                  = ["$request.header.Authorization"]
  authorizer_uri                    = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/${aws_lambda_function.authorizer.arn}/invocations"
  depends_on                        = [aws_lambda_permission.apigw_auth]
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  payload_format_version = "2.0"
  integration_uri        = aws_lambda_function.ec2_handler.invoke_arn
}

resource "aws_apigatewayv2_route" "instances_get" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "GET /instances"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.lambda_auth.id
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "instances_post" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "POST /instances"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.lambda_auth.id
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "prod"
  auto_deploy = true
}

# ---------------- IAM for Lambda ----------------
resource "aws_iam_role" "lambda_role" {
  name_prefix = "ec2-control-lambda-role-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{ Effect="Allow", Action="sts:AssumeRole", Principal={ Service="lambda.amazonaws.com" } }]
  })
}
resource "aws_iam_role_policy_attachment" "lambda_basic" { role = aws_iam_role.lambda_role.name  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" }
resource "aws_iam_policy" "ec2_control_policy" {
  name_prefix = "ec2-control-policy-"
  policy = jsonencode({ Version="2012-10-17", Statement=[{ Effect="Allow", Action=[
    "ec2:DescribeInstances","ec2:StartInstances","ec2:StopInstances","ec2:RebootInstances"], Resource="*" }] })
}
resource "aws_iam_role_policy_attachment" "lambda_ec2" { role = aws_iam_role.lambda_role.name  policy_arn = aws_iam_policy.ec2_control_policy.arn }

resource "aws_iam_policy" "ssm_read_auth" {
  name_prefix = "ssm-read-auth-params-"
  policy = jsonencode({ Version="2012-10-17", Statement=[{ Effect="Allow", Action=[
    "ssm:GetParameter","ssm:GetParameters","ssm:GetParameterHistory"],
    Resource=[
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/ec2-auth/*",
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/ec2dash/auth/*",
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/ec2-dashboard/auth/*"
    ] }] })
}
resource "aws_iam_role_policy_attachment" "lambda_ssm" { role = aws_iam_role.lambda_role.name  policy_arn = aws_iam_policy.ssm_read_auth.arn }

resource "aws_iam_policy" "lambda_ssm_commands" {
  name_prefix = "lambda-ssm-commands-"
  policy = jsonencode({ Version="2012-10-17", Statement=[{ Effect="Allow", Action:[
    "ssm:SendCommand","ssm:GetCommandInvocation","ssm:ListCommands","ssm:ListCommandInvocations",
    "ssm:CancelCommand","ssm:DescribeInstanceInformation"], Resource="*" }] })
}
resource "aws_iam_role_policy_attachment" "lambda_ssm_commands" { role = aws_iam_role.lambda_role.name  policy_arn = aws_iam_policy.lambda_ssm_commands.arn }

# ---------------- APIGW -> Lambda invoke perms ----------------
resource "aws_lambda_permission" "apigw_auth"     { statement_id="AllowExecutionFromAPIGatewayAuth" action="lambda:InvokeFunction" function_name=aws_lambda_function.authorizer.function_name principal="apigateway.amazonaws.com" source_arn="${aws_apigatewayv2_api.api.execution_arn}/authorizers/*" }
resource "aws_lambda_permission" "apigw_handler"  { statement_id="AllowExecutionFromAPIGateway"     action="lambda:InvokeFunction" function_name=aws_lambda_function.ec2_handler.function_name principal="apigateway.amazonaws.com" source_arn="${aws_apigatewayv2_api.api.execution_arn}/*/*" }

# ---------------- Upload HTML/JS to S3 (private) ----------------
locals {
  app_js_path  = "${local.web_dir}/app.v3.js"
  app_js_md5   = filemd5(local.app_js_path)
  app_js_short = substr(local.app_js_md5, 0, 8)
}

data "template_file" "html" {
  template = file("${local.web_dir}/index.html.tpl")
  vars = { api_url = aws_apigatewayv2_stage.default.invoke_url, js_ver = local.app_js_md5, js_ver_short = local.app_js_short }
}

resource "aws_s3_object" "index_html" { bucket = aws_s3_bucket.frontend.id  key = "index.html"  content = data.template_file.html.rendered content_type = "text/html" cache_control = "no-cache" }
resource "aws_s3_object" "app_v3_js"  { bucket = aws_s3_bucket.frontend.id  key = "app.v3.js"   source  = local.app_js_path             content_type = "application/javascript" cache_control = "max-age=31536000, immutable" }

# ---------------- CloudFront + OAC ----------------
resource "aws_cloudfront_origin_access_control" "oac" {
  name = "ec2dash-s3-oac"
  description = "Origin Access Control for S3 frontend"
  origin_access_control_origin_type = "s3"
  signing_behavior = "always"
  signing_protocol = "sigv4"
}

# Optional: Basic Auth at the edge
resource "aws_cloudfront_function" "basic_auth" {
  count   = var.enable_cf_basic_auth ? 1 : 0
  name    = "ec2dash-basic-auth"
  runtime = "cloudfront-js-1.0"
  publish = true
  code    = <<-EOJS
function handler(event) {
  var req = event.request;
  var h = req.headers || {};
  var auth = (h.authorization && h.authorization.value) || "";
  var ok = auth === "Basic ${var.cf_basic_auth_b64}";
  if (!ok) {
    return {
      statusCode: 401,
      statusDescription: "Unauthorized",
      headers: { "www-authenticate": { value: "Basic realm=\\"Restricted\\"" } }
    };
  }
  return req;
}
EOJS
}

# --- Normalize IPs: add /32 if omitted ---
locals {
  team_cidrs_normalized = [for a in var.team_cidrs : can(regex(".+/.+", a)) ? a : "${a}/32" ]
}

# Optional: WAF allow-list (CloudFront scope)
resource "aws_wafv2_ip_set" "team" {
  provider           = aws.us_east_1
  count              = length(var.team_cidrs) > 0 ? 1 : 0
  name               = "ec2dash-team-ips"
  description        = "Team IP allow-list for CloudFront"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = local.team_cidrs_normalized
}

resource "aws_wafv2_web_acl" "allow_team" {
  provider = aws.us_east_1
  count    = length(var.team_cidrs) > 0 ? 1 : 0

  name        = "ec2dash-allow-team"
  description = "Only allow requests from team CIDRs"
  scope       = "CLOUDFRONT"

  default_action { block {} }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "ec2dash-allow-team"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "AllowTeamIPs"
    priority = 1

    action { allow {} }

    statement {
      ip_set_reference_statement { arn = aws_wafv2_ip_set.team[0].arn }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowTeamIPs"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled             = true
  comment             = "EC2 Dashboard Frontend"
  default_root_object = "index.html"

  origin {
    domain_name              = aws_s3_bucket.frontend.bucket_regional_domain_name
    origin_id                = "s3-frontend"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  default_cache_behavior {
    target_origin_id       = "s3-frontend"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    forwarded_values {
      query_string = false
      headers      = ["Origin"]
      cookies { forward = "none" }
    }

    dynamic "function_association" {
      for_each = var.enable_cf_basic_auth ? [1] : []
      content {
        event_type   = "viewer-request"
        function_arn = aws_cloudfront_function.basic_auth[0].arn
      }
    }
  }

  custom_error_response { error_code = 403 response_code = 200 response_page_path = "/index.html" error_caching_min_ttl = 0 }
  custom_error_response { error_code = 404 response_code = 200 response_page_path = "/index.html" error_caching_min_ttl = 0 }

  price_class = "PriceClass_100"
  restrictions { geo_restriction { restriction_type = "none" } }
  viewer_certificate { cloudfront_default_certificate = true }

  # Attach WAF if configured
  web_acl_id = length(var.team_cidrs) > 0 ? aws_wafv2_web_acl.allow_team[0].arn : null

  depends_on = [aws_s3_object.index_html, aws_s3_object.app_v3_js]
}

# Bucket policy: allow ONLY CloudFront (OAC) to read objects
resource "aws_s3_bucket_policy" "frontend_oac" {
  bucket = aws_s3_bucket.frontend.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowCloudFrontReadViaOAC",
      Effect    = "Allow",
      Principal = { Service = "cloudfront.amazonaws.com" },
      Action    = ["s3:GetObject"],
      Resource  = "${aws_s3_bucket.frontend.arn}/*",
      Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.cdn.arn } }
    }]
  })
}

# ---------------- Optional EC2 SSM endpoints/profile (unchanged) ----------------
locals { ssm_endpoints = ["ssm", "ssmmessages", "ec2messages"] }
resource "aws_vpc_endpoint" "ssm_endpoints" {
  count               = var.create_ssm_endpoints ? length(local.ssm_endpoints) : 0
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${local.ssm_endpoints[count.index]}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = var.endpoint_sg_id != null ? [var.endpoint_sg_id] : []
  private_dns_enabled = true
}
