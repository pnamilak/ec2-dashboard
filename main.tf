#############################################
# EC2 Dashboard – main.tf
# - Publishes index.html (templated), login.html, login.js to S3 on every apply
# - Exposes outputs for CloudFront invalidation
#############################################

locals {
  name_prefix = "${var.project_name}-${random_id.suffix.hex}"

  # Match instances by Name tag (case-flexible)
  env_filters = flatten([
    for e in var.env_names : [
      "*${e}*",
      "*${lower(e)}*",
      "*${upper(e)}*"
    ]
  ])
}

resource "random_id" "suffix" {
  byte_length = 2
}

data "aws_caller_identity" "me" {}

# ---------- SES sender ----------
resource "aws_ses_email_identity" "sender" {
  email = var.ses_sender_email
}

# ---------- DynamoDB: OTP store ----------
resource "aws_dynamodb_table" "otp" {
  name         = "${local.name_prefix}-otp"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "email"

  attribute {
    name = "email"
    type = "S"
  }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }
}

# ---------- SSM Parameters ----------
resource "random_password" "jwt_secret" {
  length  = 32
  special = false
}

resource "aws_ssm_parameter" "jwt_secret" {
  name  = "/${var.project_name}/jwt_secret"
  type  = "SecureString"
  value = random_password.jwt_secret.result
}

resource "aws_ssm_parameter" "user_params" {
  for_each = var.app_users
  name     = "/${var.project_name}/users/${each.key}"
  type     = "SecureString"
  value    = each.value
}

# ---------- Lambda packaging ----------
data "archive_file" "api_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda-packaged.zip"
}

# ---------- IAM role for Lambdas ----------
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${local.name_prefix}-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name = "${local.name_prefix}-lambda-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid     = "Logs",
        Effect  = "Allow",
        Action  = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "*"
      },
      {
        Sid     = "SES",
        Effect  = "Allow",
        Action  = ["ses:SendEmail", "ses:SendRawEmail"],
        Resource = "*"
      },
      {
        Sid     = "DDB",
        Effect  = "Allow",
        Action  = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:DeleteItem"],
        Resource = aws_dynamodb_table.otp.arn
      },
      {
        Sid     = "EC2",
        Effect  = "Allow",
        Action  = ["ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances"],
        Resource = "*"
      },
      {
        Sid     = "SSMRun",
        Effect  = "Allow",
        Action  = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:DescribeInstanceInformation"
        ],
        Resource = "*"
      },
      {
        Sid     = "SSMParams",
        Effect  = "Allow",
        Action  = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"],
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.me.account_id}:parameter/${var.project_name}/*"
      }
    ]
  })
}

# ---------- Lambda functions ----------
resource "aws_lambda_function" "api" {
  function_name = "${local.name_prefix}-api"
  role          = aws_iam_role.lambda_exec.arn
  filename      = data.archive_file.api_zip.output_path
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  timeout       = 30

  environment {
    variables = {
      REGION            = var.aws_region
      OTP_TABLE         = aws_dynamodb_table.otp.name
      SES_SENDER        = var.ses_sender_email
      ALLOWED_DOMAIN    = var.allowed_email_domain
      PARAM_USER_PREFIX = "/${var.project_name}/users"
      JWT_PARAM         = "/${var.project_name}/jwt_secret"
      ENV_NAMES         = join(",", var.env_names)
    }
  }
}

resource "aws_lambda_function" "authorizer" {
  function_name = "${local.name_prefix}-authorizer"
  role          = aws_iam_role.lambda_exec.arn
  filename      = data.archive_file.api_zip.output_path
  handler       = "authorizer.lambda_handler"
  runtime       = "python3.12"
  timeout       = 10

  environment {
    variables = {
      REGION    = var.aws_region
      JWT_PARAM = "/${var.project_name}/jwt_secret"
    }
  }
}

resource "aws_lambda_permission" "api_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
}

resource "aws_lambda_permission" "auth_invoke" {
  statement_id  = "AllowAPIGatewayInvokeAuthorizer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorizer.function_name
  principal     = "apigateway.amazonaws.com"
}

# ---------- API Gateway (HTTP API) ----------
resource "aws_apigatewayv2_api" "api" {
  name          = "${local.name_prefix}-httpapi"
  protocol_type = "HTTP"

  cors_configuration {
    allow_headers = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_origins = ["*"]
  }
}

resource "aws_apigatewayv2_integration" "api_lambda" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_authorizer" "auth" {
  api_id                            = aws_apigatewayv2_api.api.id
  authorizer_type                   = "REQUEST"
  name                              = "${local.name_prefix}-authz"
  authorizer_uri                    = aws_lambda_function.authorizer.invoke_arn
  identity_sources                  = ["$request.header.Authorization"]
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = true
  authorizer_result_ttl_in_seconds  = 60
}

# Public routes
resource "aws_apigatewayv2_route" "request_otp" {
  api_id    = aws_apigatewayv2_api.api.id
  route_key = "POST /request-otp"
  target    = "integrations/${aws_apigatewayv2_integration.api_lambda.id}"
}

resource "aws_apigatewayv2_route" "verify_otp" {
  api_id    = aws_apigatewayv2_api.api.id
  route_key = "POST /verify-otp"
  target    = "integrations/${aws_apigatewayv2_integration.api_lambda.id}"
}

resource "aws_apigatewayv2_route" "login" {
  api_id    = aws_apigatewayv2_api.api.id
  route_key = "POST /login"
  target    = "integrations/${aws_apigatewayv2_integration.api_lambda.id}"
}

# Protected routes
resource "aws_apigatewayv2_route" "instances" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "GET /instances"
  target             = "integrations/${aws_apigatewayv2_integration.api_lambda.id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.auth.id
}

resource "aws_apigatewayv2_route" "instance_action" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "POST /instance-action"
  target             = "integrations/${aws_apigatewayv2_integration.api_lambda.id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.auth.id
}

resource "aws_apigatewayv2_route" "services" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "POST /services"
  target             = "integrations/${aws_apigatewayv2_integration.api_lambda.id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.auth.id
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "$default"
  auto_deploy = true
}

# ---------- Static site: S3 + CloudFront ----------
resource "aws_s3_bucket" "website" {
  bucket        = var.website_bucket_name != "" ? var.website_bucket_name : "${local.name_prefix}-site"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "site" {
  bucket = aws_s3_bucket.website.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.website.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "${local.name_prefix}-oac"
  description                       = "OAC for S3 website"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  default_root_object = "index.html"

  origin {
    domain_name              = aws_s3_bucket.website.bucket_regional_domain_name
    origin_id                = "s3-site"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  default_cache_behavior {
    target_origin_id       = "s3-site"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = true
      cookies { forward = "none" }
    }
    # honor object cache headers
    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 31536000
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate { cloudfront_default_certificate = true }
}

data "aws_iam_policy_document" "site_bucket" {
  statement {
    sid     = "AllowCloudFrontRead"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.website.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.site.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.website.id
  policy = data.aws_iam_policy_document.site_bucket.json
}

# Upload rendered index.html (template)
resource "aws_s3_object" "index" {
  bucket         = aws_s3_bucket.website.id
  key            = "index.html"
  content_type   = "text/html"
  cache_control  = "no-store, no-cache, must-revalidate, max-age=0"
  content = templatefile("${path.module}/html/index.html.tpl", {
    api_base_url         = aws_apigatewayv2_api.api.api_endpoint
    allowed_email_domain = var.allowed_email_domain
    env_names            = join(",", var.env_names)
  })
}

# Upload static login assets (re-upload whenever file content changes)
resource "aws_s3_object" "login_html" {
  bucket        = aws_s3_bucket.website.id
  key           = "login.html"
  source        = "${path.module}/html/login.html"
  content_type  = "text/html"
  cache_control = "no-store, no-cache, must-revalidate, max-age=0"

  # etag forces Terraform to detect changes and update object each apply when file content changes
  etag = filemd5("${path.module}/html/login.html")
}

resource "aws_s3_object" "login_js" {
  bucket        = aws_s3_bucket.website.id
  key           = "login.js"
  source        = "${path.module}/html/login.js"
  content_type  = "application/javascript"
  cache_control = "no-store, no-cache, must-revalidate, max-age=0"
  etag          = filemd5("${path.module}/html/login.js")
}

# ============================================================
# EC2 SSM – Role / Instance Profile and optional attachments
# ============================================================
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2_ssm_role" {
  name               = "${local.name_prefix}-ec2-ssm-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_core" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "${local.name_prefix}-ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm_role.name
}

# Discover instances
data "aws_instances" "targets_running" {
  filter {
    name   = "instance-state-name"
    values = ["running"]
  }
  filter {
    name   = "tag:Name"
    values = local.env_filters
  }
}

data "aws_instances" "targets_stopped" {
  filter {
    name   = "instance-state-name"
    values = ["stopped"]
  }
  filter {
    name   = "tag:Name"
    values = local.env_filters
  }
}

locals {
  target_ids_map = {
    none    = []
    running = data.aws_instances.targets_running.ids
    stopped = data.aws_instances.targets_stopped.ids
    both    = distinct(concat(data.aws_instances.targets_running.ids, data.aws_instances.targets_stopped.ids))
  }
  target_ids = local.target_ids_map[var.assign_profile_target]
}

# Idempotent attach via AWS CLI (run locally on the runner)
resource "null_resource" "attach_profile" {
  for_each = toset(local.target_ids)

  triggers = {
    instance_id  = each.value
    profile_name = aws_iam_instance_profile.ec2_ssm_profile.name
    region       = var.aws_region
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-lc"]
    command = <<EOF
set -euo pipefail
IID="${each.value}"
PROFILE="${aws_iam_instance_profile.ec2_ssm_profile.name}"
REGION="${var.aws_region}"

CUR_ID=$(aws ec2 describe-iam-instance-profile-associations \
  --filters Name=instance-id,Values="$IID" \
  --region "$REGION" \
  --query 'IamInstanceProfileAssociations[0].AssociationId' \
  --output text 2>/dev/null || true)

CUR_ARN=$(aws ec2 describe-iam-instance-profile-associations \
  --filters Name=instance-id,Values="$IID" \
  --region "$REGION" \
  --query 'IamInstanceProfileAssociations[0].IamInstanceProfile.Arn' \
  --output text 2>/dev/null || true)

[ "$CUR_ID"  = "None" ] && CUR_ID=""
[ "$CUR_ARN" = "None" ] && CUR_ARN=""

CUR_PROFILE=$(echo "$CUR_ARN" | awk -F'/' '{print $NF}')

if [ -n "$CUR_ID" ] && [ "$CUR_PROFILE" = "$PROFILE" ]; then
  echo "Instance $IID already associated with profile $PROFILE"
  exit 0
fi

if [ -n "$CUR_ID" ] && [ "$CUR_PROFILE" != "$PROFILE" ]; then
  echo "Disassociating old profile $CUR_PROFILE from $IID ..."
  aws ec2 disassociate-iam-instance-profile --association-id "$CUR_ID" --region "$REGION"
  sleep 3
fi

echo "Associating profile $PROFILE to $IID ..."
aws ec2 associate-iam-instance-profile --iam-instance-profile Name="$PROFILE" --instance-id "$IID" --region "$REGION" >/dev/null
echo "Done."
EOF
  }
}

