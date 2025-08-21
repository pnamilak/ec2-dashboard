output "s3_website_url" {
  value       = "http://${aws_s3_bucket.frontend.bucket}.s3-website.${var.aws_region}.amazonaws.com/"
  description = "Public S3 static website URL"
}

# Keep this as your simple API endpoint (no stage)
output "api_gateway_url" {
  value       = aws_apigatewayv2_api.api.api_endpoint
  description = "Base API endpoint (without stage)"
}

output "lambda_handler_name" {
  value = aws_lambda_function.ec2_handler.function_name
}

output "authorizer_lambda_name" {
  value = aws_lambda_function.authorizer.function_name
}

output "lambda_role_name" {
  value = aws_iam_role.lambda_role.name
}

output "ec2_ssm_instance_profile_arn" {
  value       = aws_iam_instance_profile.ec2_ssm.arn
  description = "Attach this profile to instances that should be SSM-managed."
}
