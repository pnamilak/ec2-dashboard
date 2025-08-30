output "api_endpoint" {
  value       = aws_apigatewayv2_api.api.api_endpoint
  description = "HTTP API base URL"
}

output "cloudfront_domain" {
  value       = aws_cloudfront_distribution.site.domain_name
  description = "CloudFront domain for the dashboard"
}

output "website_bucket" {
  value       = aws_s3_bucket.website.id
}

output "lambda_api_name" {
  value = aws_lambda_function.api.function_name
}

output "lambda_authorizer_name" {
  value = aws_lambda_function.authorizer.function_name
}
