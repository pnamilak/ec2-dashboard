output "api_endpoint" {
  value       = aws_apigatewayv2_api.api.api_endpoint
  description = "HTTP API base URL"
}

output "cloudfront_domain" {
  value       = aws_cloudfront_distribution.site.domain_name
  description = "CloudFront domain for the dashboard"
}

output "website_bucket" {
  value = aws_s3_bucket.website.id
}

output "lambda_api_name" {
  value = aws_lambda_function.api.function_name
}

output "lambda_authorizer_name" {
  value = aws_lambda_function.authorizer.function_name
}

output "site_bucket" {
  description = "S3 bucket name serving the website"
  value       = aws_s3_bucket.website.bucket
}

output "cloudfront_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.site.id
}

output "api_base_url" {
  description = "HTTP API base URL"
  value       = aws_apigatewayv2_api.api.api_endpoint
}
