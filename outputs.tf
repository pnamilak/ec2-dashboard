# outputs.tf — minimal, works with your current main.tf

output "s3_bucket_name" {
  description = "Private S3 bucket hosting the frontend (served via CloudFront)"
  value       = aws_s3_bucket.frontend.id
}

output "cloudfront_domain" {
  description = "Use this URL to access the dashboard"
  value       = aws_cloudfront_distribution.cdn.domain_name
}

output "api_base_url" {
  description = "API Gateway invoke URL"
  value       = aws_apigatewayv2_stage.default.invoke_url
}
