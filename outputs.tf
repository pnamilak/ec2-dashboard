output "entry_cloudfront_domain" {
  description = "Open this URL for Email+OTP access"
  value       = aws_cloudfront_distribution.entry_cdn.domain_name
}

output "cloudfront_domain" {
  description = "REAL dashboard URL (behind Basic Auth)"
  value       = aws_cloudfront_distribution.cdn.domain_name
}

output "api_base_url" {
  description = "API Gateway base URL"
  value       = aws_apigatewayv2_stage.default.invoke_url
}
