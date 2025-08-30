output "cloudfront_domain" {
  value = aws_cloudfront_distribution.site.domain_name
}

output "api_endpoint" {
  value = aws_apigatewayv2_api.api.api_endpoint
}
