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

output "ec2_ssm_instance_profile_name" {
  description = "EC2 SSM instance profile name (null if not created)"
  value       = var.create_ec2_ssm_profile ? aws_iam_instance_profile.ec2_ssm_profile[0].name : null
}
