terraform {
  backend "s3" {
    bucket         = "tfstate-pnamilak"
    key            = "fleet/terraform.tfstate"
    region         = "us-east-2"
    dynamodb_table = "fleet-ec2-lock"   # optional
    encrypt        = true
  }
}
