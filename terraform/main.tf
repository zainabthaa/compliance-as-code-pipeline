terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {} # unique bucket name

# creating an insecure s3 bucket
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "compliance-demo-insecure-${data.aws_caller_identity.current.account_id}"
}

# remove AWS blocking feature 
resource "aws_s3_bucket_public_access_block" "insecure_bucket_access" {
  bucket = aws_s3_bucket.insecure_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# creating a secure s3 bucket
resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "compliance-demo-compliant-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "compliant_bucket_access" {
  bucket = aws_s3_bucket.compliant_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# every object written in the secure bucket must be encrypted with AWS256 before being stored 
resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_bucket_encryption" {
  bucket = aws_s3_bucket.compliant_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}