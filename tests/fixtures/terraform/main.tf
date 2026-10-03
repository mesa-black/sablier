# Infrastructure declared as code, with the decisions a report should repeat.

resource "aws_db_instance" "accounting" {
  identifier        = "accounting"
  engine            = "postgres"
  storage_encrypted = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "invoices" {
  bucket = aws_s3_bucket.invoices.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.invoices.arn
    }
  }
}

resource "aws_cloudfront_distribution" "site" {
  viewer_certificate {
    minimum_protocol_version = "TLSv1.1"
  }
}

resource "tls_private_key" "deploy" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_kms_key" "signing" {
  description              = "release signing"
  customer_master_key_spec = "ECC_NIST_P384"
}

# A line that only mentions the attribute is not a decision:
# storage_encrypted = false
