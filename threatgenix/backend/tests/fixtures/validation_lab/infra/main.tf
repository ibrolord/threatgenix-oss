resource "aws_s3_bucket" "statement_exports" {
  bucket = "northstar-bank-statement-exports"
}

resource "aws_s3_bucket_public_access_block" "statement_exports" {
  bucket                  = aws_s3_bucket.statement_exports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
