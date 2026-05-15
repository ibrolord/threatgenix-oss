resource "aws_s3_bucket" "public_reports" {
  bucket = "threatgenix-prodsec-fixture-public-reports"
  acl    = "public-read"
}

resource "aws_security_group" "open_ssh" {
  name        = "threatgenix-prodsec-fixture-open-ssh"
  description = "Fixture security group intentionally open for scanner smoke tests"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
