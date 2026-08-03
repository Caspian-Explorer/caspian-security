# Hardened Terraform — should produce no Error/Warning findings.

resource "aws_s3_bucket" "logs" {
  bucket = "example-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_db_instance" "app" {
  identifier             = "app-db"
  engine                 = "postgres"
  instance_class         = "db.t4g.small"
  storage_encrypted      = true
  publicly_accessible    = false
  password               = var.db_password
  skip_final_snapshot    = false
  deletion_protection    = true
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_security_group" "internal" {
  name = "internal-only"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
