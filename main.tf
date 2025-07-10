module "secure_logs_bucket" {
  source = "./modules/s3"

  create_bucket              = true
  prefix_resource_name       = var.prefix_resource_name
  bucket_name                = var.bucket_name
  use_prefix_resource_name   = true
  force_destroy              = true

  attach_deny_insecure_transport_policy = true
  attach_require_latest_tls_policy      = true

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = var.tags
}
