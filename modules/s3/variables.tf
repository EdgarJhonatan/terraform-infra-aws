variable "create_bucket" {
  description = "Required - condition to create the bucket"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Optional - AWS Tags to be added to all the resources created within the module"
  type        = map(string)
  default     = {}
}

##################################################################
# General variables
##################################################################

variable "use_prefix_resource_name" {
  description = "Required - condition to use the prefix_resource_name"
  type        = bool
  default     = true
}

variable "prefix_resource_name" {
  description = "Required - The prefix_resource_name is used to build the resource name"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.prefix_resource_name))
    error_message = "The prefix_resource_name value must be lowercase!"
  }
}

variable "bucket_name" {
  description = "Required - the bucket_name, it must be unique and lower case."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9.-]+$", var.bucket_name))
    error_message = "The bucket_name value must be lowercase!"
  }
}

##################################################################
# S3 Bucket variables
##################################################################

variable "acl" {
  description = "(Optional) The canned ACL to apply. Conflicts with `grant`"
  type        = string
  default     = null
}

variable "allowed_kms_key_arn" {
  description = "The ARN of KMS key which should be allowed in PutObject"
  type        = string
  default     = null
}

variable "attach_access_log_delivery_policy" {
  description = "Controls if S3 bucket should have S3 access log delivery policy attached"
  type        = bool
  default     = false
}

variable "attach_analytics_destination_policy" {
  description = "Controls if S3 bucket should have bucket analytics destination policy attached."
  type        = bool
  default     = false
}

variable "attach_deny_incorrect_encryption_headers" {
  description = "Controls if S3 bucket should deny incorrect encryption headers policy attached."
  type        = bool
  default     = false
}

variable "attach_deny_incorrect_kms_key_sse" {
  description = "Controls if S3 bucket policy should deny usage of incorrect KMS key SSE."
  type        = bool
  default     = false
}

variable "attach_deny_insecure_transport_policy" {
  description = "Controls if S3 bucket should have deny non-SSL transport policy attached"
  type        = bool
  default     = false
}

variable "attach_deny_ssec_encrypted_object_uploads" {
  description = "Controls if S3 bucket should deny SSEC encrypted object uploads."
  type        = bool
  default     = false
}

variable "attach_deny_unencrypted_object_uploads" {
  description = "Controls if S3 bucket should deny unencrypted object uploads policy attached."
  type        = bool
  default     = false
}

variable "attach_elb_log_delivery_policy" {
  description = "Controls if S3 bucket should have ELB log delivery policy attached"
  type        = bool
  default     = false
}

variable "attach_inventory_destination_policy" {
  description = "Controls if S3 bucket should have bucket inventory destination policy attached."
  type        = bool
  default     = false
}

variable "attach_lb_log_delivery_policy" {
  description = "Controls if S3 bucket should have ALB/NLB log delivery policy attached"
  type        = bool
  default     = false
}

variable "attach_policy" {
  description = "Controls if S3 bucket should have bucket policy attached (set to `true` to use value of `policy` as bucket policy)"
  type        = bool
  default     = false
}

variable "attach_public_policy" {
  description = "Controls if a user defined public bucket policy will be attached (set to `false` to allow upstream to apply defaults to the bucket)"
  type        = bool
  default     = true
}

variable "attach_require_latest_tls_policy" {
  description = "Controls if S3 bucket should require the latest version of TLS"
  type        = bool
  default     = false
}

variable "block_public_acls" {
  description = "Whether Amazon S3 should block public ACLs for this bucket."
  type        = bool
  default     = true
}

variable "block_public_policy" {
  description = "Whether Amazon S3 should block public bucket policies for this bucket."
  type        = bool
  default     = true
}

variable "expected_bucket_owner" {
  description = "The account ID of the expected bucket owner"
  type        = string
  default     = null
}

variable "force_destroy" {
  description = "(Optional, Default:false ) A boolean that indicates all objects should be deleted from the bucket so that the bucket can be destroyed without error. These objects are not recoverable."
  type        = bool
  default     = false
}

variable "ignore_public_acls" {
  description = "Whether Amazon S3 should ignore public ACLs for this bucket."
  type        = bool
  default     = true
}

variable "object_lock_enabled" {
  description = "Whether S3 bucket should have an Object Lock configuration enabled."
  type        = bool
  default     = false
}

variable "versioning" {
  description = "Map containing versioning configuration."
  type        = map(string)
  default     = {}
}

variable "policy" {
  description = "(Optional) A valid bucket policy JSON document. Note that if the policy document is not specific enough (but still valid), Terraform may view the policy as constantly changing in a terraform plan. In this case, please make sure you use the verbose/specific version of the policy. For more information about building AWS IAM policy documents with Terraform, see the AWS IAM Policy Document Guide."
  type        = string
  default     = null
}

variable "restrict_public_buckets" {
  description = "Whether Amazon S3 should restrict public bucket policies for this bucket."
  type        = bool
  default     = true
}

variable "server_side_encryption_configuration" {
  description = "Map containing server-side encryption configuration."
  type        = any
  default     = {}
}