package main

# check if safegaurd is enabled - making it NOT public
deny contains msg if { 
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_public_access_block"
	resource.change.after.block_public_acls == false

	msg := sprintf(
		"CIS 2.1.5.1 VIOLATION: %s has block_public_acls = false. S3 buckets must block public access.",
		[resource.address],
	)
}

# check if server-side encryption enabled
    # insecure bucket doesn't have this resource written - undefined
# check if bucket has enc by looking through the source code
bucket_has_encryption(bucket_address) if {
	some resource in input.configuration.root_module.resources
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
	some reference in resource.expressions.bucket.references
	reference == bucket_address
}

deny contains msg if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	not bucket_has_encryption(bucket.address)

	msg := sprintf(
		"CIS 2.1.1 VIOLATION: %s has no server-side encryption configured.",
		[bucket.address],
	)
}

# versioning compliant bucket
bucket_has_versioning(bucket_address) if {
	some resource in input.configuration.root_module.resources
	resource.type == "aws_s3_bucket_versioning"
	some reference in resource.expressions.bucket.references
	reference == bucket_address
}

deny contains msg if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	not bucket_has_versioning(bucket.address)

	msg := sprintf(
		"CIS 2.1.2 VIOLATION: %s has no versioning configuration enabled.",
		[bucket.address]
	)
}