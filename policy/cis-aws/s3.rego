package main

# ---- 2.1.5.1  S3 Block Public Access -------------------------------------
# All four settings must be true. Checking only one (block_public_acls) lets
# a bucket that still allows public *policies* slip through.
public_access_flags := [
	"block_public_acls",
	"block_public_policy",
	"ignore_public_acls",
	"restrict_public_buckets",
]

deny contains msg if {
	some res in input.resource_changes
	res.type == "aws_s3_bucket_public_access_block"

	# a flag that is false, missing or unknown is NOT proven safe
	disabled := [flag |
		some flag in public_access_flags
		object.get(res.change.after, flag, false) != true
	]
	count(disabled) > 0

	msg := {
		"msg": sprintf("%s does not enable: %s. S3 buckets must block public access.", [res.address, concat(", ", disabled)]),
		"control_id": "2.1.5.1",
		"resource": res.address,
		"severity": "critical",
	}
}

# ---- helpers: does a companion resource point at this bucket? -------------
# Looks through the whole configuration (including modules) for a resource of
# `resource_type` whose `bucket` argument references the bucket address.
companion_for_bucket(resource_type, bucket_address) := {res |
	some res in config_resources
	res.type == resource_type
	some reference in res.expressions.bucket.references
	concat("", [res.prefix, reference]) == bucket_address
}

# ---- 2.1.1  S3 server-side encryption -------------------------------------
bucket_has_encryption(bucket_address) if {
	count(companion_for_bucket("aws_s3_bucket_server_side_encryption_configuration", bucket_address)) > 0
}

deny contains msg if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	not bucket_has_encryption(strip_index(bucket.address))

	msg := {
		"msg": sprintf("%s has no server-side encryption configured.", [bucket.address]),
		"control_id": "2.1.1",
		"resource": bucket.address,
		"severity": "high",
	}
}

# ---- 2.1.2  S3 versioning -------------------------------------------------
# The versioning resource must exist AND have status = "Enabled".
# (status = "Suspended"/"Disabled" used to pass because only existence was checked.)
bucket_has_versioning(bucket_address) if {
	some res in companion_for_bucket("aws_s3_bucket_versioning", bucket_address)
	res.expressions.versioning_configuration[0].status.constant_value == "Enabled"
}

deny contains msg if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	not bucket_has_versioning(strip_index(bucket.address))

	msg := {
		"msg": sprintf("%s does not have versioning enabled (needs an aws_s3_bucket_versioning resource with status = \"Enabled\").", [bucket.address]),
		"control_id": "2.1.2",
		"resource": bucket.address,
		"severity": "medium",
	}
}