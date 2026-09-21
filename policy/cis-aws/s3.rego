package main

# helpers: read resources from the root AND from every module 

# Full address prefix of a module, e.g. "module.a.module.b."  (root = "").
module_prefix(path) := concat("", [p[1] | some p in sorted]) if {
	sorted := sort([[i, sprintf("module.%s.", [path[i + 1]])] | some i; path[i] == "module_calls"])
}

# remove "[0]" / ["key"] added by count and for_each, so addresses can match.
strip_index(address) := regex.replace(address, `\[[^\]]*\]`, "")

# every resource written in the code, root and modules, with its full address.
config_resources contains {"address": address, "type": res.type, "refs": refs} if {
	walk(input.configuration.root_module, [path, node])
	count(path) == 0 # the root module
	some res in node.resources
	address := res.address
	refs := {ref | some ref in res.expressions.bucket.references}
}

config_resources contains {"address": address, "type": res.type, "refs": refs} if {
	walk(input.configuration.root_module, [path, node])
	count(path) > 0
	path[count(path) - 1] == "module" # this node is a module body
	prefix := module_prefix(path)
	some res in node.resources
	address := concat("", [prefix, res.address])
	refs := {concat("", [prefix, ref]) | some ref in res.expressions.bucket.references}
}

# The resource of `type` that points at this bucket (if any).
companion_for_bucket(bucket_address, type) := res.address if {
	some res in config_resources
	res.type == type
	bucket_address in res.refs
}

# public access block 

# fails when block_public_acls = false (the bucket could be made public).
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_public_access_block"
	resource.change.after.block_public_acls == false

	msg := {
		"msg": sprintf("%s has block_public_acls = false. S3 buckets must block public access.", [resource.address]),
		"control_id": "2.1.5.1",
		"resource": resource.address,
		"severity": "critical",
	}
}

# encryption

bucket_has_encryption(bucket_address) if {
	companion_for_bucket(bucket_address, "aws_s3_bucket_server_side_encryption_configuration")
}

# fails when no encryption resource points at the bucket.
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

# versioning

# true only if a versioning resource points at the bucket AND its status is "Enabled".
bucket_has_versioning(bucket_address) if {
	versioning_address := companion_for_bucket(bucket_address, "aws_s3_bucket_versioning")
	some rc in input.resource_changes
	strip_index(rc.address) == versioning_address
	some cfg in rc.change.after.versioning_configuration
	cfg.status == "Enabled"
}

# fails when versioning is missing, or its status is not "Enabled".
deny contains msg if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	not bucket_has_versioning(strip_index(bucket.address))

	msg := {
		"msg": sprintf("%s does not have versioning set to Enabled.", [bucket.address]),
		"control_id": "2.1.2",
		"resource": bucket.address,
		"severity": "medium",
	}
}
