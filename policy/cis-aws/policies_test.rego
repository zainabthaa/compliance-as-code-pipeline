package main

# Run with:  conftest verify --policy policy/cis-aws
# Each test feeds a tiny fake Terraform plan to the policies and checks
# which resources get flagged for a given control.

flagged(id, plan) := {m.resource | some m in deny with input as plan; m.control_id == id}

# ---------- security groups (5.2 / 5.3) ----------
sg(address, ingress) := {"resource_changes": [{
	"address": address, "type": "aws_security_group",
	"change": {"after": {"ingress": ingress}},
}]}

rule(proto, from, to, v4, v6) := {"protocol": proto, "from_port": from, "to_port": to, "cidr_blocks": v4, "ipv6_cidr_blocks": v6}

test_ssh_open_ipv4 if flagged("5.2", sg("aws_security_group.a", [rule("tcp", 22, 22, ["0.0.0.0/0"], [])])) == {"aws_security_group.a"}

test_ssh_open_ipv6 if flagged("5.2", sg("aws_security_group.a", [rule("tcp", 22, 22, [], ["::/0"])])) == {"aws_security_group.a"}

test_ssh_via_port_range if flagged("5.2", sg("aws_security_group.a", [rule("tcp", 0, 65535, ["0.0.0.0/0"], [])])) == {"aws_security_group.a"}

test_all_traffic_exposes_ssh_and_rdp if {
	plan := sg("aws_security_group.a", [rule("-1", 0, 0, ["0.0.0.0/0"], [])])
	flagged("5.2", plan) == {"aws_security_group.a"}
	flagged("5.3", plan) == {"aws_security_group.a"}
}

test_ssh_internal_only_passes if count(flagged("5.2", sg("aws_security_group.a", [rule("tcp", 22, 22, ["10.0.0.0/16"], [])]))) == 0

test_other_port_open_is_not_ssh if count(flagged("5.2", sg("aws_security_group.a", [rule("tcp", 443, 443, ["0.0.0.0/0"], [])]))) == 0

test_dual_stack_gives_single_finding if count([m | some m in deny with input as sg("aws_security_group.a", [rule("tcp", 22, 22, ["0.0.0.0/0"], ["::/0"])]); m.control_id == "5.2"]) == 1

test_standalone_sg_rule if {
	plan := {"resource_changes": [{
		"address": "aws_security_group_rule.ssh", "type": "aws_security_group_rule",
		"change": {"after": {"type": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": null}},
	}]}
	flagged("5.2", plan) == {"aws_security_group_rule.ssh"}
}

test_standalone_vpc_ingress_rule if {
	plan := {"resource_changes": [{
		"address": "aws_vpc_security_group_ingress_rule.rdp", "type": "aws_vpc_security_group_ingress_rule",
		"change": {"after": {"ip_protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ipv4": null, "cidr_ipv6": "::/0"}},
	}]}
	flagged("5.3", plan) == {"aws_vpc_security_group_ingress_rule.rdp"}
}

# ---------- IAM-1 ----------
iam(doc) := {"resource_changes": [{
	"address": "aws_iam_policy.p", "type": "aws_iam_policy",
	"change": {"after": {"policy": json.marshal(doc)}},
}]}

test_iam_string_wildcards if count(flagged("IAM-1", iam({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))) == 1

test_iam_list_wildcards if count(flagged("IAM-1", iam({"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]}))) == 1

test_iam_single_statement_object if count(flagged("IAM-1", iam({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}))) == 1

test_iam_deny_statement_not_flagged if count(flagged("IAM-1", iam({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}))) == 0

test_iam_scoped_policy_passes if count(flagged("IAM-1", iam({"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}]}))) == 0

test_iam_role_inline_policy_checked if {
	plan := {"resource_changes": [{
		"address": "aws_iam_role_policy.p", "type": "aws_iam_role_policy",
		"change": {"after": {"policy": json.marshal({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})}},
	}]}
	flagged("IAM-1", plan) == {"aws_iam_role_policy.p"}
}

# ---------- S3 ----------
test_pab_partial_settings_flagged if {
	plan := {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.x", "type": "aws_s3_bucket_public_access_block",
		"change": {"after": {"block_public_acls": true, "block_public_policy": false, "ignore_public_acls": true, "restrict_public_buckets": true}},
	}]}
	flagged("2.1.5.1", plan) == {"aws_s3_bucket_public_access_block.x"}
}

test_pab_all_true_passes if {
	plan := {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.x", "type": "aws_s3_bucket_public_access_block",
		"change": {"after": {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}},
	}]}
	count(flagged("2.1.5.1", plan)) == 0
}

# root-level bucket with versioning + encryption
root_ok := {
	"resource_changes": [{"address": "aws_s3_bucket.b", "type": "aws_s3_bucket", "change": {"after": {}}}],
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket_versioning", "address": "aws_s3_bucket_versioning.v", "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}, "versioning_configuration": [{"status": {"constant_value": "Enabled"}}]}},
		{"type": "aws_s3_bucket_server_side_encryption_configuration", "address": "aws_s3_bucket_server_side_encryption_configuration.e", "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}}},
	]}},
}

test_bucket_with_versioning_and_encryption_passes if {
	count(flagged("2.1.1", root_ok)) == 0
	count(flagged("2.1.2", root_ok)) == 0
}

test_versioning_suspended_flagged if {
	plan := json.patch(root_ok, [{"op": "replace", "path": "/configuration/root_module/resources/0/expressions/versioning_configuration/0/status/constant_value", "value": "Suspended"}])
	flagged("2.1.2", plan) == {"aws_s3_bucket.b"}
}

test_bucket_inside_module_is_matched if {
	plan := {
		"resource_changes": [{"address": "module.data.aws_s3_bucket.b", "type": "aws_s3_bucket", "change": {"after": {}}}],
		"configuration": {"root_module": {"resources": [], "module_calls": {"data": {"module": {"resources": [
			{"type": "aws_s3_bucket_versioning", "address": "aws_s3_bucket_versioning.v", "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}, "versioning_configuration": [{"status": {"constant_value": "Enabled"}}]}},
			{"type": "aws_s3_bucket_server_side_encryption_configuration", "address": "aws_s3_bucket_server_side_encryption_configuration.e", "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}}},
		]}}}}},
	}
	count(flagged("2.1.1", plan)) == 0
	count(flagged("2.1.2", plan)) == 0
}

test_bucket_with_count_index_is_matched if {
	plan := json.patch(root_ok, [{"op": "replace", "path": "/resource_changes/0/address", "value": "aws_s3_bucket.b[0]"}])
	count(flagged("2.1.1", plan)) == 0
}

test_bucket_without_companions_flagged if {
	plan := {"resource_changes": [{"address": "aws_s3_bucket.lonely", "type": "aws_s3_bucket", "change": {"after": {}}}], "configuration": {"root_module": {"resources": []}}}
	flagged("2.1.1", plan) == {"aws_s3_bucket.lonely"}
	flagged("2.1.2", plan) == {"aws_s3_bucket.lonely"}
}

# ---------- SECRET-1 ----------
cfg(type, address, expressions) := {"configuration": {"root_module": {"resources": [{"type": type, "address": address, "expressions": expressions}]}}}

test_literal_db_password_flagged if flagged("SECRET-1", cfg("aws_db_instance", "aws_db_instance.d", {"password": {"constant_value": "hunter2"}})) == {"aws_db_instance.d"}

test_variable_password_passes if count(flagged("SECRET-1", cfg("aws_db_instance", "aws_db_instance.d", {"password": {"references": ["var.pw"]}}))) == 0

test_secret_in_other_resource_types_flagged if flagged("SECRET-1", cfg("aws_secretsmanager_secret_version", "aws_secretsmanager_secret_version.s", {"secret_string": {"constant_value": "abc"}})) == {"aws_secretsmanager_secret_version.s"}

test_empty_string_not_flagged if count(flagged("SECRET-1", cfg("aws_db_instance", "aws_db_instance.d", {"password": {"constant_value": ""}}))) == 0

test_secret_in_module_flagged if {
	plan := {"configuration": {"root_module": {"resources": [], "module_calls": {"db": {"module": {"resources": [
		{"type": "aws_db_instance", "address": "aws_db_instance.d", "expressions": {"password": {"constant_value": "hunter2"}}},
	]}}}}}}
	flagged("SECRET-1", plan) == {"module.db.aws_db_instance.d"}
}
