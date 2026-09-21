package main

# SECRET-1: no password may be typed directly into the Terraform code.
# fails when a database password is written as plain text in the .tf file.
deny contains msg if {
	some res in input.configuration.root_module.resources
	res.type == "aws_db_instance"
	res.expressions.password.constant_value

	msg := {
		"msg": sprintf("%s has a hardcoded plaintext password in source code.", [res.address]),
		"control_id": "SECRET-1",
		"resource": res.address,
		"severity": "critical",
	}
}