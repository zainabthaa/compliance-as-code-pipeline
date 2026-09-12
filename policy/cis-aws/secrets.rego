package main

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