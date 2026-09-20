package main

# SECRET-1: a literal secret typed into Terraform source.
# Looks at every resource in the configuration (not just aws_db_instance),
secret_arguments := {
	"password",
	"master_password",
	"administrator_login_password",
	"secret_string",
	"secret_key",
	"secret_access_key",
	"access_key",
	"api_key",
	"auth_token",
	"token",
	"private_key",
	"client_secret",
}

deny contains msg if {
	some res in config_resources
	some argument, expression in res.expressions
	argument in secret_arguments
	is_string(expression.constant_value)
	expression.constant_value != ""

	msg := {
		"msg": sprintf("%s has a hardcoded plaintext value for '%s' in source code.", [res.address, argument]),
		"control_id": "SECRET-1",
		"resource": res.address,
		"severity": "critical",
	}
}
