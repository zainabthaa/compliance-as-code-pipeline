package main

deny contains msg if {
	some db in input.resource_changes
	db.type == "aws_db_instance"
	db.change.after.publicly_accessible == true

	msg := sprintf(
		"CIS 2.3 VIOLATION: %s is a publicly accessible RDS instance.",
		[db.address],
	)
}