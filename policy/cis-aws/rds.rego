package main

# RDS = managed databases on AWS.

# a database must not be reachable from the internet.
# fails when publicly_accessible = true.
deny contains msg if {
	some db in input.resource_changes
	db.type == "aws_db_instance"
	db.change.after.publicly_accessible == true

	msg := {
		"msg": sprintf("%s is a publicly accessible RDS instance.", [db.address]),
		"control_id": "2.3",
		"resource": db.address,
		"severity": "critical",
	}
}

# database storage must be encrypted.
# fails when storage_encrypted = false.
deny contains msg if {
	some db in input.resource_changes
	db.type == "aws_db_instance"
	db.change.after.storage_encrypted == false

	msg := {
		"msg": sprintf("%s has unencrypted RDS storage.", [db.address]),
		"control_id": "2.3.3",
		"resource": db.address,
		"severity": "high",
	}
}