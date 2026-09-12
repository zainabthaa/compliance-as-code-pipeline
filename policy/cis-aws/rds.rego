package main

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