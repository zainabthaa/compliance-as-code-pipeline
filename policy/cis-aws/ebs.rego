package main

# EBS volumes (the hard drives of EC2 servers) must be encrypted.
# fails when encrypted = false.
deny contains msg if {
	some vol in input.resource_changes
	vol.type == "aws_ebs_volume"
	vol.change.after.encrypted == false

	msg := {
		"msg": sprintf("%s is an unencrypted EBS volume.", [vol.address]),
		"control_id": "EBS-1",
		"resource": vol.address,
		"severity": "high",
	}
}