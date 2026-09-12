package main 

# volume is a hardware term - ebs is a hard drive for EC2
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