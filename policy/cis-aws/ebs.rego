package main 

# volume is a hardware term - ebs is a hard drive for EC2
deny contains msg if {
    some vol in input.resource_changes
    vol.type = "aws_ebs_volume"
	vol.change.after.encrypted == false

    msg := sprintf(
        "CIS EBS-1 VIOLATION: %s is an unencrypted EBS volume.",
		[vol.address],
    )
}