package main 

# SSH port 22
deny contains msg if {
	some sg in input.resource_changes
	sg.type == "aws_security_group"

	some rule in sg.change.after.ingress
	rule.from_port <= 22
	rule.to_port >= 22

	some cidr in rule.cidr_blocks
	cidr == "0.0.0.0/0" # entire internet 

	msg := sprintf(
		"CIS 5.2 VIOLATION: %s allows SSH (port 22) ingress from 0.0.0.0/0 (entire internet).",
		[sg.address],
	)
}

# RDP port 3389
deny contains msg if {
    some sg in input.resource_changes
    sg.type == "aws_security_group"

    some rule in sg.change.after.ingress
    rule.from_port <= 3389
    rule.to_port >= 3389

    some cidr in rule.cidr_blocks
    cidr == "0.0.0.0/0"

    msg := sprintf(
        "CIS 5.3 VIOLATION: %s allows RDP (port 3389) ingress from 0.0.0.0/0 (entire internet).",
        [sg.address],
    )
}