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

	msg := {
        "msg": sprintf("%s allows SSH (port 22) ingress from 0.0.0.0/0 (entire internet).", [sg.address]),
        "control_id": "5.2",
        "resource": sg.address,
        "severity": "critical",

    }
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

    msg := {
        "msg": sprintf("%s allows RDP (port 3389) ingress from 0.0.0.0/0 (entire internet).", [sg.address]),
        "control_id": "5.3",
        "resource": sg.address,
        "severity": "critical",
    }
}