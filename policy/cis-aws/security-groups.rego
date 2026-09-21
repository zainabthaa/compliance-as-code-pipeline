package main

# Security groups are firewalls. Remote-admin ports must not be open to the
# whole internet (0.0.0.0/0).

# SSH (port 22).
# fails when an ingress rule covers port 22 and allows 0.0.0.0/0.
deny contains msg if {
	some sg in input.resource_changes
	sg.type == "aws_security_group"

	some rule in sg.change.after.ingress
	rule.from_port <= 22 # port 22 is inside the rule's port range
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

# RDP (port 3389, Windows remote desktop). Same idea as SSH above.
# fails when an ingress rule covers port 3389 and allows 0.0.0.0/0.
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