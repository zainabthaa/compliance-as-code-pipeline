package main 

deny contains msg if {
	some sg in input.resource_changes
	sg.type == "aws_security_group"

    # using port 22
	some rule in sg.change.after.ingress
	rule.from_port <= 22
	rule.to_port >= 22

    # 
	some cidr in rule.cidr_blocks
	cidr == "0.0.0.0/0" # entire internet 

	msg := sprintf(
		"CIS 5.2 VIOLATION: %s allows SSH (port 22) ingress from 0.0.0.0/0 (entire internet).",
		[sg.address],
	)
}