package main

# 5.2 / 5.3: SSH (22) and RDP (3389) must not be reachable from the internet.
#  - IPv6 (::/0) is treated as "the internet" too

sensitive_ports := {
	22: {"control_id": "5.2", "name": "SSH"},
	3389: {"control_id": "5.3", "name": "RDP"},
}

open_cidrs := {"0.0.0.0/0", "::/0"}

# --- normalize the three ways Terraform can declare an ingress rule --------

# inline `ingress { }` blocks on aws_security_group
ingress_rules contains rule if {
	some rc in input.resource_changes
	rc.type == "aws_security_group"
	some r in rc.change.after.ingress
	rule := {
		"address": rc.address,
		"protocol": r.protocol,
		"from": r.from_port,
		"to": r.to_port,
		"cidrs": ({c | some c in r.cidr_blocks} | {c | some c in r.ipv6_cidr_blocks}),
	}
}

# standalone aws_security_group_rule
ingress_rules contains rule if {
	some rc in input.resource_changes
	rc.type == "aws_security_group_rule"
	rc.change.after.type == "ingress"
	r := rc.change.after
	rule := {
		"address": rc.address,
		"protocol": r.protocol,
		"from": r.from_port,
		"to": r.to_port,
		"cidrs": ({c | some c in r.cidr_blocks} | {c | some c in r.ipv6_cidr_blocks}),
	}
}

# standalone aws_vpc_security_group_ingress_rule (one CIDR per rule)
ingress_rules contains rule if {
	some rc in input.resource_changes
	rc.type == "aws_vpc_security_group_ingress_rule"
	r := rc.change.after
	rule := {
		"address": rc.address,
		"protocol": r.ip_protocol,
		"from": r.from_port,
		"to": r.to_port,
		"cidrs": ({c | c := r.cidr_ipv4} | {c | c := r.cidr_ipv6}),
	}
}

# --- does this rule expose `port`? -----------------------------------------
port_exposed(rule, _) if rule.protocol == "-1"

port_exposed(rule, port) if {
	rule.protocol in {"tcp", "6"}
	rule.from <= port
	rule.to >= port
}

deny contains msg if {
	some rule in ingress_rules
	some port, info in sensitive_ports
	port_exposed(rule, port)

	open := {c | some c in rule.cidrs; c in open_cidrs}
	count(open) > 0

	msg := {
		"msg": sprintf("%s allows %s (port %d) ingress from %s (entire internet).", [rule.address, info.name, port, concat(", ", sort(open))]),
		"control_id": info.control_id,
		"resource": rule.address,
		"severity": "critical",
	}
}
