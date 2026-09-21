package main

# CIS AWS v5.0.0 5.3 / 5.4: remote server administration ports (SSH 22, RDP 3389)
# must not be reachable from the internet.
#   5.3 = IPv4 (0.0.0.0/0)      5.4 = IPv6 (::/0)
# The same rule can raise both if it opens both address families.

admin_ports := {22: "SSH", 3389: "RDP"}

open_cidrs := {
	"0.0.0.0/0": {"control_id": "5.3", "family": "IPv4"},
	"::/0": {"control_id": "5.4", "family": "IPv6"},
}

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
	some port, name in admin_ports
	port_exposed(rule, port)

	some cidr, info in open_cidrs
	cidr in rule.cidrs

	msg := {
		"msg": sprintf("%s allows %s (port %d) ingress from %s (entire internet, %s).", [rule.address, name, port, cidr, info.family]),
		"control_id": info.control_id,
		"resource": rule.address,
		"severity": "critical",
	}
}
