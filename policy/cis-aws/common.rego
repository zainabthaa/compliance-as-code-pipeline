package main

as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

module_prefix(path) := concat("", [sprintf("module.%s.", [path[i + 1]]) | some i, p in path; p == "module_calls"])

strip_index(address) := regex.replace(address, `\[[^\]]*\]`, "")

# Every resource declared in the Terraform *configuration* - the root module
# AND all nested module calls. Used for checks that need to look at how
# resources reference each other (plan values for new resources are unknown).
config_resources contains r if {
	walk(input.configuration.root_module, [path, node])
	some res in node.resources
	prefix := module_prefix(path)
	r := {
		"type": res.type,
		"address": concat("", [prefix, res.address]),
		"prefix": prefix,
		"expressions": object.get(res, "expressions", {}),
	}
}
