package main

# a policy that allows a wildcard action on every resource is a "full admin" key.
# flag it when a statement has ALL of these:
#   - effect is "Allow"
#   - action is "*"  or a whole service like "s3:*"  (alone or inside a list)
#   - resource is "*" (alone or inside a list)
# Terraform lets you write Action / Resource / Statement as either a single
# value or a list, so we first turn everything into a list.

as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

# "*" = every action.  "s3:*" = every action of one service.
is_wildcard_action(a) if a == "*"

is_wildcard_action(a) if endswith(a, ":*")

# fails when an allow statement has a wildcard action and a "*" resource.
deny contains msg if {
	some pol in input.resource_changes
	pol.type == "aws_iam_policy"

	policy_doc := json.unmarshal(pol.change.after.policy)

	some statement in as_list(policy_doc.Statement) # one object OR a list
	statement.Effect == "Allow"

	some action in as_list(statement.Action)
	is_wildcard_action(action)

	"*" in as_list(statement.Resource)

	msg := {
		"msg": sprintf("%s allows Action=%q on Resource=* (wildcard access).", [pol.address, action]),
		"control_id": "IAM-1",
		"resource": pol.address,
		"severity": "high",
	}
}