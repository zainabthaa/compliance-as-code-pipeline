package main

iam_policy_types := {
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
	"aws_iam_group_policy",
}

deny contains msg if {
	some pol in input.resource_changes
	pol.type in iam_policy_types

	policy_doc := json.unmarshal(pol.change.after.policy)

	some statement in as_list(policy_doc.Statement)
	statement.Effect == "Allow"
	"*" in as_list(statement.Action)
	"*" in as_list(statement.Resource)

	msg := {
		"msg": sprintf("%s grants wildcard Action=* and Resource=* (full admin access).", [pol.address]),
		"control_id": "IAM-1",
		"resource": pol.address,
		"severity": "high",
	}
}
