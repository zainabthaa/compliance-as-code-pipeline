package main

deny contains msg if {
	some pol in input.resource_changes
	pol.type == "aws_iam_policy"

	policy_doc := json.unmarshal(pol.change.after.policy)

	some statement in policy_doc.Statement
	statement.Action == "*"
	statement.Resource == "*"

	msg := {
		"msg": sprintf("%s grants wildcard Action=* and Resource=* (full admin access).", [pol.address]),
		"control_id": "IAM-1",
		"resource": pol.address,
		"severity": "high",

	}
}