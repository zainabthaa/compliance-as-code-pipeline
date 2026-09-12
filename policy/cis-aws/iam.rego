package main

deny contains msg if {
	some pol in input.resource_changes
	pol.type == "aws_iam_policy"

	policy_doc := json.unmarshal(pol.change.after.policy)

	some statement in policy_doc.Statement
	statement.Action == "*"
	statement.Resource == "*"

	msg := sprintf(
		"IAM VIOLATION: %s grants wildcard Action=* and Resource=* (full admin access).",
		[pol.address],
	)
}