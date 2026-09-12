"""
Shared logic for running Conftest and processing compliance results.
Used by both generate_report.py and generate_dashboard.py.
"""

import subprocess
import json


REMEDIATION_DB = {
    "2.1.1": {
        "title": "S3 Bucket Server-Side Encryption",
        "risk": "Without encryption at rest, anyone who gains unauthorized access to the underlying storage can read the raw data directly.",
        "remediation": "Add an aws_s3_bucket_server_side_encryption_configuration resource for this bucket with sse_algorithm = \"AES256\".",
    },
    "2.1.2": {
        "title": "S3 Bucket Versioning",
        "risk": "Without versioning, an accidental or malicious overwrite/delete permanently destroys the data — there is no way to recover a prior version.",
        "remediation": "Add an aws_s3_bucket_versioning resource for this bucket with status = \"Enabled\".",
    },
    "2.1.5.1": {
        "title": "S3 Block Public Access",
        "risk": "Disabling this safeguard means the bucket could be made publicly accessible, intentionally or by mistake, exposing its contents to the entire internet.",
        "remediation": "Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.",
    },
    "2.3": {
        "title": "RDS Publicly Accessible",
        "risk": "A database reachable directly from the internet is one of the most common real-world breach vectors — attackers actively scan for exposed databases.",
        "remediation": "Set publicly_accessible = false on the RDS instance, and access it via a bastion host or VPN instead.",
    },
    "2.3.3": {
        "title": "RDS Storage Encryption",
        "risk": "Unencrypted database storage means raw data is readable if the underlying disk is ever accessed without authorization.",
        "remediation": "Set storage_encrypted = true on the RDS instance.",
    },
    "5.2": {
        "title": "SSH Open to the Internet",
        "risk": "Port 22 open to 0.0.0.0/0 means anyone on the internet can attempt to log into the server — a constant, automated attack target.",
        "remediation": "Restrict the security group's ingress CIDR block for port 22 to a specific internal range, not 0.0.0.0/0.",
    },
    "5.3": {
        "title": "RDP Open to the Internet",
        "risk": "Same risk as SSH exposure, but for Windows remote desktop access — a very common ransomware entry point in real-world breaches.",
        "remediation": "Restrict the security group's ingress CIDR block for port 3389 to a specific internal range, not 0.0.0.0/0.",
    },
    "EBS-1": {
        "title": "EBS Volume Encryption",
        "risk": "An unencrypted disk volume exposes raw data if the volume is ever improperly detached, snapshotted, or accessed outside its intended instance.",
        "remediation": "Set encrypted = true on the EBS volume.",
    },
    "IAM-1": {
        "title": "IAM Wildcard Policy",
        "risk": "A policy granting Action=\"*\" and Resource=\"*\" gives full administrative control over the entire AWS account to anything using it — a single compromised credential means total account takeover.",
        "remediation": "Scope the policy's Action and Resource fields to only the specific permissions needed, instead of \"*\".",
    },
    "SECRET-1": {
        "title": "Hardcoded Credentials",
        "risk": "A password committed directly in source code is visible to anyone with repo access, remains in Git history forever even if later removed, and is a leading cause of real-world credential leaks.",
        "remediation": "Move the password into a Terraform variable marked sensitive = true, supplied via .tfvars (gitignored) or a secrets manager.",
    },
}


CONTROL_RESOURCE_TYPE = {
    "2.1.1": "aws_s3_bucket",
    "2.1.2": "aws_s3_bucket",
    "2.1.5.1": "aws_s3_bucket_public_access_block",
    "2.3": "aws_db_instance",
    "2.3.3": "aws_db_instance",
    "5.2": "aws_security_group",
    "5.3": "aws_security_group",
    "EBS-1": "aws_ebs_volume",
    "IAM-1": "aws_iam_policy",
    "SECRET-1": "aws_db_instance",
}


def load_plan_json(path="terraform/tfplan.json"):
    """Load the raw Terraform plan JSON directly (needed to enumerate ALL resources, not just violations)."""
    with open(path) as f:
        return json.load(f)


def get_resources_by_type(plan_json, resource_type):
    """Return a list of resource addresses for every resource of the given type in the plan."""
    return [
        r["address"]
        for r in plan_json.get("resource_changes", [])
        if r["type"] == resource_type
    ]


def build_resource_control_summary(plan_json, violations):
    """
    Return a list of {control_id, title, resource, status} for every
    (control, resource) pair that applies - i.e. every resource of the
    control's target type, whether it passed or failed.
    """
    failed_by_control = {}
    for v in violations:
        failed_by_control.setdefault(v["control_id"], set()).add(v["resource"])

    summary = []
    for control_id, info in REMEDIATION_DB.items():
        resource_type = CONTROL_RESOURCE_TYPE.get(control_id)
        if resource_type is None:
            continue

        resources = get_resources_by_type(plan_json, resource_type)
        failed_resources = failed_by_control.get(control_id, set())

        for resource_address in resources:
            summary.append({
                "control_id": control_id,
                "title": info["title"],
                "resource": resource_address,
                "status": "FAIL" if resource_address in failed_resources else "PASS",
            })
    return summary

def run_conftest():
    """Run Conftest against the plan JSON and return the parsed JSON output."""
    result = subprocess.run(
        [
            "conftest", "test", "terraform/tfplan.json",
            "--policy", "policy/cis-aws",
            "--output", "json",
        ],
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def parse_violations(conftest_output):
    """Flatten Conftest's output into a simple list of violation dicts."""
    violations = []
    for file_result in conftest_output:
        for failure in file_result.get("failures", []):
            violations.append({
                "control_id": failure["metadata"]["control_id"],
                "resource": failure["metadata"]["resource"],
                "severity": failure["metadata"]["severity"],
                "reason": failure["msg"],
            })
    return violations


def build_control_summary(violations):
    """Return a list of {control_id, title, status} for every known control."""
    failed_ids = {v["control_id"] for v in violations}

    summary = []
    for control_id, info in REMEDIATION_DB.items():
        summary.append({
            "control_id": control_id,
            "title": info["title"],
            "status": "FAIL" if control_id in failed_ids else "PASS",
        })
    return summary