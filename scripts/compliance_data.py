"""
Shared logic for running Conftest and processing compliance results.
Used by both generate_report.py and generate_dashboard.py.
"""

import subprocess
import json


REMEDIATION_DB = {
    "2.1.1": {
        "title": "S3 Bucket Server-Side Encryption",
        "remediation": "Add an aws_s3_bucket_server_side_encryption_configuration resource for this bucket with sse_algorithm = \"AES256\".",
    },
    "2.1.2": {
        "title": "S3 Bucket Versioning",
        "remediation": "Add an aws_s3_bucket_versioning resource for this bucket with status = \"Enabled\".",
    },
    "2.1.5.1": {
        "title": "S3 Block Public Access",
        "remediation": "Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.",
    },
    "2.3": {
        "title": "RDS Publicly Accessible",
        "remediation": "Set publicly_accessible = false on the RDS instance, and access it via a bastion host or VPN instead.",
    },
    "2.3.3": {
        "title": "RDS Storage Encryption",
        "remediation": "Set storage_encrypted = true on the RDS instance.",
    },
    "5.2": {
        "title": "SSH Open to the Internet",
        "remediation": "Restrict the security group's ingress CIDR block for port 22 to a specific internal range, not 0.0.0.0/0.",
    },
    "5.3": {
        "title": "RDP Open to the Internet",
        "remediation": "Restrict the security group's ingress CIDR block for port 3389 to a specific internal range, not 0.0.0.0/0.",
    },
    "EBS-1": {
        "title": "EBS Volume Encryption",
        "remediation": "Set encrypted = true on the EBS volume.",
    },
    "IAM-1": {
        "title": "IAM Wildcard Policy",
        "remediation": "Scope the policy's Action and Resource fields to only the specific permissions needed, instead of \"*\".",
    },
    "SECRET-1": {
        "title": "Hardcoded Credentials",
        "remediation": "Move the password into a Terraform variable marked sensitive = true, supplied via .tfvars (gitignored) or a secrets manager.",
    },
}


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