"""
Compliance report generator.

Runs Conftest against the Terraform plan JSON, parses the structured
violations it finds, and generates a human-readable Markdown report.
"""

import subprocess
import json
import sys
from datetime import datetime, timezone


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


def build_report(violations):
    """Generate a Markdown compliance report from the parsed violations."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(violations)

    lines = []
    lines.append("# Compliance Report")
    lines.append(f"\nGenerated: {timestamp}")
    lines.append(f"\n**Total violations found: {total}**\n")

    if total == 0:
        lines.append("✅ No violations found. All checked controls passed.\n")
        return "\n".join(lines)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    violations_sorted = sorted(
        violations, key=lambda v: severity_order.get(v["severity"], 99)
    )

    lines.append("| Severity | Control | Resource | Issue |")
    lines.append("|---|---|---|---|")
    for v in violations_sorted:
        lines.append(
            f"| {v['severity'].upper()} | {v['control_id']} | `{v['resource']}` | {v['reason']} |"
        )

    lines.append("\n## Details & Remediation\n")
    for v in violations_sorted:
        info = REMEDIATION_DB.get(v["control_id"], {})
        if not info:
            print(f"WARNING: no remediation entry found for control_id '{v['control_id']}'")
        title = info.get("title", "Unknown Control")
        remediation = info.get("remediation", "No remediation guidance available.")

        lines.append(f"### {v['control_id']} — {title}")
        lines.append(f"- **Severity:** {v['severity'].upper()}")
        lines.append(f"- **Resource:** `{v['resource']}`")
        lines.append(f"- **Issue:** {v['reason']}")
        lines.append(f"- **Remediation:** {remediation}\n")

    return "\n".join(lines)


def main():
    conftest_output = run_conftest()
    violations = parse_violations(conftest_output)
    report = build_report(violations)

    with open("compliance-report.md", "w") as f:
        f.write(report)

    print(f"Report generated: compliance-report.md ({len(violations)} violations found)")

    if violations:
        sys.exit(1)

if __name__ == "__main__":
    main()