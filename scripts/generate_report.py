"""
Generates the Markdown compliance report and sets CI pass/fail.
"""

import sys
from datetime import datetime, timezone
from compliance_data import run_conftest, parse_violations, REMEDIATION_DB


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