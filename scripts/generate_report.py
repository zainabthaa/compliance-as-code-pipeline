"""
Generates the Markdown compliance report and sets CI pass/fail.

Exit codes:  0 = nothing blocking   1 = blocking violations (the gate)   2 = tooling error
"""

import sys
from datetime import datetime, timezone

from compliance_data import (
    CONTROLS,
    ComplianceToolError,
    SEVERITY_RANK,
    reference_summary,
    evaluate,
    load_gate,
    load_waivers,
    parse_violations,
    run_conftest,
    today_utc,
)


def _sorted(items):
    return sorted(items, key=lambda v: -SEVERITY_RANK.get(v["severity"], 99))


def _findings_table(items):
    lines = ["| Severity | Control | Resource | Issue |", "|---|---|---|---|"]
    for v in _sorted(items):
        lines.append(f"| {v['severity'].upper()} | {v['control_id']} | `{v['resource']}` | {v['reason']} |")
    return lines


def build_report(evaluation, today=None):
    """Generate a Markdown compliance report from an evaluate() result."""
    today = today or today_utc()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    blocking, warnings, waived = evaluation["blocking"], evaluation["warnings"], evaluation["waived"]

    lines = ["# Compliance Report", f"\nGenerated: {timestamp}"]
    lines.append(
        f"\n**Gate:** findings of severity `{evaluation['fail_on']}` or higher block the merge. "
        f"**Blocking: {len(blocking)}** · Warnings: {len(warnings)} · Waived: {len(waived)}\n"
    )

    if not (blocking or warnings or waived):
        lines.append("✅ No violations found. All checked controls passed.\n")
    elif not blocking:
        lines.append("✅ No blocking violations. See warnings and waivers below.\n")

    if blocking:
        lines.append("## ❌ Blocking violations\n")
        lines += _findings_table(blocking)

    if warnings:
        lines.append(f"\n## ⚠️ Warnings (below the `{evaluation['fail_on']}` gate, not blocking)\n")
        lines += _findings_table(warnings)

    if waived:
        lines.append("\n## 🛡️ Waived (approved exceptions)\n")
        lines.append("| Control | Resource | Owner | Expires | Reason |")
        lines.append("|---|---|---|---|---|")
        for v in waived:
            w = v["waiver"]
            days = (w["_expires"] - today).days
            lines.append(f"| {v['control_id']} | `{v['resource']}` | {w['owner']} | {w['expires']} ({days}d left) | {w['reason']} |")

    if evaluation["expired_waivers"] or evaluation["unused_waivers"]:
        lines.append("\n## 🧹 Waiver housekeeping\n")
        for w in evaluation["expired_waivers"]:
            lines.append(f"- **Expired** waiver for `{w['resource']}` ({w['control_id']}, owner {w['owner']}, expired {w['expires']}) - the finding is enforced again.")
        for w in evaluation["unused_waivers"]:
            lines.append(f"- **Unused** waiver for `{w['resource']}` ({w['control_id']}) matches no current finding - remove it.")

    detail_items = _sorted(blocking + warnings)
    if detail_items:
        lines.append("\n## Details & Remediation\n")
        for v in detail_items:
            info = CONTROLS.get(v["control_id"], {})
            if not info:
                print(f"WARNING: no metadata entry found for control_id '{v['control_id']}'", file=sys.stderr)
            lines.append(f"### {v['control_id']} — {info.get('title', 'Unknown Control')}")
            lines.append(f"- **Severity:** {v['severity'].upper()}")
            lines.append(f"- **Resource:** `{v['resource']}`")
            lines.append(f"- **Issue:** {v['reason']}")
            lines.append(f"- **Remediation:** {info.get('remediation', 'No remediation guidance available.')}")
            refs = reference_summary(info)
            if refs:
                lines.append("- **Frameworks:** " + " · ".join(f"{label}: {text}" for label, text in refs))
            lines.append("")

    return "\n".join(lines) + "\n"


def main():
    try:
        violations = parse_violations(run_conftest())
        evaluation = evaluate(violations, load_waivers(), load_gate())
    except ComplianceToolError as e:
        # exit code 2 = the tooling broke; exit code 1 = real compliance violations
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    with open("compliance-report.md", "w") as f:
        f.write(build_report(evaluation))

    print(
        f"Report generated: compliance-report.md "
        f"({len(evaluation['blocking'])} blocking, {len(evaluation['warnings'])} warnings, {len(evaluation['waived'])} waived)"
    )
    if evaluation["blocking"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
