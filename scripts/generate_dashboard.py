"""
Generates the static HTML compliance dashboard.
"""

from datetime import datetime, timezone
from compliance_data import (
    run_conftest,
    parse_violations,
    load_plan_json,
    build_resource_control_summary,
    REMEDIATION_DB,
)


def build_dashboard(violations, resource_control_summary):
    """Generate a static, interactive HTML dashboard - one row per control, expandable to per-resource detail."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    total_checks = len(resource_control_summary)
    failed_checks = sum(1 for r in resource_control_summary if r["status"] == "FAIL")
    passed_checks = sum(1 for r in resource_control_summary if r["status"] == "PASS")

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in violations:
        severity_counts[v["severity"]] = severity_counts.get(v["severity"], 0) + 1

    # Lookup: (control_id, resource) -> the specific violation reason
    reason_lookup = {(v["control_id"], v["resource"]): v["reason"] for v in violations}

    # Group the flat resource_control_summary back into {control_id: [entries]}
    grouped = {}
    for entry in resource_control_summary:
        grouped.setdefault(entry["control_id"], []).append(entry)

    rows_html = ""
    for i, (control_id, entries) in enumerate(grouped.items()):
        info = REMEDIATION_DB.get(control_id, {})
        title = info.get("title", "Unknown Control")
        risk = info.get("risk", "No risk description available.")
        remediation = info.get("remediation", "No remediation guidance available.")

        fail_count = sum(1 for e in entries if e["status"] == "FAIL")

        if fail_count == 0:
            badge_class = "pass"
            badge_label = "PASS"
        else:
            badge_class = "fail"
            badge_label = "FAIL"

        # Build the per-resource breakdown shown when expanded
        failing_entries = [e for e in entries if e["status"] == "FAIL"]

        if failing_entries:
            resource_items = ""
            for e in failing_entries:
                reason = reason_lookup.get((control_id, e["resource"]), "Violation detected.")
                resource_items += f"""
                <li>
                    <span class="mini-badge fail">FAIL</span>
                    <code>{e['resource']}</code> — {reason}
                </li>"""
        else:
            resource_items = "<li>All resources passed this control.</li>"

        row_id = f"detail-{i}"

        rows_html += f"""
        <tr class="summary-row" onclick="toggleRow('{row_id}')">
            <td><span class="arrow" id="arrow-{i}">&#9656;</span></td>
            <td>{control_id}</td>
            <td>{title}</td>
            <td><span class="badge {badge_class}">{badge_label}</span></td>
        </tr>"""

        rows_html += f"""
        <tr class="detail-row" id="{row_id}" style="display: none;">
            <td colspan="4">
                <div class="detail-box">
                    <p><strong>Why this matters:</strong> {risk}</p>
                    <p><strong>Resources checked:</strong></p>
                    <ul>{resource_items}</ul>
                    <p><strong>How to fix it:</strong> {remediation}</p>
                </div>
            </td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Compliance Dashboard</title>
    <style>
        body {{ font-family: -apple-system, Arial, sans-serif; background: #0d1117; color: #e6edf3; padding: 2rem; }}
        h1 {{ color: #58a6ff; }}
        .meta {{ color: #8b949e; margin-bottom: 1.5rem; }}
        .cards {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; justify-content: center; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.5rem; }}
        .card .num {{ font-size: 2rem; font-weight: bold; }}
        .card .label {{ color: #8b949e; font-size: 0.85rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
        th, td {{ text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid #30363d; }}
        th {{ background: #21262d; }}
        .summary-row {{ cursor: pointer; }}
        .summary-row:hover {{ background: #1c2129; }}
        .arrow {{ display: inline-block; transition: transform 0.15s ease; color: #8b949e; }}
        .arrow.open {{ transform: rotate(90deg); }}
        .badge {{ padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; white-space: nowrap; }}
        .badge.pass {{ background: #238636; color: white; }}
        .badge.fail {{ background: #da3633; color: white; }}
        .mini-badge {{ padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.7rem; font-weight: bold; margin-right: 0.4rem; }}
        .mini-badge.pass {{ background: #238636; color: white; }}
        .mini-badge.fail {{ background: #da3633; color: white; }}
        .detail-box {{ background: #0d1117; border-left: 3px solid #58a6ff; padding: 1rem 1.25rem; margin: 0.5rem 0; border-radius: 4px; }}
        .detail-box p {{ margin: 0.5rem 0; line-height: 1.5; }}
        .detail-box ul {{ margin: 0.25rem 0 0.5rem 0; list-style: none; padding-left: 0; }}
        .detail-box li {{ margin: 0.35rem 0; }}
        .detail-box code {{ background: #21262d; padding: 0.1rem 0.4rem; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>Compliance Dashboard</h1>
    <div class="meta">Generated: {timestamp} &middot; Click any row to see per-resource details</div>

    <div class="cards">
        <div class="card"><div class="num">{total_checks}</div><div class="label">Total Checks</div></div>
        <div class="card"><div class="num" style="color:#3fb950">{passed_checks}</div><div class="label">Passed</div></div>
        <div class="card"><div class="num" style="color:#f85149">{failed_checks}</div><div class="label">Failed</div></div>
        <div class="card"><div class="num" style="color:#f85149">{severity_counts['critical']}</div><div class="label">Critical</div></div>
        <div class="card"><div class="num" style="color:#d29922">{severity_counts['high']}</div><div class="label">High</div></div>
    </div>

    <table>
        <tr><th></th><th>Control ID</th><th>Title</th><th>Status</th></tr>
        {rows_html}
    </table>

    <script>
        function toggleRow(rowId) {{
            const row = document.getElementById(rowId);
            const index = rowId.split('-')[1];
            const arrow = document.getElementById('arrow-' + index);
            if (row.style.display === 'none') {{
                row.style.display = 'table-row';
                arrow.classList.add('open');
            }} else {{
                row.style.display = 'none';
                arrow.classList.remove('open');
            }}
        }}
    </script>
</body>
</html>"""

    return html


def main():
    conftest_output = run_conftest()
    violations = parse_violations(conftest_output)
    plan_json = load_plan_json()
    resource_control_summary = build_resource_control_summary(plan_json, violations)

    dashboard_html = build_dashboard(violations, resource_control_summary)

    with open("dashboard.html", "w") as f:
        f.write(dashboard_html)

    print(f"Dashboard generated: dashboard.html ({len(violations)} violations across {len(resource_control_summary)} checks)")


if __name__ == "__main__":
    main()