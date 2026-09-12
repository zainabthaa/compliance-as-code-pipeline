"""
Generates the static HTML compliance dashboard.
"""

from datetime import datetime, timezone
from compliance_data import run_conftest, parse_violations, build_control_summary


def build_dashboard(violations, control_summary):
    """Generate a static HTML dashboard showing pass/fail per control."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_controls = len(control_summary)
    passed = sum(1 for c in control_summary if c["status"] == "PASS")
    failed = total_controls - passed

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in violations:
        severity_counts[v["severity"]] = severity_counts.get(v["severity"], 0) + 1

    rows_html = ""
    for c in control_summary:
        status_class = "pass" if c["status"] == "PASS" else "fail"
        rows_html += f"""
        <tr>
            <td>{c['control_id']}</td>
            <td>{c['title']}</td>
            <td><span class="badge {status_class}">{c['status']}</span></td>
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
        .cards {{ display: flex; gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.5rem; }}
        .card .num {{ font-size: 2rem; font-weight: bold; }}
        .card .label {{ color: #8b949e; font-size: 0.85rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
        th, td {{ text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid #30363d; }}
        th {{ background: #21262d; }}
        .badge {{ padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }}
        .badge.pass {{ background: #238636; color: white; }}
        .badge.fail {{ background: #da3633; color: white; }}
    </style>
</head>
<body>
    <h1>Compliance Dashboard</h1>
    <div class="meta">Generated: {timestamp}</div>

    <div class="cards">
        <div class="card"><div class="num">{total_controls}</div><div class="label">Total Controls</div></div>
        <div class="card"><div class="num" style="color:#3fb950">{passed}</div><div class="label">Passed</div></div>
        <div class="card"><div class="num" style="color:#f85149">{failed}</div><div class="label">Failed</div></div>
        <div class="card"><div class="num" style="color:#f85149">{severity_counts['critical']}</div><div class="label">Critical</div></div>
        <div class="card"><div class="num" style="color:#d29922">{severity_counts['high']}</div><div class="label">High</div></div>
    </div>

    <table>
        <tr><th>Control ID</th><th>Title</th><th>Status</th></tr>
        {rows_html}
    </table>
</body>
</html>"""

    return html


def main():
    conftest_output = run_conftest()
    violations = parse_violations(conftest_output)
    control_summary = build_control_summary(violations)
    dashboard_html = build_dashboard(violations, control_summary)

    with open("dashboard.html", "w") as f:
        f.write(dashboard_html)

    print(f"Dashboard generated: dashboard.html ({len(violations)} violations found)")


if __name__ == "__main__":
    main()