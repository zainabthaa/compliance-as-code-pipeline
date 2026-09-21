"""
Generates the static HTML compliance dashboard.
"""

import sys
from datetime import datetime, timezone
from html import escape

from compliance_data import (
    run_conftest,
    parse_violations,
    load_plan_json,
    build_resource_control_summary,
    evaluate,
    load_gate,
    load_waivers,
    strip_index,
    CONTROLS,
    STATUS_RANK,
    ComplianceToolError,
    reference_summary,
)


def build_dashboard(evaluation, resource_control_summary):
    """Generate a static, interactive HTML dashboard - one row per control, expandable to per-resource detail."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    total_checks = len(resource_control_summary)
    counts = {s: sum(1 for r in resource_control_summary if r["status"] == s) for s in STATUS_RANK}
    open_findings = evaluation["blocking"] + evaluation["warnings"]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in open_findings:
        severity_counts[v["severity"]] = severity_counts.get(v["severity"], 0) + 1

    # (control_id, resource) -> (status, finding)
    finding_lookup = {}
    for label, items in (("WAIVED", evaluation["waived"]), ("WARN", evaluation["warnings"]), ("FAIL", evaluation["blocking"])):
        for v in items:
            finding_lookup[(v["control_id"], strip_index(v["resource"]))] = (label, v)

    grouped = {}
    for entry in resource_control_summary:
        grouped.setdefault(entry["control_id"], []).append(entry)

    rows_html = ""
    for i, (control_id, entries) in enumerate(grouped.items()):
        info = CONTROLS.get(control_id, {})
        title = escape(info.get("title", "Unknown Control"))
        risk = escape(info.get("risk", "No risk description available."))
        remediation = escape(info.get("remediation", "No remediation guidance available."))
        frameworks = " &middot; ".join(f"<strong>{escape(l)}:</strong> {escape(t)}" for l, t in reference_summary(info))

        worst = max((e["status"] for e in entries), key=STATUS_RANK.get)
        badge_class = worst.lower()
        affected = sum(1 for e in entries if e["status"] == worst)
        badge_text = f"{worst} &times;{affected}" if worst != "PASS" and affected > 1 else worst
        badge_title = f"{affected} resource(s) with status {worst}" if worst != "PASS" else "All resources passed"

        resource_items = ""
        for e in entries:
            if e["status"] == "PASS":
                continue
            label, v = finding_lookup.get((control_id, strip_index(e["resource"])), (e["status"], {}))
            reason = escape(v.get("reason", "Violation detected."))
            extra = ""
            if label == "WAIVED":
                w = v["waiver"]
                extra = f" <em>Waived by {escape(w['owner'])} until {escape(w['expires'])}: {escape(w['reason'])}</em>"
            elif v.get("expired_waiver"):
                extra = f" <em>Waiver expired {escape(v['expired_waiver']['expires'])} - enforced again.</em>"
            resource_items += f"""
                <li>
                    <span class="mini-badge {label.lower()}">{label}</span>
                    <code>{escape(e['resource'])}</code> — {reason}{extra}
                </li>"""
        if not resource_items:
            resource_items = "<li>All resources passed this control.</li>"

        row_id = f"detail-{i}"

        rows_html += f"""
        <tr class="summary-row" onclick="toggleRow('{row_id}')">
            <td><span class="arrow" id="arrow-{i}">&#9656;</span></td>
            <td>{escape(control_id)}</td>
            <td>{title}</td>
            <td><span class="badge {badge_class}" title="{badge_title}">{badge_text}</span></td>
        </tr>"""

        rows_html += f"""
        <tr class="detail-row" id="{row_id}" style="display: none;">
            <td colspan="4">
                <div class="detail-box">
                    <p><strong>Why this matters:</strong> {risk}</p>
                    <p><strong>Resources checked:</strong></p>
                    <ul>{resource_items}</ul>
                    <p><strong>How to fix it:</strong> {remediation}</p>
                    <p class="frameworks">{frameworks}</p>
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
        .badge.warn {{ background: #9e6a03; color: white; }}
        .badge.waived {{ background: #1f6feb; color: white; }}
        .mini-badge {{ padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.7rem; font-weight: bold; margin-right: 0.4rem; }}
        .mini-badge.pass {{ background: #238636; color: white; }}
        .mini-badge.fail {{ background: #da3633; color: white; }}
        .mini-badge.warn {{ background: #9e6a03; color: white; }}
        .mini-badge.waived {{ background: #1f6feb; color: white; }}
        .detail-box {{ background: #0d1117; border-left: 3px solid #58a6ff; padding: 1rem 1.25rem; margin: 0.5rem 0; border-radius: 4px; }}
        .detail-box p {{ margin: 0.5rem 0; line-height: 1.5; }}
        .detail-box .frameworks {{ color: #8b949e; font-size: 0.85rem; }}
        .detail-box ul {{ margin: 0.25rem 0 0.5rem 0; list-style: none; padding-left: 0; }}
        .detail-box li {{ margin: 0.35rem 0; }}
        .detail-box code {{ background: #21262d; padding: 0.1rem 0.4rem; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>Compliance Dashboard</h1>
    <div class="meta">Generated: {timestamp} &middot; Gate: <code>{evaluation['fail_on']}</code>+ blocks &middot; Click any row to see per-resource details<br>Cards count individual findings (one control on one resource); rows group them by control, so one row can hold several findings.</div>

    <div class="cards">
        <div class="card"><div class="num">{total_checks}</div><div class="label">Total Checks</div></div>
        <div class="card"><div class="num" style="color:#3fb950">{counts['PASS']}</div><div class="label">Passed</div></div>
        <div class="card"><div class="num" style="color:#f85149">{counts['FAIL']}</div><div class="label">Blocking findings</div></div>
        <div class="card"><div class="num" style="color:#d29922">{counts['WARN']}</div><div class="label">Warning findings</div></div>
        <div class="card"><div class="num" style="color:#58a6ff">{counts['WAIVED']}</div><div class="label">Waived findings</div></div>
        <div class="card"><div class="num" style="color:#f85149">{severity_counts['critical']}</div><div class="label">Critical</div></div>
        <div class="card"><div class="num" style="color:#d29922">{severity_counts['high']}</div><div class="label">High</div></div>
        <div class="card"><div class="num" style="color:#58a6ff">{severity_counts['medium']}</div><div class="label">Medium</div></div>
        <div class="card"><div class="num" style="color:#8b949e">{severity_counts['low']}</div><div class="label">Low</div></div>
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
    try:
        violations = parse_violations(run_conftest())
        evaluation = evaluate(violations, load_waivers(), load_gate())
        plan_json = load_plan_json()
    except ComplianceToolError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    resource_control_summary = build_resource_control_summary(plan_json, evaluation)
    dashboard_html = build_dashboard(evaluation, resource_control_summary)

    with open("dashboard.html", "w") as f:
        f.write(dashboard_html)

    print(f"Dashboard generated: dashboard.html ({len(violations)} findings across {len(resource_control_summary)} checks)")


if __name__ == "__main__":
    main()
