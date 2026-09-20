"""
Shared logic for running Conftest and processing compliance results.
Used by both generate_report.py and generate_dashboard.py.

Control metadata (title, severity, risk, remediation, which Terraform resource
types a control applies to) lives in controls/controls.json - the single source
of truth. The Rego policies decide PASS/FAIL; this file only reads results.
"""

import json
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROLS_FILE = REPO_ROOT / "controls" / "controls.json"
PLAN_JSON = REPO_ROOT / "terraform" / "tfplan.json"
POLICY_DIR = REPO_ROOT / "policy" / "cis-aws"


class ComplianceToolError(Exception):
    """Something is wrong with the tooling/inputs (NOT a compliance violation)."""


def load_controls(path=CONTROLS_FILE):
    """Load controls.json and return {control_id: {...}} preserving file order."""
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        raise ComplianceToolError(f"Controls file not found: {path}")
    except json.JSONDecodeError as e:
        raise ComplianceToolError(f"Controls file {path} is not valid JSON: {e}")
    return {c["id"]: c for c in data["controls"]}


CONTROLS = load_controls()


def load_plan_json(path=PLAN_JSON):
    """Load the raw Terraform plan JSON (needed to enumerate ALL resources, not just violations)."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        raise ComplianceToolError(
            f"Terraform plan JSON not found at {path}. Run "
            "'terraform plan -out=tfplan.binary && terraform show -json tfplan.binary > tfplan.json' "
            "inside the terraform/ directory first."
        )
    except json.JSONDecodeError as e:
        raise ComplianceToolError(f"{path} is not valid JSON: {e}")


def strip_index(address):
    """aws_s3_bucket.b["x"] -> aws_s3_bucket.b (count/for_each indexes removed)."""
    return re.sub(r"\[[^\]]*\]", "", address)


def get_resources_by_type(plan_json, resource_types):
    """Return the addresses of every resource in the plan whose type is in resource_types."""
    wanted = set(resource_types)
    return [
        r["address"]
        for r in plan_json.get("resource_changes", [])
        if r["type"] in wanted
    ]


def run_conftest(plan_path=PLAN_JSON, policy_dir=POLICY_DIR):
    """Run Conftest against the plan JSON and return the parsed JSON output.

    Conftest exit codes: 0 = no failures, 1 = policy failures. Anything else
    (or unparseable output) means the tool itself broke, which must NOT be
    mistaken for "compliant" or reported as a Python traceback.
    """
    if not Path(plan_path).exists():
        # produces the friendly "how to generate the plan" message
        load_plan_json(plan_path)

    try:
        result = subprocess.run(
            ["conftest", "test", str(plan_path), "--policy", str(policy_dir), "--output", "json"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise ComplianceToolError(
            "The 'conftest' binary was not found on PATH. Install it from https://www.conftest.dev/install/"
        )

    if result.returncode not in (0, 1):
        raise ComplianceToolError(
            f"Conftest failed (exit code {result.returncode}):\n{result.stderr.strip() or result.stdout.strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ComplianceToolError(
            "Conftest did not return valid JSON.\n"
            f"stdout: {result.stdout.strip()[:500]}\nstderr: {result.stderr.strip()[:500]}"
        )


def parse_violations(conftest_output):
    """Flatten Conftest's output into a de-duplicated list of violation dicts."""
    violations = []
    seen = set()
    for file_result in conftest_output:
        for failure in file_result.get("failures", []):
            meta = failure.get("metadata") or {}
            missing = {"control_id", "resource", "severity"} - meta.keys()
            if missing:
                raise ComplianceToolError(
                    f"A policy returned a violation without required fields {sorted(missing)}: "
                    f"{failure.get('msg')!r}. Every deny rule must emit "
                    "{msg, control_id, resource, severity}."
                )
            key = (meta["control_id"], meta["resource"])
            if key in seen:
                continue
            seen.add(key)
            violations.append({
                "control_id": meta["control_id"],
                "resource": meta["resource"],
                "severity": meta["severity"],
                "reason": failure["msg"],
            })
    return violations


def build_resource_control_summary(plan_json, violations):
    """
    Return a list of {control_id, title, resource, status} for every
    (control, resource) pair that applies - every resource of a control's target
    types, whether it passed or failed. Violations on resources outside those
    types (or from a control missing in controls.json) are still included as FAIL
    so a violation can never silently disappear from the dashboard.
    """
    failed = {}
    for v in violations:
        failed.setdefault(v["control_id"], set()).add(strip_index(v["resource"]))

    summary = []
    for control_id, info in CONTROLS.items():
        seen = set()
        for address in get_resources_by_type(plan_json, info["resource_types"]):
            seen.add(strip_index(address))
            summary.append({
                "control_id": control_id,
                "title": info["title"],
                "resource": address,
                "status": "FAIL" if strip_index(address) in failed.get(control_id, set()) else "PASS",
            })
        for address in sorted(failed.get(control_id, set()) - seen):
            summary.append({
                "control_id": control_id,
                "title": info["title"],
                "resource": address,
                "status": "FAIL",
            })

    for control_id in sorted(set(failed) - set(CONTROLS)):
        for address in sorted(failed[control_id]):
            summary.append({
                "control_id": control_id,
                "title": "Unknown Control",
                "resource": address,
                "status": "FAIL",
            })
    return summary


def build_control_summary(violations):
    """Return a list of {control_id, title, status} for every known control."""
    failed_ids = {v["control_id"] for v in violations}
    return [
        {"control_id": cid, "title": info["title"], "status": "FAIL" if cid in failed_ids else "PASS"}
        for cid, info in CONTROLS.items()
    ]
