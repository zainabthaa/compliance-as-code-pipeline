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
from datetime import date, datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROLS_FILE = REPO_ROOT / "controls" / "controls.json"
GATE_FILE = REPO_ROOT / "config" / "gate.json"
WAIVERS_FILE = REPO_ROOT / "config" / "waivers.json"
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


def reference_summary(info):
    """Short framework references for a control: [(label, "id, id"), ...] - used by report and dashboard."""
    refs = info.get("references") or {}
    out = []
    cis = refs.get("cis_aws") or {}
    if cis.get("items"):
        match = "" if cis.get("match") == "direct" else f" ({cis['match']} match)"
        out.append(("CIS AWS v5.0.0", ", ".join(i["id"] for i in cis["items"]) + match))
    else:
        out.append(("CIS AWS v5.0.0", "no matching recommendation"))
    nist = refs.get("nist_800_53") or {}
    if nist.get("items"):
        out.append(("NIST 800-53 Rev 5", ", ".join(i["id"] for i in nist["items"])))
    iso = refs.get("iso_27001") or {}
    if iso.get("items"):
        out.append(("ISO 27001:2022", ", ".join(i["id"] for i in iso["items"])))
    return out


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
    """Flatten Conftest's output into one violation per (control, resource).

    If a resource breaks the same control in several ways (e.g. SSH and RDP both
    open on one security group), the reasons are merged so none is lost.
    """
    merged = {}
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
            if key not in merged:
                merged[key] = {
                    "control_id": meta["control_id"],
                    "resource": meta["resource"],
                    "severity": meta["severity"],
                    "reason": failure["msg"],
                }
            elif failure["msg"] not in merged[key]["reason"].split(" | "):
                merged[key]["reason"] += " | " + failure["msg"]
    return list(merged.values())


# ---------------------------------------------------------------------------
# Severity gate + waivers
# ---------------------------------------------------------------------------

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def load_gate(path=GATE_FILE):
    """Return the severity at/above which findings block the pipeline (default: medium)."""
    try:
        with open(path) as f:
            fail_on = json.load(f).get("fail_on", "medium")
    except FileNotFoundError:
        return "medium"
    except json.JSONDecodeError as e:
        raise ComplianceToolError(f"{path} is not valid JSON: {e}")
    if fail_on not in SEVERITY_RANK:
        raise ComplianceToolError(
            f"{path}: fail_on must be one of {sorted(SEVERITY_RANK, key=SEVERITY_RANK.get)}, got {fail_on!r}"
        )
    return fail_on


def load_waivers(path=WAIVERS_FILE, known_controls=None):
    """Load and strictly validate the waivers file. Returns a list of waiver dicts."""
    known_controls = CONTROLS if known_controls is None else known_controls
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as e:
        raise ComplianceToolError(f"{path} is not valid JSON: {e}")

    waivers = data.get("waivers", [])
    if not isinstance(waivers, list):
        raise ComplianceToolError(f"{path}: 'waivers' must be a list")

    required = ("control_id", "resource", "owner", "reason", "expires")
    for i, w in enumerate(waivers, start=1):
        where = f"{path}: waiver #{i}"
        if not isinstance(w, dict):
            raise ComplianceToolError(f"{where} must be an object")
        missing = [k for k in required if not str(w.get(k, "")).strip()]
        if missing:
            raise ComplianceToolError(f"{where} is missing required field(s): {', '.join(missing)}")
        if w["control_id"] not in known_controls:
            raise ComplianceToolError(f"{where} references unknown control_id {w['control_id']!r}")
        if any(ch in w["resource"] for ch in "*?"):
            raise ComplianceToolError(f"{where}: wildcards are not allowed - waive one exact resource at a time")
        try:
            w["_expires"] = date.fromisoformat(w["expires"])
        except ValueError:
            raise ComplianceToolError(f"{where}: expires must be a YYYY-MM-DD date, got {w['expires']!r}")
    return waivers


def today_utc():
    return datetime.now(timezone.utc).date()


def evaluate(violations, waivers=(), fail_on="medium", today=None):
    """
    Apply waivers and the severity gate to raw violations.

    Returns a dict:
      blocking        - findings at/above the gate with no valid waiver (these fail the pipeline)
      warnings        - findings below the gate with no valid waiver
      waived          - findings covered by an unexpired waiver (each carries its 'waiver')
      expired_waivers - waivers that matched a finding but have expired (finding is NOT waived)
      unused_waivers  - waivers matching no current finding (stale - should be removed)
      fail_on         - the gate threshold used
    """
    today = today or today_utc()
    threshold = SEVERITY_RANK[fail_on]
    result = {"blocking": [], "warnings": [], "waived": [], "expired_waivers": [], "unused_waivers": [], "fail_on": fail_on}
    matched = set()

    for v in violations:
        key = (v["control_id"], strip_index(v["resource"]))
        candidates = [
            (i, w) for i, w in enumerate(waivers)
            if (w["control_id"], strip_index(w["resource"])) == key
        ]
        active = next(((i, w) for i, w in candidates if w["_expires"] >= today), None)
        matched.update(i for i, _ in candidates)

        if active:
            result["waived"].append({**v, "waiver": active[1]})
            continue

        item = dict(v)
        if candidates:
            item["expired_waiver"] = candidates[0][1]
            for _, w in candidates:
                if w not in result["expired_waivers"]:
                    result["expired_waivers"].append(w)
        # unknown severities fail safe: treat them as blocking
        rank = SEVERITY_RANK.get(v["severity"], len(SEVERITY_RANK))
        (result["blocking"] if rank >= threshold else result["warnings"]).append(item)

    result["unused_waivers"] = [w for i, w in enumerate(waivers) if i not in matched]
    return result


STATUS_RANK = {"PASS": 0, "WAIVED": 1, "WARN": 2, "FAIL": 3}


def finding_status_map(evaluation):
    """{(control_id, resource): 'FAIL'|'WARN'|'WAIVED'} - the worst status wins per pair."""
    status = {}
    for label, items in (("WAIVED", evaluation["waived"]), ("WARN", evaluation["warnings"]), ("FAIL", evaluation["blocking"])):
        for v in items:
            status[(v["control_id"], strip_index(v["resource"]))] = label
    return status


def build_resource_control_summary(plan_json, evaluation):
    """
    Return a list of {control_id, title, resource, status} for every
    (control, resource) pair that applies - every resource of a control's target
    types - with status PASS / FAIL / WARN / WAIVED. Findings on resources outside
    those types (or from a control missing in controls.json) are still included so
    a finding can never silently disappear from the dashboard.
    """
    status = finding_status_map(evaluation)
    summary = []
    listed = set()

    for control_id, info in CONTROLS.items():
        for address in get_resources_by_type(plan_json, info["resource_types"]):
            key = (control_id, strip_index(address))
            listed.add(key)
            summary.append({
                "control_id": control_id,
                "title": info["title"],
                "resource": address,
                "status": status.get(key, "PASS"),
            })

    for (control_id, address), label in sorted(status.items()):
        if (control_id, address) in listed:
            continue
        summary.append({
            "control_id": control_id,
            "title": CONTROLS.get(control_id, {}).get("title", "Unknown Control"),
            "resource": address,
            "status": label,
        })
    return summary


def build_control_summary(evaluation):
    """Return a list of {control_id, title, status} - worst resource status per control."""
    status = finding_status_map(evaluation)
    out = []
    for cid, info in CONTROLS.items():
        worst = max((s for (c, _), s in status.items() if c == cid), key=STATUS_RANK.get, default="PASS")
        out.append({"control_id": cid, "title": info["title"], "status": worst})
    return out
