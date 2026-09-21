"""Tests for the severity gate and the waiver (exception) workflow.

Run:  python3 -m unittest discover -s tests -v
"""

import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from compliance_data import ComplianceToolError, evaluate, load_gate, load_waivers  # noqa: E402
from generate_report import build_report  # noqa: E402

TODAY = date(2026, 9, 21)


def violation(control="5.3", resource="aws_security_group.a", severity="critical"):
    return {"control_id": control, "resource": resource, "severity": severity, "reason": "reason"}


def waiver(control="5.3", resource="aws_security_group.a", expires="2026-12-31"):
    return {
        "control_id": control, "resource": resource, "owner": "alice", "reason": "vendor needs it",
        "expires": expires, "_expires": date.fromisoformat(expires),
    }


def write_json(data):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(data, f)
    f.close()
    return f.name


class SeverityGate(unittest.TestCase):
    def setUp(self):
        self.vs = [violation("a", "r1", "critical"), violation("b", "r2", "high"), violation("c", "r3", "medium"), violation("d", "r4", "low")]

    def sev(self, items):
        return sorted(v["severity"] for v in items)

    def test_gate_medium_blocks_medium_and_up(self):
        r = evaluate(self.vs, fail_on="medium", today=TODAY)
        self.assertEqual(self.sev(r["blocking"]), ["critical", "high", "medium"])
        self.assertEqual(self.sev(r["warnings"]), ["low"])

    def test_gate_high_downgrades_medium_to_warning(self):
        r = evaluate(self.vs, fail_on="high", today=TODAY)
        self.assertEqual(self.sev(r["blocking"]), ["critical", "high"])
        self.assertEqual(self.sev(r["warnings"]), ["low", "medium"])

    def test_gate_critical_only(self):
        r = evaluate(self.vs, fail_on="critical", today=TODAY)
        self.assertEqual(self.sev(r["blocking"]), ["critical"])

    def test_unknown_severity_fails_safe(self):
        r = evaluate([violation(severity="banana")], fail_on="critical", today=TODAY)
        self.assertEqual(len(r["blocking"]), 1)

    def test_invalid_gate_value_rejected(self):
        with self.assertRaises(ComplianceToolError):
            load_gate(write_json({"fail_on": "urgent"}))

    def test_missing_gate_file_defaults_to_medium(self):
        self.assertEqual(load_gate("/nonexistent/gate.json"), "medium")


class Waivers(unittest.TestCase):
    def test_active_waiver_removes_block(self):
        r = evaluate([violation()], [waiver()], today=TODAY)
        self.assertEqual((len(r["blocking"]), len(r["waived"])), (0, 1))

    def test_waiver_expiring_today_is_still_valid(self):
        r = evaluate([violation()], [waiver(expires="2026-09-21")], today=TODAY)
        self.assertEqual(len(r["waived"]), 1)

    def test_expired_waiver_no_longer_applies(self):
        r = evaluate([violation()], [waiver(expires="2026-09-20")], today=TODAY)
        self.assertEqual((len(r["blocking"]), len(r["waived"])), (1, 0))
        self.assertEqual(len(r["expired_waivers"]), 1)
        self.assertIn("expired_waiver", r["blocking"][0])

    def test_waiver_is_scoped_to_control_and_resource(self):
        vs = [violation("5.3", "aws_security_group.a"), violation("5.3", "aws_security_group.b"), violation("5.4", "aws_security_group.a")]
        r = evaluate(vs, [waiver("5.3", "aws_security_group.a")], today=TODAY)
        self.assertEqual(len(r["waived"]), 1)
        self.assertEqual(len(r["blocking"]), 2)

    def test_waiver_matches_count_index(self):
        r = evaluate([violation(resource="aws_security_group.a[0]")], [waiver()], today=TODAY)
        self.assertEqual(len(r["waived"]), 1)

    def test_unused_waiver_is_reported(self):
        r = evaluate([], [waiver()], today=TODAY)
        self.assertEqual(len(r["unused_waivers"]), 1)

    def test_waived_finding_is_not_a_warning_either(self):
        r = evaluate([violation(severity="low")], [waiver()], today=TODAY)
        self.assertEqual((len(r["warnings"]), len(r["waived"])), (0, 1))


class WaiverFileValidation(unittest.TestCase):
    def load(self, waivers):
        return load_waivers(write_json({"waivers": waivers}), known_controls={"5.3": {}})

    def good(self, **over):
        w = {"control_id": "5.3", "resource": "aws_security_group.a", "owner": "alice", "reason": "why", "expires": "2026-12-31"}
        w.update(over)
        return w

    def test_valid_file_loads(self):
        self.assertEqual(len(self.load([self.good()])), 1)

    def test_empty_and_missing_file_ok(self):
        self.assertEqual(self.load([]), [])
        self.assertEqual(load_waivers("/nonexistent/waivers.json"), [])

    def test_missing_field_rejected(self):
        for field in ("control_id", "resource", "owner", "reason", "expires"):
            with self.subTest(field=field), self.assertRaises(ComplianceToolError):
                self.load([self.good(**{field: ""})])

    def test_bad_date_rejected(self):
        with self.assertRaises(ComplianceToolError):
            self.load([self.good(expires="31/12/2026")])

    def test_unknown_control_rejected(self):
        with self.assertRaises(ComplianceToolError):
            self.load([self.good(control_id="NOPE-1")])

    def test_wildcard_resource_rejected(self):
        with self.assertRaises(ComplianceToolError):
            self.load([self.good(resource="aws_security_group.*")])

    def test_invalid_json_rejected(self):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        f.write("{not json")
        f.close()
        with self.assertRaises(ComplianceToolError):
            load_waivers(f.name)


class ReportContent(unittest.TestCase):
    def test_report_sections(self):
        vs = [violation("5.3", "aws_security_group.a", "critical"), violation("S3-VER-1", "aws_s3_bucket.b", "medium"), violation("5.4", "aws_security_group.c", "critical")]
        r = evaluate(vs, [waiver("5.4", "aws_security_group.c"), waiver("5.3", "aws_security_group.zzz")], fail_on="high", today=TODAY)
        text = build_report(r, today=TODAY)
        self.assertIn("Blocking: 1", text)
        self.assertIn("Warnings (below", text)
        self.assertIn("Waived (approved exceptions)", text)
        self.assertIn("Unused** waiver", text)
        self.assertIn("alice", text)


if __name__ == "__main__":
    unittest.main()
