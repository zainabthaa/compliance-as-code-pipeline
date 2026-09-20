"""Guards against drift between the Rego policies and controls/controls.json.

Run:  python3 -m unittest discover -s tests -v
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from compliance_data import CONTROLS, parse_violations, build_resource_control_summary, ComplianceToolError  # noqa: E402


def rego_control_ids():
    ids = set()
    for f in (ROOT / "policy" / "cis-aws").glob("*.rego"):
        if f.name.endswith("_test.rego"):
            continue
        ids |= set(re.findall(r'"control_id":\s*"([^"]+)"', f.read_text()))
    # security-groups.rego takes its ids from a lookup table: "control_id": "5.2"
    return ids


class ControlMetadata(unittest.TestCase):
    def test_every_rego_control_has_metadata(self):
        missing = rego_control_ids() - set(CONTROLS)
        self.assertFalse(missing, f"Rego emits control ids missing from controls.json: {missing}")

    def test_every_control_has_a_rule(self):
        orphan = set(CONTROLS) - rego_control_ids()
        self.assertFalse(orphan, f"controls.json lists controls no Rego rule emits: {orphan}")

    def test_required_fields(self):
        for cid, c in CONTROLS.items():
            for field in ("title", "severity", "resource_types", "risk", "remediation"):
                self.assertTrue(c.get(field), f"{cid} is missing '{field}'")
            self.assertIn(c["severity"], {"critical", "high", "medium", "low"})


class ParsingAndSummary(unittest.TestCase):
    def conftest_output(self, *failures):
        return [{"failures": list(failures)}]

    def failure(self, cid="5.2", resource="aws_security_group.a", msg="x"):
        return {"msg": msg, "metadata": {"control_id": cid, "resource": resource, "severity": "critical"}}

    def test_duplicates_are_collapsed(self):
        out = parse_violations(self.conftest_output(self.failure(), self.failure()))
        self.assertEqual(len(out), 1)

    def test_missing_metadata_raises_clear_error(self):
        with self.assertRaises(ComplianceToolError):
            parse_violations(self.conftest_output({"msg": "plain string deny"}))

    def test_violation_outside_known_types_still_shown(self):
        v = parse_violations(self.conftest_output(self.failure("SECRET-1", "aws_foo.bar")))
        summary = build_resource_control_summary({"resource_changes": []}, v)
        self.assertIn(("SECRET-1", "aws_foo.bar", "FAIL"), [(s["control_id"], s["resource"], s["status"]) for s in summary])


if __name__ == "__main__":
    unittest.main()
