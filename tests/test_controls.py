"""Guards against drift between the Rego policies and controls/controls.json.

Run:  python3 -m unittest discover -s tests -v
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from compliance_data import CONTROLS, parse_violations, build_resource_control_summary, evaluate, ComplianceToolError  # noqa: E402


def rego_control_ids():
    ids = set()
    for f in (ROOT / "policy" / "cis-aws").glob("*.rego"):
        if f.name.endswith("_test.rego"):
            continue
        ids |= set(re.findall(r'"control_id":\s*"([^"]+)"', f.read_text()))
    # security-groups.rego takes its ids from a lookup table (open_cidrs) that also uses "control_id": "..."
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


class FrameworkReferences(unittest.TestCase):
    def test_every_control_has_all_three_frameworks(self):
        for cid, c in CONTROLS.items():
            refs = c.get("references", {})
            for fw in ("cis_aws", "nist_800_53", "iso_27001"):
                self.assertIn(fw, refs, f"{cid} has no '{fw}' reference block")
            self.assertTrue(refs["nist_800_53"]["items"], f"{cid} needs at least one NIST control")
            self.assertTrue(refs["iso_27001"]["items"], f"{cid} needs at least one ISO control")
            self.assertIn(refs["cis_aws"]["match"], {"direct", "related", "none"})

    def test_identifier_formats(self):
        patterns = {"nist_800_53": r"^[A-Z]{2}-\d+(\(\d+\))?$", "iso_27001": r"^A\.\d+\.\d+$", "cis_aws": r"^\d+(\.\d+)+$"}
        for cid, c in CONTROLS.items():
            for fw, pattern in patterns.items():
                for item in c["references"][fw]["items"]:
                    self.assertRegex(item["id"], pattern, f"{cid}: bad {fw} id {item['id']!r}")
                    self.assertTrue(item["title"].strip())

    def test_cis_match_none_has_no_ids_and_vice_versa(self):
        for cid, c in CONTROLS.items():
            cis = c["references"]["cis_aws"]
            self.assertEqual(cis["match"] == "none", not cis["items"], f"{cid}: CIS match/items disagree")

    def test_numeric_ids_are_real_cis_numbers_and_only_those(self):
        """Rule: a control ID that looks like a CIS number IS that CIS recommendation (direct match).
        Anything else must use a project ID like S3-ENC-1 - never a made-up number."""
        for cid, c in CONTROLS.items():
            cis = c["references"]["cis_aws"]
            if re.match(r"^\d+(\.\d+)+$", cid):
                self.assertEqual(cis["match"], "direct", f"{cid} looks like a CIS number but is not a direct match")
                self.assertIn(cid, [i["id"] for i in cis["items"]], f"{cid} is not its own CIS reference")
            else:
                self.assertNotEqual(cis["match"], "direct", f"{cid} is a direct CIS match: use the CIS number as its ID")

    def test_mapping_doc_is_up_to_date(self):
        from generate_mapping_doc import OUTPUT, render
        self.assertTrue(OUTPUT.exists(), "docs/control-mapping.md is missing")
        self.assertEqual(OUTPUT.read_text(), render(), "docs/control-mapping.md is out of date: run python3 scripts/generate_mapping_doc.py")


class DashboardCounts(unittest.TestCase):
    def test_row_shows_number_of_affected_resources(self):
        from generate_dashboard import build_dashboard
        v = [
            {"control_id": "5.3", "resource": "aws_security_group.a", "severity": "critical", "reason": "ssh open"},
            {"control_id": "5.3", "resource": "aws_security_group.b", "severity": "critical", "reason": "rdp open"},
        ]
        ev = evaluate(v)
        summary = build_resource_control_summary(
            {"resource_changes": [{"address": a, "type": "aws_security_group"} for a in ("aws_security_group.a", "aws_security_group.b")]}, ev
        )
        html = build_dashboard(ev, summary)
        self.assertIn("FAIL &times;2", html)
        self.assertIn("Blocking findings", html)


class ParsingAndSummary(unittest.TestCase):
    def conftest_output(self, *failures):
        return [{"failures": list(failures)}]

    def failure(self, cid="5.3", resource="aws_security_group.a", msg="x"):
        return {"msg": msg, "metadata": {"control_id": cid, "resource": resource, "severity": "critical"}}

    def test_duplicates_are_collapsed(self):
        out = parse_violations(self.conftest_output(self.failure(), self.failure()))
        self.assertEqual(len(out), 1)

    def test_distinct_reasons_for_same_resource_are_merged(self):
        out = parse_violations(self.conftest_output(self.failure(msg="allows SSH"), self.failure(msg="allows RDP")))
        self.assertEqual(len(out), 1)
        self.assertIn("allows SSH", out[0]["reason"])
        self.assertIn("allows RDP", out[0]["reason"])

    def test_missing_metadata_raises_clear_error(self):
        with self.assertRaises(ComplianceToolError):
            parse_violations(self.conftest_output({"msg": "plain string deny"}))

    def test_violation_outside_known_types_still_shown(self):
        v = parse_violations(self.conftest_output(self.failure("SECRET-1", "aws_foo.bar")))
        summary = build_resource_control_summary({"resource_changes": []}, evaluate(v))
        self.assertIn(("SECRET-1", "aws_foo.bar", "FAIL"), [(s["control_id"], s["resource"], s["status"]) for s in summary])


if __name__ == "__main__":
    unittest.main()
