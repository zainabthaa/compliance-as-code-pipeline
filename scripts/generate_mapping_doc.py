"""
Generates docs/control-mapping.md from controls/controls.json so the published
mapping can never drift from the metadata the pipeline actually uses.

    python3 scripts/generate_mapping_doc.py          # rewrite the file
    python3 scripts/generate_mapping_doc.py --check  # exit 1 if it is out of date
"""

import sys
from pathlib import Path

from compliance_data import CONTROLS, REPO_ROOT, reference_summary

OUTPUT = REPO_ROOT / "docs" / "control-mapping.md"


def render():
    lines = [
        "# Control mapping",
        "",
        "Generated from `controls/controls.json` by `scripts/generate_mapping_doc.py`. Do not edit by hand.",
        "",
        "How to read this:",
        "",
        "- **Control ID:** a numeric ID (like 2.2.3) is a real CIS AWS Foundations Benchmark v5.0.0 recommendation number, used only when this check is a direct match for it. "
        "An ID like S3-ENC-1 is a project ID for a check with no equivalent CIS recommendation (or only a related one).",
        "- **CIS AWS** is the closest recommendation in the CIS AWS Foundations Benchmark v5.0.0, taken from the benchmark document. "
        "*direct* means the same requirement, *related* means overlapping but not identical, *none* means the benchmark has no such recommendation.",
        "- **NIST 800-53** is Rev 5. Where AWS Security Hub documents an equivalent control, its related requirements were used "
        "(base controls only, enhancements omitted). Otherwise the mapping is author-assigned and says so.",
        "- **ISO 27001** is 2022 Annex A. These are author-assigned by control intent and indicative only. "
        "The ISO standard itself is paywalled and no official crosswalk was used.",
        "- A mapping shows which requirement a check *supports*. It is not a claim that passing the check makes you compliant.",
        "",
        "## Summary",
        "",
        "| Control | Title | CIS AWS v5.0.0 | NIST 800-53 Rev 5 | ISO 27001:2022 |",
        "|---|---|---|---|---|",
    ]
    for cid, info in CONTROLS.items():
        refs = dict(reference_summary(info))
        lines.append(
            f"| {cid} | {info['title']} | {refs.get('CIS AWS v5.0.0', '')} | {refs.get('NIST 800-53 Rev 5', '')} | {refs.get('ISO 27001:2022', '')} |"
        )

    lines += ["", "## Detail and basis", ""]
    for cid, info in CONTROLS.items():
        r = info["references"]
        lines.append(f"### {cid} — {info['title']}")
        lines.append("")
        cis = r["cis_aws"]
        if cis["items"]:
            for i in cis["items"]:
                lines.append(f"- **CIS {i['id']}** ({cis['match']}): {i['title']}")
        else:
            lines.append("- **CIS:** none")
        if cis.get("note"):
            lines.append(f"  - {cis['note']}")
        lines.append("- **NIST 800-53 Rev 5:** " + "; ".join(f"{i['id']} {i['title']}" for i in r["nist_800_53"]["items"]))
        lines.append(f"  - Basis: {r['nist_800_53']['basis']}")
        lines.append("- **ISO 27001:2022:** " + "; ".join(f"{i['id']} {i['title']}" for i in r["iso_27001"]["items"]))
        lines.append(f"  - Basis: {r['iso_27001']['basis']}")
        lines.append("")

    lines += [
        "## Sources",
        "",
        "- CIS Amazon Web Services Foundations Benchmark v5.0.0 (recommendation numbers and titles)",
        "- AWS Security Hub controls reference: S3, RDS, EC2 and IAM controls, 'Related requirements' (NIST 800-53 Rev 5)",
        "- NIST SP 800-53 Rev 5 (control titles)",
        "- ISO/IEC 27001:2022 Annex A (control titles)",
        "",
    ]
    return "\n".join(lines)


def main():
    text = render()
    if "--check" in sys.argv:
        current = OUTPUT.read_text() if OUTPUT.exists() else ""
        if current != text:
            print(f"{OUTPUT} is out of date. Run: python3 scripts/generate_mapping_doc.py", file=sys.stderr)
            sys.exit(1)
        return
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(text)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
