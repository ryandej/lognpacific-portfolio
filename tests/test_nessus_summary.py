"""Synthetic .nessus v2 contract tests; never represents an actual scan."""
import importlib.util
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("nessus_summary", ROOT / "stig-remediations/nessus_summary.py")
ns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ns)
TARGET = "192.0.2.15"  # Documentation-only fixture, not a Cyber Range address.
CID = next(iter(ns.CONTROLS))


def fixture(result="FAILED", revision="v2r11", auth="yes", controls=None):
    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report", name="SYNTHETIC")
    host = ET.SubElement(report, "ReportHost", name=TARGET)
    props = ET.SubElement(host, "HostProperties")
    ET.SubElement(props, "tag", name="host-ip").text = TARGET
    scan = ET.SubElement(host, "ReportItem", pluginID="19506")
    ET.SubElement(scan, "plugin_output").text = "Credentialed checks : " + auth
    for cid in controls or [CID]:
        row = ET.SubElement(host, "ReportItem", pluginID="21156")
        for name, value in {
            "compliance-check-name": cid + " - synthetic check",
            "compliance-result": result,
            "compliance-info": ns.CONTROLS[cid]["RuleId"],
            "compliance-audit-file": "DISA_STIG_Microsoft_Windows_11_" + revision + ".audit",
            "compliance-actual-value": "SENSITIVE-FIXTURE-VALUE",
        }.items():
            ET.SubElement(row, ns.CM + name).text = value
    return root


def summary(root, target=TARGET):
    return ns.summarize(ET.tostring(root, encoding="utf-8"), target)


def item(root):
    return root.find("Report/ReportHost/ReportItem[@pluginID='21156']")


def fragments():
    root = fixture(controls=list(ns.CONTROLS))
    report = root.find("Report"); host = report.find("ReportHost")
    props = host.find("HostProperties")
    for key, value in (("host-uuid", "SYNTHETIC-HOST"), ("HOST_START", "SYNTHETIC-START"),
                       ("HOST_END", "SYNTHETIC-END")):
        ET.SubElement(props, "tag", name=key).text = value
    second = ET.SubElement(report, "ReportHost", name=TARGET)
    second.append(deepcopy(props))
    for row in host.findall("ReportItem")[5:]:
        host.remove(row); second.append(row)
    return root


class NessusSummaryTests(unittest.TestCase):
    def test_all_ten_controls_and_no_live_claim(self):
        r = summary(fixture(controls=list(ns.CONTROLS)))
        self.assertEqual(len(r["controls"]), 10)
        self.assertTrue(all(x["status"] == "fail" for x in r["controls"]))
        self.assertEqual(r["claim"], "unverified")
        self.assertEqual(r["origin"], "synthetic")

    def test_allowlisted_output_excludes_host_and_raw_values(self):
        r = json.dumps(summary(fixture()))
        self.assertNotIn(TARGET, r)
        self.assertNotIn("SENSITIVE-FIXTURE-VALUE", r)
        self.assertNotIn("synthetic check", r)

    def test_policy_credentials_host_metadata_and_plugin_text_never_emerge(self):
        root = fixture()
        marker = "SYNTHETIC-PRIVATE-CONTENT"
        policy = ET.SubElement(root, "Policy")
        ET.SubElement(policy, "Credentials").text = marker
        ET.SubElement(root.find(".//HostProperties"), "tag", name="host-fqdn").text = marker
        root.find(".//plugin_output").text += "\n" + marker
        ET.SubElement(item(root), "plugin_output").text = marker
        result = json.dumps(summary(root))
        self.assertNotIn(marker, result)
        self.assertNotIn(TARGET, result)
        self.assertEqual(json.loads(result)["credentialed_checks"], "yes")

    def test_missing_controls_are_unassessed(self):
        self.assertEqual([x["status"] for x in summary(fixture())["controls"]].count("not_assessed"), 9)

    def test_empty_host_report_is_not_pass(self):
        root = fixture(); host = root.find("Report/ReportHost")
        for row in list(host.findall("ReportItem")): host.remove(row)
        r = summary(root)
        self.assertEqual(r["credentialed_checks"], "unknown")
        self.assertTrue(all(x["status"] == "not_assessed" for x in r["controls"]))

    def test_zero_hosts_rejected(self):
        root = fixture(); report = root.find("Report"); report.remove(report.find("ReportHost"))
        with self.assertRaises(ns.Invalid): summary(root)

    def test_multiple_hosts_rejected(self):
        root = fixture(); ET.SubElement(root.find("Report"), "ReportHost", name="192.0.2.16")
        with self.assertRaises(ns.Invalid): summary(root)

    def test_same_host_export_fragments_preserve_all_results(self):
        r = summary(fragments())
        self.assertEqual(r["report_items"], 11)
        self.assertEqual(r["credentialed_checks"], "yes")
        self.assertTrue(all(c["status"] == "fail" for c in r["controls"]))

    def test_fragment_identity_and_window_conflicts_rejected(self):
        for key in ("host-ip", "host-uuid", "HOST_START", "HOST_END"):
            root = fragments()
            root.findall("Report/ReportHost")[1].find("HostProperties/tag[@name='" + key + "']").text = "OTHER"
            with self.subTest(key=key), self.assertRaises(ns.Invalid): summary(root)

    def test_fragment_missing_binding_rejected(self):
        for key in ("host-ip", "host-uuid", "HOST_START", "HOST_END"):
            root = fragments(); props = root.findall("Report/ReportHost")[1].find("HostProperties")
            props.remove(props.find("tag[@name='" + key + "']"))
            with self.subTest(key=key), self.assertRaises(ns.Invalid): summary(root)

    def test_fragment_duplicate_metadata_rejected(self):
        root = fragments()
        ET.SubElement(root.findall("Report/ReportHost")[1].find("HostProperties"),
                      "tag", name="host-uuid").text = "SYNTHETIC-HOST"
        with self.assertRaises(ns.Invalid): summary(root)

    def test_repeated_export_fragment_rejected(self):
        root = fragments(); report = root.find("Report")
        report.append(deepcopy(report.findall("ReportHost")[1]))
        with self.assertRaises(ns.Invalid): summary(root)

    def test_different_fragment_host_name_rejected(self):
        root = fragments(); root.findall("Report/ReportHost")[1].set("name", "192.0.2.16")
        with self.assertRaises(ns.Invalid): summary(root)

    def test_nested_host_cannot_escape_scope_validation(self):
        root = fixture(); extra = ET.SubElement(root, "Unknown")
        ET.SubElement(extra, "ReportHost", name="192.0.2.16")
        with self.assertRaises(ns.Invalid): summary(root)

    def test_nested_report_is_rejected(self):
        root = fixture(); ET.SubElement(root.find("Report"), "Report")
        with self.assertRaises(ns.Invalid): summary(root)

    def test_wrong_target_rejected(self):
        with self.assertRaises(ns.Invalid): summary(fixture(), "192.0.2.16")

    def test_disagreeing_host_identity_rejected(self):
        root = fixture(); root.find(".//tag").text = "192.0.2.16"
        with self.assertRaises(ns.Invalid): summary(root)

    def test_duplicate_host_identity_rejected(self):
        root = fixture(); ET.SubElement(root.find(".//HostProperties"), "tag", name="host-ip").text = TARGET
        with self.assertRaises(ns.Invalid): summary(root)

    def test_policy_only_rejected(self):
        with self.assertRaises(ns.Invalid): ns.summarize(b"<NessusClientData_v2><Policy/></NessusClientData_v2>", TARGET)

    def test_entities_rejected_before_parsing(self):
        for data in (b'<!DOCTYPE x [<!ENTITY e "payload">]><x>&e;</x>', b'<!DOCTYPE x SYSTEM "file:///private"><x/>'):
            with self.subTest(data=data), self.assertRaises(ns.Invalid): ns.summarize(data, TARGET)

    def test_utf16_and_bad_xml_rejected(self):
        for data in ("<x/>".encode("utf-16"), b"<NessusClientData_v2>"):
            with self.assertRaises(ns.Invalid): ns.summarize(data, TARGET)

    def test_duplicate_field_rejected(self):
        root = fixture(); ET.SubElement(item(root), ns.CM + "compliance-result").text = "PASSED"
        with self.assertRaises(ns.Invalid): summary(root)

    def test_duplicate_control_results_are_ambiguous(self):
        r = summary(fixture(controls=[CID, CID]))
        self.assertEqual(r["controls"][0]["status"], "ambiguous")
        self.assertEqual(ns.compare(r, r)["controls"][0]["reported_transition"], "not-comparable")

    def test_warning_and_unknown_status_are_inconclusive(self):
        for result in ("WARNING", "ERROR", "NOT_APPLICABLE", "unexpected"):
            self.assertEqual(summary(fixture(result=result))["controls"][0]["status"], "inconclusive")

    def test_old_benchmark_never_claims_compatible(self):
        r = summary(fixture(revision="v2r7"))
        self.assertFalse(r["controls"][0]["observations"][0]["mapping_compatible"])
        self.assertEqual(ns.compare(r, r)["controls"][0]["reported_transition"], "not-comparable")

    def test_rule_revision_not_filled_from_catalog(self):
        root = fixture(); item(root).remove(item(root).find(ns.CM + "compliance-info"))
        r = summary(root)
        self.assertIsNone(r["controls"][0]["observations"][0]["rule_id"])
        self.assertFalse(r["controls"][0]["observations"][0]["mapping_compatible"])

    def test_rule_revision_from_actual_reference_field(self):
        root = fixture(); row = item(root)
        row.find(ns.CM + "compliance-info").text = "SYNTHETIC rationale"
        ET.SubElement(row, ns.CM + "compliance-reference").text = "Rule-ID|" + ns.CONTROLS[CID]["RuleId"]
        r = summary(root)["controls"][0]["observations"][0]
        self.assertEqual(r["rule_id"], ns.CONTROLS[CID]["RuleId"])
        self.assertTrue(r["mapping_compatible"])

    def test_conflicting_rule_fields_not_compatible(self):
        root = fixture()
        ET.SubElement(item(root), ns.CM + "compliance-reference").text = "Rule-ID|SV-999999r999999_rule"
        r = summary(root)["controls"][0]["observations"][0]
        self.assertIsNone(r["rule_id"])
        self.assertFalse(r["mapping_compatible"])

    def test_conflicting_authentication_blocks_comparison(self):
        root = fixture(); root.find(".//plugin_output").text += "\nCredentialed checks : no"
        r = summary(root)
        self.assertEqual(r["credentialed_checks"], "conflicting")
        self.assertEqual(ns.compare(r, r)["controls"][0]["reported_transition"], "not-comparable")

    def test_observed_smb_authentication_annotation_is_private(self):
        root = fixture()
        root.find(".//plugin_output").text = "Credentialed checks : yes, as 'SYNTHETIC-PRIVATE-ACCOUNT' via SMB"
        r = summary(root)
        self.assertEqual(r["credentialed_checks"], "yes")
        self.assertNotIn("SYNTHETIC-PRIVATE-ACCOUNT", json.dumps(r))

    def test_unknown_authentication_suffix_is_not_promoted(self):
        root = fixture()
        root.find(".//plugin_output").text = "Credentialed checks : yes, but unrecognized qualification"
        self.assertEqual(summary(root)["credentialed_checks"], "unknown")

    def test_no_authentication_blocks_comparison(self):
        before = summary(fixture(auth="no")); after = summary(fixture(result="PASSED"))
        self.assertEqual(ns.compare(before, after)["controls"][0]["reported_transition"], "not-comparable")

    def test_truncation_blocks_comparison(self):
        root = fixture(); item(root).find(ns.CM + "compliance-actual-value").text = "***TRUNCATED***"
        r = summary(root)
        self.assertTrue(r["truncated"])
        self.assertEqual(ns.compare(r, r)["controls"][0]["reported_transition"], "not-comparable")

    def test_diagnostic_problem_blocks_comparison(self):
        root = fixture(); ET.SubElement(root.find(".//ReportHost"), "ReportItem", pluginID="24786")
        r = summary(root)
        self.assertTrue(r["diagnostic_problem_present"])
        self.assertEqual(ns.compare(r, r)["controls"][0]["reported_transition"], "not-comparable")

    def test_transitions_are_provisional(self):
        for before, after, expected in [("FAILED", "PASSED", "fail-to-pass"), ("PASSED", "FAILED", "regressed"),
                                        ("PASSED", "PASSED", "already-passing"), ("FAILED", "FAILED", "still-failing")]:
            r = ns.compare(summary(fixture(before)), summary(fixture(after)))
            self.assertEqual(r["controls"][0]["reported_transition"], expected)
            self.assertEqual(r["claim"], "unverified")

    def test_wrong_namespace_does_not_supply_a_result(self):
        root = fixture(); item(root).find(ns.CM + "compliance-check-name").tag = "{urn:untrusted}compliance-check-name"
        self.assertEqual(summary(root)["controls"][0]["status"], "not_assessed")

    def test_nonexact_identifier_is_not_mapped(self):
        root = fixture(); item(root).find(ns.CM + "compliance-check-name").text = CID + "9 - synthetic"
        self.assertEqual(summary(root)["controls"][0]["status"], "not_assessed")

    def test_symlink_input_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); (p / "a").write_bytes(b"fixture"); (p / "b").symlink_to(p / "a")
            with self.assertRaises(OSError): ns.read_private(p / "b")

    def test_size_limit(self):
        with self.assertRaises(ns.Invalid): ns.summarize(b" " * (ns.MAX_BYTES + 1), TARGET)


if __name__ == "__main__":
    unittest.main()
