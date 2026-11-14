"""Synthetic, non-mutating tests. No cloud, registry, service, or KQL execution."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


E = load("evidence", "stig-remediations/evidence.py")
D = load("preflight", "deployment/preflight.py")
A = load("auth_sequence", "cyber-defense/auth_sequence.py")
F = load("kql_fixture", "cyber-defense/kql_fixture.py")
Q = load("quality", "tools/check_repository.py")
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def evidence_fixture():
    """Fabricated in memory; never saved or presented as observed telemetry."""
    data = E.new_ledger("authorized-live", "ASSET-FIXTURE")
    def proof(kind, at):
        ref = "EV-" + kind.upper()
        data["evidence"][ref] = dict(kind=kind, sha256="a" * 64, captured_at=at,
                                     asset=data["asset"], disclosure_reviewed=True)
        return ref
    benchmark_ref = proof("benchmark", "2026-01-01T00:00:00Z")
    data["benchmark"] = dict(label="V2R11", evidence=benchmark_ref)
    for row in data["controls"]:
        c = E.CONTROLS[row["control"]]
        for stage, minute, status in (("baseline", 1, "fail"), ("followup", 4, "pass")):
            at = f"2026-01-01T00:0{minute}:00Z"
            row[stage] = dict(status=status, at=at, evidence=proof(stage, at), benchmark="V2R11", rule_id=c["RuleId"])
        at = "2026-01-01T00:02:00Z"
        row["remediation"] = dict(status="Changed", at=at, evidence=proof("remediation", at), changed=True, exit_code=0)
        at = "2026-01-01T00:03:00Z"
        row["local"] = dict(status="RegistryMatch", at=at, evidence=proof("local", at), value_exists=True, kind="DWord", value=c["ExpectedValue"])
        at = "2026-01-01T00:05:00Z"
        row["review"] = dict(status="reviewed", at=at, evidence=proof("review", at))
        row["claim"] = "tenable_verified"
    return data


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.data = evidence_fixture()
        self.row = self.data["controls"][0]

    def test_initial_ledger_has_ten_unassessed_records(self):
        data = E.new_ledger()
        result = E.validate(data)
        self.assertEqual(len(result), 10)
        self.assertTrue(all(r["claim"] == "unverified" and r["missing"] for r in result.values()))
        self.assertIsNone(data["benchmark"]["label"])

    def test_ten_complete_synthetic_contract_fixtures(self):
        result = E.validate(self.data)
        self.assertTrue(all(not r["missing"] and r["comparison"] == "fail-to-pass" for r in result.values()))

    def test_all_identifiers_map_exactly(self):
        for cid, control in E.CONTROLS.items():
            for key in ("ControlId", "VulnerabilityId", "RuleId"):
                with self.subTest(cid=cid, key=key):
                    self.assertEqual(E.map_identifier(control[key]), cid)

    def test_mapping_never_guesses_unknown_or_deferred_control(self):
        for identifier in ("WN11-CC-000305", "slideshow", "SV-253352r1_rule", ""):
            with self.assertRaises(E.Invalid): E.map_identifier(identifier)

    def test_synthetic_origin_cannot_claim_live_validation(self):
        self.data["origin"] = "synthetic"
        with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_benchmark_mismatch_records_but_blocks_claim(self):
        self.data["benchmark"]["label"] = "V2R7"
        with self.assertRaises(E.Invalid): E.validate(self.data)
        for row in self.data["controls"]: row["claim"] = "unverified"
        self.assertIn("benchmark reconciliation", E.validate(self.data)[self.row["control"]]["missing"])

    def test_followup_rule_revision_mismatch_blocks_claim(self):
        self.row["followup"]["rule_id"] = "SV-253352r1_rule"
        with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_scan_revision_mismatch_not_comparable(self):
        self.row["baseline"]["benchmark"] = "V2R7"
        self.row["claim"] = "unverified"
        self.assertEqual(E.validate(self.data)[self.row["control"]]["comparison"], "not-comparable")

    def test_missing_evidence_is_rejected(self):
        del self.data["evidence"]["EV-BASELINE"]
        with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_cross_asset_or_wrong_evidence_kind_rejected(self):
        for key, value in (("asset", "ASSET-OTHER"), ("kind", "local")):
            data = deepcopy(self.data)
            data["evidence"]["EV-BASELINE"][key] = value
            with self.assertRaises(E.Invalid): E.validate(data)

    def test_unreviewed_disclosure_blocks_final_claim(self):
        self.data["evidence"]["EV-FOLLOWUP"]["disclosure_reviewed"] = False
        with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_wrong_dword_and_type_rejected_for_all_controls(self):
        for i, control in enumerate(self.data["controls"]):
            for key, value in (("kind", "String"), ("value", 99), ("value", True), ("value_exists", False)):
                with self.subTest(control=control["control"], field=key):
                    data = deepcopy(self.data)
                    data["controls"][i]["local"][key] = value
                    with self.assertRaises(E.Invalid): E.validate(data)

    def test_whatif_and_rollback_not_remediation_success(self):
        for status, changed in (("NotApplied", False), ("Restored", True), ("AlreadyRestored", False)):
            self.row["remediation"].update(status=status, changed=changed)
            with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_zero_exit_does_not_prove_change(self):
        self.row["remediation"].update(status="AlreadyMatches", changed=True)
        with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_already_matching_is_not_new_fail_to_pass(self):
        self.row["baseline"]["status"] = "pass"
        self.row["remediation"].update(status="AlreadyMatches", changed=False)
        self.assertEqual(E.validate(self.data)[self.row["control"]]["comparison"], "already-passing")

    def test_partial_write_error_preserves_uncertainty(self):
        self.row["claim"] = "unverified"
        self.row["remediation"].update(status="Error", changed=None, exit_code=2)
        self.assertIn("successful apply outcome", E.validate(self.data)[self.row["control"]]["missing"])

    def test_chronology_blocks_claim(self):
        self.row["local"]["at"] = "2026-01-01T00:00:00Z"
        with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_evidence_capture_before_observation_rejected(self):
        self.data["evidence"]["EV-FOLLOWUP"]["captured_at"] = "2026-01-01T00:00:00Z"
        with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_naive_timestamp_rejected(self):
        self.row["local"]["at"] = "2026-01-01T00:03:00"
        with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_date_without_time_rejected(self):
        with self.assertRaises(E.Invalid): E.utc("2026-01-01Z")

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(E.Invalid): E.load_json('{"claim":"unverified","claim":"tenable_verified"}')

    def test_pass_to_fail_is_regression(self):
        self.row["claim"] = "unverified"
        self.row["baseline"]["status"] = "pass"
        self.row["followup"]["status"] = "fail"
        self.assertEqual(E.validate(self.data)[self.row["control"]]["comparison"], "regressed")

    def test_existing_dword_requires_observed_value(self):
        self.row["claim"] = "unverified"
        self.row["local"].update(status="RegistryMismatch", value=None)
        with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_duplicate_missing_and_unknown_control_rejected(self):
        for change in ("duplicate", "missing", "unknown"):
            data = deepcopy(self.data)
            if change == "duplicate": data["controls"][-1] = data["controls"][0]
            if change == "missing": data["controls"].pop()
            if change == "unknown": data["controls"][0]["control"] = "WN11-CC-999999"
            with self.assertRaises(E.Invalid): E.validate(data)

    def test_unknown_payload_cannot_enter_report(self):
        self.row["raw_output"] = "PRIVATE-FIXTURE"
        with self.assertRaises(E.Invalid): E.report(self.data, self.row["control"])

    def test_report_links_aliases_and_states_limitations(self):
        report = E.report(self.data, self.row["control"])
        self.assertIn("EV-BASELINE", report)
        self.assertIn("fail-to-pass", report)
        self.assertIn("not independent authentication", report)

    def test_missing_review_blocks_final_claim(self):
        self.row["review"] = dict(status="pending", at=None, evidence=None)
        with self.assertRaises(E.Invalid): E.validate(self.data)

    def test_windows_claim_does_not_require_or_imply_tenable(self):
        self.row["claim"] = "windows_verified"
        self.row["baseline"] = E.blank_scan()
        self.row["followup"] = E.blank_scan()
        result = E.validate(self.data)[self.row["control"]]
        self.assertIn("followup assessment", result["missing"])
        self.assertEqual(result["claim"], "windows_verified")


def deployment_fixture():
    data = D.template()
    data.update(captured_at="2026-01-01T00:00:00Z", resource_group_exists=True,
                region=D.SPEC["region"], image_urn=D.SPEC["image_urn"], image_available=True,
                image_os_disk_gib=127, size=D.SPEC["size"], size_available=True,
                nonzonal_supported=True, compute_registered=True, family_free_vcpus=2,
                trusted_launch_supported=True, subnet_capacity_available=True,
                regional_free_vcpus=2, subnet_succeeded=True, subnet_has_delegations=False,
                scanner_scope_authorized=True, scanner_path_verified=True)
    data["expected_scope"] = {k: "FIXTURE-" + k for k in D.SCOPE_KEYS}
    data["observed_scope"] = dict(data["expected_scope"])
    data["permissions"] = dict.fromkeys(D.PERMISSIONS, True)
    data["checks"] = dict.fromkeys(D.CHECKS, True)
    return data


class DeploymentTests(unittest.TestCase):
    def setUp(self): self.data = deployment_fixture()
    def evaluate(self): return D.evaluate(self.data, now=BASE)

    def test_blank_template_fails_closed(self):
        self.assertTrue(D.evaluate(D.template(), now=BASE)["blockers"])

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(ValueError): D.load_json('{"public_ip":true,"public_ip":false}')

    def test_ready_never_deploys(self):
        result = self.evaluate()
        self.assertTrue(result["ready_for_deployment_review"])
        self.assertFalse(result["deploy"])
        self.assertEqual(result["azure_operations"], 0)

    def test_scope_mismatch_blocks_without_echoing_identifiers(self):
        for key in D.SCOPE_KEYS:
            self.data = deployment_fixture()
            self.data["observed_scope"][key] = "CONFIDENTIAL-FIXTURE"
            result = self.evaluate()
            self.assertTrue(result["blockers"])
            self.assertNotIn("CONFIDENTIAL-FIXTURE", json.dumps(result))

    def test_unknown_permissions_and_management_block(self):
        for group, keys in (("permissions", D.PERMISSIONS), ("checks", D.CHECKS)):
            for key in keys:
                with self.subTest(group=group, key=key):
                    self.data = deployment_fixture()
                    self.data[group][key] = None
                    self.assertTrue(self.evaluate()["blockers"])

    def test_stale_future_and_invalid_observation_time(self):
        for stamp in ("2025-12-31T23:29:59Z", "2026-01-01T00:00:01Z", None, "2026-01-01"):
            self.data["captured_at"] = stamp
            self.assertTrue(self.evaluate()["blockers"])

    def test_single_existing_vm_preserved_never_create(self):
        self.data["expected_vm_fingerprint"] = "a" * 64
        self.data["existing_vms"] = [dict(identity_fingerprint="a" * 64, conforms_to_spec=True)]
        result = self.evaluate()
        self.assertTrue(result["preserve_existing_vm"])
        self.assertFalse(result["ready_for_deployment_review"])
        self.assertFalse(result["deploy"])

    def test_existing_unrecognized_vm_blocks(self):
        self.data["existing_vms"] = [dict(identity_fingerprint="b" * 64, conforms_to_spec=True)]
        self.assertTrue(self.evaluate()["blockers"])

    def test_duplicate_vms_block(self):
        self.data["existing_vms"] = [{}, {}]
        self.assertEqual(self.evaluate()["proposed_action"], "stop")

    def test_disappeared_preserved_vm_requires_recovery(self):
        self.data["expected_vm_fingerprint"] = "a" * 64
        self.assertEqual(self.evaluate()["proposed_action"], "stop")

    def test_quota_image_size_and_disk_constraints(self):
        for key, value in (("family_free_vcpus", 1), ("regional_free_vcpus", True), ("image_os_disk_gib", 129),
                           ("image_available", False), ("size_available", False), ("size", "OTHER"),
                           ("region", "OTHER"), ("subnet_has_delegations", True),
                           ("trusted_launch_supported", None), ("subnet_capacity_available", None)):
            self.data = deployment_fixture()
            self.data[key] = value
            self.assertTrue(self.evaluate()["blockers"])

    def test_public_ip_and_other_spec_changes_block(self):
        for key, value in (("public_ip", True), ("size", "OTHER"), ("os_disk_sku", "OTHER"),
                           ("zone", "1"), ("vm_limit", 2), ("nic_count", 2), ("public_ip", 0)):
            spec = deepcopy(D.SPEC)
            spec[key] = value
            self.assertTrue(D.evaluate(self.data, spec=spec, now=BASE)["blockers"])

    def test_scanner_dependencies_separate_from_deployment(self):
        self.data["scanner_path_verified"] = None
        result = self.evaluate()
        self.assertTrue(result["ready_for_deployment_review"])
        self.assertTrue(result["baseline_dependencies"])


def event(minute, action="LogonFailed", report=1, **kwargs):
    row = dict(Timestamp=BASE + timedelta(minutes=minute), DeviceId="DEVICE-A", AccountName="alice",
               AccountDomain="LAB", RemoteIP="SOURCE-A", LogonType="Network", ReportId=report, ActionType=action)
    row.update(kwargs)
    return row


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.events = [event(i, report=i) for i in range(5)] + [event(5, "LogonSuccess", 10)]

    def detect(self, events=None, devices=("DEVICE-A",)):
        return A.detect(self.events if events is None else events, BASE, BASE + timedelta(minutes=30), devices)

    def test_burst_then_success(self):
        self.assertEqual(self.detect()[0]["failure_count"], 5)

    def test_below_threshold(self): self.assertFalse(self.detect(self.events[1:]))
    def test_no_success(self): self.assertFalse(self.detect(self.events[:-1]))
    def test_empty_scope(self): self.assertFalse(self.detect(devices=()))

    def test_join_keys_prevent_unrelated_correlation(self):
        for key in ("DeviceId", "AccountName", "AccountDomain", "RemoteIP", "LogonType"):
            rows = deepcopy(self.events)
            rows[-1][key] = "OTHER"
            self.assertFalse(self.detect(rows))

    def test_domain_and_user_case_normalized(self):
        self.events[-1].update(AccountName="ALICE", AccountDomain="lab")
        self.assertEqual(len(self.detect()), 1)

    def test_missing_keys_do_not_correlate(self):
        for key in ("AccountName", "AccountDomain", "RemoteIP", "LogonType", "ReportId"):
            rows = deepcopy(self.events)
            rows[-1][key] = None
            self.assertFalse(self.detect(rows))

    def test_failure_after_or_at_success_excluded(self):
        self.events[0]["Timestamp"] = self.events[-1]["Timestamp"]
        self.assertFalse(self.detect())
        self.events[0]["Timestamp"] += timedelta(seconds=1)
        self.assertFalse(self.detect())

    def test_exact_ten_minute_boundary_included(self):
        self.events[-1]["Timestamp"] = BASE + timedelta(minutes=10)
        self.assertEqual(len(self.detect()), 1)
        self.events[-1]["Timestamp"] += timedelta(microseconds=1)
        self.assertFalse(self.detect())

    def test_duplicate_rows_do_not_inflate_count(self):
        self.assertFalse(self.detect(self.events[1:] + [self.events[1]] * 10))

    def test_same_report_id_different_timestamps_remain_distinct(self):
        for row in self.events: row["ReportId"] = 0
        self.assertEqual(len(self.detect()), 1)

    def test_input_order_independent(self):
        self.assertEqual(self.detect(), self.detect(list(reversed(self.events))))

    def test_end_boundary_excluded(self):
        self.events[-1]["Timestamp"] = BASE + timedelta(minutes=30)
        self.assertFalse(self.detect())

    def test_missing_timezone_rejected(self):
        self.events[0]["Timestamp"] = datetime(2026, 1, 1)
        with self.assertRaises(ValueError): self.detect()

    def test_invalid_window_threshold_rejected(self):
        with self.assertRaises(ValueError): A.detect([], BASE, BASE, [])
        with self.assertRaises(ValueError): A.detect([], BASE, BASE + timedelta(hours=1), [], threshold=0)

    def test_service_fixture_expected_counts_match_reference_model(self):
        rows, expected, scope, start = F.fixture()
        actual = A.detect(rows, start, start + timedelta(minutes=30), scope)
        counts = dict.fromkeys(expected, 0)
        for result in actual: counts[result["key"][0]] += 1
        self.assertEqual(counts, expected)

    def test_rendered_fixture_uses_actual_query_body(self):
        source = (ROOT / "cyber-defense/auth-sequence.kql").read_text()
        body = source.rpartition("\nSuccesses\n")[2].rstrip()
        generated = F.render()
        self.assertIn(body, generated)
        self.assertIn("SYNTHETIC ONLY", generated)
        self.assertNotIn("DeviceLogonEvents", generated)
        self.assertIn("Passed=(ActualRows == ExpectedRows)", generated)

    def test_fixture_rejects_threshold_drift(self):
        source = (ROOT / "cyber-defense/auth-sequence.kql").read_text()
        for threshold in (4, 6):
            changed = source.replace("let Threshold = 5;", f"let Threshold = {threshold};")
            with self.subTest(threshold=threshold), patch.object(F.Path, "read_text", return_value=changed):
                with self.assertRaisesRegex(ValueError, "Threshold.*reference model"):
                    F.render()

    def test_fixture_rejects_window_drift(self):
        source = (ROOT / "cyber-defense/auth-sequence.kql").read_text()
        for window in ("9m", "11m"):
            changed = source.replace("let Window = 10m;", f"let Window = {window};")
            with self.subTest(window=window), patch.object(F.Path, "read_text", return_value=changed):
                with self.assertRaisesRegex(ValueError, "Window.*reference model"):
                    F.render()


class QualityTests(unittest.TestCase):
    def test_api_key_literals_and_headers_are_reported_without_values(self):
        key = "SYNTHETIC" * 8
        for name in ("access_key", "secret_key", "api_key", "accessKey", "secretKey"):
            text = json.dumps({name: key})
            self.assertEqual(Q.inspect_text(text), [(1, "literal-api-key")])
            self.assertNotIn(key, repr(Q.inspect_text(text)))
        for name in ("accessKey", "secretKey"):
            self.assertEqual(Q.inspect_text(name + "=" + key + ";"), [(1, "literal-api-key")])

    def test_key_references_and_nonsecret_placeholders_are_not_literals(self):
        for text in ('keys["secret_key"]', '"accessKey=" + keys["access_key"]',
                     json.dumps({"access_key": "REDACTED", "secret_key": "REDACTED"})):
            self.assertFalse(Q.inspect_text(text))

    def test_secret_detection_does_not_echo_match(self):
        secret = "gh" + "p_" + "X" * 36
        result = Q.inspect_text("example\n" + secret)
        self.assertEqual(result, [(2, "github-credential")])
        self.assertNotIn(secret, repr(result))

    def test_protected_sources_rejected_before_reading(self):
        for path in ("Planning/example.md", ".azure/example.json", "private-evidence/data.json", "sample.nessus", ".env", "capture.evtx"):
            self.assertTrue(Q.protected(Path(path)))

    def test_public_source_not_blocked_by_keywords(self):
        for path in ("token_analysis.py", "password_policy.ps1", "docs/security.md"):
            self.assertFalse(Q.protected(Path(path)))

    def test_private_topology_detected(self):
        value = "192." + "168.50.12"
        self.assertEqual(Q.inspect_text(value), [(1, "private-ip")])

    def test_unsafe_links_do_not_read_sources(self):
        text = "[private](../Planning/DO-NOT-READ.md)"
        issues = Q.check_links(ROOT / "docs" / "example.md", text, ROOT)
        self.assertEqual(issues, ["unsafe documentation link"])

    def test_missing_link_detected(self):
        self.assertEqual(Q.check_links(ROOT / "README.md", "[absent](nonexistent.md)", ROOT), ["broken documentation link"])

    def test_all_queries_have_explicit_empty_scope(self):
        paths = list((ROOT / "threat-hunting").rglob("*.kql")) + list((ROOT / "cyber-defense").glob("*.kql"))
        self.assertEqual(len(paths), 11)
        for path in paths:
            text = path.read_text()
            for clause in ("let Start = datetime(null);", "let End = datetime(null);", "let DeviceScope = dynamic([]);", "where DeviceId in (DeviceScope)", "where Timestamp >= Start and Timestamp < End"):
                self.assertIn(clause, text)

    def test_cli_defaults_are_non_deploying(self):
        run = subprocess.run([sys.executable, "-B", str(ROOT / "deployment/preflight.py")], capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertFalse(json.loads(run.stdout)["deploy"])

    def test_initial_ledger_cli_does_not_fabricate_results(self):
        run = subprocess.run([sys.executable, "-B", str(ROOT / "stig-remediations/evidence.py"), "init"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertTrue(all(row["baseline"]["status"] == "not_assessed" for row in json.loads(run.stdout)["controls"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
