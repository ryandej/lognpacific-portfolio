"""Synthetic guard tests; no Tenable connection, scan or Windows operation."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "stig-remediations"))
import tenable_client as T
import tenable_diagnostic as D


def fixture():
    scope = {"scan_id": 42, "scan_name": "Synthetic owned scan",
             "target": "198.51.100.7", "scanner_name": "Synthetic scanner"}
    settings = dict(D.SAFETY, name=scope["scan_name"], text_targets=scope["target"],
                    scanner_id="synthetic-scanner-selection", fast_network_discovery="yes")
    settings.update({k: "yes" for k in D.CHANGES})
    settings.update(portscan_range="default", audit_trail="none", log_live_hosts="no")
    snap = {"uuid": "synthetic-template", "settings": settings,
            "schedule": {"enabled": False, "rrules": None, "starttime": None, "timezone": None},
            "credentials": [{"id": 8, "auth_method": "Password", "username": "synthetic-local-user"}],
            "audits": [{"id": "21156_DISA_STIG_Microsoft_Windows_11_v2r11.audit", "variables": {}}],
            "plugins": {"Policy Compliance": {"id": 29, "status": "mixed", "lock_state": "Locked",
                                               "individual": {"21156": "enabled", "999": "disabled"}},
                        "Synthetic diagnostics": {"id": 1, "status": "disabled"}}}
    mapping = {p: "Synthetic diagnostics" for p in D.DIAGNOSTICS}
    return scope, snap, mapping


class DiagnosticGuards(unittest.TestCase):
    def setUp(self):
        self.scope, self.before, self.mapping = fixture()

    def test_default_is_offline(self):
        self.assertEqual(D.main(["launch"]), 0)

    def test_explicit_scanner_retained(self):
        self.assertEqual(D.payload(self.before, self.scope)["settings"]["scanner_id"],
                         "synthetic-scanner-selection")

    def test_ping_bypass_includes_dependent_fast_discovery_setting(self):
        after=D.patch(self.before,self.mapping)
        self.assertEqual(after['settings']['ping_the_remote_host'],'no')
        self.assertEqual(after['settings']['fast_network_discovery'],'no')
        self.assertEqual(self.before['settings']['fast_network_discovery'],'yes')

    def test_no_credential_or_audit_mutation(self):
        self.assertEqual(set(D.payload(self.before, self.scope)), {"uuid", "settings", "plugins"})

    def test_expanded_target_rejected(self):
        self.before["settings"]["text_targets"] += ",198.51.100.8"
        with self.assertRaises(T.Blocked):D.payload(self.before, self.scope)

    def test_wrong_name_rejected(self):
        self.before["settings"]["name"] = "Another scan"
        with self.assertRaises(T.Blocked):D.payload(self.before, self.scope)

    def test_missing_scanner_rejected(self):
        del self.before["settings"]["scanner_id"]
        with self.assertRaises(T.Blocked):D.payload(self.before, self.scope)

    def test_every_safety_flag_enforced(self):
        for key in D.SAFETY:
            with self.subTest(key=key):
                snap = copy.deepcopy(self.before)
                snap["settings"][key] = "unexpected"
                with self.assertRaises(T.Blocked):D.payload(snap, self.scope)

    def test_schedule_rejected(self):
        self.before["schedule"]["enabled"] = True
        with self.assertRaises(T.Blocked):D.payload(self.before, self.scope)

    def test_recurring_schedule_rejected(self):
        self.before["schedule"]["rrules"] = "FREQ=DAILY"
        with self.assertRaises(T.Blocked):D.payload(self.before, self.scope)

    def test_wrong_or_multiple_audits_rejected(self):
        for audits in ([], [{"id": "different"}], self.before["audits"] * 2):
            with self.subTest(audits=len(audits)):
                snap = copy.deepcopy(self.before);snap["audits"] = audits
                with self.assertRaises(T.Blocked):D.payload(snap, self.scope)

    def test_missing_or_changed_credential_rejected(self):
        for credentials in ([], [{"auth_method": "Kerberos"}], self.before["credentials"] * 2):
            with self.subTest(credentials=len(credentials)):
                snap = copy.deepcopy(self.before);snap["credentials"] = credentials
                with self.assertRaises(T.Blocked):D.payload(snap, self.scope)

    def test_patch_preserves_original_and_protected_state(self):
        saved = copy.deepcopy(self.before)
        after = D.patch(self.before, self.mapping)
        self.assertEqual(saved, self.before)
        for key in ("uuid", "schedule", "credentials", "audits"):
            self.assertEqual(after[key], self.before[key])
        for key, value in D.CHANGES.items():self.assertEqual(after["settings"][key], value)
        selected = {int(p) for f in after["plugins"].values() for p, v in f.get("individual", {}).items() if v == "enabled"}
        self.assertEqual(selected, D.DIAGNOSTICS | {21156})

    def test_plugin_mapping_must_be_exact(self):
        for mapping in ({}, dict(self.mapping, unexpected="Synthetic diagnostics")):
            with self.assertRaises(T.Blocked):D.patch(self.before, mapping)

    def test_broad_family_rejected(self):
        self.before["plugins"]["Synthetic diagnostics"]["status"] = "enabled"
        with self.assertRaises(T.Blocked):D.patch(self.before, self.mapping)

    def test_unknown_original_setting_rejected(self):
        del self.before["settings"]["audit_trail"]
        with self.assertRaises(T.Blocked):D.patch(self.before, self.mapping)

    def test_conflicting_defaults_rejected(self):
        with self.assertRaises(T.Blocked):
            D.selected_defaults([{"id": "x", "default": "yes"}, {"id": "x", "default": "no"}], {"x"})

    def test_secret_and_option_values_excluded(self):
        value = [{"id": "scanner_id", "default": "selected", "options": [{"id": "other", "name": "unrelated"}]},
                 {"id": "password", "default": "synthetic-sensitive-value"}]
        self.assertEqual(D.selected_defaults(value, {"scanner_id"}), {"scanner_id": "selected"})

    def test_unrelated_editor_route_rejected(self):
        obj = D.Diagnostic(SimpleNamespace(scan="42"), "/tmp")
        with self.assertRaises(T.Blocked):obj.get("/families/99")

    def test_duplicate_launch_prevented_and_receipt_before_request(self):
        after = D.patch(self.before, self.mapping)
        with tempfile.TemporaryDirectory() as tmp:
            calls = []
            def transport(method, path, body):
                self.assertTrue(Path(tmp, "launch-attempt.private.json").is_file())
                calls.append((method, path, body))
                return b'{"scan_uuid":"synthetic-run"}'
            c = SimpleNamespace(scope=self.scope, scan="42", history=lambda: {"history": [{"id": 7}]}, _https=transport)
            obj = D.Diagnostic(c, tmp);obj.prepared=lambda:(self.before, after);obj.snapshot=lambda:after
            self.assertTrue(obj.launch()["launch_submitted"])
            with self.assertRaises(FileExistsError):obj.launch()
            self.assertEqual(calls, [("POST", "/scans/42/launch", b"{}")])

    def test_timeout_does_not_allow_launch_retry(self):
        after = D.patch(self.before, self.mapping)
        with tempfile.TemporaryDirectory() as tmp:
            calls = []
            def transport(*args):calls.append(args);raise T.Blocked("Transport failed")
            c = SimpleNamespace(scope=self.scope, scan="42", history=lambda: {"history": []}, _https=transport)
            obj=D.Diagnostic(c,tmp);obj.prepared=lambda:(self.before,after);obj.snapshot=lambda:after
            with self.assertRaises(T.Blocked):obj.launch()
            with self.assertRaises(FileExistsError):obj.launch()
            self.assertEqual(len(calls),1)

    def test_restore_is_noop_if_already_original(self):
        obj=D.Diagnostic(SimpleNamespace(),"/tmp")
        obj.prepared=lambda:(self.before,D.patch(self.before,self.mapping));obj.snapshot=lambda:self.before
        self.assertEqual(obj.restore(),{"restored":True,"write_needed":False})

    def test_restore_refuses_concurrent_credential_change(self):
        after=D.patch(self.before,self.mapping);after['credentials'][0]['id']=99
        obj=D.Diagnostic(SimpleNamespace(),"/tmp");obj.prepared=lambda:(self.before,after);obj.snapshot=lambda:after
        with self.assertRaises(T.Blocked):obj.restore()

    def test_restore_refuses_unrelated_plugin_change(self):
        after=D.patch(self.before,self.mapping)
        current=copy.deepcopy(after)
        current['plugins']['Policy Compliance']['individual']['999']='enabled'
        obj=D.Diagnostic(SimpleNamespace(),'/tmp')
        obj.prepared=lambda:(self.before,after);obj.snapshot=lambda:current
        with self.assertRaises(T.Blocked):obj.restore()


if __name__ == "__main__":
    unittest.main()
