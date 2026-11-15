"""Offline workbook contracts and fail-closed scope behavior; no Azure calls."""
import importlib.util
import json
from pathlib import Path
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("workbook", ROOT / "cyber-defense/workbooks/build_workbook.py")
W = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(W)
WORKSPACE = "/subscriptions/" + str(uuid.UUID(int=0)) + "/resourceGroups/SYNTHETIC/providers/Microsoft.OperationalInsights/workspaces/SYNTHETIC"


class WorkbookTests(unittest.TestCase):
    def test_reproducible_artifact(self):
        self.assertEqual(W.build(), json.loads((W.HERE / "authentication-investigation.workbook.json").read_text()))

    def test_five_distinct_operational_panels(self):
        items = W.build()["items"]
        panels = [x for x in items if x["type"] == 3]
        self.assertEqual({x["name"] for x in panels}, set(W.PANELS))
        self.assertEqual(len(panels), 5)
        self.assertEqual({x["content"]["visualization"] for x in panels}, {"table", "timechart", "categoricalbar"})
        self.assertEqual(len({x["name"] for x in items}), len(items))

    def test_default_uses_no_live_table_or_workspace(self):
        d = W.build()
        self.assertIn("Generated test events", json.dumps(d))
        self.assertEqual(d["fallbackResourceIds"], [])
        for x in d["items"]:
            if x["type"] != 3:
                continue
            q = x["content"]["query"]
            self.assertIn("datatable(", q)
            self.assertNotIn("DeviceLogonEvents", q)
            self.assertNotIn("workspace(", q)
            self.assertEqual(x["content"]["crossComponentResources"], [])

    def test_fixed_scope_survives_time_picker(self):
        for x in W.build()["items"]:
            if x["type"] == 3:
                q = W.render_query(x)
                self.assertIn("where Timestamp >= Start and Timestamp < End", q)
                self.assertIn("where DeviceId in (DeviceScope)", q)
                self.assertNotIn("{TimeRange}", q)
                self.assertIn('let Threshold = 5;', q)
                self.assertIn('let Window = 10m;', q)

    def test_time_control_has_explicit_absolute_value_and_selectable_ranges(self):
        item = next(x for x in W.build()["items"] if x["name"] == "time-scope")
        param = item["content"]["parameters"][0]
        self.assertEqual(param["value"]["durationMs"], 1800000)
        self.assertEqual(W.utc(param["value"]["endTime"]) - W.timedelta(milliseconds=param["value"]["durationMs"]), W.utc("2026-01-01T00:00:00Z"))
        self.assertNotIn("startTime", param["value"])
        self.assertTrue(param["typeSettings"]["allowCustom"])
        self.assertTrue(all(x["durationMs"] > 0 for x in param["typeSettings"]["selectableValues"]))

    def test_actual_detector_retained(self):
        source = W.DETECTOR.read_text()
        body = source.rpartition("\nSuccesses\n")[2].rstrip()
        for x in W.build()["items"]:
            if x["type"] == 3:
                self.assertIn("let Candidates = (Successes\n" + body + "\n);", x["content"]["query"])

    def test_fixture_model_expectations_unchanged(self):
        spec = importlib.util.spec_from_file_location("reference", W.HERE.parent / "auth_sequence.py")
        model = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(model)
        rows, expected, devices, start = W.FIXTURE.fixture()
        observed = model.detect(rows, start, start + W.timedelta(minutes=30), devices)
        self.assertEqual(len(observed), 2)
        self.assertEqual({r["key"][0] for r in observed}, {d for d, count in expected.items() if count})
        self.assertEqual([r["failure_count"] for r in observed], [5, 5])

    def test_live_requires_complete_scope(self):
        for kwargs in [{}, {"device_id": "a" * 40}, {"device_id": "a" * 40, "start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z"}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                W.build(mode="live", **kwargs)

    def test_valid_live_is_explicit_and_single_device(self):
        d = W.build(mode="live", device_id="a" * 40, start="2026-01-01T00:00:00Z", end="2026-01-01T01:00:00Z", workspace=WORKSPACE)
        self.assertNotIn("Generated test events", json.dumps(d))
        self.assertEqual(d["fallbackResourceIds"], [WORKSPACE])
        for x in d["items"]:
            if x["type"] == 3:
                q = x["content"]["query"]
                self.assertIn("DeviceLogonEvents", q)
                self.assertNotIn("datatable(", q)
                self.assertIn('let DeviceScope = dynamic(["' + "a" * 40 + '"]);', q)

    def test_invalid_targets_rejected(self):
        for target in ["", "*", "a" * 39, "z" * 40, '"; union *', ["a" * 40]]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                W.build(mode="live", device_id=target, start="2026-01-01T00:00:00Z", end="2026-01-01T01:00:00Z", workspace=WORKSPACE)

    def test_invalid_windows_rejected(self):
        for start, end in [(None, None), ("2026-01-01", "2026-01-02"), ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"), ("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z"), ("2026-01-01T00:00:00Z", "2026-01-02T00:00:01Z")]:
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                W.build(mode="live", device_id="a" * 40, start=start, end=end, workspace=WORKSPACE)

    def test_unapproved_workspace_shapes_rejected(self):
        for scope in ["https://example.com", "*", WORKSPACE + "/extra", WORKSPACE + "'", WORKSPACE.replace("workspaces", "servers")]:
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                W.build(workspace=scope)

    def test_azure_normalized_workspace_id_case_is_accepted(self):
        d = W.build(workspace=WORKSPACE.lower())
        self.assertEqual(d["fallbackResourceIds"], [WORKSPACE.lower()])

    def test_synthetic_scope_cannot_be_relabelled_live(self):
        for kw in [{"device_id": "a" * 40}, {"start": "2026-01-01T00:00:00Z"}, {"end": "2026-01-01T01:00:00Z"}]:
            with self.assertRaises(ValueError):
                W.build(**kw)
        with self.assertRaises(ValueError):
            W.build(mode="production")

    def test_settings_and_source_drift_rejected(self):
        devices, start, end = W.scope("synthetic", None, None, None, None)
        source = W.DETECTOR.read_text()
        for changed in [source.replace("Threshold = 5", "Threshold = 4"), source.replace("Window = 10m", "Window = 9m"), source.replace("let Scoped = materialize(", "let Scoped=materialize("), source.replace("\nSuccesses\n", "\nSuccesses |\n")]:
            with self.assertRaises(ValueError):
                W.query_prefix("synthetic", devices, start, end, changed)

    def test_unexpected_ui_parameter_rejected(self):
        with self.assertRaises(ValueError):
            W.render_query({"content": {"query": "print value=1"}})

    def test_coverage_does_not_hide_empty_or_dirty_data(self):
        coverage = next(x for x in W.build()["items"] if x["name"] == "coverage")["content"]["query"]
        for term in ["DuplicateRows", "MissingKeyRows", "UnknownActions", "NoTelemetry", "CandidateSequences", "RawRows-DistinctRows"]:
            self.assertIn(term, coverage)

    def test_source_chart_displays_both_outcomes_against_categorical_source(self):
        panel = next(x for x in W.build()["items"] if x["name"] == "sources")["content"]
        self.assertEqual(panel["visualization"], "categoricalbar")
        self.assertEqual(panel["chartSettings"]["xAxis"], "SourceLabel")
        self.assertEqual(panel["chartSettings"]["yAxis"], ["Failures", "Successes"])
        self.assertIn('SourceLabel=strcat(RemoteIP, " | ", LogonType)', panel["query"])


if __name__ == "__main__":
    unittest.main()
