"""Recorded workbook totals and rejection of inconsistent source summaries."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("recorded_workbook", ROOT / "cyber-defense/workbooks/build_investigation.py")
W = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(W)


class RecordedWorkbookTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(W.SUMMARY.read_text())

    def test_saved_artifact_matches_recorded_counts(self):
        self.assertEqual(W.build(), json.loads(W.ARTIFACT.read_text()))
        self.assertEqual(self.data["timeline_records"], 233)

    def test_five_panels_use_only_recorded_aggregate_tables(self):
        panels = [p for p in W.build()["items"] if p["type"] == 3]
        self.assertEqual([p["name"] for p in panels], ["overview", "sources", "timeline", "actions", "queries"])
        for p in panels:
            q = p["content"]["query"]
            self.assertTrue(q.startswith(("print ", "datatable(")))
            self.assertNotIn("workspace(", q)
            self.assertEqual(p["content"]["crossComponentResources"], [])
        self.assertFalse(any(p["type"] == 9 for p in W.build()["items"]))

    def test_each_breakdown_reconciles(self):
        for key in ("sources", "timeline_bins", "actions"):
            with self.subTest(key=key):
                d = deepcopy(self.data)
                d[key][0]["records"] += 1
                with self.assertRaises(ValueError): W.build(d)

    def test_invalid_counts_rejected(self):
        for value in (-1, True, "233", 233.0):
            d = deepcopy(self.data)
            d["timeline_records"] = value
            with self.subTest(value=value), self.assertRaises(ValueError): W.build(d)

    def test_duplicate_or_unknown_sources_rejected(self):
        for value in (self.data["sources"][0]["table"], "UnknownEvents"):
            d = deepcopy(self.data)
            d["sources"][1]["table"] = value
            with self.subTest(value=value), self.assertRaises(ValueError): W.build(d)

    def test_gaps_in_bins_rejected(self):
        self.data["timeline_bins"][1]["start_minute"] += 1
        with self.assertRaises(ValueError): W.build(self.data)

    def test_incomplete_or_duplicated_query_receipts_rejected(self):
        for mutation in ("partial", "duplicate", "timeline"):
            d = deepcopy(self.data)
            if mutation == "partial": d["queries"][0]["complete_response"] = False
            if mutation == "duplicate": d["queries"][1] = d["queries"][0]
            if mutation == "timeline": d["queries"][-1]["returned_rows"] -= 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): W.build(d)

    def test_duplicate_actions_rejected(self):
        self.data["actions"].append(self.data["actions"][0])
        with self.assertRaises(ValueError): W.build(self.data)

    def test_source_label_and_output_are_explicit(self):
        self.data["data"] = "Synthetic test events"
        with self.assertRaises(ValueError): W.build(self.data)
        text = json.dumps(W.build())
        self.assertIn("Recorded results", text)
        self.assertIn("saved counts", text)
        self.assertNotIn("SYNTHETIC FIXTURES ONLY", text)


if __name__ == "__main__":
    unittest.main()
