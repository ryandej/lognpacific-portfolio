"""Check denominators and reject unsupported program-result claims."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("program_metrics", ROOT / "vulnerability-management/metrics.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class ProgramMetricsTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "vulnerability-management/assessment-summary.json").read_text())

    def test_actual_cycle_denominators(self):
        r = M.calculate(self.data)
        self.assertEqual(r["selected_verified_closures"], 10)
        self.assertEqual(r["assessed_audit_items"], 258)
        self.assertEqual(r["failed_item_reduction_percent"], 8.55)
        self.assertEqual((r["unresolved_errors"], r["unresolved_warnings"]), (65, 8))

    def test_missing_authentication_or_equivalence(self):
        for flag in ["authenticated_baseline", "authenticated_followup", "same_asset_and_equivalent_configuration"]:
            with self.subTest(flag=flag):
                d = copy.deepcopy(self.data);d[flag] = False
                with self.assertRaises(ValueError):M.calculate(d)

    def test_unequal_or_incomplete_coverage(self):
        for op in ["remove", "increase"]:
            d = copy.deepcopy(self.data)
            if op == "remove":del d["counts"]["followup"]["ERROR"]
            else:d["counts"]["followup"]["PASSED"] += 1
            with self.assertRaises(ValueError):M.calculate(d)

    def test_duplicate_missing_or_unverified_controls(self):
        for op in ["duplicate", "empty", "unverified", "wrong_rule", "wrong_benchmark"]:
            d = copy.deepcopy(self.data)
            if op == "duplicate":d["controls"].append(d["controls"][0])
            elif op == "empty":d["controls"] = []
            elif op == "unverified":d["controls"][0]["followup"] = "ERROR"
            elif op == "wrong_rule":d["controls"][0]["rule_id"] = "unknown"
            else:d["controls"][0]["benchmark"] = "V2R4"
            with self.subTest(op=op), self.assertRaises(ValueError):M.calculate(d)

    def test_errors_must_not_be_promoted_to_passes(self):
        d = copy.deepcopy(self.data);d["counts"]["followup"]["ERROR"] -= 1;d["counts"]["followup"]["PASSED"] += 1
        with self.assertRaises(ValueError):M.calculate(d)

    def test_counts_and_export_digests_are_required(self):
        for mutation in [True, -1, "117"]:
            d = copy.deepcopy(self.data);d["counts"]["baseline"]["FAILED"] = mutation
            with self.assertRaises(ValueError):M.calculate(d)
        d = copy.deepcopy(self.data);d["baseline_sha256"] = ""
        with self.assertRaises(ValueError):M.calculate(d)


if __name__ == "__main__":unittest.main()
