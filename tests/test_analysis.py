"""Synthetic aggregate statistics only; no clinical metrics or holdout read."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

from pcfl.analysis import analyze_registry, h4_noninferior, paired_bootstrap, rate, write_analysis
from test_experiments import example_attempt, example_plan

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from release_research import create_release


class AnalysisTests(unittest.TestCase):
    def test_paired_seed_bootstrap_preserves_correlated_pairs_and_one_sided_bound(self):
        stats = paired_bootstrap([1, 2, 3, 4, 5], [1.01, 2.01, 3.01, 4.01, 5.01], resamples=2000, seed=7)
        self.assertAlmostEqual(stats["mean_difference"], -0.01)
        self.assertAlmostEqual(stats["one_sided95_lower"], -0.01)
        self.assertGreater(stats["one_sided95_lower"], -0.02)
        self.assertEqual(stats["independent_seeds"], 5)
        self.assertEqual(stats, paired_bootstrap([1, 2, 3, 4, 5], [1.01, 2.01, 3.01, 4.01, 5.01], resamples=2000, seed=7))

    def test_empty_matrix_retains_all_required_cells_and_is_inconclusive(self):
        report = analyze_registry(example_plan(), [])
        self.assertFalse(report["primary_matrix_complete"])
        self.assertEqual(report["coverage"]["primary_cells"]["unattempted"], 160)
        self.assertTrue(all(row["verdict"] == "inconclusive" for row in report["hypotheses"].values()))
        self.assertIsNone(rate(0, 0))

    def test_noninferiority_requires_strictly_exceeding_margin(self):
        self.assertFalse(h4_noninferior(-0.02))
        self.assertFalse(h4_noninferior(-0.03))
        self.assertTrue(h4_noninferior(-0.019))
        self.assertFalse(h4_noninferior(float("nan")))

    def test_full_synthetic_matrix_never_asserts_clinical_verdicts_or_40_seeds(self):
        plan = example_plan()
        attempts = [example_attempt(plan, cell, identity=f"attempt-{number}") for number, cell in enumerate(plan["primary_cells"])]
        report = analyze_registry(plan, attempts, bootstrap_resamples=1000)
        self.assertTrue(report["primary_matrix_complete"])
        self.assertFalse(report["confirmatory_verdict_permitted"])
        pooled = [row for row in report["tables"]["paired_governance"] if row["stratum"] == "primary-seed-pooled"]
        self.assertTrue(all(row["independent_seeds"] == 5 for row in pooled))
        self.assertTrue(all(row["verdict"] == "inconclusive" for row in report["hypotheses"].values()))

    def test_failure_retry_cannot_silently_replace_a_missing_primary_cell(self):
        plan = example_plan()
        failed = example_attempt(plan, identity="failed", status="failed")
        success = example_attempt(plan, identity="retry")
        report = analyze_registry(plan, [failed, success])
        self.assertEqual(report["attempt_count"], 2)
        self.assertEqual(report["coverage"]["primary_cells"]["failed_or_ambiguous"], 1)
        self.assertEqual(report["status_counts"], {"failed": 1, "successful": 1})
        self.assertEqual(report["tables"]["cost"][0]["observed_total_usd"], 3.2)

    def test_zero_invalid_opportunities_are_undefined_with_denominators_retained(self):
        plan = example_plan()
        row = example_attempt(plan)
        row["metrics"].update(oracle_invalid_presented=0, oracle_invalid_incorporations=0)
        report = analyze_registry(plan, [row])
        target = report["tables"]["governance"][0]
        self.assertEqual(target["invalid_presented"], 0)
        self.assertIsNone(target["invalid_rate"])

    def test_mismatched_plan_and_duplicate_attempts_are_rejected(self):
        plan = example_plan()
        row = example_attempt(plan)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            analyze_registry(plan, [row, row])
        row["equivalence_hash"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "configuration"):
            analyze_registry(plan, [row])

    def test_release_reproduces_tables_and_does_not_claim_phase_completion(self):
        plan = example_plan()
        attempts = [example_attempt(plan)]
        report = analyze_registry(plan, attempts)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, second = root / "release", root / "reproduced"
            (root / "src").mkdir()
            (root / "src/synthetic.py").write_bytes(b"# synthetic source fixture\n")
            manifest = create_release(plan, attempts, first, source_root=root)
            write_analysis(analyze_registry(json.loads((first / "locked_plan.json").read_text()), json.loads((first / "aggregate_attempts.json").read_text())), second)
            self.assertEqual((first / "governance.csv").read_bytes(), (second / "governance.csv").read_bytes())
            self.assertFalse(manifest["all_phases_complete"])
            self.assertFalse(manifest["raw_clinical_data_included"])
            self.assertIn("claim_evidence_matrix.csv", manifest["files_sha256"])
            with self.assertRaisesRegex(ValueError, "new_or_empty"):
                create_release(plan, attempts, first)


if __name__ == "__main__":
    unittest.main()
