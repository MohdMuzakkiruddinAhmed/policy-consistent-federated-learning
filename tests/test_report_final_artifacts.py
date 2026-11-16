"""Hermetic synthetic reporting fixtures; never real P8 acceptance/evaluation."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

from pcfl.analysis import analyze_registry
from pcfl.experiments import append_attempt, file_digest, freeze_plan
from test_experiments import example_attempt, example_plan, synthetic_gate_refs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from report_final_artifacts import generate, json_write


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        (self.root / "src/synthetic.py").write_bytes(b"# synthetic source fixture\n")
        candidate = example_plan(frozen_training=True)
        self.plan = freeze_plan(candidate, synthetic_gate_refs(candidate, self.root), self.root)
        self.plan_path, self.ledger, self.analysis_path = [self.root / name for name in ("plan.json", "attempts.jsonl", "analysis.json")]
        json_write(self.plan_path, self.plan)
        self.ledger.touch()
        self.attempts = []
        self.refresh()

    def refresh(self):
        json_write(self.analysis_path, analyze_registry(self.plan, self.attempts))

    def add(self, cell=None, identity="attempt-1", status="successful"):
        row = example_attempt(self.plan, cell, identity=identity, status=status)
        row["execution"]["namespace"] = "run-" + identity
        append_attempt(self.ledger, self.plan, row)
        self.attempts.append(row)
        self.refresh()
        return row

    def run_report(self, *, output=None, **kwargs):
        return generate(self.plan_path, self.ledger, self.analysis_path, output or self.root / "output", evidence_root=self.root, **kwargs)

    def evidence(self, report, *, category="validation", alias="proof"):
        path = self.root / (alias + ".json")
        json_write(path, report)
        spec = {"category": category, "path": path.name, "sha256": file_digest(path)}
        index = self.root / "index.json"
        json_write(index, {"schema_version": "0.1.0", "kind": "reporting-evidence-index",
            "plan_digest": self.plan["plan_digest"], "reports": {alias: spec}})
        return index, path

    def figures(self):
        folder = self.root / "figures"
        folder.mkdir()
        artifact = folder / "invalid_incorporation_by_scenario.svg"
        artifact.write_text("<svg/>\n")
        aggregate = self.root / "aggregate_attempts.json"
        json_write(aggregate, self.attempts)
        manifest = folder / "figures_manifest.json"
        json_write(manifest, {"schema_version": "0.1.0", "kind": "reproducible-descriptive-research-figures",
            "plan_digest": self.plan["plan_digest"], "all_attempts_retained": len(self.attempts),
            "files": [{"path": artifact.name, "sha256": file_digest(artifact)}],
            "input_sha256": {"plan": file_digest(self.plan_path), "analysis": file_digest(self.analysis_path), "attempts": file_digest(aggregate)}})
        return manifest, aggregate, artifact

    def test_incomplete_accepted_synthetic_study_retains_failures_and_required_named_drafts(self):
        cell = next(cell for cell in self.plan["targeted_cells"] if cell["scenario_id"] == "S4")
        self.add(cell, "failed", "failed")
        self.add(cell, "retry")
        manifest = self.run_report()
        self.assertTrue(manifest["successful"])
        self.assertFalse(manifest["all_phases_complete"])
        self.assertEqual(manifest["attempt_count"], 2)
        self.assertIn("H4-inconclusive", manifest["pending"])
        self.assertIn("bound-cost-evidence", manifest["pending"])
        for name in ("results", "limitations", "design_principles", "validation_findings", "final_validation"):
            self.assertTrue((self.root / "output/reports" / (name + ".md")).is_file())
        claims = json.loads((self.root / "output/claim_evidence_matrix.json").read_text())
        self.assertTrue(any(row["RQ"] == "RQ1" for row in claims))
        self.assertTrue(all(row["verdict"] == "inconclusive" for row in claims if row["hypothesis"]))
        rows = json.loads((self.root / "output/supplements/targeted_attempts.json").read_text())["rows"]
        self.assertEqual([row["status"] for row in rows], ["failed", "successful"])
        self.assertTrue(all(not row["eligible_clean_cell"] for row in rows))
        self.assertIn("run-failed", (self.root / "output/supplements/targeted_attempts.csv").read_text())
        with self.assertRaisesRegex(ValueError, "new_or_empty"):
            self.run_report()

    def test_candidate_plan_is_rejected_before_output_creation(self):
        json_write(self.plan_path, example_plan(frozen_training=True))
        with self.assertRaisesRegex(ValueError, "accepted_frozen"):
            self.run_report()
        self.assertFalse((self.root / "output").exists())

    def test_stale_analysis_and_tampered_ledger_are_rejected(self):
        self.add()
        report = json.loads(self.analysis_path.read_text())
        report["hypotheses"]["H4"]["verdict"] = "supported"
        json_write(self.analysis_path, report)
        with self.assertRaisesRegex(ValueError, "exact_reproduction"):
            self.run_report()
        self.refresh()
        self.ledger.write_text(self.ledger.read_text().replace('"status":"successful"', '"status":"failed"'))
        with self.assertRaisesRegex(ValueError, "chain_broken"):
            self.run_report()
        self.assertFalse((self.root / "output").exists())

    def test_frozen_source_or_gate_leaf_change_is_not_accepted(self):
        source = self.root / "src/synthetic.py"
        source.write_text("# changed source\n")
        with self.assertRaisesRegex(ValueError, "source_changed"):
            self.run_report()
        source.write_bytes(b"# synthetic source fixture\n")
        (self.root / "synthetic-proof.json").write_text('{"successful":false}')
        with self.assertRaises(ValueError):
            self.run_report()

    def test_exact_figures_bind_plan_analysis_attempts_and_actual_file_bytes(self):
        self.add()
        manifest, aggregate, artifact = self.figures()
        result = self.run_report(figure_manifest=manifest, figure_attempts=aggregate)
        self.assertEqual(result["figures"][0]["figure_id"], "invalid_incorporation_by_scenario")
        artifact.write_text("<svg>changed</svg>")
        with self.assertRaisesRegex(ValueError, "figure_artifact_digest_changed"):
            self.run_report(output=self.root / "changed", figure_manifest=manifest, figure_attempts=aggregate)
        json_write(aggregate, [])
        with self.assertRaisesRegex(ValueError, "aggregate_attempts_mismatch"):
            self.run_report(output=self.root / "mismatch", figure_manifest=manifest, figure_attempts=aggregate)

    def test_reference_hash_plan_and_path_binding_fail_closed(self):
        index, proof = self.evidence({"kind": "synthetic-mechanism", "successful": True})
        proof.write_text('{"kind":"changed"}')
        with self.assertRaisesRegex(ValueError, "digest_changed"):
            self.run_report(evidence_index=index)
        index, _ = self.evidence({"kind": "synthetic-mechanism", "plan_digest": "0" * 64})
        with self.assertRaisesRegex(ValueError, "plan_binding"):
            self.run_report(evidence_index=index)
        content = json.loads(index.read_text())
        content["reports"]["proof"]["path"] = "../outside.json"
        json_write(index, content)
        with self.assertRaisesRegex(ValueError, "relative_owned"):
            self.run_report(evidence_index=index)

    def test_run_cost_is_raw_digest_bound_and_explicitly_inferred(self):
        attempt = self.add()
        row = {"cell_id": attempt["cell_id"], "raw_result": {"sha256": attempt["evidence"]["raw_result_sha256"]},
            "timing_status": "observed", "cost_usd": {"measurement": "inferred-allocation", "direct_compute": .1,
                "allocated_shared_experimental_allowance": .2, "planning_upper_allocation": .3,
                "per_published_round_planning_upper": .06}, "resources": {"vcpu_seconds": 100, "memory_gib_seconds": 400}}
        report = {"kind": "retained-run-priced-usage-allocation", "actual_invoice": False, "successful": True, "runs": [row]}
        index, _ = self.evidence(report, category="cost")
        manifest = self.run_report(evidence_index=index)
        self.assertNotIn("bound-cost-evidence", manifest["pending"])
        costs = json.loads((self.root / "output/supplements/run_cost_allocations.json").read_text())
        self.assertFalse(costs["actual_invoice"])
        self.assertFalse(costs["cpu_utilization_measured"])
        self.assertEqual(costs["runs"][0]["attempt_id"], attempt["attempt_id"])
        report["runs"][0]["raw_result"]["sha256"] = "0" * 64
        index, _ = self.evidence(report, category="cost")
        with self.assertRaisesRegex(ValueError, "not_bound_to_retained"):
            self.run_report(output=self.root / "bad-cost", evidence_index=index)

    def test_unknown_cost_measurement_or_negative_reservation_cannot_be_reported(self):
        attempt = self.add()
        report = {"kind": "retained-run-priced-usage-allocation", "actual_invoice": False, "runs": [{
            "cell_id": attempt["cell_id"], "raw_result": {"sha256": attempt["evidence"]["raw_result_sha256"]},
            "resources": {"cpu_seconds": 1}}]}
        index, _ = self.evidence(report, category="cost")
        with self.assertRaisesRegex(ValueError, "reserved_resource_inference"):
            self.run_report(evidence_index=index)

    def test_synthetic_successes_are_explicit_descriptives_never_clinical_claims(self):
        cell = next(row for row in self.plan["primary_cells"] if row["baseline_id"] == "P1" and row["scenario_id"] == "S2")
        self.add(cell)
        manifest = self.run_report()
        claims = json.loads((self.root / "output/claim_evidence_matrix.json").read_text())
        h1 = next(row for row in claims if row["hypothesis"] == "H1")
        self.assertEqual(h1["data_kind_counts"], {"synthetic_test": 1})
        self.assertFalse(h1["clinical_confirmatory_claim_permitted"])
        self.assertEqual(h1["clinical_eligible_attempt_ids"], [])
        self.assertEqual(h1["verdict"], "inconclusive")
        self.assertFalse(manifest["clinical_confirmatory_verdict_permitted"])
        rows = json.loads((self.root / "output/tables/family_descriptives.json").read_text())["rows"]
        self.assertEqual(rows[0]["data_kind"], "synthetic_test")
        self.assertEqual(rows[0]["clinical_eligible_attempts"], 0)
        self.assertIsNone(rows[0]["confidence_interval"])
        self.assertIn("Synthetic mechanism observations remain synthetic", (self.root / "output/reports/results.md").read_text())
        rq1 = json.loads((self.root / "output/tables/rq1_protocol_evidence.json").read_text())
        self.assertEqual({row["scenario_id"] for row in rq1}, {"S" + str(number) for number in range(9)})

    def test_h2_stratum_run_ids_match_actual_nonzero_denominator_paired_seed_sample(self):
        for baseline in ("P1", "B2"):
            cell = next(row for row in self.plan["primary_cells"] if row["baseline_id"] == baseline
                        and row["scenario_id"] == "S1" and row["distribution"] == "iid" and row["seed"] == 296)
            row = example_attempt(self.plan, cell, identity="pair-" + baseline)
            row["execution"]["namespace"] = "run-pair-" + baseline
            if baseline == "P1": row["metrics"].update(oracle_invalid_presented=0, oracle_invalid_incorporations=0)
            append_attempt(self.ledger, self.plan, row)
            self.attempts.append(row)
        self.refresh()
        self.run_report()
        claims = json.loads((self.root / "output/claim_evidence_matrix.json").read_text())
        row = next(row for row in claims if row["component"] == "paired-baseline-comparison:P1-B2:iid-S1")
        self.assertEqual(row["statistical_seed_ids"], [])
        self.assertEqual(row["run_ids"], [])
        self.assertEqual(set(row["retained_run_ids"]), {"run-pair-P1", "run-pair-B2"})
        self.assertEqual(set(row["not_used_in_statistical_sample_attempt_ids"]), {"pair-P1", "pair-B2"})
        self.assertIsNone(row["effect_estimate"])
        self.assertIsNone(row["confidence_interval_95"])

    def test_all_claim_table_and_copied_figure_links_exist_and_manifest_hashes_reproduce(self):
        self.add()
        manifest, aggregate, artifact = self.figures()
        first = self.run_report(figure_manifest=manifest, figure_attempts=aggregate)
        second = self.run_report(output=self.root / "reproduced", figure_manifest=manifest, figure_attempts=aggregate)
        self.assertEqual(first, second)
        output = self.root / "output"
        self.assertEqual((output / "figures" / artifact.name).read_bytes(), artifact.read_bytes())
        claims = json.loads((output / "claim_evidence_matrix.json").read_text())
        for claim in claims:
            for link in claim["table_links"] + claim["figure_links"]:
                path = output / link["path"]
                self.assertTrue(path.is_file(), link)
                if "sha256" in link: self.assertEqual(file_digest(path), link["sha256"])
        for name, expected in first["files_sha256"].items():
            self.assertEqual(file_digest(output / name), expected)
            self.assertEqual((output / name).read_bytes(), (self.root / "reproduced" / name).read_bytes())
        self.assertIn("claim-linked-figures-incomplete", first["pending"])
        self.assertEqual(first["ledger_chain"]["records"], 1)

    def test_ambiguous_repeated_attempt_raw_cost_binding_cannot_silently_choose_one(self):
        row = self.add(identity="original")
        self.add(identity="repeated")
        report = {"kind": "retained-run-priced-usage-allocation", "actual_invoice": False, "runs": [{
            "cell_id": row["cell_id"], "raw_result": {"sha256": row["evidence"]["raw_result_sha256"]},
            "cost_usd": None, "resources": None}]}
        index, _ = self.evidence(report, category="cost")
        with self.assertRaisesRegex(ValueError, "ambiguous_retained_attempt"):
            self.run_report(evidence_index=index)
        self.assertFalse((self.root / "output").exists())

    def test_partial_cost_and_unexecuted_exploratory_evidence_stay_pending_null(self):
        attempt = self.add()
        report = {"kind": "retained-run-priced-usage-allocation", "actual_invoice": False, "successful": False,
            "task_window_coverage_complete": False, "runs": [{"cell_id": attempt["cell_id"],
                "raw_result": {"sha256": attempt["evidence"]["raw_result_sha256"]},
                "timing_status": "missing-or-invalid", "cost_usd": None, "resources": None}]}
        index, _ = self.evidence(report, category="cost", alias="partial-cost")
        content = json.loads(index.read_text())
        exploratory = self.root / "exploratory.json"
        json_write(exploratory, {"kind": "exploratory_robustness_validation", "registered_primary_case": False, "successful": False})
        content["reports"]["exploratory"] = {"category": "exploratory", "path": exploratory.name, "sha256": file_digest(exploratory)}
        json_write(index, content)
        manifest = self.run_report(evidence_index=index)
        self.assertIn("run-cost-partial-or-pending-source-coverage", manifest["pending"])
        self.assertIn("run-cost-unaccounted-attempts", manifest["pending"])
        self.assertIn("exploratory-normalized-summaries-and-interpretation", manifest["pending"])
        costs = json.loads((self.root / "output/supplements/run_cost_allocations.json").read_text())
        self.assertIsNone(costs["runs"][0]["cost_usd"])
        self.assertIsNone(costs["runs"][0]["resources"])
        self.assertFalse(costs["complete_seven_component_run_cost_ledger"])
        self.assertEqual(costs["runs"][0]["allocation_status"], "pending-or-partial-supplied-scope")
        extra = json.loads((self.root / "output/supplements/exploratory_evidence.json").read_text())
        self.assertIsNone(extra["effect"])
        self.assertIsNone(extra["confidence_interval"])

    def test_failed_family_descriptives_preserve_missing_counters_and_utility_as_null(self):
        cell = self.plan["ablation_cells"][0]
        row = example_attempt(self.plan, cell, identity="failed-ablation", status="failed")
        del row["metrics"]["oracle_invalid_presented"]
        del row["metrics"]["auroc"]
        append_attempt(self.ledger, self.plan, row)
        self.attempts.append(row)
        self.refresh()
        self.run_report()
        groups = json.loads((self.root / "output/tables/family_descriptives.json").read_text())["rows"]
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(group["family"], "ablation")
        self.assertEqual(group["status_counts"], {"failed": 1})
        self.assertEqual(group["counts"]["oracle_invalid_presented"], {"sum": None, "observed_attempts": 0, "missing_attempts": 1})
        self.assertIsNone(group["utility_descriptives"]["auroc"]["mean"])
        self.assertEqual(group["utility_descriptives"]["auroc"]["missing_attempts"], 1)
        self.assertEqual(group["clean_successful_attempts"], 0)
        self.assertIsNone(group["effect"])
        self.assertIsNone(group["confidence_interval"])


if __name__ == "__main__":
    unittest.main()
