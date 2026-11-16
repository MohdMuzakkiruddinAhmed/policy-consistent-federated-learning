"""Metadata-only pilot selection tests; no AWS, training, row or test access."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "scripts/prepare_campaign.py").is_file())
STAGE = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests"), str(ROOT / "src")]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.ROOT = ROOT
    return module


candidate_path = STAGE / "prepare_campaign.py"
module = load("staged_safety_preparer", candidate_path if candidate_path.is_file() else ROOT / "scripts/prepare_campaign.py")
original_path = STAGE / "original_prepare_campaign.py"
original = load("original_safety_preparer", original_path if original_path.is_file() else ROOT / "scripts/prepare_campaign.py")


def arguments():
    return ({"campaign_id": "synthetic-master", "application_campaign_id": "synthetic-safety-application"},
        {"state_table_name": "synthetic-state", "bucket_name": "synthetic-bucket"},
        {"service_endpoints": {"opa": "https://opa.invalid", "evaluation": "https://evaluation.invalid"}},
        {"model_schema_hash": "a" * 64}, {"evaluation/frozen/validation.csv": {"sha256": "b" * 64}})


class SafetyAuditPilotTests(unittest.TestCase):
    def test_both_distributions_append_one_seed593_audit_fault_and_preserve_original_five_cases(self):
        for distribution in ("iid", "non_iid"):
            with self.subTest(distribution=distribution):
                before = original.runtime_cases(*arguments(), distribution=distribution, stage="safety-pilot")
                after = module.runtime_cases(*arguments(), distribution=distribution, stage="safety-pilot")
                self.assertEqual(len(after), 6)
                # In the staged delivery this compares exact original metadata,
                # IDs, run IDs, training, restart instructions and fault choice.
                if len(before) == 5: self.assertEqual(after[:5], before)
                self.assertEqual([(case["runtime"]["scenario_id"], case["runtime"]["seed"]) for case in after[:5]],
                    [("S4", 296), ("S5", 296), ("S6", 296), ("S7", 296), ("S8", 296)])
                extra = after[-1]
                self.assertEqual(extra["cell_id"], f"safety-pilot-{distribution}-P1-S8-593")
                self.assertEqual(extra["runtime"]["baseline_id"], "P1")
                self.assertEqual(extra["runtime"]["seed"], 593)
                self.assertEqual(extra["runtime"]["scripted_fault"], "audit_transport_unavailable")
                self.assertEqual(after[4]["runtime"]["scripted_fault"], "opa_transport_unavailable")
                self.assertEqual(len({case["cell_id"] for case in after}), 6)
                self.assertEqual(len({case["runtime"]["persistent_run_id"] for case in after}), 6)
                self.assertTrue(all("final_holdout" not in case["runtime"] for case in after))

    def test_pilot_forecast_is_32_training_plus_12_safety_with_unchanged_full_budget(self):
        training, safety = [], []
        prescribed = json.loads((ROOT / "configs/experiments_training.json").read_text())
        for distribution in ("iid", "non_iid"):
            training += module.runtime_cases(*arguments(), distribution=distribution, stage="training-pilot")
            safety += module.runtime_cases(*arguments(), distribution=distribution, stage="safety-pilot")
        self.assertEqual((len(training), len(safety), len(training) + len(safety)), (32, 12, 44))
        self.assertTrue(all(case["runtime"]["rounds"] == prescribed["num_rounds"] == 5 for case in safety))
        self.assertTrue(all(case["runtime"]["training"] == prescribed for case in safety))
        self.assertTrue(all(case["runtime"]["max_examples_per_client"] == prescribed["max_examples_per_client"] for case in safety))
        self.assertTrue(all(case["runtime"]["validation_max_examples"] == prescribed["max_validation_examples"] for case in safety))
        self.assertEqual({case["runtime"]["scripted_fault"] for case in safety if case["runtime"]["scenario_id"] == "S8"},
            {"audit_transport_unavailable", "opa_transport_unavailable"})

    def test_connectivity_training_and_registered_families_are_unchanged(self):
        from test_experiments import example_plan
        from pcfl.experiments import GATES, digest
        plan = example_plan(frozen_training=True)
        plan.update(status="accepted_frozen", confirmatory_execution_enabled=True,
            acceptance={"gates": {name: {"passed": True, "sha256": "c" * 64} for name in GATES}})
        plan["plan_digest"] = digest({key: value for key, value in plan.items() if key != "plan_digest"})
        for stage in ("connectivity", "training-pilot", "primary", "targeted", "ablation", "replication"):
            for distribution in ("iid", "non_iid"):
                with self.subTest(stage=stage, distribution=distribution):
                    options = {"plan": plan} if stage in {"primary", "targeted", "ablation", "replication"} else {}
                    before = original.runtime_cases(*arguments(), distribution=distribution, stage=stage, **options)
                    after = module.runtime_cases(*arguments(), distribution=distribution, stage=stage, **options)
                    self.assertEqual(after, before)
                    expected = {"connectivity": 1, "training-pilot": 16, "primary": 80, "targeted": 25, "ablation": 20, "replication": 4}
                    self.assertEqual(len(after), expected[stage])
                    if options:
                        planned = {cell["cell_id"]: cell for cell in plan[stage + "_cells"] if cell["distribution"] == distribution}
                        self.assertEqual({row["cell_id"] for row in after}, set(planned))
                        for row in after:
                            self.assertEqual(row["runtime"]["seed"], planned[row["cell_id"]]["seed"])
                            self.assertEqual(row["runtime"]["equivalence_hash"], planned[row["cell_id"]]["equivalence_hash"])


if __name__ == "__main__": unittest.main()
