"""Synthetic registry/accounting tests; no training or holdout access."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from pcfl.experiments import (COUNT_METRICS, GATES, GATE_CHECKS, append_attempt, build_plan, digest,
    file_digest, freeze_plan, load_attempts, scientific_binding, validate_attempt, validate_plan)

ROOT = Path(__file__).resolve().parents[1]


def example_plan(*, frozen_training=False):
    config = json.loads((ROOT / "configs/experiments.json").read_text())
    training = json.loads((ROOT / config["training_config"]).read_text())
    training.update(pilot_only=not frozen_training, confirmatory_frozen=frozen_training)
    hashes = {f"{distribution}/org_{number:02d}.csv": digest([distribution, number])
              for distribution in ("iid", "non_iid") for number in range(1, 9)}
    hashes.update({name: digest(name) for name in ("preprocessor.json", "test.csv", "validation.csv")})
    data = {"private_artifacts_sha256": hashes, "checks": {key: True for key in
            ("patient_disjoint_splits", "preprocessing_fit_training_only", "test_holdout_frozen")}}
    sources = {"src/synthetic.py": hashlib.sha256(b"# synthetic source fixture\n").hexdigest()}
    provenance = {"source_files_sha256": sources, "source_sha256": digest(sources), "git_commit": None,
                  "image_digests": {"runtime": "123456789012.dkr.ecr.us-east-1.amazonaws.com/pcfl-test/runtime@sha256:" + "b" * 64}}
    return build_plan(config, training, data, provenance)


def example_attempt(plan, cell=None, *, identity="attempt-1", status="successful"):
    cell = cell or plan["primary_cells"][0]
    metrics = {key: 0 for key in COUNT_METRICS}
    metrics.update(unique_presented_updates=8, oracle_invalid_presented=2, oracle_valid_presented=6,
                   oracle_invalid_incorporations=0 if cell["baseline_id"] == "P1" else 2,
                   accepted_updates=6 if cell["baseline_id"] == "P1" else 8, final_decisions=8,
                   audit_complete_decisions=8, audit_record_sets_tested=1, audit_record_sets_verified=1,
                   tamper_attempted=1, tamper_detected=1, selected_eligible_clients=8, accepted_clients=6,
                   published_models=5, evaluation_split="validation", data_kind="synthetic_test", threshold=0.5,
                   auroc=0.75, auprc=0.5, f1=0.5, precision=0.5, recall=0.5, prevalence=0.1,
                   latency_ms={"opa": [1, 2, 3], "round": [100, 200], "cold_start": [500]},
                   cost_usd={"compute": 1, "network": 0.1, "storage": 0.1, "logging": 0.1,
                             "api": 0.1, "idle": 0.1, "control": 0.1, "total": 1.6, "measurement": "inferred"})
    return {"attempt_id": identity, "cell_id": cell["cell_id"], "plan_digest": plan["plan_digest"],
        "equivalence_hash": cell["equivalence_hash"], "status": status, "reason_code": "synthetic-fixture",
        "started_at_utc": "2026-01-01T00:00:00Z", "finished_at_utc": "2026-01-01T00:01:00Z", "metrics": metrics,
        "evidence": {key: "c" * 64 for key in ("raw_result_sha256", "oracle_report_sha256", "audit_report_sha256", "topology_report_sha256")},
        "execution": {"deployment_id": "synthetic", "namespace": "synthetic", "task_definition_digest": "d" * 64,
                      "client_task_ids": [f"synthetic-task-{i}" for i in range(8)], "eight_separate_fargate_clients": False,
                      "final_holdout_authorized": False}}


def synthetic_gate_refs(candidate, root):
    """Test-only complete gate fixtures; never research evidence."""
    root = Path(root)
    proof = root / "synthetic-proof.json"
    proof.write_text(json.dumps({"successful": True, "kind": "synthetic-test-only"}))
    result = {"gates": {}}
    for key in GATES:
        gate = root / (key + ".json")
        gate.write_text(json.dumps({"kind": "scientific-gate-assessment", "successful": True,
            "gate_id": key, "candidate_plan_digest": candidate["plan_digest"],
            "scientific_binding": scientific_binding(candidate), "reviewer": "synthetic-test-fixture",
            "checks": {name: True for name in GATE_CHECKS[key]},
            "evidence": [{"path": proof.name, "sha256": file_digest(proof)}]}))
        result["gates"][key] = {"path": gate.name, "sha256": file_digest(gate), "passed": True}
    return result


class ExperimentPlanningTests(unittest.TestCase):
    def test_exact_160_matrix_and_full_paired_configuration_equivalence(self):
        first = example_plan()
        self.assertEqual(first, example_plan())
        self.assertEqual(len(first["primary_cells"]), 160)
        self.assertEqual(len(first["targeted_cells"]), 50)
        self.assertEqual(len(first["ablation_cells"]), 40)
        self.assertEqual(len(first["replication_cells"]), 8)
        self.assertFalse(first["confirmatory_execution_enabled"])
        matches = {}
        for cell in first["primary_cells"]:
            matches.setdefault(cell["match_id"], set()).add(cell["equivalence_hash"])
            self.assertEqual(cell["shared_config"]["initialization_seed"], cell["seed"])
        self.assertEqual(len(matches), 40)
        self.assertTrue(all(len(hashes) == 1 for hashes in matches.values()))

    def test_coherently_resigned_different_partition_breaks_manifest_equivalence(self):
        plan = example_plan()
        cell = plan["primary_cells"][0]
        cell["shared_config"]["partition_hashes"]["org_01"] = "0" * 64
        cell["equivalence_hash"] = digest(cell["shared_config"])
        cell["cell_id"] = "primary-" + digest({key: value for key, value in cell.items() if key != "cell_id"})[:24]
        plan["plan_digest"] = digest({key: value for key, value in plan.items() if key != "plan_digest"})
        with self.assertRaisesRegex(ValueError, "equivalence"):
            validate_plan(plan)

    def test_freeze_requires_all_gate_hashes_and_already_frozen_training(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src/synthetic.py").write_bytes(b"# synthetic source fixture\n")
            plan = example_plan()
            accepted_candidate = example_plan(frozen_training=True)
            acceptance = synthetic_gate_refs(plan, root)
            with self.assertRaisesRegex(ValueError, "frozen_training"):
                freeze_plan(plan, acceptance, root)
            acceptance = synthetic_gate_refs(accepted_candidate, root)
            frozen = freeze_plan(accepted_candidate, acceptance, root)
            self.assertEqual(frozen["status"], "accepted_frozen")
            self.assertFalse(frozen["final_test_access_permitted"])
            gate = root / (next(iter(GATES)) + ".json")
            gate.write_text('{"successful":false}')
            with self.assertRaisesRegex(ValueError, "digest"):
                freeze_plan(accepted_candidate, acceptance, root)

    def test_ledger_keeps_failure_then_retry_and_detects_rewrite(self):
        plan = example_plan()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "attempts.jsonl"
            append_attempt(path, plan, example_attempt(plan, status="failed"))
            append_attempt(path, plan, example_attempt(plan, identity="attempt-2"))
            self.assertEqual([row["status"] for row in load_attempts(path, plan)], ["failed", "successful"])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                append_attempt(path, plan, example_attempt(plan))
            content = path.read_text().replace('"status":"failed"', '"status":"aborted"')
            path.write_text(content)
            with self.assertRaisesRegex(ValueError, "chain_broken"):
                load_attempts(path, plan)

    def test_attempt_rejects_holdout_before_freeze_records_and_cost_omissions(self):
        plan = example_plan()
        row = example_attempt(plan)
        row["metrics"]["evaluation_split"] = "test"
        with self.assertRaisesRegex(ValueError, "holdout"):
            validate_attempt(plan, row)
        row = example_attempt(plan)
        row["metrics"]["patient_records"] = []
        with self.assertRaisesRegex(ValueError, "private_payload"):
            validate_attempt(plan, row)
        row = example_attempt(plan)
        row["metrics"]["cost_usd"].pop("idle")
        with self.assertRaisesRegex(ValueError, "cost"):
            validate_attempt(plan, row)


if __name__ == "__main__":
    unittest.main()
