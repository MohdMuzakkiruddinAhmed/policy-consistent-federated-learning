"""Synthetic provenance, real-byte ingestion and fail-closed gate tests."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from pcfl.analysis import analyze_registry
from pcfl.experiments import (COUNT_METRICS, append_attempt, build_plan, derive_verified_metrics,
    digest, file_digest, freeze_plan, load_attempts, registered_runtime_matches, frozen_runtime_image_matches,
    scientific_binding, scientific_sources, scientific_training, validate_gate_report)
from test_experiments import example_attempt, example_plan, synthetic_gate_refs
from test_runtime_verify import persistent_fixture

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from accept_experiments import assess_acceptance
from ingest_experiments import ingest_cloud


def registered_fixture(plan, cell, producer_scenario):
    """Prepared configuration and separately constructed producer-shaped output."""
    shared = cell["shared_config"]
    runtime = {key: cell[key] for key in ("cell_id", "match_id", "equivalence_hash", "baseline_id", "scenario_id", "distribution", "seed")}
    runtime.update(plan_digest=plan["plan_digest"], training=shared["training"], rounds=shared["training"]["num_rounds"],
        max_examples_per_client=shared["training"]["max_examples_per_client"], validation_max_examples=shared["training"]["max_validation_examples"],
        validation_source_sha256=shared["validation_sha256"], scenario_target_org=shared["policy_schedule"]["target_org"],
        experiment_binding={"plan_digest": plan["plan_digest"], "cell_id": cell["cell_id"], "equivalence_hash": cell["equivalence_hash"],
            "family": cell["family"], "policy_schedule_hash": shared["policy_schedule_hash"], "source_sha256": plan["provenance"]["source_sha256"]})
    # Flower emits the normalized scenario name, not the prepared canonical ID.
    raw = {"schema_version": "0.1.0", "kind": "local_deployment_runtime_pilot", "successful": True,
        "baseline_id": cell["baseline_id"], "scenario_id": producer_scenario, "seed": cell["seed"],
        "plan_digest": plan["plan_digest"], "cell_id": cell["cell_id"], "match_id": cell["match_id"],
        "equivalence_hash": cell["equivalence_hash"], "distribution": cell["distribution"]}
    image = plan["provenance"]["image_digests"]["runtime"]
    inventory = {"account_id": "123456789012", "region": "us-east-1", "image": {"reference": image},
        "foundation": {"image_repositories": {"coordinator": image.split("@", 1)[0]}},
        "uploads": [{"sha256": value, "version_id": "immutable-v1"} for value in shared["partition_hashes"].values()]}
    return runtime, raw, inventory


class ScientificWorkflowTests(unittest.TestCase):
    def test_inventory_ignores_operational_reports_and_prose_but_binds_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("src/pcfl/learning.py", "scripts/plan_experiments.py", "containers/Dockerfile",
                         "containers/requirements-linux.lock", "policies/rego/data.json", "schemas/result.json",
                         "infra/cloud/main.tf", "configs/project.json", "containers/build_validation.json", "docs/status.md", "reports/status.json"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}")
            before = scientific_sources(root)
            self.assertIn("containers/Dockerfile", before)
            self.assertIn("containers/requirements-linux.lock", before)
            for name in ("configs/project.json", "containers/build_validation.json", "docs/status.md", "reports/status.json"):
                self.assertNotIn(name, before)
                (root / name).write_text('{"timestamp":"later"}')
            self.assertEqual(before, scientific_sources(root))
            (root / "src/pcfl/learning.py").write_text("changed")
            self.assertNotEqual(before, scientific_sources(root))

    def test_training_admin_flags_do_not_change_scientific_contract(self):
        first = example_plan(frozen_training=True)
        config, training = first["configuration"], deepcopy(first["training_candidate"])
        data = {"checks": {key: True for key in ("patient_disjoint_splits", "preprocessing_fit_training_only", "test_holdout_frozen")},
                "private_artifacts_sha256": {f"{d}/{o}.csv": h for c in first["primary_cells"] for d in [c["distribution"]] for o, h in c["shared_config"]["partition_hashes"].items()}}
        shared = first["primary_cells"][0]["shared_config"]
        data["private_artifacts_sha256"].update({"preprocessor.json": shared["preprocessor_sha256"], "test.csv": shared["test_holdout_sha256"], "validation.csv": shared["validation_sha256"]})
        first = build_plan(config, training, data, first["provenance"])
        training.update(acceptance_status="later-reviewed", confirmatory_frozen=False)
        data["scope"] = {"cloud_upload_performed": True}
        second = build_plan(config, training, data, first["provenance"])
        self.assertEqual(first["primary_cells"], second["primary_cells"])
        self.assertEqual(scientific_binding(first), scientific_binding(second))
        self.assertNotIn("acceptance_status", scientific_training(training))

    def test_acceptance_reads_same_candidate_and_rejects_underlying_evidence_tamper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "src/synthetic.py").write_bytes(b"# synthetic source fixture\n")
            plan = example_plan(frozen_training=True)
            plan["training_candidate"]["confirmatory_frozen"] = False
            plan["plan_digest"] = digest({key: value for key, value in plan.items() if key != "plan_digest"})
            refs = synthetic_gate_refs(plan, root)
            paths = {key: ref["path"] for key, ref in refs["gates"].items()}
            report, acceptance = assess_acceptance(plan, paths, root)
            self.assertTrue(report["successful"])
            accepted = freeze_plan(plan, acceptance, root)
            self.assertTrue(accepted["training_candidate"]["confirmatory_frozen"])
            self.assertFalse(plan["training_candidate"]["confirmatory_frozen"])
            report, acceptance = assess_acceptance(plan, {}, root)
            self.assertFalse(report["successful"])
            self.assertIsNone(acceptance)
            (root / "synthetic-proof.json").write_text('{"successful":true,"changed":true}')
            with self.assertRaisesRegex(ValueError, "underlying_evidence_digest"):
                freeze_plan(plan, refs, root)

    def test_missing_tamper_is_missing_and_explicit_no_tamper_is_observed_zero(self):
        with tempfile.TemporaryDirectory() as temp:
            raw = persistent_fixture(Path(temp))
            raw["selection"] = [{"org_id": row["org_id"], "selected": True} for row in raw["tasks"]]
            summary = {"successful": True, "audit_verified": True, "unique_presented_updates": 2,
                "oracle_invalid_presented": 0, "oracle_invalid_incorporations": 0, "oracle_valid_rejections": 0,
                "accepted_updates": 2, "final_decisions": 2, "published_models": 1}
            metrics, sources = derive_verified_metrics(raw, summary)
            self.assertNotIn("tamper_attempted", metrics)
            self.assertNotIn("cost_usd", metrics)
            self.assertEqual(metrics["oracle_valid_presented"], 2)
            raw["measurement_manifest"] = {"schema_version": "0.1.0", "tamper_scope": "this-runtime-invocation", "tamper_mode": "none_declared", "tamper_results": []}
            metrics, sources = derive_verified_metrics(raw, summary)
            self.assertEqual(metrics["tamper_attempted"], 0)
            self.assertEqual(COUNT_METRICS - set(metrics), set())
            raw["measurement_manifest"]["tamper_results"] = [{"attack_id": "attack-1", "detected": True}]
            with self.assertRaisesRegex(ValueError, "tamper"):
                derive_verified_metrics(raw, summary)

    def test_runtime_binding_rejects_smoke_budget_and_wrong_image(self):
        plan = example_plan()
        cell = plan["primary_cells"][0]
        shared = cell["shared_config"]
        runtime, raw, inventory = registered_fixture(plan, cell, "stable")
        self.assertTrue(registered_runtime_matches(plan, cell, runtime, raw, inventory))
        runtime["rounds"] = 1
        self.assertFalse(registered_runtime_matches(plan, cell, runtime, raw, inventory))
        runtime["rounds"] = shared["training"]["num_rounds"]
        inventory["image"]["reference"] = "wrong@sha256:" + "0" * 64
        self.assertFalse(registered_runtime_matches(plan, cell, runtime, raw, inventory))

    def test_all_nine_actual_producer_scenario_names_bind_to_canonical_cells(self):
        plan = example_plan()
        names = ("stable", "between_round", "mid_round", "delayed", "revoke_regrant", "expiry", "near_commit", "duplicate_restart", "transport_fault")
        cells = [*plan["primary_cells"], *plan["targeted_cells"]]
        for number, name in enumerate(names):
            cell = next(row for row in cells if row["scenario_id"] == f"S{number}" and row["baseline_id"] == "P1")
            runtime, raw, inventory = registered_fixture(plan, cell, name)
            with self.subTest(scenario=name):
                self.assertTrue(registered_runtime_matches(plan, cell, runtime, raw, inventory))
                runtime["scenario_id"] = name
                raw["scenario_id"] = f"S{number}"
                self.assertTrue(registered_runtime_matches(plan, cell, runtime, raw, inventory))
                raw["scenario_id"] = names[(number + 1) % 9]
                self.assertFalse(registered_runtime_matches(plan, cell, runtime, raw, inventory))
                raw["scenario_id"] = name
                raw["baseline_id"] = "B1"
                self.assertFalse(registered_runtime_matches(plan, cell, runtime, raw, inventory))

    def test_unknown_scenarios_and_mismatched_prepared_method_remain_excluded(self):
        plan = example_plan()
        cell = next(row for row in plan["primary_cells"] if row["scenario_id"] == "S2" and row["baseline_id"] == "P1")
        for unknown in (None, "midround", "S9", "MID_ROUND", 2):
            runtime, raw, inventory = registered_fixture(plan, cell, unknown)
            with self.subTest(unknown=unknown):
                self.assertFalse(registered_runtime_matches(plan, cell, runtime, raw, inventory))
        runtime, raw, inventory = registered_fixture(plan, cell, "mid_round")
        runtime["baseline_id"] = "B3"
        self.assertFalse(registered_runtime_matches(plan, cell, runtime, raw, inventory))

    def test_frozen_content_may_use_new_owned_replication_repository_only(self):
        plan = example_plan()
        runtime, raw, original = registered_fixture(plan, plan["primary_cells"][0], "stable")
        mirror = "123456789012.dkr.ecr.us-east-1.amazonaws.com/pcfl-fresh-replica/coordinator"
        inventory = deepcopy(original)
        inventory["foundation"]["image_repositories"] = {"coordinator": mirror}
        inventory["image"]["reference"] = mirror + "@sha256:" + "b" * 64
        self.assertNotEqual(inventory["image"]["reference"], plan["provenance"]["image_digests"]["runtime"])
        self.assertTrue(registered_runtime_matches(plan, plan["primary_cells"][0], runtime, raw, inventory))
        for invalid in (mirror + "@sha256:" + "0" * 64,
                        "123456789012.dkr.ecr.us-east-1.amazonaws.com/unrelated/coordinator@sha256:" + "b" * 64,
                        mirror.replace("123456789012", "999999999999") + "@sha256:" + "b" * 64,
                        mirror.replace("us-east-1", "us-west-2") + "@sha256:" + "b" * 64):
            changed = deepcopy(inventory)
            changed["image"]["reference"] = invalid
            with self.subTest(invalid=invalid):
                self.assertFalse(registered_runtime_matches(plan, plan["primary_cells"][0], runtime, raw, changed))
        foreign = deepcopy(inventory)
        foreign.update(account_id="999999999999")
        foreign["foundation"]["image_repositories"] = {"coordinator": mirror.replace("123456789012", "999999999999")}
        foreign["image"]["reference"] = foreign["foundation"]["image_repositories"]["coordinator"] + "@sha256:" + "b" * 64
        self.assertFalse(frozen_runtime_image_matches(plan, foreign))
        # An unrelated earlier pilot digest is not the frozen runtime content.
        plan["provenance"]["image_digests"]["pilot_runtime"] = mirror + "@sha256:" + "a" * 64
        inventory["image"]["reference"] = plan["provenance"]["image_digests"]["pilot_runtime"]
        self.assertFalse(frozen_runtime_image_matches(plan, inventory))

    def test_development_observation_never_fills_primary_matrix(self):
        plan, row = example_plan(), None
        row = example_attempt(plan, status="excluded")
        row.update(cell_id="connectivity-P1-S0-296", equivalence_hash=None)
        row["metrics"].pop("tamper_attempted")
        row["metrics"].pop("tamper_detected")
        row["observation"] = {"scope": "development", "baseline_id": "P1", "source_cell_id": row["cell_id"],
            "missing_metrics": ["tamper_attempted", "tamper_detected"], "exclusion_reasons": ["development-not-registered"], "measurement_sources": {}}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.jsonl"
            append_attempt(path, plan, row)
            report = analyze_registry(plan, load_attempts(path, plan))
        self.assertEqual(report["development_observations"], 1)
        self.assertEqual(report["coverage"]["primary_cells"]["unattempted"], 160)
        self.assertEqual(report["tables"]["cost"][-1]["attempts"], 1)
        self.assertFalse(report["confirmatory_verdict_permitted"])

    def test_explicit_empty_opa_trace_is_zero_calls_not_missing_instrumentation(self):
        plan = example_plan()
        row = example_attempt(plan)
        row["metrics"]["latency_ms"]["opa"] = []
        report = analyze_registry(plan, [row])
        value = next(value for value in report["tables"]["latency"] if value["baseline_id"] == row.get("baseline_id", "B1") and value["series"] == "opa")
        self.assertEqual(value["operation_samples"], 0)
        self.assertEqual(value["attempts_missing_series"], 0)
        self.assertIsNone(value["p50_ms"])

    def test_ingestion_reverifies_bytes_and_separates_corruption_from_execution_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root, cell_id, campaign_id = Path(temp), "development-P1-S0-296", "synthetic-campaign"
            directory = root / "r" / hashlib.sha256(cell_id.encode()).hexdigest()[:8]
            directory.mkdir(parents=True)
            raw = persistent_fixture(directory)
            raw["selection"] = [{"org_id": row["org_id"], "selected": True} for row in raw["tasks"]]
            (directory / "cell.json").write_text(json.dumps({"cell_id": cell_id}))
            path = directory / "runtime_result.json"
            path.write_text(json.dumps(raw))
            (directory / "artifact_paths.json").write_text(json.dumps({file_digest(value): value.relative_to(directory).as_posix() for value in directory.rglob("*.npz")}))
            artifact = {"bucket": "synthetic-bucket", "key": f"evidence/campaigns/{campaign_id}/{cell_id}/runtime_result.json",
                        "sha256": file_digest(path), "size_bytes": path.stat().st_size, "version_id": "immutable-synthetic-version"}
            index = {"campaign_id": campaign_id, "started_at_utc": "2026-01-01T00:00:00Z", "finished_at_utc": "2026-01-01T00:01:00Z",
                     "cases": [{"cell_id": cell_id, "successful": True, "artifacts": [artifact]}]}
            index_path = root / "r/campaign_result.json"
            index_path.write_text(json.dumps(index))
            inventory = {"campaign_id": campaign_id, "foundation": {"bucket_name": "synthetic-bucket"},
                         "export": {"index_sha256": file_digest(index_path),
                             "index_key": f"evidence/campaigns/{campaign_id}/campaign_result.json",
                             "index_version_id": "immutable-synthetic-index-version"}}
            inventory_path, campaign_path = root / "inventory.json", root / "campaign.json"
            inventory_path.write_text(json.dumps(inventory))
            campaign_path.write_text(json.dumps({"campaign_id": campaign_id, "cases": [{"cell_id": cell_id, "runtime": {"baseline_id": "P1"}}]}))
            ledger, output, plan = root / "ledger.jsonl", root / "ingestion-v1", example_plan()
            before = file_digest(path)
            with patch("ingest_experiments.validate_placement", return_value={"successful": False, "kind": "synthetic-test-only"}):
                report = ingest_cloud(plan, inventory_path, campaign_path, ledger, output)
                again = ingest_cloud(plan, inventory_path, campaign_path, ledger, output)
                self.assertEqual(report, again)
                self.assertEqual(len(load_attempts(ledger, plan)), 1)
                self.assertEqual(file_digest(path), before)
                self.assertEqual(load_attempts(ledger, plan)[0]["metrics"]["accepted_updates"], 2)
                self.assertEqual(load_attempts(ledger, plan)[0]["status"], "excluded")
                raw["current_model_digest"] = "0" * 64
                path.write_text(json.dumps(raw))
                ingest_cloud(plan, inventory_path, campaign_path, ledger, root / "ingestion-v2")
                raw["successful"] = False
                path.write_text(json.dumps(raw))
                artifact.update(sha256=file_digest(path), size_bytes=path.stat().st_size)
                index["cases"][0]["successful"] = False
                index_path.write_text(json.dumps(index))
                inventory["export"]["index_sha256"] = file_digest(index_path)
                inventory_path.write_text(json.dumps(inventory))
                ingest_cloud(plan, inventory_path, campaign_path, ledger, root / "ingestion-v3")
            rows = load_attempts(ledger, plan)
            self.assertEqual([row["status"] for row in rows], ["excluded", "excluded", "failed"])
            self.assertEqual(rows[1]["metrics"], {})
            self.assertIn("raw-result-integrity-failed", rows[1]["observation"]["exclusion_reasons"])


if __name__ == "__main__":
    unittest.main()
