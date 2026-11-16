import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
spec = importlib.util.spec_from_file_location("prepare_cloud_campaign", ROOT / "scripts/prepare_campaign.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CampaignPreparationTests(unittest.TestCase):
    def case_arguments(self):
        return ({"campaign_id": "master", "application_campaign_id": "app"},
                {"state_table_name": "synthetic-state", "bucket_name": "synthetic-bucket"},
                {"service_endpoints": {"opa": "https://opa.invalid", "evaluation": "https://eval.invalid"}},
                {"model_schema_hash": "a" * 64}, {"evaluation/frozen/validation.csv": {"sha256": "b" * 64}})

    def test_training_pilot_keeps_test_locked_and_matches_prescribed_full_data_training(self):
        cases = module.runtime_cases(*self.case_arguments(), distribution="iid", stage="training-pilot")
        self.assertEqual(len(cases), 16)
        self.assertEqual({case["runtime"]["baseline_id"] for case in cases}, {"B1", "B2", "B3", "P1"})
        self.assertEqual({case["runtime"]["scenario_id"] for case in cases}, {"S0", "S1", "S2", "S3"})
        self.assertTrue(all(case["runtime"]["rounds"] == 5 for case in cases))
        self.assertTrue(all(case["runtime"]["max_examples_per_client"] == 100000 for case in cases))
        self.assertTrue(all("final_holdout" not in case["runtime"] for case in cases))
        self.assertEqual(len({case["runtime"]["persistent_run_id"] for case in cases}), 16)

    def test_registered_preparation_requires_acceptance_and_uses_each_seeded_target(self):
        from test_experiments import example_plan
        from pcfl.experiments import digest, GATES
        plan = example_plan(frozen_training=True)
        with self.assertRaisesRegex(ValueError, "accepted_plan"):
            module.runtime_cases(*self.case_arguments(), distribution="iid", stage="primary", plan=plan)
        plan.update(status="accepted_frozen", confirmatory_execution_enabled=True,
                    acceptance={"gates": {gate: {"passed": True, "sha256": "c" * 64} for gate in GATES}})
        plan["plan_digest"] = digest({key: value for key, value in plan.items() if key != "plan_digest"})
        cases = module.runtime_cases(*self.case_arguments(), distribution="non_iid", stage="primary", plan=plan)
        self.assertEqual(len(cases), 80)
        records = {cell["cell_id"]: cell for cell in plan["primary_cells"]}
        for case in cases:
            source = records[case["cell_id"]]
            self.assertEqual(case["runtime"]["scenario_target_org"], source["shared_config"]["policy_schedule"]["target_org"])
            self.assertEqual(case["runtime"]["seed"], source["seed"])
            self.assertEqual(case["equivalence_hash"], source["equivalence_hash"])
            self.assertEqual(case["runtime"]["experiment_binding"]["source_sha256"], plan["provenance"]["source_sha256"])
        ablations = module.runtime_cases(*self.case_arguments(), distribution="iid", stage="ablation", plan=plan)
        self.assertEqual(len(ablations), 20)
        self.assertTrue(all(case["runtime"]["authority_backend"] == "dynamodb-s3-ablation" for case in ablations))
        self.assertTrue(all("final_holdout" not in case["runtime"] for case in ablations))
        from collections import Counter
        positions = Counter()
        for distribution in ("iid", "non_iid"):
            ordered = module.runtime_cases(*self.case_arguments(), distribution=distribution, stage="primary", plan=plan)
            for index, case in enumerate(ordered):
                positions[case["runtime"]["baseline_id"], index % 4] += 1
        self.assertEqual(set(positions.values()), {10})

    def test_initial_preparation_preserves_old_budget_and_creates_no_live_flags_or_secret_values(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "configs").mkdir()
            (workspace / "data_manifests").mkdir()
            data = workspace / "data/processed/uci296-v0.1.0-seed296"
            data.mkdir(parents=True)
            files = {"preprocessor.json": b"synthetic-only", "validation.csv": b"synthetic-validation", "test.csv": b"synthetic-held-out-bytes"}
            files.update({f"{distribution}/org_{i:02d}.csv": b"synthetic-client" for distribution in ("iid", "non_iid") for i in range(1, 9)})
            hashes = {}
            for name, content in files.items():
                path = data / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                hashes[name] = hashlib.sha256(content).hexdigest()
            (workspace / "data_manifests/dataset.json").write_text(json.dumps({"private_artifacts_sha256": hashes}))
            (workspace / "configs/aws_campaign_authorization.json").write_text(json.dumps({"approved": True, "approved_total_usd": 20,
                "account_id": "123456789012", "region": "us-east-1", "authorization_scope": "remaining-phases-cloud-campaign-including-replication"}))
            for filename in ("reports/runtime_infrastructure_validation.json", "containers/build_validation.json", "reports/service_container_validation.json"):
                path = workspace / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"successful":true}')
            request_dir = workspace / "private-campaign"
            with patch.object(module, "ROOT", workspace):
                request_path = module.initial_request(request_dir)
            request = json.loads(Path(request_path).read_text())
            self.assertEqual(len(request["data_uploads"]), 34)
            self.assertFalse(request["final_test_evaluation_permitted"])
            self.assertEqual(request["secrets"], [])
            variables = json.loads(Path(request["foundation_vars"]).read_text())
            self.assertFalse(variables["resource_creation_enabled"])
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", Path(request_path).read_text())
            self.assertTrue(request["project_id"].startswith("pcfl-r2-"))
            (data / "iid/org_01.csv").write_bytes(b"changed")
            with patch.object(module, "ROOT", workspace), self.assertRaises(ValueError):
                module.initial_request(workspace / "other-campaign")


if __name__ == "__main__":
    unittest.main()
