"""Operator scope tests use public synthetic manifests and never open data."""

from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from pcfl.experiments import digest, GATES
from test_experiments import example_plan
from test_prepare_campaign import module as prepare

spec = importlib.util.spec_from_file_location("operator_holdout_scope", ROOT / "scripts/authorize_holdout.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OperatorScopeTests(unittest.TestCase):
    def fixture(self):
        plan = example_plan(frozen_training=True)
        plan.update(status="accepted_frozen", confirmatory_execution_enabled=True,
                    acceptance={"gates": {gate: {"passed": True, "sha256": "c" * 64} for gate in GATES}})
        plan["plan_digest"] = digest({key: value for key, value in plan.items() if key != "plan_digest"})
        schema = "a" * 64
        cases = prepare.runtime_cases({"campaign_id": "master", "application_campaign_id": "app"},
            {"state_table_name": "synthetic-state", "bucket_name": "synthetic-bucket"},
            {"service_endpoints": {"opa": "https://opa.invalid", "evaluation": "https://eval.invalid"}},
            {"model_schema_hash": schema}, {"evaluation/frozen/validation.csv": {"sha256": "b" * 64}},
            distribution="iid", stage="primary", plan=plan)
        return plan, {"campaign_id": "app", "plan_digest": plan["plan_digest"], "cases": cases}, schema

    def test_accepted_registered_scope_is_explicit_and_hashed(self):
        plan, campaign, schema = self.fixture()
        auth = module.authorization_for(plan, campaign, model_schema_hash=schema,
            user_authorization={"source": "explicit-user-instruction", "instruction": "OK please work and finish all the phases"})
        self.assertEqual(len(auth["runs"]), 80)
        self.assertEqual(auth["plan_digest"], plan["plan_digest"])
        self.assertEqual(auth["authorization_digest"], digest({key: value for key, value in auth.items() if key != "authorization_digest"}))

    def test_prepared_scope_changes_or_missing_user_record_cannot_issue_authority(self):
        plan, campaign, schema = self.fixture()
        record = {"source": "explicit-user-instruction", "instruction": "OK please work and finish all the phases"}
        for field, value in (("seed", 999), ("rounds", 99), ("equivalence_hash", "0" * 64),
                             ("max_examples_per_client", 64), ("baseline_id", "B2"),
                             ("scenario_target_org", "org_99"), ("scenario_control", False)):
            changed = deepcopy(campaign)
            changed["cases"][0]["runtime"][field] = value
            with self.assertRaisesRegex(ValueError, "scope_mismatch"):
                module.authorization_for(plan, changed, model_schema_hash=schema, user_authorization=record)
        with self.assertRaisesRegex(ValueError, "instruction"):
            module.authorization_for(plan, campaign, model_schema_hash=schema, user_authorization={})
        candidate = example_plan(frozen_training=True)
        with self.assertRaisesRegex(ValueError, "accepted_plan"):
            module.authorization_for(candidate, campaign, model_schema_hash=schema, user_authorization=record)


if __name__ == "__main__":
    unittest.main()
