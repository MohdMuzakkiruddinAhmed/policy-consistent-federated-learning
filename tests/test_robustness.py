"""Synthetic metadata/client tests for an inactive additive exploratory app."""
from copy import deepcopy
import csv
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict

STAGE = Path(__file__).resolve().parents[1]
ROOT = STAGE
sys.path.append(str(ROOT / "tests"))
from test_evaluation import preprocessor
from test_experiments import synthetic_gate_refs

from pcfl import learning
from pcfl.data import CATEGORICAL_FEATURES, FEATURES, NUMERIC_FEATURES
from pcfl.evaluation import build_model_metadata
from pcfl.experiments import build_plan, digest, freeze_plan
from pcfl.robustness import (DEFAULTS, LEVELS, adapter_source_digest, architecture, deployment_inputs, descriptor,
    factors, register, schedule, selected_orgs, targets, validate_data, validate_descriptor, validate_registry)
from pcfl.robust_policy import changes
from pcfl import robust_flower_app as app


def data_fixture():
    clients = {f"org_{number:02d}": {"encounters": 100, "patient_groups": 100, "positive_encounters": 25} for number in range(1, 9)}
    base = {"checks": {name: True for name in ("patient_disjoint_splits", "preprocessing_fit_training_only", "test_holdout_frozen")},
        "source": {"csv_sha256": "a" * 64}, "splits": {"train": {"encounters": 800}, "validation": {"encounters": 16}, "test": {"encounters": 16}},
        "recipe": {"dirichlet_alpha": .5}, "partitions": {"iid": {"organizations": deepcopy(clients)}, "non_iid": {"organizations": deepcopy(clients)}},
        "private_artifacts_sha256": {f"{kind}/org_{number:02d}.csv": digest([kind, number]) for kind in ("iid", "non_iid") for number in range(1, 9)}}
    base["private_artifacts_sha256"].update({name: digest(name) for name in ("preprocessor.json", "validation.csv", "test.csv")})
    alternate = deepcopy(base); alternate["recipe"]["dirichlet_alpha"] = 1.0
    for number in range(1, 9): alternate["private_artifacts_sha256"][f"non_iid/org_{number:02d}.csv"] = digest([1.0, number])
    preparation = {"attempts": [{"alpha": .1, "status": "failed", "constraints_weakened": False, "retry_limit": 200,
        "minimum_patient_groups": 100, "minimum_positive_encounters": 25, "reason": "partition_constraints_not_met_within_retry_budget"}]}
    return base, alternate, preparation


@lru_cache(maxsize=1)
def plan_fixture():
    config = json.loads((STAGE / "configs/experiments.json").read_text())
    training = json.loads((STAGE / "configs/experiments_training.json").read_text())
    training["pilot_only"] = False
    base, _, _ = data_fixture()
    source = {"src/synthetic.py": hashlib.sha256(b"# synthetic fixture\n").hexdigest()}
    provenance = {"source_files_sha256": source, "source_sha256": digest(source), "git_commit": None,
                  "image_digests": {"runtime": "example.invalid/main@sha256:" + "b" * 64}}
    plan = build_plan(config, training, base, provenance)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); (root / "src").mkdir(); (root / "src/synthetic.py").write_bytes(b"# synthetic fixture\n")
        return freeze_plan(plan, synthetic_gate_refs(plan, root), root)


@lru_cache(maxsize=1)
def registry_fixture():
    return register(plan_fixture(), *data_fixture(), build_model_metadata(preprocessor()),
        adapter_source_sha256=adapter_source_digest(), adapter_image="example.invalid/exploratory@sha256:" + "c" * 64)


class RobustnessContractTests(unittest.TestCase):
    def test_OFAT_control_is_deduplicated_one_seed_and_failed_alpha_is_not_a_run(self):
        registry = registry_fixture()
        validate_registry(registry)
        self.assertEqual(registry["independent_seed_count"], 1)
        self.assertLessEqual(len(registry["cases"]), 24)
        self.assertEqual(len(registry["excluded_preparation_attempts"]), 1)
        self.assertTrue(all(case["seed"] == 296 and case["actual_cloud_trial"] is False for case in registry["cases"]))
        self.assertFalse(registry["execution_authorized"])
        for distribution in ("iid", "non_iid"):
            controls = [case for case in registry["cases"] if case["distribution"] == distribution and case["robustness"]["factors"] == DEFAULTS]
            self.assertEqual(len(controls), 1)
        self.assertFalse(any(case["robustness"]["factors"]["non_iid_alpha"] == .1 for case in registry["cases"]))
        self.assertTrue(all(case["robustness"]["factors"]["non_iid_alpha"] == .5 for case in registry["cases"] if case["distribution"] == "iid"))

    def test_participation_keeps_four_six_eight_unique_identities_and_actual_policy_counts(self):
        for fraction, count in ((.5, 4), (.75, 6), (1.0, 8)):
            first = selected_orgs(296, 1, fraction)
            self.assertEqual(first, selected_orgs(296, 1, fraction))
            self.assertEqual(len(first), count); self.assertEqual(len(set(first)), count)
            for rate in (0, 1, 4):
                value = {**DEFAULTS, "participation_fraction": fraction, "revocations_per_round": rate}
                events = schedule(296, 5, value)
                for number in range(1, 6):
                    revoked = [event for event in events if event["kind"] == "REVOKE" and event["round_id"] == f"round-{number}"]
                    self.assertEqual(len(revoked), rate)
                    self.assertTrue({event["org_id"] for event in revoked} <= set(selected_orgs(296, number, fraction)))
                self.assertEqual(len([event for event in events if event["kind"] == "GRANT"]), 8 + 4 * rate)

    def test_architecture_intervention_measures_parameter_count_and_does_not_pad(self):
        metadata = build_model_metadata(preprocessor())
        base = architecture(metadata, 1); larger = architecture(metadata, 4)
        self.assertEqual(base["hidden_dims"], [64, 32])
        self.assertAlmostEqual(larger["realized_parameter_multiplier"], 4, delta=.01)
        model = learning.create_model(metadata["preprocessor"], hidden_dims=larger["hidden_dims"])
        self.assertEqual(sum(parameter.numel() for parameter in model.parameters()), larger["parameter_count"])
        self.assertEqual(sum(array.nbytes for array in learning.get_parameters(model)), larger["float32_parameter_bytes"])
        self.assertNotEqual(larger["model_metadata"]["model_schema_hash"], metadata["model_schema_hash"])

    def test_alpha_minima_holdouts_and_original_failure_cannot_be_silently_changed(self):
        base, alternate, preparation = data_fixture()
        validate_data(base, alternate, preparation)
        for name in ("test.csv", "validation.csv", "preprocessor.json", "iid/org_01.csv"):
            changed = deepcopy(alternate); changed["private_artifacts_sha256"][name] = "0" * 64
            with self.subTest(name=name), self.assertRaises(ValueError): validate_data(base, changed, preparation)
        changed = deepcopy(alternate); changed["partitions"]["non_iid"]["organizations"]["org_01"]["patient_groups"] = 99
        with self.assertRaises(ValueError): validate_data(base, changed, preparation)
        changed = deepcopy(preparation); changed["attempts"][0]["constraints_weakened"] = True
        with self.assertRaises(ValueError): validate_data(base, alternate, changed)

    def test_descriptor_rejects_holdout_self_claims_unregistered_levels_seed_and_mutable_image(self):
        case = registry_fixture()["cases"][0]
        for fields in ({"final_test_access_permitted": True}, {"confirmatory": True}, {"seed": 593},
                       {"adapter_image": "runtime:latest"}, {"factors": {**DEFAULTS, "participation_fraction": True}},
                       {"factors": {**DEFAULTS, "non_iid_alpha": .1}}):
            changed = {**case["robustness"], **fields}
            changed["descriptor_digest"] = digest({key: value for key, value in changed.items() if key != "descriptor_digest"})
            with self.subTest(fields=fields), self.assertRaises(ValueError): validate_descriptor(changed, seed=296)

    def test_deployments_separate_client_partitions_and_evaluator_architectures(self):
        base = {"authority_backend": "dynamodb-s3-opa", "baseline_id": "P1", "table_name": "synthetic-table", "bucket": "synthetic-bucket",
            "opa": {"endpoint": "https://opa.invalid", "expected_rule_hash": "a" * 64}, "evaluator": {"endpoint": "https://eval.invalid"}}
        groups = deployment_inputs(registry_fixture(), base)["groups"]
        self.assertGreaterEqual(len(groups), 5)
        for group in groups:
            model = group["evaluation_override"]["model_metadata"]
            for case in group["cases"]:
                runtime = case["runtime"]
                self.assertEqual(runtime["model_metadata"], model)
                self.assertEqual(runtime["experiment_binding"]["family"], "exploratory")
                self.assertEqual(runtime["rounds"], 5)
                self.assertNotIn("final_holdout", runtime)
                self.assertEqual(runtime["scenario_id"], "robustness")
        with self.assertRaises(ValueError): deployment_inputs(registry_fixture(), {**base, "final_holdout": {}})

    def test_exact_policy_request_idempotency_binds_phase_round_and_factor_schedule(self):
        value = {**DEFAULTS, "revocations_per_round": 4}
        actions = changes("robust-synthetic", 296, 5, value, "after_dispatch", "round-1")
        self.assertEqual(len(actions), 4)
        self.assertEqual(actions, changes("robust-synthetic", 296, 5, value, "after_dispatch", "round-1"))
        self.assertNotEqual(actions, changes("other-run", 296, 5, value, "after_dispatch", "round-1"))


if __name__ == "__main__":
    unittest.main()
