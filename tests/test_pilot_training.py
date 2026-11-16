"""Pilot orchestration boundaries and small synthetic model-protocol checks."""

from copy import deepcopy
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
RUNTIME = all(importlib.util.find_spec(name) is not None for name in ("numpy", "torch", "sklearn"))
if RUNTIME:
    import numpy as np
    import pilot_training as pilot
    from pcfl.contracts import ORGANIZATIONS
    from pcfl.data import NUMERIC_FEATURES, CATEGORICAL_FEATURES, FEATURES


@unittest.skipUnless(RUNTIME, "pinned runtime supplies learning dependencies")
class TrainingPilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "private-data"
        self.data.mkdir()
        self.config = json.loads((ROOT / "configs/experiments_training.json").read_text(encoding="utf-8"))

    def prepared_inputs(self):
        state = {"schema_version": "0.1.0", "fit_scope": "training_only", "fit_rows": 16,
            "feature_order": list(FEATURES), "target": "y",
            "numeric": {name: {"median": 0, "mean": 0, "scale": 1} for name in NUMERIC_FEATURES},
            "categorical": {name: {"missing_code": 0, "unknown_code": 1, "vocabulary": {"observed": 2}}
                            for name in CATEGORICAL_FEATURES}}
        (self.data / "preprocessor.json").write_text(json.dumps(state), encoding="utf-8")
        names = ["validation.csv", *[f"{distribution}/{org}.csv" for distribution in pilot.DISTRIBUTIONS for org in ORGANIZATIONS]]
        for name in names:
            path = self.data / name
            path.parent.mkdir(exist_ok=True)
            with path.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow([*FEATURES, "y"])
                for value in range(2):
                    writer.writerow([*[value] * len(NUMERIC_FEATURES), *[2] * len(CATEGORICAL_FEATURES), value])
        manifest = {"schema_version": "0.1.0", "source": {"dataset_id": 296},
            "private_artifacts_sha256": {name: hashlib.sha256((self.data / name).read_bytes()).hexdigest()
                                         for name in ["preprocessor.json", *names]},
            "splits": {"train": {"encounters": 16}, "validation": {"encounters": 2}},
            "partitions": {distribution: {"organizations": {org: {"encounters": 2} for org in ORGANIZATIONS}}
                           for distribution in pilot.DISTRIBUTIONS}}
        path = self.root / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_candidate_training_values_and_final_test_boundary_cannot_drift(self):
        pilot.candidate_settings(self.config)
        for changed in ({"hidden_dims": [32]}, {"num_rounds": 2}, {"optimizer": "sgd"}, {"learning_rate": .01},
                        {"final_test_access_permitted": True}, {"confirmatory_frozen": True}, {"cpu_threads": True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                pilot.candidate_settings({**self.config, **changed})

    def test_explicit_input_allowlist_never_opens_test_or_membership_and_loads_full_partitions(self):
        manifest = self.prepared_inputs()
        original = Path.read_bytes
        reads = []
        def allowed_read(path):
            self.assertNotIn(path.name, {"test.csv", "membership.json"})
            reads.append(path)
            return original(path)
        with patch.object(Path, "read_bytes", allowed_read):
            _, hashes, _, partitions, validation = pilot.load_inputs(self.data, manifest, self.config)
        self.assertEqual(len(hashes), 18)
        self.assertEqual(len(validation), 2)
        self.assertTrue(all(len(dataset) == dataset.source_rows == 2 for values in partitions.values() for dataset in values.values()))
        self.assertEqual({name for name in hashes if name.endswith(".csv")}, {"validation.csv", *[
            f"{distribution}/{org}.csv" for distribution in pilot.DISTRIBUTIONS for org in ORGANIZATIONS]})
        self.assertFalse((self.data / "test.csv").exists())

    def test_input_tampering_and_partial_sampling_budget_fail_closed(self):
        manifest = self.prepared_inputs()
        with self.assertRaisesRegex(ValueError, "full_partition"):
            pilot.load_inputs(self.data, manifest, {**self.config, "max_examples_per_client": 1})
        path = self.data / "iid/org_01.csv"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "digest_mismatch"):
            pilot.load_inputs(self.data, manifest, self.config)

    def test_fedavg_uses_sample_counts_and_rejects_duplicate_or_invalid_contributors(self):
        template = [np.zeros(1, dtype=np.float32)]
        updates = [{"org_id": "org_01", "sample_count": 1, "arrays": [np.array([1], dtype=np.float32)]},
                   {"org_id": "org_02", "sample_count": 3, "arrays": [np.array([5], dtype=np.float32)]}]
        np.testing.assert_array_equal(pilot.fedavg(updates, template)[0], [4])
        np.testing.assert_array_equal(pilot.fedavg(list(reversed(updates)), template)[0], [4])
        for values in ([], updates + [updates[0]], [{**updates[0], "sample_count": True}],
                       [{**updates[0], "arrays": [np.array([np.nan], dtype=np.float32)]}]):
            with self.subTest(values=len(values)), self.assertRaises(ValueError):
                pilot.fedavg(values, template)

    def test_small_eight_client_attempt_is_deterministic_and_progress_contains_no_arrays(self):
        manifest = self.prepared_inputs()
        _, _, state, partitions, validation = pilot.load_inputs(self.data, manifest, self.config)
        config = {**self.config, "hidden_dims": [4], "num_rounds": 1}
        progress = []
        first = pilot.train_attempt(partitions["iid"], validation, state, config, distribution="iid", seed=296, progress=progress.append)
        second = pilot.train_attempt(partitions["iid"], validation, state, config, distribution="iid", seed=296)
        self.assertEqual(first["initial_parameters_digest"], second["initial_parameters_digest"])
        self.assertEqual(first["final_parameters_digest"], second["final_parameters_digest"])
        self.assertEqual(first["curves"], second["curves"])
        self.assertEqual(first["rounds"][0]["training_sample_count"], 16)
        self.assertEqual([value["seed"] for value in first["rounds"][0]["clients"]], list(range(396, 404)))
        self.assertEqual(first["curves"][-1]["validation_metrics"]["count"], 2)
        self.assertFalse(first["final_test_accessed"])
        for value in progress:
            encoded = json.dumps(value, allow_nan=False)
            for field in ('"arrays"', '"labels"', '"predictions"', '"rows"'):
                self.assertNotIn(field, encoded)

    def test_every_failed_attempt_is_retained_without_freezing_or_success(self):
        manifest_path = self.prepared_inputs()
        inputs = pilot.load_inputs(self.data, manifest_path, self.config)
        config_path = self.root / "training.json"
        config_path.write_text(json.dumps(self.config), encoding="utf-8")
        report_path = self.root / "report.json"
        with patch.object(pilot, "load_inputs", return_value=inputs), patch.object(pilot, "train_attempt", side_effect=RuntimeError("synthetic_failure")):
            report = pilot.run_pilot(data_root=self.data, manifest_path=manifest_path, training_path=config_path,
                                    output_root=self.root / "artifacts", report_path=report_path)
        self.assertFalse(report["successful"])
        self.assertFalse(report["confirmatory_frozen"])
        self.assertEqual(report["failed_attempts"], 10)
        self.assertEqual(report["completed_attempts"], 0)
        self.assertTrue(all(value["status"] == "failed" and value["reason"] == "synthetic_failure" for value in report["attempts"]))
        self.assertEqual(json.loads(report_path.read_text())["attempts"], report["attempts"])

    def test_pilot_outputs_cannot_overwrite_private_data(self):
        with self.assertRaisesRegex(ValueError, "overwrite_private_dataset"):
            pilot.run_pilot(data_root=self.data, manifest_path="unused", training_path="unused",
                output_root=self.root / "artifacts", report_path=self.data / "test.csv")
