from copy import deepcopy
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from pcfl.data import CATEGORICAL_FEATURES, FEATURES, NUMERIC_FEATURES, fit_preprocessor, transform_row

try:
    import numpy as np
    import torch
    from torch.utils.data import TensorDataset
    from pcfl.learning import (classification_metrics, create_model, encode_features, evaluate,
                               feature_layout, get_parameters, load_partition, set_parameters, train_local)
    RUNTIME_AVAILABLE = True
except ImportError:
    RUNTIME_AVAILABLE = False


def raw_row(number=1, category="A", label="NO"):
    row = {name: str(number) for name in NUMERIC_FEATURES}
    row.update({name: category for name in CATEGORICAL_FEATURES})
    row.update({"patient_nbr": str(number), "encounter_id": str(number), "readmitted": label})
    return row


@unittest.skipUnless(RUNTIME_AVAILABLE, "Install the pinned runtime dependencies to test learning")
class LearningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.state = fit_preprocessor([raw_row(1), raw_row(3, label="<30")])
        self.preprocessor = self.directory / "preprocessor.json"
        self.preprocessor.write_text(json.dumps(self.state), encoding="utf-8")

    def partition(self, rows, name="partition.csv"):
        path = self.directory / name
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(list(FEATURES) + ["y"])
            writer.writerows(transform_row(row, self.state) for row in rows)
        return path

    def test_nominal_codes_become_distinct_one_hot_buckets(self):
        raw = np.zeros((3, len(FEATURES)), dtype=np.float64)
        raw[:, :len(NUMERIC_FEATURES)] = 0.25
        raw[0, len(NUMERIC_FEATURES):] = 0
        raw[1, len(NUMERIC_FEATURES):] = 1
        raw[2, len(NUMERIC_FEATURES):] = 2
        encoded = encode_features(raw, self.state)
        self.assertEqual(encoded.shape, (3, 8 + 32 * 3))
        np.testing.assert_array_equal(encoded[:, :8], raw[:, :8])
        np.testing.assert_array_equal(encoded[:, 8:11], np.eye(3, dtype=np.float32))
        np.testing.assert_array_equal(encoded[:, 8:].sum(axis=1), [32, 32, 32])

    def test_invalid_category_codes_and_numeric_values_fail(self):
        for value in (-1, 0.5, 3, float("nan"), float("inf")):
            features = np.zeros((1, len(FEATURES)))
            features[0, 8] = value
            with self.assertRaises(ValueError):
                encode_features(features, self.state)
        features = np.zeros((1, len(FEATURES)))
        features[0, 0] = np.finfo(np.float64).max
        with self.assertRaises(ValueError):
            encode_features(features, self.state)

    def test_load_preserves_frozen_preprocessor_and_unseen_bucket(self):
        path = self.partition([raw_row(100, "heldout-only", "<30")], "validation.csv")
        before = self.preprocessor.read_bytes()
        data = load_partition(path, self.preprocessor)
        self.assertEqual(self.preprocessor.read_bytes(), before)
        self.assertEqual(data.preprocessor, self.state)
        self.assertNotIn("heldout-only", data.preprocessor["categorical"]["race"]["vocabulary"])
        np.testing.assert_array_equal(data.tensors[0][0, 8:11].numpy(), [0, 1, 0])
        self.assertEqual(data.source_sha256, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_seeded_partition_sample_is_repeatable_and_label_blind(self):
        path = self.partition([raw_row(i, label="<30" if i % 3 else "NO") for i in range(1, 31)])
        first = load_partition(path, self.preprocessor, max_examples=10, seed=4)
        second = load_partition(path, self.preprocessor, max_examples=10, seed=4)
        other = load_partition(path, self.preprocessor, max_examples=10, seed=5)
        self.assertEqual(first.source_rows, 30)
        self.assertEqual(len(first), 10)
        self.assertEqual(first.sampled_positions_digest, second.sampled_positions_digest)
        self.assertNotEqual(first.sampled_positions_digest, other.sampled_positions_digest)
        self.assertTrue(torch.equal(first.tensors[0], second.tensors[0]))

    def test_identifier_headers_or_invalid_labels_cannot_enter_predictors(self):
        path = self.partition([raw_row()])
        content = path.read_text(encoding="utf-8")
        path.write_text(content.replace("time_in_hospital", "patient_nbr", 1), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "header_mismatch"):
            load_partition(path, self.preprocessor)
        path = self.partition([raw_row()])
        with path.open(encoding="utf-8", newline="") as stream:
            rows = list(csv.reader(stream))
        rows[1][-1] = "unknown-label"
        with path.open("w", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerows(rows)
        with self.assertRaisesRegex(ValueError, "invalid_prepared_csv_row"):
            load_partition(path, self.preprocessor)

    def test_validation_fitted_preprocessor_is_rejected(self):
        changed = deepcopy(self.state)
        changed["fit_scope"] = "validation"
        with self.assertRaisesRegex(ValueError, "frozen_preprocessor"):
            create_model(changed)

    def test_parameter_roundtrip_detaches_arrays_and_binds_model_schema(self):
        model = create_model(self.state, seed=1)
        other = create_model(self.state, seed=2)
        expected = get_parameters(model)
        set_parameters(other, expected)
        self.assertEqual(model.schema_hash, other.schema_hash)
        for left, right in zip(get_parameters(model), get_parameters(other), strict=True):
            np.testing.assert_array_equal(left, right)
        expected[0].flat[0] += 100
        self.assertNotEqual(expected[0].flat[0], get_parameters(model)[0].flat[0])

    def test_invalid_parameter_bundle_changes_nothing(self):
        model = create_model(self.state)
        original = get_parameters(model)
        for defect in ("count", "shape", "dtype", "nan"):
            invalid = [array.copy() for array in original]
            invalid[0].flat[0] += 1
            if defect == "count":
                invalid.pop()
            elif defect == "shape":
                invalid[-1] = np.zeros((10,), dtype=np.float32)
            elif defect == "dtype":
                invalid[-1] = invalid[-1].astype(np.float64)
            else:
                invalid[-1].flat[0] = np.nan
            with self.assertRaises(ValueError):
                set_parameters(model, invalid)
            for unchanged, expected in zip(get_parameters(model), original, strict=True):
                np.testing.assert_array_equal(unchanged, expected)

    def test_known_metrics_and_fixed_threshold(self):
        metrics = classification_metrics([0, 0, 1, 1], [0.1, 0.4, 0.35, 0.8])
        self.assertAlmostEqual(metrics["auroc"], 0.75)
        self.assertAlmostEqual(metrics["auprc"], 5 / 6)
        self.assertAlmostEqual(metrics["precision"], 1)
        self.assertAlmostEqual(metrics["recall"], 0.5)
        self.assertAlmostEqual(metrics["f1"], 2 / 3)
        self.assertEqual(metrics["threshold"], 0.5)

    def test_single_class_metrics_are_explicitly_undefined(self):
        negatives = classification_metrics([0, 0], [0.1, 0.2])
        self.assertIsNone(negatives["auroc"])
        self.assertIsNone(negatives["auprc"])
        self.assertEqual(negatives["precision"], 0)
        self.assertEqual(negatives["recall"], 0)
        positives = classification_metrics([1, 1], [0.1, 0.9])
        self.assertIsNone(positives["auroc"])
        self.assertEqual(positives["auprc"], 1)
        for labels, scores in (([], []), ([0, 1], [0.1]), ([0, 2], [0.1, 0.3]), ([0, 1], [0.2, np.nan])):
            with self.assertRaises(ValueError):
                classification_metrics(labels, scores)

    def test_local_training_improves_synthetic_loss_and_repeats_seed(self):
        rows = [raw_row(1 if index % 2 else 3, label="NO" if index % 2 else "<30") for index in range(64)]
        dataset = load_partition(self.partition(rows), self.preprocessor)
        first, second = create_model(self.state, seed=9), create_model(self.state, seed=9)
        settings = {"local_epochs": 8, "batch_size": 16, "learning_rate": 0.01, "cpu_threads": 1}
        left = train_local(first, dataset, settings, seed=10)
        right = train_local(second, dataset, settings, seed=10)
        self.assertLess(left["loss_after"], left["loss_before"] * 0.5)
        self.assertEqual(left["sample_count"], 64)
        self.assertEqual(left["example_exposures"], 64 * 8)
        self.assertEqual(left["batches"], 4 * 8)
        self.assertEqual(left["loss_after"], right["loss_after"])
        for a, b in zip(get_parameters(first), get_parameters(second), strict=True):
            np.testing.assert_array_equal(a, b)

    def test_same_shape_different_preprocessor_cannot_evaluate(self):
        data = load_partition(self.partition([raw_row(), raw_row(3, label="<30")]), self.preprocessor)
        changed = deepcopy(self.state)
        changed["categorical"]["race"]["vocabulary"] = {"different-category": 2}
        model = create_model(changed)
        self.assertEqual(model.input_dimension, data.tensors[0].shape[1])
        with self.assertRaisesRegex(ValueError, "preprocessor_schema_mismatch"):
            evaluate(model, data)

    def test_evaluation_restores_model_mode_and_rejects_invalid_tensors(self):
        model = create_model(self.state)
        data = load_partition(self.partition([raw_row(), raw_row(3, label="<30")]), self.preprocessor)
        model.train()
        metrics = evaluate(model, data)
        self.assertTrue(model.training)
        self.assertTrue(math_is_finite_positive(metrics["loss"]))
        invalid = TensorDataset(data.tensors[0].double(), data.tensors[1])
        with self.assertRaises(ValueError):
            evaluate(model, invalid)


def math_is_finite_positive(value):
    return isinstance(value, float) and 0 < value < float("inf")


if __name__ == "__main__":
    unittest.main()
