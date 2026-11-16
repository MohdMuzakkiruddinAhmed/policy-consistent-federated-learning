"""Synthetic tests; no source health records are embedded in tests or output."""

from copy import deepcopy
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from pcfl.data import (
    CATEGORICAL_FEATURES, FEATURES, NUMERIC_FEATURES, ORGS, assert_group_disjoint,
    fit_preprocessor, label, missing, partition_training, prepare_dataset,
    read_dataset, sha256_file, split_patient_groups, transform_row,
)


def synthetic_rows(groups=128, per_group=2):
    rows = []
    for group in range(groups):
        for encounter in range(per_group):
            row = {column: "2" for column in NUMERIC_FEATURES}
            row.update({column: "synthetic_category" for column in CATEGORICAL_FEATURES})
            row.update({"patient_nbr": str(100000 + group), "encounter_id": str(1000000 + len(rows)),
                        "readmitted": "<30" if group % 2 else "NO"})
            rows.append(row)
    return rows


def write_archive(path, rows):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("diabetic_data.csv", stream.getvalue())


class DataPreparationTests(unittest.TestCase):
    def test_label_contract_rejects_unknown_targets(self):
        self.assertEqual([label(value) for value in ("<30", ">30", "NO")], [1, 0, 0])
        for value in (None, "", "?", "<60", True):
            with self.assertRaises(ValueError):
                label(value)

    def test_patient_groups_never_cross_split_boundaries(self):
        rows = synthetic_rows()
        split = split_patient_groups(rows, seed=42)
        self.assertTrue(assert_group_disjoint(rows, split))
        self.assertEqual(set().union(*(set(v) for v in split.values())), set(range(len(rows))))
        self.assertEqual(sum(len(value) for value in split.values()), len(rows))
        self.assertEqual(split, split_patient_groups(rows, seed=42))
        changed = split_patient_groups(rows, seed=43)
        self.assertNotEqual(split, changed)
        reversed_rows = list(reversed(rows))
        reversed_split = split_patient_groups(reversed_rows, seed=42)
        for name in split:
            original_groups = {rows[i]["patient_nbr"] for i in split[name]}
            reversed_groups = {reversed_rows[i]["patient_nbr"] for i in reversed_split[name]}
            self.assertEqual(original_groups, reversed_groups)

    def test_overlap_checker_rejects_patient_and_duplicate_row_leaks(self):
        rows = synthetic_rows()
        for bad in ({"a": [0], "b": [1]}, {"a": [0, 0]}, {"a": [0], "b": [0]}):
            with self.assertRaises(ValueError):
                assert_group_disjoint(rows, bad)

    def test_fit_statistics_and_vocabularies_use_training_rows_only(self):
        rows = synthetic_rows(groups=3, per_group=1)
        rows[0]["num_medications"] = "1"
        rows[1]["num_medications"] = "3"
        rows[2]["num_medications"] = "1001"
        rows[2]["race"] = "heldout_only_category"
        fit = fit_preprocessor(rows[:2])
        before = deepcopy(fit)
        transformed = transform_row(rows[2], fit)
        index = FEATURES.index("num_medications")
        self.assertEqual(transformed[index], 999.0)
        self.assertEqual(transformed[FEATURES.index("race")], 1)
        self.assertNotIn("heldout_only_category", fit["categorical"]["race"]["vocabulary"])
        self.assertEqual(fit, before)
        self.assertEqual(fit["fit_rows"], 2)

    def test_missing_imputation_and_unknown_categories_are_distinct(self):
        rows = synthetic_rows(groups=3, per_group=1)
        rows[0]["num_medications"], rows[1]["num_medications"], rows[2]["num_medications"] = "1", "5", "?"
        rows[0]["gender"], rows[1]["gender"], rows[2]["gender"] = "A", "B", "Unknown/Invalid"
        rows[0]["max_glu_serum"] = "None"
        fit = fit_preprocessor(rows)
        self.assertEqual(fit["numeric"]["num_medications"]["median"], 3)
        self.assertEqual(transform_row(rows[2], fit)[FEATURES.index("num_medications")], 0)
        self.assertEqual(transform_row(rows[2], fit)[FEATURES.index("gender")], 0)
        self.assertIn("None", fit["categorical"]["max_glu_serum"]["vocabulary"])
        self.assertFalse(missing("None"))
        self.assertTrue(missing("?"))

    def test_numeric_validation_and_constant_training_columns(self):
        rows = synthetic_rows(groups=3, per_group=1)
        fit = fit_preprocessor(rows)
        self.assertEqual(fit["numeric"]["num_medications"]["scale"], 1)
        for bad in ("nan", "inf", "-1", "1.5", "not_a_number"):
            broken = deepcopy(rows)
            broken[0]["num_medications"] = bad
            with self.assertRaises(ValueError):
                fit_preprocessor(broken)
        with self.assertRaises(ValueError):
            fit_preprocessor([])

    def test_identifiers_outcome_and_discharge_proxy_are_never_features(self):
        for forbidden in ("patient_nbr", "encounter_id", "readmitted", "discharge_disposition_id"):
            self.assertNotIn(forbidden, FEATURES)
        fit = fit_preprocessor(synthetic_rows())
        transformed = transform_row(synthetic_rows()[0], fit)
        self.assertEqual(len(transformed), len(FEATURES) + 1)
        self.assertEqual(fit["feature_order"], list(FEATURES))

    def test_iid_and_dirichlet_partitions_cover_train_groups_only(self):
        rows = synthetic_rows(groups=192)
        split = split_patient_groups(rows)
        for distribution in ("iid", "non_iid"):
            allocations, recipe = partition_training(rows, split["train"], distribution,
                                                    seed=42, min_groups=1, min_positives=1)
            self.assertEqual(tuple(allocations), ORGS)
            self.assertEqual(set().union(*(set(v) for v in allocations.values())), set(split["train"]))
            self.assertTrue(assert_group_disjoint(rows, allocations))
            self.assertTrue(all(counts["positive_encounters"] >= 1 for counts in recipe["organizations"].values()))
            repeated = partition_training(rows, split["train"], distribution,
                                          seed=42, min_groups=1, min_positives=1)
            self.assertEqual((allocations, recipe), repeated)
            if distribution == "non_iid":
                self.assertEqual(set(recipe["dirichlet_weights"]), {"0", "1"})
                for values in recipe["dirichlet_weights"].values():
                    self.assertAlmostEqual(sum(values), 1.0)

    def test_impossible_partition_constraints_fail_boundedly(self):
        rows = synthetic_rows(groups=8, per_group=1)
        for distribution in ("iid", "non_iid"):
            with self.assertRaises(ValueError):
                partition_training(rows, list(range(len(rows))), distribution, min_groups=2, min_positives=1)
        with self.assertRaises(ValueError):
            partition_training(rows, list(range(len(rows))), "non_iid", alpha=0, min_groups=1, min_positives=1)

    def test_archive_schema_duplicate_encounters_and_labels_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.zip"
            rows = synthetic_rows()
            write_archive(path, rows)
            loaded, schema = read_dataset(path)
            self.assertEqual(len(loaded), len(rows))
            self.assertEqual(len(schema["csv_sha256"]), 64)
            broken = deepcopy(rows)
            broken[1]["encounter_id"] = broken[0]["encounter_id"]
            write_archive(path, broken)
            with self.assertRaises(ValueError):
                read_dataset(path)
            broken = deepcopy(rows)
            broken[0].pop("patient_nbr")
            for row in broken[1:]:
                row.pop("patient_nbr")
            write_archive(path, broken)
            with self.assertRaises(ValueError):
                read_dataset(path)

    def test_pipeline_freezes_artifacts_and_publishes_aggregate_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, output, manifest_path = root / "raw.zip", root / "processed", root / "manifest.json"
            rows = synthetic_rows(groups=192)
            write_archive(archive, rows)
            result = prepare_dataset(archive, output, manifest_path, min_groups=1, min_positives=1)
            self.assertTrue(all(result["checks"].values()))
            self.assertEqual(result["source_counts"]["encounters"], len(rows))
            self.assertEqual(len(result["partitions"]["iid"]["organizations"]), 8)
            self.assertEqual(len(result["partitions"]["non_iid"]["organizations"]), 8)
            for group in {row["patient_nbr"] for row in rows}:
                self.assertNotIn(f'"{group}"', manifest_path.read_text(encoding="utf-8"))
            with (output / "iid/org_01.csv").open(encoding="utf-8", newline="") as stream:
                headers = next(csv.reader(stream))
            self.assertEqual(headers, list(FEATURES) + ["y"])
            self.assertNotIn("patient_nbr", headers)
            before_hash = sha256_file(output / "test.csv")
            self.assertEqual(prepare_dataset(archive, output, manifest_path, min_groups=1, min_positives=1), result)
            self.assertEqual(sha256_file(output / "test.csv"), before_hash)
            with self.assertRaises(ValueError):
                prepare_dataset(archive, output, manifest_path, seed=999, min_groups=1, min_positives=1)
            (output / "test.csv").write_text("modified", encoding="utf-8")
            with self.assertRaises(ValueError):
                prepare_dataset(archive, output, manifest_path, min_groups=1, min_positives=1)


if __name__ == "__main__":
    unittest.main()
