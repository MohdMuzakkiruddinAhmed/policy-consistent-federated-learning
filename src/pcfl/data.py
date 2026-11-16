"""Leakage-controlled UCI 296 preparation using the Python standard library.

Patient identifiers are grouping keys only. This module never logs source rows.
Processed clinical records and membership files belong in ignored local storage.
"""

from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import random
import statistics
from urllib.request import Request, urlopen
import zipfile

PROTOCOL_VERSION = "0.1.0"
SOURCE_URL = "https://archive.ics.uci.edu/static/public/296/diabetes%2B130-us%2Bhospitals%2Bfor%2Byears%2B1999-2008.zip"
SOURCE_PAGE = "https://archive.ics.uci.edu/dataset/296/diabetes-130-us-hospitals-for-years-1999-2008"
DOI = "https://doi.org/10.24432/C5230J"
ATTRIBUTION = "Clore, J., Cios, K., DeShazo, J., & Strack, B. (2014). Diabetes 130-US Hospitals for Years 1999-2008. UCI Machine Learning Repository."
LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
ORGS = tuple(f"org_{number:02d}" for number in range(1, 9))
NUMERIC_FEATURES = (
    "time_in_hospital", "num_lab_procedures", "num_procedures", "num_medications",
    "number_outpatient", "number_emergency", "number_inpatient", "number_diagnoses",
)
CATEGORICAL_FEATURES = (
    "race", "gender", "age", "admission_type_id", "admission_source_id",
    "max_glu_serum", "A1Cresult", "metformin", "repaglinide", "nateglinide",
    "chlorpropamide", "glimepiride", "acetohexamide", "glipizide", "glyburide",
    "tolbutamide", "pioglitazone", "rosiglitazone", "acarbose", "miglitol",
    "troglitazone", "tolazamide", "examide", "citoglipton", "insulin",
    "glyburide-metformin", "glipizide-metformin", "glimepiride-pioglitazone",
    "metformin-rosiglitazone", "metformin-pioglitazone", "change", "diabetesMed",
)
FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES
EXCLUDED_FEATURES = {
    "patient_nbr": "Grouping key only; identifier forbidden as predictor.",
    "encounter_id": "Encounter identifier forbidden as predictor.",
    "readmitted": "Target observed after discharge; forbidden as predictor.",
    "discharge_disposition_id": "Conservative exclusion of discharge/death/hospice and outcome-proxy categories.",
    "weight": "Extensive missingness; omitted by a prespecified conservative allowlist.",
    "payer_code": "Payer proxy omitted from the initial feature set.",
    "medical_specialty": "High missingness/provider proxy omitted from the initial feature set.",
    "diag_1": "High-cardinality diagnosis coding omitted from this initial model specification.",
    "diag_2": "High-cardinality diagnosis coding omitted from this initial model specification.",
    "diag_3": "High-cardinality diagnosis coding omitted from this initial model specification.",
}


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_file(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(canonical_json(value) + b"\n")


def label(value):
    if value not in ("<30", ">30", "NO"):
        raise ValueError("invalid_readmission_label")
    return int(value == "<30")


def missing(value):
    return value is None or str(value).strip() in ("", "?", "Unknown/Invalid", "Unknown")


def _number(value):
    if missing(value):
        return None
    try:
        number = float(value)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid_numeric_feature") from error
    if not math.isfinite(number) or number < 0 or not number.is_integer():
        raise ValueError("invalid_numeric_feature")
    return number


def download_dataset(destination):
    """Download the official HTTPS archive without extracting arbitrary ZIP paths."""
    path = Path(destination)
    if path.exists():
        with zipfile.ZipFile(path) as archive:
            if "diabetic_data.csv" not in archive.namelist():
                raise ValueError("cached_archive_missing_dataset")
        return path
    request = Request(SOURCE_URL, headers={"User-Agent": "pcfl-research/0.1.0"})
    with urlopen(request, timeout=60) as response:
        content = response.read(50 * 1024 * 1024 + 1)
    if len(content) > 50 * 1024 * 1024:
        raise ValueError("archive_size_limit_exceeded")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        if "diabetic_data.csv" not in archive.namelist():
            raise ValueError("archive_missing_dataset")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def read_dataset(archive_path):
    with zipfile.ZipFile(archive_path) as archive:
        info = archive.getinfo("diabetic_data.csv")
        if info.file_size > 100 * 1024 * 1024:
            raise ValueError("dataset_size_limit_exceeded")
        content = archive.read(info)
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
    columns = reader.fieldnames or []
    if len(columns) != len(set(columns)) or not set(FEATURES + ("patient_nbr", "encounter_id", "readmitted")) <= set(columns):
        raise ValueError("dataset_schema_mismatch")
    rows, encounters = [], set()
    for row in reader:
        if None in row or any(value is None for value in row.values()):
            raise ValueError("malformed_dataset_row")
        if not row["patient_nbr"].isdigit() or not row["encounter_id"].isdigit():
            raise ValueError("invalid_group_or_encounter_key")
        if row["encounter_id"] in encounters:
            raise ValueError("duplicate_encounter_key")
        encounters.add(row["encounter_id"])
        label(row["readmitted"])
        for column in NUMERIC_FEATURES:
            _number(row[column])
        rows.append(row)
    if not rows:
        raise ValueError("empty_dataset")
    return rows, {"columns": columns, "csv_sha256": hashlib.sha256(content).hexdigest(),
                  "csv_size_bytes": len(content)}


def split_patient_groups(rows, seed=296):
    """Assign entire patients by seeded hash rank, independent of row delivery order."""
    if type(seed) is not int:
        raise ValueError("invalid_seed")
    groups = {row["patient_nbr"] for row in rows}
    if len(groups) < 3 or any(not isinstance(group, str) or not group.strip() for group in groups):
        raise ValueError("insufficient_or_invalid_patient_groups")
    ranked = sorted(groups, key=lambda group: (hashlib.sha256(f"pcfl-split-v1:{seed}:{group}".encode()).digest(), group))
    train_end = max(1, int(len(ranked) * 0.70))
    validation_end = min(len(ranked) - 1, train_end + max(1, int(len(ranked) * 0.15)))
    membership = {group: "train" for group in ranked[:train_end]}
    membership.update({group: "validation" for group in ranked[train_end:validation_end]})
    membership.update({group: "test" for group in ranked[validation_end:]})
    split = {"train": [], "validation": [], "test": []}
    for index, row in enumerate(rows):
        split[membership[row["patient_nbr"]]].append(index)
    return split


def assert_group_disjoint(rows, assignments):
    seen_groups, seen_rows = set(), set()
    for indices in assignments.values():
        group_set = {rows[index]["patient_nbr"] for index in indices}
        if seen_groups & group_set or seen_rows & set(indices) or len(indices) != len(set(indices)):
            raise ValueError("patient_or_row_overlap")
        seen_groups.update(group_set)
        seen_rows.update(indices)
    return True


def fit_preprocessor(training_rows):
    """Caller supplies training rows only; never inspect validation/test vocabularies."""
    if not training_rows:
        raise ValueError("empty_training_data")
    numeric, categorical = {}, {}
    for column in NUMERIC_FEATURES:
        values = [_number(row.get(column)) for row in training_rows]
        observed = [value for value in values if value is not None]
        imputation = statistics.median(observed) if observed else 0.0
        imputed = [imputation if value is None else value for value in values]
        mean = statistics.fmean(imputed)
        scale = statistics.pstdev(imputed) or 1.0
        numeric[column] = {"median": imputation, "mean": mean, "scale": scale,
                           "missing_training_rows": len(values) - len(observed)}
    for column in CATEGORICAL_FEATURES:
        categories = sorted({str(row.get(column)).strip() for row in training_rows if not missing(row.get(column))})
        categorical[column] = {"missing_code": 0, "unknown_code": 1,
                               "vocabulary": {category: index + 2 for index, category in enumerate(categories)}}
    return {"schema_version": PROTOCOL_VERSION, "fit_scope": "training_only",
            "fit_rows": len(training_rows), "numeric": numeric, "categorical": categorical,
            "feature_order": list(FEATURES), "target": "y"}


def transform_row(row, preprocessing):
    values = []
    for column in NUMERIC_FEATURES:
        state = preprocessing["numeric"][column]
        value = _number(row.get(column))
        standardized = ((state["median"] if value is None else value) - state["mean"]) / state["scale"]
        if not math.isfinite(standardized):
            raise ValueError("nonfinite_transformed_feature")
        values.append(standardized)
    for column in CATEGORICAL_FEATURES:
        state = preprocessing["categorical"][column]
        value = row.get(column)
        values.append(0 if missing(value) else state["vocabulary"].get(str(value).strip(), 1))
    return values + [label(row["readmitted"])]


def _counts(rows, indices):
    positives = sum(label(rows[index]["readmitted"]) for index in indices)
    return {"encounters": len(indices), "patient_groups": len({rows[index]["patient_nbr"] for index in indices}),
            "positive_encounters": positives, "negative_encounters": len(indices) - positives,
            "positive_prevalence": positives / len(indices) if indices else None}


def partition_training(rows, indices, distribution, seed=296, alpha=0.5,
                       min_groups=100, min_positives=25, max_attempts=200):
    if distribution not in ("iid", "non_iid") or type(seed) is not int:
        raise ValueError("invalid_partition_configuration")
    if type(min_groups) is not int or min_groups < 1 or type(min_positives) is not int or min_positives < 1:
        raise ValueError("invalid_partition_minimum")
    if type(max_attempts) is not int or max_attempts < 1 or not math.isfinite(alpha) or not 0.01 <= alpha <= 100:
        raise ValueError("invalid_dirichlet_configuration")
    if len(indices) != len(set(indices)):
        raise ValueError("duplicate_training_indices")
    groups = defaultdict(list)
    for index in indices:
        groups[rows[index]["patient_nbr"]].append(index)
    if len(groups) < len(ORGS) * min_groups or sum(label(rows[i]["readmitted"]) for i in indices) < len(ORGS) * min_positives:
        raise ValueError("insufficient_groups_or_positives_for_partitions")
    for attempt in range(max_attempts):
        rng = random.Random(f"pcfl-partition-v1:{seed}:{distribution}:{attempt}")
        allocated = {org: [] for org in ORGS}
        weights = None
        if distribution == "iid":
            ordered = sorted(groups)
            rng.shuffle(ordered)
            for position, group in enumerate(ordered):
                allocated[ORGS[position % len(ORGS)]].extend(groups[group])
        else:
            # Mixed-label patient groups remain intact; stratum=any early readmission.
            strata = {0: [], 1: []}
            for group in sorted(groups):
                strata[int(any(label(rows[i]["readmitted"]) for i in groups[group]))].append(group)
            weights = {}
            for stratum, patient_groups in strata.items():
                draws = [rng.gammavariate(alpha, 1.0) for _ in ORGS]
                total = sum(draws)
                if total <= 0:
                    raise ValueError("degenerate_dirichlet_draw")
                probabilities = [draw / total for draw in draws]
                weights[str(stratum)] = probabilities
                rng.shuffle(patient_groups)
                for group in patient_groups:
                    chosen = rng.choices(ORGS, weights=probabilities, k=1)[0]
                    allocated[chosen].extend(groups[group])
        for value in allocated.values():
            value.sort()
        summary = {org: _counts(rows, value) for org, value in allocated.items()}
        if all(counts["patient_groups"] >= min_groups and counts["positive_encounters"] >= min_positives for counts in summary.values()):
            assert_group_disjoint(rows, allocated)
            if set().union(*(set(value) for value in allocated.values())) != set(indices):
                raise ValueError("partition_coverage_mismatch")
            return allocated, {"distribution": distribution, "seed": seed, "accepted_attempt": attempt,
                               "dirichlet_alpha": alpha if distribution == "non_iid" else None,
                               "min_groups": min_groups, "min_positive_encounters": min_positives,
                               "max_attempts": max_attempts, "group_stratum": "any_positive_encounter",
                               "dirichlet_weights": weights, "organizations": summary}
    raise ValueError("partition_constraints_not_met_within_retry_budget")


def _write_records(path, rows, indices, preprocessing):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(list(FEATURES) + ["y"])
        for index in indices:
            values = transform_row(rows[index], preprocessing)
            writer.writerow([format(value, ".10g") if isinstance(value, float) else value for value in values])


def prepare_dataset(archive_path, output_dir, manifest_path, seed=296, alpha=0.5,
                    min_groups=100, min_positives=25):
    output_dir, manifest_path = Path(output_dir), Path(manifest_path)
    recipe = {"protocol_version": PROTOCOL_VERSION, "split_seed": seed, "partition_seed": seed,
              "split_group_ratios": {"train": 0.70, "validation": 0.15, "test": 0.15},
              "dirichlet_alpha": alpha, "min_groups_per_client": min_groups,
              "min_positive_encounters_per_client": min_positives, "features": list(FEATURES)}
    source_hash = sha256_file(archive_path)
    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        if existing.get("recipe") != recipe or existing.get("source", {}).get("archive_sha256") != source_hash:
            raise ValueError("frozen_recipe_or_source_differs_use_new_versioned_outputs")
        for relative_path, expected_hash in existing["private_artifacts_sha256"].items():
            path = output_dir / relative_path
            if not path.is_file() or sha256_file(path) != expected_hash:
                raise ValueError("frozen_private_artifact_integrity_failure")
        return existing
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("output_directory_not_empty_without_matching_manifest")
    rows, schema = read_dataset(archive_path)
    split = split_patient_groups(rows, seed)
    assert_group_disjoint(rows, split)
    if set().union(*(set(value) for value in split.values())) != set(range(len(rows))):
        raise ValueError("split_coverage_mismatch")
    preprocessing = fit_preprocessor([rows[index] for index in split["train"]])
    allocations, partition_summaries = {}, {}
    for distribution in ("iid", "non_iid"):
        allocations[distribution], partition_summaries[distribution] = partition_training(
            rows, split["train"], distribution, seed, alpha, min_groups, min_positives)
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / "preprocessor.json", preprocessing)
    # Membership contains patient keys and row indices: private, ignored, never logged.
    _write_json(output_dir / "membership.json", {
        "split": {name: {"row_indices": indices, "patient_groups": sorted({rows[i]["patient_nbr"] for i in indices})}
                  for name, indices in split.items()}, "partitions": allocations})
    for name in ("validation", "test"):
        _write_records(output_dir / f"{name}.csv", rows, split[name], preprocessing)
    for distribution, organizations in allocations.items():
        for org, indices in organizations.items():
            _write_records(output_dir / distribution / f"{org}.csv", rows, indices, preprocessing)
    artifact_hashes = {path.relative_to(output_dir).as_posix(): sha256_file(path)
                       for path in sorted(output_dir.rglob("*")) if path.is_file()}
    manifest = {"schema_version": PROTOCOL_VERSION, "kind": "uci296_data_preparation",
                "source": {"dataset_id": 296, "page": SOURCE_PAGE, "download": SOURCE_URL, "doi": DOI,
                           "attribution": ATTRIBUTION, "license": "CC BY 4.0", "license_url": LICENSE_URL,
                           "archive_sha256": source_hash, "archive_size_bytes": Path(archive_path).stat().st_size,
                           **schema}, "recipe": recipe,
                "prediction_timing": "discharge_time_secondary_benchmark_not_clinical_validation",
                "target": {"positive": "readmitted == '<30'", "negative": [">30", "NO"]},
                "feature_contract": {"numeric": list(NUMERIC_FEATURES), "categorical": list(CATEGORICAL_FEATURES),
                                     "excluded": EXCLUDED_FEATURES, "identifiers_in_predictors": False,
                                     "numeric_encoding": "training_median_imputation_then_population_zscore",
                                     "categorical_encoding": "training_vocabulary_codes_missing0_unknown1; one-hot-or-embeddings-required-in-model-adapter"},
                "source_counts": _counts(rows, list(range(len(rows)))),
                "source_label_counts": dict(sorted(Counter(row["readmitted"] for row in rows).items())),
                "source_missing_selected_fields": {column: sum(missing(row[column]) for row in rows) for column in FEATURES},
                "splits": {name: _counts(rows, indices) for name, indices in split.items()},
                "partitions": partition_summaries, "private_artifacts_sha256": artifact_hashes,
                "checks": {"patient_disjoint_splits": True, "patient_disjoint_clients_within_each_distribution": True,
                           "all_rows_assigned_once_per_split_and_distribution": True, "eight_clients_per_distribution": True,
                           "preprocessing_fit_training_only": True, "test_holdout_frozen": True,
                           "no_identifiers_in_processed_predictors": True},
                "scope": {"organizations_are_fictional": True, "cloud_upload_performed": False,
                          "real_hospital_membership_inferred": False, "hypothesis_results": False}}
    _write_json(manifest_path, manifest)
    return manifest
