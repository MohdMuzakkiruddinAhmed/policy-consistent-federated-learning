"""Five-seed, full-partition local model-protocol pilot; validation only.

This driver directly executes sample-weighted FedAvg. It does not demonstrate
distributed placement, governance enforcement, cloud performance or hypotheses.
"""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import statistics
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import numpy as np
import sklearn
import torch

from pcfl import learning
from pcfl.contracts import ORGANIZATIONS, digest
from pcfl.evaluation import parameters_digest

SEEDS = (296, 593, 887, 1181, 1483)
DISTRIBUTIONS = ("iid", "non_iid")
FROZEN_VALUES = {"device": "cpu", "cpu_threads": 1, "hidden_dims": [64, 32], "optimizer": "adam",
    "learning_rate": 0.001, "local_epochs": 1, "batch_size": 64, "num_rounds": 5,
    "classification_threshold": 0.5, "development_evaluation_split": "validation",
    "final_test_access_permitted": False}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    for attempt in range(6):
        try:
            temporary.replace(path)
            return
        except PermissionError:
            # Windows indexers can briefly hold an already published report.
            # Keep atomic replacement and the prior complete bytes throughout.
            if attempt == 5:
                raise
            time.sleep(0.05 * 2 ** attempt)


def candidate_settings(config):
    for name, expected in FROZEN_VALUES.items():
        if (config.get(name) != expected or (isinstance(expected, bool) and type(config.get(name)) is not bool)
                or (type(expected) is int and type(config.get(name)) is not int)):
            raise ValueError("pilot_candidate_configuration_mismatch:" + name)
    for name in ("max_examples_per_client", "max_validation_examples"):
        if type(config.get(name)) is not int or config[name] < 1:
            raise ValueError("invalid_pilot_example_budget")
    if config.get("confirmatory_frozen") is not False:
        raise ValueError("pilot_must_not_claim_confirmatory_freeze")
    return {name: config[name] for name in learning.DEFAULT_TRAINING}


def load_inputs(data_root, manifest_path, config):
    """Read only the 18 named training/preprocessor/validation artifacts."""
    data_root = Path(data_root).resolve()
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "0.1.0" or manifest.get("source", {}).get("dataset_id") != 296:
        raise ValueError("unsupported_pilot_dataset_manifest")
    names = ["preprocessor.json", "validation.csv", *[f"{distribution}/{org}.csv"
             for distribution in DISTRIBUTIONS for org in ORGANIZATIONS]]
    verified = {}
    for name in names:
        path = (data_root / name).resolve()
        if not path.is_relative_to(data_root) or path != data_root / name:
            raise ValueError("pilot_artifact_outside_data_root")
        expected = manifest["private_artifacts_sha256"].get(name)
        if not isinstance(expected, str) or file_hash(path) != expected:
            raise ValueError("pilot_input_digest_mismatch:" + name)
        verified[name] = expected
    # Parse the already hash-checked frozen training aggregates; never fit here.
    preprocessor = learning.load_preprocessor(data_root / "preprocessor.json")
    if file_hash(data_root / "preprocessor.json") != verified["preprocessor.json"]:
        raise ValueError("pilot_preprocessor_changed_during_load")
    validation = learning.load_partition(data_root / "validation.csv", preprocessor, max_examples=None)
    if (validation.source_sha256 != verified["validation.csv"] or len(validation) != validation.source_rows
            or len(validation) != manifest["splits"]["validation"]["encounters"]
            or len(validation) > config["max_validation_examples"]):
        raise ValueError("pilot_full_validation_binding_mismatch")
    partitions = {}
    for distribution in DISTRIBUTIONS:
        partitions[distribution] = {}
        for org in ORGANIZATIONS:
            name = f"{distribution}/{org}.csv"
            dataset = learning.load_partition(data_root / name, preprocessor, max_examples=None)
            expected_count = manifest["partitions"][distribution]["organizations"][org]["encounters"]
            if (dataset.source_sha256 != verified[name] or len(dataset) != dataset.source_rows
                    or len(dataset) != expected_count or len(dataset) > config["max_examples_per_client"]):
                raise ValueError("pilot_full_partition_binding_mismatch:" + name)
            partitions[distribution][org] = dataset
        if sum(map(len, partitions[distribution].values())) != manifest["splits"]["train"]["encounters"]:
            raise ValueError("pilot_training_partition_coverage_mismatch")
    return manifest, verified, preprocessor, partitions, validation


def fedavg(updates, template):
    """Use unique contributor sample counts, never batch/exposure counts."""
    if not updates or len({value["org_id"] for value in updates}) != len(updates):
        raise ValueError("empty_or_duplicate_pilot_contributors")
    for update in updates:
        if type(update["sample_count"]) is not int or update["sample_count"] < 1:
            raise ValueError("invalid_pilot_sample_count")
        if len(update["arrays"]) != len(template):
            raise ValueError("pilot_parameter_count_mismatch")
        for actual, expected in zip(update["arrays"], template, strict=True):
            if (not isinstance(actual, np.ndarray) or actual.dtype != np.float32 or actual.shape != expected.shape
                    or not np.isfinite(actual).all()):
                raise ValueError("pilot_parameter_shape_or_value_mismatch")
    total = sum(update["sample_count"] for update in updates)
    result = [np.zeros_like(value, dtype=np.float64) for value in template]
    for update in sorted(updates, key=lambda value: value["org_id"]):
        for target, value in zip(result, update["arrays"], strict=True):
            target += value.astype(np.float64) * (update["sample_count"] / total)
    return [value.astype(np.float32) for value in result]


def train_attempt(partitions, validation, preprocessor, config, *, distribution, seed, progress=None):
    """Execute a stable all-client candidate; progress receives aggregate state only."""
    if set(partitions) != set(ORGANIZATIONS):
        raise ValueError("exactly_eight_pilot_training_partitions_required")
    started = time.perf_counter()
    model = learning.create_model(preprocessor, seed=seed, hidden_dims=config["hidden_dims"])
    local_model = learning.create_model(preprocessor, seed=seed, hidden_dims=config["hidden_dims"])
    arrays = learning.get_parameters(model)
    training = {name: config[name] for name in learning.DEFAULT_TRAINING}
    result = {"attempt_id": "pilot-" + uuid.uuid4().hex, "distribution": distribution, "seed": seed,
        "status": "running", "successful": False, "started_utc": utc_now(), "model_schema_hash": model.schema_hash,
        "initial_parameters_digest": parameters_digest(arrays), "training_counts": {org: len(partitions[org]) for org in ORGANIZATIONS},
        "validation_count": len(validation), "curves": [{"round": 0, "parameters_digest": parameters_digest(arrays),
            "validation_metrics": learning.evaluate(model, validation, threshold=config["classification_threshold"])}],
        "rounds": [], "final_test_accessed": False, "is_confirmatory": False}
    if progress:
        progress(deepcopy(result))
    for number in range(1, config["num_rounds"] + 1):
        round_started = time.perf_counter()
        before_digest = parameters_digest(arrays)
        updates, clients = [], []
        for index, org in enumerate(ORGANIZATIONS):
            learning.set_parameters(local_model, arrays)
            client_seed = seed + number * 100 + index
            metadata = learning.train_local(local_model, partitions[org], training, seed=client_seed)
            if (metadata["sample_count"] != len(partitions[org]) or metadata["example_exposures"] != len(partitions[org]) * training["local_epochs"]):
                raise ValueError("pilot_training_sample_count_mismatch")
            weights = learning.get_parameters(local_model)
            updates.append({"org_id": org, "sample_count": len(partitions[org]), "arrays": weights})
            clients.append({"org_id": org, "parameters_digest": parameters_digest(weights), **metadata})
        arrays = fedavg(updates, arrays)
        learning.set_parameters(model, arrays)
        metrics = learning.evaluate(model, validation, threshold=config["classification_threshold"])
        if metrics["count"] != len(validation):
            raise ValueError("pilot_validation_sampling_forbidden")
        result["curves"].append({"round": number, "parameters_digest": parameters_digest(arrays), "validation_metrics": metrics})
        result["rounds"].append({"round": number, "input_parameters_digest": before_digest,
            "output_parameters_digest": parameters_digest(arrays), "selected_clients": 8, "accepted_clients": 8,
            "training_sample_count": sum(len(dataset) for dataset in partitions.values()), "clients": clients,
            "duration_seconds": time.perf_counter() - round_started})
        if progress:
            progress(deepcopy(result))
    result.update(status="completed", successful=True, final_parameters_digest=parameters_digest(arrays),
                  completed_utc=utc_now(), duration_seconds=time.perf_counter() - started)
    if progress:
        progress(deepcopy(result))
    return result


def descriptive_summary(attempts):
    result = {}
    for distribution in DISTRIBUTIONS:
        completed = [value for value in attempts if value.get("successful") and value["distribution"] == distribution]
        summary = {"independent_seed_count": len(completed), "descriptive_only": True, "metrics": {}}
        for name in ("auroc", "auprc", "loss", "f1", "precision", "recall"):
            values = [value["curves"][-1]["validation_metrics"][name] for value in completed]
            values = [value for value in values if value is not None]
            if not values:
                summary["metrics"][name] = None
                continue
            sd = statistics.stdev(values) if len(values) > 1 else None
            summary["metrics"][name] = {"n": len(values), "mean": statistics.fmean(values), "sample_sd": sd,
                "standard_error": sd / math.sqrt(len(values)) if sd is not None else None,
                "minimum": min(values), "maximum": max(values)}
        result[distribution] = summary
    return result


def run_pilot(*, data_root, manifest_path, training_path, output_root, report_path):
    private_root = Path(data_root).resolve()
    if Path(output_root).resolve().is_relative_to(private_root) or Path(report_path).resolve().is_relative_to(private_root):
        raise ValueError("pilot_outputs_must_not_overwrite_private_dataset")
    run_id = "model-pilot-" + uuid.uuid4().hex[:12]
    directory = Path(output_root) / run_id
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": "0.1.0", "kind": "full-data-local-training-protocol-pilot", "run_id": run_id,
        "started_utc": utc_now(), "status": "running", "successful": False, "attempts": [], "planned_attempts": 10,
        "seeds": list(SEEDS), "distributions": list(DISTRIBUTIONS), "final_test_accessed": False,
        "is_confirmatory": False, "confirmatory_frozen": False, "research_gates_passed": [],
        "distributed_runtime_demonstrated": False, "aws_used": False, "artifacts_directory": str(directory.resolve())}
    started = time.perf_counter()
    def retain():
        write_json(directory / "pilot.json", report)
        write_json(report_path, report)
    retain()
    try:
        config = json.loads(Path(training_path).read_text(encoding="utf-8"))
        candidate_settings(config)
        torch.set_num_threads(config["cpu_threads"])
        torch.use_deterministic_algorithms(True)
        manifest, hashes, preprocessor, partitions, validation = load_inputs(data_root, manifest_path, config)
        report.update(training_configuration=config, training_config_sha256=file_hash(training_path),
            training_config_digest=digest(config), dataset_manifest_sha256=file_hash(manifest_path), verified_input_sha256=hashes,
            source_dataset_sha256=manifest["source"].get("csv_sha256"), full_training_rows_per_distribution=manifest["splits"]["train"]["encounters"],
            full_validation_rows=len(validation), runtime={"python": platform.python_version(), "torch": torch.__version__,
            "numpy": np.__version__, "scikit_learn": sklearn.__version__, "platform": platform.platform(), "cpu_threads": 1},
            source_sha256={name: file_hash(ROOT / name) for name in ("scripts/pilot_training.py", "src/pcfl/learning.py",
                "src/pcfl/data.py", "src/pcfl/contracts.py", "src/pcfl/evaluation.py", "requirements-runtime.lock")})
        retain()
        for distribution in DISTRIBUTIONS:
            for seed in SEEDS:
                path = directory / f"{distribution}-seed-{seed}.json"
                partial = {"distribution": distribution, "seed": seed, "successful": False, "status": "starting"}
                report["attempts"].append(partial)
                retain()
                last_round = -1
                def progress(value):
                    nonlocal last_round
                    partial.clear()
                    partial.update(value)
                    write_json(path, partial)
                    retain()
                    number = value["curves"][-1]["round"]
                    if number != last_round:
                        print(json.dumps({"event": "pilot_round", "distribution": distribution, "seed": seed, "round": number,
                            "validation_auroc": value["curves"][-1]["validation_metrics"]["auroc"]}), flush=True)
                        last_round = number
                try:
                    train_attempt(partitions[distribution], validation, preprocessor, config,
                                  distribution=distribution, seed=seed, progress=progress)
                except Exception as error:
                    partial.update(status="failed", successful=False, error=type(error).__name__, reason=str(error), completed_utc=utc_now())
                    write_json(path, partial)
                    retain()
        completed = [value for value in report["attempts"] if value.get("successful")]
        matched_initialization = all(len({value["initial_parameters_digest"] for value in completed if value["seed"] == seed}) == 1
                                     for seed in SEEDS)
        report.update(successful=len(completed) == 10 and matched_initialization,
            status="completed" if len(completed) == 10 and matched_initialization else "incomplete",
            completed_attempts=len(completed), failed_attempts=len(report["attempts"]) - len(completed),
            same_seed_initialization_matches_distributions=matched_initialization, descriptive_summary=descriptive_summary(report["attempts"]),
            completed_utc=utc_now(), duration_seconds=time.perf_counter() - started,
            limitations=["Direct single-process FedAvg validates model protocol, not distributed placement or governance safety.",
                "Validation curves are development evidence; final test remains unread and no hypothesis is tested.",
                "Five seeds per distribution are descriptive; the two partitions reuse the same frozen training cohort.",
                "CPU timings include local training evaluations and do not predict cloud network or policy-service overhead."])
        retain()
        return report
    except Exception as error:
        report.update(status="failed", successful=False, error=type(error).__name__, reason=str(error),
                      completed_utc=utc_now(), duration_seconds=time.perf_counter() - started)
        retain()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=ROOT / "data/processed/uci296-v0.1.0-seed296")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data_manifests/dataset.json")
    parser.add_argument("--training-config", type=Path, default=ROOT / "configs/experiments_training.json")
    parser.add_argument("--output-root", type=Path, default=ROOT / "results/pilottraining")
    parser.add_argument("--report", type=Path, default=ROOT / "reports/training_pilot.json")
    args = parser.parse_args()
    result = run_pilot(data_root=args.data_root, manifest_path=args.manifest, training_path=args.training_config,
                       output_root=args.output_root, report_path=args.report)
    print(json.dumps({"successful": result["successful"], "completed_attempts": result["completed_attempts"],
                      "report": str(args.report)}), flush=True)
    raise SystemExit(0 if result["successful"] else 1)


if __name__ == "__main__":
    main()
