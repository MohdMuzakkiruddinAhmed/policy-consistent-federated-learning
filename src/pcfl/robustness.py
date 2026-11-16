"""Exploratory factor contracts; no dataset rows, AWS calls, or holdout access."""
from copy import deepcopy
import hashlib
import itertools
import json
import random
import re
from pathlib import Path

from .contracts import ORGANIZATIONS, digest
from .evaluation import build_model_metadata, create_model_from_metadata
from .experiments import scientific_data, validate_plan

PROTOCOL = "pcfl-exploratory-robustness-v1"
DEFAULTS = {"non_iid_alpha": .5, "revocations_per_round": 1, "participation_fraction": 1.0,
            "update_size_multiplier": 1, "artificial_latency_ms": 0, "client_clock_skew_ms": 0}
LEVELS = {"non_iid_alpha": [.1, .5, 1.0], "revocations_per_round": [0, 1, 4],
    "participation_fraction": [.5, .75, 1.0], "update_size_multiplier": [1, 4],
    "artificial_latency_ms": [0, 250, 1000], "client_clock_skew_ms": [-60000, 0, 60000]}
ADAPTER_MODULES = ("robustness.py", "robust_policy.py", "robust_flower_app.py", "robust_flower_client.py", "robust_cloud_coordinator.py", "robust_service_runtime.py")


def adapter_source_digest():
    package = Path(__file__).resolve().parent
    return digest({name: hashlib.sha256((package / name).read_bytes()).hexdigest() for name in ADAPTER_MODULES})


def factors(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULTS):
        raise ValueError("exact_six_exploratory_factors_required")
    for key, allowed in LEVELS.items():
        if type(value[key]) not in (int, float) or value[key] not in allowed:
            raise ValueError("unregistered_exploratory_factor_level")
        if key not in {"non_iid_alpha", "participation_fraction"} and type(value[key]) is not int:
            raise ValueError("integer_exploratory_factor_required")
    return {key: float(value[key]) if key in {"non_iid_alpha", "participation_fraction"} else value[key] for key in DEFAULTS}


def selected_orgs(seed, round_number, fraction):
    if type(seed) is not int or not 0 <= seed < 2**32 or type(round_number) is not int or not 1 <= round_number <= 100:
        raise ValueError("typed_exploratory_seed_round_required")
    if type(fraction) not in (int, float) or fraction not in {.5, .75, 1.0}:
        raise ValueError("registered_participation_fraction_required")
    organizations = list(ORGANIZATIONS)
    random.Random(digest([PROTOCOL, "selection", seed, round_number])).shuffle(organizations)
    return sorted(organizations[:round(8 * fraction)])


def targets(seed, round_number, value):
    value = factors(value)
    chosen = selected_orgs(seed, round_number, value["participation_fraction"])
    random.Random(digest([PROTOCOL, "revocation", seed, round_number])).shuffle(chosen)
    return sorted(chosen[:value["revocations_per_round"]])


def schedule(seed, rounds, value):
    value = factors(value)
    if type(rounds) is not int or not 2 <= rounds <= 100:
        raise ValueError("exploratory_round_budget_required")
    events = [{"phase": "before_run", "round_id": "initial", "org_id": org, "kind": "GRANT"} for org in ORGANIZATIONS]
    for number in range(1, rounds + 1):
        if number > 1:
            events += [{"phase": "before_round", "round_id": f"round-{number}", "org_id": org, "kind": "GRANT"}
                       for org in targets(seed, number - 1, value)]
        events += [{"phase": "after_dispatch", "round_id": f"round-{number}", "org_id": org, "kind": "REVOKE"}
                   for org in targets(seed, number, value)]
    return events


def architecture(metadata, multiplier):
    if type(multiplier) is not int or multiplier not in {1, 4}:
        raise ValueError("registered_architecture_multiplier_required")
    model = create_model_from_metadata(metadata)
    if metadata["hidden_dims"] != [64, 32]:
        raise ValueError("frozen_main_64_32_architecture_required")
    baseline = sum(parameter.numel() for parameter in model.parameters())
    widths = [64, 32]
    if multiplier == 4:
        dimension, desired = model.input_dimension, baseline * 4
        def ranking(pair):
            first, second = pair
            count = first * (dimension + 1 + second) + 2 * second + 1
            return (abs(count - desired), abs(first / 64 - second / 32), first, second)
        widths = list(min(itertools.product(range(64, 513), range(32, 513)), key=ranking))
    actual = build_model_metadata(metadata["preprocessor"], seed=metadata["seed"], hidden_dims=widths)
    altered = create_model_from_metadata(actual)
    count = sum(parameter.numel() for parameter in altered.parameters())
    if abs(count / baseline - multiplier) > .01:
        raise ValueError("requested_parameter_budget_not_approximated")
    return {"model_metadata": actual, "baseline_parameter_count": baseline, "parameter_count": count,
        "float32_parameter_bytes": count * 4, "realized_parameter_multiplier": count / baseline,
        "requested_multiplier": multiplier, "hidden_dims": widths,
        "interpretation": "architecture/capacity and parameter payload intervention; not a pure network-padding test"}


def validate_data(base, alternate, preparation):
    for manifest in (base, alternate):
        if (manifest.get("checks", {}).get("patient_disjoint_splits") is not True
                or manifest["checks"].get("preprocessing_fit_training_only") is not True
                or manifest["checks"].get("test_holdout_frozen") is not True):
            raise ValueError("frozen_train_only_disjoint_data_required")
    unchanged = ["preprocessor.json", "validation.csv", "test.csv", *[f"iid/{org}.csv" for org in ORGANIZATIONS]]
    if (any(base["private_artifacts_sha256"].get(name) != alternate["private_artifacts_sha256"].get(name) for name in unchanged)
            or base.get("source", {}).get("csv_sha256") != alternate.get("source", {}).get("csv_sha256")
            or base.get("splits") != alternate.get("splits") or alternate.get("recipe", {}).get("dirichlet_alpha") != 1.0):
        raise ValueError("alternate_alpha_changed_frozen_cohort_or_preprocessor")
    for manifest in (base, alternate):
        clients = manifest["partitions"]["non_iid"]["organizations"]
        if (set(clients) != set(ORGANIZATIONS) or any(item["patient_groups"] < 100 or item["positive_encounters"] < 25 for item in clients.values())
                or sum(item["encounters"] for item in clients.values()) != manifest["splits"]["train"]["encounters"]):
            raise ValueError("original_partition_minima_and_coverage_required")
    failed = next((item for item in preparation.get("attempts", []) if item.get("alpha") == .1), None)
    if (not failed or failed.get("status") != "failed" or failed.get("constraints_weakened") is not False
            or failed.get("retry_limit") != 200 or failed.get("minimum_patient_groups") != 100
            or failed.get("minimum_positive_encounters") != 25):
        raise ValueError("alpha_point1_original_bounded_failure_must_be_retained")
    return deepcopy(failed)


def descriptor(value, *, seed, data_manifest_digest, reference_plan_digest, adapter_source_sha256, adapter_image):
    result = {"schema_version": "0.1.0", "protocol_id": PROTOCOL, "factors": factors(value), "seed": seed,
        "data_manifest_digest": data_manifest_digest, "reference_main_plan_digest": reference_plan_digest,
        "adapter_source_sha256": adapter_source_sha256, "adapter_image": adapter_image, "evaluation_split": "validation",
        "final_test_access_permitted": False, "confirmatory": False}
    result["descriptor_digest"] = digest(result)
    validate_descriptor(result, seed=seed)
    return result


def validate_descriptor(value, *, seed):
    required = {"schema_version", "protocol_id", "factors", "seed", "data_manifest_digest", "reference_main_plan_digest",
                "adapter_source_sha256", "adapter_image", "evaluation_split", "final_test_access_permitted", "confirmatory", "descriptor_digest"}
    if (not isinstance(value, dict) or set(value) != required or value.get("schema_version") != "0.1.0"
            or value.get("protocol_id") != PROTOCOL or type(value.get("seed")) is not int or value["seed"] != seed
            or seed != 296 or value.get("evaluation_split") != "validation"
            or value.get("final_test_access_permitted") is not False or value.get("confirmatory") is not False
            or not isinstance(value.get("adapter_image"), str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", value["adapter_image"])
            or any(not isinstance(value.get(name), str) or not re.fullmatch(r"[0-9a-f]{64}", value[name]) for name in
                   ("data_manifest_digest", "reference_main_plan_digest", "adapter_source_sha256", "descriptor_digest"))
            or value["descriptor_digest"] != digest({key: item for key, item in value.items() if key != "descriptor_digest"})):
        raise ValueError("explicit_validation_only_exploratory_descriptor_required")
    normalized = factors(value["factors"])
    if sum(normalized[key] != DEFAULTS[key] for key in DEFAULTS) > 1:
        raise ValueError("one_factor_at_a_time_exploratory_scope_required")
    if value["factors"]["non_iid_alpha"] == .1:
        raise ValueError("alpha_point1_preparation_failed_no_runtime_case_allowed")
    return deepcopy(value)


def register(plan, base, alternate, preparation, metadata, *, adapter_source_sha256, adapter_image, seeds=(296,)):
    validate_plan(plan)
    if plan["status"] != "accepted_frozen":
        raise ValueError("accepted_main_plan_required_for_exploratory_registration")
    if (plan["training_candidate"].get("num_rounds") != 5 or plan["training_candidate"].get("hidden_dims") != [64, 32]
            or plan["training_candidate"].get("classification_threshold") != .5):
        raise ValueError("frozen_five_round_64_32_reference_required")
    failed = validate_data(base, alternate, preparation)
    if plan["data_manifest_digest"] != digest(scientific_data(base)):
        raise ValueError("accepted_main_data_manifest_binding_required")
    if not isinstance(seeds, (tuple, list)) or list(seeds) != [296] or type(seeds[0]) is not int:
        raise ValueError("prespecified_descriptive_seed_296_only")
    variants = {}
    for factor, levels in LEVELS.items():
        for level in levels:
            configuration = factors({**DEFAULTS, factor: level})
            variants.setdefault(digest(configuration), {"factors": configuration, "factor_levels": []})["factor_levels"].append([factor, level])
    specs = {multiplier: architecture(metadata, multiplier) for multiplier in (1, 4)}
    cases, excluded = [], []
    for seed, distribution in itertools.product(seeds, ("iid", "non_iid")):
        for variant in variants.values():
            value = variant["factors"]
            if distribution == "iid" and value["non_iid_alpha"] != .5:
                continue  # This factor is defined only for non-IID allocation.
            if value["non_iid_alpha"] == .1:
                excluded.append({"seed": seed, "distribution": distribution, "factors": value, "status": "failed_preparation",
                                 "evidence": failed, "actual_cloud_trial": False})
                continue
            data = alternate if value["non_iid_alpha"] == 1.0 else base
            data_sha = digest(scientific_data(data))
            contract = descriptor(value, seed=seed, data_manifest_digest=data_sha,
                reference_plan_digest=plan["plan_digest"], adapter_source_sha256=adapter_source_sha256, adapter_image=adapter_image)
            model = specs[value["update_size_multiplier"]]
            group = "group-" + digest([distribution, data_sha, model["model_metadata"]["metadata_digest"]])[:20]
            shared = {"robustness": contract, "distribution": distribution, "model_schema_hash": model["model_metadata"]["model_schema_hash"],
                "partition_hashes": {org: data["private_artifacts_sha256"][f"{distribution}/{org}.csv"] for org in ORGANIZATIONS},
                "preprocessor_sha256": data["private_artifacts_sha256"]["preprocessor.json"],
                "validation_sha256": data["private_artifacts_sha256"]["validation.csv"],
                "training": {key: val for key, val in plan["training_candidate"].items() if key not in {"seed", "pilot_only", "confirmatory_frozen", "acceptance_status"}}}
            shared["training"]["hidden_dims"] = model["hidden_dims"]
            cases.append({"case_id": "exploratory-" + digest([contract, distribution])[:24], "deployment_group": group,
                "seed": seed, "distribution": distribution, "robustness": contract, "architecture": deepcopy(model),
                "shared_config": shared, "equivalence_hash": digest(shared),
                "partition_hashes": shared["partition_hashes"],
                "schedule": schedule(seed, 5, value), "status": "registered_not_run", "actual_cloud_trial": False,
                "requires": ["completed_P9_primary", "completed_P10_targeted", "separate_exploratory_image_source_budget_acceptance", "eight_actual_client_tasks"]})
    result = {"schema_version": "0.1.0", "kind": "exploratory-robustness-registry", "reference_main_plan_digest": plan["plan_digest"],
        "cases": cases, "excluded_preparation_attempts": excluded, "independent_seed_count": len(seeds),
        "actual_cloud_trials_executed": 0, "final_holdout_accessed": False, "execution_authorized": False,
        "control_reuse": "one identical default configuration per seed/distribution; no duplicate independent controls",
        "inference_scope": "descriptive exploratory factors; not the primary 160-cell matrix"}
    result["registry_digest"] = digest(result)
    return result


def validate_registry(registry):
    if (not isinstance(registry, dict) or registry.get("kind") != "exploratory-robustness-registry"
            or registry.get("registry_digest") != digest({key: value for key, value in registry.items() if key != "registry_digest"})
            or registry.get("execution_authorized") is not False or registry.get("final_holdout_accessed") is not False
            or registry.get("actual_cloud_trials_executed") != 0 or not isinstance(registry.get("cases"), list)
            or registry.get("independent_seed_count") != 1 or len(registry["cases"]) > 24):
        raise ValueError("unexecuted_exploratory_registry_required")
    ids = set()
    for case in registry["cases"]:
        validate_descriptor(case["robustness"], seed=case["seed"])
        if (case["case_id"] != "exploratory-" + digest([case["robustness"], case["distribution"]])[:24]
                or case["case_id"] in ids or case["equivalence_hash"] != digest(case["shared_config"])
                or case["shared_config"]["robustness"] != case["robustness"] or case["status"] != "registered_not_run"
                or case["actual_cloud_trial"] is not False or case["distribution"] not in {"iid", "non_iid"}
                or case["shared_config"]["partition_hashes"] != case["partition_hashes"]):
            raise ValueError("exploratory_case_digest_or_binding_mismatch")
        ids.add(case["case_id"])
    return True


def deployment_inputs(registry, base_runtime):
    """Create public case inputs only; existing host tooling injects per-role secrets."""
    validate_registry(registry)
    allowed = {"authority_backend", "baseline_id", "scenario_id", "rounds", "seed", "model_metadata", "validation_source_sha256",
        "table_name", "bucket", "opa", "evaluator", "scenario_control", "training", "max_examples_per_client",
        "message_timeout_seconds", "persistent_run_id", "scenario_target_org"}
    if (not isinstance(base_runtime, dict) or set(base_runtime) - allowed or base_runtime.get("authority_backend") != "dynamodb-s3-opa"
            or base_runtime.get("baseline_id") != "P1" or any("key" in name for name in base_runtime.get("opa", {}) if name != "expected_rule_hash")
            or any(name in base_runtime.get("evaluator", {}) for name in ("client_key", "client_cert", "expected_holdout"))):
        raise ValueError("public_P1_runtime_template_without_secrets_required")
    groups = {}
    for case in registry["cases"]:
        name, shared = case["deployment_group"], case["shared_config"]
        runtime = deepcopy(base_runtime)
        runtime.update(baseline_id="P1", scenario_id="robustness", scenario_control=True, seed=case["seed"],
            persistent_run_id="robust-" + case["case_id"].removeprefix("exploratory-"), rounds=shared["training"]["num_rounds"],
            max_examples_per_client=shared["training"]["max_examples_per_client"], model_metadata=case["architecture"]["model_metadata"],
            validation_source_sha256=shared["validation_sha256"], distribution=case["distribution"],
            plan_digest=registry["registry_digest"], cell_id=case["case_id"], match_id="exploratory-" + digest([case["seed"], case["distribution"]])[:24],
            equivalence_hash=case["equivalence_hash"], robustness=case["robustness"],
            training={key: shared["training"][key] for key in ("optimizer", "learning_rate", "local_epochs", "batch_size", "cpu_threads")})
        runtime["experiment_binding"] = {"plan_digest": registry["registry_digest"], "cell_id": case["case_id"],
            "equivalence_hash": case["equivalence_hash"], "family": "exploratory", "policy_schedule_hash": digest(case["schedule"]),
            "source_sha256": case["robustness"]["adapter_source_sha256"]}
        group = groups.setdefault(name, {"group_id": name, "distribution": case["distribution"],
            "partition_hashes": case["partition_hashes"], "evaluation_override": {"dataset_role": "validation",
                "model_metadata": case["architecture"]["model_metadata"], "max_examples": shared["training"]["max_validation_examples"]},
            "cases": [], "policy_campaign": {"protocol_id": PROTOCOL, "runs": []}})
        if (group["partition_hashes"] != case["partition_hashes"]
                or group["evaluation_override"]["model_metadata"] != case["architecture"]["model_metadata"]):
            raise ValueError("deployment_group_mixed_client_data_or_evaluator_architecture")
        group["cases"].append({"cell_id": case["case_id"], "match_id": runtime["match_id"], "equivalence_hash": case["equivalence_hash"], "runtime": runtime})
        group["policy_campaign"]["runs"].append({"run_id": runtime["persistent_run_id"], "rounds": runtime["rounds"],
            "seed": case["seed"], "factors": case["robustness"]["factors"]})
    return {"schema_version": "0.1.0", "kind": "exploratory-private-deployment-inputs", "registry_digest": registry["registry_digest"],
        "groups": list(groups.values()), "execution_authorized": False, "actual_cloud_trials_executed": 0,
        "requires_separate_actor_generations_for_each_group": True}
