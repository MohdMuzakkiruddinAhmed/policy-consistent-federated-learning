"""Deterministic comparison registry and fail-closed experiment accounting.

This module plans runs and retains aggregate attempts. It executes no training,
AWS operation, or holdout evaluation and imports no enforcing implementation.
"""

from copy import deepcopy
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re

BASELINES = ["B1", "B2", "B3", "P1"]
DISTRIBUTIONS = ["iid", "non_iid"]
PRIMARY_SCENARIOS = ["S0", "S1", "S2", "S3"]
SEEDS = [296, 593, 887, 1181, 1483]
STATUSES = {"successful", "failed", "aborted", "excluded"}
GATES = {"P5_training", "P6_semantics", "P7_safety_audit", "P8_pilot", "baseline_oracle", "manifest_equivalence", "fargate_isolation", "cost_budget"}
GATE_CHECKS = {
    "P5_training": {"real_training", "full_own_partitions", "five_independent_seeds", "frozen_training_protocol", "validation_only"},
    "P6_semantics": {"independent_oracle", "s0_s8_coverage", "native_opa", "durable_publication"},
    "P7_safety_audit": {"all_final_decisions_audited", "operational_errors_accounted", "external_anchor", "tamper_detection", "fail_closed_faults"},
    "P8_pilot": {"five_seed_full_data_validation", "cloud_protocol_pilot", "failures_retained", "performance_review", "no_test_access"},
    "baseline_oracle": {"all_four_methods", "independent_oracle", "expected_unsafe_baselines_observed", "p1_excludes_invalid", "no_b1_opa_overhead"},
    "manifest_equivalence": {"full_config_equivalence", "same_initial_model", "same_partitions", "same_schedule", "same_training_budget"},
    "fargate_isolation": {"actual_fargate", "eight_clients", "distinct_roles_and_partitions", "private_network", "actual_boundary_probes", "image_source_binding"},
    "cost_budget": {"operator_budget", "current_spend_accounted", "projected_cost", "expiry_backstops", "notifications_verified"}}
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
COUNT_METRICS = {"unique_presented_updates", "oracle_invalid_presented", "oracle_invalid_incorporations",
    "oracle_valid_presented", "oracle_valid_rejections", "accepted_updates", "final_decisions",
    "audit_complete_decisions", "audit_record_sets_tested", "audit_record_sets_verified", "tamper_attempted",
    "tamper_detected", "selected_eligible_clients", "accepted_clients", "published_models", "revocations",
    "post_revocation_invalid_publications", "coordination_operations"}
UTILITY_METRICS = {"auroc", "auprc", "f1", "precision", "recall", "prevalence", "threshold"}
OTHER_METRICS = {"evaluation_split", "data_kind", "latency_ms", "cost_usd", "resources", "revocation_response_ms", "revocation_response_censored", "revocation_response"}
LATENCY_SERIES = {"opa", "commit", "publication", "round", "cold_start", "failure", "run_initialization", "issue_dispatch",
    "ack_wait", "ack_authorization", "train_dispatch", "policy_barrier", "train_wait", "receipt", "evaluation", "run"}


def validate_revocation_response(value):
    """Strict aggregate interval/censor records, never a fabricated point lag."""
    fields = {"status", "clock", "events", "opportunity_events", "measured_events", "right_censored_events", "missing_events",
              "exact_response_ms", "operation_coverage_complete", "measurement_errors", "reason"}
    if (not isinstance(value, dict) or set(value) != fields or value["status"] not in {"no-event", "measured", "right-censored", "missing", "mixed"}
            or value["clock"] != "coordinator-perf-counter-relative-ms" or value["exact_response_ms"] is not None
            or type(value["operation_coverage_complete"]) is not bool or not isinstance(value["reason"], str) or len(value["reason"]) > 256
            or not isinstance(value["events"], list) or len(value["events"]) > 1000):
        raise ValueError("invalid_revocation_interval_measurements")
    names = ("opportunity_events", "measured_events", "right_censored_events", "missing_events", "measurement_errors")
    if any(value[name] is not None and (type(value[name]) is not int or value[name] < 0) for name in names):
        raise ValueError("invalid_revocation_observation_counts")
    event_fields = {"run_id", "event_id", "org_id", "kind", "order", "epoch", "status", "response_lower_ms", "response_upper_ms",
        "exact_response_ms", "censor_lower_ms", "censor_upper_ms", "operation_sequence", "operation", "task_id", "update_id",
        "manifest_id", "enforcement_order", "reason"}
    ids = set()
    for row in value["events"]:
        if (not isinstance(row, dict) or set(row) != event_fields or row["status"] not in {"measured", "right-censored", "missing"}
                or row["kind"] not in {"REVOKE", "EXPIRE", "CHANGE"} or row["exact_response_ms"] is not None
                or any(not isinstance(row[name], str) or not _ID.fullmatch(row[name]) for name in ("run_id", "event_id", "org_id"))
                or any(type(row[name]) is not int or row[name] < 1 for name in ("order", "epoch"))
                or not isinstance(row["reason"], str) or len(row["reason"]) > 256 or row["event_id"] in ids):
            raise ValueError("invalid_revocation_event_measurements")
        ids.add(row["event_id"])
        for name in ("task_id", "update_id", "manifest_id"):
            if row[name] is not None and (not isinstance(row[name], str) or not _ID.fullmatch(row[name])):
                raise ValueError("invalid_revocation_operation_identity")
        for prefix in ("response", "censor"):
            lower, upper = row[prefix + "_lower_ms"], row[prefix + "_upper_ms"]
            required = row["status"] == ("measured" if prefix == "response" else "right-censored")
            if required and (not _number(lower) or not _number(upper) or lower > upper) or not required and (lower is not None or upper is not None):
                raise ValueError("invalid_revocation_interval_bounds")
        if row["status"] == "measured":
            if (row["operation"] not in {"issue", "receive", "publish"} or type(row["operation_sequence"]) is not int or row["operation_sequence"] < 1
                    or type(row["enforcement_order"]) is not int or row["enforcement_order"] < row["order"]):
                raise ValueError("invalid_revocation_enforcement_binding")
        elif any(row[name] is not None for name in ("operation_sequence", "operation", "task_id", "update_id", "manifest_id", "enforcement_order")):
            raise ValueError("censored_or_missing_response_cannot_claim_enforcement")
    if value["opportunity_events"] is None:
        if (value["status"] != "missing" or value["events"] or value["operation_coverage_complete"]
                or any(value[name] != expected for name, expected in (("measured_events", 0), ("right_censored_events", 0), ("missing_events", None), ("measurement_errors", None)))):
            raise ValueError("unknown_revocation_opportunities_must_stay_missing")
    else:
        counts = {state: sum(row["status"] == state for row in value["events"]) for state in ("measured", "right-censored", "missing")}
        if (value["opportunity_events"] != len(value["events"]) or value["measured_events"] != counts["measured"]
                or value["right_censored_events"] != counts["right-censored"] or value["missing_events"] != counts["missing"]
                or type(value["measurement_errors"]) is not int):
            raise ValueError("revocation_event_denominators_mismatch")
        expected = next(iter({row["status"] for row in value["events"]})) if value["events"] and len({row["status"] for row in value["events"]}) == 1 else "mixed" if value["events"] else "no-event"
        if not value["events"] and (not value["operation_coverage_complete"] or value["measurement_errors"]): expected = "missing"
        if value["status"] != expected or (value["measured_events"] or value["right_censored_events"]) and (not value["operation_coverage_complete"] or value["measurement_errors"]):
            raise ValueError("revocation_censor_or_status_claim_mismatch")
    return True

# Operational annotations do not change the model or its scientific protocol.
TRAINING_ANNOTATIONS = {"seed", "pilot_only", "confirmatory_frozen", "acceptance_status"}


def scientific_training(training):
    return {key: deepcopy(value) for key, value in training.items() if key not in TRAINING_ANNOTATIONS}


def scientific_data(data):
    return {key: deepcopy(value) for key, value in data.items() if key != "scope"}


def scientific_binding(plan):
    """Stable acceptance context, independent of gate timestamps and prose."""
    return {"source_sha256": plan["provenance"]["source_sha256"],
            "training_digest": digest(scientific_training(plan["training_candidate"])),
            "data_manifest_digest": plan["data_manifest_digest"],
            "image_digests": deepcopy(plan["provenance"]["image_digests"])}


def scientific_sources(root):
    """Inventory executable/proof inputs; never generated reports, secrets or prose.

    Training and data are bound separately by canonical content in the plan. A
    documentation edit or a refreshed cloud inventory must not invalidate a lock.
    """
    root = Path(root).resolve()
    patterns = {"src": {".py"}, "scripts": {".py"}, "tests": {".py"},
                "policies": {".rego", ".json"}, "schemas": {".json"},
                "infra": {".tf", ".lock", ".hcl"}, "containers": {".py", ".lock"}}
    paths = set()
    for directory, suffixes in patterns.items():
        for path in (root / directory).rglob("*"):
            if (path.is_file() and path.suffix in suffixes
                    and not {"__pycache__", ".terraform", "node_modules"} & set(path.parts)):
                paths.add(path)
    for name in ("pyproject.toml", "requirements.lock", "requirements-runtime.lock", "requirements-analysis.in", "requirements-analysis.lock", "containers/Dockerfile"):
        if (root / name).is_file():
            paths.add(root / name)
    if any(path.is_symlink() or not path.resolve().is_relative_to(root) for path in paths):
        raise ValueError("scientific_source_symlink_forbidden")
    return {path.relative_to(root).as_posix(): file_digest(path) for path in sorted(paths)}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _hash(value):
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _public_fields(value):
    """Reject obvious credential payloads at every public configuration level."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "source_files_sha256" and isinstance(item, dict) and all(_hash(entry) for entry in item.values()):
                continue
            if re.search(r"password|secret|credential|access_key|private_key|patient_records|encounter_id", key, re.I):
                raise ValueError("private_payload_forbidden_in_public_experiment_metadata")
            _public_fields(item)
    elif isinstance(value, list):
        for item in value:
            _public_fields(item)
    elif isinstance(value, str) and (re.search(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", value) or "-----BEGIN" in value):
        raise ValueError("credential_material_forbidden_in_public_experiment_metadata")


def policy_schedule(scenario, seed, timing):
    """Declarative barriers, interpreted by the runner using authority order."""
    target = f"org_{random.Random(seed).randrange(1, 9):02d}"
    triggers = {
        "S0": [],
        "S1": [{"barrier": "before-round-2-dispatch", "action": "REVOKE"}],
        "S2": [{"barrier": "after-round-1-dispatch-before-receipt", "action": "REVOKE"}],
        "S3": [{"barrier": "after-round-1-dispatch-before-receipt", "action": "REVOKE"},
               {"barrier": "after-revocation-commit", "action": "RELEASE_DELAYED_UPDATE", "delay_ms": timing["delayed_update_ms"]}],
        "S4": [{"barrier": "after-round-1-dispatch-before-receipt", "action": "REVOKE"},
               {"barrier": "after-revocation-commit-before-original-receipt", "action": "GRANT"}],
        "S5": [{"barrier": "after-round-1-dispatch-before-receipt", "action": "EXPIRE"}],
        "S6": [{"barrier": "candidate-staged-before-manifest-transaction", "action": "REVOKE"}],
        "S7": [{"barrier": "before-receipt", "action": "DUPLICATE_REORDER_RESTART"}],
        "S8": [{"barrier": "before-manifest-transaction", "action": "AUDIT_OR_OPA_OUTAGE_AND_TAMPER_COPIES"}],
    }
    if scenario not in triggers:
        raise ValueError("unknown_policy_scenario")
    return {"schema_version": "0.1.0", "scenario_id": scenario, "seed": seed,
            "target_org": target, "initial_grants": [f"org_{i:02d}" for i in range(1, 9)],
            "events": [dict(event, org_id=target) for event in triggers[scenario]],
            "ordering": "authority-committed-inclusive-interval", "fictional_organizations": True}


def build_plan(config, training, data_manifest, provenance):
    config, training, data_manifest, provenance = map(deepcopy, (config, training, data_manifest, provenance))
    for public in (config, training, provenance):
        _public_fields(public)
    if (set(config) != {"schema_version", "protocol_id", "training_config", "data_manifest", "seeds", "baselines", "distributions", "primary_scenarios", "targeted_scenarios", "analysis", "resources", "selection", "timing", "execution", "robustness_registry"}
            or set(provenance) != {"source_files_sha256", "source_sha256", "image_digests", "git_commit"}
            or not provenance["source_files_sha256"] or any(not _hash(value) for value in provenance["source_files_sha256"].values())
            or provenance["source_sha256"] != digest(provenance["source_files_sha256"])
            or (provenance["git_commit"] is not None and not re.fullmatch(r"[0-9a-f]{40}", provenance["git_commit"]))):
        raise ValueError("public_hash_only_configuration_and_provenance_required")
    for name in provenance["source_files_sha256"]:
        if (not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts
                or "\\" in name or name.startswith(".") or any(part in {"data", "results", ".terraform"} for part in Path(name).parts)):
            raise ValueError("public_relative_source_inventory_required")
    if any(not isinstance(value, str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", value) for value in provenance["image_digests"].values()):
        raise ValueError("immutable_registry_image_references_required")
    if (config.get("baselines") != BASELINES or config.get("distributions") != DISTRIBUTIONS
            or config.get("primary_scenarios") != PRIMARY_SCENARIOS or config.get("seeds") != SEEDS
            or len(set(SEEDS)) != 5 or config.get("execution") != {"confirmatory_enabled": False, "final_test_access_permitted": False}):
        raise ValueError("locked_primary_factor_contract_required")
    analysis = config["analysis"]
    if (analysis.get("confidence_level") != 0.95 or analysis.get("h4_noninferiority_margin") != 0.02
            or analysis.get("h4_one_sided") is not True or analysis.get("minimum_independent_seeds") != 5
            or analysis.get("bootstrap_method") != "paired-percentile-seed-clusters"
            or not isinstance(analysis.get("bootstrap_resamples"), int) or analysis["bootstrap_resamples"] < 1000):
        raise ValueError("prespecified_statistical_contract_required")
    if (training.get("classification_threshold") != 0.5 or training.get("num_rounds", 0) < 2
            or training.get("final_test_access_permitted") is not False or config["resources"]["client_count"] != 8):
        raise ValueError("candidate_training_or_topology_contract_invalid")
    artifacts = data_manifest["private_artifacts_sha256"]
    if not all(_hash(artifacts.get(f"{distribution}/org_{i:02d}.csv")) for distribution in DISTRIBUTIONS for i in range(1, 9)):
        raise ValueError("complete_frozen_partition_hashes_required")
    if not all(data_manifest.get("checks", {}).get(key) is True for key in ("patient_disjoint_splits", "preprocessing_fit_training_only", "test_holdout_frozen")):
        raise ValueError("data_leakage_and_holdout_checks_required")
    shared_training = scientific_training(training)
    data_digest = digest(scientific_data(data_manifest))
    common = {"training": shared_training, "resources": config["resources"], "selection": config["selection"],
              "data_manifest_digest": data_digest, "source": {key: value for key, value in provenance.items() if key != "git_commit"},
              "preprocessor_sha256": artifacts["preprocessor.json"], "test_holdout_sha256": artifacts["test.csv"],
              "validation_sha256": artifacts["validation.csv"], "analysis": analysis}
    primary, targeted, ablations, replications = [], [], [], []

    def cell(baseline, distribution, scenario, seed, family, variant=None):
        schedule = policy_schedule(scenario, seed, config["timing"])
        shared = {**deepcopy(common), "distribution": distribution, "seed": seed,
                  "initialization_seed": seed,
                  "partition_hashes": {org: artifacts[f"{distribution}/{org}.csv"] for org in schedule["initial_grants"]},
                  "policy_schedule": schedule, "policy_schedule_hash": digest(schedule)}
        match_id = f"{distribution}-{scenario}-{seed}"
        record = {"family": family, "baseline_id": baseline, "distribution": distribution, "scenario_id": scenario,
                  "seed": seed, "match_id": match_id, "equivalence_hash": digest(shared), "shared_config": shared,
                  "variant": variant, "unsafe_comparator": variant in {"Abl-2", "Abl-3", "Abl-4"},
                  "requires_fresh_deployment": family == "replication", "final_test_access_permitted": False}
        record["cell_id"] = family + "-" + digest(record)[:24]
        return record

    for distribution in DISTRIBUTIONS:
        for scenario in PRIMARY_SCENARIOS:
            for seed in SEEDS:
                for baseline in BASELINES:
                    primary.append(cell(baseline, distribution, scenario, seed, "primary"))
        for scenario in config["targeted_scenarios"]:
            for seed in SEEDS:
                targeted.append(cell("P1", distribution, scenario, seed, "targeted"))
        for variant, scenario in {"Abl-1": "S2", "Abl-2": "S6", "Abl-3": "S8", "Abl-4": "S4"}.items():
            for seed in SEEDS:
                ablations.append(cell("P1", distribution, scenario, seed, "ablation", variant))
        for scenario in ("S2", "S3"):
            for baseline in ("B3", "P1"):
                replications.append(cell(baseline, distribution, scenario, SEEDS[0], "replication"))
    plan = {"schema_version": "0.1.0", "protocol_id": config["protocol_id"], "status": "candidate_locked",
            "confirmatory_execution_enabled": False, "final_test_access_permitted": False,
            "configuration": config, "training_candidate": training, "data_manifest_digest": data_digest,
            "scientific_binding_version": "1",
            "provenance": provenance, "primary_cells": primary, "targeted_cells": targeted,
            "ablation_cells": ablations, "replication_cells": replications,
            "robustness_registry": {"status": "registered-not-scheduled", "grid": config["robustness_registry"]},
            "acceptance": None,
            "blockers": ["P8 acceptance evidence required", "confirmatory training protocol not yet accepted",
                         "final holdout requires separate authorized confirmatory evaluation"]}
    plan["plan_digest"] = digest(plan)
    validate_plan(plan)
    return plan


def validate_plan(plan):
    _public_fields(plan)
    if not isinstance(plan, dict) or plan.get("plan_digest") != digest({key: value for key, value in plan.items() if key != "plan_digest"}):
        raise ValueError("experiment_plan_digest_mismatch")
    cells = plan["primary_cells"]
    expected = {(baseline, distribution, scenario, seed) for baseline in BASELINES for distribution in DISTRIBUTIONS for scenario in PRIMARY_SCENARIOS for seed in SEEDS}
    actual = [(c["baseline_id"], c["distribution"], c["scenario_id"], c["seed"]) for c in cells]
    if len(cells) != 160 or set(actual) != expected or len(set(actual)) != 160:
        raise ValueError("complete_locked_160_cell_matrix_required")
    groups = {}
    all_cells = sum((plan[name] for name in ("primary_cells", "targeted_cells", "ablation_cells", "replication_cells")), [])
    if len({c["cell_id"] for c in all_cells}) != len(all_cells):
        raise ValueError("duplicate_experiment_cell_identity")
    for cell in all_cells:
        if cell["equivalence_hash"] != digest(cell["shared_config"]):
            raise ValueError("experiment_shared_configuration_digest_mismatch")
        schedule = cell["shared_config"]["policy_schedule"]
        if cell["shared_config"]["policy_schedule_hash"] != digest(schedule):
            raise ValueError("experiment_schedule_digest_mismatch")
        body = {key: value for key, value in cell.items() if key != "cell_id"}
        if cell["cell_id"] != cell["family"] + "-" + digest(body)[:24]:
            raise ValueError("experiment_cell_digest_mismatch")
        if cell["family"] == "primary":
            groups.setdefault(cell["match_id"], []).append(cell)
    if any(len(group) != 4 or len({c["equivalence_hash"] for c in group}) != 1 for group in groups.values()):
        raise ValueError("paired_full_manifest_equivalence_failed")
    if plan["status"] not in {"candidate_locked", "accepted_frozen"}:
        raise ValueError("unknown_experiment_plan_status")
    if plan["status"] == "accepted_frozen":
        acceptance = plan.get("acceptance") or {}
        if (set(acceptance.get("gates", {})) != GATES or plan.get("confirmatory_execution_enabled") is not True
                or plan["training_candidate"].get("confirmatory_frozen") is not True
                or plan["training_candidate"].get("pilot_only") is not False
                or any(ref.get("passed") is not True or not _hash(ref.get("sha256")) for ref in acceptance["gates"].values())):
            raise ValueError("accepted_plan_evidence_required")
    if plan.get("final_test_access_permitted") is not False:
        raise ValueError("plan_does_not_authorize_final_holdout_access")
    return True


def freeze_plan(plan, acceptance, root):
    """Accept only explicit, hash-checked passing gate artifacts; never run data."""
    validate_plan(plan)
    if (plan["status"] != "candidate_locked" or plan.get("scientific_binding_version") != "1"
            or set(acceptance.get("gates", {})) != GATES):
        raise ValueError("complete_p8_gate_evidence_required")
    root = Path(root).resolve()
    for gate_id, reference in acceptance["gates"].items():
        path = (root / reference["path"]).resolve()
        if not path.is_relative_to(root) or not _hash(reference.get("sha256")) or file_digest(path) != reference["sha256"]:
            raise ValueError("acceptance_gate_artifact_digest_mismatch")
        report = json.loads(path.read_text(encoding="utf-8"))
        if (reference.get("passed") is not True or report.get("successful") is not True
                or report.get("gate_id") != gate_id or report.get("candidate_plan_digest") != plan["plan_digest"]):
            raise ValueError("acceptance_gate_not_passed")
        validate_gate_report(plan, gate_id, report, root)
    training = plan["training_candidate"]
    images = plan["provenance"].get("image_digests", {})
    if (training.get("pilot_only") is not False
            or not _hash(plan["provenance"].get("source_sha256")) or not images
            or any(not isinstance(value, str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", value) for value in images.values())):
        raise ValueError("frozen_training_source_and_registry_images_required")
    for name, expected in plan["provenance"]["source_files_sha256"].items():
        source = (root / name).resolve()
        if not source.is_relative_to(root) or not source.is_file() or file_digest(source) != expected:
            raise ValueError("source_changed_since_candidate_lock")
    result = deepcopy(plan)
    # Acceptance is the transition; editing a candidate annotation beforehand
    # would change the very digest that its gate reports are required to bind.
    result["training_candidate"].update(confirmatory_frozen=True, acceptance_status="accepted-by-hash-bound-gates")
    result.update(status="accepted_frozen", confirmatory_execution_enabled=True, acceptance=deepcopy(acceptance),
                  blockers=["final holdout requires separate authorized confirmatory evaluation"])
    result.pop("plan_digest")
    result["plan_digest"] = digest(result)
    validate_plan(result)
    return result


def validate_gate_report(plan, gate_id, report, root):
    """Verify an operator assessment and its actual immutable evidence files.

    This validates completeness/binding, not the truth of a naked assertion.
    The named checks are explicit scientific review obligations; the assessment
    must retain the real reports and state who performed that review.
    """
    root = Path(root).resolve()
    if (gate_id not in GATES or report.get("kind") != "scientific-gate-assessment"
            or report.get("gate_id") != gate_id or report.get("candidate_plan_digest") != plan["plan_digest"]
            or report.get("scientific_binding") != scientific_binding(plan)
            or set(report.get("checks", {})) != GATE_CHECKS[gate_id]
            or any(value is not True for value in report["checks"].values())
            or report.get("successful") is not True
            or not isinstance(report.get("reviewer"), str) or not _ID.fullmatch(report["reviewer"])
            or not isinstance(report.get("evidence"), list) or not report["evidence"]):
        raise ValueError("complete_matching_scientific_gate_assessment_required")
    for ref in report["evidence"]:
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or not _hash(ref["sha256"]):
            raise ValueError("gate_evidence_reference_required")
        path = (root / ref["path"]).resolve()
        if (not path.is_relative_to(root) or path.is_symlink() or not path.is_file()
                or file_digest(path) != ref["sha256"]):
            raise ValueError("gate_underlying_evidence_digest_mismatch")
        leaf = json.loads(path.read_text(encoding="utf-8"))
        if leaf.get("successful") is not True:
            raise ValueError("gate_underlying_report_not_successful")
        if (("candidate_plan_digest" in leaf and leaf["candidate_plan_digest"] != plan["plan_digest"])
                or ("scientific_binding" in leaf and leaf["scientific_binding"] != scientific_binding(plan))):
            raise ValueError("gate_underlying_scientific_context_mismatch")
    _public_fields(report)
    return True


def validate_attempt(plan, row, *, _plan_validated=False):
    if not _plan_validated:
        validate_plan(plan)
    _public_fields(row)
    required = {"attempt_id", "cell_id", "plan_digest", "equivalence_hash", "status", "reason_code", "started_at_utc", "finished_at_utc", "metrics", "evidence", "execution"}
    if not isinstance(row, dict) or set(row) not in (required, required | {"observation"}):
        raise ValueError("aggregate_attempt_schema_required")
    cells = {c["cell_id"]: c for family in ("primary_cells", "targeted_cells", "ablation_cells", "replication_cells") for c in plan[family]}
    observation = row.get("observation", {})
    development = observation.get("scope") == "development"
    if observation:
        if (set(observation) != {"scope", "baseline_id", "source_cell_id", "missing_metrics", "exclusion_reasons", "measurement_sources"}
                or observation["scope"] not in {"development", "registered"}
                or observation["baseline_id"] not in BASELINES
                or not isinstance(observation["source_cell_id"], str) or not _ID.fullmatch(observation["source_cell_id"])
                or not isinstance(observation["missing_metrics"], list) or set(observation["missing_metrics"]) - COUNT_METRICS
                or not isinstance(observation["exclusion_reasons"], list)
                or any(not isinstance(reason, str) or not _ID.fullmatch(reason) for reason in observation["exclusion_reasons"])
                or not isinstance(observation["measurement_sources"], dict)
                or any(key not in COUNT_METRICS | UTILITY_METRICS | OTHER_METRICS or not isinstance(value, str) or len(value) > 512
                       for key, value in observation["measurement_sources"].items())):
            raise ValueError("bounded_aggregate_observation_metadata_required")
    if (row["plan_digest"] != plan["plan_digest"]
            or (development and (row["cell_id"] in cells or row["equivalence_hash"] is not None or row["status"] == "successful"))
            or (not development and (row["cell_id"] not in cells or row["equivalence_hash"] != cells[row["cell_id"]]["equivalence_hash"]))
            or not isinstance(row["attempt_id"], str) or not _ID.fullmatch(row["attempt_id"])
            or row["status"] not in STATUSES or not isinstance(row["reason_code"], str) or not _ID.fullmatch(row["reason_code"])):
        raise ValueError("attempt_identity_or_locked_configuration_mismatch")
    metrics = row["metrics"]
    try:
        times = [datetime.fromisoformat(row[key].replace("Z", "+00:00")) for key in ("started_at_utc", "finished_at_utc")]
        if any(value.tzinfo is None for value in times) or times[1] < times[0]:
            raise ValueError("invalid_attempt_timestamps")
    except (ValueError, TypeError, AttributeError):
        raise ValueError("invalid_attempt_timestamps") from None
    if not isinstance(metrics, dict) or set(metrics) - COUNT_METRICS - UTILITY_METRICS - OTHER_METRICS:
        raise ValueError("unknown_or_record_level_metric_fields")
    for key in COUNT_METRICS & set(metrics):
        if type(metrics[key]) is not int or metrics[key] < 0:
            raise ValueError("invalid_aggregate_count")
    for numerator, denominator in (("oracle_invalid_incorporations", "oracle_invalid_presented"), ("oracle_valid_rejections", "oracle_valid_presented"),
            ("audit_complete_decisions", "final_decisions"), ("audit_record_sets_verified", "audit_record_sets_tested"), ("tamper_detected", "tamper_attempted"),
            ("accepted_updates", "unique_presented_updates"), ("accepted_clients", "selected_eligible_clients")):
        if numerator in metrics and denominator in metrics and metrics[numerator] > metrics[denominator]:
            raise ValueError("aggregate_numerator_exceeds_denominator")
    for key in UTILITY_METRICS & set(metrics):
        if metrics[key] is not None and (not _number(metrics[key]) or metrics[key] > 1):
            raise ValueError("invalid_aggregate_utility_metric")
    if metrics.get("evaluation_split", "none") not in {"none", "validation", "test"} or metrics.get("data_kind", "clinical") not in {"clinical", "synthetic_test"}:
        raise ValueError("unknown_evaluation_scope")
    if metrics.get("evaluation_split") == "test" and (plan["status"] != "accepted_frozen" or row["execution"].get("final_holdout_authorized") is not True):
        raise ValueError("final_holdout_execution_not_authorized")
    if metrics.get("threshold", 0.5) != 0.5:
        raise ValueError("frozen_classification_threshold_required")
    if "revocation_response_ms" in metrics and metrics["revocation_response_ms"] is not None and not _number(metrics["revocation_response_ms"]):
        raise ValueError("scalar_revocation_response_required")
    if "revocation_response_censored" in metrics and type(metrics["revocation_response_censored"]) is not bool:
        raise ValueError("typed_revocation_censoring_required")
    if "revocation_response" in metrics:
        validate_revocation_response(metrics["revocation_response"])
        if metrics.get("revocation_response_ms") is not None or "revocation_response_censored" in metrics:
            raise ValueError("bounded_response_cannot_claim_legacy_exact_scalar")
    for series, values in metrics.get("latency_ms", {}).items():
        if series not in LATENCY_SERIES or not isinstance(values, list) or any(not _number(value) for value in values):
            raise ValueError("invalid_latency_measurements")
    costs = metrics.get("cost_usd", {})
    if costs:
        components = {"compute", "network", "storage", "logging", "api", "idle", "control"}
        if (set(costs) != components | {"total", "measurement"} or costs["measurement"] not in {"measured", "inferred"}
                or any(not _number(costs[key]) for key in components | {"total"})
                or not math.isclose(sum(costs[key] for key in components), costs["total"], rel_tol=1e-9, abs_tol=1e-9)):
            raise ValueError("invalid_or_incomplete_cost_accounting")
    resources = metrics.get("resources", {})
    if set(resources) - {"vcpu_seconds", "memory_gib_seconds", "cpu_seconds"} or any(not _number(value) for value in resources.values()):
        raise ValueError("invalid_resource_measurements")
    if (set(row["evidence"]) - {"raw_result_sha256", "oracle_report_sha256", "audit_report_sha256", "topology_report_sha256", "ingestion_report_sha256"}
            or any(not _hash(value) for value in row["evidence"].values())):
        raise ValueError("hash_only_evidence_references_required")
    execution = row["execution"]
    if not isinstance(execution, dict) or set(execution) - {"deployment_id", "namespace", "task_definition_digest", "client_task_ids", "eight_separate_fargate_clients", "final_holdout_authorized"}:
        raise ValueError("unknown_execution_metadata")
    for key in ("deployment_id", "namespace"):
        if key in execution and (not isinstance(execution[key], str) or not _ID.fullmatch(execution[key])):
            raise ValueError("bounded_execution_identifiers_required")
    if "task_definition_digest" in execution and not _hash(execution["task_definition_digest"]):
        raise ValueError("hashed_task_definition_required")
    if "client_task_ids" in execution and (not isinstance(execution["client_task_ids"], list)
            or len(execution["client_task_ids"]) > 8 or any(not isinstance(value, str) or len(value) > 256 for value in execution["client_task_ids"])):
        raise ValueError("bounded_client_task_identifiers_required")
    for key in ("eight_separate_fargate_clients", "final_holdout_authorized"):
        if key in execution and type(execution[key]) is not bool:
            raise ValueError("typed_execution_flags_required")
    if row["status"] == "successful" and (not COUNT_METRICS <= set(metrics) or not {"raw_result_sha256", "oracle_report_sha256", "audit_report_sha256", "topology_report_sha256"} <= set(row["evidence"])):
        raise ValueError("successful_attempt_requires_complete_counts_and_evidence")
    return True


def load_attempts(path, plan):
    validate_plan(plan)
    path = Path(path)
    if not path.exists():
        return []
    previous, attempts, ids = "0" * 64, [], set()
    for sequence, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        record = json.loads(line)
        if (set(record) != {"sequence", "prev_hash", "attempt", "event_hash"} or record["sequence"] != sequence
                or record["prev_hash"] != previous or record["event_hash"] != digest({key: record[key] for key in ("sequence", "prev_hash", "attempt")})):
            raise ValueError("experiment_attempt_chain_broken")
        validate_attempt(plan, record["attempt"], _plan_validated=True)
        if record["attempt"]["attempt_id"] in ids:
            raise ValueError("duplicate_experiment_attempt_id")
        ids.add(record["attempt"]["attempt_id"])
        attempts.append(record["attempt"])
        previous = record["event_hash"]
    return attempts


def append_attempt(path, plan, row):
    """Single durable writer, exclusive lock, hash-linked append, no replacement."""
    validate_attempt(plan, row)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(path.suffix + ".lock")
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        attempts = load_attempts(path, plan)
        if row["attempt_id"] in {record["attempt_id"] for record in attempts}:
            raise ValueError("duplicate_experiment_attempt_id")
        previous = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])["event_hash"] if attempts else "0" * 64
        body = {"sequence": len(attempts) + 1, "prev_hash": previous, "attempt": row}
        with path.open("ab") as stream:
            stream.write(canonical({**body, "event_hash": digest(body)}) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
        lock.unlink()


def derive_verified_metrics(raw, summary):
    """Extract aggregate observations only after independent case verification.

    No absent instrument is converted to zero. Transaction counts are committed
    run-namespace outcomes, not SDK calls or global governance overhead.
    """
    from .oracle import evaluate_interval
    if summary.get("successful") is not True or summary.get("audit_verified") is not True:
        raise ValueError("independently_verified_case_required")
    metrics, sources = {}, {}
    for key in ("unique_presented_updates", "oracle_invalid_presented", "oracle_invalid_incorporations",
                "oracle_valid_rejections", "accepted_updates", "final_decisions", "published_models", "audit_complete_decisions"):
        if key in summary:
            metrics[key], sources[key] = summary[key], "independent-runtime-verifier." + key
    # Older verifier summaries expose only final_decisions; an audit-verified
    # exact final-decision chain establishes this count without a producer claim.
    if "audit_complete_decisions" not in metrics:
        metrics["audit_complete_decisions"] = summary["final_decisions"]
        sources["audit_complete_decisions"] = "independent-runtime-verifier.audit_verified+final_decisions"
    metrics["oracle_valid_presented"] = summary["unique_presented_updates"] - summary["oracle_invalid_presented"]
    sources["oracle_valid_presented"] = "verified-unique-presented-minus-verified-invalid"
    metrics.update(audit_record_sets_tested=1, audit_record_sets_verified=1)
    for name in ("audit_record_sets_tested", "audit_record_sets_verified"):
        sources[name] = "one-complete-export-independently-verified-this-ingestion"
    tasks, manifests, updates = raw["tasks"], raw["published_manifests"], {row["update_id"]: row for row in raw["updates"]}
    selection = raw.get("selection")
    if isinstance(selection, list):
        metrics["selected_eligible_clients"] = len({row["org_id"] for row in selection if row.get("selected") is True})
        sources["selected_eligible_clients"] = "distinct-organizations-selected-by-method-in-run;not-oracle-currently-eligible"
    members = {uid for manifest in manifests for uid in manifest["included_update_ids"]}
    metrics["accepted_clients"] = len({updates[uid]["org_id"] for uid in members})
    sources["accepted_clients"] = "distinct-organizations-in-verified-published-manifests"
    orders = [task["issue_order"] for task in tasks]
    ends = [manifest["commit_order"] for manifest in manifests] + [row["evaluation_order"] for row in raw["decisions"].values()]
    if orders and ends:
        revokes = [event for event in raw["policy_events"] if event["kind"] == "REVOKE" and min(orders) <= event["order"] <= max(ends)]
        metrics["revocations"] = len(revokes)
        sources["revocations"] = "REVOKE-events-within-issued-task-to-final-decision-authority-order-window"
        invalid_publications = set()
        for manifest in manifests:
            for uid in manifest["included_update_ids"]:
                update = updates[uid]
                query = {"org_id": update["org_id"], "purpose": update["purpose"], "start_order": update["start_order"],
                         "commit_order": manifest["commit_order"], "actions": ["train", "submit_update", "aggregate"]}
                if (not evaluate_interval(raw["policy_events"], query)["valid"]
                        and any(event["org_id"] == update["org_id"] and update["start_order"] <= event["order"] <= manifest["commit_order"] for event in revokes)):
                    invalid_publications.add(manifest["manifest_id"])
        metrics["post_revocation_invalid_publications"] = len(invalid_publications)
        sources["post_revocation_invalid_publications"] = "distinct-verified-manifests-with-oracle-invalid-member-crossing-REVOKE"
    records = raw.get("durable_evidence", {}).get("run_records")
    if isinstance(records, list):
        metrics["coordination_operations"] = sum(row.get("record_type") == "transaction_outcome" for row in records)
        sources["coordination_operations"] = "committed-run-namespace-transaction-outcome-rows;excludes-SDK-attempts-and-policy-writer"
    instrument = raw.get("measurement_manifest")
    if instrument is not None:
        if (not isinstance(instrument, dict) or set(instrument) != {"schema_version", "tamper_scope", "tamper_mode", "tamper_results"}
                or instrument["schema_version"] != "0.1.0" or instrument["tamper_scope"] != "this-runtime-invocation"
                or instrument["tamper_mode"] not in {"none_declared", "injected"} or not isinstance(instrument["tamper_results"], list)):
            raise ValueError("invalid_runtime_measurement_manifest")
        attacks = instrument["tamper_results"]
        if (any(not isinstance(attack, dict) or set(attack) != {"attack_id", "detected"}
                or not isinstance(attack["attack_id"], str) or not _ID.fullmatch(attack["attack_id"])
                or type(attack["detected"]) is not bool for attack in attacks)
                or len({attack["attack_id"] for attack in attacks}) != len(attacks)
                or (instrument["tamper_mode"] == "none_declared" and attacks)
                or (instrument["tamper_mode"] == "injected" and not attacks)):
            raise ValueError("invalid_actual_tamper_measurements")
        metrics.update(tamper_attempted=len(attacks), tamper_detected=sum(attack["detected"] for attack in attacks))
        for name in ("tamper_attempted", "tamper_detected"):
            sources[name] = "exact-raw-result.measurement_manifest;this-invocation-only"
    utility = summary.get("test_metrics") if summary.get("final_holdout_authorization_verified") else summary.get("validation_metrics")
    metrics.update(evaluation_split="test" if summary.get("final_holdout_authorization_verified") else "validation" if utility else "none", data_kind="clinical")
    if utility:
        metrics.update({name: utility[name] for name in UTILITY_METRICS if name in utility})
        for name in UTILITY_METRICS & set(metrics):
            sources[name] = "committed-aggregate-evaluation-response"
    latencies = {}
    if "policy_rpc_metrics" in raw:
        latencies["opa"] = [row["duration_ms"] for row in raw["policy_rpc_metrics"]]
    for name, field in (("round", "duration_seconds"), ("publication", "publication_seconds")):
        if isinstance(raw.get("rounds"), list) and all(field in row for row in raw["rounds"]):
            latencies[name] = [row[field] * 1000 for row in raw["rounds"]]
    if "revocation_response" in summary:
        validate_revocation_response(summary["revocation_response"])
        metrics["revocation_response"] = summary["revocation_response"]
        sources["revocation_response"] = "independent-runtime-verifier.authority-and-operation-bound-local-clock-brackets"
    if summary.get("runtime_observations_verified") is True:
        # Observer publication durations replace the coarser legacy series.
        latencies.update(summary["runtime_stage_latency_ms"])
    if latencies:
        metrics["latency_ms"], sources["latency_ms"] = latencies, "native-OPA-and-round-instrumentation;verified-observer-stage-intervals-where-present"
    return metrics, sources


def canonical_scenario_id(value):
    """Normalize only the versioned producer's nine documented scenario names."""
    if not isinstance(value, str):
        return None
    if value in {f"S{number}" for number in range(9)}:
        return value
    return {"stable": "S0", "between_round": "S1", "mid_round": "S2", "delayed": "S3",
        "revoke_regrant": "S4", "expiry": "S5", "near_commit": "S6", "duplicate_restart": "S7",
        "transport_fault": "S8"}.get(value)


def frozen_runtime_image_matches(plan, inventory):
    """Bind immutable runtime content to its actual owned ECR repository.

    Fresh deployment repositories may differ. Actual task/index/leaf relations
    remain independently checked by the ingestion caller's placement verifier.
    """
    pattern = (r"(?P<account>[0-9]{12})\.dkr\.ecr\.(?P<region>[a-z0-9-]+)\.amazonaws\.com/"
        r"(?P<repository>(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*)"
        r"@(?P<digest>sha256:[0-9a-f]{64})")
    expected_ref = plan.get("provenance", {}).get("image_digests", {}).get("runtime")
    actual_ref = inventory.get("image", {}).get("reference")
    if not isinstance(expected_ref, str) or not isinstance(actual_ref, str):
        return False
    expected, actual = re.fullmatch(pattern, expected_ref), re.fullmatch(pattern, actual_ref)
    owned = inventory.get("foundation", {}).get("image_repositories", {})
    if not expected or not actual or not isinstance(owned, dict):
        return False
    region = plan.get("configuration", {}).get("resources", {}).get("region")
    return (actual["digest"] == expected["digest"]
        and actual["account"] == expected["account"] == inventory.get("account_id")
        and actual["region"] == expected["region"] == inventory.get("region") == region
        and actual_ref.split("@", 1)[0] in owned.values())


def registered_runtime_matches(plan, cell, runtime, raw, inventory):
    """Bind actual prepared inputs to the entire matched scientific contract."""
    shared = cell["shared_config"]
    expected = {"plan_digest": plan["plan_digest"], "cell_id": cell["cell_id"], "match_id": cell["match_id"], "equivalence_hash": cell["equivalence_hash"]}
    scenario = canonical_scenario_id(cell.get("scenario_id"))
    if (scenario is None or any(raw.get(key) != value or runtime.get(key) != value for key, value in expected.items())
            or raw.get("baseline_id") != cell["baseline_id"] or canonical_scenario_id(raw.get("scenario_id")) != scenario
            or runtime.get("baseline_id") != cell["baseline_id"] or canonical_scenario_id(runtime.get("scenario_id")) != scenario
            or runtime.get("distribution") != cell["distribution"] or runtime.get("seed") != cell["seed"]
            or runtime.get("scenario_target_org") != shared["policy_schedule"]["target_org"]
            or scientific_training(runtime.get("training", {})) != shared["training"]
            or runtime.get("rounds") != shared["training"]["num_rounds"]
            or runtime.get("max_examples_per_client") != shared["training"]["max_examples_per_client"]
            or runtime.get("validation_max_examples") != shared["training"]["max_validation_examples"]
            or runtime.get("validation_source_sha256") != shared["validation_sha256"]
            or not frozen_runtime_image_matches(plan, inventory)):
        return False
    uploaded = {row.get("sha256") for row in inventory.get("uploads", []) if row.get("version_id") not in {None, "null", ""}}
    binding = runtime.get("experiment_binding", {})
    return (set(shared["partition_hashes"].values()) <= uploaded
            and binding.get("policy_schedule_hash") == shared["policy_schedule_hash"]
            and binding.get("source_sha256") == plan["provenance"]["source_sha256"]
            and all(binding.get(key) == expected[key] for key in ("plan_digest", "cell_id", "equivalence_hash")))
