"""Read strict aggregate exploratory summaries; never reopen models or records."""
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re

KIND = "independent-exploratory-robustness-summary"
SHA = re.compile(r"[0-9a-f]{64}")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
DEFAULTS = {"non_iid_alpha": .5, "revocations_per_round": 1, "participation_fraction": 1.0,
    "update_size_multiplier": 1, "artificial_latency_ms": 0, "client_clock_skew_ms": 0}
LEVELS = {"non_iid_alpha": [.1, .5, 1.0], "revocations_per_round": [0, 1, 4],
    "participation_fraction": [.5, .75, 1.0], "update_size_multiplier": [1, 4],
    "artificial_latency_ms": [0, 250, 1000], "client_clock_skew_ms": [-60000, 0, 60000]}
VERIFICATION = {"protected_witness", "weighted_models", "audit_complete", "evaluation_bound", "placement8", "selected_subset", "schedule_bound"}
COUNTS = {"assigned_tasks", "acknowledged_tasks", "presented_updates", "accepted_updates", "rejected_updates",
    "final_operational_errors", "indeterminate_tasks", "final_decisions", "audit_complete_decisions", "published_models",
    "oracle_invalid_presented", "oracle_invalid_incorporations"}
METRICS = COUNTS | {"validation_metrics", "round_durations_ms", "actual_selected_per_round", "parameter_bytes",
    "configured_reply_delay_ms", "reported_clock_offsets_ms"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite_robustness_json")))


def checked_reference(root, reference):
    if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
            or not isinstance(reference["path"], str) or not isinstance(reference["sha256"], str) or not SHA.fullmatch(reference["sha256"])):
        raise ValueError("strict_exploratory_evidence_reference_required")
    root, relative = Path(root).resolve(), Path(reference["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("owned_relative_exploratory_evidence_required")
    path = root / relative
    if (not path.is_file() or not path.resolve().is_relative_to(root) or path.suffix.lower() not in {".json", ".pem"}):
        raise ValueError("aggregate_json_or_public_key_evidence_only")
    for item in (path, *path.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("linked_exploratory_evidence_forbidden")
        if item == root: break
    if path.suffix.lower() == ".pem" and not path.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----"):
        raise ValueError("exploratory_public_key_only")
    if hashlib.sha256(path.read_bytes()).hexdigest() != reference["sha256"]:
        raise ValueError("exploratory_evidence_bytes_changed")
    return path


def exact_object(value, fields, reason):
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(reason)


def identifier(value, nullable=False):
    return value is None and nullable or isinstance(value, str) and ID.fullmatch(value) is not None


def exact_version(value):
    exact_object(value, {"bucket", "key", "version_id", "sha256", "size_bytes"}, "strict_exploratory_version_required")
    if (not isinstance(value["bucket"], str) or not value["bucket"] or not isinstance(value["key"], str)
            or any(part in {"", ".", ".."} for part in value["key"].split("/"))
            or not isinstance(value["version_id"], str) or value["version_id"] in {"", "null"}
            or not isinstance(value["sha256"], str) or not SHA.fullmatch(value["sha256"])
            or type(value["size_bytes"]) is not int or value["size_bytes"] < 0):
        raise ValueError("invalid_exploratory_exact_version")


def factors(value):
    exact_object(value, set(DEFAULTS), "exact_exploratory_factor_vector_required")
    if (any(type(value[key]) not in (int, float) or value[key] not in levels for key, levels in LEVELS.items())
            or any(type(value[key]) is not int for key in DEFAULTS if key not in {"non_iid_alpha", "participation_fraction"})
            or sum(value[key] != default for key, default in DEFAULTS.items()) > 1):
        raise ValueError("registered_one_factor_vector_required")


def factor_levels(value):
    return [[key, level] for key, levels in LEVELS.items() for level in levels if {**DEFAULTS, key: level} == value]


def metrics(value):
    exact_object(value, METRICS, "strict_exploratory_aggregate_metrics_required")
    integer = lambda number: type(number) is int and number >= 0
    finite = lambda number: type(number) in (int, float) and math.isfinite(number) and number >= 0
    if any(not integer(value[key]) for key in COUNTS | {"parameter_bytes", "configured_reply_delay_ms"}):
        raise ValueError("nonnegative_exploratory_counts_required")
    for numerator, denominator in (("accepted_updates", "presented_updates"), ("rejected_updates", "presented_updates"),
        ("oracle_invalid_incorporations", "oracle_invalid_presented"), ("audit_complete_decisions", "final_decisions")):
        if value[numerator] > value[denominator]: raise ValueError("exploratory_count_denominator_mismatch")
    durations = value["round_durations_ms"]
    selected = value["actual_selected_per_round"]
    offsets = value["reported_clock_offsets_ms"]
    if (not isinstance(durations, list) or len(durations) > 100 or any(not finite(number) for number in durations)
            or not isinstance(offsets, list) or len(offsets) > 1000 or any(type(number) is not int or number not in {-60000, 0, 60000} for number in offsets)
            or not isinstance(selected, list) or len(selected) > 100):
        raise ValueError("bounded_exploratory_round_observations_required")
    rounds = set()
    for row in selected:
        exact_object(row, {"round_id", "org_ids", "selected_count", "accepted_count"}, "strict_exploratory_selection_required")
        if (not identifier(row["round_id"]) or row["round_id"] in rounds or not isinstance(row["org_ids"], list)
                or len(set(row["org_ids"])) != len(row["org_ids"]) or not set(row["org_ids"]) <= {f"org_{number:02d}" for number in range(1, 9)}
                or not integer(row["selected_count"]) or not integer(row["accepted_count"])
                or row["selected_count"] != len(row["org_ids"]) or row["accepted_count"] > row["selected_count"]):
            raise ValueError("exploratory_selection_identity_or_counts_invalid")
        rounds.add(row["round_id"])
    validation = value["validation_metrics"]
    if validation is not None:
        exact_object(validation, {"count", "positive_count", "prevalence", "auroc", "auprc", "precision", "recall", "f1", "threshold", "loss"}, "aggregate_validation_metrics_only")
        if (not integer(validation["count"]) or not validation["count"] or not integer(validation["positive_count"])
                or validation["positive_count"] > validation["count"] or validation["threshold"] != .5
                or any(not finite(number) or key != "loss" and number > 1 for key, number in validation.items()
                       if key not in {"count", "positive_count"} and not (key in {"auroc", "auprc"} and number is None))
                or validation["prevalence"] != validation["positive_count"] / validation["count"]):
            raise ValueError("invalid_exploratory_validation_summary")


def normalize(report, *, root, plan_digest, report_alias, report_sha256):
    top = {"schema_version", "kind", "plan_digest", "registry_digest", "normalization_complete", "successful", "independent_seed_count",
        "confirmatory", "evaluation_split", "final_test_accessed", "data_kind", "inputs", "cases", "attempts", "excluded_preparation_attempts", "limitations"}
    exact_object(report, top, "strict_normalized_exploratory_summary_required")
    if (report["schema_version"] != "0.1.0" or report["kind"] != KIND or report["plan_digest"] != plan_digest
            or not isinstance(report["registry_digest"], str) or not SHA.fullmatch(report["registry_digest"])
            or report["independent_seed_count"] != 1 or type(report["independent_seed_count"]) is not int
            or report["confirmatory"] is not False or report["evaluation_split"] != "validation"
            or report["final_test_accessed"] is not False or report["data_kind"] != "clinical"
            or type(report["successful"]) is not bool or type(report["normalization_complete"]) is not bool
            or not isinstance(report["limitations"], list) or any(not isinstance(text, str) for text in report["limitations"])):
        raise ValueError("clinical_n1_validation_descriptive_scope_required")
    if not isinstance(report["inputs"], list) or not report["inputs"]:
        raise ValueError("hash_bound_exploratory_registry_inputs_required")
    bound = {}
    registries = []
    for reference in report["inputs"]:
        path = checked_reference(root, reference)
        bound[reference["sha256"]] = path
        if path.suffix == ".json":
            body = read_json(path)
            if isinstance(body, dict) and body.get("kind") == "exploratory-robustness-registry":
                registries.append(body)
    if len(registries) != 1:
        raise ValueError("one_exact_exploratory_registry_required")
    registry = registries[0]
    if (registry.get("registry_digest") != report["registry_digest"]
            or digest({key: value for key, value in registry.items() if key != "registry_digest"}) != report["registry_digest"]
            or registry.get("reference_main_plan_digest") != plan_digest or registry.get("independent_seed_count") != 1
            or registry.get("execution_authorized") is not False or registry.get("final_holdout_accessed") is not False
            or registry.get("actual_cloud_trials_executed") != 0):
        raise ValueError("exploratory_registry_digest_or_main_plan_mismatch")
    if (not isinstance(registry.get("cases"), list) or not 1 <= len(registry["cases"]) <= 24
            or len({row["case_id"] for row in registry["cases"]}) != len(registry["cases"])):
        raise ValueError("bounded_unique_planned_exploratory_cases_required")
    planned = {row["case_id"]: row for row in registry["cases"]}
    if (not isinstance(report["cases"], list) or len(report["cases"]) != len(planned)
            or {row["case_id"] for row in report["cases"]} != set(planned)
            or report["excluded_preparation_attempts"] != registry.get("excluded_preparation_attempts")):
        raise ValueError("complete_exploratory_case_and_preparation_coverage_required")
    if not isinstance(report["attempts"], list) or len(report["attempts"]) > 1000:
        raise ValueError("bounded_all_exploratory_attempts_required")
    attempts, by_case = {}, {case: [] for case in planned}
    attempt_fields = {"attempt_id", "case_id", "application_campaign_id", "run_id", "index", "raw_result", "execution_successful", "verification", "status", "reason", "metrics", "evidence_refs"}
    for row in report["attempts"]:
        exact_object(row, attempt_fields, "strict_exploratory_attempt_required")
        if (not identifier(row["attempt_id"]) or row["attempt_id"] in attempts or row["case_id"] not in planned
                or not identifier(row["application_campaign_id"]) or type(row["execution_successful"]) is not bool
                or row["status"] not in {"successful", "failed", "unverified"} or not isinstance(row["reason"], str)
                or not isinstance(row["evidence_refs"], list)):
            raise ValueError("unique_bound_exploratory_attempt_required")
        exact_object(row["verification"], VERIFICATION, "exact_exploratory_verification_fields_required")
        if any(type(flag) is not bool for flag in row["verification"].values()):
            raise ValueError("typed_exploratory_verification_required")
        refs = dict(bound)
        for reference in row["evidence_refs"]:
            path = checked_reference(root, reference)
            refs[reference["sha256"]] = path
        prefix = "evidence/campaigns/" + row["application_campaign_id"] + "/"
        exact_version(row["index"])
        if row["attempt_id"] != "exploratory-attempt-" + digest([row["index"], row["case_id"]])[:32]:
            raise ValueError("exploratory_attempt_identity_not_bound_to_source_index_version")
        if (not re.fullmatch(re.escape(prefix) + r"(?:campaign_result|index-[0-9]{4,})\.json", row["index"]["key"])
                or row["index"]["sha256"] not in refs or refs[row["index"]["sha256"]].suffix != ".json"
                or refs[row["index"]["sha256"]].stat().st_size != row["index"]["size_bytes"]):
            raise ValueError("exploratory_index_version_bytes_not_bound")
        index = read_json(refs[row["index"]["sha256"]])
        indexed_cases = [case for case in index.get("cases", []) if case.get("cell_id") == row["case_id"]]
        if index.get("campaign_id") != row["application_campaign_id"] or len(indexed_cases) != 1:
            raise ValueError("exploratory_producer_index_application_or_case_mismatch")
        raw_key = prefix + row["case_id"] + "/runtime_result.json"
        indexed_raw = [value for value in indexed_cases[0].get("artifacts", []) if value.get("key") == raw_key]
        if row["raw_result"] is not None:
            exact_version(row["raw_result"])
            raw = row["raw_result"]
            if (not identifier(row["run_id"]) or raw["key"] != prefix + row["case_id"] + "/runtime_result.json"
                    or raw["bucket"] != row["index"]["bucket"] or raw["sha256"] not in refs
                    or refs[raw["sha256"]].suffix != ".json" or refs[raw["sha256"]].stat().st_size != raw["size_bytes"]
                    or len(indexed_raw) != 1 or any(indexed_raw[0].get(key) != raw[key] for key in raw)):
                raise ValueError("exploratory_raw_identity_or_version_bytes_mismatch")
            body = read_json(refs[raw["sha256"]])
            source = planned[row["case_id"]]
            if (body.get("persistent_run_id") != row["run_id"]
                    or row["execution_successful"] is not (body.get("successful") is True and indexed_cases[0].get("successful") is True)):
                raise ValueError("exploratory_actual_run_or_execution_flag_mismatch")
            if row["status"] == "successful" and (body.get("cell_id") != row["case_id"]
                    or body.get("cloud_campaign_id") != row["application_campaign_id"]
                    or body.get("robustness") != source["robustness"] or body.get("seed") != source["seed"]
                    or body.get("distribution") != source["distribution"] or body.get("registered_primary_case") is not False
                    or body.get("test_holdout_evaluated") is not False or body.get("data_kind", "clinical") != "clinical"
                    or body.get("kind") != "exploratory_robustness_validation" or body.get("aws_used") is not True):
                raise ValueError("exploratory_unchanged_raw_identity_or_scope_mismatch")
        elif row["run_id"] is not None or indexed_raw:
            raise ValueError("missing_raw_cannot_invent_exploratory_run_id")
        if row["metrics"] is not None:
            metrics(row["metrics"])
            if not all(row["verification"].values()):
                raise ValueError("exploratory_numeric_metrics_require_all_verifications")
        verified_success = row["execution_successful"] and all(row["verification"].values()) and row["raw_result"] is not None
        if (row["status"] == "successful") != bool(verified_success):
            raise ValueError("exploratory_success_requires_all_protected_verifications")
        if row["status"] == "successful" and (row["metrics"] is None
                or row["metrics"]["published_models"] > 0 and row["metrics"]["validation_metrics"] is None):
            raise ValueError("successful_exploratory_clinical_metrics_required")
        attempts[row["attempt_id"]] = row; by_case[row["case_id"]].append(row)
    cases = []
    case_fields = {"case_id", "group_id", "seed", "distribution", "factors", "factor_levels", "adapter_source_sha256", "adapter_image",
        "reference_main_plan_digest", "status", "attempt_ids", "metrics"}
    for row in report["cases"]:
        exact_object(row, case_fields, "strict_exploratory_case_required")
        source, observations = planned[row["case_id"]], by_case[row["case_id"]]
        descriptor = source["robustness"]
        factors(row["factors"])
        levels = row["factor_levels"]
        if (not isinstance(levels, list) or any(not isinstance(pair, list) or len(pair) != 2 or pair[0] not in DEFAULTS for pair in levels)
                or len({pair[0] for pair in levels}) != len(levels) or dict(levels) != dict(factor_levels(row["factors"]))):
            raise ValueError("exploratory_factor_axis_references_mismatch")
        if (row["seed"] != 296 or type(row["seed"]) is not int or row["seed"] != source["seed"]
                or row["distribution"] not in {"iid", "non_iid"} or row["distribution"] != source["distribution"]
                or row["group_id"] != source["deployment_group"] or row["factors"] != descriptor["factors"]
                or row["factors"]["non_iid_alpha"] == .1 or row["distribution"] == "iid" and row["factors"]["non_iid_alpha"] != .5
                or descriptor.get("schema_version") != "0.1.0" or descriptor.get("protocol_id") != "pcfl-exploratory-robustness-v1"
                or descriptor.get("confirmatory") is not False or descriptor.get("evaluation_split") != "validation"
                or descriptor.get("final_test_access_permitted") is not False or descriptor.get("seed") != 296
                or descriptor.get("descriptor_digest") != digest({key: value for key, value in descriptor.items() if key != "descriptor_digest"})
                or row["case_id"] != "exploratory-" + digest([descriptor, row["distribution"]])[:24]
                or source.get("status") != "registered_not_run" or source.get("actual_cloud_trial") is not False
                or row["adapter_source_sha256"] != descriptor["adapter_source_sha256"]
                or row["adapter_image"] != descriptor["adapter_image"] or row["reference_main_plan_digest"] != plan_digest
                or descriptor["reference_main_plan_digest"] != plan_digest
                or not isinstance(row["adapter_source_sha256"], str) or not SHA.fullmatch(row["adapter_source_sha256"])
                or not isinstance(row["adapter_image"], str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", row["adapter_image"])
                or not isinstance(row["attempt_ids"], list) or len(set(row["attempt_ids"])) != len(row["attempt_ids"])
                or set(row["attempt_ids"]) != {item["attempt_id"] for item in observations}):
            raise ValueError("exploratory_case_factor_seed_image_or_attempt_binding_mismatch")
        expected_status = "unattempted" if not observations else "multiple-attempts" if len(observations) > 1 else observations[0]["status"]
        expected_metrics = observations[0]["metrics"] if expected_status == "successful" else None
        if row["status"] != expected_status or row["metrics"] != expected_metrics:
            raise ValueError("exploratory_case_status_or_metric_selection_mismatch")
        if expected_metrics is not None and (expected_metrics["parameter_bytes"] != source["architecture"]["float32_parameter_bytes"]
                or expected_metrics["configured_reply_delay_ms"] != row["factors"]["artificial_latency_ms"]
                or any(value != row["factors"]["client_clock_skew_ms"] for value in expected_metrics["reported_clock_offsets_ms"])
                or len(expected_metrics["round_durations_ms"]) != 5
                or [item["round_id"] for item in expected_metrics["actual_selected_per_round"]] != [f"round-{number}" for number in range(1, 6)]
                or any(item["selected_count"] != round(8 * row["factors"]["participation_fraction"]) for item in expected_metrics["actual_selected_per_round"])):
            raise ValueError("exploratory_metric_factor_or_actual_payload_binding_mismatch")
        cases.append({**deepcopy(row), "report_alias": report_alias, "report_sha256": report_sha256,
            "registry_digest": report["registry_digest"], "data_kind": "clinical" if expected_metrics is not None else "clinical-registered-no-verified-success", "independent_seed_count": 1,
            "confirmatory": False, "effect": None, "confidence_interval": None,
            "run_ids": [item["run_id"] for item in observations], "clinical_metric_status": "verified-descriptive" if expected_metrics is not None else "pending-or-not-successful"})
    all_success = all(row["status"] == "successful" for row in report["cases"])
    if report["successful"] != all_success or report["successful"] and not report["normalization_complete"]:
        raise ValueError("exploratory_summary_success_coverage_mismatch")
    displayed_attempts = [{**deepcopy(row), "metrics": deepcopy(row["metrics"]) if row["status"] == "successful" else None,
        "source_metrics_retained": row["metrics"] is not None, "report_alias": report_alias, "report_sha256": report_sha256,
        "data_kind": "clinical" if all(row["verification"].values()) else "unverified-scope", "independent_seed_count": 1, "confirmatory": False,
        "effect": None, "confidence_interval": None} for row in report["attempts"]]
    return {"report_alias": report_alias, "report_sha256": report_sha256, "registry_digest": report["registry_digest"],
        "normalization_complete": report["normalization_complete"], "successful": report["successful"],
        "cases": cases, "attempts": displayed_attempts, "excluded_preparation_attempts": deepcopy(report["excluded_preparation_attempts"]),
        "limitations": deepcopy(report["limitations"]), "independent_seed_count": 1, "confirmatory": False,
        "evaluation_split": "validation", "final_test_accessed": False, "effect": None, "confidence_interval": None}


def descriptive_row(row):
    """Flatten only displayed successful metrics; unknowns stay null."""
    value = deepcopy(row)
    observed = value.pop("metrics", None)
    for key in COUNTS | {"parameter_bytes", "configured_reply_delay_ms", "reported_clock_offsets_ms", "actual_selected_per_round"}:
        value[key] = deepcopy(observed.get(key)) if observed is not None else None
    utility = observed.get("validation_metrics") if observed else None
    for key in ("count", "positive_count", "prevalence", "auroc", "auprc", "precision", "recall", "f1", "threshold", "loss"):
        value["validation_" + key] = utility.get(key) if utility else None
    durations = observed["round_durations_ms"] if observed else []
    value["observed_round_count"] = len(durations) if observed is not None else None
    value["mean_round_duration_ms"] = sum(durations) / len(durations) if durations else None
    value["effect"], value["confidence_interval"] = None, None
    return value


def collect(evidence, *, root, plan_digest):
    reports, cases, attempts, excluded, registries = [], [], [], [], set()
    for reference in evidence:
        if reference["category"] != "exploratory" or reference.get("kind") != KIND:
            continue
        path = checked_reference(root, {key: reference[key] for key in ("path", "sha256")})
        normalized = normalize(read_json(path), root=root, plan_digest=plan_digest,
            report_alias=reference["alias"], report_sha256=reference["sha256"])
        if normalized["registry_digest"] in registries:
            raise ValueError("duplicate_exploratory_registry_summary_choose_one_bound_snapshot")
        registries.add(normalized["registry_digest"])
        cases.extend(normalized["cases"]); attempts.extend(normalized["attempts"])
        excluded.extend({**deepcopy(row), "report_alias": reference["alias"], "report_sha256": reference["sha256"],
            "registry_digest": normalized["registry_digest"], "clinical_cloud_trial": False,
            "effect": None, "confidence_interval": None} for row in normalized["excluded_preparation_attempts"])
        reports.append({key: deepcopy(value) for key, value in normalized.items()
                        if key not in {"cases", "attempts", "excluded_preparation_attempts"}})
    case_rows = [descriptive_row(row) for row in cases]
    by_case = {(row["report_alias"], row["case_id"]): row for row in cases}
    attempt_rows = []
    for row in attempts:
        parent = by_case[(row["report_alias"], row["case_id"])]
        metadata = {key: deepcopy(parent[key]) for key in ("group_id", "seed", "distribution", "factors", "factor_levels",
            "adapter_source_sha256", "adapter_image", "reference_main_plan_digest", "registry_digest")}
        attempt_rows.append(descriptive_row({**metadata, **row}))
    axes = []
    for row in case_rows:
        for factor, level in row["factor_levels"]:
            axes.append({**deepcopy(row), "factor": factor, "level": level,
                "shared_default_control": row["factors"] == DEFAULTS,
                "independent_observation_id": row["registry_digest"] + ":" + row["case_id"],
                "control_reuse": "same case may reference several OFAT axes; never additional independent trials"})
    verified = sum(row["status"] == "successful" for row in attempts)
    return {"status": "normalized-clinical-descriptive-only" if verified else "normalized-coverage-without-verified-clinical-outcomes" if reports else "pending-normalized-summary",
        "reports": reports, "cases": cases, "attempts": attempts, "excluded_preparation_attempts": excluded,
        "case_csv_rows": case_rows, "attempt_csv_rows": attempt_rows, "factor_csv_rows": axes,
        "independent_seed_count": 1 if reports else None, "confirmatory": False, "effect": None, "confidence_interval": None,
        "verified_clinical_attempts": verified,
        "complete_verified_case_coverage": bool(reports) and all(row["successful"] and row["normalization_complete"] for row in reports)}


def claim_row(summary, *, plan_digest, attempts_digest):
    eligible_cases = [row for row in summary["cases"] if row["status"] == "successful"]
    eligible = {identity for row in eligible_cases for identity in row["attempt_ids"]}
    attempts = summary["attempts"]
    return {"RQ": "RQ4", "hypothesis": None, "component": "separately-normalized-ofat-robustness",
        "scenarios": ["exploratory-ofat"], "plan_digest": plan_digest, "attempts_digest": attempts_digest,
        "attempt_source": "separate exploratory normalization; never added to the registered primary ledger",
        "exploratory_registry_digests": [row["registry_digest"] for row in summary["reports"]],
        "planned_exploratory_case_ids": [row["case_id"] for row in summary["cases"]],
        "unattempted_exploratory_case_ids": [row["case_id"] for row in summary["cases"] if row["status"] == "unattempted"],
        "retained_attempt_ids": [row["attempt_id"] for row in attempts], "eligible_attempt_ids": sorted(eligible),
        "run_ids": [row["run_id"] for row in attempts if row["attempt_id"] in eligible],
        "retained_run_ids": [row["run_id"] for row in attempts],
        "failed_or_ambiguous_attempt_ids": [row["attempt_id"] for row in attempts if row["attempt_id"] not in eligible],
        "statistical_result": {"status": "descriptive-only", "independent_seed_count": summary["independent_seed_count"],
            "effect": None, "confidence_interval": None}, "effect_estimate": None, "confidence_interval_95": None,
        "clinical_confirmatory_claim_permitted": False, "verdict": "descriptive-only",
        "table_ids": ["exploratory_cases", "exploratory_attempts", "exploratory_factor_levels", "exploratory_preparation_failures"],
        "table_links": [{"table_id": name, "path": "supplements/" + name + ".csv"} for name in
            ("exploratory_cases", "exploratory_attempts", "exploratory_factor_levels", "exploratory_preparation_failures")],
        "figure_ids": [], "figure_links": [], "pending_figure_ids": [],
        "evidence_aliases": [row["report_alias"] for row in summary["reports"]],
        "inference_scope": "one seed296; validation-only, OFAT/shared-control descriptives; no H4, CI, population robustness or phase-completion claim"}
