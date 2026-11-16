"""Normalize retained validation-only exploratory exports; no SDK or row reads.

This is a descriptive one-seed adapter assessment, never a primary G1/P1 pass,
holdout authorization, phase acceptance or population robustness estimate.
"""
import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import random
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"src"))
from pcfl import ablation_verify, runtime_verify
from pcfl.experiments import digest, scientific_data
from pcfl.robustness import ADAPTER_MODULES, DEFAULTS, LEVELS, PROTOCOL, validate_registry
from validate_cloud_placement import validate_snapshot, sha as snapshot_sha
from verify_cloud_campaign import scoped_artifact_cache

ORGS = {f"org_{number:02d}" for number in range(1, 9)}
VERIFICATIONS = ("protected_witness", "weighted_models", "audit_complete", "evaluation_bound", "placement8", "selected_subset", "schedule_bound")
SHA = re.compile(r"[0-9a-f]{64}\Z")


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    def invalid(value): raise ValueError("nonfinite_exploratory_metadata_forbidden")
    return json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=invalid)


def owned(root, value, *, suffixes=(".json", ".pem")):
    root = Path(root).resolve()
    path = Path(value)
    if not path.is_absolute(): path = root/path
    if (not path.resolve().is_relative_to(root.resolve()) or not path.is_file() or path.suffix.lower() not in suffixes
            or path.resolve().suffix.lower() not in suffixes
            or any(item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction())
                   for item in (path, *path.parents) if item.resolve().is_relative_to(root))):
        raise ValueError("owned_exploratory_metadata_file_required")
    return path.resolve()


def reference(path, root): return {"path": Path(path).resolve().relative_to(Path(root).resolve()).as_posix(), "sha256": sha(path)}


def bound(root, ref, *, pem=False):
    if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or not SHA.fullmatch(ref.get("sha256", "")):
        raise ValueError("strict_exploratory_file_reference_required")
    if Path(ref["path"]).is_absolute() or ".." in Path(ref["path"]).parts:
        raise ValueError("relative_exploratory_evidence_reference_required")
    path = owned(root, ref["path"], suffixes=(".pem",) if pem else (".json",))
    if sha(path) != ref["sha256"]: raise ValueError("bound_exploratory_input_changed")
    return path, path.read_bytes() if pem else read(path)


def exact_ref(value, *, bucket=None, key=None):
    fields = ("bucket", "key", "version_id", "sha256", "size_bytes")
    result = {name: value[name] for name in fields}
    if (not all(isinstance(result[name], str) and result[name] for name in fields[:-1])
            or result["version_id"] == "null" or not SHA.fullmatch(result["sha256"])
            or type(result["size_bytes"]) is not int or result["size_bytes"] < 1
            or bucket is not None and result["bucket"] != bucket or key is not None and result["key"] != key):
        raise ValueError("exact_exploratory_S3_version_required")
    return result


def retained_version(inventory, expected, directory):
    rows = [row for row in inventory.get("retained_artifact_versions", []) if all(row.get(name) == expected[name] for name in expected)]
    if len(rows) != 1: raise ValueError("exact_exploratory_version_not_retained")
    path = owned(directory, rows[0]["local_path"])
    if sha(path) != expected["sha256"] or path.stat().st_size != expected["size_bytes"]:
        raise ValueError("retained_exploratory_version_changed")
    return path


def chosen(seed, number, fraction):
    organizations = sorted(ORGS)
    random.Random(digest([PROTOCOL, "selection", seed, number])).shuffle(organizations)
    return sorted(organizations[:round(8*fraction)])


def intended_schedule(seed, rounds, factors):
    result = [{"phase": "before_run", "round_id": "initial", "org_id": org, "kind": "GRANT"} for org in sorted(ORGS)]
    previous = []
    for number in range(1, rounds+1):
        if number > 1:
            result += [{"phase": "before_round", "round_id": f"round-{number}", "org_id": org, "kind": "GRANT"} for org in previous]
        targets = chosen(seed, number, factors["participation_fraction"])
        random.Random(digest([PROTOCOL, "revocation", seed, number])).shuffle(targets)
        previous = sorted(targets[:factors["revocations_per_round"]])
        result += [{"phase": "after_dispatch", "round_id": f"round-{number}", "org_id": org, "kind": "REVOKE"} for org in previous]
    return result


def schedule_proof(raw, case):
    expected = intended_schedule(case["seed"], 5, case["robustness"]["factors"])
    if expected != case["schedule"]: raise ValueError("registered_exploratory_schedule_changed")
    by_id = {row["event_id"]: row for row in raw["policy_events"]}
    selected = []
    for event in expected:
        request = "robust-policy-" + digest([PROTOCOL, raw["persistent_run_id"], event])[:40]
        identity = "policy-" + hashlib.sha256(request.encode()).hexdigest()[:40]
        actual = by_id.get(identity)
        if actual is None or any(actual.get(name) != event[name] for name in ("org_id", "kind")):
            raise ValueError("actual_exploratory_policy_event_missing_or_rebound")
        selected.append((event, actual))
    if any(left[1]["order"] >= right[1]["order"] for left, right in zip(selected, selected[1:])):
        raise ValueError("exploratory_policy_schedule_order_changed")
    scope_end = max([row["evaluation_order"] for row in raw["decisions"].values()] + [row["commit_order"] for row in raw["published_manifests"]], default=0)
    if any(selected[0][1]["order"] <= event["order"] <= scope_end and event["event_id"] not in {row[1]["event_id"] for row in selected} for event in raw["policy_events"]):
        raise ValueError("unregistered_policy_event_inside_exploratory_case")
    for event, actual in selected:
        if event["phase"] == "before_run": continue
        tasks = [row for row in raw["tasks"] if row["round_id"] == event["round_id"]]
        if not tasks: raise ValueError("exploratory_scheduled_round_missing")
        if event["phase"] == "before_round" and any(row["issue_order"] <= actual["order"] for row in tasks):
            raise ValueError("exploratory_regrant_must_precede_dispatch")
        if event["phase"] == "after_dispatch":
            task = next((row for row in tasks if row["org_id"] == event["org_id"]), None)
            ends = [row["evaluation_order"] for row in raw["decisions"].values() if row["round_id"] == event["round_id"]]
            if task is None or task["start_order"] >= actual["order"] or not ends or actual["order"] >= max(ends):
                raise ValueError("exploratory_revoke_must_cross_dispatched_lifecycle")


def exploratory_placement(inventory, application, image, raw):
    """Eight physical actors, with selected training subsets checked separately."""
    contract = inventory["runtime_contract"]
    registry = raw["node_registry"]
    if len(registry) != 8 or set(registry.values()) != ORGS: raise ValueError("eight_exploratory_registered_identities_required")
    for row in raw["tasks"]:
        if type(row["node_id"]) is not int or registry.get(str(row["node_id"])) != row["org_id"]:
            raise ValueError("exploratory_task_registry_binding_mismatch")
    for snap in reversed(inventory.get("learning_placement_snapshots", [])):
        try:
            checks = validate_snapshot(snap)
            if (not checks or not all(checks.values()) or snap.get("source_failures") or snap["snapshot_sha256"] != snapshot_sha({key: val for key, val in snap.items() if key != "snapshot_sha256"})
                    or snap["application_campaign_id"] != application or snap["runtime_generation"] != inventory["runtime_generation"]
                    or any(snap[name] != inventory[name] for name in ("account_id", "region", "project_id"))
                    or snap["cluster_arn"] != contract["cluster_arn"] or snap["expected_roles"] != contract["task_role_arns"]
                    or snap["expected_security_groups"] != contract["security_group_ids"] or set(snap["expected_subnets"]) != set(contract["subnet_ids"])
                    or snap["expected_vpc"] != contract["vpc_id"]
                    or any(row["definition_image"] != image or row["task_definition_arn"] != contract["task_definition_arns"][row["name"]] for row in snap["tasks"])
                    or snap["public_key_bindings"]["config_sha256"] != inventory["secret_versions"]["coordinator-config"]["sha256"]
                    or snap["public_key_bindings"]["secret_version_id"] != inventory["secret_versions"]["coordinator-config"]["version_id"]
                    or any(snap["public_key_bindings"]["keys"][org]["ssh_sha256"] != inventory["runtime_plan"]["registered_node_bindings"][org]["public_key_sha256"] for org in ORGS)):
                continue
            return True
        except (ValueError, KeyError, TypeError): continue
    raise ValueError("exploratory_eight_physical_actor_placement_not_established")


def selected_proof(raw, case, data):
    factors, seed = case["robustness"]["factors"], case["seed"]
    rounds = raw.get("rounds", [])
    if [row.get("round_id") for row in rounds] != [f"round-{number}" for number in range(1, 6)]:
        raise ValueError("all_five_exploratory_rounds_required")
    result = []
    for number, report in enumerate(rounds, 1):
        round_id = f"round-{number}"; expected = chosen(seed, number, factors["participation_fraction"])
        tasks = [row for row in raw["tasks"] if row["round_id"] == round_id]
        updates = [row for row in raw["updates"] if row["round_id"] == round_id]
        if (len(tasks) != len(expected) or {row["org_id"] for row in tasks} != set(expected)
                or len(updates) != len(expected) or {row["org_id"] for row in updates} != set(expected)
                or report.get("selected_clients") != len(expected) or report.get("received_updates") != len(expected)):
            raise ValueError("exact_seeded_exploratory_selected_subset_required")
        for update in updates:
            count = data["partitions"][case["distribution"]]["organizations"][update["org_id"]]["encounters"]
            if update["sample_count"] != min(count, case["shared_config"]["training"]["max_examples_per_client"]):
                raise ValueError("exploratory_full_own_partition_count_mismatch")
        accepted = sum(row["round_id"] == round_id and row["outcome"] == "accepted" for row in raw["decisions"].values())
        if accepted != report.get("accepted_updates"): raise ValueError("exploratory_round_acceptance_count_mismatch")
        result.append({"round_id": round_id, "org_ids": expected, "selected_count": len(expected), "accepted_count": accepted})
    training = raw.get("client_training", [])
    if len(training) != len(raw["updates"]) or {(row["org_id"], row["round_id"]) for row in training} != {(row["org_id"], row["round_id"]) for row in raw["updates"]}:
        raise ValueError("exploratory_actual_client_training_records_required")
    if any(row.get("artificial_application_reply_delay_ms") != factors["artificial_latency_ms"] or row.get("client_reported_clock_offset_ms") != factors["client_clock_skew_ms"] for row in training):
        raise ValueError("exploratory_reported_delay_or_clock_intervention_mismatch")
    settings = case["shared_config"]["training"]
    for row in training:
        number = int(row["round_id"].removeprefix("round-"))
        count = min(data["partitions"][case["distribution"]]["organizations"][row["org_id"]]["encounters"], settings["max_examples_per_client"])
        if (row.get("sample_count") != count or row.get("epochs") != settings["local_epochs"] or row.get("optimizer") != settings["optimizer"]
                or row.get("example_exposures") != count*settings["local_epochs"]
                or row.get("batches") != math.ceil(count/settings["batch_size"])*settings["local_epochs"]
                or row.get("seed") != seed + number*100 + sorted(ORGS).index(row["org_id"])):
            raise ValueError("exploratory_actual_training_budget_mismatch")
    return result


def assess_runtime(path, case_directory, raw, case, data, inventory, application, witness, public_key, public_pin):
    if (raw.get("kind") != "exploratory_robustness_validation" or raw.get("registered_primary_case") is not False
            or raw.get("aws_used") is not True or raw.get("test_holdout_evaluated") is not False
            or raw.get("baseline_id") != "P1" or raw.get("authority_backend") != "dynamodb-s3-opa"
            or raw.get("robustness") != case["robustness"] or raw.get("seed") != case["seed"]
            or raw.get("distribution") != case["distribution"] or raw.get("cloud_campaign_id") != application
            or raw.get("cell_id") != case["case_id"] or raw.get("equivalence_hash") != case["equivalence_hash"]
            or raw.get("model_schema_hash") != case["shared_config"]["model_schema_hash"]
            or raw.get("model_metadata_digest") != case["architecture"]["model_metadata"]["metadata_digest"]
            or raw.get("validation_source_sha256") != case["shared_config"]["validation_sha256"]
            or any(name in raw for name in ("test_metrics", "final_holdout", "holdout_authorization_digest"))):
        raise ValueError("exact_validation_only_exploratory_runtime_binding_required")
    binding = {"plan_digest": raw["plan_digest"], "cell_id": case["case_id"], "equivalence_hash": case["equivalence_hash"],
        "family": "exploratory", "policy_schedule_hash": digest(case["schedule"]), "source_sha256": case["robustness"]["adapter_source_sha256"]}
    if raw.get("experiment_binding") != binding: raise ValueError("exploratory_source_schedule_binding_mismatch")
    payload = witness.get("payload", {})
    if (payload.get("cell_id") != case["case_id"] or payload.get("application_campaign_id") != application
            or payload.get("campaign_id") != inventory["campaign_id"] or payload.get("execution_successful") is not (raw.get("successful") is True)):
        raise ValueError("exploratory_operator_witness_application_binding_mismatch")
    with scoped_artifact_cache(case_directory):
        assessment = ablation_verify.assess_case(path, witness=witness, public_key_pem=public_key, expected_public_key_sha256=public_pin)
        if (assessment["oracle_invalid_incorporations"] != 0 or not assessment["audit_complete_for_all_final_outcomes"]
                or not assessment["attempt_accounting_complete"]):
            raise ValueError("exploratory_safety_audit_or_attempt_accounting_failed")
        # Native P1 structure/receipts, DDB histories and exact committed evaluator
        # response are checked separately from the partial-protocol witness check.
        if raw["published_manifests"]:
            runtime_verify._verify_persistent(raw, sorted(raw["policy_events"], key=lambda row: row["order"]),
                {row["update_id"]: row for row in raw["updates"]}, {row["task_id"]: row for row in raw["tasks"]},
                errors={row["update_id"]: row for row in raw.get("attempt_failures", [])})
            expected_count = min(data["splits"]["validation"]["encounters"], case["shared_config"]["training"]["max_validation_examples"])
            if raw["validation_metrics"]["count"] != expected_count: raise ValueError("full_exploratory_validation_count_mismatch")
        elif raw.get("validation_metrics") is not None or raw.get("evaluation_service_response") is not None:
            raise ValueError("empty_exploratory_publication_cannot_claim_utility")
        expected_bytes = case["architecture"]["float32_parameter_bytes"]
        for record in [*raw["updates"], *raw["published_manifests"]]:
            values = runtime_verify._load_artifact(record["artifact"], case_directory)
            if sum(value.nbytes for value in values) != expected_bytes:
                raise ValueError("exploratory_real_parameter_payload_mismatch")
    schedule_proof(raw, case)
    selected = selected_proof(raw, case, data)
    exploratory_placement(inventory, application, case["robustness"]["adapter_image"], raw)
    durations = [row["duration_seconds"]*1000 for row in raw["rounds"]]
    if any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in durations):
        raise ValueError("bounded_actual_exploratory_round_timings_required")
    final = assessment["final_allow_count"] + assessment["final_deny_count"] + assessment["final_error_count"]
    metrics = {"assigned_tasks": assessment["task_assignment_count"], "acknowledged_tasks": assessment["acknowledged_task_count"],
        "presented_updates": assessment["presented_update_count"], "accepted_updates": assessment["final_allow_count"],
        "rejected_updates": assessment["final_deny_count"], "final_operational_errors": assessment["final_error_count"],
        "indeterminate_tasks": assessment["indeterminate_count"], "final_decisions": final,
        "audit_complete_decisions": assessment["final_audit_recorded_count"], "published_models": assessment["weighted_models_verified"],
        "oracle_invalid_presented": assessment["oracle_invalid_presented"], "oracle_invalid_incorporations": assessment["oracle_invalid_incorporations"],
        "validation_metrics": raw.get("validation_metrics"), "round_durations_ms": durations, "actual_selected_per_round": selected,
        "parameter_bytes": expected_bytes, "configured_reply_delay_ms": case["robustness"]["factors"]["artificial_latency_ms"],
        "reported_clock_offsets_ms": [row["client_reported_clock_offset_ms"] for row in raw["client_training"]]}
    return metrics


def source_case(registry, case):
    value = case["robustness"]["factors"]
    levels = [[name, level] for name, allowed in LEVELS.items() for level in allowed if value == {**DEFAULTS, name: level}]
    return {"case_id": case["case_id"], "group_id": case["deployment_group"], "seed": case["seed"], "distribution": case["distribution"],
        "factors": deepcopy(value), "factor_levels": levels, "adapter_source_sha256": case["robustness"]["adapter_source_sha256"],
        "adapter_image": case["robustness"]["adapter_image"], "reference_main_plan_digest": registry["reference_main_plan_digest"],
        "status": "unattempted", "attempt_ids": [], "metrics": None}


def normalize(spec_path, *, evidence_root=ROOT):
    root = Path(evidence_root).resolve(); spec_path = owned(root, spec_path)
    spec = read(spec_path)
    if (set(spec) != {"schema_version", "kind", "registry", "data_manifests", "groups"} or spec["schema_version"] != "0.1.0"
            or spec["kind"] != "exploratory-normalization-input" or not isinstance(spec["groups"], list)
            or not isinstance(spec["data_manifests"], list)):
        raise ValueError("strict_exploratory_normalization_input_required")
    registry_path, registry = bound(root, spec["registry"]); validate_registry(registry)
    inputs = [reference(spec_path, root), reference(registry_path, root)]
    data = {}
    for ref in spec["data_manifests"]:
        path, manifest = bound(root, ref); inputs.append(reference(path, root))
        identity = digest(scientific_data(manifest))
        if identity in data: raise ValueError("duplicate_exploratory_data_manifest")
        data[identity] = manifest
    cases = {case["case_id"]: case for case in registry["cases"]}
    rows = {identity: source_case(registry, case) for identity, case in cases.items()}
    attempts, seen = [], set()
    for group in spec["groups"]:
        if set(group) != {"inventory", "campaign", "adapter_manifest", "public_key", "public_key_sha256"} or not SHA.fullmatch(group["public_key_sha256"]):
            raise ValueError("strict_exploratory_group_input_required")
        inv_path, inventory = bound(root, group["inventory"])
        campaign_path, campaign = bound(root, group["campaign"])
        manifest_path, adapter = bound(root, group["adapter_manifest"])
        public_path, public = bound(root, group["public_key"], pem=True)
        if b"PRIVATE KEY" in public or not public.startswith(b"-----BEGIN PUBLIC KEY-----"):
            raise ValueError("public_only_exploratory_operator_key_required")
        from cryptography.hazmat.primitives import serialization
        public_object = serialization.load_pem_public_key(public)
        actual_pin = hashlib.sha256(public_object.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        if actual_pin != group["public_key_sha256"]: raise ValueError("external_exploratory_operator_key_pin_mismatch")
        group_inputs = [reference(path, root) for path in (inv_path, campaign_path, manifest_path, public_path)]
        inputs.extend(group_inputs)
        source_map = {name: adapter.get("new_files_sha256", {}).get("src/pcfl/"+name) for name in ADAPTER_MODULES}
        actual_source_map = {name: sha(ROOT/"src/pcfl"/name) for name in ADAPTER_MODULES}
        if (adapter.get("kind") != "additive-exploratory-adapter-manifest" or adapter.get("accepted_main_plan_digest") != registry["reference_main_plan_digest"]
                or adapter.get("main_source_changed") is not False or source_map != actual_source_map or digest(source_map) != adapter.get("adapter_source_sha256")):
            raise ValueError("immutable_exploratory_adapter_source_binding_required")
        export = inventory["export"]; inv_dir = inv_path.parent
        application = export.get("application_campaign_id", inventory.get("application_campaign_id"))
        export_root = Path(export.get("export_root", inv_dir/"r")).resolve()
        if not export_root.is_relative_to(inv_dir) or campaign.get("campaign_id") != application or campaign.get("plan_digest") != registry["registry_digest"]:
            raise ValueError("exploratory_owned_application_export_required")
        bucket = inventory["foundation"]["bucket_name"]
        campaign_uploads = [row for row in inventory.get("uploads", []) if row.get("bucket") == bucket
            and row.get("key") == f"metadata/{application}/campaign.json" and row.get("sha256") == sha(campaign_path) and row.get("version_id") not in {None, "", "null"}]
        if len(campaign_uploads) != 1: raise ValueError("exact_uploaded_exploratory_campaign_required")
        planned = {row["cell_id"]: row["runtime"] for row in campaign["cases"]}
        group_ids = {cases[identity]["deployment_group"] for identity in planned if identity in cases}
        if (len(group_ids) != 1 or set(planned) != {identity for identity, case in cases.items() if case["deployment_group"] in group_ids}
                or application != "robust-" + registry["registry_digest"][:12] + "-" + next(iter(group_ids)).removeprefix("group-")):
            raise ValueError("exact_registered_exploratory_group_campaign_required")
        for identity, runtime in planned.items():
            case = cases[identity]
            shared = case["shared_config"]
            if (runtime.get("robustness") != case["robustness"] or runtime.get("rounds") != 5 or runtime.get("seed") != case["seed"]
                    or runtime.get("model_metadata") != case["architecture"]["model_metadata"] or runtime.get("distribution") != case["distribution"]
                    or runtime.get("persistent_run_id") != "robust-" + identity.removeprefix("exploratory-")
                    or case["robustness"]["adapter_source_sha256"] != adapter["adapter_source_sha256"]
                    or inventory["image"]["reference"] != case["robustness"]["adapter_image"]
                    or any(name in runtime for name in ("final_holdout", "data_dir", "validation_path", "benchmark_policy_writer"))):
                raise ValueError("public_exploratory_runtime_or_image_binding_mismatch")
            if (runtime.get("training") != {name: shared["training"][name] for name in ("optimizer", "learning_rate", "local_epochs", "batch_size", "cpu_threads")}
                    or runtime.get("max_examples_per_client") != shared["training"]["max_examples_per_client"]
                    or runtime.get("validation_source_sha256") != shared["validation_sha256"] or runtime.get("baseline_id") != "P1"
                    or runtime.get("authority_backend") != "dynamodb-s3-opa" or runtime.get("scenario_id") != "robustness" or runtime.get("scenario_control") is not True):
                raise ValueError("public_exploratory_training_protocol_mismatch")
        index_path = owned(inv_dir, export_root/"campaign_result.json")
        index_ref = exact_ref({"bucket": bucket, "key": export.get("index_key", f"evidence/campaigns/{application}/campaign_result.json"),
            "version_id": export["index_version_id"], "sha256": export["index_sha256"], "size_bytes": index_path.stat().st_size}, bucket=bucket)
        if (not re.fullmatch(rf"evidence/campaigns/{re.escape(application)}/(?:campaign_result|index-[0-9]{{4}})\.json", index_ref["key"])
                or sha(index_path) != index_ref["sha256"]): raise ValueError("exact_exploratory_index_version_or_body_mismatch")
        retained_version(inventory, index_ref, inv_dir)
        index = read(index_path)
        if index.get("campaign_id") != application or len({row["cell_id"] for row in index["cases"]}) != len(index["cases"]):
            raise ValueError("exploratory_producer_index_identity_mismatch")
        for record in index["cases"]:
            identity = record["cell_id"]
            if identity not in planned: raise ValueError("unregistered_exploratory_indexed_case")
            case = cases[identity]
            evidence_refs = [*group_inputs, reference(index_path, root)]
            attempt = {"attempt_id": "exploratory-attempt-" + digest([index_ref, identity])[:32], "case_id": identity,
                "application_campaign_id": application, "index": index_ref, "raw_result": None, "run_id": None,
                "execution_successful": False, "verification": {name: False for name in VERIFICATIONS}, "status": "unverified",
                "reason": "producer-runtime-result-absent", "metrics": None, "evidence_refs": evidence_refs}
            if attempt["attempt_id"] in seen: raise ValueError("duplicate_exploratory_source_attempt")
            seen.add(attempt["attempt_id"])
            raw_refs = [ref for ref in record.get("artifacts", []) if ref.get("key") == f"evidence/campaigns/{application}/{identity}/runtime_result.json"]
            if not raw_refs:
                attempt["status"] = "failed" if record.get("status") in {"failed", "evidence_export_failed"} else "unverified"
                attempts.append(attempt); continue
            if len(raw_refs) != 1: raise ValueError("unique_exploratory_runtime_result_required")
            raw_ref = exact_ref(raw_refs[0], bucket=bucket)
            retained_version(inventory, raw_ref, inv_dir)
            directory = Path(export.get("case_directories", {}).get(identity, export_root/hashlib.sha256(identity.encode()).hexdigest()[:8])).resolve()
            if not directory.is_relative_to(export_root): raise ValueError("exploratory_case_directory_outside_export")
            path = owned(directory, "runtime_result.json")
            if read(owned(directory, "cell.json")) != {"cell_id": identity} or sha(path) != raw_ref["sha256"] or path.stat().st_size != raw_ref["size_bytes"]:
                raise ValueError("exact_exploratory_case_raw_bytes_required")
            raw = read(path); attempt.update(raw_result=raw_ref, run_id=raw.get("persistent_run_id"),
                execution_successful=record.get("successful") is True and raw.get("successful") is True)
            if raw.get("persistent_run_id") != planned[identity]["persistent_run_id"] or raw.get("plan_digest") != registry["registry_digest"]:
                raise ValueError("actual_exploratory_persistent_run_rebound")
            evidence_refs.extend([reference(path, root), reference(owned(directory, "artifact_paths.json"), root)])
            try:
                witnesses = [row for row in inventory.get("protected_operator_witnesses", []) if row.get("cell_id") == identity
                    and row.get("application_campaign_id", inventory["campaign_id"]) == application and row.get("raw_result_sha256") == raw_ref["sha256"]]
                if len(witnesses) != 1: raise ValueError("one_exact_exploratory_operator_witness_required")
                witness_record = witnesses[0]; witness_path = owned(inv_dir, witness_record["local_path"])
                if sha(witness_path) != witness_record["sha256"]: raise ValueError("exploratory_witness_bytes_changed")
                witness_ref = exact_ref({**witness_record, "bucket": bucket, "size_bytes": witness_path.stat().st_size}, bucket=bucket)
                if not witness_ref["key"].startswith("anchors/"): raise ValueError("protected_exploratory_anchor_prefix_required")
                retained_version(inventory, witness_ref, inv_dir); evidence_refs.append(reference(witness_path, root))
                witness = read(witness_path)
                if not attempt["execution_successful"]:
                    # Failure evidence can establish real audited outcomes while
                    # providing no complete training/utility result. Keep that
                    # distinction; never turn the producer failure into success.
                    if (raw.get("robustness") != case["robustness"] or raw.get("distribution") != case["distribution"]
                            or raw.get("seed") != case["seed"] or raw.get("cell_id") != identity or raw.get("cloud_campaign_id") != application
                            or raw.get("test_holdout_evaluated") is True or "test_metrics" in raw
                            or witness.get("payload", {}).get("cell_id") != identity
                            or witness["payload"].get("application_campaign_id") != application
                            or witness["payload"].get("campaign_id") != inventory["campaign_id"]
                            or witness["payload"].get("execution_successful") is not False):
                        raise ValueError("failed_exploratory_source_scope_mismatch")
                    with scoped_artifact_cache(directory):
                        partial = ablation_verify.assess_case(path, witness=witness, public_key_pem=public, expected_public_key_sha256=group["public_key_sha256"])
                    attempt["verification"].update(protected_witness=True,
                        weighted_models=partial["weighted_models_tested"] == partial["weighted_models_verified"] == len(raw["published_manifests"]),
                        audit_complete=partial["audit_complete_for_all_final_outcomes"])
                    attempt.update(status="failed", reason="protected-partial-failed-execution;clinical-outcomes-null")
                else:
                    metrics = assess_runtime(path, directory, raw, case, data[case["robustness"]["data_manifest_digest"]], inventory,
                        application, witness, public, group["public_key_sha256"])
                    attempt.update(metrics=metrics, verification={name: True for name in VERIFICATIONS},
                        status="successful", reason="independently-assessed-validation-only-exploratory-case")
            except (ValueError, KeyError, TypeError, OSError) as error:
                attempt.update(status="unverified" if attempt["execution_successful"] else "failed", reason=type(error).__name__ + ":" + str(error)[:200])
            attempts.append(attempt)
    for identity, row in rows.items():
        matches = [attempt for attempt in attempts if attempt["case_id"] == identity]
        row["attempt_ids"] = [attempt["attempt_id"] for attempt in matches]
        if len(matches) > 1: row["status"] = "multiple-attempts"
        elif matches:
            row["status"] = matches[0]["status"]
            if row["status"] == "successful": row["metrics"] = matches[0]["metrics"]
    # Detect concurrent writer changes rather than racing an active inventory.
    for ref in [*inputs, *[ref for attempt in attempts for ref in attempt["evidence_refs"]]]:
        bound(root, ref, pem=ref["path"].endswith(".pem"))
    inputs = list({row["path"]: row for row in inputs}.values())
    return {"schema_version": "0.1.0", "kind": "independent-exploratory-robustness-summary", "data_kind": "clinical",
        "plan_digest": registry["reference_main_plan_digest"], "registry_digest": registry["registry_digest"], "normalization_complete": True,
        "successful": bool(rows) and all(row["status"] == "successful" for row in rows.values()), "independent_seed_count": 1,
        "confirmatory": False, "evaluation_split": "validation", "final_test_accessed": False, "inputs": inputs,
        "cases": list(rows.values()), "attempts": attempts, "excluded_preparation_attempts": deepcopy(registry["excluded_preparation_attempts"]),
        "limitations": ["One fixed seed296; OFAT/control reuse is descriptive, with no independent replication, CI or H4 inference",
            "Eight physical actors and exact selected subsets are exploratory placement evidence, not primary G1 acceptance",
            "Configured client delay and reported clock offset are application interventions, not network latency or authority-clock changes",
            "Timing-response observer normalization is not claimed here; unchanged traces remain retained",
            "Costs require the separately bound attributable-cost evidence; missing cost is not zero",
            "Failed, unverified, unattempted and repeated cases remain explicit and cannot supply successful clinical outcomes"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path); parser.add_argument("--evidence-root", type=Path, default=ROOT)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(); report = normalize(args.spec, evidence_root=args.evidence_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as target: json.dump(report, target, indent=2, sort_keys=True, allow_nan=False); target.write("\n")
    print(json.dumps({"normalization_complete": True, "successful": report["successful"], "case_status_counts": dict(Counter(row["status"] for row in report["cases"])),
        "independent_seed_count": 1, "AWS_calls": False}))


if __name__ == "__main__": main()
