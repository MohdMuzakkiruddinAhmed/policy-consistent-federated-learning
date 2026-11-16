"""Derive eight candidate-bound gates from actual retained pilot evidence.

Host-only: no AWS client, training, clinical CSV or final-test access. Missing,
stale, unverified or incompatible evidence leaves a check false with its reason.
The small cloud protocol pilot is seed296 across four methods/scenarios and both
distributions; independent learning variability comes from five full local seeds.
"""

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from pcfl.experiments import (BASELINES, DISTRIBUTIONS, GATE_CHECKS, SEEDS, canonical,
    digest, file_digest, scientific_binding, scientific_data, scientific_training, validate_plan)
from pcfl.oracle import evaluate_interval
from anchor_evidence import retained_cases, verify_witness
from validate_cloud_placement import validate_placement
from verify_cloud_campaign import verify_export

ORGS = tuple(f"org_{number:02d}" for number in range(1, 9))
ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError)
TAMPER_KINDS = {"modification", "deletion", "reordering", "duplicate_replay",
                "rechain_and_replace_colocated_anchor", "replace_witness_and_untrusted_public_key"}
CLOUD_TAMPER_KINDS = {"modify-record", "delete-record", "replay-record", "reorder-records", "truncate-chain", "change-model-bytes"}
COST_COMPONENTS = {"compute", "network", "storage", "logging", "api", "idle", "control"}


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def scenario_name(value):
    return {"stable": "S0", "before_dispatch": "S1", "between_round": "S1", "mid_round": "S2", "delayed": "S3",
            "regrant": "S4", "expiry": "S5", "near_commit": "S6", "duplicate_restart": "S7",
            "audit_outage": "S8", "opa_outage": "S8"}.get(value, value)


class Evidence:
    def __init__(self, root):
        self.root, self.sources = Path(root).resolve(), {}

    def path(self, value, suffix=None):
        path = (self.root / value).resolve()
        if not path.is_relative_to(self.root) or not path.is_file() or (suffix and path.suffix != suffix):
            raise ValueError("owned_evidence_file_required")
        self.sources[path.relative_to(self.root).as_posix()] = file_digest(path)
        return path

    def load(self, value):
        return json.loads(self.path(value, ".json").read_text(encoding="utf-8"))


def source_current(hashes, plan, *, required=None):
    expected = plan["provenance"]["source_files_sha256"]
    names = set(required) if required is not None else set(hashes)
    return bool(names) and names <= set(hashes) and all(name in expected and hashes[name] == expected[name] for name in names)


def permitted_pilot_image(reference, plan):
    images = plan["provenance"]["image_digests"]
    runtime = images.get("runtime", "")
    candidates = {images[key] for key in ("runtime", "pilot_runtime") if key in images}
    return bool(runtime) and reference in candidates and reference.split("@sha256:")[-1] == runtime.split("@sha256:")[-1]


def local_training_facts(report, dataset, plan):
    """Recompute counts and descriptive seed variance from every retained curve."""
    training, artifacts = plan["training_candidate"], dataset["private_artifacts_sha256"]
    attempts = report.get("attempts", [])
    expected = {(distribution, seed) for distribution in DISTRIBUTIONS for seed in SEEDS}
    completed = [row for row in attempts if row.get("successful") is True]
    labels = [(row.get("distribution"), row.get("seed")) for row in completed]
    source_names = {"scripts/pilot_training.py", "src/pcfl/learning.py", "src/pcfl/data.py", "src/pcfl/contracts.py",
                    "src/pcfl/evaluation.py", "requirements-runtime.lock"}
    source_ok = source_current(report.get("source_sha256", {}), plan, required=source_names)
    protocol = (scientific_training(report.get("training_configuration", {})) == scientific_training(training)
                and report.get("training_config_digest") == digest(report.get("training_configuration", {}))
                and report.get("kind") == "full-data-local-training-protocol-pilot" and source_ok)
    inputs = {name: value for name, value in artifacts.items() if name == "preprocessor.json" or name == "validation.csv" or name.startswith(("iid/", "non_iid/"))}
    inputs_ok = (report.get("verified_input_sha256") == inputs and report.get("source_dataset_sha256") == dataset.get("source", {}).get("csv_sha256"))
    full, real, curves_valid, no_test = True, True, True, report.get("final_test_accessed") is False
    initial, observations = {}, {distribution: [] for distribution in DISTRIBUTIONS}
    for attempt in completed:
        distribution, seed = attempt.get("distribution"), attempt.get("seed")
        if distribution not in DISTRIBUTIONS or seed not in SEEDS:
            full = False
            continue
        counts = {org: dataset["partitions"][distribution]["organizations"][org]["encounters"] for org in ORGS}
        rounds, curves = attempt.get("rounds", []), attempt.get("curves", [])
        no_test = no_test and attempt.get("final_test_accessed") is False and attempt.get("is_confirmatory") is False
        full = full and attempt.get("training_counts") == counts and attempt.get("validation_count") == dataset["splits"]["validation"]["encounters"]
        full = full and len(rounds) == training["num_rounds"] and len(curves) == training["num_rounds"] + 1
        full = full and [row.get("round") for row in rounds] == list(range(1, training["num_rounds"] + 1))
        initial.setdefault(seed, set()).add(attempt.get("initial_parameters_digest"))
        for number, round_ in enumerate(rounds, 1):
            clients = round_.get("clients", [])
            full = full and len(clients) == 8 and {row.get("org_id") for row in clients} == set(ORGS)
            for client in clients:
                org = client.get("org_id")
                if org not in counts:
                    full = False
                    continue
                expected_seed = seed + number * 100 + ORGS.index(org)
                full = full and client.get("sample_count") == counts[org] and client.get("example_exposures") == counts[org] * training["local_epochs"]
                real = real and client.get("epochs") == training["local_epochs"] and client.get("optimizer") == training["optimizer"] and client.get("seed") == expected_seed
                real = real and client.get("batches") == math.ceil(counts[org] / training["batch_size"]) * training["local_epochs"]
                real = real and all(finite(client.get(name)) for name in ("loss", "loss_before", "loss_after", "duration_seconds"))
        for number, curve in enumerate(curves):
            metric = curve.get("validation_metrics", {})
            curves_valid = curves_valid and curve.get("round") == number and metric.get("count") == dataset["splits"]["validation"]["encounters"]
            curves_valid = curves_valid and metric.get("threshold") == .5 and all(finite(metric.get(name)) for name in ("auroc", "auprc", "f1", "precision", "recall", "prevalence", "loss"))
            curves_valid = curves_valid and all(0 <= metric[name] <= 1 for name in ("auroc", "auprc", "f1", "precision", "recall", "prevalence") if finite(metric.get(name)))
        if curves and curves_valid:
            observations[distribution].append({"seed": seed, "initial_auroc": curves[0]["validation_metrics"]["auroc"],
                "final_auroc": curves[-1]["validation_metrics"]["auroc"], "final_auprc": curves[-1]["validation_metrics"]["auprc"],
                "initial_loss": curves[0]["validation_metrics"]["loss"], "final_loss": curves[-1]["validation_metrics"]["loss"]})
    five = len(completed) == 10 and len(labels) == len(set(labels)) and set(labels) == expected
    retained = (report.get("planned_attempts") == 10 and report.get("completed_attempts") == len(completed)
                and report.get("failed_attempts") == len(attempts) - len(completed))
    variances = {}
    for distribution, rows in observations.items():
        values = [row["final_auroc"] for row in rows]
        variances[distribution] = {"independent_seeds": len(values), "observations": rows,
            "auroc_mean": statistics.fmean(values) if values else None,
            "auroc_sample_sd": statistics.stdev(values) if len(values) >= 2 else None}
    return {"successful": report.get("successful") is True, "protocol": protocol, "source_current": source_ok,
        "inputs": inputs_ok, "full": full and bool(completed), "real": real and bool(completed), "five": five,
        "validation_only": no_test, "curves_valid": curves_valid and bool(completed), "retained": retained,
        "initialization_matched": set(initial) == set(SEEDS) and all(len(values) == 1 and None not in values for values in initial.values()),
        "descriptive_variance": variances, "completed_attempts": len(completed), "failed_attempts": len(attempts) - len(completed)}


def full_cloud_case(runtime, raw, dataset, plan, inventory):
    """Development cells must match the candidate model/budget, not its cell ID."""
    training = plan["training_candidate"]
    distribution = runtime.get("distribution")
    if distribution not in DISTRIBUTIONS:
        return {"protocol": False, "reason": "unknown-pilot-distribution"}
    expected_counts = {org: dataset["partitions"][distribution]["organizations"][org]["encounters"] for org in ORGS}
    uploaded = {row.get("sha256") for row in inventory.get("uploads", []) if row.get("version_id") not in {None, "", "null"}}
    partitions = (all(dataset["private_artifacts_sha256"][f"{distribution}/{org}.csv"] in uploaded for org in ORGS)
                  and dataset["private_artifacts_sha256"]["preprocessor.json"] in uploaded)
    metadata = runtime.get("model_metadata", {})
    protocol = (scientific_training(runtime.get("training", {})) == scientific_training(training)
        and runtime.get("rounds") == training["num_rounds"] and runtime.get("max_examples_per_client") == training["max_examples_per_client"]
        and runtime.get("validation_max_examples") == training["max_validation_examples"]
        and runtime.get("validation_source_sha256") == dataset["private_artifacts_sha256"]["validation.csv"]
        and runtime.get("baseline_id") == raw.get("baseline_id") and runtime.get("seed") == raw.get("seed")
        and runtime.get("persistent_run_id") == raw.get("persistent_run_id")
        and scenario_name(raw.get("scenario_id")) == runtime.get("scenario_id")
        and raw.get("cloud_campaign_id") == inventory["export"].get("application_campaign_id", inventory.get("application_campaign_id", inventory["campaign_id"]))
        and raw.get("model_metadata_digest") == metadata.get("metadata_digest") and bool(metadata.get("metadata_digest"))
        and raw.get("model_schema_hash") == metadata.get("model_schema_hash") and bool(metadata.get("model_schema_hash"))
        and metadata.get("hidden_dims") == training["hidden_dims"]
        and permitted_pilot_image(inventory.get("image", {}).get("reference"), plan))
    records = raw.get("client_training", [])
    full, seed_ok = bool(records), bool(records)
    presented = {(row["round_id"], row["org_id"]) for row in raw.get("updates", [])}
    trained = [(row.get("round_id"), row.get("org_id")) for row in records]
    # A denied in-flight update can still have trained; every presented update
    # must have genuine metadata, and duplicate telemetry cannot inflate counts.
    full = full and presented <= set(trained) and len(trained) == len(set(trained))
    for record in records:
        org = record.get("org_id")
        if org not in ORGS or not isinstance(record.get("round_id"), str) or not record["round_id"].startswith("round-"):
            full = False
            continue
        number = int(record["round_id"].split("-")[-1])
        count = expected_counts[org]
        full = full and record.get("sample_count") == count and record.get("example_exposures") == count * training["local_epochs"]
        full = full and record.get("epochs") == training["local_epochs"] and record.get("optimizer") == training["optimizer"]
        full = full and record.get("batches") == math.ceil(count / training["batch_size"]) * training["local_epochs"]
        seed_ok = seed_ok and record.get("seed") == runtime["seed"] + number * 100 + ORGS.index(org)
    for update in raw.get("updates", []):
        full = full and update["sample_count"] == expected_counts[update["org_id"]]
    metrics = raw.get("validation_metrics")
    validation_full = isinstance(metrics, dict) and metrics.get("count") == dataset["splits"]["validation"]["encounters"] and metrics.get("threshold") == .5
    no_test = raw.get("test_holdout_evaluated") is False and not raw.get("test_metrics") and not runtime.get("final_holdout")
    body = {"distribution": distribution, "seed": runtime.get("seed"), "rounds": runtime.get("rounds"),
        "training": scientific_training(runtime.get("training", {})), "maximum_rows": runtime.get("max_examples_per_client"),
        "validation_maximum": runtime.get("validation_max_examples"), "validation_sha256": runtime.get("validation_source_sha256"),
        "model_metadata": runtime.get("model_metadata"), "image": inventory.get("image", {}).get("reference"),
        "scenario_id": runtime.get("scenario_id"), "scenario_target_org": runtime.get("scenario_target_org"),
        "scenario_control": runtime.get("scenario_control"), "partition_hashes": {org: dataset["private_artifacts_sha256"][f"{distribution}/{org}.csv"] for org in ORGS}}
    return {"protocol": protocol, "partitions": partitions, "full": full, "seed": seed_ok,
        "validation_full": validation_full, "validation_only": no_test, "shared_digest": digest(body),
        "initial_digest": raw.get("initial_parameters_digest"), "trained_client_rounds": len(records),
        "final_model_digest": raw.get("current_model_digest")}


def local_service_facts(spec, evidence, plan):
    report, manifest = evidence.load(spec["report"]), evidence.load(spec["manifest"])
    transcript = evidence.path(spec["transcript"], ".txt")
    body = transcript.read_text(encoding="utf-8")
    hashes = manifest.get("source_files_sha256", {})
    relevant = {name for name in plan["provenance"]["source_files_sha256"] if name.startswith(("src/", "tests/", "policies/", "schemas/"))}
    source_ok = source_current(hashes, plan, required=relevant)
    transcript_ok = report.get("transcript_sha256") == file_digest(transcript)
    ok = (report.get("successful") is True and report.get("failures") == 0 and report.get("errors") == 0
        and report.get("skipped") == 0 and report.get("tests_run", 0) > 0 and report.get("tested_interpreter_pin_matches") is True
        and report.get("integration_modes", {}).get("PCFL_LOCAL_INTEGRATION") == "1"
        and report.get("integration_modes", {}).get("PCFL_GOVERNANCE_TEST_LOCAL") == "1"
        and report.get("opa_service_integration_enabled") is True and transcript_ok
        and report.get("source_input_digest") == digest(hashes) == manifest.get("source_input_digest")
        and manifest.get("successful") is True and source_ok)
    # TextTestRunner verbosity2 emits 'test_name (...) ... ok'. An aggregate
    # passed count cannot stand in for these named operational/protocol checks.
    def passed(name):
        return any(line.startswith(name + " (") and line.rstrip().endswith("... ok") for line in body.splitlines())
    required = {
        "native_oracle": "test_actual_service_matches_all_sixteen_independent_oracle_traces",
        "races_and_regrant": "test_actual_sdk_and_opa_recover_restart_reject_gap_and_recompute_after_race",
        "comparators": "test_actual_durable_baseline_matrix_and_restart_semantics",
        "duplicate_restart": "test_S7_consumption_replay_is_idempotent_after_bound_restart_ack",
        "fault_recovery": "test_S8_fault_failure_preserves_prior_commit_and_explicit_recovery_counts",
        "error_accounting": "test_durable_error_without_received_arrays_is_counted_and_audited"}
    return {"successful": ok, "named_checks": {key: ok and passed(name) for key, name in required.items()},
            "tests_run": report.get("tests_run"), "skipped": report.get("skipped"), "source_current": source_ok,
            "transcript_digest_verified": transcript_ok,
            "mismatched_or_unrecorded_sources": sorted(name for name in relevant if hashes.get(name) != plan["provenance"]["source_files_sha256"].get(name))}


def cloud_pilot_facts(spec, evidence, dataset, plan):
    inventory_path = evidence.path(spec["inventory"], ".json")
    inventory, campaign = evidence.load(spec["inventory"]), evidence.load(spec["campaign"])
    public_key = evidence.path(spec["witness_public_key"], ".pem") if spec.get("witness_public_key") else None
    pin = spec.get("expected_public_key_sha256")
    report = verify_export(inventory_path, witness_public_key=public_key, witness_public_key_sha256=pin)
    placement = validate_placement(deepcopy(inventory), export_root=Path(inventory["export"].get("export_root", inventory_path.parent / "r")))
    application, cases = retained_cases(inventory, inventory_path)
    from reconcile_campaign_cost import prepared_pilot_campaigns
    bound = prepared_pilot_campaigns({"data_uploads": []}, {inventory["campaign_id"]: inventory}, [evidence.path(spec["campaign"], ".json")])
    if application not in bound or bound[application]["source"]["sha256"] != file_digest(evidence.path(spec["campaign"], ".json")):
        raise ValueError("public_pilot_campaign_not_bound_to_uploaded_immutable_metadata_version")
    if campaign.get("campaign_id") != application or campaign.get("dataset_manifest_sha256") != file_digest(evidence.path(plan["configuration"]["data_manifest"], ".json")):
        raise ValueError("prepared_campaign_dataset_or_application_binding_mismatch")
    prepared = {row["cell_id"]: row["runtime"] for row in campaign["cases"]}
    if len(prepared) != len(campaign["cases"]) or set(prepared) != {cell_id for cell_id, *_ in cases}:
        raise ValueError("prepared_and_exported_pilot_cases_must_match_exactly")
    summaries = {row["cell_id"]: row["summary"] for row in report["verified_cases"]}
    partials = {row["cell_id"]: row["summary"] for row in report.get("partial_assessments", [])}
    resource_spec = plan["configuration"]["resources"]
    actual_sizes = {row["name"]: {"cpu_units": int(row["cpu"]), "memory_mib": int(row["memory_mib"])}
                    for row in placement.get("source_snapshot", {}).get("tasks", []) if row.get("name") in {*ORGS, "coordinator"}}
    expected_sizes = {org: {"cpu_units": int(resource_spec["client_vcpu"] * 1024), "memory_mib": resource_spec["client_memory_mib"]} for org in ORGS}
    expected_sizes["coordinator"] = {"cpu_units": int(resource_spec["coordinator_vcpu"] * 1024), "memory_mib": resource_spec["coordinator_memory_mib"]}
    sizes_match = actual_sizes == expected_sizes and inventory.get("region") == resource_spec["region"]
    rows = []
    for cell_id, directory, raw, raw_sha in cases:
        raw_path = directory / "runtime_result.json"
        evidence.path(raw_path, ".json")
        runtime = prepared[cell_id]
        facts = full_cloud_case(runtime, raw, dataset, plan, inventory)
        facts["resources"] = sizes_match
        facts["actual_task_sizes"] = actual_sizes
        facts["shared_digest"] = digest([facts.get("shared_digest"), actual_sizes, inventory.get("region")])
        bindings = [row for row in inventory.get("protected_operator_witnesses", []) if row.get("cell_id") == cell_id
                    and row.get("raw_result_sha256") == raw_sha and row.get("application_campaign_id", inventory["campaign_id"]) == application]
        anchored = False
        if len(bindings) == 1 and public_key is not None and pin:
            binding = bindings[0]
            witness_path = evidence.path(binding["local_path"], ".json")
            witness = json.loads(witness_path.read_text())
            payload = witness.get("payload", {})
            anchored = (file_digest(witness_path) == binding["sha256"] and binding.get("key", "").startswith("anchors/")
                and binding.get("version_id") not in {None, "", "null"}
                and verify_witness(witness, public_key.read_bytes(), expected_public_key_sha256=pin)
                and payload.get("raw_result_sha256") == raw_sha and payload.get("run_id") == raw["persistent_run_id"]
                and payload.get("anchor") == raw["anchor"] and payload.get("cell_id") == cell_id
                and payload.get("application_campaign_id", application) == application)
        events = [row for row in raw.get("policy_events", []) if row.get("org_id") == runtime.get("scenario_target_org")]
        lower = min((row["issue_order"] for row in raw.get("tasks", [])), default=0)
        end = max([row["commit_order"] for row in raw.get("published_manifests", [])] + [row["evaluation_order"] for row in raw.get("decisions", {}).values()] + [lower])
        # Initial grants and history from previous cells are retained by the
        # verifier; the per-run trace records only relative relevant mutations.
        mutations = [row for row in events if lower <= row["order"] <= end and row["kind"] != "GRANT"]
        first_commit = min((row["commit_order"] for row in raw.get("published_manifests", []) if row["round_id"] == "round-1"), default=end)
        second_dispatch = min((row["issue_order"] for row in raw.get("tasks", []) if row["round_id"] == "round-2"), default=end + 1)
        schedule = [{"kind": row["kind"], "relative_order": index, "after_first_commit": row["order"] > first_commit,
                     "before_second_dispatch": row["order"] < second_dispatch} for index, row in enumerate(mutations)]
        summary = summaries.get(cell_id)
        validation_scope = failed_validation_scope(runtime, raw, cell_id=cell_id, application=application,
            campaign_sha256=bound[application]["source"]["sha256"], uploaded_versions=bound[application]["uploaded_versions"],
            inventory=inventory, placement_checks=placement.get("checks", {}), plan=plan, source_root=evidence.root,
            partial_summary=partials.get(cell_id, {}))
        rows.append({"cell_id": cell_id, "baseline": runtime["baseline_id"], "distribution": runtime.get("distribution"),
            "raw_result_sha256": raw_sha,
            "scenario": runtime.get("scenario_id"), "seed": runtime.get("seed"), "facts": facts,
            "summary": summary, "partial": partials.get(cell_id), "anchored": anchored,
            "operational_abort_accounting": operational_fault_accounting(raw, partials.get(cell_id, {})),
            "failed_validation_scope": validation_scope,
            "execution_successful": raw.get("successful") is True, "native_opa_calls": len(raw.get("policy_rpc_metrics", [])),
            "policy_trace": schedule, "initialization_config_digest": digest({"metadata": runtime.get("model_metadata"), "seed": runtime.get("seed")}),
            "fault_trace": raw.get("fault_trace", []), "scripted_fault": raw.get("scripted_fault"),
            "ablation_id": raw.get("ablation_id"),
            "test_accessed": raw.get("test_holdout_evaluated") is not False and validation_scope.get("verified") is not True,
            "scope": "development-pilot-not-a-registered-primary-trial"})
    # A pinned image/build manifest check is part of placement replay, not an
    # unverified claim from the campaign JSON.
    return {"successful": report.get("successful") is True, "rows": rows, "placement": placement.get("checks", {}),
        "placement_successful": placement.get("successful") is True,
        "image_reference": inventory.get("image", {}).get("reference"), "inventory": inventory,
        "failed_cases_retained": len(report.get("failed_cases", [])), "exported_cases": len(cases),
        "all_case_outcomes_retained": len(summaries) + len(partials) == len(cases)}


def isolation_facts(name, evidence, plan):
    path, inventory = evidence.path(name, ".json"), evidence.load(name)
    placement = validate_placement(deepcopy(inventory), export_root=Path(inventory["export"].get("export_root", path.parent / "r")))
    image = inventory.get("image", {}).get("reference")
    if not permitted_pilot_image(image, plan):
        raise ValueError("fresh_isolation_image_outside_exact_frozen_runtime_content")
    return {"inventory": inventory, "placement_successful": placement.get("successful") is True,
            "placement": placement.get("checks", {}), "image_reference": image}


def operational_fault_accounting(raw, summary):
    """Classify audited post-receipt aborts without relabeling durable outcomes.

    Caller must first independently verify the externally signed partial case.
    This additional proof distinguishes an operational abort from policy denial.
    It preserves the actual allow/deny/error counts and failed execution status.
    """
    result = {"kind": "post-receipt-operational-abort-accounting", "verified": False,
        "operational_abort_rejected_update_count": 0, "update_ids": []}
    try:
        reasons = {"opa_transport_unavailable": "policy_evaluator_unavailable_or_invalid_response",
            "audit_transport_unavailable": "transaction_not_confirmed"}
        kind = raw.get("scripted_fault")
        if (kind not in reasons or raw.get("reason") != reasons[kind] or raw.get("successful") is not False
                or raw.get("ablation_id") is not None or raw.get("baseline_id") != "P1"
                or any(summary.get(key) is not True for key in ("protected_witness_verified",
                    "audit_complete_for_all_final_outcomes", "attempt_accounting_complete"))
                or summary.get("indeterminate_count") != 0):
            raise ValueError("protected_complete_failed_P1_transport_case_required")
        armed = [row for row in raw["fault_trace"] if row.get("phase") == "fault_armed"]
        closed = [row for row in raw["fault_trace"] if row.get("phase") == "fault_failed_closed"]
        if len(armed) != 1 or len(closed) != 1: raise ValueError("unique_fault_lifecycle_required")
        armed, closed = armed[0], closed[0]
        if (armed.get("kind") != kind or closed.get("kind") != kind
                or closed.get("pointer_unchanged") is not True or closed.get("published_models_during_fault") != 0
                or closed.get("recovery_errors") != [] or closed.get("anchor_before_recovery") != armed.get("anchor_before")
                or closed.get("anchor_after_recovery") != raw["anchor"]
                or (kind == "audit_transport_unavailable" and not (type(closed.get("blocked_calls")) is int and closed["blocked_calls"] > 0))):
            raise ValueError("fault_closure_or_recovery_binding_failed")
        tasks = [task for task in raw["tasks"] if task["round_id"] == armed["round_id"]]
        uids = {task["update_id"] for task in tasks}
        if (not uids or len(uids) != len(tasks) or closed.get("indeterminate_tasks_before_recovery") != len(uids)
                or raw["anchor"]["count"] - armed["anchor_before"]["count"] != len(uids)):
            raise ValueError("all_pending_fault_round_tasks_required")
        updates = {row["update_id"]: row for row in raw["updates"]}
        rows = {row["SK"]: row for row in raw["durable_evidence"]["run_records"]}
        operations = raw["runtime_observations"]["operations"]
        publications = [row for row in operations if row.get("operation") == "publish" and row.get("round_id") == armed["round_id"]]
        if len(publications) != 1 or publications[0].get("outcome") != "exception":
            raise ValueError("bound_publication_exception_required")
        publication = publications[0]
        included = {uid for manifest in raw["published_manifests"] for uid in manifest["included_update_ids"]}
        for task in tasks:
            uid = task["update_id"]
            decision = raw["decisions"][uid]
            stored = json.loads(rows["UPDATE#" + uid]["decision_json"])
            native = json.loads(rows["OPA_FINAL#" + uid]["opa_decision_json"])
            receipts = [op for op in operations if op.get("operation") == "receive" and op.get("update_id") == uid]
            failures = [op for op in operations if op.get("operation") == "fail" and op.get("update_id") == uid]
            audits = [event for event in raw["audit"] if event["payload"].get("update_id") == uid]
            if (uid not in updates or uid in included or decision.get("outcome") != "rejected"
                    or decision.get("reason") != "scripted_transport_fault_round_aborted" or decision.get("manifest_ref") is not None
                    or stored != decision or native.get("valid") is not True
                    or native.get("decision_id") != decision.get("policy_decision_id")
                    or len(audits) != 1 or audits[0]["payload"] != decision
                    or len(receipts) != 1 or receipts[0].get("outcome") != "pending"
                    or len(failures) != 1 or failures[0].get("outcome") != "rejected"
                    or not receipts[0]["sequence"] < publication["sequence"] < failures[0]["sequence"]
                    or any(op.get(key) != task[key] for op in (receipts[0], failures[0]) for key in ("task_id", "org_id", "round_id"))):
                raise ValueError("post_receipt_operational_abort_binding_failed")
        if summary.get("final_deny_count", 0) < len(uids): raise ValueError("abort_count_exceeds_final_denials")
        return {**result, "verified": True, "operational_abort_rejected_update_count": len(uids), "update_ids": sorted(uids),
            "final_error_count": summary["final_error_count"], "final_deny_count": summary["final_deny_count"],
            "scope": "failed-execution-audited-operational-aborts-not-policy-denials-or-full-protocol-pass"}
    except (KeyError, ValueError, TypeError, IndexError) as error:
        return {**result, "reason": str(error)[:160]}


def failed_validation_scope(runtime, raw, *, cell_id, application, campaign_sha256,
        uploaded_versions, inventory, placement_checks, plan, source_root, partial_summary):
    """Prove a missing failed-result test flag from exact immutable runtime scope."""
    result = {"verified": False, "raw_test_holdout_evaluated_present": "test_holdout_evaluated" in raw,
        "raw_test_holdout_evaluated": raw.get("test_holdout_evaluated"), "test_accessed": True}
    try:
        if (any(partial_summary.get(key) is not True for key in ("protected_witness_verified",
                "audit_complete_for_all_final_outcomes", "attempt_accounting_complete"))
                or partial_summary.get("indeterminate_count") != 0):
            raise ValueError("independent_protected_complete_partial_case_required")
        if raw.get("successful") is not False or "test_holdout_evaluated" in raw:
            raise ValueError("only_missing_flag_on_failed_execution_uses_prepared_scope")
        forbidden = {"final_holdout", "expected_holdout", "accepted_plan", "accepted_plan_digest", "holdout_authorization",
            "holdout_authorization_digest", "holdout_authorization_id", "test_metrics", "test_source_sha256",
            "test_sha256", "test_sample_digest", "final_test_authorization", "test_object"}
        if forbidden & set(runtime) or forbidden & set(raw) or forbidden & set(runtime.get("evaluator", {})):
            raise ValueError("final_test_or_authority_field_present")
        if any(("dataset_role" in scope and scope["dataset_role"] != "validation")
                or ("confirmatory" in scope and scope["confirmatory"] is not False)
                for scope in (runtime, raw, runtime.get("evaluator", {}))):
            raise ValueError("explicit_test_or_confirmatory_role_present")
        reasons = {"opa_transport_unavailable": "policy_evaluator_unavailable_or_invalid_response",
            "audit_transport_unavailable": "transaction_not_confirmed"}
        if (runtime.get("baseline_id") != "P1" or runtime.get("scenario_id") != "S8"
                or raw.get("scenario_id") not in {"S8", "transport_fault"}
                or raw.get("scripted_fault") not in reasons or raw.get("reason") != reasons[raw["scripted_fault"]]):
            raise ValueError("known_failed_transport_path_required")
        if (raw.get("cloud_campaign_id") != application or raw.get("cell_id") != cell_id
                or raw.get("persistent_run_id") != runtime.get("persistent_run_id")
                or raw.get("baseline_id") != runtime.get("baseline_id") or raw.get("seed") != runtime.get("seed")
                or raw.get("scripted_fault") != runtime.get("scripted_fault")
                or raw.get("validation_source_sha256") != runtime.get("validation_source_sha256")):
            raise ValueError("prepared_failed_case_identity_mismatch")
        training = runtime["training"]
        if (runtime.get("rounds") != 5 or training.get("num_rounds") != 5
                or training.get("development_evaluation_split") != "validation"
                or training.get("final_test_access_permitted") is not False or training.get("confirmatory_frozen") is not False):
            raise ValueError("explicit_five_round_validation_only_runtime_required")
        refs = [row for row in uploaded_versions if row.get("sha256") == campaign_sha256
            and row.get("key") == f"metadata/{application}/campaign.json" and row.get("kind") == "campaign"
            and row.get("bucket") == inventory.get("foundation", {}).get("bucket_name")
            and row.get("version_id") not in {None, "", "null"}]
        if len(refs) != 1: raise ValueError("exact_immutable_uploaded_campaign_receipt_required")
        if not permitted_pilot_image(inventory.get("image", {}).get("reference"), plan):
            raise ValueError("failed_scope_image_not_pinned_by_candidate")
        required_checks = ("actual_image_manifest_relation", "source_snapshot_integrity", "snapshot_matches_current_image",
            "snapshot_matches_current_application", "snapshot_matches_current_config")
        if any(placement_checks.get(key) is not True for key in required_checks):
            raise ValueError("actual_source_image_and_runtime_placement_binding_required")
        names = ("src/pcfl/flower_app.py", "src/pcfl/persistent.py", "src/pcfl/cloud_coordinator.py")
        pinned = plan["provenance"]["source_files_sha256"]
        if any(pinned.get(name) != file_digest(Path(source_root) / name) for name in names):
            raise ValueError("failed_runtime_path_source_not_current_pinned_code")
        armed = [row for row in raw["fault_trace"] if row.get("phase") == "fault_armed"]
        closed = [row for row in raw["fault_trace"] if row.get("phase") == "fault_failed_closed"]
        if (len(armed) != 1 or len(closed) != 1 or armed[0].get("round_id") != "round-2"
                or armed[0].get("published_models_before") != 1 or closed[0].get("pointer_unchanged") is not True
                or closed[0].get("published_models_during_fault") != 0
                or len(raw["published_manifests"]) != 1 or raw["published_manifests"][0].get("round_id") != "round-1"
                or any(stage.get("name") in {"evaluation", "final_test_evaluation", "test_evaluation"}
                    for stage in raw["runtime_observations"]["stages"])):
            raise ValueError("failed_round_two_before_final_test_path_required")
        return {**result, "verified": True, "test_accessed": False,
            "source": "exact-immutable-prepared-runtime + pinned failed path",
            "application_campaign_id": application, "cell_id": cell_id, "run_id": raw["persistent_run_id"],
            "uploaded_campaign": refs[0], "runtime_sha256": digest(runtime),
            "source_files_sha256": {name: pinned[name] for name in names},
            "scope": "no-final-test-access-in-this-failed-validation-only-invocation; validation-evaluation-not-excluded"}
    except (OSError, KeyError, ValueError, TypeError, IndexError) as error:
        return {**result, "reason": str(error)[:160]}


def protected_fault_facts(spec, evidence):
    """Reassess signed partial/fault cases and test six changed-copy attacks."""
    from pcfl.ablation_verify import assess_case
    from verify_cloud_campaign import scoped_artifact_cache
    path, witness_path = evidence.path(spec["case"], ".json"), evidence.path(spec["witness"], ".json")
    public = evidence.path(spec["witness_public_key"], ".pem").read_bytes()
    pin = spec["expected_public_key_sha256"]
    raw, witness = json.loads(path.read_text()), json.loads(witness_path.read_text())
    options = {"witness": witness, "public_key_pem": public, "expected_public_key_sha256": pin}
    if (path.parent / "artifact_paths.json").is_file():
        with scoped_artifact_cache(path.parent):
            summary = assess_case(path, **options)
    else:
        summary = assess_case(path, **options)
    payload = witness["payload"]
    if payload.get("raw_result_sha256") != file_digest(path):
        raise ValueError("protected_case_byte_binding_mismatch")
    attacks = []
    for name in sorted(TAMPER_KINDS):
        changed, changed_witness, changed_public = deepcopy(raw), deepcopy(witness), public
        if name == "modification":
            changed["anchor"]["count"] += 1
        elif name == "deletion":
            changed["audit"] = changed["audit"][1:]
        elif name == "reordering":
            changed["audit"] = list(reversed(changed["audit"]))
        elif name == "duplicate_replay":
            changed["audit"] = changed["audit"] + changed["audit"][:1]
        elif name == "rechain_and_replace_colocated_anchor":
            changed["anchor"]["head"] = "f" * 64
            changed_witness["payload"]["anchor"] = changed["anchor"]
            changed_witness["payload_sha256"] = digest(changed_witness["payload"])
        else:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from anchor_evidence import create_witness
            key = ec.generate_private_key(ec.SECP384R1())
            changed_public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            changed_witness = create_witness(deepcopy(payload), key)
        # A no-op on an empty/singleton audit is not a real altered-copy attack.
        changed_bytes = canonical(changed)
        if name in {"deletion", "reordering", "duplicate_replay"} and changed == raw:
            attacks.append({"attack_id": name, "detected": False, "reason": "insufficient-audit-records-for-this-mutation"})
            continue
        accepted = (verify_witness(changed_witness, changed_public, expected_public_key_sha256=pin)
                    and changed_witness["payload"].get("raw_result_sha256") == hashlib.sha256(changed_bytes).hexdigest()
                    and changed_witness["payload"].get("anchor") == changed["anchor"])
        attacks.append({"attack_id": name, "detected": not accepted, "reason": "externally-pinned-signature-and-signed-raw-byte-anchor-binding"})
    return {"summary": summary, "operational_abort_accounting": operational_fault_accounting(raw, summary),
        "ablation_id": raw.get("ablation_id"), "scenario": scenario_name(raw.get("scenario_id")),
        "test_accessed": raw.get("test_holdout_evaluated") is not False,
        "fault_trace": raw.get("fault_trace", []), "scripted_fault": raw.get("scripted_fault"),
        "execution_successful": raw.get("successful") is True, "protected_tamper_checks": attacks,
        "case_sha256": file_digest(path), "operator_public_key_sha256": pin}


def cost_facts(spec, evidence, plan, dataset, clouds=()):
    """Replay the offline usage/pricing calculation, never trust its pass flag."""
    from reconcile_campaign_cost import load_scope, price_basis, prepared_pilot_campaigns, pilot_throughput, reconcile, timestamp
    report = evidence.load(spec["report"])
    request_path = evidence.path(spec["request"], ".json")
    quote_path, catalog_path = evidence.path(spec["quote"], ".json"), evidence.path(spec["catalog"], ".json")
    request, approval, ledger, inventories, inputs = load_scope(request_path, root=evidence.root)
    quote, rates = price_basis(quote_path, catalog_path, request=request, approval=approval)
    for ref in report.get("source_inputs", []):
        if file_digest(evidence.path(ref["path"], ".json")) != ref["sha256"]:
            raise ValueError("cost_source_artifact_changed")
    for ref in inputs:
        if file_digest(evidence.path(ref["path"], ".json")) != ref["sha256"]:
            raise ValueError("cost_scope_artifact_changed")
    extra = [row["prepared_campaign"]["path"] for row in report.get("throughput", {}).get("qualifying_cases", []) if row.get("prepared_campaign")]
    extra += spec.get("pilot_campaigns", [])
    for path in extra:
        evidence.path(path, ".json")
    prepared = prepared_pilot_campaigns(request, inventories, extra)
    throughput = pilot_throughput(inventories, dataset, plan["training_candidate"]["num_rounds"], prepared)
    assumptions = report["remaining_work_assumptions"]
    repeated = reconcile(request, approval, ledger, inventories, quote, rates,
        now=timestamp(report["as_of_utc"]), throughput=throughput, remaining_cells=assumptions["cells"],
        remaining_deployments=assumptions["future_deployments"], application_launches=assumptions["application_launches"],
        fault_events=assumptions["bounded_fault_events"], observations=report.get("aws_observations"),
        **({"root": evidence.root} if approval.get("kind") == "campaign-authorization-amendment" else {}))
    equal = all(report.get(key) == value for key, value in repeated.items())
    required_sources = {"scripts/reconcile_campaign_cost.py"}
    if approval.get("kind") == "campaign-authorization-amendment":
        required_sources.add("scripts/campaign_budget.py")
    if "cost_scope_snapshot" in request:
        required_sources.add("scripts/cost_scope_snapshot.py")
    ready = equal and source_current(report.get("source_sha256", {}), plan, required=required_sources)
    from forecast_remaining_campaign import replay_for_gate
    forecast = replay_for_gate(spec.get("remaining_forecast"), evidence, plan, dataset, report, clouds)
    result = {"reproduced": ready, "operator_budget": ready and repeated["checks"]["operator_budget"],
        "current_spend_accounted": ready and repeated["checks"]["current_spend_accounted"],
        "projected_cost": ready and forecast.get("reproduced") is True and forecast.get("projected_cost") is True,
        "projected_total_usd": forecast.get("projected_total_usd"),
        "projected_cumulative_fleet_hours": forecast.get("projected_cumulative_fleet_hours"),
        "remaining_forecast": forecast,
        "legacy_flat_projected_total_usd": repeated["projected_total_conservative_estimate_usd"],
        "current_conservative_estimate_usd": repeated["current_conservative_planning_estimate_usd"],
        "approved_total_usd": approval["approved_total_usd"], "measurement": repeated["measurement"],
        "actual_bill_reconciled": repeated["actual_bill_reconciled"], "scope_deployments": sorted(inventories)}
    if approval.get("kind") == "campaign-authorization-amendment":
        result.update(budget_semantics="cumulative-inclusive-of-predecessors",
            maximum_cumulative_fleet_hours=approval["max_cumulative_fleet_hours"], budget_lineage=repeated["budget_lineage"])
    return result


def control_facts(report, inventory):
    account, region = inventory.get("account_id"), inventory.get("region")
    scope = (report.get("campaign_id") == inventory.get("campaign_id") and report.get("account_id") == account
             and report.get("region") == region and report.get("performed_read_only") is True)
    schedules = report.get("schedules", [])
    expiry = (scope and len(schedules) == 2 and len({row.get("schedule_arn") for row in schedules}) == 2
        and len({row.get("function_arn") for row in schedules}) == 2
        and all(row.get("state") == "ENABLED" and row.get("function_state") == "Active"
            and row.get("last_update_status") == "Successful" and row.get("target", {}).get("Arn") == row.get("function_arn")
            and row.get("timezone") == "UTC" and row.get("flexible_time_window") == {"Mode": "OFF"}
            and row.get("expression", "").startswith("at(") and row.get("function_code_sha256")
            and f":{account}:" in row.get("function_arn", "") for row in schedules))
    proof = report.get("machine_alert_evidence", {})
    queue, topic = proof.get("queue", {}), proof.get("expected_topic_arn", "")
    query = {"NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN", "Threshold": 80, "ThresholdType": "PERCENTAGE"}
    notification = any(all(row.get(name) == query[name] for name in ("NotificationType", "ComparisonOperator", "Threshold"))
        and ("ThresholdType" not in row or row["ThresholdType"] == "PERCENTAGE") for row in proof.get("notifications", []))
    notifications = (scope and queue.get("SqsManagedSseEnabled") == "true" and f":{region}:{account}:" in queue.get("QueueArn", "")
        and f":{region}:{account}:" in topic and proof.get("subscribers_query_notification") == query and notification
        and any(row.get("Protocol") == "sqs" and row.get("Endpoint") == queue.get("QueueArn") and row.get("TopicArn") == topic
                and row.get("SubscriptionArn", "").startswith(topic + ":") and row.get("Owner") == account for row in proof.get("subscriptions", []))
        and any(row.get("SubscriptionType") == "SNS" and row.get("Address") == topic for row in proof.get("subscribers", [])))
    return {"expiry": bool(expiry), "notifications": bool(notifications), "billing_delivery_observed": report.get("cost_alert_billing_delivery_observed") is True}


def derive_checks(plan, local, services, container, clouds, faults, controls, costs, *, global_binding, errors, isolations=()):
    """Pure aggregation of independently derived facts; no authored pass flags."""
    checks = {gate: {name: False for name in names} for gate, names in GATE_CHECKS.items()}
    reasons = {gate: {} for gate in GATE_CHECKS}
    def put(gate, name, passed, explanation):
        checks[gate][name] = bool(passed)
        reasons[gate][name] = {"passed": bool(passed), "reason": ("established: " if passed else "not-established: ") + explanation}
    local_valid = global_binding and all(local.get(key) is True for key in ("successful", "protocol", "inputs", "full", "real", "five", "validation_only", "curves_valid", "initialization_matched"))
    for name, value in (("real_training", local.get("real") and local.get("successful")),
                        ("full_own_partitions", local.get("full") and local.get("inputs")),
                        ("five_independent_seeds", local.get("five") and local.get("initialization_matched")),
                        ("frozen_training_protocol", local.get("protocol")), ("validation_only", local.get("validation_only"))):
        put("P5_training", name, global_binding and value, "Derived from ten full local client-round/validation curves and exact source/config/data hashes; five seeds per distribution required.")
    rows = [row for cloud in clouds for row in cloud.get("rows", [])]
    primary = [row for row in rows if row["scenario"] in {"S0", "S1", "S2", "S3"}]
    expected = {(baseline, distribution, scenario, 296) for baseline in BASELINES for distribution in DISTRIBUTIONS for scenario in ("S0", "S1", "S2", "S3")}
    labels = [(row["baseline"], row["distribution"], row["scenario"], row["seed"]) for row in primary]
    exact_matrix = len(labels) == len(set(labels)) == 32 and set(labels) == expected
    protocol = bool(primary) and all(all(row["facts"].get(key) is True for key in ("protocol", "partitions", "full", "seed", "validation_full", "validation_only", "resources")) for row in primary)
    independent = bool(primary) and all((row.get("summary") or {}).get("successful") is True and row["summary"].get("persistent_protocol_verified") is True for row in primary)
    cloud_valid = global_binding and exact_matrix and protocol and independent and all(cloud.get("placement_successful") is True for cloud in clouds)
    observer_complete = exact_matrix and all(
        (row.get("summary") or {}).get("runtime_observations_verified") is True
        and row["summary"].get("revocation_response", {}).get("operation_coverage_complete") is True
        and row["summary"].get("revocation_response", {}).get("measurement_errors") == 0
        and row["summary"].get("revocation_response", {}).get("missing_events") == 0
        and row["summary"].get("revocation_response", {}).get("status") in ({"no-event"} if row["scenario"] == "S0" else {"measured", "right-censored", "mixed"})
        and (row["scenario"] == "S0" or (row["summary"].get("revocation_response", {}).get("opportunity_events") or 0) > 0)
        for row in primary)
    named = services.get("named_checks", {})
    local_services = services.get("successful") is True
    container_ok = (container.get("successful") is True and container.get("source_current") is True
        and container.get("native_mutual_tls_services") is True and container.get("eight_client_containers") is True
        and len(container.get("cases", [])) == 8)
    opa = independent and any(row["native_opa_calls"] > 0 for row in primary if row["baseline"] == "P1") and named.get("native_oracle") is True
    put("P6_semantics", "independent_oracle", global_binding and independent and local_services and named.get("native_oracle"), "Each cloud case is independently reconstructed; source-current native OPA matches all sixteen independent oracle fixtures.")
    # Primary timing traces are cloud observations; remaining scenarios combine
    # targeted cloud/protected cases with explicitly local service regressions.
    coverage = {row["scenario"] for row in rows if row.get("summary") or row.get("partial")}
    if local_services and named.get("native_oracle") and named.get("races_and_regrant"):
        coverage |= {"S4", "S5", "S6"}
    if local_services and named.get("duplicate_restart"):
        coverage.add("S7")
    if any(row.get("scripted_fault") in {"audit_transport_unavailable", "opa_transport_unavailable"} for row in faults):
        coverage.add("S8")
    put("P6_semantics", "s0_s8_coverage", global_binding and {f"S{i}" for i in range(9)} <= coverage and container_ok,
        "S0-S3 must have real cloud observations; S4-S7 may use named current native/service regressions; S8 needs a separately protected runtime fault case. Local coverage is not a cloud targeted trial.")
    put("P6_semantics", "native_opa", global_binding and opa and container_ok, "Actual native OPA IDs/queries verified in cloud; current real mTLS container/service campaign required.")
    put("P6_semantics", "durable_publication", global_binding and independent and all(row["summary"].get("published_models", 0) > 0 and row["summary"].get("model_reconstruction_verified") is True for row in primary), "Actual committed DDB manifests, S3 versions, reconstructed models and pointer chain required for every main-pilot cell.")
    p1 = [row for row in primary if row["baseline"] == "P1"]
    unsafe = [row for row in primary if row["baseline"] in {"B1", "B2", "B3"} and row["scenario"] in {"S2", "S3"}]
    baseline_invalid = (len(unsafe) == 12 and all((row.get("summary") or {}).get("oracle_invalid_presented", 0) > 0
        and row["summary"].get("oracle_invalid_incorporations", 0) > 0 for row in unsafe))
    for name, value in (("all_four_methods", exact_matrix), ("independent_oracle", independent),
                        ("expected_unsafe_baselines_observed", baseline_invalid),
                        ("p1_excludes_invalid", len(p1) == 8 and all((row.get("summary") or {}).get("oracle_invalid_incorporations") == 0 for row in p1)
                         and all((row.get("summary") or {}).get("oracle_invalid_presented", 0) > 0 for row in p1 if row["scenario"] in {"S2", "S3"})),
                        ("no_b1_opa_overhead", any(row["baseline"] == "B1" for row in primary) and all(row["native_opa_calls"] == 0 for row in primary if row["baseline"] == "B1"))):
        put("baseline_oracle", name, global_binding and value, "Derived from exactly32 seed296 method/distribution/scenario cases; expected unsafe S2/S3 baselines must include actual invalid updates while P1 excludes them.")
    groups = {}
    for row in primary:
        groups.setdefault((row["distribution"], row["scenario"], row["seed"]), []).append(row)
    matched = exact_matrix and all(len(group) == 4 and len({row["facts"].get("shared_digest") for row in group}) == 1 for group in groups.values())
    initials = exact_matrix and all(len({row["initialization_config_digest"] for row in group}) == 1 for group in groups.values())
    stable_models = [group for key, group in groups.items() if key[1] == "S0"]
    initials = initials and len(stable_models) == 2 and all(len({row["facts"].get("final_model_digest") for row in group}) == 1 and all(row["facts"].get("final_model_digest") for row in group) for group in stable_models)
    schedules = exact_matrix and all(len({digest(row["policy_trace"]) for row in group}) == 1 for group in groups.values())
    for name, value in (("full_config_equivalence", matched and protocol), ("same_initial_model", initials),
                        ("same_partitions", matched and all(row["facts"].get("partitions") is True for row in primary)),
                        ("same_schedule", matched and schedules), ("same_training_budget", matched and protocol)):
        put("manifest_equivalence", name, global_binding and value, "Match public source-pinned inputs, all full sample counts, initialization context and stable final digests; compare relative policy-event barriers rather than growing absolute authority epochs.")
    audited = independent and all(row["summary"].get("audit_verified") is True and row["summary"].get("audit_complete_decisions") == row["summary"].get("final_decisions") for row in primary)
    p1_faults = [row for row in faults if row.get("ablation_id") is None]
    fault_audit = bool(p1_faults) and all(row["summary"].get("audit_complete_for_all_final_outcomes") is True
        and row["summary"].get("final_audit_expected_count") == row["summary"].get("final_audit_recorded_count") for row in p1_faults)
    accounted = fault_audit and all(row["summary"].get("attempt_accounting_complete") is True and row["summary"].get("indeterminate_count") == 0 for row in p1_faults)
    fault_kinds = set()
    for row in p1_faults:
        for trace in row.get("fault_trace", []):
            if (trace.get("phase") == "fault_failed_closed" and trace.get("pointer_unchanged") is True
                    and trace.get("published_models_during_fault") == 0 and trace.get("recovery_errors") == []
                    and (row.get("scripted_fault") != "audit_transport_unavailable" or trace.get("blocked_calls", 0) > 0)):
                fault_kinds.add(row.get("scripted_fault"))
    fault_closed = {"audit_transport_unavailable", "opa_transport_unavailable"} <= fault_kinds and accounted
    tamper = any({entry["attack_id"] for entry in row.get("protected_tamper_checks", []) if entry.get("detected") is True} in (TAMPER_KINDS, CLOUD_TAMPER_KINDS) for row in faults)
    anchors = bool(rows) and all(row["anchored"] is True for row in rows) and bool(p1_faults) and all(row["summary"].get("protected_witness_verified") is True for row in p1_faults)
    for name, value in (("all_final_decisions_audited", audited and fault_audit),
                        ("operational_errors_accounted", accounted and local_services and named.get("error_accounting") and bool(p1_faults) and all(row["summary"].get("final_error_count", 0) > 0
                            or (row.get("operational_abort_accounting", {}).get("verified") is True
                                and type(row["operational_abort_accounting"].get("operational_abort_rejected_update_count")) is int
                                and row["operational_abort_accounting"]["operational_abort_rejected_update_count"] > 0)
                            for row in p1_faults)),
                        ("external_anchor", anchors), ("tamper_detection", tamper), ("fail_closed_faults", fault_closed)):
        put("P7_safety_audit", name, global_binding and value, "Count every allow/deny/error plus indeterminate task; protected P1 fault proofs must retain unchanged pointers and complete recovery, with external key pins and six changed-copy attacks.")
    for name, value in (("five_seed_full_data_validation", local_valid), ("cloud_protocol_pilot", cloud_valid),
                        ("failures_retained", local.get("retained") and bool(clouds) and all(row.get("all_case_outcomes_retained") is True for row in clouds)),
                        ("performance_review", local_valid and observer_complete and all(value.get("independent_seeds") == 5 and finite(value.get("auroc_sample_sd")) for value in local.get("descriptive_variance", {}).values()) and len(local.get("descriptive_variance", {})) == 2),
                        ("no_test_access", local.get("validation_only") and bool(rows) and all(not row["test_accessed"] for row in rows + faults))):
        put("P8_pilot", name, global_binding and value, "Five full local seeds provide descriptive learning variance; all32 current cloud traces require independent event/operation bindings and complete coverage, explicit S0 no-event and bounded/censored changed-policy responses with zero measurement errors. No final-test data or confirmatory power claim is used.")
    placement_names = {
        "actual_fargate": {"simultaneously_running_fargate", "actual_linux_amd64_platform"},
        "eight_clients": {"eight_distinct_learning_clients", "distinct_task_eni_and_private_ip"},
        "distinct_roles_and_partitions": {"actual_role_and_org_binding", "nine_actual_attributable_iam_probes"},
        "private_network": {"actual_private_network_boundary", "actual_private_subnets", "no_internal_appio_ports"},
        "actual_boundary_probes": {"nine_actual_attributable_iam_probes"},
        "image_source_binding": {"actual_image_manifest_relation", "source_snapshot_integrity", "snapshot_matches_current_image", "snapshot_matches_current_application"}}
    placements = [*clouds, *isolations]
    runtime_reference = plan["provenance"]["image_digests"].get("runtime")
    current_runtime_placed = bool(runtime_reference) and any(cloud.get("image_reference") == runtime_reference for cloud in placements)
    for name, required in placement_names.items():
        value = current_runtime_placed and all(cloud.get("placement_successful") is True and all(cloud["placement"].get(key) is True for key in required) for cloud in placements)
        put("fargate_isolation", name, global_binding and value, "Replay actual task/ENI/IAM probes/private placement and captured image/source/config generation; local containers cannot establish Fargate isolation.")
    needed_controls = {cloud["inventory"]["campaign_id"] for cloud in placements}
    control_by_campaign = {row.get("campaign_id"): row for row in controls}
    observed_controls = {cloud["inventory"]["campaign_id"]: control_facts(control_by_campaign.get(cloud["inventory"]["campaign_id"], {}), cloud["inventory"]) for cloud in placements}
    expiry = bool(needed_controls) and all(observed_controls[name]["expiry"] for name in needed_controls)
    notifications = bool(needed_controls) and all(observed_controls[name]["notifications"] for name in needed_controls)
    for name, value in (("operator_budget", costs.get("operator_budget")), ("current_spend_accounted", costs.get("current_spend_accounted")),
                        ("projected_cost", costs.get("projected_cost")), ("expiry_backstops", expiry), ("notifications_verified", notifications)):
        reason = "Replay priced past usage and current-source stratified forecast for279 scientific cells, actual pending safety12-or-verified0 and one fresh-main G1; retain1.5 margin, launches/faults,12h application/24h project bounds and original$20/32h limits. Verify deployed expiry and encrypted machine budget subscription; billing-threshold delivery remains unobserved unless separately captured."
        if costs.get("budget_semantics") == "cumulative-inclusive-of-predecessors":
            reason = "Replay typed cumulative user approval and terminal predecessor lineage, exact carried ledger/inventories, inherited reserves/costs and fresh measured usage; compare full remaining-work forecast with that approved cumulative USD/fleet limit and unchanged capacity/expiry. Snapshot replay stays read-only and does not retroactively change predecessor compliance."
        put("cost_budget", name, global_binding and value, reason)
    return checks, reasons, {"cloud296_expected_cells": 32, "cloud296_observed_cells": len(primary), "exact_cloud296_matrix": exact_matrix,
        "cloud_protocol_valid": cloud_valid, "cloud_observer_coverage_complete": observer_complete, "semantic_coverage": sorted(coverage), "local_services_valid": local_services,
        "current_container_campaign_valid": container_ok, "matched_groups": len(groups), "current_runtime_placed": current_runtime_placed,
        "fresh_isolation_snapshots": len(isolations), "protected_fault_kinds": sorted(kind for kind in fault_kinds if kind),
        "local_descriptive_variance": local.get("descriptive_variance", {}),
        "local_training_checks": {key: value for key, value in local.items() if key != "descriptive_variance"},
        "local_service_checks": services, "scientific_binding_current": global_binding,
        "cloud_case_checks": [{"cell_id": row["cell_id"], "baseline": row["baseline"], "distribution": row["distribution"],
            "scenario": row["scenario"], "seed": row["seed"], "required_protocol_checks": row["facts"],
            "independent_verification": bool(row.get("summary")), "external_anchor": row["anchored"],
            "native_opa_calls": row["native_opa_calls"],
            "oracle_invalid_presented": (row.get("summary") or {}).get("oracle_invalid_presented"),
            "oracle_invalid_incorporations": (row.get("summary") or {}).get("oracle_invalid_incorporations")} for row in rows],
        "protected_partial_assessments": [{key: value for key, value in row.items() if key not in {"fault_trace"}} for row in faults],
        "control_observations": observed_controls, "cost": costs, "evidence_errors": errors}


def external_tamper_facts(spec, evidence):
    from tamper_cloud_evidence import assess
    report = evidence.load(spec["report"])
    inventory_path = evidence.path(spec["inventory"], ".json")
    public = evidence.path(spec["witness_public_key"], ".pem")
    repeated = assess(inventory_path, cell_id=spec["cell_id"], public_key_path=public,
                      public_key_sha256=spec["expected_public_key_sha256"])
    if report != repeated or report.get("successful") is not True:
        raise ValueError("cloud_tamper_report_not_reproduced")
    _, cases = retained_cases(evidence.load(spec["inventory"]), inventory_path)
    selected = [raw for name, directory, raw, sha in cases if name == spec["cell_id"]]
    if len(selected) != 1 or selected[0].get("test_holdout_evaluated") is not False:
        raise ValueError("validation_only_tamper_case_required")
    return {"ablation_id": "external-tamper-only", "protected_tamper_checks": report["attacks"],
            "scripted_fault": None, "test_accessed": False, "tamper_scope": report["tamper_scope"],
            "case_sha256": report["raw_result_sha256"]}


def assess_pilots(plan, inputs, root=ROOT):
    validate_plan(plan)
    allowed = {"data_manifest", "local_training", "local_validation", "container_validation", "cloud_pilots", "isolation_inventories", "fault_cases", "tamper_tests", "controls", "cost"}
    if not isinstance(inputs, dict) or set(inputs) - allowed:
        raise ValueError("known_pilot_evidence_inputs_required")
    evidence, errors = Evidence(root), []
    def attempt(label, function, default):
        try:
            return function()
        except ERRORS as error:
            errors.append({"evidence": label, "type": type(error).__name__, "reason": str(error)[:300]})
            return default
    dataset = attempt("data_manifest", lambda: evidence.load(inputs.get("data_manifest", plan["configuration"]["data_manifest"])), {})
    current = attempt("source_inventory", lambda: all(file_digest(evidence.path(name)) == sha for name, sha in plan["provenance"]["source_files_sha256"].items()), False)
    binding = bool(dataset) and current and digest(scientific_data(dataset)) == plan["data_manifest_digest"]
    local = attempt("local_training", lambda: local_training_facts(evidence.load(inputs["local_training"]), dataset, plan), {})
    services = attempt("local_validation", lambda: local_service_facts(inputs["local_validation"], evidence, plan), {})
    container = attempt("container_validation", lambda: evidence.load(inputs["container_validation"]), {})
    container["source_current"] = source_current(container.get("source_files_sha256", {}), plan)
    collections = {}
    for name, limit in (("cloud_pilots", 32), ("isolation_inventories", 8), ("fault_cases", 32), ("tamper_tests", 16), ("controls", 8)):
        values = inputs.get(name, [])
        if not isinstance(values, list) or len(values) > limit:
            raise ValueError("bounded_pilot_evidence_collection_required:" + name)
        collections[name] = values
    clouds = [attempt("cloud_pilots:" + str(index), lambda spec=spec: cloud_pilot_facts(spec, evidence, dataset, plan), {})
              for index, spec in enumerate(collections["cloud_pilots"])]
    clouds = [value for value in clouds if value]
    isolations = [attempt("isolation_inventories:" + str(index), lambda name=name: isolation_facts(name, evidence, plan), {})
                  for index, name in enumerate(collections["isolation_inventories"])]
    isolations = [value for value in isolations if value]
    faults = [attempt("fault_cases:" + str(index), lambda spec=spec: protected_fault_facts(spec, evidence), {})
              for index, spec in enumerate(collections["fault_cases"])]
    faults = [value for value in faults if value]
    for fault in faults:
        matches = [row for cloud in clouds for row in cloud["rows"]
            if row.get("raw_result_sha256") == fault.get("case_sha256")
            and row.get("failed_validation_scope", {}).get("verified") is True]
        if len(matches) == 1:
            fault["failed_validation_scope"] = matches[0]["failed_validation_scope"]
            fault["test_accessed"] = False
    faults += [{"summary": row["partial"], "ablation_id": row.get("ablation_id"), "scenario": row.get("scenario"),
                "scripted_fault": row.get("scripted_fault"), "fault_trace": row.get("fault_trace", []),
                "operational_abort_accounting": row.get("operational_abort_accounting", {}),
                "failed_validation_scope": row.get("failed_validation_scope", {}),
                "test_accessed": row.get("test_accessed"), "execution_successful": row.get("execution_successful"),
                "protected_tamper_checks": []}
               for cloud in clouds for row in cloud["rows"] if row.get("partial") is not None]
    faults += [attempt("tamper_tests:" + str(index), lambda spec=spec: external_tamper_facts(spec, evidence), {})
               for index, spec in enumerate(collections["tamper_tests"])]
    faults = [value for value in faults if value]
    controls = [attempt("controls:" + str(index), lambda name=name: evidence.load(name), {}) for index, name in enumerate(collections["controls"])]
    costs = attempt("cost", lambda: cost_facts(inputs["cost"], evidence, plan, dataset, clouds), {})
    checks, reasons, facts = derive_checks(plan, local, services, container, clouds, faults, controls, costs,
                                          global_binding=binding, errors=errors, isolations=isolations)
    dependencies = {"data_manifest": set(GATE_CHECKS), "source_inventory": set(GATE_CHECKS),
        "local_training": {"P5_training", "P8_pilot"}, "local_validation": {"P6_semantics", "P7_safety_audit"},
        "container_validation": {"P6_semantics"}, "cloud_pilots": {"P6_semantics", "P7_safety_audit", "P8_pilot", "baseline_oracle", "manifest_equivalence", "fargate_isolation"},
        "isolation_inventories": {"fargate_isolation", "cost_budget"},
        "fault_cases": {"P6_semantics", "P7_safety_audit", "P8_pilot"}, "tamper_tests": {"P7_safety_audit", "P8_pilot"}, "controls": {"cost_budget"}, "cost": {"cost_budget"}}
    # A missing requested source cannot be hidden by a successful subset.
    for error in errors:
        for gate in dependencies[error["evidence"].split(":")[0]]:
            for name in checks[gate]:
                checks[gate][name] = False
                reasons[gate][name] = {"passed": False, "reason": "requested-evidence-unavailable:" + error["evidence"] + ":" + error["reason"]}
    return {"successful": all(all(group.values()) for group in checks.values()), "checks": checks, "reasons": reasons,
        "facts": facts, "scientific_binding_current": binding,
        "source_artifacts": [{"path": name, "sha256": sha} for name, sha in sorted(evidence.sources.items())],
        "limitations": ["These are preregistration readiness gates, not confirmatory hypothesis results.",
            "Learning variability uses five local seeds; cloud protocol observations use one seed across32 cells.",
            "Five seed clusters give limited precision; no prospective power guarantee is asserted.",
            "Local native/service checks for targeted semantics are not actual cloud robustness trials.",
            "Initialization equivalence binds captured constructor metadata/seed/source and equal stable final models; raw initial arrays are not exported.",
            "Copied evidence attacks do not modify protected AWS objects or establish arbitrary adversary coverage.",
            "Expected S8 fault outcomes remain failed executions and do not satisfy the current clean-targeted H3 inferential readiness rule.",
            "Inferred usage, service reserves and future-duration assumptions are not a hard billing cap or invoice."]}


def write_assessments(plan, result, output, root=ROOT):
    root, output = Path(root).resolve(), Path(output).resolve()
    if not output.is_relative_to(root):
        raise ValueError("gate_output_must_be_owned_repository_directory")
    def retain(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        content = canonical(value) + b"\n"
        if path.exists() and path.read_bytes() != content:
            raise ValueError("gate_output_exists_use_new_version")
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(content)
    gate_paths = {}
    for gate, values in sorted(result["checks"].items()):
        passing = all(values.values())
        derived = {"kind": "derived-pilot-gate-evidence", "successful": passing, "gate_id": gate,
            "candidate_plan_digest": plan["plan_digest"], "scientific_binding": scientific_binding(plan),
            "checks": result["reasons"][gate], "facts": result["facts"],
            "source_artifacts": result["source_artifacts"], "limitations": result["limitations"]}
        leaf = output / (gate + "-evidence.json")
        retain(leaf, derived)
        path = output / (gate + ".json")
        retain(path, {"kind": "scientific-gate-assessment", "successful": passing, "gate_id": gate,
            "candidate_plan_digest": plan["plan_digest"], "scientific_binding": scientific_binding(plan),
            "reviewer": "automated-pilot-evidence-assessor-v1", "checks": values,
            "evidence": [{"path": leaf.relative_to(root).as_posix(), "sha256": file_digest(leaf)}]})
        gate_paths[gate] = path.relative_to(root).as_posix()
    retain(output / "gate-paths.json", gate_paths)
    retain(output / "pilot-readiness.json", {"kind": "actual-pilot-gate-readiness", "successful": result["successful"],
        "candidate_plan_digest": plan["plan_digest"], "scientific_binding": scientific_binding(plan), **result,
        "final_test_accessed": False, "aws_calls": False, "accepted_plan_created": False})
    return gate_paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--inputs", required=True, help="Public JSON paths to actual retained pilot evidence")
    parser.add_argument("--output", required=True, help="New repository-owned assessment directory")
    args = parser.parse_args()
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    result = assess_pilots(plan, json.loads(Path(args.inputs).read_text(encoding="utf-8")))
    write_assessments(plan, result, args.output)
    print(json.dumps({"successful": result["successful"], "gate_passed": {gate: all(values.values()) for gate, values in result["checks"].items()},
        "candidate_plan_digest": plan["plan_digest"], "evidence_errors": result["facts"]["evidence_errors"],
        "acceptance_input": str(Path(args.output) / "gate-paths.json"), "aws_calls": False, "final_test_accessed": False}, sort_keys=True, indent=2))
    return 0 if result["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
