"""Offline, staged planning model. It grants no execution or spending permission.

Default pending-safety projection reads pinned JSON metadata only. Removing all
twelve safety cases requires native offline assessor replay (retained model NPZ
and public-key evidence); no AWS, dataset loader or clinical CSV is used. The P8
gate additionally binds timing inputs to freshly independent verified cases.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re

VERSION = "pcfl-remaining-work-stratified-v2"
SOURCE_NAME = "scripts/forecast_remaining_campaign.py"
METHODS = ("B1", "B2", "B3", "P1")
DISTRIBUTIONS = ("iid", "non_iid")
HEX = re.compile(r"[0-9a-f]{64}\Z")
COUNTS = {"primary": 160, "targeted": 50, "ablation": 40, "replication": 8, "exploratory": 21}


def number(value, minimum=0):
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum:
        raise ValueError("finite_planning_number_required")
    return value


def count(value):
    if type(value) is not int or not 0 <= value <= 10000:
        raise ValueError("bounded_typed_planning_count_required")
    return value


def stamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("aware_planning_timestamp_required")
    return result.astimezone(timezone.utc)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ref(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": sha(path)}


def load_bound(value, base):
    if (not isinstance(value, dict) or set(value) != {"path", "sha256"}
            or not isinstance(value["sha256"], str) or not HEX.fullmatch(value["sha256"])):
        raise ValueError("explicit_json_input_pin_required")
    path = Path(value["path"])
    path = path if path.is_absolute() else base / path
    if path.suffix.lower() != ".json" or path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("regular_bounded_json_metadata_only")
    if sha(path) != value["sha256"]:
        raise ValueError("forecast_input_digest_mismatch")
    return json.loads(path.read_text(encoding="utf-8")), path.resolve()


def canonical_scenario(value):
    return {"stable": "S0", "between_round": "S1", "mid_round": "S2", "delayed": "S3"}.get(value, value)


def collect_batch(spec, *, base, account_id, region, image_digest, witness_pin, manifest):
    """Consume one complete, externally protected 16-case training pilot export."""
    values, paths = {}, {}
    for name in ("verification", "placement", "inventory", "prepared_campaign", "export_index"):
        values[name], paths[name] = load_bound(spec[name], base)
    verification, placement, inventory, prepared, index = (values[name] for name in
        ("verification", "placement", "inventory", "prepared_campaign", "export_index"))
    distribution = spec["distribution"]
    if distribution not in DISTRIBUTIONS:
        raise ValueError("registered_pilot_distribution_required")
    app = prepared["campaign_id"]
    for value in (verification, placement, inventory):
        if value.get("account_id") != account_id or value.get("region") != region:
            raise ValueError("forecast_pilot_account_region_mismatch")
    if (verification.get("kind") != "independent-cloud-campaign-export-validation"
            or verification.get("application_campaign_id") != app or verification.get("successful") is not True
            or verification.get("externally_protected_witnesses_verified") is not True
            or verification.get("test_holdout_evaluated") is not False
            or any(verification.get(key) for key in ("failed_cases", "partial_assessments", "unprotected_case_ids"))):
        raise ValueError("complete_protected_training_pilot_verification_required")
    if (placement.get("kind") != "actual-aws-learning-placement-validation" or placement.get("successful") is not True
            or not placement.get("checks") or any(value is not True for value in placement["checks"].values())
            or placement.get("source_snapshot", {}).get("application_campaign_id") != app
            or placement.get("source_snapshot", {}).get("image_relations", {}).get(image_digest, {}).get("verified") is not True
            or inventory.get("application_campaign_id") != app
            or not inventory.get("image", {}).get("reference", "").endswith("@" + image_digest)):
        raise ValueError("pinned_image_actual_placement_required")
    if inventory.get("shutdown_confirmation", {}).get("confirmed") is not True:
        raise ValueError("completed_pilot_compute_shutdown_required")
    export = inventory["exports_by_application"][app]
    if (export.get("index_sha256") != spec["export_index"]["sha256"]
            or export.get("index_version_id") in (None, "", "null")
            or export.get("index_key") != f"evidence/campaigns/{app}/campaign_result.json"
            or index.get("campaign_id") != app
            or Path(export["export_root"]).resolve() != paths["export_index"].parent):
        raise ValueError("exact_versioned_export_index_required")
    upload_matches = [row for row in inventory.get("uploads", []) if row.get("sha256") == spec["prepared_campaign"]["sha256"]
        and row.get("key", "").startswith("metadata/") and row.get("version_id") not in (None, "", "null")]
    if not upload_matches:
        raise ValueError("prepared_pilot_uploaded_version_required")
    mappings = {}
    for label, rows in (("prepared", prepared["cases"]), ("index", index["cases"]), ("verification", verification["verified_cases"])):
        mappings[label] = {row["cell_id"]: row for row in rows}
        if len(mappings[label]) != len(rows) or len(rows) != 16:
            raise ValueError("complete_unique_sixteen_case_pilot_required")
    if not (mappings["prepared"].keys() == mappings["index"].keys() == mappings["verification"].keys()):
        raise ValueError("pilot_report_index_config_case_binding_mismatch")
    expected = manifest["partitions"][distribution]["organizations"]
    if len(expected) != 8:
        raise ValueError("eight_public_partition_counts_required")
    combinations, observations, finished, tasks = set(), [], [], set(inventory.get("task_arns", []))
    all_outer_seconds, started = 0.0, []
    for cell_id, case in mappings["index"].items():
        runtime = mappings["prepared"][cell_id]["runtime"]
        method, scenario = runtime["baseline_id"], canonical_scenario(runtime["scenario_id"])
        pair = (method, scenario)
        if pair in combinations or method not in METHODS or scenario not in ("S0", "S1", "S2", "S3") or runtime.get("distribution") != distribution:
            raise ValueError("exact_four_method_four_scenario_pilot_required")
        combinations.add(pair)
        artifacts = [row for row in case.get("artifacts", []) if row.get("key", "").endswith("/runtime_result.json")]
        if len(artifacts) != 1 or artifacts[0].get("version_id") in (None, "", "null"):
            raise ValueError("one_exact_versioned_raw_result_required")
        artifact = artifacts[0]
        if (artifact.get("bucket") != inventory.get("foundation", {}).get("bucket_name")
                or artifact.get("key") != f"evidence/campaigns/{app}/{cell_id}/runtime_result.json"):
            raise ValueError("owned_exact_raw_object_key_required")
        raw_path = Path(export["case_directories"][cell_id]) / "runtime_result.json"
        raw, _ = load_bound({"path": str(raw_path), "sha256": artifact["sha256"]}, base)
        verified = mappings["verification"][cell_id]
        witness = verified.get("protected_operator_witness", {})
        summary = verified["summary"]
        if (raw_path.stat().st_size != artifact["size_bytes"] or case.get("successful") is not True
                or raw.get("successful") is not True or raw.get("aws_used") is not True
                or raw.get("test_holdout_evaluated") is not False or raw.get("cloud_campaign_id") != app
                or raw.get("cell_id") != cell_id or raw.get("persistent_run_id") != runtime.get("persistent_run_id")
                or raw.get("baseline_id") != method or canonical_scenario(raw.get("scenario_id")) != scenario
                or verified.get("raw_result_sha256") != artifact["sha256"]
                or witness.get("protected_witness_verified") is not True or witness.get("external_public_key_sha256") != witness_pin
                or witness.get("witness", {}).get("raw_result_sha256") != artifact["sha256"]
                or summary.get("successful") is not True or summary.get("persistent_protocol_verified") is not True):
            raise ValueError("full_protected_pilot_raw_binding_required")
        finished.append(stamp(raw["case_finished_at_utc"]))
        started.append(stamp(raw["case_started_at_utc"]))
        all_outer_seconds += number(raw["elapsed_seconds"], .000001)
        if scenario != "S0":
            continue
        records = raw.get("client_training", [])
        frozen = {"optimizer": "adam", "learning_rate": .001, "batch_size": 64, "local_epochs": 1,
            "num_rounds": 5, "hidden_dims": [64, 32], "cpu_threads": 1, "device": "cpu"}
        training = runtime.get("training", {})
        if (runtime.get("rounds") != 5 or len(raw.get("rounds", [])) != 5 or len(records) != 40
                or any(training.get(key) != value for key, value in frozen.items())
                or runtime.get("model_metadata", {}).get("hidden_dims") != [64, 32]
                or summary.get("committed_evaluation_response_verified") is not True
                or raw.get("validation_metrics", {}).get("count") != manifest["splits"]["validation"]["encounters"]
                or any(sum(row.get("org_id") == org and row.get("round_id") == f"round-{n}"
                    and row.get("sample_count") == sizes["encounters"] for row in records) != 1
                    for org, sizes in expected.items() for n in range(1, 6))):
            raise ValueError("five_round_full_partition_pilot_required")
        stages = [row for row in raw.get("runtime_observations", {}).get("stages", []) if row.get("name") == "run"]
        durations = summary.get("runtime_stage_latency_ms", {}).get("run", [])
        if (summary.get("runtime_observations_verified") is not True or len(stages) != 1 or len(durations) != 1
                or stages[0].get("status") != "complete" or stages[0].get("start_ms") != 0
                or abs(number(stages[0]["end_ms"], .000001) - number(durations[0], .000001)) > 1e-6):
            raise ValueError("independently_verified_complete_run_stage_required")
        server, outer = durations[0] / 1000, number(raw["elapsed_seconds"], .000001)
        if outer < server:
            raise ValueError("server_stage_exceeds_outer_interval")
        restart = runtime.get("host_restart")
        restart_evidence = None
        if restart:
            restart_evidence = inventory.get("client_restart_events", {}).get(restart["request_id"])
            if (not restart_evidence or restart["request_id"] not in placement.get("client_restart_evidence", {}).get("verified", [])
                    or restart.get("run_id") != raw["persistent_run_id"]):
                raise ValueError("configured_restart_needs_actual_verified_event")
        observations.append({"cell_id": cell_id, "application_campaign_id": app, "baseline_id": method,
            "distribution": distribution, "server_run_seconds": server, "outer_seconds": outer,
            "nonrestart_supervisor_seconds": None if restart else outer - server,
            "host_restart_present": bool(restart), "restart_request_id": restart.get("request_id") if restart else None,
            "source_raw": {**artifact, "local_metadata": ref(raw_path)},
            "source_index": {**spec["export_index"], "key": export["index_key"], "version_id": export["index_version_id"]},
            "verification": spec["verification"], "placement": spec["placement"], "prepared_campaign": spec["prepared_campaign"]})
    accounted_times = [*finished, stamp(inventory["shutdown_confirmation"]["at_utc"])]
    accounted_times += [stamp(row["stopped_at"]) for row in inventory.get("observed_tasks", []) if row.get("stopped_at")]
    definitions = set(inventory.get("runtime_contract", {}).get("task_definition_arns", {}).values())
    application_tasks = [row for row in inventory.get("observed_tasks", []) if row.get("task_definition_arn") in definitions]
    shared = None
    if application_tasks and all(row.get("billing_started_at") and row.get("stopped_at") for row in application_tasks):
        start = min(stamp(row["billing_started_at"]) for row in application_tasks)
        end = max(stamp(row["stopped_at"]) for row in application_tasks)
        span = (end - start).total_seconds()
        if span < all_outer_seconds or min(started) < start or max(finished) > end:
            raise ValueError("application_task_clock_span_smaller_than_serial_cases")
        shared = {"task_count": len(application_tasks), "current_task_definition_arns": sorted(definitions),
            "task_arns": sorted(row["task_arn"] for row in application_tasks), "billing_start_utc": start.isoformat(),
            "last_stop_utc": end.isoformat(), "whole_application_task_wall_seconds": span,
            "all_case_outer_seconds": all_outer_seconds, "shared_wall_upper_seconds": span - all_outer_seconds,
            "scope": "current-task-definition generation;startup/probes/export/gaps/stop;actualcaseouteralreadycontainsrestart"}
    bootstrap = None
    all_billing_starts = [stamp(row["billing_started_at"]) for row in inventory.get("observed_tasks", []) if row.get("billing_started_at")]
    if inventory.get("deployment_started_at") and all_billing_starts:
        interval = (min(all_billing_starts) - stamp(inventory["deployment_started_at"])).total_seconds()
        if interval < 0:
            raise ValueError("deployment_begins_after_recorded_task_billing")
        bootstrap = {"deployment_started_at": inventory["deployment_started_at"],
            "first_recorded_task_billing_at": min(all_billing_starts).isoformat(), "elapsed_seconds": interval,
            "pure_bootstrap_benchmark": False, "scope": "pre-first-recorded-task interval includes operator/build gaps"}
    return {"distribution": distribution, "complete_verified_pilot": True, "observations": observations,
        "task_arns": sorted(tasks), "latest_case_finish_utc": max(finished).isoformat(),
        "accounted_through_utc": max(accounted_times).isoformat(),
        "shared_application_envelope": shared,
        "pre_first_recorded_task_interval": bootstrap,
        "source_inputs": [spec[name] for name in values]}


def plan_work(plan):
    canonical = json.dumps({key: value for key, value in plan.items() if key != "plan_digest"},
        sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if plan.get("plan_digest") != hashlib.sha256(canonical).hexdigest():
        raise ValueError("bound_plan_internal_digest_mismatch")
    rows = []
    for family, key in (("primary", "primary_cells"), ("targeted", "targeted_cells"), ("ablation", "ablation_cells"), ("replication", "replication_cells")):
        cells = plan.get(key, [])
        if len(cells) != COUNTS[family]:
            raise ValueError("complete_expected_scientific_registry_required")
        rows += [{"work_id": cell["cell_id"], "family": family, "baseline_id": cell["baseline_id"],
            "distribution": cell["distribution"], "scenario_id": cell["scenario_id"], "variant": cell.get("variant"),
            "seed": cell["seed"], "architecture_multiplier": 1, "partition_multiplier": 1,
            "added_delay_seconds": 0, "registered_cell_id": cell["cell_id"], "completed": False} for cell in cells]
    return rows


def exploratory_work(base_manifest, alternate_manifest):
    """Twenty-one PLANNING rows; actual registration still requires accepted P8/P9."""
    defaults = {"participation_fraction": 1, "revocations_per_round": 1, "update_size_multiplier": 1,
        "artificial_latency_ms": 0, "client_clock_skew_ms": 0, "non_iid_alpha": .5}
    levels = {"participation_fraction": [.5, .75, 1], "revocations_per_round": [0, 1, 4],
        "update_size_multiplier": [1, 4], "artificial_latency_ms": [0, 250, 1000],
        "client_clock_skew_ms": [-60000, 0, 60000], "non_iid_alpha": [.5, 1]}
    configurations = {json.dumps(defaults, sort_keys=True): defaults}
    for factor, choices in levels.items():
        for choice in choices:
            value = {**defaults, factor: choice}
            configurations.setdefault(json.dumps(value, sort_keys=True), value)
    base_max = max(row["encounters"] for row in base_manifest["partitions"]["non_iid"]["organizations"].values())
    alternate_max = max(row["encounters"] for row in alternate_manifest["partitions"]["non_iid"]["organizations"].values())
    ratio = max(1, number(alternate_max, 1) / number(base_max, 1))
    rows = []
    for distribution in DISTRIBUTIONS:
        for value in configurations.values():
            if distribution == "iid" and value["non_iid_alpha"] != .5:
                continue
            identity = hashlib.sha256(json.dumps([distribution, value], sort_keys=True).encode()).hexdigest()[:20]
            rows.append({"work_id": "exploratory-planning-" + identity, "family": "exploratory", "baseline_id": "P1",
                "distribution": distribution, "scenario_id": "robustness", "variant": None, "seed": 296,
                "architecture_multiplier": 4.01 if value["update_size_multiplier"] == 4 else 1,
                "architecture_factor_basis": "source-guaranteed requested4 plus.01 realized-ratio ceiling; replace with max(4,realized bound metadata) before adapter execution" if value["update_size_multiplier"] == 4 else "baseline",
                "partition_multiplier": ratio if value["non_iid_alpha"] == 1 else 1,
                # Delays are concurrent in the app; price all eight serially as a conservative planning allowance.
                "added_delay_seconds": 5 * 8 * value["artificial_latency_ms"] / 1000,
                "registered_cell_id": None, "factors": value, "completed": False})
    if len(rows) != 21:
        raise ValueError("deduplicated_twenty_one_exploratory_settings_required")
    return rows


def safety_work():
    return [{"work_id": f"safety-planning-{distribution}-{scenario}-{seed}", "family": "safety_pilot",
        "baseline_id": "P1", "distribution": distribution, "scenario_id": scenario, "variant": None,
        "seed": seed, "architecture_multiplier": 1, "partition_multiplier": 1, "added_delay_seconds": 0,
        "registered_cell_id": None, "completed": False}
        for distribution in DISTRIBUTIONS for scenario, seed in [*( (f"S{n}", 296) for n in range(4, 9)), ("S8", 593)]]


def sentinel_work():
    # Actual connectivity is one round/64-client-examples/128 validation rows.
    # Budget a whole frozen five-round P1/IID case; no small-case discount.
    return [{"work_id": "fresh-main-connectivity-sentinel", "family": "fresh_g1", "baseline_id": "P1",
        "distribution": "iid", "scenario_id": "S0", "variant": None, "seed": 296,
        "architecture_multiplier": 1, "partition_multiplier": 1, "added_delay_seconds": 0,
        "registered_cell_id": None, "completed": False}]


def verified_safety_completion(rows, expected_hashes):
    """Only fresh assessor results can justify removing twelve future pilots."""
    required = {(d, s, seed) for d in DISTRIBUTIONS for s, seed in
        [*((f"S{n}", 296) for n in range(4, 9)), ("S8", 593)]}
    selected = [row for row in rows if row.get("scenario") in {f"S{n}" for n in range(4, 9)}]
    keys = [(row.get("distribution"), row.get("scenario"), row.get("seed")) for row in selected]
    if len(selected) != 12 or len(set(keys)) != 12 or set(keys) != required or len(expected_hashes) != 12:
        raise ValueError("all_twelve_fresh_safety_pilots_required_before_subtraction")
    for row in selected:
        raw_sha = row.get("raw_result_sha256")
        if (row.get("baseline") != "P1" or row.get("anchored") is not True or row.get("test_accessed") is not False
                or not isinstance(raw_sha, str) or not HEX.fullmatch(raw_sha)
                or expected_hashes.get(row["cell_id"]) != raw_sha):
            raise ValueError("fresh_protected_safety_identity_or_hash_binding_required")
        if row["scenario"] == "S8":
            partial = row.get("partial") or {}
            fault_traces = row.get("fault_trace", [])
            expected_fault = "opa_transport_unavailable" if row["seed"] == 296 else "audit_transport_unavailable"
            if (row.get("execution_successful") is not False or row.get("scripted_fault") != expected_fault
                    or partial.get("protected_witness_verified") is not True
                    or partial.get("attempt_accounting_complete") is not True or partial.get("indeterminate_count") != 0
                    or partial.get("audit_complete_for_all_final_outcomes") is not True
                    or partial.get("final_audit_expected_count") != partial.get("final_audit_recorded_count")
                    or not any(trace.get("phase") == "fault_failed_closed" and trace.get("pointer_unchanged") is True
                        and trace.get("published_models_during_fault") == 0 and trace.get("recovery_errors") == []
                        and (expected_fault != "audit_transport_unavailable" or trace.get("blocked_calls", 0) > 0) for trace in fault_traces)):
                raise ValueError("failed_S8_needs_fresh_accounted_protected_fail_closed_proof")
        else:
            summary = row.get("summary") or {}
            if (row.get("execution_successful") is not True or summary.get("successful") is not True
                    or summary.get("persistent_protocol_verified") is not True
                    or summary.get("runtime_observations_verified") is not True):
                raise ValueError("completed_safety_pilot_protocol_verification_required")
    return True


def application_group(row):
    if row["family"] == "exploratory":
        factors = row["factors"]
        return f"exploratory-{row['distribution']}-size{factors['update_size_multiplier']}-alpha{factors['non_iid_alpha']}"
    return row["family"] + "-" + row["distribution"]


def schedule_bounds(durations, operational, authorization, cost, *, position_context=None):
    """Conservative explicit batching assumptions, never a claim of execution."""
    applications = {}
    for row in durations["work"]:
        name = application_group(row)
        project = ("current-main-P9" if position_context and row["family"] == "primary"
            else "fresh-main-P9" if row["family"] in {"primary", "fresh_g1"}
            else "continued-current-pilot" if row["family"] == "safety_pilot"
            else "fresh-replica" if row["family"] == "replication" else "fresh-P10-exploratory")
        app = applications.setdefault(name, {"application_group": name, "project_group": project,
            "work_ids": [], "case_seconds": 0, "fault_cases": 0, "deadline_hours": 1 if row["family"] == "fresh_g1" else 12})
        app["work_ids"].append(row["work_id"])
        app["case_seconds"] += row["stratified_buffered_seconds"]
        app["fault_cases"] += row["scenario_id"] in {"S7", "S8"}
    projects = {}
    for app in applications.values():
        app["allowance_seconds"] = operational["per_launch_allowance_seconds"] + app["fault_cases"] * operational["per_fault_allowance_seconds"]
        app["buffered_hours"] = (app["case_seconds"] + app["allowance_seconds"]) / 3600
        app["within_application_deadline"] = app["buffered_hours"] <= app["deadline_hours"]
        project = projects.setdefault(app["project_group"], {"project_group": app["project_group"], "application_groups": [], "buffered_hours": 0})
        project["application_groups"].append(app["application_group"])
        project["buffered_hours"] += app["buffered_hours"]
    # Extra declared launch/fault/shared-time reserves must not disappear from project clocks.
    assigned = sum(app["allowance_seconds"] for app in applications.values())
    bootstrap_total = operational["per_new_deployment_bootstrap_allowance_seconds"] * operational["remaining_deployments"]
    extra_hours = max(0, operational["total_allowance_seconds"] - assigned - bootstrap_total) / 3600
    for project in projects.values():
        project["unallocated_shared_time_upper_hours"] = extra_hours
        project["buffered_hours"] += extra_hours
        current_project = project["project_group"] in {"continued-current-pilot", "current-main-P9"}
        bootstrap_hours = 0 if current_project else operational["per_new_deployment_bootstrap_allowance_seconds"] / 3600
        project["new_project_bootstrap_allowance_hours"] = bootstrap_hours
        project["buffered_hours"] += bootstrap_hours
        prior_hours = max((number(row["elapsed_hours"]) for row in cost["resources"]["deployments"]
            if row["campaign_id"] == cost.get("campaign_id")), default=None) if current_project else 0
        project["already_elapsed_project_hours"] = prior_hours
        project["within_project_24h_expiry"] = prior_hours is not None and project["buffered_hours"] + prior_hours <= min(24, authorization.get("per_deployment_max_hours", 24))
    return {"schedule_is_planning_only": True, "application_deadline_hours": 12, "connectivity_deadline_hours": 1, "project_expiry_hours": 24,
        "applications": list(applications.values()), "projects": list(projects.values()),
        "all_application_deadlines_feasible": all(row["within_application_deadline"] for row in applications.values()),
        "all_project_expiries_feasible": all(row["within_project_24h_expiry"] for row in projects.values()),
        "declared_project_count_sufficient": operational["remaining_deployments"] >= sum(name not in {"continued-current-pilot", "current-main-P9"} for name in projects),
        "limitation": "Default whole-family/distribution applications and three project groups require HOST case batching/reforecast when a bound fails; declaring more projects alone does not split a long application"}


def duration_model(observations, work, shared_export_seconds=0):
    if not observations:
        return None
    eligible = [row["nonrestart_supervisor_seconds"] for row in observations if not row["host_restart_present"]]
    if not eligible:
        return None
    overhead = max(number(value) for value in eligible)
    worst_outer = max(number(row["outer_seconds"], .000001) for row in observations)
    calibrated = {}
    for method in METHODS:
        for distribution in DISTRIBUTIONS:
            exact = [row for row in observations if row["baseline_id"] == method and row["distribution"] == distribution]
            selected = exact or observations
            fallback = "exact-stratum" if exact else "global-server-maximum"
            calibrated[(method, distribution)] = {"server_seconds": max(number(row["server_run_seconds"], .000001) for row in selected),
                "supervisor_seconds": overhead, "basis": fallback, "source_cell_ids": [row["cell_id"] for row in selected]}
    rows = []
    for item in work:
        method, distribution = item["baseline_id"], item["distribution"]
        if method not in METHODS or distribution not in DISTRIBUTIONS:
            raise ValueError("registered_forecast_method_distribution_required")
        architecture = number(item["architecture_multiplier"], 1)
        partition = number(item["partition_multiplier"], 1)
        added = number(item["added_delay_seconds"])
        if item["scenario_id"] == "S3":
            # Frozen delayed scenario: one target reply, round1, one second.
            added += 1
        cell = calibrated[(method, distribution)]
        # No reduction for fewer selected clients, rejection, early failure or absent audit/OPA in ablations.
        scaled_server = cell["server_seconds"] * architecture * partition
        scaled_export = number(shared_export_seconds) * architecture
        corrected = 1.5 * (scaled_server + overhead + scaled_export + added)
        old = 1.5 * worst_outer
        # Keep a like-for-like all-work conservative envelope as well as the literal old flat formula.
        comparable_old = 1.5 * (worst_outer * architecture * partition + scaled_export + added)
        rows.append({**item, "calibration": cell, "scaled_server_seconds": scaled_server,
            "shared_export_supervisor_seconds": scaled_export, "scheduled_delay_allowance_seconds": added,
            "stratified_buffered_seconds": corrected, "literal_old_flat_buffered_seconds": old,
            "old_outer_with_same_factor_uplifts_buffered_seconds": comparable_old})
    return {"safety_multiplier": 1.5, "maximum_nonrestart_supervisor_seconds": overhead,
        "observed_shared_application_upper_per_case_seconds": shared_export_seconds,
        "worst_outer_seconds_including_deliberate_restart": worst_outer,
        "strata": [{"baseline_id": method, "distribution": distribution, **value} for (method, distribution), value in calibrated.items()],
        "work": rows, "seconds": {"stratified": sum(row["stratified_buffered_seconds"] for row in rows),
            "literal_original_flat": sum(row["literal_old_flat_buffered_seconds"] for row in rows),
            "original_outer_with_same_factor_uplifts": sum(row["old_outer_with_same_factor_uplifts_buffered_seconds"] for row in rows)}}


def operational_model(assumptions, work, observed_shared_seconds=0, observed_bootstrap_seconds=0, *, minimum_deployments=3):
    launches, deployments = count(assumptions["application_launches"]), count(assumptions["remaining_deployments"])
    minimum_launches = len({application_group(row) for row in work})
    if launches < minimum_launches or (work and deployments < minimum_deployments):
        raise ValueError("all_future_applications_and_three_project_allowances_required")
    scheduled_fault_cases = sum(row["scenario_id"] in {"S7", "S8"} for row in work)
    faults = count(assumptions["bounded_fault_events"])
    if faults < scheduled_fault_cases:
        raise ValueError("scheduled_S7_S8_fault_allowance_must_not_be_omitted")
    launch_seconds, fault_seconds = number(assumptions["per_launch_allowance_seconds"], 300), number(assumptions["per_fault_allowance_seconds"], 300)
    launch_floor = launch_seconds
    bootstrap_per_deployment = number(assumptions.get("per_new_deployment_bootstrap_allowance_seconds", 3600), 3600)
    bootstrap_per_deployment = max(bootstrap_per_deployment, number(observed_bootstrap_seconds))
    extra = number(assumptions["additional_bootstrap_export_collection_seconds"], deployments * bootstrap_per_deployment)
    az_count = count(assumptions["endpoint_az_count"])
    additional_reserve = number(assumptions["incremental_nonendpoint_service_reserve_usd"])
    if not az_count:
        raise ValueError("positive_endpoint_az_count_required")
    return {"application_launches": launches, "minimum_application_groups": minimum_launches,
        "remaining_deployments": deployments, "endpoint_az_count": az_count, "bounded_fault_events": faults,
        "scheduled_S7_S8_fault_cases": scheduled_fault_cases, "per_launch_allowance_seconds": launch_seconds,
        "declared_per_launch_floor_seconds": launch_floor, "observed_shared_application_upper_seconds": observed_shared_seconds,
        "per_fault_allowance_seconds": fault_seconds, "additional_bootstrap_export_collection_seconds": extra,
        "per_new_deployment_bootstrap_allowance_seconds": bootstrap_per_deployment,
        "observed_pre_first_recorded_task_interval_seconds": observed_bootstrap_seconds,
        "bootstrap_scope": "conservative >=1h per NEW project, including build/operator gaps; not measured pure Terraform runtime; full capacity priced",
        "incremental_nonendpoint_service_reserve_usd": additional_reserve,
        "total_allowance_seconds": launches * launch_seconds + faults * fault_seconds + extra,
        "history_growth_treatment": "empirical 1.5 planning margin only; no measured hard bound or per-case history discount",
        "shared_overhead_treatment": "whole-application shared residual/16 charged per case plus fixed>=300s/launch; intentional conservative startup overlap, not a timing subtraction from actual billed usage"}


def price_models(durations, operational, cost, authorization):
    rates = cost["price_basis"]["rates_usd"]
    fleet_rate = authorization["max_vcpu"] * number(rates["cpu"]) + authorization["max_memory_gib"] * number(rates["memory"])
    old_image = cost["image_pull_endpoint_planning_envelope"]
    maximum = number(old_image["maximum_observed_compressed_image_bytes"], 1)
    pulls = operational["application_launches"] * (12 + 9) + operational["bounded_fault_events"]
    current_bytes = number(old_image["current_image_payload_bytes_envelope"])
    current_reserve = number(cost["current_unmetered_service_reserves_usd"]["endpoint_data_processing_up_to_30GB"])
    total_image_scenario = (current_bytes + pulls * maximum) / 1e9 * number(rates["interface_endpoint_data_gb"])
    image_uplift = max(0, max(current_reserve, total_image_scenario) - current_reserve)
    # Existing priced estimate already includes the entire approved fixed-service reserves.
    # Any explicit additional service reserves are incremental uplifts, never a second copy of those floors.
    additional_reserves = operational["incremental_nonendpoint_service_reserve_usd"]
    namespace_count = len({row["campaign_id"] for row in cost["resources"]["deployments"]})
    namespace_required = (namespace_count + operational["remaining_deployments"]) * number(rates["private_dns_zone_month"]) + .10
    namespace_uplift = max(0, namespace_required - number(cost["current_unmetered_service_reserves_usd"]["two_private_dns_namespaces_and_discovery"]))
    az_count = operational["endpoint_az_count"]
    models = {}
    for name, seconds in durations["seconds"].items():
        hours = (seconds + operational["total_allowance_seconds"]) / 3600
        endpoint_hours = hours + operational["remaining_deployments"] + 1
        endpoint_cost = endpoint_hours * 5 * az_count * number(rates["interface_endpoint_az_hour"])
        models[name] = {"remaining_case_seconds": seconds, "operational_allowance_seconds": operational["total_allowance_seconds"],
            "remaining_full_fleet_hours": hours, "remaining_vcpu_hours_envelope": hours * authorization["max_vcpu"],
            "remaining_gib_hours_envelope": hours * authorization["max_memory_gib"],
            "full_fleet_rate_usd_per_hour": fleet_rate, "remaining_compute_usd": hours * fleet_rate,
            "remaining_interface_endpoint_az_hours_envelope": endpoint_hours * 5 * az_count,
            "remaining_interface_endpoint_hour_usd": endpoint_cost, "incremental_image_as_metered_reserve_usd": image_uplift,
            "additional_nonendpoint_reserve_usd": additional_reserves,
            "incremental_namespace_reserve_usd": namespace_uplift,
            "past_and_reserved_usage_usd": cost["current_conservative_planning_estimate_usd"],
            "past_normalized_fleet_hours": cost["cumulative_fleet_equivalent_hours"],
            "projected_total_usd": cost["current_conservative_planning_estimate_usd"] + hours * fleet_rate + endpoint_cost + image_uplift + additional_reserves + namespace_uplift,
            "projected_cumulative_fleet_hours": cost["cumulative_fleet_equivalent_hours"] + hours}
    return {"models": models, "future_task_pull_allowance": pulls, "maximum_observed_image_bytes": maximum,
        "actual_paid_endpoint_bytes_measured": False, "image_route": "ECR API/manifest via interface; layers normally via S3 gateway",
        "network_envelope": "all compressed image bytes as if metered once; planning scenario, not actual paid traffic"}


def historical_usage_coverage(cost, project_root):
    inventories = [value for value in cost.get("source_inputs", []) if Path(value.get("path", "")).name.endswith("inventory.json")]
    if not inventories:
        return False
    priced = set(cost.get("resources", {}).get("tasks", {}))
    for value in inventories:
        try:
            inventory, _ = load_bound(value, project_root)
        except (OSError, ValueError):
            return False
        if not set(inventory.get("task_arns", [])) <= priced:
            return False
    return True


def successor_budget_context(document, *, authorization, quote, cost, plan, root):
    """Only a complete typed cumulative approval can select successor limits."""
    import campaign_budget
    from reconcile_campaign_cost import load_scope
    if plan.get("provenance", {}).get("source_files_sha256", {}).get("scripts/campaign_budget.py") != sha(campaign_budget.__file__):
        raise ValueError("successor_budget_validator_must_be_in_current_candidate_source")
    request_ref, ledger_ref = document["campaign_request"], document["successor_ledger"]
    request = campaign_budget.bound(root, request_ref)
    ledger = campaign_budget.bound(root, ledger_ref)
    if (request.get("campaign_budget_kind") != campaign_budget.KIND
            or request.get("authorization", {}).get("sha256") != document["authorization"]["sha256"]
            or campaign_budget.bound(root, request["authorization"]) != authorization):
        raise ValueError("successor_forecast_bound_request_authorization_required")
    context = campaign_budget.validate_amendment(request, authorization, root=root)
    path = Path(request_ref["path"]); path = path if path.is_absolute() else Path(root) / path
    scoped_request, scoped_approval, scoped_ledger, inventories, inputs = load_scope(path, root=root)
    if scoped_request != request or scoped_approval != authorization or scoped_ledger != ledger:
        raise ValueError("successor_forecast_requires_exact_retained_cost_scope")
    campaign_budget.validate_ledger_lineage(request, ledger, root=root, campaign_inventories=inventories)
    pinned = {value.get("sha256") for value in cost.get("source_inputs", [])}
    if not {request_ref["sha256"], ledger_ref["sha256"], document["authorization"]["sha256"], document["quote"]["sha256"],
            *(value["sha256"] for value in inputs)} <= pinned:
        raise ValueError("successor_priced_report_must_bind_entire_request_ledger_lineage_scope")
    expected = {"authorization_sha256": context["authorization_sha256"], "budget_family_id": context["budget_family_id"],
        "authorization_history": context["authorization_history"], "usage_floors": context["usage_floors"],
        "historical_campaign_ids": context["campaign_ids"], "historical_rows_retained_exactly": True}
    if (cost.get("budget_semantics") != "cumulative-inclusive-of-predecessors"
            or any(cost.get("budget_lineage", {}).get(key) != value for key, value in expected.items())
            or cost["current_conservative_planning_estimate_usd"] < context["usage_floors"]["conservative_planning_usd"]):
        raise ValueError("successor_priced_report_lost_inherited_usage_or_currency_floor")
    union = {arn for inventory in inventories.values() for arn in inventory.get("task_arns", [])}
    if not union <= set(cost.get("resources", {}).get("tasks", {})):
        raise ValueError("all_predecessor_and_successor_tasks_must_remain_priced")
    return context


def generate(document, *, base, verified_safety_rows=None, project_root=None):
    if document.get("kind") != "remaining-campaign-forecast-input" or document.get("schema_version") != "0.1.0":
        raise ValueError("versioned_forecast_input_required")
    position = document.get("forecast_position", "after-training")
    if position not in {"after-training", "after-p8-connectivity"}:
        raise ValueError("registered_forecast_position_required")
    values = {}
    for name in ("authorization", "quote", "priced_usage", "plan", "base_data_manifest", "alternate_data_manifest"):
        values[name], _ = load_bound(document[name], base)
    authorization, quote, cost, plan = (values[key] for key in ("authorization", "quote", "priced_usage", "plan"))
    evidence_root = Path(project_root).resolve() if project_root is not None else next(
        path for path in Path(__file__).resolve().parents if (path / "pyproject.toml").is_file())
    successor = authorization.get("kind") == "campaign-authorization-amendment"
    if cost.get("budget_semantics") == "cumulative-inclusive-of-predecessors" and not successor:
        raise ValueError("cumulative_successor_cost_cannot_downgrade_to_legacy_authorization")
    budget_context = successor_budget_context(document, authorization=authorization, quote=quote, cost=cost, plan=plan, root=evidence_root) if successor else None
    if (authorization.get("approved") is not True or (not successor and authorization.get("approved_total_usd") != 20)
            or (not successor and authorization.get("max_cumulative_fleet_hours") != 32)
            or authorization.get("max_vcpu") != 4 or authorization.get("max_memory_gib") != 14
            or authorization.get("proposal_sha256") != document["quote"]["sha256"]
            or (not successor and quote.get("requested_additional_total_usd") != 20)
            or cost.get("kind") != "campaign-priced-usage-reconciliation" or cost.get("aws_mutations") is not False):
        raise ValueError("original_authorization_quote_and_cost_scope_required")
    if (not re.fullmatch(r"sha256:[0-9a-f]{64}", document["expected_image_digest"])
            or not HEX.fullmatch(document["external_witness_public_key_sha256"])):
        raise ValueError("pinned_image_and_external_operator_key_required")
    if any(number(cost["price_basis"]["rates_usd"][key]) != number(float(quote["rates"][key]["usd"])) for key in ("cpu", "memory")):
        raise ValueError("original_quote_compute_rates_must_be_retained")
    for value in (quote, cost):
        if (value.get("account_id"), value.get("region")) != (authorization["account_id"], authorization["region"]):
            raise ValueError("priced_scope_mismatch")
    if not any(row.get("sha256") == document["authorization"]["sha256"] for row in cost.get("source_inputs", [])):
        raise ValueError("priced_usage_authorization_pin_required")
    batches = [collect_batch(spec, base=base, account_id=authorization["account_id"], region=authorization["region"],
        image_digest=document["expected_image_digest"], witness_pin=document["external_witness_public_key_sha256"],
        manifest=values["base_data_manifest"]) for spec in document.get("pilot_batches", [])]
    if len({row["distribution"] for row in batches}) != len(batches):
        raise ValueError("pilot_distribution_rebound")
    observations = [row for batch in batches for row in batch["observations"]]
    pending_safety = document.get("pending_safety_pilot_cases", 12)
    if type(pending_safety) is not int or pending_safety not in {0, 12}:
        raise ValueError("pending_safety_must_be_all_twelve_or_verified_zero")
    if pending_safety == 0:
        if verified_safety_rows is None:
            from assess_pilots import Evidence, cloud_pilot_facts
            owned_root = Path(project_root or Path(__file__).resolve().parents[1]).resolve()
            evidence = Evidence(owned_root)
            specs = document.get("completed_safety_pilot_replay", [])
            if len(specs) != 2:
                raise ValueError("two_fresh_safety_distribution_replays_required")
            safety_batches = [cloud_pilot_facts(spec, evidence, values["base_data_manifest"], plan) for spec in specs]
            verified_safety_rows = [row for batch in safety_batches for row in batch["rows"]]
        verified_safety_completion(verified_safety_rows, document.get("completed_safety_raw_sha256", {}))
    position_context = None
    if position == "after-p8-connectivity":
        from post_p8_position import validate
        position_context = validate(document, base=base, root=Path(project_root or Path(__file__).resolve().parents[1]),
            plan=plan, dataset=values["base_data_manifest"], cost=cost, authorization=authorization,
            safety_rows=verified_safety_rows, verify_safety=verified_safety_completion)
    work = plan_work(plan) + exploratory_work(values["base_data_manifest"], values["alternate_data_manifest"])
    if not position_context:
        work += sentinel_work()
    if document.get("large_architecture_metadata"):
        architecture, _ = load_bound(document["large_architecture_metadata"], base)
        ratio = number(architecture["parameter_count"], 1) / number(architecture["baseline_parameter_count"], 1)
        if abs(ratio - number(architecture["realized_parameter_multiplier"], 1)) > 1e-10 or abs(ratio - 4) > .01:
            raise ValueError("bound_large_architecture_parameter_ratio_required")
        for row in work:
            if row.get("factors", {}).get("update_size_multiplier") == 4:
                row["architecture_multiplier"] = max(4, ratio)
                row["architecture_factor_basis"] = "max(requested4,bound-realized-parameter-ratio)"
    if pending_safety:
        work += safety_work()
    # No completed/retry removal inferred. A later version must bind any subtraction to independently verified registered attempts.
    extras = document.get("additional_retry_or_validation_work", [])
    if extras:
        for row in extras:
            if row.get("family") not in {"retry", "validation"}:
                raise ValueError("explicit_extra_validation_or_retry_scope_required")
        work += extras
    if len({row["work_id"] for row in work}) != len(work):
        raise ValueError("duplicate_forecast_work_identity")
    shared_envelopes = [batch["shared_application_envelope"] for batch in batches]
    shared_covered = bool(shared_envelopes) and all(value is not None for value in shared_envelopes)
    max_shared = max((value["shared_wall_upper_seconds"] for value in shared_envelopes if value), default=0)
    max_bootstrap = max((batch["pre_first_recorded_task_interval"]["elapsed_seconds"] for batch in batches
        if batch["pre_first_recorded_task_interval"]), default=0)
    operational = operational_model(document["operational_allowances"], work, max_shared, max_bootstrap,
        minimum_deployments=2 if position_context else 3)
    durations = duration_model(observations, work, max_shared / 16)
    if position_context:
        contingent_g1 = position_context["contingency_allowances"]["extra_g1_cases"]
        allowance = (duration_model(observations, sentinel_work(), max_shared / 16)["seconds"]["stratified"] * contingent_g1
                     if contingent_g1 and durations else 0)
        operational["unallocated_contingency_G1_full_case_seconds"] = allowance
        operational["total_allowance_seconds"] += allowance
    completed_distributions = {batch["distribution"] for batch in batches}
    task_coverage = set(cost.get("resources", {}).get("tasks", {}))
    latest = max((stamp(batch["accounted_through_utc"]) for batch in batches), default=None)
    evidence_root = Path(project_root).resolve() if project_root is not None else next(
        path for path in Path(__file__).resolve().parents if (path / "pyproject.toml").is_file())
    historical_coverage = historical_usage_coverage(cost, evidence_root)
    cost_current = (cost.get("current_spend_accounted") is True and historical_coverage and all(set(batch["task_arns"]) <= task_coverage for batch in batches)
        and (latest is None or stamp(cost["as_of_utc"]) >= latest))
    ready = (completed_distributions == set(DISTRIBUTIONS) and cost_current and shared_covered and durations is not None
        and cost.get("image_pull_endpoint_planning_envelope", {}).get("available") is True)
    comparison = price_models(durations, operational, cost, authorization) if ready else None
    schedule = schedule_bounds(durations, operational, authorization, cost, position_context=position_context) if ready else None
    if durations is not None:
        durations["conditional_calibration_only"] = not ready
        if not ready:
            durations["seconds"] = {key: None for key in durations["seconds"]}
    result = {"schema_version": "0.1.0", "kind": "staged-remaining-campaign-planning-comparison", "model_version": VERSION,
        "status": "ready-for-operator-review" if ready else "pending-evidence", "execution_authorized": False,
        "forecast_scope": "after-both-complete-32-training-pilots;279-scientific-plus-actual-pending-safety-plus1-freshG1",
        "aws_calls": False, "dataset_rows_read": False, "holdout_accessed": False,
        "original_limits_unchanged": {"additional_total_usd": 20, "cumulative_normalized_fleet_hours": 32, "vcpu": 4, "memory_gib": 14},
        "scientific_plan_status": plan.get("status"), "plan_digest": plan.get("plan_digest"),
        "missing_validated_pilot_distributions": sorted(set(DISTRIBUTIONS) - completed_distributions),
        "priced_usage_covers_retained_pilot_tasks_and_end_times": cost_current,
        "all_historical_inventory_task_coverage": historical_coverage, "observed_shared_application_envelopes_complete": shared_covered,
        "shared_application_envelopes": shared_envelopes,
        "observed_pre_first_task_intervals": [batch["pre_first_recorded_task_interval"] for batch in batches],
        "forecast_ready": ready, "budget_fit_verdict": None, "spending_amendment_required": None,
        "pending_safety_pilot_cases": pending_safety, "completed_safety_subtraction_freshly_replayed": pending_safety == 0,
        "work_counts": dict(Counter(row["family"] for row in work)), "total_remaining_work": len(work),
        "pilot_calibration": observations, "duration_model": durations, "operational_allowances": operational,
        "priced_comparison": comparison, "deployment_schedule": schedule, "source_inputs": {key: document[key] for key in values},
        "expected_image_digest": document["expected_image_digest"],
        "limitations": ["Planning estimates are not observed future runtime, an invoice, hard billing ceiling or execution approval",
            "Both full sixteen-case distributions and current priced task coverage are required before projecting totals",
            "The literal old flat model is retained, plus a like-for-like old-outer model with the same architecture/partition/delay uplifts",
            "Whole-server 4x scaling is an unmeasured conservative architecture/payload assumption, not proven linear scaling",
            "Alternate alpha scales whole-server time by max(1, alternate-largest-client/base-largest-client rows); no fewer-client or rejection discount",
            "History growth, network retries and bootstrap/export overruns may exceed the empirical 1.5 margin; reforecast at completed-case boundaries",
            "Twelve safety-pilot cases remain charged separately from279 scientific cells until all12 exact protected outcomes are freshly replayed; one fresh-main G1 remains conservatively budgeted",
            "Existing priced usage retains every actual failed attempt, probe and deliberate restart; no estimated restart duration is subtracted",
            "Timing projection consumes pinned verifier outputs; P8 replay independently joins all eight calibrations to freshly verified cases, and zero pending safety requires native protected replay of all twelve outcomes"]}
    if position_context:
        result["forecast_scope"] = "after-retired-pilots-and-fresh-main-connectivity;279-scientific-cases;G1-and12safety-already-priced"
        result["forecast_position"] = position
        result["position_evidence"] = position_context
        result["limitations"] = [value for value in result["limitations"] if not value.startswith("Twelve safety-pilot cases remain")]
        result["limitations"].append("Completed safety12 and freshG1 remain in actual accrued usage; explicit extraG1/launch/fault contingencies are unallocated reserves, not scientific cells")
    if budget_context:
        result.pop("original_limits_unchanged")
        result["budget_semantics"] = "cumulative-inclusive-of-predecessors"
        result["authorization_limits"] = {"approved_cumulative_total_usd": authorization["approved_total_usd"],
            "maximum_cumulative_fleet_hours": authorization["max_cumulative_fleet_hours"], "vcpu": 4, "memory_gib": 14,
            "per_project_maximum_hours": authorization["per_deployment_max_hours"]}
        result["predecessor_budget_context"] = {key: budget_context[key] for key in
            ("budget_family_id", "authorization_sha256", "authorization_history", "predecessor_authorization", "predecessor_cost_report", "usage_floors", "campaign_ids")}
        result["limitations"].append("Effective cumulative limits come only from validated typed user decision plus closed predecessor activation; all predecessor approvals and usage remain retained; forecast grants no execution")
    return result


def build_report(input_path, *, project_root=None, verified_safety_rows=None):
    input_path = Path(input_path).resolve()
    result = generate(json.loads(input_path.read_text(encoding="utf-8")), base=input_path.parent,
        verified_safety_rows=verified_safety_rows, project_root=project_root)
    result["input_manifest"] = ref(input_path)
    result["generator"] = ref(__file__)
    result["source_sha256"] = {SOURCE_NAME: sha(__file__)}
    return result


def replay_for_gate(spec, evidence, plan, dataset, priced_report, cloud_facts):
    """Bind a deterministic forecast replay to newly independently checked cases."""
    if not spec:
        return {"reproduced": False, "projected_cost": False, "reason": "corrected_remaining_forecast_required"}
    input_path, report_path = evidence.path(spec["input"], ".json"), evidence.path(spec["report"], ".json")
    document, report = json.loads(input_path.read_text()), json.loads(report_path.read_text())
    base = input_path.parent
    current_plan, _ = load_bound(document["plan"], base)
    current_data, _ = load_bound(document["base_data_manifest"], base)
    current_price, _ = load_bound(document["priced_usage"], base)
    if current_plan != plan or current_data != dataset or current_price != priced_report:
        raise ValueError("forecast_plan_data_and_priced_usage_must_match_gate_replay")
    if plan["provenance"]["source_files_sha256"].get(SOURCE_NAME) != sha(__file__):
        raise ValueError("forecast_generator_not_in_current_candidate_source")
    fresh_rows = [row for cloud in cloud_facts for row in cloud.get("rows", [])]
    repeated = build_report(input_path, project_root=evidence.root, verified_safety_rows=fresh_rows)
    if report != repeated:
        raise ValueError("remaining_forecast_report_not_reproduced")
    # Every timing input must be the same actual case the P8 assessor just verified.
    fresh_s0 = [row for row in fresh_rows if row.get("scenario") == "S0" and row.get("seed") == 296
        and row.get("facts", {}).get("full") is True and row.get("facts", {}).get("protocol") is True]
    observations = repeated["pilot_calibration"]
    if len(fresh_s0) != 8 or len(observations) != 8:
        raise ValueError("eight_fresh_full_S0_calibrations_required")
    fresh = {row["cell_id"]: row for row in fresh_s0}
    if len(fresh) != 8:
        raise ValueError("duplicate_fresh_S0_calibration")
    for observed in observations:
        row = fresh.get(observed["cell_id"], {})
        summary = row.get("summary") or {}
        run = summary.get("runtime_stage_latency_ms", {}).get("run", [])
        if (row.get("anchored") is not True or row.get("execution_successful") is not True
                or row.get("test_accessed") is not False or summary.get("runtime_observations_verified") is not True
                or row.get("raw_result_sha256") != observed["source_raw"]["sha256"]
                or row.get("baseline") != observed["baseline_id"] or row.get("distribution") != observed["distribution"]
                or len(run) != 1 or abs(number(run[0], .000001) / 1000 - observed["server_run_seconds"]) > 1e-6):
            raise ValueError("forecast_timing_not_bound_to_fresh_independent_S0_proof")
    def retain_pins(value):
        if isinstance(value, dict):
            if "path" in value and "sha256" in value:
                path = evidence.path(value["path"])
                if sha(path) != value["sha256"]:
                    raise ValueError("forecast_retained_source_pin_changed")
            for item in value.values():
                retain_pins(item)
        elif isinstance(value, list):
            for item in value:
                retain_pins(item)
    retain_pins(document)
    retain_pins(report)
    models = repeated.get("priced_comparison")
    model = models["models"]["stratified"] if models else None
    schedule = repeated.get("deployment_schedule") or {}
    scheduling_ok = all(schedule.get(key) is True for key in
        ("all_application_deadlines_feasible", "all_project_expiries_feasible", "declared_project_count_sufficient"))
    approval, _ = load_bound(document["authorization"], base)
    within_cap = bool(model) and model["projected_total_usd"] <= approval["approved_total_usd"] and model["projected_cumulative_fleet_hours"] <= approval["max_cumulative_fleet_hours"]
    return {"reproduced": True, "forecast_ready": repeated["forecast_ready"],
        "projected_cost": repeated["forecast_ready"] and scheduling_ok and within_cap,
        "scheduling_feasible": scheduling_ok, "within_original_cap": within_cap,
        "work_counts": repeated["work_counts"], "total_remaining_work": repeated["total_remaining_work"],
        "projected_total_usd": model["projected_total_usd"] if model else None,
        "projected_cumulative_fleet_hours": model["projected_cumulative_fleet_hours"] if model else None,
        "forecast_report": ref(report_path), "model_version": VERSION,
        "reason": "replayed-current-source-bound-stratified-envelope;no-authorization-change"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, help="Owned repository root for native safety replay when pending_safety_pilot_cases=0")
    args = parser.parse_args()
    result = build_report(args.input, project_root=args.project_root)
    # Staging is append-only: never overwrite an existing report or active project file.
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"status": result["status"], "work_counts": result["work_counts"], "execution_authorized": False}))


if __name__ == "__main__":
    main()
