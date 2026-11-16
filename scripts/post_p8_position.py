"""Offline evidence checks for the forecast after retired pilots and fresh G1.

Despite the historical position name, P8 acceptance can follow this cost check.
This module neither accepts a plan nor authorizes execution or spending.
"""
from datetime import datetime
import hashlib
import json
from pathlib import Path

CHECKS = {"no_active_owned_tasks", "no_owned_ecs_services", "no_owned_interface_endpoints",
    "no_owned_runtime_vpc", "foundation_removed", "all_recorded_evidence_retained", "all_recorded_stacks_destroyed"}
POSITION = "after-p8-connectivity"


def _stamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None: raise ValueError("aware_position_clock_required")
    return result


def _pin(value, base, *, suffix=".json"):
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError("exact_position_input_pin_required")
    path = Path(value["path"])
    if not path.is_absolute(): path = Path(base) / path
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("linked_position_input_forbidden")
    if not path.is_file() or path.suffix != suffix or path.stat().st_size > 64 * 1024**2:
        raise ValueError("regular_bounded_position_input_required")
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != value["sha256"]:
        raise ValueError("position_input_hash_changed")
    return (json.loads(body) if suffix == ".json" else body), path.resolve()


def _cost_scope(path, root):
    # The amendment/snapshot-aware consumer is authoritative for typed approval,
    # exact old-ledger carry and immutable snapshot scope. No AWS is imported.
    from reconcile_campaign_cost import load_scope
    return load_scope(path, root=root)


def _native_g1(spec, root, dataset, plan):
    from assess_pilots import Evidence, cloud_pilot_facts, isolation_facts, retained_cases
    evidence = Evidence(root)
    translated = {"inventory": spec["inventory"]["path"], "campaign": spec["campaign"]["path"],
        "witness_public_key": spec["witness_public_key"]["path"],
        "expected_public_key_sha256": spec["expected_public_key_sha256"]}
    facts = cloud_pilot_facts(translated, evidence, dataset, plan)
    isolation = isolation_facts(translated["inventory"], evidence, plan)
    inventory_path = evidence.path(translated["inventory"], ".json")
    _, cases = retained_cases(facts["inventory"], inventory_path)
    return facts, isolation, cases


def validate(document, *, base, root, plan, dataset, cost, authorization, safety_rows, verify_safety):
    """Independently replay prerequisites; return deterministic scope metadata."""
    if plan.get("status") not in {"candidate_locked", "accepted_frozen"}:
        raise ValueError("current_candidate_or_accepted_plan_required_without_P8_cycle")
    if plan.get("provenance", {}).get("source_files_sha256", {}).get("scripts/post_p8_position.py") != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError("post_connectivity_checker_must_be_in_candidate_source")
    if document.get("pending_safety_pilot_cases") != 0:
        raise ValueError("post_connectivity_requires_completed_safety_twelve")
    verify_safety(safety_rows, document.get("completed_safety_raw_sha256", {}))
    proof = document.get("post_p8_connectivity")
    if not isinstance(proof, dict) or set(proof) != {"cost_request", "g1", "retired_pilot_campaigns", "contingency_allowances"}:
        raise ValueError("strict_post_connectivity_proof_required")
    request, request_path = _pin(proof["cost_request"], base)
    marker = request.get("cost_scope_snapshot", {})
    if (request.get("kind") != "frozen-campaign-cost-request" or marker.get("schema_version") != "0.1.0"
            or marker.get("kind") != "campaign-cost-scope-snapshot" or marker.get("execution_disabled") is not True):
        raise ValueError("immutable_execution_disabled_cost_request_required")
    _, _ = _pin(marker["manifest"], root)
    scoped_request, scoped_authorization, ledger, inventories, scope_inputs = _cost_scope(request_path, root)
    if scoped_request != request or scoped_authorization != authorization:
        raise ValueError("post_connectivity_cost_request_authorization_scope_mismatch")
    account, region, current = request["account_id"], request["region"], request["campaign_id"]
    if ((cost.get("account_id"), cost.get("region"), cost.get("campaign_id")) != (account, region, current)
            or cost.get("current_spend_accounted") is not True or current not in inventories):
        raise ValueError("current_MAIN_cost_scope_required")
    cost_pins = {row.get("sha256") for row in cost.get("source_inputs", [])}
    if not {proof["cost_request"]["sha256"], *(row["sha256"] for row in scope_inputs)} <= cost_pins:
        raise ValueError("current_cost_must_pin_entire_immutable_scope")
    task_union = {arn for inv in inventories.values() for arn in inv.get("task_arns", [])}
    if not set(ledger.get("tasks", {})) <= task_union or not task_union <= set(cost.get("resources", {}).get("tasks", {})):
        raise ValueError("all_historical_and_current_tasks_must_remain_priced")
    pairs = proof["retired_pilot_campaigns"]
    if not isinstance(pairs, list) or not pairs:
        raise ValueError("retired_pilot_terminal_proofs_required")
    retired, latest_retirement = set(), None
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != {"inventory", "readback"}:
            raise ValueError("exact_retired_inventory_readback_pair_required")
        inventory, _ = _pin(pair["inventory"], base)
        readback, _ = _pin(pair["readback"], base)
        campaign = inventory.get("campaign_id")
        if (campaign in retired or campaign == current or inventories.get(campaign) != inventory
                or inventory.get("teardown_complete") is not True
                or readback.get("kind") != "actual-aws-campaign-teardown-validation"
                or readback.get("successful") is not True or readback.get("performed_read_only") is not True
                or readback.get("inventory_sha256") != pair["inventory"]["sha256"]
                or any(readback.get(key) != inventory.get(key) for key in ("account_id", "region", "project_id", "campaign_id"))
                or (inventory.get("account_id"), inventory.get("region")) != (account, region)
                or set(readback.get("checks", {})) != CHECKS or any(value is not True for value in readback["checks"].values())):
            raise ValueError("exact_retired_pilot_teardown_readback_required")
        retired.add(campaign)
        at = _stamp(readback["checked_at_utc"])
        latest_retirement = max(latest_retirement, at) if latest_retirement else at
    if retired != set(inventories) - {current}:
        raise ValueError("all_historical_projects_require_retired_proof")
    retained_safety_raw = {item.get("sha256") for name in retired
        for item in inventories[name].get("retained_artifact_versions", [])
        if item.get("key", "").endswith("/runtime_result.json") and item.get("version_id") not in {None, "", "null"}}
    if not {row["raw_result_sha256"] for row in safety_rows if row.get("scenario") in {f"S{n}" for n in range(4, 9)}} <= retained_safety_raw:
        raise ValueError("completed_safety_raw_must_belong_to_retired_priced_custody")
    current_inv = inventories[current]
    if current_inv.get("project_id") in {inventories[name].get("project_id") for name in retired}:
        raise ValueError("MAIN_project_must_be_fresh_after_pilot_teardown")
    if _stamp(current_inv["deployment_started_at"]) < latest_retirement:
        raise ValueError("fresh_MAIN_started_before_pilot_teardown_readback")
    deployments = cost.get("resources", {}).get("deployments", [])
    if not any(row.get("campaign_id") == current and row.get("finished_at") is None
               and type(row.get("elapsed_hours")) in (int, float) and row["elapsed_hours"] >= 0 for row in deployments):
        raise ValueError("actual_elapsed_CURRENT_MAIN_project_clock_required")
    if any(not row.get("finished_at") for row in deployments if row.get("campaign_id") in retired):
        raise ValueError("historical_project_cost_clock_must_be_closed")
    spec = proof["g1"]
    if not isinstance(spec, dict) or set(spec) != {"inventory", "campaign", "witness_public_key", "expected_public_key_sha256"}:
        raise ValueError("exact_fresh_G1_native_proof_spec_required")
    g1_inv, inventory_path = _pin(spec["inventory"], base)
    campaign, campaign_path = _pin(spec["campaign"], base)
    _, key_path = _pin(spec["witness_public_key"], base, suffix=".pem")
    if g1_inv != current_inv or g1_inv.get("campaign_id") != current:
        raise ValueError("G1_inventory_must_equal_current_cost_snapshot_inventory")
    native_spec = {**spec, "inventory": {**spec["inventory"], "path": str(inventory_path)},
        "campaign": {**spec["campaign"], "path": str(campaign_path)},
        "witness_public_key": {**spec["witness_public_key"], "path": str(key_path)}}
    facts, isolation, cases = _native_g1(native_spec, root, dataset, plan)
    image = plan.get("provenance", {}).get("image_digests", {}).get("runtime")
    if (facts.get("successful") is not True or facts.get("placement_successful") is not True
            or isolation.get("placement_successful") is not True or not isolation.get("placement")
            or any(value is not True for value in isolation["placement"].values())
            or facts.get("image_reference") != image or isolation.get("image_reference") != image
            or facts.get("exported_cases") != 1 or facts.get("all_case_outcomes_retained") is not True
            or len(facts.get("rows", [])) != 1 or len(cases) != 1 or len(campaign.get("cases", [])) != 1):
        raise ValueError("fresh_source_bound_protected_G1_and_isolation_required")
    row, (cell_id, _, raw, raw_sha) = facts["rows"][0], cases[0]
    runtime = campaign["cases"][0]["runtime"]
    summary = row.get("summary") or {}
    records = raw.get("client_training", [])
    metadata = runtime.get("model_metadata", {})
    if (row.get("cell_id") != cell_id or row.get("raw_result_sha256") != raw_sha
            or row.get("anchored") is not True or row.get("execution_successful") is not True
            or row.get("test_accessed") is not False or row.get("baseline") != "P1" or row.get("scenario") not in {"S0", "stable"}
            or summary.get("successful") is not True or summary.get("persistent_protocol_verified") is not True
            or summary.get("committed_evaluation_response_verified") is not True
            or summary.get("runtime_observations_verified") is not True
            or campaign["cases"][0].get("cell_id") != cell_id or raw.get("cell_id") != cell_id
            or campaign.get("campaign_id") != current_inv.get("application_campaign_id")
            or raw.get("cloud_campaign_id") != campaign.get("campaign_id")
            or raw.get("successful") is not True or raw.get("aws_used") is not True
            or raw.get("baseline_id") != "P1" or runtime.get("baseline_id") != "P1"
            or runtime.get("scenario_id") != "S0" or raw.get("scenario_id") not in {"S0", "stable"}
            or runtime.get("distribution") != "iid" or runtime.get("seed") != 296 or raw.get("seed") != 296
            or runtime.get("persistent_run_id") != raw.get("persistent_run_id")
            or not metadata.get("metadata_digest") or raw.get("model_metadata_digest") != metadata.get("metadata_digest")
            or not metadata.get("model_schema_hash") or raw.get("model_schema_hash") != metadata.get("model_schema_hash")
            or metadata.get("hidden_dims") != [64, 32] or row.get("facts", {}).get("partitions") is not True
            or runtime.get("validation_source_sha256") != dataset.get("private_artifacts_sha256", {}).get("validation.csv")
            or not runtime.get("validation_source_sha256")
            or runtime.get("rounds") != 1 or runtime.get("max_examples_per_client") != 64
            or runtime.get("validation_max_examples") != 128 or len(raw.get("rounds", [])) != 1
            or len(records) != 8 or {record.get("org_id") for record in records} != {f"org_{n:02d}" for n in range(1, 9)}
            or any(record.get("sample_count") != 64 or record.get("round_id") != "round-1"
                   or record.get("optimizer") != "adam" or record.get("epochs") != 1
                   or record.get("example_exposures") != 64 or record.get("batches") != 1
                   or record.get("seed") != 396 + int(record["org_id"][-2:]) - 1 for record in records)
            or raw.get("validation_metrics", {}).get("count") != 128
            or raw.get("test_holdout_evaluated") is not False
            or runtime.get("final_holdout") or raw.get("test_metrics")
            or _stamp(raw["case_started_at_utc"]) < _stamp(current_inv["deployment_started_at"])
            or _stamp(cost["as_of_utc"]) < _stamp(raw["case_finished_at_utc"])):
        raise ValueError("actual_one_round_64_128_validation_G1_required")
    allowances = proof["contingency_allowances"]
    if (not isinstance(allowances, dict) or set(allowances) != {"extra_application_launches", "extra_fault_events", "extra_g1_cases"}
            or any(type(value) is not int or not 0 <= value <= 100 for value in allowances.values())
            or allowances["extra_application_launches"] < allowances["extra_g1_cases"]):
        raise ValueError("explicit_bounded_unallocated_contingency_counts_required")
    operational = document["operational_allowances"]
    if (operational.get("application_launches") != 13 + allowances["extra_application_launches"]
            or operational.get("bounded_fault_events") != 30 + allowances["extra_fault_events"]
            or operational.get("remaining_deployments") != 2):
        raise ValueError("post_connectivity_exact_13_science_groups_30_faults_2_new_projects_required")
    return {"forecast_position": POSITION, "scientific_cases": 279, "actual_G1_already_priced": True,
        "completed_safety_cases_already_priced": 12, "current_project_campaign_id": current,
        "current_project_group": "current-main-P9", "retired_campaign_ids": sorted(retired),
        "G1_cell_id": cell_id, "G1_raw_sha256": raw_sha, "G1_run_id": raw["persistent_run_id"],
        "contingency_allowances": allowances, "cost_request": proof["cost_request"],
        "new_project_groups": ["fresh-P10-exploratory", "fresh-replica"],
        "P8_acceptance_required_before_this_cost_check": False, "execution_authorized": False}
