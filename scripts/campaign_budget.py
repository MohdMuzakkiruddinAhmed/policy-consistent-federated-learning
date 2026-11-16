"""Pure local amendment checks; this module issues no spending permission.

This module creates no approval, request, ledger file, resource or spending
permission. Callers may later persist the returned deep copy ONLY after a real
user decision and coherent activation of every consumer described in design.md.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re

SCOPE = "remaining-phases-cloud-campaign-including-replication"
KIND = "campaign-authorization-amendment"
STATUS = "pure-local-validation-no-spending-side-effects"
CHECKS = {"no_active_owned_tasks", "no_owned_ecs_services", "no_owned_interface_endpoints",
    "no_owned_runtime_vpc", "foundation_removed", "all_recorded_evidence_retained", "all_recorded_stacks_destroyed"}
SHA = re.compile(r"[0-9a-f]{64}")


class RetiredAuthorization(ValueError):
    """Historical approval remains valid evidence but cannot execute new work."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("finite_nonnegative_budget_quantity_required")
    return value


def stamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None: raise ValueError("timezone_aware_budget_clock_required")
    return result


def bound(root, ref):
    if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or not isinstance(ref["sha256"], str) or not SHA.fullmatch(ref["sha256"]):
        raise ValueError("exact_budget_evidence_reference_required")
    root, path = Path(root).resolve(), Path(ref["path"])
    if not path.is_absolute(): path = root / path
    if ".." in path.parts: raise ValueError("budget_evidence_traversal_forbidden")
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("linked_budget_evidence_forbidden")
    if not path.is_file() or not path.resolve().is_relative_to(root) or path.stat().st_size > 64 * 1024**2:
        raise ValueError("owned_bounded_budget_evidence_required")
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != ref["sha256"]: raise ValueError("budget_evidence_hash_changed")
    return json.loads(body)


def scope(document, account, region):
    if document.get("account_id") != account or document.get("region") != region:
        raise ValueError("budget_evidence_account_region_mismatch")


def canonical_reference(root, reference):
    # Runtime requests use absolute bindings; finalization uses repository-
    # relative bindings. Normalize the same owned file before persisting lineage.
    bound(root, reference)
    path = Path(reference["path"])
    if not path.is_absolute(): path = Path(root) / path
    return {"path": path.resolve().relative_to(Path(root).resolve()).as_posix(), "sha256": reference["sha256"]}


def capacities(document):
    if (document.get("max_vcpu") != 4 or type(document.get("max_vcpu")) not in (int, float)
            or document.get("max_memory_gib") != 14 or document.get("per_deployment_max_hours") != 24):
        raise ValueError("unchanged_4vcpu_14gib_24hour_limits_required")
    if number(document.get("approved_total_usd")) <= 0 or number(document.get("max_cumulative_fleet_hours")) <= 0:
        raise ValueError("positive_cumulative_limits_required")


def campaigns(ledger):
    tasks, deployments = ledger.get("tasks"), ledger.get("deployments")
    if not isinstance(tasks, dict) or not isinstance(deployments, dict) or not deployments:
        raise ValueError("complete_predecessor_task_and_deployment_maps_required")
    result = set()
    for row in [*tasks.values(), *deployments.values()]:
        name = row.get("campaign_id")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,63}", name):
            raise ValueError("every_budget_row_requires_original_campaign_id")
        result.add(name)
    return result


def monotone_snapshot(old, terminal):
    """Quote can precede authorized safety work; terminal history may only grow."""
    if not set(old["tasks"]) <= set(terminal["tasks"]) or not set(old["deployments"]) <= set(terminal["deployments"]):
        raise ValueError("quote_snapshot_usage_was_dropped")
    for arn, previous in old["tasks"].items():
        current = terminal["tasks"][arn]
        if any(current.get(key) != previous.get(key) for key in ("campaign_id", "cpu", "memory_mib")):
            raise ValueError("quote_task_identity_changed")
        if any(number(current[key]) < number(previous[key]) for key in ("vcpu_hours", "gib_hours")):
            raise ValueError("quote_task_usage_decreased")
        if previous.get("last_status") == "STOPPED" and digest(current) != digest(previous):
            raise ValueError("already_terminal_quote_task_changed")
    for key, previous in old["deployments"].items():
        current = terminal["deployments"][key]
        if any(current.get(name) != previous.get(name) for name in ("campaign_id", "project_id", "started_at")):
            raise ValueError("quote_deployment_identity_or_clock_changed")
        if previous.get("finished_at") and digest(current) != digest(previous):
            raise ValueError("already_terminal_quote_deployment_changed")


def cost_report(report, *, account, region, authorization_ref, quote_ref, ledger_ref, inventories=None):
    scope(report, account, region)
    if (report.get("kind") != "campaign-priced-usage-reconciliation" or report.get("measurement") != "inferred"
            or report.get("aws_mutations") is not False or report.get("current_spend_accounted") is not True):
        raise ValueError("accounted_inferred_predecessor_cost_report_required")
    # The source ledger may have progressed after quote time. Its retained
    # immutable snapshot has the same hash; original report bytes stay unchanged.
    pinned = {item.get("sha256") for item in report.get("source_inputs", [])}
    if not {authorization_ref["sha256"], quote_ref["sha256"], ledger_ref["sha256"]} <= pinned:
        raise ValueError("cost_report_original_auth_quote_ledger_not_bound")
    number(report["current_conservative_planning_estimate_usd"])
    if inventories:
        if not {item["sha256"] for item in inventories} <= pinned:
            raise ValueError("terminal_cost_report_inventories_not_bound")


def validate_amendment(request, approval=None, *, root, _seen=()):
    """Validate a real future B record plus independent terminal activation.

    Returns expected predecessor rows/floors. Does not persist or authorize work.
    The quote is frozen BEFORE terminal hashes exist; activation pins those later.
    """
    authorization_ref = canonical_reference(root, request["authorization"])
    actual = bound(root, authorization_ref)
    if approval is not None and actual != approval: raise ValueError("approval_does_not_equal_bound_bytes")
    approval = actual
    if authorization_ref["sha256"] in _seen or len(_seen) >= 8:
        raise ValueError("acyclic_bounded_amendment_chain_required")
    account, region = request["account_id"], request["region"]
    scope(approval, account, region)
    capacities(approval)
    if (approval.get("kind") != KIND or approval.get("schema_version") != "0.1.0"
            or approval.get("approved") is not True or approval.get("source") != "user-conversation"
            or approval.get("authorization_scope") != SCOPE
            or approval.get("budget_semantics") != "cumulative-inclusive-of-predecessors"):
        raise ValueError("explicit_approved_typed_cumulative_amendment_required")
    quote_ref = {"path": approval["proposal_path"], "sha256": approval["proposal_sha256"]}
    quote = bound(root, quote_ref); scope(quote, account, region)
    decision = bound(root, approval["approval_decision"]); scope(decision, account, region)
    if (decision.get("kind") != "user-approved-campaign-budget-amendment" or decision.get("approved") is not True
            or decision.get("source") != "user-conversation" or decision.get("proposal_sha256") != quote_ref["sha256"]
            or not isinstance(decision.get("user_statement"), str) or not decision["user_statement"].strip()
            or any(decision.get(name) != approval.get(name) for name in
                ("approved_total_usd", "max_cumulative_fleet_hours", "max_vcpu", "max_memory_gib", "per_deployment_max_hours", "authorization_scope", "budget_semantics"))):
        raise ValueError("unchanged_actual_user_decision_and_proposal_required")
    activation = bound(root, approval["activation"]); scope(activation, account, region)
    if (activation.get("kind") != "terminal-campaign-budget-activation" or activation.get("proposal_sha256") != quote_ref["sha256"]
            or activation.get("approval_decision_sha256") != approval["approval_decision"]["sha256"]):
        raise ValueError("separate_terminal_activation_binding_required")
    predecessor = canonical_reference(root, activation["predecessor_authorization"])
    previous = bound(root, predecessor); scope(previous, account, region)
    capacities(previous)
    if previous.get("kind") == KIND:
        parent = validate_amendment({"authorization": predecessor, "account_id": account, "region": region}, root=root,
            _seen=(*_seen, authorization_ref["sha256"]))
    else:
        if (previous.get("approved") is not True or previous.get("source") != "user-conversation"
                or previous.get("authorization_scope") != SCOPE or previous["approved_total_usd"] > 20
                or previous["max_cumulative_fleet_hours"] > 32):
            raise ValueError("legacy_predecessor_must_remain_within_20usd_32hour_limits")
        parent = None
    old_quote_ref = canonical_reference(root, activation["predecessor_quote"])
    old_quote = bound(root, old_quote_ref)
    scope(old_quote, account, region)
    if old_quote_ref["sha256"] != previous.get("proposal_sha256"):
        raise ValueError("original_predecessor_quote_changed")
    old_ledger_ref = canonical_reference(root, activation["terminal_ledger"])
    old_cost_ref = canonical_reference(root, activation["terminal_cost_report"])
    terminal, terminal_cost = bound(root, old_ledger_ref), bound(root, old_cost_ref)
    if terminal.get("authorization_sha256") != predecessor["sha256"]:
        raise ValueError("terminal_ledger_wrong_predecessor_authorization")
    if parent:
        validate_ledger_lineage({"authorization": predecessor, "account_id": account, "region": region}, terminal,
            root=root, _context=parent, campaign_inventories=_terminal_inventories(activation["terminal_campaigns"], root, account, region)[0])
    snapshot_ledger_ref, snapshot_cost_ref = quote["basis"]["ledger"], quote["basis"]["cost_report"]
    snapshot, quote_cost = bound(root, snapshot_ledger_ref), bound(root, snapshot_cost_ref)
    if snapshot.get("authorization_sha256") != predecessor["sha256"]:
        raise ValueError("quote_snapshot_wrong_authorization")
    cost_report(quote_cost, account=account, region=region, authorization_ref=predecessor,
        quote_ref=old_quote_ref, ledger_ref=snapshot_ledger_ref)
    if (quote.get("kind") != "campaign-budget-amendment-proposal" or quote.get("authorization_scope") != SCOPE
            or quote.get("budget_semantics") != "cumulative-inclusive-of-predecessors"
            or quote.get("predecessor_authorization_sha256") != predecessor["sha256"]
            or quote.get("predecessor_quote_sha256") != old_quote_ref["sha256"]
            or quote.get("requested_cumulative_total_usd") != approval["approved_total_usd"]
            or quote.get("maximum_cumulative_fleet_hours") != approval["max_cumulative_fleet_hours"]
            or "requested_additional_total_usd" in quote):
        raise ValueError("immutable_cumulative_proposal_not_bound")
    if (approval["approved_total_usd"] < previous["approved_total_usd"]
            or approval["max_cumulative_fleet_hours"] < previous["max_cumulative_fleet_hours"]
            or approval["approved_total_usd"] == previous["approved_total_usd"] and approval["max_cumulative_fleet_hours"] == previous["max_cumulative_fleet_hours"]
            or quote.get("requested_incremental_usd") != approval["approved_total_usd"] - previous["approved_total_usd"]):
        raise ValueError("no_reset_or_ambiguous_incremental_budget_allowed")
    if quote.get("catalog_sha256") != old_quote.get("catalog_sha256") or quote.get("rates") != old_quote.get("rates"):
        raise ValueError("minimal_amendment_cannot_reprice_historical_usage")
    monotone_snapshot(snapshot, terminal)
    old_campaigns = campaigns(terminal)
    inventories, inventory_refs = _terminal_inventories(activation["terminal_campaigns"], root, account, region)
    if set(inventories) != old_campaigns: raise ValueError("all_predecessor_campaigns_require_terminal_readback")
    recorded_tasks = {arn for inventory in inventories.values() for arn in inventory.get("task_arns", [])}
    if set(terminal["tasks"]) != recorded_tasks or set(terminal_cost.get("resources", {}).get("tasks", {})) != recorded_tasks:
        raise ValueError("terminal_task_union_or_priced_task_coverage_mismatch")
    latest, vcpu, gib, endpoints = None, 0, 0, 0
    for arn, row in terminal["tasks"].items():
        if row.get("last_status") != "STOPPED": raise ValueError("terminal_predecessor_task_not_stopped")
        vcpu += number(row["vcpu_hours"]); gib += number(row["gib_hours"])
        priced = terminal_cost["resources"]["tasks"][arn]
        if any(number(priced[name]) < number(row[name]) for name in ("vcpu_hours", "gib_hours")):
            raise ValueError("terminal_priced_usage_below_ledger")
    for row in terminal["deployments"].values():
        if not row.get("finished_at"): raise ValueError("terminal_predecessor_clock_still_open")
        start, finish = stamp(row["started_at"]), stamp(row["finished_at"])
        if finish < start: raise ValueError("terminal_clock_went_backwards")
        endpoints += (finish - start).total_seconds() / 3600
        latest = max(latest, finish) if latest else finish
    cost_report(terminal_cost, account=account, region=region, authorization_ref=predecessor,
        quote_ref=old_quote_ref, ledger_ref=old_ledger_ref, inventories=inventory_refs)
    if latest and stamp(terminal_cost["as_of_utc"]) < latest: raise ValueError("terminal_cost_report_precedes_closed_clocks")
    for inventory in inventories.values():
        history = inventory.get("task_observation_history", {})
        observations = [*inventory.get("observed_tasks", []), *(history.values() if isinstance(history, dict) else [])]
        for observation in observations:
            if (observation.get("task_arn") in terminal["tasks"] and observation.get("stopped_at")
                    and stamp(terminal_cost["as_of_utc"]) < stamp(observation["stopped_at"])):
                raise ValueError("terminal_cost_report_precedes_recorded_task_stop")
    owned_images = set()
    for inventory in inventories.values():
        repositories = set(inventory.get("foundation", {}).get("image_repositories", {}).values())
        for image in [*inventory.get("image_history", []), *([inventory["image"]] if inventory.get("image") else [])]:
            reference = image.get("reference")
            if (not isinstance(reference, str) or not re.fullmatch(rf"{account}\.dkr\.ecr\.{re.escape(region)}\.amazonaws\.com/{re.escape(inventory['project_id'])}/[a-z0-9._/-]+@sha256:[0-9a-f]{{64}}", reference)
                    or reference.split("@", 1)[0] not in repositories):
                raise ValueError("predecessor_image_outside_exact_owned_repository_history")
            owned_images.add(reference)
    for report in (quote_cost, terminal_cost):
        for image in report.get("aws_observations", {}).get("images", []):
            if (image.get("reference") not in owned_images or type(image.get("compressed_image_bytes")) is not int
                    or image["compressed_image_bytes"] <= 0 or stamp(image["pushed_at"]) > stamp(report["as_of_utc"])):
                raise ValueError("predecessor_image_observation_not_owned_and_immutable")
    floors = {"vcpu_hours": vcpu, "gib_hours": gib, "endpoint_deployment_hours": endpoints,
        "conservative_planning_usd": max(number(terminal_cost["current_conservative_planning_estimate_usd"]),
                                        number(quote_cost["current_conservative_planning_estimate_usd"]))}
    estimate = number(quote.get("estimated_bounded_total_usd"))
    if not floors["conservative_planning_usd"] <= estimate <= approval["approved_total_usd"]:
        raise ValueError("approved_bound_proposal_estimate_required")
    if (max(vcpu / 4, gib / 14, endpoints) >= approval["max_cumulative_fleet_hours"]
            or floors["conservative_planning_usd"] >= approval["approved_total_usd"]):
        raise ValueError("approved_successor_has_no_remaining_budget_after_terminal_usage")
    return {"status": STATUS, "authorization_sha256": authorization_ref["sha256"], "predecessor_authorization": predecessor,
        "predecessor_ledger": old_ledger_ref, "predecessor_cost_report": old_cost_ref,
        "budget_family_id": parent["budget_family_id"] if parent else predecessor["sha256"],
        "authorization_history": [*(parent["authorization_history"] if parent else [predecessor]), authorization_ref],
        "tasks": deepcopy(terminal["tasks"]), "deployments": deepcopy(terminal["deployments"]),
        "owned_image_references": sorted(owned_images),
        "terminal_inventory_refs": deepcopy(inventory_refs),
        "campaign_ids": sorted(old_campaigns), "project_ids": sorted({inv["project_id"] for inv in inventories.values()}), "usage_floors": floors,
        "approved_predecessor_cost_reports": {**(parent["approved_predecessor_cost_reports"] if parent else {}), old_cost_ref["sha256"]: {"reference": old_cost_ref, "authorization_sha256": predecessor["sha256"]}}}


def _terminal_inventories(pairs, root, account, region):
    if not isinstance(pairs, list) or not pairs: raise ValueError("terminal_inventory_readback_pairs_required")
    result, refs = {}, []
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != {"inventory", "readback"}: raise ValueError("exact_terminal_pair_required")
        inventory, readback = bound(root, pair["inventory"]), bound(root, pair["readback"])
        scope(inventory, account, region); scope(readback, account, region)
        campaign = inventory["campaign_id"]
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,63}", campaign)
                or not re.fullmatch(r"[a-z][a-z0-9-]{2,25}", inventory.get("project_id", ""))
                or campaign in result or inventory.get("teardown_complete") is not True
                or readback.get("kind") != "actual-aws-campaign-teardown-validation" or readback.get("successful") is not True
                or readback.get("performed_read_only") is not True or readback.get("inventory_sha256") != pair["inventory"]["sha256"]
                or any(readback.get(name) != inventory.get(name) for name in ("campaign_id", "project_id"))
                or set(readback.get("checks", {})) != CHECKS or not all(value is True for value in readback["checks"].values())):
            raise ValueError("actual_closed_predecessor_inventory_readback_required")
        prefix = f"arn:aws:ecs:{region}:{account}:task/{inventory['project_id']}-runtime/"
        if any(not arn.startswith(prefix) or not re.fullmatch(r"[a-f0-9]{32}", arn[len(prefix):]) for arn in inventory.get("task_arns", [])):
            raise ValueError("predecessor_task_inventory_outside_owned_cluster")
        result[campaign] = inventory; refs.append(pair["inventory"])
    return result, refs


def new_ledger(request, *, root):
    """Return an in-memory successor; never open/write a successor ledger file."""
    context = validate_amendment(request, root=root)
    return {"authorization_sha256": context["authorization_sha256"], "budget_family_id": context["budget_family_id"],
        "authorization_history": deepcopy(context["authorization_history"]),
        "carry_forward": {name: deepcopy(context[name]) for name in ("predecessor_authorization", "predecessor_ledger", "predecessor_cost_report", "campaign_ids", "usage_floors")},
        "tasks": deepcopy(context["tasks"]), "deployments": deepcopy(context["deployments"])}


def validate_ledger_lineage(request, ledger, *, root, campaign_inventories=None, _context=None):
    context = _context or validate_amendment(request, root=root)
    expected = {"authorization_sha256": context["authorization_sha256"], "budget_family_id": context["budget_family_id"],
        "authorization_history": context["authorization_history"],
        "carry_forward": {name: context[name] for name in ("predecessor_authorization", "predecessor_ledger", "predecessor_cost_report", "campaign_ids", "usage_floors")}}
    if any(digest(ledger.get(name)) != digest(value) for name, value in expected.items()):
        raise ValueError("successor_ledger_exact_carry_forward_receipt_required")
    for collection in ("tasks", "deployments"):
        current = ledger.get(collection)
        if not isinstance(current, dict): raise ValueError("successor_usage_maps_required")
        if any(digest(current.get(key)) != digest(value) for key, value in context[collection].items()):
            raise ValueError("successor_dropped_or_changed_exact_predecessor_rows")
        for key in set(current) - set(context[collection]):
            row = current[key]; campaign = row.get("campaign_id")
            inventory = (campaign_inventories or {}).get(campaign)
            if (campaign in context["campaign_ids"] or not inventory or inventory.get("campaign_id") != campaign
                    or inventory.get("project_id") in context["project_ids"]):
                raise ValueError("future_usage_requires_fresh_owned_successor_campaign_inventory")
            scope(inventory, request["account_id"], request["region"])
            if collection == "tasks":
                prefix = f"arn:aws:ecs:{request['region']}:{request['account_id']}:task/{inventory['project_id']}-runtime/"
                if key not in inventory.get("task_arns", []) or not key.startswith(prefix) or not re.fullmatch(r"[a-f0-9]{32}", key[len(prefix):]):
                    raise ValueError("future_task_outside_owned_campaign_cluster")
                number(row["vcpu_hours"]); number(row["gib_hours"])
            elif row.get("project_id") != inventory["project_id"]:
                raise ValueError("future_deployment_project_scope_mismatch")
    return context


def accepts_predecessor_cost_report(request, reference, *, root):
    context = validate_amendment(request, root=root)
    item = context["approved_predecessor_cost_reports"].get(reference.get("sha256"))
    if item is None: raise ValueError("cost_observation_not_exact_approved_terminal_predecessor")
    report = bound(root, reference)
    if not any(row.get("sha256") == item["authorization_sha256"] for row in report.get("source_inputs", [])):
        raise ValueError("predecessor_cost_observation_original_auth_missing")
    # Reusing image observations still requires existing merge_image_observations
    # exact historical owned-image identity/size/date checks; this is no bypass.
    return {"accepted": True, "basis": "exact-hash-bound-terminal-predecessor-lineage",
        "authorization_sha256": item["authorization_sha256"], "report_sha256": reference["sha256"]}


def campaign_inventories(request, ledger, *, root, current_inventory=None):
    """Load the full carried/new union; never adopt a foreign campaign by name."""
    names = campaigns(ledger) | {request.get("campaign_id")} - {None}
    result = {}
    for name in names:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,63}", name):
            raise ValueError("owned_budget_campaign_name_required")
        if current_inventory is not None and name == request.get("campaign_id"):
            inventory = current_inventory
        else:
            path = Path(root) / "results/aws" / name / "inventory.json"
            if path.is_symlink() or not path.resolve().is_relative_to(Path(root).resolve()):
                raise ValueError("owned_budget_campaign_inventory_required")
            inventory = json.loads(path.read_bytes())
        scope(inventory, request["account_id"], request["region"])
        if inventory.get("campaign_id") != name: raise ValueError("budget_campaign_inventory_identity_changed")
        result[name] = inventory
    return result


def retirement_registry(root):
    path = Path(root) / "results/aws/budget-authorization-retirements.json"
    if not path.exists():
        if (Path(root) / "results/aws/budget-lineage-required.json").exists():
            raise ValueError("required_budget_retirement_registry_missing_restore_exact_history")
        return {"schema_version": "0.1.0", "kind": "campaign-budget-authorization-retirements", "successors": {}}
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("linked_budget_retirement_registry_forbidden")
        if part == Path(root): break
    value = json.loads(path.read_bytes())
    if (set(value) != {"schema_version", "kind", "successors"} or value.get("schema_version") != "0.1.0"
            or value.get("kind") != "campaign-budget-authorization-retirements" or not isinstance(value.get("successors"), dict)
            or len(value["successors"]) > 8):
        raise ValueError("strict_budget_retirement_registry_required")
    return value


def assert_authorization_not_retired(request, *, root):
    registry = retirement_registry(root)
    for previous_hash, reference in registry["successors"].items():
        if not isinstance(previous_hash, str) or not SHA.fullmatch(previous_hash):
            raise ValueError("retirement_original_authorization_hash_required")
        context = validate_amendment({"authorization": reference, "account_id": request["account_id"],
            "region": request["region"]}, root=root)
        if context["predecessor_authorization"]["sha256"] != previous_hash:
            raise ValueError("retirement_registry_successor_chain_mismatch")
    if request.get("authorization", {}).get("sha256") in registry["successors"]:
        raise RetiredAuthorization("predecessor_authorization_is_retired_for_execution")
    return registry


def proposed_retirement_registry(request, context, *, root):
    registry = retirement_registry(root)
    previous = context["predecessor_authorization"]["sha256"]
    successor = canonical_reference(root, request["authorization"])
    existing = registry["successors"].get(previous)
    if existing is not None and digest(existing) != digest(successor):
        raise ValueError("budget_authorization_cannot_fork_to_different_successor")
    # Existing history is validated, but the predecessor may already be retired
    # to this same successor after a crash between registry and ledger writes.
    assert_authorization_not_retired({"authorization": request["authorization"], "account_id": request["account_id"],
        "region": request["region"]}, root=root)
    registry["successors"][previous] = successor
    return registry


def require_successor_registration(request, *, root):
    context = validate_amendment(request, root=root)
    registry = retirement_registry(root)
    if digest(registry["successors"].get(context["predecessor_authorization"]["sha256"])) != digest(canonical_reference(root, request["authorization"])):
        raise ValueError("successor_activation_retirement_registry_missing")
    return context
