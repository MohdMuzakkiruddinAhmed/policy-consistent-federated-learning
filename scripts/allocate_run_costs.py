"""Allocate priced AWS usage to retained runs; no AWS, clinical rows or invoices.

Direct compute uses UTC interval intersections with actual task billing windows.
Everything else remains an explicitly attributed shared experimental allowance.
The resulting upper allocation is a planning estimate, not a per-run AWS bill.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stamp(value):
    if not isinstance(value, str):
        raise ValueError("typed_usage_timestamp_required")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timezone_aware_usage_time_required")
    return result.astimezone(timezone.utc)


def number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("finite_nonnegative_usage_required")
    return value


def binding(path):
    return {"path": str(Path(path).resolve()), "sha256": sha(path)}


def owned_path(root, path):
    root, path = Path(root).absolute(), Path(path).absolute()
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("cost_artifact_outside_owned_export")
    for component in (path, *path.parents):
        if component.is_symlink() or (hasattr(component, "is_junction") and component.is_junction()):
            raise ValueError("linked_cost_artifact_forbidden")
        if component == root:
            break
    return path.resolve()


def load_cases(inventory_path):
    inventory_path = Path(inventory_path).resolve()
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    export = inventory["export"]
    application = export.get("application_campaign_id", inventory["campaign_id"])
    directory = owned_path(inventory_path.parent, export.get("export_root", inventory_path.parent / "r"))
    if (inventory.get("application_campaign_id", application) != application
            or export.get("index_key") != f"evidence/campaigns/{application}/campaign_result.json"
            or export.get("index_version_id") in {None, "", "null"}):
        raise ValueError("cost_source_index_identity_or_version_mismatch")
    index_path = owned_path(directory, directory / "campaign_result.json")
    if sha(index_path) != export["index_sha256"]:
        raise ValueError("cost_source_index_changed")
    receipts = {}
    for receipt in inventory.get("retained_artifact_versions", []):
        identity = receipt["bucket"], receipt["key"], receipt["version_id"]
        if identity in receipts:
            raise ValueError("duplicate_cost_custody_version")
        receipts[identity] = receipt
    def custody(reference, actual_path):
        identity = reference["bucket"], reference["key"], reference["version_id"]
        receipt = receipts.get(identity)
        if (receipt is None or receipt["sha256"] != reference["sha256"]
                or receipt["size_bytes"] != reference["size_bytes"]):
            raise ValueError("cost_source_exact_custody_receipt_missing")
        cached = owned_path(inventory_path.parent, receipt["local_path"])
        if (sha(cached) != reference["sha256"] or cached.stat().st_size != reference["size_bytes"]
                or sha(actual_path) != reference["sha256"] or actual_path.stat().st_size != reference["size_bytes"]):
            raise ValueError("cost_custody_bytes_changed")
    custody({"bucket": inventory["foundation"]["bucket_name"], "key": export["index_key"],
             "version_id": export["index_version_id"], "sha256": export["index_sha256"],
             "size_bytes": index_path.stat().st_size}, index_path)
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if index["campaign_id"] != application:
        raise ValueError("cost_source_application_mismatch")
    cases, seen = [], set()
    for case in index["cases"]:
        cell = case["cell_id"]
        if cell in seen:
            raise ValueError("duplicate_cost_source_case")
        seen.add(cell)
        path = owned_path(directory, directory / hashlib.sha256(cell.encode()).hexdigest()[:8] / "runtime_result.json")
        marker = json.loads(owned_path(directory, path.parent / "cell.json").read_text(encoding="utf-8"))
        if marker != {"cell_id": cell}:
            raise ValueError("cost_source_case_marker_mismatch")
        refs = [r for r in case["artifacts"] if r["key"] == f"evidence/campaigns/{application}/{cell}/runtime_result.json"]
        if (len(refs) != 1 or refs[0]["sha256"] != sha(path)
                or refs[0]["size_bytes"] != path.stat().st_size
                or refs[0]["bucket"] != inventory["foundation"]["bucket_name"]
                or refs[0].get("version_id") in {None, "", "null"}):
            raise ValueError("cost_source_raw_version_mismatch")
        custody(refs[0], path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("cell_id") != cell or raw.get("cloud_campaign_id") != application:
            raise ValueError("cost_source_raw_identity_mismatch")
        cases.append({"cell_id": cell, "application_campaign_id": application,
            "deployment_id": inventory["campaign_id"], "raw_result": binding(path), "raw": raw})
    return inventory, cases


def allocate(cost, sources):
    """sources contains (inventory, exact raw case descriptors) pairs."""
    if (cost.get("kind") != "campaign-priced-usage-reconciliation"
            or cost.get("current_spend_accounted") is not True or cost.get("measurement") != "inferred"):
        raise ValueError("priced_accounted_usage_required")
    rates = cost["price_basis"]["rates_usd"]
    cpu_rate, memory_rate = number(rates["cpu"]), number(rates["memory"])
    total_upper = number(cost["current_conservative_planning_estimate_usd"])
    priced = cost["resources"]["tasks"]
    task_rows, runs, seen, windows, expected_tasks, known_apps = {}, [], set(), {}, {}, set()
    for inventory, cases in sources:
        if inventory["account_id"] != cost["account_id"] or inventory["region"] != cost["region"]:
            raise ValueError("run_cost_account_or_region_mismatch")
        expected_tasks.setdefault(inventory["campaign_id"], set()).update(inventory.get("task_arns", []))
        known_apps.update(inventory.get("exports_by_application", {}))
        known_apps.update(row.get("application_campaign_id") for row in inventory.get("operator_recoveries", []))
        known_apps.update(row.get("application_campaign_id") for row in inventory.get("operator_launch_interruptions", []))
        history = inventory.get("task_observation_history", {})
        history = list(history.values()) if isinstance(history, dict) else history
        for task in [*history, *inventory.get("observed_tasks", [])]:
            arn = task["task_arn"]
            if arn not in priced:
                raise ValueError("task_missing_from_priced_usage")
            previous = task_rows.get(arn)
            if previous and any(previous.get(k) != task.get(k) for k in ("cpu", "memory_mib")):
                raise ValueError("task_usage_identity_rebound")
            if previous and any(previous.get(k) and task.get(k) and previous[k] != task[k]
                                for k in ("billing_started_at", "stopped_at")):
                raise ValueError("task_usage_clock_rebound")
            if previous is None or task.get("stopped_at"):
                task_rows[arn] = task
        for source in cases:
            identity = source["application_campaign_id"], source["cell_id"]
            if identity in seen:
                raise ValueError("duplicate_run_cost_input")
            seen.add(identity)
            raw = source["raw"]
            row = {key: source[key] for key in ("cell_id", "application_campaign_id", "deployment_id", "raw_result")}
            row.update(execution_reported_success=raw.get("successful") is True,
                published_models=len(raw["published_manifests"]) if isinstance(raw.get("published_manifests"), list) else None,
                cost_usd=None, resources=None)
            try:
                start, end = stamp(raw["case_started_at_utc"]), stamp(raw["case_finished_at_utc"])
                duration = number(raw["elapsed_seconds"])
                if end <= start or abs((end-start).total_seconds()-duration) > max(1, duration*.001):
                    raise ValueError("case_wall_and_monotonic_duration_disagree")
            except (KeyError, TypeError, ValueError) as error:
                row.update(timing_status="missing-or-invalid", timing_reason=str(error))
            else:
                row.update(timing_status="observed", started_at_utc=start.isoformat(),
                    finished_at_utc=end.isoformat(), elapsed_seconds=duration)
                windows.setdefault(source["deployment_id"], []).append((start, end, row))
            runs.append(row)
    for group in windows.values():
        group.sort(key=lambda item: item[0])
        if any(left[1] > right[0] for left, right in zip(group, group[1:])):
            raise ValueError("overlapping_sequential_case_usage_windows")
    missing_tasks = {deployment: sorted(arn for arn in arns if arn not in task_rows
        or not task_rows[arn].get("billing_started_at") or not task_rows[arn].get("stopped_at"))
        for deployment, arns in expected_tasks.items()}
    for task in task_rows.values():
        if task.get("billing_started_at") and task.get("stopped_at") and stamp(task["stopped_at"]) < stamp(task["billing_started_at"]):
            raise ValueError("negative_task_usage_window")
    consumed = {}
    for deployment, group in windows.items():
        for start, end, row in group:
            cpu_seconds, memory_seconds = 0., 0.
            for arn, task in task_rows.items():
                if not task.get("billing_started_at") or not task.get("stopped_at"):
                    continue
                # Case/deployment ownership is also bound by its recorded task ARNs.
                owners = {inv["campaign_id"] for inv, _ in sources if arn in inv.get("task_arns", [])}
                if deployment not in owners:
                    continue
                seconds = max(0., (min(end, stamp(task["stopped_at"]))-max(start, stamp(task["billing_started_at"]))).total_seconds())
                cpu = seconds * number(task["cpu"]) / 1024
                memory = seconds * number(task["memory_mib"]) / 1024
                cpu_seconds += cpu
                memory_seconds += memory
                old = consumed.setdefault(arn, [0., 0.])
                old[0] += cpu / 3600
                old[1] += memory / 3600
            if not cpu_seconds or not memory_seconds:
                row.update(timing_status="no-task-usage-coverage", timing_reason="No recorded billed task overlaps this case")
            else:
                row["resource_coverage_complete"] = not missing_tasks.get(deployment)
                row["resources"] = {"vcpu_seconds": cpu_seconds, "memory_gib_seconds": memory_seconds}
                row["direct_compute_usd"] = (cpu_seconds*cpu_rate+memory_seconds*memory_rate)/3600
    for arn, (cpu, memory) in consumed.items():
        if cpu > number(priced[arn]["vcpu_hours"])+1e-8 or memory > number(priced[arn]["gib_hours"])+1e-8:
            raise ValueError("allocated_compute_exceeds_recorded_billable_usage")
    observed = [row for row in runs if row["timing_status"] == "observed"]
    direct = sum(row["direct_compute_usd"] for row in observed)
    if direct > total_upper + 1e-8:
        raise ValueError("direct_compute_exceeds_global_planning_estimate")
    seconds = sum(row["elapsed_seconds"] for row in observed)
    remainder = max(0., total_upper-direct)
    for row in observed:
        share = row["elapsed_seconds"]/seconds if seconds else 0
        upper = row["direct_compute_usd"]+remainder*share
        row["cost_usd"] = {"measurement": "inferred-allocation", "direct_compute": row["direct_compute_usd"],
            "allocated_shared_experimental_allowance": remainder*share, "planning_upper_allocation": upper,
            "per_published_round_planning_upper": upper/row["published_models"] if row["published_models"] else None}
    selected_apps = {row["application_campaign_id"] for row in runs}
    omitted_apps = sorted(known_apps - selected_apps - {None})
    return {"schema_version": "0.1.0", "kind": "retained-run-priced-usage-allocation",
        "successful": bool(runs) and len(observed) == len(runs) and not any(missing_tasks.values()),
        "scope": "explicitly-supplied-application-inventories;not-study-completion",
        "selected_applications": sorted(selected_apps), "known_retained_applications_omitted": omitted_apps,
        "all_known_applications_supplied": not omitted_apps,
        "task_window_coverage_complete": not any(missing_tasks.values()), "missing_task_windows": missing_tasks,
        "actual_invoice": False, "aws_calls": False,
        "allocation_scope": "all supplied run windows; all remaining campaign cost is shared experimental overhead",
        "shared_weight": "observed per-case monotonic elapsed seconds", "runs": runs,
        "direct_compute_usd": direct, "shared_planning_allowance_usd": remainder,
        "allocated_total_upper_usd": total_upper if observed else 0,
        "unallocated_upper_usd": total_upper if not observed else 0,
        "limitations": ["UTC overlap infers reserved vCPU/GiB usage; it does not measure CPU utilization",
            "UTC is used only for cost attribution, never policy ordering or cross-host enforcement latency",
            "Shared allocation includes idle/probe/restart/collection time and all unmetered service reserves",
            "A per-run planning upper allocation is not an AWS invoice or a guaranteed upper bill",
            "Storage, requests, logging and controls remain shared allowances; missing measurements are not zero charges",
            "Interim allocations change when the supplied run set or priced-usage snapshot changes"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cost-report", required=True, type=Path)
    parser.add_argument("--inventories", nargs="+", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = allocate(json.loads(args.cost_report.read_text(encoding="utf-8")), [load_cases(path) for path in args.inventories])
    report["inputs"] = {"priced_usage": binding(args.cost_report), "inventories": [binding(path) for path in args.inventories]}
    report["source_sha256"] = sha(__file__)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"successful": report["successful"], "runs": len(report["runs"]), "actual_invoice": False}))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
