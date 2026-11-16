"""Pure pre-bootstrap expiry containment; no SDK, ledger edits or new authority."""
from datetime import datetime
import math


def finite(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("finite_nonnegative_containment_quantity_required")
    return value


def instant(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None: raise ValueError("timezone_aware_containment_clock_required")
    return result


def check_bootstrap_window(request, approval, ledger, variables, *, now, current_deployment_key=None, recorded_expiry_utc=None):
    if now.tzinfo is None: raise ValueError("timezone_aware_containment_now_required")
    if ledger.get("authorization_sha256") != request["authorization"]["sha256"]:
        raise ValueError("containment_ledger_authorization_mismatch")
    limit = finite(approval["max_cumulative_fleet_hours"])
    if not limit: raise ValueError("positive_cumulative_containment_limit_required")
    expiry = instant(variables["hard_expiry_utc"])
    window = (expiry - now).total_seconds() / 3600
    if not 0 < window <= min(24, finite(approval["per_deployment_max_hours"])):
        raise ValueError("bootstrap_expiry_outside_approved_deployment_window")
    tasks, deployments = ledger.get("tasks", {}), ledger.get("deployments", {})
    if not isinstance(tasks, dict) or not isinstance(deployments, dict):
        raise ValueError("recorded_containment_usage_maps_required")
    cpu_hours = memory_hours = endpoint_hours = endpoint_upper_hours = 0
    for row in tasks.values():
        if row.get("last_status") != "STOPPED":
            raise ValueError("fresh_bootstrap_requires_all_old_tasks_stopped")
        cpu, memory = finite(row["cpu"]) / 1024, finite(row["memory_mib"]) / 1024
        if cpu <= 0 or memory <= 0: raise ValueError("recorded_task_resource_sizes_required")
        measured_cpu, measured_memory = finite(row["vcpu_hours"]), finite(row["gib_hours"])
        # Same conservative Linux billing model as the priced-usage loader:
        # image-pull/created fallback observations already entered the ledger;
        # stopped metadata may have expired, so retain its durable hour floors.
        seconds = max(60, math.ceil(max(measured_cpu / cpu, measured_memory / memory) * 3600))
        cpu_hours += max(measured_cpu, seconds / 3600 * cpu)
        memory_hours += max(measured_memory, seconds / 3600 * memory)
    for key, row in deployments.items():
        start = instant(row["started_at"])
        if row.get("finished_at"):
            finish = instant(row["finished_at"])
            if finish > now: raise ValueError("recorded_deployment_finish_is_in_the_future")
        else:
            if (key != current_deployment_key or row.get("campaign_id") != request["campaign_id"]
                    or row.get("project_id") != request["project_id"]):
                raise ValueError("fresh_bootstrap_requires_other_deployments_closed")
            # Retry of this exact partial bootstrap is not a fresh second fleet.
            finish = now
            if (expiry - start).total_seconds() / 3600 > min(24, finite(approval["per_deployment_max_hours"])):
                raise ValueError("partial_bootstrap_cannot_reset_total_deployment_lifetime")
            if recorded_expiry_utc and expiry > instant(recorded_expiry_utc):
                raise ValueError("partial_bootstrap_cannot_extend_recorded_expiry")
        elapsed = (finish - start).total_seconds() / 3600
        if elapsed < 0: raise ValueError("recorded_containment_clock_went_backwards")
        endpoint_hours += elapsed
        endpoint_upper_hours += math.ceil(elapsed)
    accrued = max(cpu_hours / 4, memory_hours / 14, endpoint_upper_hours)
    planned_window = math.ceil(window)
    if accrued + planned_window > limit:
        raise ValueError("bootstrap_expiry_exceeds_remaining_cumulative_budget")
    return {"kind": "pre-sdk-bootstrap-cumulative-expiry-containment", "successful": True,
        "authorization_sha256": request["authorization"]["sha256"], "as_of_utc": now.isoformat(),
        "hard_expiry_utc": expiry.isoformat(), "approved_cumulative_hours": limit,
        "recorded_task_count": len(tasks), "recorded_deployment_count": len(deployments),
        "retained_vcpu_hours_upper": cpu_hours, "retained_gib_hours_upper": memory_hours,
        "retained_endpoint_elapsed_hours": endpoint_hours, "retained_endpoint_billed_hours_upper": endpoint_upper_hours,
        "accrued_normalized_hours_upper": accrued, "proposed_window_hours": window,
        "reserved_window_hours_upper": planned_window, "remaining_hours_before_window": limit - accrued,
        "normalization": {"vcpu": 4, "memory_gib": 14},
        "ledger_rows_modified": False, "aws_calls": False,
        "scope": "planned expiry containment; provider cleanup outcome still requires observed confirmation"}
