"""Price recorded campaign usage and project remaining work; never mutate AWS.

Offline by default. Optional observations read only explicitly recorded resources.
Cost Explorer results are delayed estimates, never an invoice or billing cap.
"""
import argparse
import calendar
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from aws_campaign import load_request, validate_authorization, write_json
from cloud_io import file_sha256, task_evidence

SOURCES = {
    "fargate_billing": "https://aws.amazon.com/fargate/pricing/",
    "endpoint_billing": "https://aws.amazon.com/privatelink/pricing/",
    "secrets": "https://aws.amazon.com/secrets-manager/pricing/",
    "ecr": "https://aws.amazon.com/ecr/pricing/",
    "ecr_image_size": "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_ImageDetail.html",
    "ecr_layer_route": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html",
    "logs": "https://aws.amazon.com/cloudwatch/pricing/",
    "log_bytes": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Monitoring-CloudWatch-Metrics.html",
    "dns_zone": "https://aws.amazon.com/route53/pricing/",
    "billing_delay": "https://docs.aws.amazon.com/cost-management/latest/userguide/ce-exploring-data.html",
}
FIXED_RATES = {"interface_endpoint_az_hour": .01, "secrets_month": .40, "ecr_gib_month": .10,
               "logs_ingested_gib": .50, "private_dns_zone_month": .50, "interface_endpoint_data_gb": .01}


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone_aware_cost_timestamp_required")
    return parsed.astimezone(timezone.utc)


def binding(path):
    return {"path": str(Path(path).resolve()), "sha256": file_sha256(path)}


def finite(value, *, minimum=0):
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum:
        raise ValueError("finite_nonnegative_usage_required")
    return value


def _candidate_approval(request, *, root):
    """Route only an actual bound typed record, never an untrusted marker alone."""
    reference = request.get("authorization") or {}
    try:
        path = Path(reference["path"])
        if not path.is_absolute(): path = Path(root) / path
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError):
        value = {}
    kind = "campaign-authorization-amendment"
    if value.get("kind") == kind or "campaign_budget_kind" in request:
        if value.get("kind") != kind or request.get("campaign_budget_kind") != kind:
            raise ValueError("typed_amendment_request_marker_and_approval_must_match")
        from campaign_budget import validate_amendment
        validate_amendment(request, value, root=root)
        return value
    return None


def _validated_approval(request, *, root):
    return _candidate_approval(request, root=root) or validate_authorization(request)


def _amendment_state(request, approval, ledger, inventories, *, root):
    from campaign_budget import bound, require_successor_registration, validate_amendment, validate_ledger_lineage
    if (approval.get("kind") != "campaign-authorization-amendment"
            or request.get("campaign_budget_kind") != approval["kind"]):
        raise ValueError("coherent_typed_successor_request_required")
    context = validate_amendment(request, approval, root=root)
    if request["campaign_id"] in context["campaign_ids"] or request["project_id"] in context["project_ids"]:
        raise ValueError("fresh_successor_campaign_and_project_required")
    validate_ledger_lineage(request, ledger, root=root, campaign_inventories=inventories)
    for reference in context["terminal_inventory_refs"]:
        original = bound(root, reference)
        if inventories.get(original["campaign_id"]) != original:
            raise ValueError("immutable_terminal_predecessor_inventory_rebound")
    if "cost_scope_snapshot" not in request:
        require_successor_registration(request, root=root)
        ledger_path = Path(root) / "results/aws" / ("budget-ledger-" + request["authorization"]["sha256"] + ".json")
        if not ledger_path.is_file() or json.loads(ledger_path.read_text(encoding="utf-8")) != ledger:
            raise ValueError("preexisting_exact_successor_ledger_required")
    return context


def _lineage_inputs(request, approval, *, root):
    """Retain explicit validated chain artifacts, not stale old source pointers."""
    from campaign_budget import bound, validate_amendment
    context = validate_amendment(request, approval, root=root)
    references = []
    for authorization in context["authorization_history"]:
        references.append(authorization)
        document = bound(root, authorization)
        if document.get("proposal_sha256"):
            quote_ref = {"path": document["proposal_path"], "sha256": document["proposal_sha256"]}
            references.append(quote_ref)
        if document.get("kind") != "campaign-authorization-amendment":
            continue
        references.extend([document["approval_decision"], document["activation"]])
        activation = bound(root, document["activation"])
        references.extend(activation[name] for name in ("predecessor_authorization", "predecessor_quote", "terminal_ledger", "terminal_cost_report"))
        for pair in activation["terminal_campaigns"]: references.extend([pair["inventory"], pair["readback"]])
        proposal = bound(root, quote_ref)
        references.extend(proposal["basis"][name] for name in ("ledger", "cost_report"))
    result = {}
    for reference in references:
        bound(root, reference)
        path = Path(reference["path"]); path = path if path.is_absolute() else Path(root) / path
        result[str(path.resolve())] = binding(path)
    return list(result.values())


def _load_amended_scope(request_path, request, approval, *, root):
    from campaign_budget import bound, validate_amendment
    context = validate_amendment(request, approval, root=root)
    if request["campaign_id"] in context["campaign_ids"] or request["project_id"] in context["project_ids"]:
        raise ValueError("fresh_successor_campaign_and_project_required")
    ledger_path = Path(root) / "results/aws" / ("budget-ledger-" + request["authorization"]["sha256"] + ".json")
    if not ledger_path.is_file(): raise ValueError("successor_ledger_must_be_explicitly_initialized_before_cost")
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    names = {request["campaign_id"], *context["campaign_ids"],
        *(row["campaign_id"] for row in ledger.get("deployments", {}).values()),
        *(row["campaign_id"] for row in ledger.get("tasks", {}).values())}
    inventories, inputs = {}, [binding(request_path), binding(ledger_path), request["authorization"]]
    for reference in context["terminal_inventory_refs"]:
        value = bound(root, reference)
        inventories[value["campaign_id"]] = value
        path = Path(reference["path"]); path = path if path.is_absolute() else Path(root) / path
        inputs.append(binding(path))
    for campaign in sorted(names - set(inventories)):
        if not isinstance(campaign, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{1,63}", campaign):
            raise ValueError("invalid_owned_successor_cost_campaign")
        path = Path(root) / "results/aws" / campaign / "inventory.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("campaign_id") != campaign or (value.get("account_id"), value.get("region")) != (request["account_id"], request["region"]):
            raise ValueError("successor_cost_inventory_scope_mismatch")
        inventories[campaign] = value; inputs.append(binding(path))
    _amendment_state(request, approval, ledger, inventories, root=root)
    inputs.extend(_lineage_inputs(request, approval, root=root))
    return request, approval, ledger, inventories, inputs


def owned_image_references(request, inventories):
    references = set()
    prefix = request["account_id"] + ".dkr.ecr." + request["region"] + ".amazonaws.com/"
    for inv in inventories.values():
        owned = set(inv.get("foundation", {}).get("image_repositories", {}).values())
        refs = {row["reference"] for row in inv.get("image_history", [])}
        if inv.get("image"):
            refs.add(inv["image"]["reference"])
        for reference in refs:
            if (not isinstance(reference, str) or not re.fullmatch(re.escape(prefix) + r"[^@\s]+@sha256:[0-9a-f]{64}", reference)
                    or reference.split("@", 1)[0] not in owned):
                raise ValueError("cost_image_scope_mismatch")
        references.update(refs)
    return references


def retained_image_observations(path, expected_sha256, *, request, now, root=ROOT):
    """Reuse exact retained metadata after repository teardown, without AWS reads."""
    path = Path(path)
    if (not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or path.is_symlink() or not path.is_file() or file_sha256(path) != expected_sha256):
        raise ValueError("bound_prior_cost_observation_report_required")
    report = json.loads(path.read_text(encoding="utf-8"))
    if (report.get("kind") != "campaign-priced-usage-reconciliation" or report.get("account_id") != request["account_id"]
            or report.get("region") != request["region"] or report.get("measurement") != "inferred"
            or report.get("aws_mutations") is not False or timestamp(report["as_of_utc"]) > now):
        raise ValueError("prior_cost_observation_scope_mismatch")
    if request.get("authorization") and not any(row.get("sha256") == request["authorization"]["sha256"]
            for row in report.get("source_inputs", [])):
        if _candidate_approval(request, root=root) is None:
            raise ValueError("prior_cost_observation_authorization_mismatch")
        from campaign_budget import accepts_predecessor_cost_report
        accepts_predecessor_cost_report(request, {"path": str(path.resolve()), "sha256": expected_sha256}, root=root)
    return {"images": report.get("aws_observations", {}).get("images", []),
            "retained_image_observation_reports": [binding(path)]}


def merge_image_observations(request, inventories, current=None, retained=None, *, now):
    result = dict(current or {})
    allowed, images = owned_image_references(request, inventories), {}
    for source in (retained or {}, current or {}):
        for row in source.get("images", []):
            reference = row.get("reference")
            if reference not in allowed:
                raise ValueError("observed_image_not_in_owned_history")
            size = row.get("compressed_image_bytes")
            if type(size) is not int or size <= 0 or timestamp(row["pushed_at"]) > now:
                raise ValueError("valid_recorded_image_size_and_clock_required")
            if reference in images and (images[reference]["compressed_image_bytes"] != row["compressed_image_bytes"]
                    or timestamp(images[reference]["pushed_at"]) != timestamp(row["pushed_at"])):
                raise ValueError("immutable_image_metadata_rebound")
            images[reference] = dict(row)
    result["images"] = [images[key] for key in sorted(images)]
    if retained:
        result["retained_image_observation_reports"] = retained.get("retained_image_observation_reports", [])
    return result, allowed


def image_pull_envelope(request, inventories, observations, *, application_launches, fault_events,
                        runtime_pulls_per_application=12, probe_pulls_per_application=9, replacement_pulls_per_fault=1):
    counts = (runtime_pulls_per_application, probe_pulls_per_application, replacement_pulls_per_fault)
    if any(type(value) is not int or not 0 <= value <= 100 for value in counts) or not runtime_pulls_per_application:
        raise ValueError("bounded_explicit_image_pull_assumptions_required")
    references = owned_image_references(request, inventories)
    images = observations.get("images", [])
    observed = {row["reference"] for row in images}
    maximum = max((row["compressed_image_bytes"] for row in images), default=None)
    recorded_tasks = {arn for inv in inventories.values() for arn in inv.get("task_arns", [])}
    future_pulls = application_launches * (runtime_pulls_per_application + probe_pulls_per_application) + fault_events * replacement_pulls_per_fault
    available = bool(maximum) and bool(references) and references <= observed
    current_bytes = len(recorded_tasks) * maximum if maximum is not None else None
    future_bytes = future_pulls * maximum if maximum is not None else None
    return {"kind": "all-image-bytes-as-metered-planning-envelope", "available": available,
        "network_bytes_measured": False, "actual_paid_endpoint_bytes": None,
        "actual_paid_endpoint_cost_usd": None, "cache_assumed": False,
        "documented_layer_route": "ECR manifest/API via interface endpoints; image layers via S3 gateway endpoint",
        "route_verified_by_traffic_measurement": False,
        "maximum_observed_compressed_image_bytes": maximum,
        "owned_image_references": sorted(references), "missing_image_size_references": sorted(references - observed),
        "current_recorded_task_pull_allowance": len(recorded_tasks), "future_pull_allowance": future_pulls,
        "current_image_payload_bytes_envelope": current_bytes, "future_image_payload_bytes_envelope": future_bytes,
        "total_image_payload_bytes_envelope": None if maximum is None else current_bytes + future_bytes,
        "bytes_per_priced_GB_assumption": 1_000_000_000,
        "assumptions": {"one_full_image_download_per_recorded_task": True,
            "runtime_pulls_per_application": runtime_pulls_per_application,
            "probe_pulls_per_application": probe_pulls_per_application,
            "replacement_pulls_per_bounded_fault": replacement_pulls_per_fault,
            "future_image_no_larger_than_maximum_observed": True,
            "all_compressed_image_payload_priced_as_if_it_crossed_one_metered_endpoint": True},
        "limitations": ["Image layers normally use S3 gateway rather than metered ECR bulk transfer; this is a planning scenario, not observed paid traffic",
            "Metadata size bounds compressed image content, not total network bytes, retries or control traffic",
            "One download per task, bounded replacement allowance and future image-size cap are assumptions; rerun after new images or launch-scope changes",
            "The original endpoint allowance remains a floor; image-envelope uplift replaces overlap rather than charging the floor twice"]}


def month_fraction(start, end):
    """Prorate observed hours against each actual UTC calendar month."""
    total = 0.0
    while start < end:
        days = calendar.monthrange(start.year, start.month)[1]
        next_month = (start.replace(day=28) + timedelta(days=4)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        boundary = min(end, next_month)
        total += (boundary - start).total_seconds() / (days * 86400)
        start = boundary
    return total


def load_scope(request_path, *, root=ROOT):
    candidate = json.loads(Path(request_path).read_text(encoding="utf-8"))
    if "cost_scope_snapshot" in candidate or candidate.get("kind") == "frozen-campaign-cost-request":
        from cost_scope_snapshot import load_scope as load_snapshot
        result = load_snapshot(request_path, root=root,
            approval_loader=lambda request: _validated_approval(request, root=root), request_validator=load_request,
            state_validator=lambda request, approval, ledger, inventories:
                _amendment_state(request, approval, ledger, inventories, root=root) if approval.get("kind") == "campaign-authorization-amendment" else None)
        if result[1].get("kind") == "campaign-authorization-amendment":
            result[4].extend(_lineage_inputs(result[0], result[1], root=root))
        return result
    request = load_request(request_path)
    amendment = _candidate_approval(request, root=root)
    if amendment is not None:
        return _load_amended_scope(request_path, request, amendment, root=root)
    approval = validate_authorization(request)
    ledger_path = root / "results/aws" / ("budget-ledger-" + request["authorization"]["sha256"] + ".json")
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    if ledger.get("authorization_sha256") != request["authorization"]["sha256"]:
        raise ValueError("cost_ledger_authorization_mismatch")
    names = {request["campaign_id"], *(row["campaign_id"] for row in ledger.get("deployments", {}).values()),
             *(row["campaign_id"] for row in ledger.get("tasks", {}).values() if row.get("campaign_id"))}
    inventories, inputs = {}, [binding(request_path), binding(ledger_path), request["authorization"]]
    for campaign in sorted(names):
        if not isinstance(campaign, str) or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in campaign):
            raise ValueError("invalid_recorded_cost_campaign")
        path = root / "results/aws" / campaign / "inventory.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        if (value.get("campaign_id") != campaign or value.get("account_id") != request["account_id"]
                or value.get("region") != request["region"]):
            raise ValueError("cost_inventory_outside_approved_target")
        inventories[campaign] = value
        inputs.append(binding(path))
    return request, approval, ledger, inventories, inputs


def price_basis(quote_path, catalog_path, *, request, approval):
    quote = json.loads(Path(quote_path).read_text(encoding="utf-8"))
    if (quote.get("account_id") != request["account_id"] or quote.get("region") != request["region"]
            or approval.get("proposal_sha256") != file_sha256(quote_path)
            or quote.get("catalog_sha256") != file_sha256(catalog_path)):
        raise ValueError("cost_quote_not_bound_to_approval_and_catalog")
    catalog = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
    rates = {}
    for label, expected in quote["rates"].items():
        terms = catalog["terms"]["OnDemand"][expected["sku"]]
        if len(terms) != 1:
            raise ValueError("ambiguous_cached_cost_rate")
        term = next(iter(terms.values()))
        if len(term["priceDimensions"]) != 1:
            raise ValueError("ambiguous_cached_cost_dimension")
        dimension = next(iter(term["priceDimensions"].values()))
        if dimension["pricePerUnit"]["USD"] != expected["usd"] or term["effectiveDate"] != expected["effective_date"]:
            raise ValueError("quoted_rate_differs_from_cached_catalog")
        rates[label] = finite(float(expected["usd"]))
    if set(rates) != {"cpu", "memory"}:
        raise ValueError("both_compute_price_dimensions_required")
    return quote, {**FIXED_RATES, **rates}


def priced_tasks(ledger, inventories, now, observations=None):
    recorded = {arn for inv in inventories.values() for arn in inv.get("task_arns", [])}
    rows = {row["task_arn"]: row for inv in inventories.values() for row in inv.get("observed_tasks", [])}
    rows.update({row["task_arn"]: row for row in (observations or {}).get("tasks", [])})
    if set(ledger.get("tasks", {})) - recorded:
        raise ValueError("cost_ledger_task_missing_owned_inventory")
    measured, coverage = {}, True
    for arn in sorted(recorded):
        old = ledger.get("tasks", {}).get(arn, {})
        cpu, memory = finite(old.get("vcpu_hours", 0)), finite(old.get("gib_hours", 0))
        actual, billed, source = None, None, "shared_recorded_usage_ledger"
        row = rows.get(arn)
        if row and row.get("billing_started_at"):
            elapsed = max(0, ((timestamp(row["stopped_at"]) if row.get("stopped_at") else now) - timestamp(row["billing_started_at"])).total_seconds())
            # AWS Linux Fargate rounds up seconds, with one minute minimum.
            actual, billed = elapsed, max(60, math.ceil(elapsed))
            cpu = max(cpu, billed / 3600 * finite(row["cpu"]) / 1024)
            memory = max(memory, billed / 3600 * finite(row["memory_mib"]) / 1024)
            source = "recorded_pull_to_stop_or_asof_with_60s_minimum"
        elif old.get("last_status") != "STOPPED" or not old:
            coverage = False
        elif old.get("cpu") and old.get("memory_mib"):
            # Stopped ECS metadata eventually expires; the durable shared ledger
            # retains resource sizes and measured hours for reconstruction.
            billed = max(60, math.ceil(max(cpu / (old["cpu"] / 1024), memory / (old["memory_mib"] / 1024)) * 3600))
            cpu, memory = billed / 3600 * old["cpu"] / 1024, billed / 3600 * old["memory_mib"] / 1024
            source = "shared_stopped_usage_ledger_rounded_to_seconds"
        measured[arn] = {"vcpu_hours": cpu, "gib_hours": memory, "actual_elapsed_seconds": actual,
                         "billed_seconds_model": billed, "basis": source}
    return measured, coverage


def priced_deployments(ledger, inventories, now, rates):
    result = []
    for key, row in ledger.get("deployments", {}).items():
        inv = inventories[row["campaign_id"]]
        if row.get("project_id") != inv["project_id"]:
            raise ValueError("endpoint_cost_clock_project_mismatch")
        start, end = timestamp(row["started_at"]), timestamp(row["finished_at"]) if row.get("finished_at") else now
        if end < start:
            raise ValueError("negative_endpoint_deployment_duration")
        contract = inv["runtime_contract"]
        count, az = len(contract["interface_endpoint_ids"]), contract["endpoint_az_count"]
        if count != 5 or type(az) is not int or not 1 <= az <= 2:
            raise ValueError("recorded_endpoint_topology_required")
        hours = (end - start).total_seconds() / 3600
        result.append({"deployment_key": key, "campaign_id": row["campaign_id"], "project_id": row["project_id"],
            "started_at": start.isoformat(), "finished_at": row.get("finished_at"), "elapsed_hours": hours,
            "charged_endpoint_az_hours_upper_estimate": math.ceil(hours) * count * az,
            "endpoint_usd_upper_estimate": math.ceil(hours) * count * az * rates["interface_endpoint_az_hour"],
            "secret_count": len(contract.get("secret_arns", {})),
            "secret_storage_usd_upper_estimate": len(contract.get("secret_arns", {})) * rates["secrets_month"] * month_fraction(start, end),
            "basis": "conservative_pre_network_bootstrap_clock_until_verified_runtime_removal"})
    return result


def prepared_pilot_campaigns(request, inventories, extra_paths=()):
    """Bind retained public case configurations to actual uploaded S3 versions."""
    candidates = {str(Path(row["source_path"]).resolve()): row for row in request.get("data_uploads", []) if row.get("kind") == "campaign"}
    candidates.update({str(Path(path).resolve()): None for path in extra_paths if str(Path(path).resolve()) not in candidates})
    result = {}
    for name, spec in candidates.items():
        path = Path(name)
        if not path.is_file():
            continue
        sha = file_sha256(path)
        if spec and sha != spec["sha256"]:
            raise ValueError("prepared_pilot_campaign_source_changed")
        refs = [row for inv in inventories.values() for row in inv.get("uploads", []) if row.get("sha256") == sha
            and row.get("key", "").startswith("metadata/") and row.get("version_id") not in {None, "", "null"}
            and row.get("bucket") == inv.get("foundation", {}).get("bucket_name")
            and (not spec or row["key"] == spec["key"])]
        if not refs:
            continue
        body = json.loads(path.read_text(encoding="utf-8"))
        application, cases = body.get("campaign_id"), body.get("cases")
        if not isinstance(application, str) or not isinstance(cases, list) or not cases:
            raise ValueError("invalid_prepared_pilot_campaign")
        mapping = {case["cell_id"]: case["runtime"] for case in cases}
        if len(mapping) != len(cases):
            raise ValueError("duplicate_prepared_pilot_case")
        record = {"cases": mapping, "source": binding(path), "uploaded_versions": refs}
        if application in result and result[application]["source"]["sha256"] != sha:
            raise ValueError("prepared_pilot_application_rebound")
        result[application] = record
    return result


def pilot_throughput(inventories, data_manifest, rounds, prepared_campaigns=None):
    qualifying, ignored = [], []
    for inv in inventories.values():
        exports = dict(inv.get("exports_by_application", {}))
        if inv.get("export"):
            active = inv["export"]
            exports.setdefault(active.get("application_campaign_id", inv["campaign_id"]), active)
        for application, exported in exports.items():
            cases = exported.get("case_directories", {})
            if not cases:
                continue
            root = Path(exported.get("export_root", str(Path(next(iter(cases.values()))).parent)))
            index_path = root / "campaign_result.json"
            if file_sha256(index_path) != exported["index_sha256"]:
                raise ValueError("cost_pilot_raw_index_digest_mismatch")
            index = json.loads(index_path.read_text(encoding="utf-8"))
            if index.get("campaign_id") != application:
                raise ValueError("cost_pilot_application_mismatch")
            for case in index["cases"]:
                cell = case["cell_id"]
                path = Path(cases[cell]) / "runtime_result.json"
                refs = [row for row in case.get("artifacts", []) if row["key"].endswith("/runtime_result.json")]
                if (len(refs) != 1 or file_sha256(path) != refs[0]["sha256"] or path.stat().st_size != refs[0]["size_bytes"]):
                    raise ValueError("cost_pilot_result_not_bound_to_raw_index")
                result = json.loads(path.read_text(encoding="utf-8"))
                prepared = (prepared_campaigns or {}).get(application)
                runtime = prepared["cases"].get(cell) if prepared else None
                if runtime is not None and (result.get("cloud_campaign_id") != application or result.get("cell_id") != cell
                        or result.get("persistent_run_id") != runtime.get("persistent_run_id")
                        or result.get("baseline_id") != runtime.get("baseline_id")
                        or (result.get("distribution") is not None and result["distribution"] != runtime.get("distribution"))):
                    raise ValueError("prepared_pilot_runtime_result_binding_mismatch")
                if (runtime is not None and case.get("successful") is True and result.get("successful") is True
                        and len(result.get("rounds", [])) != runtime.get("rounds")):
                    raise ValueError("completed_prepared_pilot_round_count_mismatch")
                distribution = result.get("distribution") if result.get("distribution") is not None else (runtime or {}).get("distribution")
                training = result.get("client_training", [])
                expected = data_manifest.get("partitions", {}).get(distribution, {}).get("organizations", {})
                complete = (runtime is None or runtime.get("rounds") == rounds) and len(expected) == 8 and len(result.get("rounds", [])) == rounds and len(training) == rounds * 8 and all(
                    sum(row.get("org_id") == org and row.get("round_id") == f"round-{number}" and row.get("sample_count") == sizes["encounters"]
                        for row in training) == 1 for org, sizes in expected.items() for number in range(1, rounds + 1))
                if (not case.get("successful") or result.get("successful") is not True or result.get("aws_used") is not True or result.get("scenario_id") not in {"S0", "stable"}
                        or result.get("test_holdout_evaluated") is not False or not complete):
                    ignored.append({"cell_id": cell, "reason": "not_successful_S0_full_partition_frozen_round_count_validation_only"})
                    continue
                qualifying.append({"cell_id": cell, "application_campaign_id": application, "distribution": distribution,
                    "baseline_id": result["baseline_id"], "elapsed_seconds": finite(result["elapsed_seconds"], minimum=.000001),
                    "runtime_result": binding(path), "index": binding(index_path),
                    **({"prepared_campaign": prepared["source"], "prepared_campaign_uploaded_versions": prepared["uploaded_versions"]} if prepared else {})})
        for recovery in inv.get("operator_recoveries", []):
            ignored.append({"application_campaign_id": recovery.get("application_campaign_id"), "recovery_id": recovery.get("recovery_id"),
                "reason": "operator_partial_recovery_is_not_a_completed_full_data_pilot_export"})
    coverage = {row["distribution"] for row in qualifying}
    return {"qualifying_cases": qualifying, "ignored_cases": ignored, "both_distributions_observed": coverage == {"iid", "non_iid"},
        "worst_observed_case_seconds": max((row["elapsed_seconds"] for row in qualifying), default=None),
        "basis": "actual_raw_pinned_successful_S0_full_partition_cloud_case_elapsed_seconds"}


def _reconcile_priced_usage(request, approval, ledger, inventories, quote, rates, *, now, throughput, remaining_cells=258,
              remaining_deployments=1, application_launches=8, fault_events=30, observations=None,
              retained_observations=None, runtime_pulls_per_application=12, probe_pulls_per_application=9,
              replacement_pulls_per_fault=1, _historical_storage_end=None):
    for count in (remaining_cells, remaining_deployments, application_launches, fault_events):
        if type(count) is not int or not 0 <= count <= 1000:
            raise ValueError("bounded_nonnegative_projection_count_required")
    if remaining_cells == 0:
        remaining_deployments = application_launches = fault_events = 0
    observed, _ = merge_image_observations(request, inventories, observations, retained_observations, now=now)
    pull_envelope = image_pull_envelope(request, inventories, observed, application_launches=application_launches,
        fault_events=fault_events, runtime_pulls_per_application=runtime_pulls_per_application,
        probe_pulls_per_application=probe_pulls_per_application, replacement_pulls_per_fault=replacement_pulls_per_fault)
    tasks, coverage = priced_tasks(ledger, inventories, now, observed)
    cpu, memory = sum(row["vcpu_hours"] for row in tasks.values()), sum(row["gib_hours"] for row in tasks.values())
    compute = cpu * rates["cpu"] + memory * rates["memory"]
    deployments = priced_deployments(ledger, inventories, now, rates)
    endpoint = sum(row["endpoint_usd_upper_estimate"] for row in deployments)
    reserves = {key: finite(value) for key, value in quote["other_allowances_usd"].items()}
    required = {"endpoint_data_processing_up_to_30GB", "secrets_and_api_calls", "two_private_dns_namespaces_and_discovery", "ECR_storage",
                "S3_storage_requests_and_export", "DynamoDB_requests_storage_backup", "bounded_masked_logs", "scheduler_lambda_SQS_and_monitoring"}
    if set(reserves) != required:
        raise ValueError("all_approved_unmetered_service_reserves_required")
    endpoint_reserve = reserves["endpoint_data_processing_up_to_30GB"]
    per_gb = finite(rates["interface_endpoint_data_gb"])
    current_pull_cost = (pull_envelope["current_image_payload_bytes_envelope"] / 1_000_000_000 * per_gb
                         if pull_envelope["available"] else None)
    total_pull_cost = (pull_envelope["total_image_payload_bytes_envelope"] / 1_000_000_000 * per_gb
                       if pull_envelope["available"] else None)
    reserves["endpoint_data_processing_up_to_30GB"] = max(endpoint_reserve, current_pull_cost or 0)
    total_pull_reserve = max(endpoint_reserve, total_pull_cost or 0)
    future_pull_uplift = max(0, total_pull_reserve - reserves["endpoint_data_processing_up_to_30GB"])
    pull_envelope.update(rate_usd_per_GB=per_gb, quoted_endpoint_allowance_usd=endpoint_reserve,
        current_scenario_cost_usd=current_pull_cost, total_scenario_cost_usd=total_pull_cost,
        current_endpoint_planning_reserve_usd=reserves["endpoint_data_processing_up_to_30GB"],
        projected_endpoint_planning_reserve_usd=total_pull_reserve if pull_envelope["available"] else None,
        incremental_future_reserve_uplift_usd=future_pull_uplift if pull_envelope["available"] else None,
        reserve_key="endpoint_data_processing_up_to_30GB (legacy quote key; may be uplifted)")
    reserves["secrets_and_api_calls"] = max(reserves["secrets_and_api_calls"], sum(row["secret_storage_usd_upper_estimate"] for row in deployments))
    log_cost = sum(row.get("incoming_bytes", 0) for row in observed.get("logs", [])) / 1024 ** 3 * rates["logs_ingested_gib"]
    reserves["bounded_masked_logs"] = max(reserves["bounded_masked_logs"], log_cost)
    ecr_storage = sum(finite(row["compressed_image_bytes"]) / 1024 ** 3 * rates["ecr_gib_month"] * month_fraction(timestamp(row["pushed_at"]),
                      (_historical_storage_end or {}).get(row["reference"], now))
                      for row in observed.get("images", []))
    reserves["ECR_storage"] = max(reserves["ECR_storage"], ecr_storage)
    reserves["two_private_dns_namespaces_and_discovery"] = max(reserves["two_private_dns_namespaces_and_discovery"],
        (len(inventories) + remaining_deployments) * rates["private_dns_zone_month"] + .10)
    current_upper = compute + endpoint + sum(reserves.values())
    delayed_rows = [day for page in observed.get("cost_explorer", {}).get("pages", []) for day in page.get("ResultsByTime", [])]
    delayed_cost = None
    if delayed_rows:
        if any(day.get("Total", {}).get("UnblendedCost", {}).get("Unit") != "USD" for day in delayed_rows):
            raise ValueError("usd_cost_explorer_observation_required")
        delayed_cost = sum(finite(float(day["Total"]["UnblendedCost"]["Amount"])) for day in delayed_rows)
        # Delayed observations cannot reduce the priced ledger. When they
        # exceed it, retain the complete unmetered reserve as well.
        current_upper = max(current_upper, delayed_cost + sum(reserves.values()))
    fleet_used = max(cpu / approval["max_vcpu"], memory / approval["max_memory_gib"], sum(row["elapsed_hours"] for row in deployments))
    future_hours, projected = None, None
    projection_ready = (remaining_cells == 0 or throughput["both_distributions_observed"]) and pull_envelope["available"]
    if projection_ready:
        future_hours = (remaining_cells * (throughput["worst_observed_case_seconds"] or 0) * 1.5 + application_launches * 300 + fault_events * 300) / 3600
        fleet_rate = approval["max_vcpu"] * rates["cpu"] + approval["max_memory_gib"] * rates["memory"]
        # Add one partial-hour allowance for each continued/new deployment.
        future_endpoint = (future_hours + remaining_deployments + (1 if future_hours else 0)) * 5 * max((inv["runtime_contract"]["endpoint_az_count"] for inv in inventories.values()), default=1) * rates["interface_endpoint_az_hour"]
        projected = current_upper + future_hours * fleet_rate + future_endpoint + future_pull_uplift
    checks = {"operator_budget": approval.get("approved") is True, "current_spend_accounted": coverage and bool(deployments),
        "projected_cost": projection_ready and projected is not None and projected <= approval["approved_total_usd"],
        "image_pull_planning_envelope_available": pull_envelope["available"],
        "cumulative_resource_hours_within_authorization": fleet_used + (future_hours or 0) <= approval["max_cumulative_fleet_hours"]}
    return {"schema_version": "0.1.0", "kind": "campaign-priced-usage-reconciliation", "as_of_utc": now.isoformat(),
        "account_id": request["account_id"], "region": request["region"], "campaign_id": request["campaign_id"],
        "measurement": "inferred", "aws_mutations": False, "actual_bill_reconciled": False,
        "successful": all(checks.values()), "checks": checks, "current_spend_accounted": checks["current_spend_accounted"],
        "priced_observed_compute_usd": compute, "measured_usage_priced_lower_bound_usd": compute,
        "current_conservative_planning_estimate_usd": current_upper, "current_unmetered_service_reserves_usd": reserves,
        "delayed_cost_explorer_observed_usd": delayed_cost,
        "remaining_authorization_after_current_reserves_usd": approval["approved_total_usd"] - current_upper,
        "projected_total_conservative_estimate_usd": projected,
        "remaining_authorization_after_projection_usd": None if projected is None else approval["approved_total_usd"] - projected,
        "cumulative_fleet_equivalent_hours": fleet_used, "projected_remaining_wall_hours": future_hours,
        "remaining_work_assumptions": {"cells": remaining_cells, "future_deployments": remaining_deployments, "application_launches": application_launches,
            "bounded_fault_events": fault_events, "case_duration_safety_multiplier": 1.5, "per_launch_allowance_seconds": 300,
            "per_fault_allowance_seconds": 300, "full_concurrent_capacity_priced": {"vcpu": approval["max_vcpu"], "memory_gib": approval["max_memory_gib"]}},
        "image_pull_endpoint_planning_envelope": pull_envelope,
        "resources": {"tasks": tasks, "deployments": deployments}, "throughput": throughput,
        "price_basis": {"rates_usd": rates, "sources": SOURCES, "fargate_catalog_sha256": quote["catalog_sha256"], "proposal_checked_at_utc": quote["checked_at_utc"]},
        "observed_auxiliary_priced_usage": {"log_ingestion_usd": log_cost, "ecr_storage_approximation_usd": ecr_storage,
            "secret_storage_upper_estimate_usd": sum(row["secret_storage_usd_upper_estimate"] for row in deployments)},
        "aws_observations": observed,
        "limitations": ["Priced usage and full-service reserves are inferred accounting, not an invoice or hard spending cap",
            "All recorded tasks, including failed probes/restarts, consume the same authorization",
            "Endpoint upper estimates start before provisioning and round every partial endpoint/AZ hour upward",
            "Secrets use conservative lifetime clocks; ECR shared-layer storage and DDB/S3 requests remain explicit reserves",
            "Image payload is not measured paid endpoint traffic: ECR layers use S3 gateway; all-image-as-metered costs are conservative planning scenarios only",
            "Missing owned image metadata blocks the image-envelope projected-cost gate; retained hash-bound prior observations support offline teardown accounting",
            "Future projection requires both distributions of successful full-partition cloud S0 pilots; connectivity cases are excluded",
            "Future fault/launch allowances and 1.5x worst observed duration are assumptions, not guaranteed runtime bounds",
            "Cost Explorer data may lag more than24hours and zero tagged cost does not prove zero charge",
            "No Free Tier, credits, discounts, taxes or unrelated account resource charges are assumed"]}


def reconcile(request, approval, ledger, inventories, quote, rates, *, root=ROOT, **options):
    """Legacy pricing is unchanged; a typed successor must carry closed history."""
    if approval.get("kind") != "campaign-authorization-amendment" and "campaign_budget_kind" not in request:
        return _reconcile_priced_usage(request, approval, ledger, inventories, quote, rates, **options)
    from campaign_budget import bound
    context = _amendment_state(request, approval, ledger, inventories, root=root)
    if quote != bound(root, {"path": approval["proposal_path"], "sha256": approval["proposal_sha256"]}):
        raise ValueError("exact_approved_successor_quote_required")
    if (any(rates.get(name) != value for name, value in FIXED_RATES.items())
            or any(rates.get(name) != float(quote["rates"][name]["usd"]) for name in ("cpu", "memory"))):
        raise ValueError("unchanged_locked_pricing_required_for_cumulative_history")
    now = options["now"]
    reports = [bound(root, row["reference"]) for row in context["approved_predecessor_cost_reports"].values()]
    reports.append(bound(root, quote["basis"]["cost_report"]))
    keys = set(quote["other_allowances_usd"])
    old_reserves = {key: 0 for key in keys}
    storage_end = {}
    for report in reports:
        values = report.get("current_unmetered_service_reserves_usd", {})
        if set(values) != keys:
            raise ValueError("native_predecessor_reserve_schema_required_for_carry_forward")
        for key in keys: old_reserves[key] = max(old_reserves[key], finite(values[key]))
    for row in context["approved_predecessor_cost_reports"].values():
        report = bound(root, row["reference"])
        closed = timestamp(report["as_of_utc"])
        if closed > now: raise ValueError("predecessor_terminal_accounting_cannot_be_in_future")
        for image in report.get("aws_observations", {}).get("images", []):
            storage_end[image["reference"]] = min(storage_end.get(image["reference"], closed), closed)
    result = _reconcile_priced_usage(request, approval, ledger, inventories, quote, rates,
        _historical_storage_end=storage_end, **options)
    original_current = result["current_conservative_planning_estimate_usd"]
    original_future_image = result["image_pull_endpoint_planning_envelope"].get("incremental_future_reserve_uplift_usd") or 0
    reserves = result["current_unmetered_service_reserves_usd"]
    retained_reserve_uplift = sum(max(0, old_reserves[key] - reserves[key]) for key in keys)
    reserves.update({key: max(reserves[key], old_reserves[key]) for key in keys})
    new_compute = sum(value["vcpu_hours"] * rates["cpu"] + value["gib_hours"] * rates["memory"]
        for arn, value in result["resources"]["tasks"].items() if arn not in context["tasks"])
    new_endpoint = sum(value["endpoint_usd_upper_estimate"] for value in result["resources"]["deployments"]
        if value["deployment_key"] not in context["deployments"])
    reserve_delta = sum(max(0, reserves[key] - old_reserves[key]) for key in keys)
    inherited_floor = context["usage_floors"]["conservative_planning_usd"]
    additive_floor = inherited_floor + new_compute + new_endpoint + reserve_delta
    current = max(original_current + retained_reserve_uplift, additive_floor)
    image = result["image_pull_endpoint_planning_envelope"]
    if image["available"]:
        current_image_reserve = reserves["endpoint_data_processing_up_to_30GB"]
        total_image_reserve = max(current_image_reserve, image["total_scenario_cost_usd"])
        image.update(current_endpoint_planning_reserve_usd=current_image_reserve,
            projected_endpoint_planning_reserve_usd=total_image_reserve,
            incremental_future_reserve_uplift_usd=max(0, total_image_reserve - current_image_reserve))
    old_fleet_floor = max(context["usage_floors"]["vcpu_hours"] / approval["max_vcpu"],
        context["usage_floors"]["gib_hours"] / approval["max_memory_gib"], context["usage_floors"]["endpoint_deployment_hours"])
    fleet = max(result["cumulative_fleet_equivalent_hours"], old_fleet_floor)
    projected = result["projected_total_conservative_estimate_usd"]
    if projected is not None:
        projected = current + projected - original_current - original_future_image + (image.get("incremental_future_reserve_uplift_usd") or 0)
    result.update(current_conservative_planning_estimate_usd=current,
        remaining_authorization_after_current_reserves_usd=approval["approved_total_usd"] - current,
        projected_total_conservative_estimate_usd=projected,
        remaining_authorization_after_projection_usd=None if projected is None else approval["approved_total_usd"] - projected,
        cumulative_fleet_equivalent_hours=fleet,
        budget_semantics="cumulative-inclusive-of-predecessors",
        budget_lineage={"authorization_sha256": context["authorization_sha256"], "budget_family_id": context["budget_family_id"],
            "authorization_history": context["authorization_history"], "predecessor_authorization": context["predecessor_authorization"],
            "predecessor_cost_report": context["predecessor_cost_report"], "usage_floors": context["usage_floors"],
            "historical_campaign_ids": context["campaign_ids"], "historical_rows_retained_exactly": True,
            "historical_storage_closed_at_terminal_asof": {key: value.isoformat() for key, value in storage_end.items()}},
        inherited_current_cost_floor_usd=inherited_floor,
        new_measured_and_reserved_cost_above_inherited_floor_usd=new_compute + new_endpoint + reserve_delta)
    result["checks"]["projected_cost"] = projected is not None and projected <= approval["approved_total_usd"]
    result["checks"]["cumulative_resource_hours_within_authorization"] = fleet + (result["projected_remaining_wall_hours"] or 0) <= approval["max_cumulative_fleet_hours"]
    result["successful"] = all(result["checks"].values())
    result["limitations"].append("Typed cumulative amendment preserves exact terminal predecessor rows, reserve floors and all accrued usage; fresh measured costs add above inherited USD floor; original authorization compliance is not retroactively changed")
    return result


def observe_resources(request, inventories, *, include_cost_explorer=False, now=None, clients=None):
    """Read exact owned metadata/metrics. No account-wide resource discovery."""
    now = now or datetime.now(timezone.utc)
    if clients is None:
        import boto3
        from botocore.config import Config
        options = {"region_name": request["region"], "config": Config(ignore_configured_endpoint_urls=True, connect_timeout=5, read_timeout=20, retries={"max_attempts": 1})}
        clients = {name: boto3.client(name, **options) for name in ("sts", "ecs", "cloudwatch", "ec2", "ecr", "ce")}
    if clients["sts"].get_caller_identity()["Account"] != request["account_id"]:
        raise ValueError("cost_observation_account_mismatch")
    owned_image_references(request, inventories)
    result = {"performed_at_utc": now.isoformat(), "tasks": [], "logs": [], "endpoint_metadata": [], "images": [], "errors": []}
    for inv in inventories.values():
        contract = inv["runtime_contract"]
        cluster = f"arn:aws:ecs:{request['region']}:{request['account_id']}:cluster/{inv['project_id']}-runtime"
        if contract["cluster_arn"] != cluster:
            raise ValueError("cost_observation_cluster_outside_recorded_project")
        arns = inv.get("task_arns", [])
        for start in range(0, len(arns), 100):
            response = clients["ecs"].describe_tasks(cluster=cluster, tasks=arns[start:start + 100])
            result["tasks"].extend(task_evidence(row, request["account_id"], request["region"], cluster) for row in response.get("tasks", []))
        begin = timestamp(inv.get("deployment_started_at", now.isoformat()))
        for group in sorted(set(contract.get("log_groups", {}).values())):
            try:
                response = clients["cloudwatch"].get_metric_statistics(Namespace="AWS/Logs", MetricName="IncomingBytes", Dimensions=[{"Name": "LogGroupName", "Value": group}],
                    StartTime=begin, EndTime=now, Period=3600, Statistics=["Sum"])
                result["logs"].append({"log_group": group, "start": begin.isoformat(), "end": now.isoformat(), "incoming_bytes": sum(row["Sum"] for row in response.get("Datapoints", [])),
                                       "datapoints": len(response.get("Datapoints", [])), "basis": "AWS/Logs IncomingBytes uncompressed Sum; subject to delivery delay"})
            except Exception as error:
                result["errors"].append({"operation": "logs_metric", "kind": type(error).__name__})
        if not inv.get("teardown_complete"):
            try:
                endpoints = clients["ec2"].describe_vpc_endpoints(VpcEndpointIds=list(contract["interface_endpoint_ids"].values()) if isinstance(contract["interface_endpoint_ids"], dict) else contract["interface_endpoint_ids"])["VpcEndpoints"]
                for endpoint in endpoints:
                    tags = {row["Key"]: row["Value"] for row in endpoint.get("Tags", [])}
                    if endpoint["VpcId"] != contract["vpc_id"] or tags.get("Project") != inv["project_id"]:
                        raise ValueError("cost_endpoint_metadata_scope_mismatch")
                    result["endpoint_metadata"].append({"id": endpoint["VpcEndpointId"], "state": endpoint["State"], "created_at": endpoint["CreationTimestamp"].isoformat(), "az_eni_count": len(endpoint.get("NetworkInterfaceIds", []))})
            except ValueError:
                raise
            except Exception as error:
                result["errors"].append({"operation": "endpoint_metadata", "kind": type(error).__name__})
        refs = owned_image_references(request, {"owned": inv})
        for reference in sorted(refs):
            repository, digest = reference.split("@")
            if repository not in inv["foundation"]["image_repositories"].values():
                raise ValueError("cost_image_scope_mismatch")
            try:
                image = clients["ecr"].describe_images(registryId=request["account_id"], repositoryName=repository.split("/", 1)[1],
                    imageIds=[{"imageDigest": digest}])["imageDetails"][0]
                if image.get("imageDigest") != digest or image.get("registryId") != request["account_id"] or image.get("repositoryName") != repository.split("/", 1)[1]:
                    raise ValueError("cost_image_observation_binding_mismatch")
                result["images"].append({"reference": reference, "compressed_image_bytes": image["imageSizeInBytes"],
                    "pushed_at": image["imagePushedAt"].isoformat(), "source": "ecr.DescribeImages",
                    "basis": "compressed repository image size; manifest-list maximum; not network or paid endpoint bytes"})
            except ValueError:
                raise
            except Exception as error:
                result["errors"].append({"operation": "image_metadata", "kind": type(error).__name__})
    result["cost_explorer"] = {"requested": include_cost_explorer, "actual_invoice": False}
    if include_cost_explorer:
        # At most two charged API pages ($0.01/page); empty or delayed project
        # tag observations never override the explicit usage model/reserves.
        request_ce = {"TimePeriod": {"Start": min(timestamp(inv["deployment_started_at"]).date() for inv in inventories.values()).isoformat(), "End": (now.date() + timedelta(days=1)).isoformat()},
            "Granularity": "DAILY", "Metrics": ["UnblendedCost"], "Filter": {"And": [
                {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [request["account_id"]]}},
                {"Tags": {"Key": "Project", "Values": sorted({inv["project_id"] for inv in inventories.values()}), "MatchOptions": ["EQUALS"]}}]}}
        pages = []
        try:
            for _ in range(2):
                response = clients["ce"].get_cost_and_usage(**request_ce)
                pages.append({"ResultsByTime": response.get("ResultsByTime", []), "NextPageToken_present": bool(response.get("NextPageToken"))})
                if not response.get("NextPageToken"):
                    break
                request_ce["NextPageToken"] = response["NextPageToken"]
            result["cost_explorer"].update(pages=pages, project_tags_activation_confirmed=False,
                estimated_or_delayed=True, api_request_charge_allowance_usd=.02)
        except Exception as error:
            result["cost_explorer"].update(unavailable=True, error_type=type(error).__name__)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--quote", type=Path, default=ROOT / "reports/campaign_cost_proposal.json")
    parser.add_argument("--catalog", type=Path, default=ROOT / "results/aws/pricing/AmazonECS-us-east-1.json")
    parser.add_argument("--data-manifest", type=Path, default=ROOT / "data_manifests/dataset.json")
    parser.add_argument("--training", type=Path, default=ROOT / "configs/experiments_training.json")
    parser.add_argument("--pilot-campaigns", type=Path, nargs="*", default=[], help="Additional retained public campaign files; each must match an actual uploaded immutable metadata version")
    parser.add_argument("--remaining-cells", type=int, default=258)
    parser.add_argument("--remaining-deployments", type=int, default=1)
    parser.add_argument("--application-launches", type=int, default=8)
    parser.add_argument("--fault-events", type=int, default=30)
    parser.add_argument("--runtime-pulls-per-application", type=int, default=12)
    parser.add_argument("--probe-pulls-per-application", type=int, default=9)
    parser.add_argument("--replacement-pulls-per-fault", type=int, default=1)
    parser.add_argument("--prior-observations-report", type=Path, help="Retained priced-usage report with owned image metadata; no AWS access required")
    parser.add_argument("--prior-observations-sha256", help="Exact SHA256 of --prior-observations-report")
    parser.add_argument("--observe", action="store_true", help="Read only recorded ECS/endpoint/image metadata and CloudWatch byte metrics")
    parser.add_argument("--cost-explorer", action="store_true", help="Additionally make at most two delayed Cost Explorer reads; up to$0.02 API charges")
    parser.add_argument("--output", type=Path, default=ROOT / "reports/cloud_cost_reconciliation.json")
    args = parser.parse_args()
    if (args.prior_observations_report is None) != (args.prior_observations_sha256 is None):
        parser.error("prior observation report and SHA256 are required together")
    request, approval, ledger, inventories, inputs = load_scope(args.request)
    quote, rates = price_basis(args.quote, args.catalog, request=request, approval=approval)
    now = datetime.now(timezone.utc)
    prior = retained_image_observations(args.prior_observations_report, args.prior_observations_sha256,
        request=request, now=now) if args.prior_observations_report is not None else None
    prepared = prepared_pilot_campaigns(request, inventories, args.pilot_campaigns)
    throughput = pilot_throughput(inventories, json.loads(args.data_manifest.read_text(encoding="utf-8")), json.loads(args.training.read_text(encoding="utf-8"))["num_rounds"], prepared)
    observed = observe_resources(request, inventories, include_cost_explorer=args.cost_explorer, now=now) if args.observe or args.cost_explorer else None
    report = reconcile(request, approval, ledger, inventories, quote, rates, now=now, throughput=throughput,
        remaining_cells=args.remaining_cells, remaining_deployments=args.remaining_deployments, application_launches=args.application_launches,
        fault_events=args.fault_events, observations=observed, retained_observations=prior,
        runtime_pulls_per_application=args.runtime_pulls_per_application, probe_pulls_per_application=args.probe_pulls_per_application,
        replacement_pulls_per_fault=args.replacement_pulls_per_fault)
    report["source_inputs"] = [*inputs, binding(args.quote), binding(args.catalog), binding(args.data_manifest), binding(args.training)]
    if args.prior_observations_report is not None:
        report["source_inputs"].append(binding(args.prior_observations_report))
    report["source_sha256"] = {"scripts/reconcile_campaign_cost.py": file_sha256(__file__)}
    if approval.get("kind") == "campaign-authorization-amendment":
        import campaign_budget
        report["source_sha256"]["scripts/campaign_budget.py"] = file_sha256(campaign_budget.__file__)
    if "cost_scope_snapshot" in request:
        import cost_scope_snapshot
        report["source_sha256"]["scripts/cost_scope_snapshot.py"] = file_sha256(cost_scope_snapshot.__file__)
    report["aws_api_calls"] = args.observe or args.cost_explorer
    write_json(args.output, report)
    print(json.dumps({key: report[key] for key in ("successful", "current_spend_accounted", "current_conservative_planning_estimate_usd", "projected_total_conservative_estimate_usd", "actual_bill_reconciled")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
