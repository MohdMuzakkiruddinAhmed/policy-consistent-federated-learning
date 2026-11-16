"""Read-only absence proof for exact recorded campaign resources and evidence.

No tag discovery or AWS mutation. Permission errors never mean absence. Private
Terraform snapshots supply exact historical identifiers, never secret values.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

CHECKS = {"no_active_owned_tasks", "no_owned_ecs_services", "no_owned_interface_endpoints", "no_owned_runtime_vpc",
          "foundation_removed", "all_recorded_evidence_retained", "all_recorded_stacks_destroyed"}


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def owned_file(value, directory):
    path = Path(value)
    if not path.is_absolute():
        path = directory / path
    path = path.resolve()
    if not path.is_relative_to(directory.resolve()) or not path.is_file():
        raise ValueError("retained_file_outside_owned_campaign_or_missing")
    return path


def operator_auxiliary_custody(inventory, directory):
    """Hash-check interrupted-launch observations and each retained task log.

    This proves custody and original identity bindings, not that an IAM probe
    passed. No account calls or log-message interpretation occur here.
    """
    def load(reference):
        path = owned_file(reference["path"], directory)
        if path.suffix.lower() != ".json": raise ValueError("operator_auxiliary_json_custody_required")
        if sha(path) != reference["sha256"]: raise ValueError("operator_auxiliary_bound_file_changed")
        return json.loads(path.read_text(encoding="utf-8"))
    def scope(record):
        return all(record.get(key) == inventory[key] for key in ("account_id", "region", "project_id", "campaign_id"))
    reports, archives = {}, 0
    for registered in inventory.get("operator_probe_log_exports", []):
        report, source = load(registered["report"]), load(registered["source_inventory"])
        if (registered.get("kind") != "registered-read-only-probe-log-custody" or not scope(report) or not scope(source)
                or report.get("kind") != "read-only-owned-probe-task-log-retention" or report.get("successful") is not True
                or report.get("performed_read_only") is not True or report.get("inventory_sha256") != registered["source_inventory"]["sha256"]
                or registered["report"]["sha256"] in reports):
            raise ValueError("operator_probe_report_original_scope_mismatch")
        contract = source["runtime_contract"]
        cluster = contract["cluster_arn"]
        if cluster != inventory["runtime_contract"]["cluster_arn"]: raise ValueError("operator_probe_original_cluster_mismatch")
        candidates = {}
        rows = [*source.get("task_observation_history", {}).values(), *source.get("observed_tasks", []),
                *source.get("client_probe_task_history", []), *source.get("client_probe_tasks", [])]
        for row in rows:
            if any(command == ["operator"] for command in row.get("effective_commands", {}).values()):
                candidates[row["task_arn"]] = row
        tasks = report.get("tasks")
        if (not isinstance(tasks, list) or len(tasks) != registered.get("task_count")
                or len({row["task_arn"] for row in tasks}) != len(tasks) or {row["task_arn"] for row in tasks} != set(candidates)):
            raise ValueError("operator_probe_task_archive_set_mismatch")
        latest = set(contract.get("task_definition_arns", {}).values())
        if registered.get("latest_revision_task_count") != sum(row["task_definition_arn"] in latest for row in tasks):
            raise ValueError("operator_probe_latest_revision_count_mismatch")
        for task in tasks:
            path = owned_file(task["path"], directory)
            body = load(task)
            observed = body.get("task", {})
            original = candidates[task["task_arn"]]
            commands = original.get("effective_commands", {})
            name = next(iter(commands)) if len(commands) == 1 else None
            definition = source.get("task_definition_history", {}).get(task["task_definition_arn"], {})
            if (not task["task_arn"].startswith(cluster.replace(":cluster/", ":task/") + "/")
                    or not re.fullmatch(r"[a-f0-9]{32}", task["task_arn"].rsplit("/", 1)[-1])
                    or not re.fullmatch(rf"arn:aws:ecs:{re.escape(inventory['region'])}:{inventory['account_id']}:task-definition/{re.escape(inventory['project_id'])}-[A-Za-z0-9_-]+:[1-9][0-9]*", task["task_definition_arn"])
                    or commands != {name: ["operator"]} or not definition or definition.get("name") != name
                    or not all(observed.get(key) == original.get(key) == task.get(key) for key in ("task_arn", "task_definition_arn", "task_role_arn"))
                    or task.get("task_role_arn") != definition.get("task_role_arn") or task.get("task_role_arn") != contract["task_role_arns"].get(name)
                    or task.get("task_role_arn") != f"arn:aws:iam::{inventory['account_id']}:role/{inventory['project_id']}-{name}"
                    or observed.get("last_status") != "STOPPED" or observed.get("effective_commands") != commands
                    or body.get("kind") != "operator-observed-isolation-probe-task-log" or body.get("pagination_complete") is not True
                    or body.get("log_group") != task.get("log_group") or task.get("log_group") != contract["log_groups"].get(name)
                    or body.get("log_stream") != task.get("log_stream") or task.get("log_stream") != "runtime/" + name + "/" + task["task_arn"].rsplit("/", 1)[-1]
                    or body.get("task_observation_source") != task.get("task_observation_source")
                    or task.get("task_observation_source") not in {"AWS_DescribeTasks", "retained_historical_STOPPED_with_current_exact_MISSING"}
                    or body.get("log_stream_state") != task.get("log_stream_state") or task.get("log_stream_state") not in {"observed", "explicit_stream_not_found"}
                    or path.stat().st_size != task.get("size_bytes") or not isinstance(body.get("events"), list)
                    or len(body["events"]) != task.get("event_count")
                    or task.get("log_stream_state") == "explicit_stream_not_found" and body["events"]):
                raise ValueError("operator_probe_task_archive_identity_or_bytes_mismatch")
            archives += 1
        reports[registered["report"]["sha256"]] = registered, report
    interruptions = inventory.get("operator_launch_interruptions", [])
    for record in interruptions:
        body = load(record)
        if (body.get("kind") != "operator-interrupted-development-launch" or body.get("application_campaign_id") != record.get("application_campaign_id")
                or body.get("training_started") is not record.get("training_started") or body.get("real_test_evaluated") is not False):
            raise ValueError("operator_interruption_original_binding_mismatch")
        required = ("original_operator_record", "actual_aws_observation", "retained_probe_logs")
        if any(body.get(name) != record.get(name) or not isinstance(record.get(name), dict) for name in required):
            raise ValueError("operator_interruption_auxiliary_references_mismatch")
        original, observation = load(record["original_operator_record"]), load(record["actual_aws_observation"])
        registered = reports.get(record["retained_probe_logs"]["sha256"])
        if (not registered or record["retained_probe_logs"] != registered[0]["report"]
                or original.get("kind") != body["kind"] or original.get("application_campaign_id") != body["application_campaign_id"]
                or original.get("training_started") is not body["training_started"]
                or observation.get("kind") != "read-only-latest-revision-pre-training-interruption-observation"
                or not scope(observation) or observation.get("successful") is not True or observation.get("performed_read_only") is not True
                or observation.get("aws_mutations") is not False or observation.get("source_inventory") != registered[0]["source_inventory"]
                or observation.get("original_interruption") != record["original_operator_record"]
                or observation.get("probe_log_report") != record["retained_probe_logs"]):
            raise ValueError("operator_interruption_actual_observation_binding_mismatch")
        guard = observation.get("guard", {})
        latest_tasks = observation.get("latest_tasks", [])
        archived = {row["task_arn"]: row for row in registered[1]["tasks"]}
        if (guard.get("account_id") != inventory["account_id"] or guard.get("active_tasks") != 0 or guard.get("service_desired_running_pending") != 0
                or len(latest_tasks) != registered[0]["latest_revision_task_count"] or len({row["task_arn"] for row in latest_tasks}) != len(latest_tasks)
                or any(row.get("last_status") != "STOPPED" or row["task_arn"] not in archived
                    or any(row.get(key) != archived[row["task_arn"]].get(key) for key in ("task_definition_arn", "task_role_arn")) for row in latest_tasks)):
            raise ValueError("operator_interruption_task_observation_set_mismatch")
    return {"operator_probe_reports_checked": len(reports), "operator_probe_task_archives_checked": archives,
            "operator_launch_interruptions_checked": len(interruptions)}


def local_custody(inventory, directory):
    """Check every retained version/index/case/witness without opening any CSV."""
    from probe_anchor import custody
    sentinel_custody = custody(inventory, directory, require_purge=inventory.get("teardown_complete") is True)
    refs, checked, pointers, observed_pointers = {}, 0, {}, set()
    bucket = inventory["foundation"]["bucket_name"]
    for ref in inventory.get("retained_artifact_versions", []):
        if (ref.get("bucket") != bucket or ref.get("version_id") in {None, "", "null"}
                or not ref.get("key", "").startswith(("evidence/", "models/", "anchors/", "metadata/"))):
            raise ValueError("invalid_retained_evidence_version")
        path = owned_file(ref["local_path"], directory)
        if path.suffix.lower() == ".csv":
            raise ValueError("clinical_csv_is_not_a_retained_model_or_evidence_artifact")
        if sha(path) != ref["sha256"] or path.stat().st_size != ref["size_bytes"]:
            raise ValueError("retained_version_bytes_changed")
        if ref["key"].startswith("metadata/") and not any(all(upload.get(name) == ref.get(name) for name in ("bucket", "key", "version_id", "sha256")) for upload in inventory.get("uploads", [])):
            raise ValueError("retained_metadata_has_no_exact_upload_receipt")
        identity = ref["key"], ref["version_id"]
        if identity in refs and any(refs[identity].get(key) != ref.get(key) for key in ("bucket", "sha256", "size_bytes")):
            raise ValueError("contradictory_retained_version")
        refs[identity] = ref
        checked += 1
    exports = dict(inventory.get("exports_by_application", {}))
    if inventory.get("export"):
        active = inventory["export"]
        application = active.get("application_campaign_id", inventory.get("application_campaign_id", inventory["campaign_id"]))
        if application in exports and exports[application].get("index_sha256") != active.get("index_sha256"):
            raise ValueError("contradictory_retained_application_index")
        exports[application] = active
    raw_results = {}
    def add_pointer(pk, manifest, order):
        if not isinstance(pk, str) or not pk.startswith("RUN#") or type(order) is not int or order < 0:
            raise ValueError("invalid_retained_pointer_binding")
        if manifest is not None and (not isinstance(manifest, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest)):
            raise ValueError("invalid_retained_pointer_manifest")
        previous = pointers.get(pk)
        if previous and previous["order"] == order and previous["manifest_id"] != manifest:
            raise ValueError("conflicting_retained_pointer_snapshots")
        if previous is None or order > previous["order"]:
            pointers[pk] = {"manifest_id": manifest, "order": order}
        if manifest is not None: observed_pointers.add((pk, manifest))
    def producer_pointers(raw):
        durable = raw.get("durable_evidence", {})
        for row in durable.get("run_records", []):
            if row.get("SK") == "POINTER":
                if row.get("PK") != "RUN#" + raw["persistent_run_id"]:
                    raise ValueError("producer_pointer_run_binding_mismatch")
                add_pointer(row["PK"], row.get("manifest_id"), durable.get("sequence", {}).get("order", row.get("commit_order", 0)))
    def bound_json(reference):
        path = owned_file(reference["path"], directory)
        if sha(path) != reference["sha256"]: raise ValueError("operator_recovery_bound_file_changed")
        return json.loads(path.read_text(encoding="utf-8"))
    def model_refs(value):
        if isinstance(value, dict):
            if {"bucket", "key", "version_id", "sha256"} <= set(value):
                exact = refs.get((value["key"], value["version_id"]))
                if exact is None or exact["bucket"] != value["bucket"] or exact["sha256"] != value["sha256"]:
                    raise ValueError("raw_model_exact_version_not_retained")
            for name, nested in value.items():
                if name.endswith("_json") and isinstance(nested, str):
                    model_refs(json.loads(nested))
                elif name.endswith("_json") and isinstance(nested, dict) and set(nested) == {"S"}:
                    model_refs(json.loads(nested["S"]))
                else:
                    model_refs(nested)
        elif isinstance(value, list):
            for nested in value: model_refs(nested)
    for application, export in exports.items():
        export_root = owned_file(Path(export.get("export_root", directory / "r")) / "campaign_result.json", directory).parent
        index_path = export_root / "campaign_result.json"
        if sha(index_path) != export["index_sha256"]:
            raise ValueError("retained_application_index_bytes_changed")
        key = export.get("index_key", f"evidence/campaigns/{application}/campaign_result.json")
        retained = refs.get((key, export["index_version_id"]))
        if retained is None or retained["sha256"] != export["index_sha256"]:
            raise ValueError("application_index_exact_version_not_retained")
        index = json.loads(index_path.read_text(encoding="utf-8"))
        if index.get("campaign_id") != application or len({row["cell_id"] for row in index["cases"]}) != len(index["cases"]):
            raise ValueError("retained_application_identity_or_duplicate_case")
        for case in index["cases"]:
            cell = case["cell_id"]
            case_directory = Path(export.get("case_directories", {}).get(cell, export_root / hashlib.sha256(cell.encode()).hexdigest()[:8]))
            case_marker = owned_file(case_directory / "cell.json", directory)
            if json.loads(case_marker.read_text()) != {"cell_id": cell}:
                raise ValueError("retained_case_marker_mismatch")
            for artifact in case["artifacts"]:
                exact = refs.get((artifact["key"], artifact["version_id"]))
                if exact is None or any(exact.get(name) != artifact.get(name) for name in ("bucket", "sha256", "size_bytes")):
                    raise ValueError("indexed_artifact_exact_version_missing")
            path = owned_file(case_directory / "runtime_result.json", directory)
            expected_key = f"evidence/campaigns/{application}/{cell}/runtime_result.json"
            raw_refs = [ref for ref in case["artifacts"] if ref["key"] == expected_key]
            if len(raw_refs) != 1 or sha(path) != raw_refs[0]["sha256"]:
                raise ValueError("retained_raw_case_bytes_changed")
            raw = json.loads(path.read_text())
            model_refs(raw); producer_pointers(raw)
            raw_results[(application, cell)] = sha(path)
            cache_path = owned_file(case_directory / "artifact_paths.json", directory)
            for expected_sha, location in json.loads(cache_path.read_text()).items():
                cached = owned_file(case_directory / location, directory)
                if not cached.is_relative_to(case_marker.parent) or cached.suffix != ".npz" or sha(cached) != expected_sha:
                    raise ValueError("retained_case_model_cache_changed")
    observations_checked, receipts_checked = 0, 0
    for recovery in inventory.get("operator_recoveries", []):
        if (recovery.get("kind") != "registered-operator-partial-cloud-recovery" or recovery.get("campaign_successful") is not False
                or recovery.get("orphan_discovery_complete") is not True):
            raise ValueError("partial_recovery_requires_completed_owned_prefix_discovery")
        report = bound_json(recovery["source_report"])
        application = recovery["application_campaign_id"]
        if (report.get("kind") != "operator-partial-cloud-export-recovery" or report.get("successful") is not False
                or report.get("campaign_complete") is not False or report.get("application_campaign_id") != application
                or report.get("bucket") != bucket or report.get("account_id") != inventory["account_id"]):
            raise ValueError("operator_recovery_source_report_binding_mismatch")
        model_refs(report.get("retained_versions", []))
        index_ref = recovery["source_index"]
        if any(index_ref.get(key) != report["producer_source_index"].get(key) for key in ("bucket", "key", "version_id", "sha256", "size_bytes")):
            raise ValueError("operator_recovery_original_index_binding_mismatch")
        index_exact = refs.get((index_ref["key"], index_ref["version_id"]))
        if index_exact is None or index_exact["sha256"] != index_ref["sha256"]:
            raise ValueError("operator_recovery_original_index_not_retained")
        index = json.loads(owned_file(index_exact["local_path"], directory).read_text())
        if index.get("campaign_id") != application: raise ValueError("operator_recovery_index_application_mismatch")
        for case in index.get("cases", []):
            for artifact in case.get("artifacts", []):
                exact = refs.get((artifact["key"], artifact["version_id"]))
                if exact is None or any(exact.get(name) != artifact.get(name) for name in ("bucket", "sha256", "size_bytes")):
                    raise ValueError("operator_recovery_indexed_exact_version_missing")
                if artifact["key"] == f"evidence/campaigns/{application}/{case['cell_id']}/runtime_result.json":
                    raw = json.loads(owned_file(exact["local_path"], directory).read_text())
                    model_refs(raw); producer_pointers(raw)
                    raw_results[(application, case["cell_id"])] = exact["sha256"]
        receipt = bound_json(recovery["orphan_discovery_receipt"])
        if receipt.get("bucket") != bucket or receipt.get("prefixes") != ["evidence/", "models/candidates/"]:
            raise ValueError("operator_orphan_discovery_scope_mismatch")
        receipt_refs = receipt.get("observed_versions")
        if not isinstance(receipt_refs, list): raise ValueError("operator_orphan_discovery_versions_missing")
        model_refs(receipt_refs)
        identities = {(row["bucket"], row["key"], row["version_id"]) for row in receipt_refs}
        if len(identities) != len(receipt_refs) or any(not row["key"].startswith(("evidence/", "models/candidates/")) for row in receipt_refs):
            raise ValueError("operator_orphan_discovery_versions_outside_scope")
        required = {(row["bucket"], row["key"], row["version_id"]) for row in report.get("retained_versions", []) if row["key"].startswith(("evidence/", "models/candidates/"))}
        if not required <= identities: raise ValueError("operator_orphan_discovery_omits_known_recovery_versions")
        receipts_checked += 1
        original_observations = {row["run_id"]: row for row in report.get("operator_observations", [])}
        registered_observations = recovery.get("operator_observations", [])
        if {row["run_id"] for row in registered_observations} != set(original_observations) or len(registered_observations) != len(original_observations):
            raise ValueError("operator_recovery_observation_set_mismatch")
        for observation in registered_observations:
            original = original_observations[observation["run_id"]]
            if any(observation.get(name) != original.get(name) for name in ("sha256", "authority_order", "observed_counts")):
                raise ValueError("operator_recovery_observation_reference_mismatch")
            body = bound_json(observation)
            pk, order = "RUN#" + observation["run_id"], observation["authority_order"]
            rows, pointer = body.get("run_records"), body.get("model_pointer")
            if (body.get("kind") != "operator-observed-partial-persistent-state" or body.get("producer_runtime_result") is not False
                    or body.get("snapshot_coherent") is not True or body.get("run_id") != observation["run_id"]
                    or body.get("table_name") != inventory["foundation"]["state_table_name"] or body.get("authority_order") != order
                    or body.get("observed_counts") != observation["observed_counts"] or body.get("sequence", {}).get("order") != {"N": str(order)}
                    or not isinstance(rows, list) or any(row.get("PK") != {"S": pk} for row in rows)):
                raise ValueError("operator_pointer_snapshot_binding_mismatch")
            if [row for row in rows if row.get("SK") == {"S": "POINTER"}] != ([] if pointer is None else [pointer]):
                raise ValueError("operator_pointer_not_original_typed_run_record")
            manifest = pointer.get("manifest_id") if pointer else None
            if manifest is not None and (not isinstance(manifest, dict) or set(manifest) != {"S"}):
                raise ValueError("operator_pointer_manifest_type_mismatch")
            add_pointer(pk, manifest["S"] if manifest else None, order)
            model_refs(rows)
            if observation.get("local_witness"):
                witness_path = owned_file(observation["local_witness"]["path"], directory)
                if sha(witness_path) != observation["local_witness"]["sha256"]:
                    raise ValueError("operator_local_witness_bytes_changed")
            observations_checked += 1
    for witness in inventory.get("protected_operator_witnesses", []):
        path = owned_file(witness["local_path"], directory)
        exact = refs.get((witness["key"], witness["version_id"]))
        if (sha(path) != witness["sha256"] or exact is None or exact["sha256"] != witness["sha256"]
                or not witness["key"].startswith("anchors/")):
            raise ValueError("protected_witness_exact_bytes_not_retained")
        application = witness.get("application_campaign_id", inventory["campaign_id"])
        if raw_results.get((application, witness["cell_id"])) != witness.get("raw_result_sha256"):
            raise ValueError("protected_witness_raw_case_not_retained")
    retired = {(row["run_pk"], row["manifest_id"]) for row in inventory.get("retired_publication_pointers", [])}
    if not retired <= observed_pointers:
        raise ValueError("retirement_not_bound_to_original_retained_pointer")
    if any(value["manifest_id"] is not None and (pk, value["manifest_id"]) not in retired for pk, value in pointers.items()):
        raise ValueError("retained_published_pointer_missing_exact_retirement_record")
    if inventory.get("task_arns") and (not (exports or inventory.get("operator_recoveries")) or not refs):
        raise ValueError("recorded_execution_requires_exported_exact_evidence")
    return {"successful": True, "retained_versions_checked": checked, "applications_checked": len(exports),
            "raw_cases_checked": len(raw_results), "witnesses_checked": len(inventory.get("protected_operator_witnesses", [])),
            "operator_observations_checked": observations_checked, "orphan_discovery_receipts_checked": receipts_checked,
            "pointer_retirements_checked": len(retired), **sentinel_custody, **operator_auxiliary_custody(inventory, directory)}


def resource_targets(inventory, directory, *, allow_partial_foundation_ecr=False):
    """Only contract identifiers and hash-bound pre-destroy state identities."""
    account, region, project = (inventory[name] for name in ("account_id", "region", "project_id"))
    targets, states, unknown = {}, [], []
    def add(kind, identifier):
        if not identifier:
            return
        if not isinstance(identifier, str):
            raise ValueError("recorded_resource_identifier_required")
        if identifier.startswith("arn:"):
            pieces = identifier.split(":", 5)
            if len(pieces) != 6 or (pieces[4] and pieces[4] != account) or (pieces[3] and pieces[3] != region):
                raise ValueError("recorded_arn_outside_account_or_region")
            if kind not in {"task", "namespace", "discovery_service", "hosted_zone"}:
                resource = pieces[5].split(":", 1)[1] if kind in {"function", "secret"} else pieces[5]
                tail = resource if kind == "secret" else resource.split("/")[-1].split(":")[0]
                if not (tail.startswith((project + "-", project + "/")) or tail == project):
                    raise ValueError("recorded_arn_outside_project")
        targets[(kind, identifier)] = {"kind": kind, "identifier": identifier}
    foundation, contract = inventory.get("foundation", {}), inventory.get("runtime_contract", {})
    cluster = contract.get("cluster_arn")
    expected_cluster = f"arn:aws:ecs:{region}:{account}:cluster/{project}-runtime"
    if cluster and cluster != expected_cluster:
        raise ValueError("recorded_cluster_outside_owned_project")
    if foundation.get("bucket_name") and foundation["bucket_name"] != f"{project}-{account}-{region}":
        raise ValueError("recorded_bucket_outside_owned_project")
    add("bucket", foundation.get("bucket_name"))
    add("table", foundation.get("state_table_name"))
    for url in foundation.get("image_repositories", {}).values():
        prefix = f"{account}.dkr.ecr.{region}.amazonaws.com/"
        if not url.startswith(prefix) or not url[len(prefix):].startswith(project + "/"):
            raise ValueError("recorded_repository_outside_owned_project")
        add("repository", url[len(prefix):])
    for name in ("client_task_role_arns", "service_task_role_arns"):
        for arn in foundation.get(name, {}).values(): add("role", arn)
    add("role", foundation.get("task_execution_role_arn"))
    for name in ("task_role_arns", "execution_role_arns"):
        for arn in contract.get(name, {}).values(): add("role", arn)
    add("cluster", cluster)
    for arn in set(inventory.get("task_arns", [])) | {row["task_arn"] for row in inventory.get("observed_tasks", [])}:
        if not cluster or not arn.startswith(cluster.replace(":cluster/", ":task/") + "/"):
            raise ValueError("recorded_task_outside_owned_cluster")
        add("task", arn)
    for name in contract.get("service_names", {}).values():
        add("service", expected_cluster.replace(":cluster/", ":service/") + "/" + name)
    for arn in contract.get("task_definition_arns", {}).values(): add("task_definition", arn)
    for arn in inventory.get("task_definition_history", {}): add("task_definition", arn)
    for name, kind in (("interface_endpoint_ids", "endpoint"), ("gateway_endpoint_ids", "endpoint"),
                       ("secret_arns", "secret"), ("log_groups", "log_group"), ("discovery_service_ids", "discovery_service"),
                       ("security_group_ids", "security_group")):
        for identifier in contract.get(name, {}).values(): add(kind, identifier)
    for identifier in contract.get("subnet_ids", []): add("subnet", identifier)
    add("vpc", contract.get("vpc_id"))
    cleanup, alerts = contract.get("automatic_cleanup", {}), contract.get("machine_cost_alerts", {})
    for name in ("schedule_arn", "provisional_schedule_arn"): add("schedule", cleanup.get(name))
    add("function", cleanup.get("function_arn")); add("queue", cleanup.get("failure_queue_url"))
    add("queue", alerts.get("queue_url")); add("topic", alerts.get("sns_topic_arn")); add("budget", alerts.get("budget_name"))
    for arn in cleanup.get("inventory", {}).get("service_arns", []): add("service", arn)
    direct = {"aws_s3_bucket": ("bucket", "bucket"), "aws_dynamodb_table": ("table", "name"),
        "aws_ecr_repository": ("repository", "name"), "aws_iam_role": ("role", "arn"),
        "aws_ecs_cluster": ("cluster", "arn"), "aws_ecs_service": ("service", "id"),
        "aws_ecs_task_definition": ("task_definition", "arn"), "aws_vpc": ("vpc", "id"),
        "aws_subnet": ("subnet", "id"), "aws_route_table": ("route_table", "id"),
        "aws_default_security_group": ("security_group", "id"), "aws_security_group": ("security_group", "id"),
        "aws_vpc_endpoint": ("endpoint", "id"), "aws_secretsmanager_secret": ("secret", "arn"),
        "aws_cloudwatch_log_group": ("log_group", "name"), "aws_lambda_function": ("function", "arn"),
        "aws_scheduler_schedule": ("schedule", "arn"), "aws_sqs_queue": ("queue", "url"),
        "aws_sns_topic": ("topic", "arn"), "aws_budgets_budget": ("budget", "name"),
        "aws_service_discovery_service": ("discovery_service", "id"),
        "aws_service_discovery_private_dns_namespace": ("namespace", "id")}
    dependent = {"aws_s3_bucket_public_access_block", "aws_s3_bucket_ownership_controls", "aws_s3_bucket_versioning",
        "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_policy", "aws_s3_bucket_lifecycle_configuration",
        "aws_iam_role_policy", "aws_route_table_association", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
        "aws_sns_topic_policy", "aws_sns_topic_subscription", "aws_sqs_queue_policy", "aws_lambda_function_event_invoke_config"}
    paths = inventory.get("state_paths", {})
    if not paths or set(paths) - {"foundation", "runtime"}:
        raise ValueError("recorded_owned_stack_states_required")
    if foundation and "foundation" not in paths or contract and "runtime" not in paths:
        raise ValueError("every_created_stack_state_required")
    snapshots = inventory.get("pre_teardown_state_snapshots", {})
    for stack, filename in paths.items():
        path = owned_file(filename, directory)
        current = json.loads(path.read_text())
        if current.get("resources") != []:
            remaining = current.get("resources")
            if (not allow_partial_foundation_ecr or stack != "foundation"
                    or not isinstance(remaining, list) or any(row.get("mode") != "managed"
                        or row.get("type") not in {"aws_ecr_repository", "terraform_data"} for row in remaining)):
                raise ValueError("recorded_terraform_stack_not_empty:" + stack)
        ref = snapshots.get(stack)
        if not ref:
            raise ValueError("hash_bound_pre_destroy_state_snapshot_required:" + stack)
        before = owned_file(ref["path"], directory)
        if sha(before) != ref["sha256"]:
            raise ValueError("pre_destroy_state_snapshot_changed")
        old = json.loads(before.read_text())
        if not isinstance(old.get("resources"), list) or not old["resources"]:
            raise ValueError("nonempty_pre_destroy_state_snapshot_required")
        if current.get("lineage") != old.get("lineage") or current.get("serial", -1) < old.get("serial", 0):
            raise ValueError("destroyed_state_lineage_or_serial_mismatch")
        for resource in old["resources"]:
            if resource.get("mode") != "managed": continue
            type_ = resource["type"]
            for instance in resource.get("instances", []):
                attrs = instance.get("attributes", {})
                tags = attrs.get("tags_all", attrs.get("tags", {})) or {}
                if tags.get("Project", project) != project:
                    raise ValueError("pre_destroy_state_has_unowned_project_resource")
                if type_ in direct:
                    kind, field = direct[type_]
                    if not attrs.get(field): raise ValueError("recorded_resource_identity_missing:" + type_)
                    add(kind, attrs[field])
                    if type_ == "aws_service_discovery_private_dns_namespace" and attrs.get("hosted_zone"):
                        add("hosted_zone", attrs["hosted_zone"])
                elif type_ not in dependent and type_ != "terraform_data":
                    unknown.append(type_)
        states.append({"stack": stack, "state_sha256": sha(path), "before_destroy_sha256": sha(before)})
    # Non-ARN names and URLs must also stay within the recorded project.
    for kind, identifier in targets:
        if kind in {"table", "budget", "log_group"} and project not in identifier:
            raise ValueError("recorded_named_resource_outside_owned_project")
        if kind == "queue" and (not identifier.startswith(f"https://sqs.{region}.amazonaws.com/{account}/") or not identifier.rsplit("/", 1)[-1].startswith(project + "-")):
            raise ValueError("recorded_queue_outside_owned_project")
        if kind == "repository" and not identifier.startswith(project + "/"):
            raise ValueError("recorded_repository_outside_owned_project")
        if kind == "task_definition" and not re.fullmatch(r"arn:aws:ecs:" + re.escape(region) + ":" + account + r":task-definition/" + re.escape(project) + r"-[A-Za-z0-9_-]+:[1-9][0-9]*", identifier):
            raise ValueError("recorded_task_definition_outside_owned_project")
    return list(targets.values()), states, sorted(set(unknown))


NOT_FOUND = {
    "bucket": {"NoSuchBucket"}, "table": {"ResourceNotFoundException"}, "repository": {"RepositoryNotFoundException"},
    "role": {"NoSuchEntity"}, "secret": {"ResourceNotFoundException"}, "function": {"ResourceNotFoundException"},
    "schedule": {"ResourceNotFoundException"}, "queue": {"QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue"},
    "topic": {"NotFound"}, "budget": {"NotFoundException"}, "namespace": {"NamespaceNotFound"},
    "discovery_service": {"ServiceNotFound"}, "hosted_zone": {"NoSuchHostedZone"},
    "vpc": {"InvalidVpcID.NotFound"}, "endpoint": {"InvalidVpcEndpointId.NotFound"},
    "subnet": {"InvalidSubnetID.NotFound"}, "route_table": {"InvalidRouteTableID.NotFound"},
    "security_group": {"InvalidGroup.NotFound"}, "log_group": {"ResourceNotFoundException"},
    "cluster": {"ClusterNotFoundException"}, "service": {"ClusterNotFoundException", "ServiceNotFoundException"},
    "task": {"ClusterNotFoundException"}, "task_definition": set()}


def observe(target, clients, inventory):
    kind, identifier = target["kind"], target["identifier"]
    account = inventory["account_id"]
    cluster = inventory.get("runtime_contract", {}).get("cluster_arn")
    result = {**target, "absent": False, "state": "present"}
    def call(service, operation, **kwargs):
        result.update(service=service, operation=operation)
        return getattr(clients[service], operation)(**kwargs)
    try:
        if kind == "bucket": call("s3", "get_bucket_location", Bucket=identifier, ExpectedBucketOwner=account)
        elif kind == "table": call("dynamodb", "describe_table", TableName=identifier)
        elif kind == "repository": call("ecr", "describe_repositories", repositoryNames=[identifier], registryId=account)
        elif kind == "role": call("iam", "get_role", RoleName=identifier.rsplit("/", 1)[-1])
        elif kind == "secret": call("secretsmanager", "describe_secret", SecretId=identifier)
        elif kind == "function": call("lambda", "get_function_configuration", FunctionName=identifier)
        elif kind == "schedule":
            group, name = identifier.split(":schedule/", 1)[1].split("/", 1)
            call("scheduler", "get_schedule", Name=name, GroupName=group)
        elif kind == "queue": call("sqs", "get_queue_attributes", QueueUrl=identifier, AttributeNames=["QueueArn"])
        elif kind == "topic": call("sns", "get_topic_attributes", TopicArn=identifier)
        elif kind == "budget": call("budgets", "describe_budget", AccountId=account, BudgetName=identifier)
        elif kind == "namespace": call("servicediscovery", "get_namespace", Id=identifier)
        elif kind == "discovery_service": call("servicediscovery", "get_service", Id=identifier)
        elif kind == "hosted_zone": call("route53", "get_hosted_zone", Id=identifier)
        elif kind == "log_group":
            token, found, tokens = None, False, set()
            while True:
                response = call("logs", "describe_log_groups", logGroupNamePrefix=identifier, **({"nextToken": token} if token else {}))
                if not isinstance(response.get("logGroups"), list): raise ValueError("unrecognized_log_group_response")
                found = found or any(row.get("logGroupName") == identifier for row in response["logGroups"])
                next_token = response.get("nextToken")
                if not next_token: break
                if next_token in tokens: raise ValueError("repeated_log_group_page")
                tokens.add(next_token)
                token = next_token
            result.update(absent=not found, state="explicit-empty-exact-name-query" if not found else "present")
        elif kind in {"vpc", "endpoint", "subnet", "route_table", "security_group"}:
            operation, field, response_key = {
                "vpc": ("describe_vpcs", "VpcIds", "Vpcs"), "endpoint": ("describe_vpc_endpoints", "VpcEndpointIds", "VpcEndpoints"),
                "subnet": ("describe_subnets", "SubnetIds", "Subnets"), "route_table": ("describe_route_tables", "RouteTableIds", "RouteTables"),
                "security_group": ("describe_security_groups", "GroupIds", "SecurityGroups")}[kind]
            response = call("ec2", operation, **{field: [identifier]})
            rows = response.get(response_key)
            if not isinstance(rows, list): raise ValueError("unrecognized_exact_network_response")
            result.update(absent=not rows or (kind == "endpoint" and all(row.get("State") == "deleted" for row in rows)),
                          state="explicit-empty-or-deleted-network-query" if not rows or kind == "endpoint" and all(row.get("State") == "deleted" for row in rows) else "present")
        elif kind in {"task", "service", "cluster"}:
            operation, field, key = {"task": ("describe_tasks", "tasks", "tasks"), "service": ("describe_services", "services", "services"),
                                     "cluster": ("describe_clusters", "clusters", "clusters")}[kind]
            response = call("ecs", operation, **{field: [identifier]}, **({"cluster": cluster} if kind != "cluster" else {}))
            rows, failures = response.get(key), response.get("failures", [])
            if not isinstance(rows, list) or not isinstance(failures, list): raise ValueError("unrecognized_exact_ecs_response")
            if not rows:
                missing = (len(failures) == 1 and failures[0].get("reason") == "MISSING"
                           and failures[0].get("arn") in {identifier, identifier.rsplit("/", 1)[-1]})
                if not missing: raise ValueError("ecs_empty_response_without_bound_MISSING")
                result.update(absent=True, state="explicit-bound-MISSING")
            elif len(rows) != 1 or failures:
                raise ValueError("ambiguous_exact_ecs_response")
            else:
                row = rows[0]
                if kind == "task":
                    gone = row.get("taskArn") == identifier and row.get("lastStatus") == "STOPPED"
                elif kind == "service":
                    gone = row.get("serviceArn") == identifier and row.get("status") == "INACTIVE" and all(row.get(key) == 0 for key in ("runningCount", "pendingCount", "desiredCount"))
                else:
                    gone = row.get("clusterArn") == identifier and row.get("status") == "INACTIVE" and all(row.get(key) == 0 for key in ("runningTasksCount", "pendingTasksCount", "activeServicesCount"))
                result.update(absent=gone, state="stopped-or-deleted-tombstone" if gone else "present")
        elif kind == "task_definition":
            # INACTIVE definition metadata is not always describable after all
            # tasks stop. Query the recorded family and exact ARN's ACTIVE
            # registration, rather than reinterpreting generic ClientException.
            family = identifier.split(":task-definition/", 1)[1].rsplit(":", 1)[0]
            token, tokens, found = None, set(), False
            while True:
                response = call("ecs", "list_task_definitions", familyPrefix=family, status="ACTIVE", **({"nextToken": token} if token else {}))
                if not isinstance(response.get("taskDefinitionArns"), list): raise ValueError("unrecognized_definition_registration_response")
                found = found or identifier in response["taskDefinitionArns"]
                token = response.get("nextToken")
                if not token: break
                if token in tokens: raise ValueError("repeated_definition_page")
                tokens.add(token)
            result.update(absent=not found, state="exact-definition-not-actively-registered" if not found else "present")
        else: raise ValueError("unsupported_recorded_resource_kind")
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in NOT_FOUND.get(kind, set()):
            result.update(absent=True, state="explicit-not-found", error_code=code)
        else:
            result.update(absent=False, state="unknown-error", error_code=code or type(error).__name__)
    return result


def validate_teardown(inventory_path, clients, *, attempts=1, retry_seconds=2, sleep=time.sleep):
    if type(attempts) is not int or not 1 <= attempts <= 12 or not isinstance(retry_seconds, (int, float)) or not 0 <= retry_seconds <= 5 or (attempts - 1) * retry_seconds > 55:
        raise ValueError("bounded_read_only_retry_required")
    path = Path(inventory_path).resolve()
    before, inventory = sha(path), json.loads(path.read_text(encoding="utf-8"))
    report = {"schema_version": "0.1.0", "kind": "actual-aws-campaign-teardown-validation", "performed_read_only": True,
        **{key: inventory[key] for key in ("account_id", "region", "project_id", "campaign_id")},
        "inventory_sha256": before, "checked_at_utc": datetime.now(timezone.utc).isoformat(), "successful": False,
        "checks": {key: False for key in sorted(CHECKS)}, "observations": [], "attempts": [], "errors": []}
    # The first actual AWS request must confirm the target identity.
    try:
        account = clients["sts"].get_caller_identity()["Account"]
        if account != inventory["account_id"] or not re.fullmatch(r"[0-9]{12}", account):
            raise ValueError("teardown_readback_account_mismatch")
        report["account_identity_confirmed"] = True
    except Exception as error:
        report["errors"].append({"scope": "identity", "code": type(error).__name__})
        return report
    try:
        targets, states, unknown = resource_targets(inventory, path.parent)
        report["recorded_stacks"] = states
        report["unsupported_recorded_resource_types"] = unknown
        report["checks"]["all_recorded_stacks_destroyed"] = inventory.get("teardown_complete") is True and not unknown
    except (OSError, ValueError, TypeError, KeyError) as error:
        report["errors"].append({"scope": "state-and-ownership", "code": str(error)[:200]})
        return report
    try:
        report["evidence_custody"] = local_custody(inventory, path.parent)
        report["checks"]["all_recorded_evidence_retained"] = True
    except (OSError, ValueError, TypeError, KeyError) as error:
        report["errors"].append({"scope": "evidence-custody", "code": str(error)[:200]})
    for number in range(1, attempts + 1):
        observations = [observe(target, clients, inventory) for target in targets]
        report["observations"] = observations
        report["attempts"].append({"attempt": number, "absent": sum(row["absent"] for row in observations),
            "present": sum(row["state"] == "present" for row in observations), "unknown_errors": sum(row["state"] == "unknown-error" for row in observations)})
        groups = {"no_active_owned_tasks": {"task"}, "no_owned_ecs_services": {"service"},
            "no_owned_interface_endpoints": {"endpoint"}, "no_owned_runtime_vpc": {"vpc"},
            "foundation_removed": {row["kind"] for row in observations} - {"task", "service", "endpoint", "vpc"}}
        for check, kinds in groups.items():
            report["checks"][check] = all(row["absent"] for row in observations if row["kind"] in kinds) and not unknown
        if all(row["absent"] for row in observations) or any(row["state"] == "unknown-error" for row in observations) or number == attempts:
            break
        sleep(retry_seconds)
    if sha(path) != before:
        report["errors"].append({"scope": "inventory", "code": "inventory_changed_during_readback"})
        report["checks"] = {key: False for key in sorted(CHECKS)}
    report["successful"] = not report["errors"] and all(report["checks"].values())
    report["limitations"] = ["Exact recorded resources only; no global tag discovery or account-wide absence claim.",
        "STOPPED tasks and INACTIVE ECS tombstones are deleted/non-running records, not active compute.",
        "Witness/version bytes are checked here; signature/semantic validation is established by separately retained proof reports.",
        "No billing invoice reconciliation is inferred from resource deletion."]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--attempts", type=int, default=1)
    parser.add_argument("--retry-seconds", type=float, default=2)
    args = parser.parse_args()
    inventory = json.loads(Path(args.inventory).read_text())
    import boto3
    from botocore.config import Config
    options = {"region_name": inventory["region"], "config": Config(ignore_configured_endpoint_urls=True,
        connect_timeout=3, read_timeout=10, retries={"max_attempts": 0})}
    services = ("sts", "s3", "dynamodb", "ecr", "iam", "secretsmanager", "lambda", "scheduler", "sqs", "sns", "budgets", "servicediscovery", "route53", "logs", "ec2", "ecs")
    clients = {name: boto3.client(name, **options) for name in services}
    report = validate_teardown(args.inventory, clients, attempts=args.attempts, retry_seconds=args.retry_seconds)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists(): raise ValueError("existing_teardown_readback_use_new_versioned_output")
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"successful": report["successful"], "checks": report["checks"], "inventory_sha256": report["inventory_sha256"]}, sort_keys=True))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
