"""Adopt exact operator recovery bytes into stopped campaign custody.

AWS reads only. The sole mutation is a guarded local inventory replacement.
This fast path defers the broader orphan-version scan and never invents a final
producer index or marks an aborted development campaign successful.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src")); sys.path.insert(0, str(ROOT / "scripts"))
from cloud_io import file_sha256, short_object_path
from verify_cloud_campaign import scoped_artifact_cache
from pcfl.runtime_verify import verify_case


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def error_code(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code")


def no_compute(clients, inventory):
    account, region, project = (inventory[key] for key in ("account_id", "region", "project_id"))
    if clients["sts"].get_caller_identity().get("Account") != account:
        raise ValueError("custody_account_mismatch")
    cluster = inventory["runtime_contract"]["cluster_arn"]
    if cluster != f"arn:aws:ecs:{region}:{account}:cluster/{project}-runtime":
        raise ValueError("custody_cluster_outside_owned_scope")
    ecs = clients["ecs"]
    for status in ("RUNNING", "PENDING"):
        try:
            response = ecs.list_tasks(cluster=cluster, desiredStatus=status)
            if response.get("taskArns") != [] or response.get("nextToken"):
                raise ValueError("active_or_unresolved_task_in_owned_cluster")
        except Exception as error:
            if error_code(error) != "ClusterNotFoundException": raise
    tasks = set(inventory.get("task_arns", [])) | {row["task_arn"] for row in inventory.get("observed_tasks", [])}
    prefix = cluster.replace(":cluster/", ":task/") + "/"
    if any(not arn.startswith(prefix) for arn in tasks): raise ValueError("unowned_recorded_task")
    for start in range(0, len(tasks), 100):
        requested = set(sorted(tasks)[start:start+100])
        try:
            response = ecs.describe_tasks(cluster=cluster, tasks=sorted(requested))
        except Exception as error:
            if error_code(error) == "ClusterNotFoundException": continue
            raise
        stopped = {row["taskArn"] for row in response.get("tasks", []) if row.get("lastStatus") == "STOPPED"}
        missing = {row["arn"] for row in response.get("failures", []) if row.get("reason") == "MISSING"}
        if stopped | missing != requested or len(response.get("tasks", [])) + len(response.get("failures", [])) != len(requested):
            raise ValueError("all_recorded_tasks_must_be_stopped_or_explicitly_missing")
    services = {cluster.replace(":cluster/", ":service/") + "/" + name for name in inventory["runtime_contract"].get("service_names", {}).values()}
    services |= set(inventory["runtime_contract"].get("automatic_cleanup", {}).get("inventory", {}).get("service_arns", []))
    for start in range(0, len(services), 10):
        requested = set(sorted(services)[start:start+10])
        try:
            response = ecs.describe_services(cluster=cluster, services=sorted(requested))
        except Exception as error:
            if error_code(error) == "ClusterNotFoundException": continue
            raise
        zero = {row["serviceArn"] for row in response.get("services", []) if all(row.get(key) == 0 for key in ("desiredCount", "runningCount", "pendingCount"))}
        missing = {row["arn"] for row in response.get("failures", []) if row.get("reason") == "MISSING"}
        if zero | missing != requested:
            raise ValueError("every_recorded_service_must_have_zero_desired_running_pending")
    return {"account_id": account, "cluster_arn": cluster, "recorded_tasks_checked": len(tasks),
            "recorded_services_checked": len(services), "active_tasks": 0, "service_desired_running_pending": 0,
            "checked_at_utc": datetime.now(timezone.utc).isoformat()}


def retained_file(path, *, sha256, size=None):
    path = Path(path).resolve()
    if not path.is_file() or path.suffix.lower() == ".csv" or file_sha256(path) != sha256 or size is not None and path.stat().st_size != size:
        raise ValueError("recovery_source_bytes_or_size_mismatch")
    return path


def adopt(inventory_path, report_path, clients, *, expected_inventory_sha256, before_commit=None):
    inventory_path, report_path = Path(inventory_path).resolve(), Path(report_path).resolve()
    original = inventory_path.read_bytes()
    if hashlib.sha256(original).hexdigest() != expected_inventory_sha256:
        raise ValueError("inventory_CAS_precondition_failed")
    inventory, recovery = json.loads(original), json.loads(report_path.read_text())
    report_sha, application = file_sha256(report_path), recovery["application_campaign_id"]
    if (recovery.get("kind") != "operator-partial-cloud-export-recovery" or recovery.get("successful") is not False
            or recovery.get("campaign_complete") is not False or recovery.get("collection_complete") is not True
            or any(recovery.get(key) != inventory[key] for key in ("account_id", "region"))
            or recovery.get("bucket") != inventory["foundation"]["bucket_name"]):
        raise ValueError("bound_partial_operator_recovery_required")
    identifier = "recovery-" + report_sha[:16]
    existing = inventory.get("operator_recoveries", [])
    if any(row.get("recovery_id") == identifier for row in existing):
        return {"successful": True, "already_registered": True, "recovery_id": identifier, "inventory_sha256": file_sha256(inventory_path)}
    guard = no_compute(clients, inventory)
    destination = inventory_path.parent / "r" / ("abort_" + hashlib.sha256(application.encode()).hexdigest()[:8])
    destination.mkdir(parents=True, exist_ok=True)
    def copy(source, target, expected):
        source = retained_file(source, sha256=expected)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and file_sha256(target) != expected: raise ValueError("existing_custody_copy_changed")
        if not target.exists(): shutil.copyfile(source, target)
        if file_sha256(target) != expected: raise ValueError("custody_copy_digest_failed")
        return {"path": str(target), "sha256": expected}
    known = {}
    for row in inventory.get("retained_artifact_versions", []):
        prior = retained_file(row["local_path"], sha256=row["sha256"], size=row["size_bytes"])
        if row["bucket"] != recovery["bucket"] or not prior.is_relative_to(inventory_path.parent):
            raise ValueError("prior_custody_outside_owned_campaign")
        identity = row["bucket"], row["key"], row["version_id"]
        if identity in known and any(known[identity].get(key) != row.get(key) for key in ("sha256", "size_bytes")):
            raise ValueError("contradictory_prior_custody_version")
        known[identity] = row
    added = 0
    for row in recovery["retained_versions"]:
        if (row.get("bucket") != recovery["bucket"] or row.get("version_id") in {None, "", "null"}
                or not row.get("key", "").startswith(("evidence/", "models/candidates/", "metadata/"))):
            raise ValueError("unowned_recovery_version")
        source = retained_file(row["local_path"], sha256=row["sha256"], size=row["size_bytes"])
        if not source.is_relative_to(report_path.parent): raise ValueError("recovery_file_outside_original_recovery_directory")
        target = short_object_path(destination / "v", row["key"], row["version_id"])
        copy(source, target, row["sha256"])
        identity = row["bucket"], row["key"], row["version_id"]
        if identity in known:
            if any(known[identity].get(key) != row.get(key) for key in ("sha256", "size_bytes")):
                raise ValueError("immutable_custody_version_conflict")
            retained_file(known[identity]["local_path"], sha256=row["sha256"], size=row["size_bytes"])
        else:
            known[identity] = {**row, "local_path": str(target)}; added += 1
    source_index = recovery["producer_source_index"]
    exact = known.get((source_index["bucket"], source_index["key"], source_index["version_id"]))
    if exact is None or exact["sha256"] != source_index["sha256"] or not source_index["key"].startswith(f"evidence/campaigns/{application}/index-"):
        raise ValueError("exact_partial_source_index_not_retained")
    verified = 0
    for case in recovery["cases"]:
        if case.get("verified") is True:
            raw = retained_file(case["raw_result_path"], sha256=case["raw_result_sha256"])
            if not raw.is_relative_to(report_path.parent): raise ValueError("raw_case_outside_original_recovery_directory")
            with scoped_artifact_cache(raw.parent): verify_case(raw)
            verified += 1
    observations = []
    for row in recovery.get("operator_observations", []):
        target = destination / "d" / (hashlib.sha256(row["run_id"].encode()).hexdigest()[:8] + ".json")
        binding = copy(row["source_path"], target, row["sha256"])
        snapshot = json.loads(target.read_text())
        if snapshot.get("kind") != "operator-observed-partial-persistent-state" or snapshot.get("producer_runtime_result") is not False:
            raise ValueError("operator_observation_cannot_be_producer_result")
        observation = {**binding, "run_id": row["run_id"], "observed_counts": row["observed_counts"], "authority_order": row["authority_order"]}
        if row.get("local_witness"):
            witness = row["local_witness"]
            observation["local_witness"] = {**witness, **copy(witness["path"], target.with_name(target.stem + "-witness.json"), witness["sha256"])}
        observations.append(observation)
    source = copy(report_path, destination / "recovery_report.json", report_sha)
    record = {"kind": "registered-operator-partial-cloud-recovery", "recovery_id": identifier,
        "application_campaign_id": application, "status": "operator-aborted-development", "campaign_successful": False,
        "producer_final_index_synthesized": False, "source_report": source,
        "original_report": {"path": str(report_path), "sha256": report_sha}, "source_index": exact,
        "retained_version_count": len(recovery["retained_versions"]), "verified_completed_cases": verified,
        "operator_observations": observations, "orphan_discovery_complete": False,
        "orphan_discovery_status": "deferred-until-full-owned-prefix-scan-before-teardown",
        "master_inventory_sha256_before_registration": expected_inventory_sha256,
        "registered_at_utc": datetime.now(timezone.utc).isoformat(), "zero_compute_guard": guard}
    inventory["retained_artifact_versions"] = list(known.values())
    inventory["operator_recoveries"] = [*existing, record]
    no_compute(clients, inventory)
    if before_commit: before_commit()
    lock = inventory_path.with_name("inventory.custody.lock")
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    temporary = inventory_path.with_name("inventory.custody.tmp")
    try:
        if file_sha256(inventory_path) != expected_inventory_sha256: raise ValueError("inventory_CAS_changed_before_replace")
        with temporary.open("xb") as stream:
            stream.write(canonical(inventory) + b"\n"); stream.flush(); os.fsync(stream.fileno())
        for attempt in range(6):
            try:
                os.replace(temporary, inventory_path); break
            except PermissionError:
                if attempt == 5: raise
                time.sleep(.1 * (attempt + 1))
    finally:
        os.close(descriptor); lock.unlink()
        if temporary.exists(): temporary.unlink()
    result = {"kind": "local-operator-recovery-custody-registration", "successful": True, "recovery_id": identifier,
        "source_report_sha256": report_sha, "versions_added": added, "known_versions_adopted": len(recovery["retained_versions"]),
        "verified_completed_cases": verified, "operator_observations_retained": len(observations),
        "inventory_sha256_before": expected_inventory_sha256, "inventory_sha256_after": file_sha256(inventory_path),
        "orphan_discovery_complete": False, "AWS_mutations": False, "producer_campaign_successful": False}
    receipt = destination / "registration_receipt.json"
    if not receipt.exists(): receipt.write_bytes(canonical(result) + b"\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True); parser.add_argument("--recovery-report", required=True)
    parser.add_argument("--expected-inventory-sha256", required=True); parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.apply:
        print(json.dumps({"AWS_calls": False, "local_inventory_update": False, "apply_required": True})); return 0
    inventory = json.loads(Path(args.inventory).read_text())
    import boto3
    from botocore.config import Config
    options = {"region_name": inventory["region"], "config": Config(ignore_configured_endpoint_urls=True, connect_timeout=5, read_timeout=15, retries={"max_attempts": 1})}
    clients = {name: boto3.client(name, **options) for name in ("sts", "ecs")}
    print(json.dumps(adopt(args.inventory, args.recovery_report, clients, expected_inventory_sha256=args.expected_inventory_sha256), sort_keys=True))
    return 0


if __name__ == "__main__": main()
