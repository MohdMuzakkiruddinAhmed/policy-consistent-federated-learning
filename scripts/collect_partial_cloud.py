"""Recover exact partial producer exports with read-only, explicitly scoped APIs.

Never constructs a completed producer index/result. Operator observations have a
different kind and remain incomplete even when individual cases verify.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from cloud_io import short_object_path
from verify_cloud_campaign import scoped_artifact_cache
from pcfl.runtime_verify import verify_case

HEX = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def safe_key(key):
    return isinstance(key, str) and "\\" not in key and all(part not in {"", ".", ".."} for part in key.split("/"))


def s3_refs(value):
    if isinstance(value, dict):
        if {"bucket", "key", "version_id", "sha256"} <= set(value):
            yield value
        for name, child in value.items():
            if name.endswith("_json") and isinstance(child, str):
                yield from s3_refs(json.loads(child))
            else:
                yield from s3_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from s3_refs(child)


class Reader:
    def __init__(self, s3, account, bucket, output, *, max_bytes=2 * 1024**3):
        self.s3, self.account, self.bucket, self.output = s3, account, bucket, Path(output)
        self.max_bytes, self.total, self.records = max_bytes, 0, {}

    def fetch(self, reference, *, allowed, directory=None, filename=None):
        key, version = reference.get("key"), reference.get("version_id")
        if (reference.get("bucket", self.bucket) != self.bucket or not safe_key(key) or not allowed(key)
                or not isinstance(version, str) or version in {"", "null"}
                or ("sha256" in reference and not HEX.fullmatch(reference["sha256"]))):
            raise ValueError("exact_owned_allowed_version_reference_required")
        identity = key, version
        if identity in self.records:
            prior = self.records[identity]
            if reference.get("sha256", prior["sha256"]) != prior["sha256"]:
                raise ValueError("contradictory_immutable_reference")
            return prior
        response = self.s3.get_object(Bucket=self.bucket, Key=key, VersionId=version, ExpectedBucketOwner=self.account)
        length = response.get("ContentLength")
        if response.get("VersionId") != version or type(length) is not int or not 0 <= length <= 128 * 1024**2:
            response["Body"].close()
            raise ValueError("actual_object_version_or_size_invalid")
        if self.total + length > self.max_bytes:
            response["Body"].close()
            raise ValueError("bounded_recovery_bytes_exceeded")
        path = short_object_path(directory or self.output / "o", key, version, filename=filename)
        hasher, size = hashlib.sha256(), 0
        try:
            with path.open("xb") as stream:
                while True:
                    block = response["Body"].read(min(1024 * 1024, length - size + 1))
                    if not block: break
                    size += len(block)
                    if size > length: raise ValueError("object_body_exceeds_declared_length")
                    stream.write(block); hasher.update(block)
        finally:
            response["Body"].close()
        observed = hasher.hexdigest()
        if size != length or reference.get("size_bytes", length) != length or reference.get("sha256", observed) != observed:
            raise ValueError("immutable_object_digest_or_length_mismatch")
        self.total += size
        record = {"bucket": self.bucket, "key": key, "version_id": version, "sha256": observed,
                  "size_bytes": size, "local_path": str(path.resolve())}
        self.records[identity] = record
        return record


def query_all(ddb, table, partition):
    rows, cursor, seen = [], None, set()
    for _ in range(1000):
        response = ddb.query(TableName=table, KeyConditionExpression="PK = :pk", ExpressionAttributeValues={":pk": {"S": partition}},
            ConsistentRead=True, **({"ExclusiveStartKey": cursor} if cursor else {}))
        if any(row.get("PK") != {"S": partition} for row in response.get("Items", [])):
            raise ValueError("operator_snapshot_partition_scope_mismatch")
        rows.extend(response.get("Items", []))
        cursor = response.get("LastEvaluatedKey")
        if not cursor: return rows
        marker = digest(canonical(cursor))
        if marker in seen: raise ValueError("operator_snapshot_repeated_page")
        seen.add(marker)
    raise ValueError("bounded_operator_snapshot_pages_exhausted")


def operator_snapshot(ddb, table, run_id, *, attempts=3):
    key = {"PK": {"S": "AUTHORITY"}, "SK": {"S": "SEQUENCE"}}
    for attempt in range(1, attempts + 1):
        before = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        if not before or not re.fullmatch(r"[0-9]+", before.get("order", {}).get("N", "")):
            raise ValueError("authoritative_sequence_not_observed")
        policies = [row for number in range(1, 9) for row in query_all(ddb, table, f"POLICY#org_{number:02d}")]
        rows = query_all(ddb, table, "RUN#" + run_id)
        after = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        if before != after: continue
        unique = {row["SK"]["S"]: row for row in rows}
        if len(unique) != len(rows): raise ValueError("duplicate_operator_run_record")
        assigned, acknowledged, final = set(), set(), {}
        for sk, row in unique.items():
            if sk.startswith("ISSUE#"):
                task = json.loads(row["task_json"]["S"]); assigned.add(task["update_id"])
            if sk.startswith("TASK#"):
                uid = row.get("update_id", {}).get("S")
                if uid: assigned.add(uid); acknowledged.add(uid)
            if sk.startswith(("UPDATE#", "ATTEMPT#")) and row.get("decision_json", {}).get("S"):
                decision = json.loads(row["decision_json"]["S"])
                if decision.get("outcome") in {"accepted", "rejected", "error"}:
                    if decision["update_id"] in final: raise ValueError("duplicate_observed_final_decision")
                    final[decision["update_id"]] = decision["outcome"]
        return {"kind": "operator-observed-partial-persistent-state", "successful": False,
            "full_protocol_pass": False, "producer_runtime_result": False, "snapshot_coherent": True,
            "table_name": table, "run_id": run_id, "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "authority_order": int(before["order"]["N"]), "fence_attempt": attempt,
            "sequence": before, "policy_records": policies, "run_records": rows,
            "observed_counts": {"assigned_tasks": len(assigned), "acknowledged_tasks": len(acknowledged),
                "final_update_decisions": sum(value in {"accepted", "rejected"} for value in final.values()),
                "final_operational_errors": sum(value == "error" for value in final.values()),
                "indeterminate_tasks": len(assigned - set(final)), "run_records": len(rows), "policy_records": len(policies)},
            "audit_head": unique.get("AUDIT_HEAD"), "model_pointer": unique.get("POINTER")}
    raise ValueError("coherent_operator_snapshot_retry_exhausted")


def scalar_row(row):
    decoded = {}
    for name, value in row.items():
        if set(value) == {"S"}: decoded[name] = value["S"]
        elif set(value) == {"N"} and re.fullmatch(r"-?[0-9]+", value["N"]): decoded[name] = int(value["N"])
        elif set(value) == {"BOOL"} and type(value["BOOL"]) is bool: decoded[name] = value["BOOL"]
        elif value == {"NULL": True}: decoded[name] = None
        else: raise ValueError("unsupported_operator_observed_attribute")
    return decoded


def latest_index(s3, *, bucket, account, application, registered_cases):
    """Discover only the finite known application's immutable index namespace."""
    prefix, request, versions, seen = f"evidence/campaigns/{application}/index-", {}, [], set()
    for _ in range(100):
        response = s3.list_object_versions(Bucket=bucket, Prefix=prefix, ExpectedBucketOwner=account, **request)
        for item in response.get("Versions", []):
            match = re.fullmatch(re.escape(prefix) + r"([0-9]{4})\.json", item.get("Key", ""))
            if not match or not 0 <= int(match[1]) < registered_cases:
                raise ValueError("unexpected_key_in_finite_application_index_namespace")
            if item.get("IsLatest") is True and item.get("VersionId") not in {None, "", "null"}:
                versions.append({"ordinal": int(match[1]), "key": item["Key"], "version_id": item["VersionId"]})
        if not response.get("IsTruncated"): break
        request = {"KeyMarker": response["NextKeyMarker"], "VersionIdMarker": response["NextVersionIdMarker"]}
        marker = digest(canonical(request))
        if marker in seen: raise ValueError("repeated_application_index_version_page")
        seen.add(marker)
    else:
        raise ValueError("bounded_application_index_version_pages_exceeded")
    if not versions: raise ValueError("no_immutable_completed_case_index_observed")
    chosen = max(versions, key=lambda row: row["ordinal"])
    if sum(row["ordinal"] == chosen["ordinal"] for row in versions) != 1:
        raise ValueError("ambiguous_latest_application_index_version")
    return chosen, versions


def collect(inventory_path, campaign_path, *, application, index_key, output, clients,
            index_version_id=None, expected_index_sha256=None, observe_runs=(), witness_key=None, witness_pin=None,
            discover_latest=False, observe_unfinished=False, operator_context="live-partial-observation"):
    inventory_path, campaign_path, output = Path(inventory_path).resolve(), Path(campaign_path).resolve(), Path(output).resolve()
    if not IDENTIFIER.fullmatch(application) or (not discover_latest and (not isinstance(index_key, str) or not re.fullmatch(r"evidence/campaigns/" + re.escape(application) + r"/(?:index-[0-9]{4}|campaign_result)\.json", index_key))):
        raise ValueError("explicit_application_index_scope_required")
    if operator_context not in {"live-partial-observation", "operator-controlled-abort-observation", "post-abort-recovery"}:
        raise ValueError("explicit_operator_recovery_context_required")
    if output.exists() and any(output.iterdir()): raise ValueError("new_owned_recovery_directory_required")
    output.mkdir(parents=True, exist_ok=True)
    inventory_bytes, campaign_bytes = inventory_path.read_bytes(), campaign_path.read_bytes()
    source_hashes = {name: digest((ROOT / name).read_bytes()) for name in ("scripts/collect_partial_cloud.py", "scripts/verify_cloud_campaign.py",
        "src/pcfl/runtime_verify.py", "src/pcfl/oracle.py", "policies/rego/pcfl.rego")}
    inventory, campaign = json.loads(inventory_bytes), json.loads(campaign_bytes)
    account, region, bucket = inventory["account_id"], inventory["region"], inventory["foundation"]["bucket_name"]
    if (not re.fullmatch(r"[0-9]{12}", account) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region)
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) or not bucket.startswith(inventory["project_id"] + "-")):
        raise ValueError("explicit_owned_account_region_bucket_required")
    if clients["sts"].get_caller_identity().get("Account") != account: raise ValueError("recovery_account_identity_mismatch")
    prepared = {case["cell_id"]: case["runtime"] for case in campaign["cases"]}
    if campaign.get("campaign_id") != application or len(prepared) != len(campaign["cases"]):
        raise ValueError("prepared_campaign_identity_or_duplicate_case")
    candidate_refs = [ref for ref in inventory.get("uploads", []) if ref.get("bucket") == bucket and ref.get("sha256") == digest(campaign_bytes)
        and ref.get("key", "").startswith("metadata/") and ref.get("version_id") not in {None, "", "null"}]
    if not candidate_refs: raise ValueError("prepared_campaign_has_no_recorded_immutable_upload")
    reader = Reader(clients["s3"], account, bucket, output)
    reader.fetch(candidate_refs[0], allowed=lambda key: key.startswith("metadata/") and key.endswith(".json"))
    (output / "master_inventory_observed.json").write_bytes(inventory_bytes)
    (output / "public_campaign_observed.json").write_bytes(campaign_bytes)
    discovered = []
    if discover_latest:
        chosen, discovered = latest_index(clients["s3"], bucket=bucket, account=account, application=application, registered_cases=len(prepared))
        index_key, index_version_id = chosen["key"], chosen["version_id"]
    head = clients["s3"].head_object(Bucket=bucket, Key=index_key, ExpectedBucketOwner=account,
        **({"VersionId": index_version_id} if index_version_id else {}))
    version = head.get("VersionId")
    if not isinstance(version, str) or version in {"", "null"} or index_version_id and version != index_version_id:
        raise ValueError("actual_index_head_version_required")
    reference = {"bucket": bucket, "key": index_key, "version_id": version, "size_bytes": head["ContentLength"]}
    if expected_index_sha256: reference["sha256"] = expected_index_sha256
    index_ref = reader.fetch(reference, allowed=lambda key: key == index_key, directory=output, filename="source_index.json")
    index = json.loads(Path(index_ref["local_path"]).read_text())
    if index.get("campaign_id") != application or not isinstance(index.get("cases"), list):
        raise ValueError("actual_producer_index_identity_mismatch")
    cases, seen, completed_runs = [], set(), set()
    for case in index["cases"]:
        cell = case["cell_id"]
        if cell not in prepared or cell in seen or not IDENTIFIER.fullmatch(cell): raise ValueError("unregistered_or_duplicate_index_case")
        seen.add(cell)
        directory = output / "r" / digest(cell.encode())[:8]
        directory.mkdir(parents=True)
        save_json(directory / "operator_case_mapping.json", {"kind": "operator-recovery-case-mapping", "cell_id": cell})
        item = {"cell_id": cell, "producer_successful": case.get("successful"), "producer_status": case.get("status"),
                "classification": "producer-case-without-exported-raw", "verified": False, "source_artifacts": [], "errors": []}
        raw_path, cache = None, {}
        try:
            for artifact in case.get("artifacts", []):
                prefix = f"evidence/campaigns/{application}/{cell}/"
                if Path(artifact["key"]).suffix not in {".json", ".npz", ".log"}: raise ValueError("non_evidence_or_model_artifact_forbidden")
                is_raw = artifact["key"] == prefix + "runtime_result.json"
                record = reader.fetch(artifact, allowed=lambda key: key.startswith(prefix), directory=directory,
                                      filename="runtime_result.json" if is_raw else None)
                item["source_artifacts"].append(record)
                if is_raw:
                    if raw_path is not None: raise ValueError("duplicate_raw_result_artifact")
                    raw_path = Path(record["local_path"])
                if Path(record["local_path"]).suffix == ".npz": cache[record["sha256"]] = Path(record["local_path"]).name
            if raw_path is not None:
                raw = json.loads(raw_path.read_text())
                runtime, run_id = prepared[cell], prepared[cell]["persistent_run_id"]
                if raw.get("cell_id") != cell or raw.get("cloud_campaign_id") != application or raw.get("persistent_run_id") != run_id:
                    raise ValueError("raw_source_campaign_case_or_run_mismatch")
                if raw.get("successful") is True and case.get("successful") is True:
                    completed_runs.add(run_id)
                for artifact in s3_refs(raw):
                    allowed = lambda key: key.endswith(".npz") and key.startswith((f"evidence/{run_id}/", f"models/candidates/{run_id}/"))
                    record = reader.fetch(artifact, allowed=allowed)
                    path = Path(record["local_path"])
                    target = short_object_path(directory, record["key"], record["version_id"])
                    if target != path and not target.exists(): shutil.copyfile(path, target)
                    cache[record["sha256"]] = target.name
                save_json(directory / "artifact_paths.json", cache)
                item["raw_result_sha256"] = digest(raw_path.read_bytes())
                item["raw_result_path"] = str(raw_path)
                if raw.get("successful") is True and case.get("successful") is True:
                    with scoped_artifact_cache(directory): item["summary"] = verify_case(raw_path)
                    item.update(verified=True, classification="independently-verified-completed-source-case")
                else:
                    item["classification"] = "producer-failed-or-partial-source-case"
        except Exception as error:
            item["errors"].append({"type": type(error).__name__, "reason": getattr(error, "response", {}).get("Error", {}).get("Code", str(error)[:250])})
            item["classification"] = "source-case-recovery-or-verification-failed"
        save_json(directory / "operator_case_assessment.json", {"kind": "operator-partial-source-case-assessment", **item})
        cases.append(item)
    observations = []
    runs = {runtime["persistent_run_id"]: (cell, runtime) for cell, runtime in prepared.items()}
    requested_runs = set(observe_runs) | ({run for run in runs if run not in completed_runs} if observe_unfinished else set())
    for run_id in sorted(requested_runs):
        if run_id not in runs or run_id in completed_runs: raise ValueError("operator_snapshot_only_for_bound_unfinished_run")
        cell, runtime = runs[run_id]
        table = runtime["table_name"]
        if table != inventory["foundation"]["state_table_name"]: raise ValueError("operator_snapshot_table_outside_owned_scope")
        snapshot = operator_snapshot(clients["dynamodb"], table, run_id)
        path = output / "d" / (digest(run_id.encode())[:8] + ".json")
        save_json(path, snapshot)
        observed = {"cell_id": cell, "run_id": run_id, "kind": snapshot["kind"], "source_path": str(path),
            "sha256": digest(path.read_bytes()), "observed_counts": snapshot["observed_counts"], "authority_order": snapshot["authority_order"]}
        observed_models = {}
        for row in snapshot["run_records"]:
            for artifact in s3_refs(scalar_row(row)):
                record = reader.fetch(artifact, allowed=lambda key: key.endswith(".npz") and key.startswith((f"evidence/{run_id}/", f"models/candidates/{run_id}/")))
                observed_models[(record["key"], record["version_id"])] = {key: record[key] for key in ("bucket", "key", "version_id", "sha256", "size_bytes")}
        observed["model_versions_retained"] = list(observed_models.values())
        if witness_key:
            from cryptography.hazmat.primitives import serialization
            from anchor_evidence import create_witness, verify_witness
            private = serialization.load_pem_private_key(Path(witness_key).read_bytes(), password=None)
            public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            payload = {"kind": "local-operator-partial-recovery-observation", "application_campaign_id": application, "cell_id": cell,
                "run_id": run_id, "snapshot_sha256": observed["sha256"], "authority_order": snapshot["authority_order"],
                "audit_head": snapshot["audit_head"], "model_pointer": snapshot["model_pointer"], "observed_counts": snapshot["observed_counts"],
                "model_versions_retained": observed["model_versions_retained"]}
            witness = create_witness(payload, private)
            if not witness_pin or not verify_witness(witness, public, expected_public_key_sha256=witness_pin):
                raise ValueError("externally_expected_operator_key_pin_required")
            witness_path = path.with_name(path.stem + "-witness.json")
            save_json(witness_path, witness)
            observed["local_witness"] = {"path": str(witness_path), "sha256": digest(witness_path.read_bytes()),
                "public_key_sha256": witness_pin, "scope": "local-operator-observation-not-an-S3-anchor"}
        observations.append(observed)
    report = {"kind": "operator-partial-cloud-export-recovery", "schema_version": "0.1.0", "successful": False,
        "campaign_complete": False, "collection_complete": all(not case["errors"] for case in cases), "performed_read_only": True,
        "account_id": account, "region": region, "bucket": bucket, "application_campaign_id": application,
        "master_inventory": {"path": str(inventory_path), "observed_sha256": digest(inventory_bytes), "modified": False},
        "producer_source_index": index_ref, "index_sha256_origin": "expected-external" if expected_index_sha256 else "computed-from-exact-version-read",
        "producer_index_successful": index.get("successful"), "producer_source_bytes_preserved": True,
        "operator_context": operator_context, "operator_context_is_self_reported_not_an_ECS_stop_attestation": True,
        "finite_index_namespace_observations": discovered,
        "cases": cases, "source_index_cases": len(cases), "registered_cases": len(prepared),
        "not_in_source_index": [{"cell_id": cell, "run_id": runtime["persistent_run_id"], "classification": "planned-case-not-observed-in-this-producer-index"}
            for cell, runtime in prepared.items() if cell not in seen],
        "operator_observations": observations, "retained_versions": list(reader.records.values()),
        "source_files_sha256_at_collection_start": source_hashes,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(), "clinical_csvs_read": False, "final_holdout_read": False,
        "limitations": ["This is operator recovery evidence, never a synthesized completed campaign/result.",
            "Individual verified cases do not establish completion or success of the partial campaign.",
            "Not-indexed cases may be running or not started; only separately typed DDB observations describe their sampled durable state.",
            "DDB recovery snapshots record observed task/final/indeterminate counts, not producer metrics or clinical evaluation."]}
    save_json(output / "recovery_report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "campaign", "application", "output"):
        parser.add_argument("--" + name, required=True)
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--index-key")
    selector.add_argument("--latest-index", action="store_true")
    parser.add_argument("--index-version-id")
    parser.add_argument("--expected-index-sha256")
    parser.add_argument("--observe-run-id", action="append", default=[])
    parser.add_argument("--observe-unfinished", action="store_true", help="Sample every bound run not completed in this exact source index, including zero-row unindexed runs")
    parser.add_argument("--operator-context", choices=("live-partial-observation", "operator-controlled-abort-observation", "post-abort-recovery"), default="live-partial-observation")
    parser.add_argument("--operator-witness-key")
    parser.add_argument("--expected-public-key-sha256")
    args = parser.parse_args()
    inventory = json.loads(Path(args.inventory).read_text())
    import boto3
    from botocore.config import Config
    options = {"region_name": inventory["region"], "config": Config(ignore_configured_endpoint_urls=True, connect_timeout=5,
        read_timeout=20, retries={"max_attempts": 1})}
    clients = {name: boto3.client(name, **options) for name in ("sts", "s3", "dynamodb")}
    try:
        report = collect(args.inventory, args.campaign, application=args.application, index_key=args.index_key, output=args.output, clients=clients,
            index_version_id=args.index_version_id, expected_index_sha256=args.expected_index_sha256,
            observe_runs=args.observe_run_id, witness_key=args.operator_witness_key, witness_pin=args.expected_public_key_sha256,
            discover_latest=args.latest_index, observe_unfinished=args.observe_unfinished, operator_context=args.operator_context)
    except Exception as error:
        output = Path(args.output)
        output.mkdir(parents=True, exist_ok=True)
        failure = {"kind": "operator-partial-cloud-recovery-failure", "successful": False, "performed_read_only": True,
            "application_campaign_id": args.application, "source_index_key": args.index_key,
            "error": {"type": type(error).__name__, "code": getattr(error, "response", {}).get("Error", {}).get("Code", str(error)[:250])},
            "producer_result_synthesized": False, "existing_source_files_preserved": True}
        # A diagnostic must never overwrite a previous recovery observation.
        if not (output / "recovery_failure.json").exists(): save_json(output / "recovery_failure.json", failure)
        print(json.dumps(failure, sort_keys=True))
        return 1
    print(json.dumps({"successful": False, "collection_complete": report["collection_complete"], "source_cases": len(report["cases"]),
        "verified_cases": sum(case["verified"] for case in report["cases"]), "not_indexed_cases": len(report["not_in_source_index"]),
        "producer_index_sha256": report["producer_source_index"]["sha256"], "report": str(Path(args.output) / "recovery_report.json")}, sort_keys=True))
    return 0 if report["collection_complete"] else 1


if __name__ == "__main__":
    main()
