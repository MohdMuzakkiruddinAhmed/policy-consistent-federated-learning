"""Bounded synthetic S3/DynamoDB integration smoke; no clinical data or compute."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aws_preflight import check_identity, find_aws
from pcfl import aws_transactions as tx
from pcfl.contracts import ACTIONS, canonical, digest
from pcfl.oracle import evaluate_interval
from pcfl.reference import evaluate_history
from pcfl.verifier import verify_chain


class AwsError(RuntimeError):
    def __init__(self, code, reason_codes=None):
        super().__init__(code)
        self.reason_codes = reason_codes or []


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def decode_item(item):
    result = {}
    for name, value in item.items():
        kind, content = next(iter(value.items()))
        if kind == "S":
            result[name] = content
        elif kind == "N":
            result[name] = int(content)
        elif kind == "NULL":
            result[name] = None
        elif kind == "BOOL":
            result[name] = content
        else:
            raise ValueError("unexpected_smoke_attribute_type")
    return result


class CloudSmoke:
    def __init__(self, cli, account, region, bucket, table, run_id, trace_phase="execution"):
        if table != "pcfl-research-state" or bucket != f"pcfl-research-{account}-{region}":
            raise ValueError("unexpected_smoke_resources")
        self.cli, self.account, self.region = cli, account, region
        self.bucket, self.table, self.run_id = bucket, table, run_id
        self.round_id = "round-1"
        if trace_phase not in {"execution", "cleanup"}:
            raise ValueError("invalid_trace_phase")
        self.directory = ROOT / "results/aws" / run_id / trace_phase
        self.directory.mkdir(parents=True, exist_ok=True)
        self.calls, self.operations, self.objects = 0, [], []
        self.schema_hash = digest({"kind": "synthetic_vector", "dimension": 2})
        self.rule_hash = hashlib.sha256((ROOT / "src/pcfl/reference.py").read_bytes()).hexdigest()
        self.source_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                              for name in ("scripts/aws_smoke.py", "src/pcfl/aws_transactions.py", "src/pcfl/contracts.py",
                                           "src/pcfl/reference.py", "src/pcfl/oracle.py", "src/pcfl/verifier.py")}

    def call(self, args, request=None):
        self.calls += 1
        if self.calls > 200:
            raise RuntimeError("bounded_smoke_call_limit_exceeded")
        self.operations.append(args[:2])
        argv = [self.cli, *args, "--region", self.region, "--no-cli-pager", "--output", "json"]
        if request is not None:
            path = self.directory / f"request-{self.calls:03d}.json"
            write_json(path, request)
            argv += ["--cli-input-json", "file://" + path.as_posix()]
        try:
            result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=30)
        except subprocess.TimeoutExpired:
            raise AwsError("RequestTimeout") from None
        if result.returncode:
            match = re.search(r"An error occurred \(([A-Za-z0-9_.-]+)\)", result.stderr)
            code = match.group(1) if match else "AwsCommandFailed"
            allowed = {"None", "ConditionalCheckFailed", "ItemCollectionSizeLimitExceeded", "TransactionConflict",
                       "ProvisionedThroughputExceeded", "ThrottlingError", "ValidationError"}
            reason_codes = []
            for group in re.findall(r"\[([A-Za-z ,]+)\]", result.stderr):
                parts = [part.strip() for part in group.split(",")]
                if parts and all(part in allowed for part in parts):
                    reason_codes = parts
            write_json(self.directory / f"response-{self.calls:03d}.json",
                       {"error_code": code, "cancellation_reason_codes": reason_codes})
            raise AwsError(code, reason_codes)
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        write_json(self.directory / f"response-{self.calls:03d}.json", data)
        return data

    def item(self, pk, sk):
        request = {"TableName": self.table, "ConsistentRead": True,
                   "Key": {"PK": {"S": pk}, "SK": {"S": sk}}}
        return decode_item(self.call(["dynamodb", "get-item"], request).get("Item", {}))

    def query(self, pk):
        request = {"TableName": self.table, "ConsistentRead": True,
                   "KeyConditionExpression": "#pk = :pk",
                   "ExpressionAttributeNames": {"#pk": "PK"},
                   "ExpressionAttributeValues": {":pk": {"S": pk}}}
        items = []
        while True:
            response = self.call(["dynamodb", "query", "--no-paginate"], request)
            items.extend(decode_item(item) for item in response.get("Items", []))
            if len(items) > 200:
                raise ValueError("unexpected_smoke_partition_size")
            if not response.get("LastEvaluatedKey"):
                return items
            request["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    def order(self):
        return self.item("AUTHORITY", "SEQUENCE")["order"]

    def transact(self, request, txn_id, run_scope=True):
        try:
            response = self.call(["dynamodb", "transact-write-items"], request)
        except AwsError:
            recovered = self.call(["dynamodb", "get-item"], tx.recovery_get_request(
                self.table, txn_id, run_id=self.run_id if run_scope else None)).get("Item")
            if not recovered or recovered.get("request_digest", {}).get("S") != tx.expected_outcome_digest(request):
                raise
            response = {"recovered_durable_outcome": True}
        return response

    def snapshot(self):
        for _ in range(3):
            before = self.order()
            histories, epochs, current = {}, {}, {}
            for org in ("org_01", "org_02"):
                records = self.query(f"POLICY#{org}")
                current[org] = next(item for item in records if item["SK"] == "CURRENT")
                events = [json.loads(item["event_json"]) for item in records if item["SK"].startswith("EVENT#")]
                events.sort(key=lambda event: event["order"])
                if (not events or events[-1]["epoch"] != current[org]["epoch"]
                        or digest(events[-1]) != current[org]["policy_hash"]):
                    raise ValueError("incomplete_authoritative_history")
                histories[org], epochs[org] = events, current[org]["epoch"]
            records = self.query(f"RUN#{self.run_id}")
            if before != self.order():
                continue
            items = {item["SK"]: item for item in records}
            pending = [item for item in records if item["SK"].startswith("UPDATE#") and item["status"] == "pending"]
            if items[f"ROUND#{self.round_id}"]["pending_count"] != len(pending):
                raise ValueError("pending_membership_incomplete")
            return {"order": before, "histories": histories, "epochs": epochs, "current": current,
                    "items": items, "pending": pending, "records": records}
        raise RuntimeError("coherent_snapshot_retry_exhausted")

    def stage(self, weights):
        body = canonical(weights)
        if len(body) > 2048:
            raise ValueError("synthetic_model_size_limit")
        sha = hashlib.sha256(body).hexdigest()
        key = f"models/candidates/{self.run_id}/{sha}.json"
        path = self.directory / f"model-{sha}.json"
        path.write_bytes(body)
        response = self.call(["s3api", "put-object", "--bucket", self.bucket, "--key", key,
                              "--expected-bucket-owner", self.account, "--body", str(path),
                              "--server-side-encryption", "AES256", "--checksum-algorithm", "SHA256"])
        version = response.get("VersionId")
        if not version or version == "null":
            raise ValueError("immutable_s3_version_required")
        staged = {"bucket": self.bucket, "key": key, "version_id": version,
                  "sha256": sha, "size_bytes": len(body)}
        self.objects.append(staged)
        head = self.call(["s3api", "head-object", "--bucket", self.bucket, "--key", key,
                          "--version-id", version, "--expected-bucket-owner", self.account])
        fetched = self.directory / f"fetched-{sha}.json"
        self.call(["s3api", "get-object", "--bucket", self.bucket, "--key", key,
                   "--version-id", version, "--expected-bucket-owner", self.account, str(fetched)])
        if (head["ContentLength"] != len(body) or head.get("VersionId") != version
                or fetched.read_bytes() != body):
            raise ValueError("staged_object_confirmation_failed")
        return staged

    def candidate(self, snapshot, weights_by_update):
        updates, epochs, histories = [], {}, {}
        all_events = [event for history in snapshot["histories"].values() for event in history]
        for pending in snapshot["pending"]:
            weights = weights_by_update[pending["update_id"]]
            if (not isinstance(weights, (list, tuple)) or len(weights) != 2
                    or any(type(value) not in (int, float) or not math.isfinite(value) for value in weights)
                    or digest(weights) != pending["weights_digest"]):
                raise ValueError("update_payload_digest_shape_or_finiteness_mismatch")
            query = {"org_id": pending["org_id"], "purpose": pending["purpose"],
                     "start_order": pending["start_order"], "commit_order": snapshot["order"],
                     "actions": list(ACTIONS)}
            if not evaluate_history(all_events, query)["valid"]:
                raise ValueError("finalize_invalid_updates_before_preparing")
            updates.append({key: pending[key] for key in ("update_id", "task_id", "org_id", "purpose",
                                                          "start_order", "sample_count", "weights_digest")})
            epochs[pending["org_id"]] = snapshot["epochs"][pending["org_id"]]
            histories[pending["org_id"]] = digest(snapshot["histories"][pending["org_id"]])
        total = sum(update["sample_count"] for update in updates)
        weights = [sum(update["sample_count"] * weights_by_update[update["update_id"]][i] for update in updates) / total
                   for i in range(2)]
        staged = self.stage(weights)
        context = {"snapshot_order": snapshot["order"], "parent_manifest_id": snapshot["items"]["POINTER"].get("manifest_id"),
                   "round_generation": snapshot["items"][f"ROUND#{self.round_id}"]["generation"],
                   "policy_epochs": epochs, "history_digests": histories, "model_schema_hash": self.schema_hash,
                   "rule_bundle_hash": self.rule_hash, "model_digest": staged["sha256"], "s3": staged,
                   "object_confirmation": {key: staged[key] for key in ("version_id", "sha256", "size_bytes")},
                   "updates": updates}
        return {**context, "candidate_id": tx.candidate_digest(context)}

    def mutate(self, org, kind, rules, suffix):
        current = self.item(f"POLICY#{org}", "CURRENT")
        order, txn_id = self.order(), f"{self.run_id}-{suffix}"
        event = {"event_id": txn_id, "org_id": org, "order": order + 1,
                 "epoch": current.get("epoch", 0) + 1, "kind": kind, "rules": rules}
        request = tx.build_policy_mutation(self.table, expected_order=order,
                    expected_epoch=current.get("epoch", 0), event=event, txn_id=txn_id)
        self.transact(request, txn_id, run_scope=False)

    def execute(self):
        if not self.item("AUTHORITY", "SEQUENCE"):
            txn_id = f"{self.run_id}-authority"
            self.transact(tx.build_initialize_authority(self.table, txn_id=txn_id), txn_id, False)
        rules = [{"purpose": "readmission", "action": action, "effect": "allow"} for action in ACTIONS]
        for number in (1, 2):
            self.mutate(f"org_{number:02d}", "GRANT", rules, f"grant-{number}")
        txn_id = f"{self.run_id}-initialize"
        self.transact(tx.build_initialize_run(self.table, run_id=self.run_id, round_id=self.round_id,
                      expected_order=self.order(), txn_id=txn_id), txn_id)
        weights_by_update = {"update-1": [1.0, 3.0], "update-2": [5.0, 7.0]}
        for number in (1, 2):
            org, uid = f"org_{number:02d}", f"update-{number}"
            snapshot = self.snapshot()
            task = {"task_id": f"task-{number}", "org_id": org, "purpose": "readmission",
                    "start_order": snapshot["order"] + 1, "policy_epoch": snapshot["epochs"][org],
                    "policy_hash": snapshot["current"][org]["policy_hash"],
                    "model_schema_hash": self.schema_hash, "nonce_digest": digest(f"synthetic-{self.run_id}-{number}")}
            txn_id = f"{self.run_id}-task-{number}"
            self.transact(tx.build_task_authorization(self.table, run_id=self.run_id, round_id=self.round_id,
                          expected_order=snapshot["order"], task=task, txn_id=txn_id), txn_id)
            snapshot = self.snapshot()
            update = {"update_id": uid, "task_id": task["task_id"], "org_id": org,
                      "purpose": task["purpose"], "start_order": task["start_order"],
                      "sample_count": number * 10, "weights_digest": digest(weights_by_update[uid]),
                      "model_schema_hash": self.schema_hash}
            txn_id = f"{self.run_id}-receipt-{number}"
            self.transact(tx.build_register_update(self.table, run_id=self.run_id, round_id=self.round_id,
                          expected_order=snapshot["order"],
                          expected_round_generation=snapshot["items"][f"ROUND#{self.round_id}"]["generation"],
                          update=update, authenticated_org=org, observed_policy_epoch=snapshot["epochs"][org],
                          history_digest=digest(snapshot["histories"][org]), txn_id=txn_id), txn_id)
        snapshot = self.snapshot()
        stale = self.candidate(snapshot, weights_by_update)
        self.mutate("org_01", "REVOKE", [], "mid-round-revoke")
        stale_txn = f"{self.run_id}-stale-publish"
        stale_request = tx.build_publication(self.table, run_id=self.run_id, round_id=self.round_id,
                          txn_id=stale_txn, candidate=stale, expected_audit_count=0, expected_audit_head="0" * 64)
        blocked = False
        cancellation_codes = []
        try:
            self.transact(stale_request, stale_txn)
        except AwsError as error:
            if str(error) != "TransactionCanceledException":
                raise
            cancellation_codes = error.reason_codes
            if cancellation_codes and cancellation_codes[:2] != ["ConditionalCheckFailed", "ConditionalCheckFailed"]:
                raise AssertionError("unexpected_stale_transaction_cancellation_reason")
            blocked = True
        if not blocked or "manifest_id" in self.item(f"RUN#{self.run_id}", "POINTER"):
            raise AssertionError("stale_candidate_was_published")
        snapshot = self.snapshot()
        invalid = next(item for item in snapshot["pending"] if item["org_id"] == "org_01")
        query = {"org_id": invalid["org_id"], "purpose": invalid["purpose"], "start_order": invalid["start_order"],
                 "commit_order": snapshot["order"], "actions": list(ACTIONS)}
        all_events = [event for history in snapshot["histories"].values() for event in history]
        if evaluate_history(all_events, query)["valid"]:
            raise AssertionError("expected_invalid_lifecycle")
        rejection_id = f"{self.run_id}-reject"
        update = {key: invalid[key] for key in ("update_id", "task_id", "org_id", "purpose", "start_order",
                                                "sample_count", "weights_digest", "model_schema_hash")}
        self.transact(tx.build_rejection(self.table, run_id=self.run_id, round_id=self.round_id,
                      expected_order=snapshot["order"], update=update, reason="authorization_interrupted",
                      observed_policy_epoch=snapshot["epochs"]["org_01"],
                      history_digest=digest(snapshot["histories"]["org_01"]), rule_bundle_hash=self.rule_hash,
                      expected_audit_count=0, expected_audit_head="0" * 64, txn_id=rejection_id), rejection_id)
        snapshot = self.snapshot()
        fresh = self.candidate(snapshot, weights_by_update)
        publish_id = f"{self.run_id}-publish"
        head = snapshot["items"]["AUDIT_HEAD"]
        request = tx.build_publication(self.table, run_id=self.run_id, round_id=self.round_id,
                       txn_id=publish_id, candidate=fresh, expected_audit_count=head["count"], expected_audit_head=head["head"])
        self.transact(request, publish_id)
        self.transact(request, publish_id)  # Exact retry must not add acceptance or audit records.
        self.mutate("org_02", "REVOKE", [], "after-publication-revoke")
        snapshot = self.snapshot()
        records, items = snapshot["records"], snapshot["items"]
        manifest = json.loads(items[f"MANIFEST#{fresh['candidate_id']}"]["manifest_json"])
        audit = [json.loads(item["event_json"]) for item in records if item["SK"].startswith("AUDIT#")]
        audit.sort(key=lambda event: event["sequence"])
        anchor = {key: items["AUDIT_HEAD"][key] for key in ("count", "head")}
        if not verify_chain(audit, anchor) or len(audit) != 2:
            raise AssertionError("audit_or_idempotency_failed")
        events = [event for history in snapshot["histories"].values() for event in history]
        oracle_checks = []
        for item in records:
            if not item["SK"].startswith("UPDATE#"):
                continue
            query = {"org_id": item["org_id"], "purpose": item["purpose"], "start_order": item["start_order"],
                     "commit_order": manifest["commit_order"], "actions": list(ACTIONS)}
            decision = evaluate_interval(events, query)
            included = item["update_id"] in [u["update_id"] for u in fresh["updates"]]
            if included and not decision["valid"]:
                raise AssertionError("oracle_invalid_incorporation")
            oracle_checks.append({"update_id": item["update_id"], "included": included, "oracle": decision})
        if items["POINTER"]["manifest_id"] != fresh["candidate_id"] or items[f"ROUND#{self.round_id}"]["pending_count"]:
            raise AssertionError("pointer_or_pending_finalization_failed")
        return {"schema_version": "0.1.0", "kind": "aws_synthetic_protocol_smoke", "successful": True,
                "account_id": self.account, "region": self.region, "run_id": self.run_id,
                "source_files_sha256": self.source_hashes,
                "finished_at_utc": datetime.now(timezone.utc).isoformat(), "aws_cli_calls": self.calls,
                "checks": {"stale_publication_blocked": blocked, "recomputed_membership": [u["org_id"] for u in fresh["updates"]],
                           "independent_oracle_no_invalid_incorporation": True, "audit_chain_verified": True,
                           "idempotent_publication": True, "post_publication_revocation_preserved_model": True,
                           "no_pending_updates_after_round_closure": True, "s3_version_and_bytes_verified": True},
                "scope": {"clients": "two synthetic records, not distributed FL clients", "opa_used": False,
                          "clinical_data_uploaded": False, "hypothesis_results": False,
                          "external_anchor": "exported local evidence; not a hardened production anchor"},
                "objects": self.objects, "oracle_checks": oracle_checks, "manifest": manifest,
                "stale_cancellation_reason_codes": cancellation_codes,
                "audit": audit, "anchor": anchor, "policy_events": events, "table_records": records,
                "estimated_cost_allowance_usd": 1, "measured_bill_usd": None, "objects_removed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "cleanup-objects"))
    args = parser.parse_args()
    config = json.loads((ROOT / "configs/project.json").read_text(encoding="utf-8"))["aws"]
    if not config["deployment_enabled"] or config["approved_budget_usd"] < 1:
        raise ValueError("smoke_scope_and_budget_not_enabled")
    cli = find_aws()
    check_identity(cli, config["account_id"], config["region"])
    outputs = json.loads((ROOT / "results/aws/foundation/outputs.json").read_text(encoding="utf-8"))
    run_id = "cloud-smoke-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
    report_path = ROOT / "results/aws/smoke.json"
    if args.action == "cleanup-objects":
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if not report["successful"] or report["account_id"] != config["account_id"]:
            raise ValueError("verified_matching_evidence_required_before_cleanup")
        run_id = report["run_id"]
    cloud = CloudSmoke(cli, config["account_id"], config["region"], outputs["bucket_name"]["value"],
                       outputs["state_table_name"]["value"], run_id,
                       trace_phase="execution" if args.action == "run" else "cleanup")
    if args.action == "run":
        report = cloud.execute()
        write_json(report_path, report)
        write_json(cloud.directory / "verified-evidence.json", report)
        print(json.dumps({"successful": True, "run_id": run_id, "checks": report["checks"],
                          "aws_cli_calls": report["aws_cli_calls"]}, indent=2))
    else:
        # Retire the live pointer before removing any of its model bytes. Archived
        # manifests and exported model files remain evidence of prior publication.
        pointer = cloud.item(f"RUN#{run_id}", "POINTER")
        if pointer.get("manifest_id"):
            order = cloud.order()
            retirement_id = run_id + "-retire"
            retirement = {"TransactItems": [
                {"Update": {"TableName": cloud.table,
                    "Key": {"PK": {"S": "AUTHORITY"}, "SK": {"S": "SEQUENCE"}},
                    "UpdateExpression": "SET #order = :next", "ConditionExpression": "#order = :old",
                    "ExpressionAttributeNames": {"#order": "order"},
                    "ExpressionAttributeValues": {":next": {"N": str(order + 1)}, ":old": {"N": str(order)}}}},
                {"Update": {"TableName": cloud.table,
                    "Key": {"PK": {"S": f"RUN#{run_id}"}, "SK": {"S": "POINTER"}},
                    "UpdateExpression": "SET #status = :retired, #retired_order = :order REMOVE #manifest",
                    "ConditionExpression": "#manifest = :expected",
                    "ExpressionAttributeNames": {"#status": "status", "#retired_order": "retired_order", "#manifest": "manifest_id"},
                    "ExpressionAttributeValues": {":retired": {"S": "RETIRED"}, ":order": {"N": str(order + 1)},
                                                  ":expected": {"S": report["manifest"]["manifest_id"]}}}}
            ], "ClientRequestToken": digest(retirement_id)[:36]}
            cloud.call(["dynamodb", "transact-write-items"], retirement)
            pointer = cloud.item(f"RUN#{run_id}", "POINTER")
        if pointer.get("status") != "RETIRED" or "manifest_id" in pointer:
            raise ValueError("live_smoke_pointer_must_be_retired_before_object_cleanup")
        report["retired_before_object_removal"] = True
        report["retired_pointer"] = pointer
        write_json(report_path, report)
        for obj in report["objects"]:
            if obj["bucket"] != cloud.bucket or not obj["key"].startswith(f"models/candidates/{run_id}/"):
                raise ValueError("refusing_cleanup_outside_recorded_synthetic_prefix")
            cloud.call(["s3api", "delete-object", "--bucket", obj["bucket"], "--key", obj["key"],
                        "--version-id", obj["version_id"], "--expected-bucket-owner", cloud.account])
        report["objects_removed"] = True
        report["objects_removed_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(report_path, report)
        print("Removed only the recorded synthetic model object versions; local evidence retained.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        raise SystemExit(1)
