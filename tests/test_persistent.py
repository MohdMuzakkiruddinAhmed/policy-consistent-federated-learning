"""Boundary and recovery tests for the persistent lifecycle adapter.

The live DynamoDB/S3/OPA integration is exercised by the pilot harness. These
tests inject responses at failure boundaries that are difficult to force in a
service, including a committed transaction whose response is lost.
"""

from copy import deepcopy
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.request import urlopen

import numpy as np

from pcfl import aws_transactions as tx
from pcfl.contracts import ACTIONS, ORGANIZATIONS, digest
from pcfl.persistent import (
    PersistentAuthority, PersistentConflict, PersistentUnavailable,
    _decode, _fields, _repack, arrays_digest,
)
from pcfl.verifier import verify_chain


RULE_HASH = digest("pinned-rego")
SCHEMA_HASH = digest("test-schema")
TABLE = "pcfl-persistent-tests"
TEMPLATE = [np.array([0, 0], dtype=np.float32)]


class VersionedS3:
    def __init__(self):
        self.meta = SimpleNamespace(endpoint_url="http://127.0.0.1:9100")
        self.objects = {}
        self.calls = []
        self.enabled = True
        self.tamper = False

    def get_bucket_versioning(self, **kwargs):
        return {"Status": "Enabled" if self.enabled else "Suspended"}

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        version = f"version-{len(self.objects) + 1}"
        self.objects[(kwargs["Key"], version)] = bytes(kwargs["Body"])
        return {"VersionId": version}

    def head_object(self, **kwargs):
        body = self.objects[(kwargs["Key"], kwargs["VersionId"])]
        return {"ContentLength": len(body), "VersionId": kwargs["VersionId"]}

    def get_object(self, **kwargs):
        body = self.objects[(kwargs["Key"], kwargs["VersionId"])]
        if self.tamper:
            body = body[:-1] + bytes([body[-1] ^ 1])
        return {"Body": io.BytesIO(body), "VersionId": kwargs["VersionId"]}


def make_authority(ddb=None, s3=None, **options):
    evaluator = options.pop("policy_evaluator", lambda events, query: {
        "valid": True, "reason": "allowed", "rule_hash": RULE_HASH,
        "decision_id": "opa-decision-1", "query": query})
    return PersistentAuthority(ddb or Mock(), s3 or VersionedS3(), table_name=TABLE,
        bucket="pcfl-private-test", run_id="test-run", template=TEMPLATE,
        model_schema_hash=SCHEMA_HASH, rule_hash=RULE_HASH,
        policy_evaluator=evaluator, **options)


def policy_records():
    result = {}
    for number, org in enumerate(ORGANIZATIONS, 1):
        event = {"event_id": f"grant-{org}", "org_id": org, "order": number,
                 "epoch": 1, "kind": "GRANT", "rules": [
                     {"purpose": "readmission", "action": action, "effect": "allow"} for action in ACTIONS]}
        result[f"POLICY#{org}"] = [
            {"PK": f"POLICY#{org}", "SK": "CURRENT", "epoch": 1, "policy_hash": digest(event)},
            {"PK": f"POLICY#{org}", "SK": f"EVENT#{number:020d}", "policy_hash": digest(event), "event_json": json.dumps(event)}]
    result["RUN#test-run"] = []
    return result


def candidate():
    updates = [{"update_id": f"update-{i}", "task_id": f"task-{i}", "org_id": org,
                "purpose": "readmission", "start_order": 10 + i, "sample_count": i,
                "weights_digest": digest([i])} for i, org in enumerate(ORGANIZATIONS[:2], 1)]
    byte_hash = digest("model-bytes")
    content = {"snapshot_order": 20, "parent_manifest_id": None, "round_generation": 2,
        "policy_epochs": {update["org_id"]: 1 for update in updates},
        "history_digests": {update["org_id"]: digest(update["org_id"]) for update in updates},
        "model_schema_hash": SCHEMA_HASH, "rule_bundle_hash": RULE_HASH, "model_digest": byte_hash,
        "s3": {"bucket": "pcfl-private-test", "key": "models/candidates/test-run/model.npz",
               "version_id": "v1", "sha256": byte_hash, "size_bytes": 256},
        "object_confirmation": {"version_id": "v1", "sha256": byte_hash, "size_bytes": 256}, "updates": updates}
    return {**content, "candidate_id": tx.candidate_digest(content)}


class PersistentBoundaryTests(unittest.TestCase):
    def test_versioning_and_explicit_local_encryption_boundary(self):
        s3 = VersionedS3()
        s3.enabled = False
        with self.assertRaisesRegex(PersistentUnavailable, "versioned_model_bucket_required"):
            make_authority(s3=s3)
        with self.assertRaisesRegex(ValueError, "explicit_loopback"):
            make_authority(s3_encryption=None)
        make_authority(local_emulation=True, s3_encryption=None)
        s3.meta.endpoint_url = "https://s3.us-east-1.amazonaws.com"
        with self.assertRaisesRegex(ValueError, "explicit_loopback"):
            make_authority(s3=s3, local_emulation=True, s3_encryption=None)

    def test_coordinator_policy_mutation_requires_separate_authority(self):
        ddb = Mock()
        authority = make_authority(ddb=ddb)
        with self.assertRaisesRegex(PersistentUnavailable, "separate_authority"):
            authority.mutate(ORGANIZATIONS[0], "REVOKE")
        ddb.transact_write_items.assert_not_called()
        actor = Mock(return_value={"event_id": "separate-authority-event"})
        authority = make_authority(policy_mutator=actor)
        self.assertEqual(authority.mutate(ORGANIZATIONS[0], "REVOKE"), actor.return_value)
        actor.assert_called_once_with(ORGANIZATIONS[0], "REVOKE")

    def test_immutable_object_version_is_read_and_both_digests_verified(self):
        s3 = VersionedS3()
        authority = make_authority(s3=s3, expected_bucket_owner="980322232249")
        arrays = [np.array([2, 5], dtype=np.float32)]
        artifact = authority._stage(arrays, key="models/candidates/test-run/candidate.npz")
        self.assertEqual(artifact["parameters_digest"], arrays_digest(arrays))
        self.assertNotEqual(artifact["sha256"], artifact["parameters_digest"])
        self.assertEqual(s3.calls[0]["ServerSideEncryption"], "AES256")
        self.assertEqual(s3.calls[0]["ExpectedBucketOwner"], "980322232249")
        np.testing.assert_array_equal(authority._load(artifact)[0], arrays[0])
        s3.tamper = True
        with self.assertRaisesRegex(PersistentUnavailable, "bytes_or_digest"):
            authority._load(artifact)

    def test_object_reference_cannot_escape_run_or_use_null_version(self):
        authority = make_authority()
        artifact = authority._stage(TEMPLATE, key="models/candidates/test-run/candidate.npz")
        for change in ({"key": "models/candidates/other-run/candidate.npz"}, {"bucket": "another-bucket"},
                       {"version_id": "null"}, {"parameters_digest": "0" * 64}):
            with self.subTest(change=change), self.assertRaises(PersistentUnavailable):
                authority._load({**artifact, **change})

    def test_opa_decision_must_be_pinned_and_bound_to_full_interval(self):
        authority = make_authority()
        snapshot = {"events": [{"opaque": "full-history"}]}
        result = authority._policy(snapshot, ORGANIZATIONS[0], 10, 30)
        self.assertEqual(result["query"]["start_order"], 10)
        self.assertEqual(result["query"]["commit_order"], 30)
        self.assertEqual(result["query"]["actions"], list(ACTIONS))
        for output in ({"valid": True, "rule_hash": "0" * 64, "decision_id": "id"},
                       {"valid": True, "rule_hash": RULE_HASH},
                       {"valid": "true", "rule_hash": RULE_HASH, "decision_id": "id"},
                       {"valid": True, "rule_hash": RULE_HASH, "decision_id": "id", "query": {}}):
            authority.evaluate = lambda events, query, value=output: value
            with self.subTest(output=output), self.assertRaises(PersistentUnavailable):
                authority._policy(snapshot, ORGANIZATIONS[0], 10, 30)

    def test_paginated_histories_always_use_strong_reads(self):
        ddb = Mock()
        last = tx._key("POLICY#org_01", "EVENT#00000000000000000001")
        ddb.query.side_effect = [{"Items": [_fields({"PK": "p", "SK": "one"})], "LastEvaluatedKey": last},
                                 {"Items": [_fields({"PK": "p", "SK": "two"})]}]
        authority = make_authority(ddb=ddb)
        self.assertEqual([item["SK"] for item in authority.query("POLICY#org_01")], ["one", "two"])
        calls = [call.kwargs for call in ddb.query.call_args_list]
        self.assertTrue(all(call["ConsistentRead"] for call in calls))
        self.assertEqual(calls[1]["ExclusiveStartKey"], last)

    def test_snapshot_retries_entire_history_when_global_fence_moves(self):
        authority = make_authority()
        records = policy_records()
        with patch.object(authority, "item", side_effect=[{"order": 8}, {"order": 9}, {"order": 9}, {"order": 9}]), \
             patch.object(authority, "query", side_effect=lambda pk: deepcopy(records[pk])) as query:
            snapshot = authority.snapshot()
        self.assertEqual(snapshot["order"], 9)
        self.assertEqual(len(snapshot["events"]), 8)
        self.assertEqual(query.call_count, 18)

    def test_snapshot_rejects_history_gap_tail_tamper_and_missing_pending_member(self):
        original = policy_records()
        variations = []
        changed = deepcopy(original)
        event = json.loads(changed["POLICY#org_01"][1]["event_json"])
        event["epoch"] = 2
        changed["POLICY#org_01"][1].update(event_json=json.dumps(event), policy_hash=digest(event))
        variations.append(changed)
        changed = deepcopy(original)
        changed["POLICY#org_01"][0]["policy_hash"] = "0" * 64
        variations.append(changed)
        changed = deepcopy(original)
        changed["RUN#test-run"] = [{"PK": "RUN#test-run", "SK": "ROUND#round-1", "pending_count": 1}]
        variations.append(changed)
        for records in variations:
            authority = make_authority()
            with self.subTest(records=records), patch.object(authority, "item", return_value={"order": 8}), \
                 patch.object(authority, "query", side_effect=lambda pk: deepcopy(records[pk])), \
                 self.assertRaises(PersistentUnavailable):
                authority.snapshot()

    def test_acknowledgment_binding_rejects_node_nonce_and_whole_task_changes_before_write(self):
        authority = make_authority()
        task = {"task_id": "task-1", "node_id": 123, "round_id": "round-1", "start_order": None,
                "nonce": "unguessable-client-nonce", "model_schema_hash": SCHEMA_HASH}
        stored = {key: value for key, value in task.items() if key != "nonce"}
        snapshot = {"items": {"ISSUE#task-1": {"task_json": json.dumps(stored), "nonce_digest": digest(task["nonce"])}}}
        with patch.object(authority, "snapshot", return_value=snapshot):
            for node, echoed in ((999, task), (123, {**task, "nonce": "changed"}),
                                 (123, {**task, "round_id": "other-round"}), (123, {**task, "extra": "unbound"})):
                with self.subTest(node=node, echoed=echoed), self.assertRaisesRegex(ValueError, "mismatch"):
                    authority.acknowledge("task-1", node, echoed)
        authority.ddb.transact_write_items.assert_not_called()

    def test_boolean_source_identity_cannot_equal_registered_numeric_node(self):
        authority = make_authority()
        task = {"task_id": "task-1", "node_id": 1, "nonce": "client-nonce"}
        snapshot = {"items": {"ISSUE#task-1": {"task_json": json.dumps({"task_id": "task-1", "node_id": 1}),
            "nonce_digest": digest(task["nonce"])}}}
        with patch.object(authority, "snapshot", return_value=snapshot), self.assertRaisesRegex(ValueError, "mismatch"):
            authority.acknowledge("task-1", True, task)

    def test_lost_response_recovers_exact_committed_outcome(self):
        request = _repack(tx.build_initialize_run(TABLE, run_id="test-run", round_id="round-1", expected_order=8, txn_id="initialize-1"))
        outcome = next(action["Put"]["Item"] for action in request["TransactItems"]
                       if "Put" in action and action["Put"]["Item"]["SK"] == {"S": "TXN#initialize-1"})
        ddb = Mock()
        ddb.transact_write_items.side_effect = TimeoutError("response lost after commit")
        ddb.get_item.return_value = {"Item": outcome}
        authority = make_authority(ddb=ddb)
        self.assertEqual(authority._transact(request, "initialize-1"), json.loads(outcome["result_json"]["S"]))
        self.assertTrue(ddb.get_item.call_args.kwargs["ConsistentRead"])
        rebound = deepcopy(outcome)
        rebound["request_digest"] = {"S": "0" * 64}
        ddb.get_item.return_value = {"Item": rebound}
        with self.assertRaisesRegex(PersistentUnavailable, "rebound"):
            authority._transact(request, "initialize-1")

    def test_unresolved_outcome_fails_closed_and_conditional_failure_recomputes(self):
        request = tx.build_initialize_run(TABLE, run_id="test-run", round_id="round-1", expected_order=8, txn_id="initialize-1")
        ddb = Mock()
        ddb.transact_write_items.side_effect = TimeoutError("network failure")
        ddb.get_item.return_value = {}
        authority = make_authority(ddb=ddb)
        with self.assertRaisesRegex(PersistentUnavailable, "not_confirmed"):
            authority._transact(request, "initialize-1")
        conflict = RuntimeError("conditional failure")
        conflict.response = {"Error": {"Code": "TransactionCanceledException"}}
        ddb.transact_write_items.side_effect = conflict
        with self.assertRaises(PersistentConflict):
            authority._transact(request, "initialize-1")
        self.assertEqual(authority.conflicts, 1)
        ddb.get_item.side_effect = TimeoutError("recovery also unavailable")
        with self.assertRaisesRegex(PersistentUnavailable, "indeterminate"):
            authority._transact(request, "initialize-1")

    def test_opa_evidence_is_atomic_with_all_decisions_and_rehashed_audit(self):
        authority = make_authority()
        context = candidate()
        request = tx.build_publication(TABLE, run_id="test-run", round_id="round-1", txn_id="publish-1",
            candidate=context, expected_audit_count=0, expected_audit_head="0" * 64)
        evaluations = {update["update_id"]: {"decision_id": f"opa-{update['update_id']}", "query": {"commit_order": 21}}
                       for update in context["updates"]}
        augmented = authority._policy_evidence(request, evaluations)
        self.assertNotEqual(tx.expected_outcome_digest(request), tx.expected_outcome_digest(augmented))
        audits = sorted((json.loads(action["Put"]["Item"]["event_json"]["S"]) for action in augmented["TransactItems"]
                         if "Put" in action and action["Put"]["Item"].get("record_type") == {"S": "audit_event"}), key=lambda event: event["sequence"])
        self.assertTrue(verify_chain(audits, {"count": 2, "head": audits[-1]["event_hash"]}))
        self.assertTrue(all(event["payload"]["policy_decision_id"].startswith("opa-") for event in audits))
        outcome = next(_decode(action["Put"]["Item"]) for action in augmented["TransactItems"]
                       if "Put" in action and action["Put"]["Item"].get("record_type") == {"S": "transaction_outcome"})
        self.assertEqual(json.loads(outcome["result_json"])["audit_head"], audits[-1]["event_hash"])
        tx.validate_transaction_request(augmented)

    def test_restart_loads_only_model_behind_published_pointer(self):
        s3 = VersionedS3()
        authority = make_authority(s3=s3)
        arrays = [np.array([7, 9], dtype=np.float32)]
        artifact = authority._stage(arrays, key="models/candidates/test-run/published.npz")
        context = candidate()
        context.update(model_digest=artifact["sha256"], s3={key: artifact[key] for key in ("bucket", "key", "version_id", "sha256", "size_bytes")},
            object_confirmation={key: artifact[key] for key in ("version_id", "sha256", "size_bytes")})
        context["candidate_id"] = tx.candidate_digest({key: value for key, value in context.items() if key != "candidate_id"})
        raw = {"manifest_id": context["candidate_id"], "candidate": context, "parameters_digest": arrays_digest(arrays),
            "artifact": artifact, "run_id": "test-run", "round_id": "round-1", "commit_order": 21, "commit_txn_id": "publish-1"}
        records = {"POINTER": {"manifest_id": context["candidate_id"]},
                   f"MANIFEST#{context['candidate_id']}": {"manifest_json": json.dumps(raw)}}
        # Construct a new instance: no producer memory or staged export is used.
        restarted = make_authority(s3=s3)
        with patch.object(restarted, "item", side_effect=lambda pk, sk: records[sk]):
            np.testing.assert_array_equal(restarted.parameters()[0], arrays[0])
        raw["artifact"] = {**artifact, "sha256": "0" * 64}
        records[f"MANIFEST#{context['candidate_id']}"]["manifest_json"] = json.dumps(raw)
        with patch.object(restarted, "item", side_effect=lambda pk, sk: records[sk]), \
             self.assertRaisesRegex(PersistentUnavailable, "manifest_binding"):
            restarted.parameters()

    def test_failure_conflict_reloads_instead_of_reusing_stale_attempt(self):
        authority = make_authority()
        with patch.object(authority, "_fail_once", side_effect=[PersistentConflict(), "error"]) as finalize:
            self.assertEqual(authority.fail("task-1", "client disconnected"), "error")
        self.assertEqual(finalize.call_count, 2)


@unittest.skipUnless(os.environ.get("PCFL_LOCAL_INTEGRATION") == "1", "explicit localhost service integration only")
class PersistentLiveServicesTests(unittest.TestCase):
    def test_actual_sdk_and_opa_recover_restart_reject_gap_and_recompute_after_race(self):
        from pcfl.governance_service import PolicyWriter
        from pcfl.opa import OpaClient, OpaUnavailable
        from botocore.exceptions import BotoCoreError, ClientError
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from integration_services import LocalIntegrationServices
        with tempfile.TemporaryDirectory(prefix="pcfl-persistent-live-") as directory, \
             LocalIntegrationServices(directory) as services:
            operator = PolicyWriter(services.ddb, services.table)
            operator.initialize()
            for org in ORGANIZATIONS:
                operator.mutate(org, "GRANT")
            opa = OpaClient(services.opa_endpoint, allow_loopback_http=True)
            def connect():
                return PersistentAuthority(services.ddb, services.s3, table_name=services.table,
                    bucket=services.bucket, run_id="live-persistent", template=TEMPLATE,
                    model_schema_hash=SCHEMA_HASH, policy_evaluator=opa.evaluate, rule_hash=opa.rule_hash,
                    policy_mutator=operator.mutate, local_emulation=True)
            authority = connect()
            tasks, updates = {}, {}
            for index, org in enumerate(ORGANIZATIONS[:3], 1):
                issued = authority.issue(org, index, "round-1")
                # Restart between issuance and acknowledgment; the returned
                # client task authenticates against durable issue bindings.
                authority = connect()
                task = authority.acknowledge(issued["task_id"], index, issued)
                arrays = [np.full_like(TEMPLATE[0], index)]
                metadata = {**task, "sample_count": index * 2, "weights_digest": arrays_digest(arrays)}
                if index == 3:
                    authority.mutate(org, "REVOKE")
                    authority.mutate(org, "GRANT")
                self.assertEqual(authority.receive(task["task_id"], index, metadata, arrays), "rejected" if index == 3 else "pending")
                tasks[index], updates[index] = task, (metadata, arrays)
            def race(attempt):
                if attempt == 0:
                    authority.mutate(ORGANIZATIONS[1], "REVOKE")
                    authority.mutate(ORGANIZATIONS[1], "GRANT")
            manifest = authority.publish("round-1", before_commit=race)
            self.assertEqual(manifest["included_update_ids"], [tasks[1]["update_id"]])
            self.assertGreaterEqual(authority.conflicts, 1)
            restarted = connect()
            np.testing.assert_array_equal(restarted.parameters()[0], np.array([1, 1], dtype=np.float32))
            for index in (1, 2, 3):
                metadata, arrays = updates[index]
                expected = "accepted" if index == 1 else "rejected"
                self.assertEqual(restarted.receive(tasks[index]["task_id"], index, metadata, arrays), expected)
            evidence = restarted.evidence()
            self.assertEqual(len(evidence["updates"]), 3)
            self.assertTrue(verify_chain(evidence["audit"], evidence["anchor"]))
            final_opa = [row for row in evidence["durable_evidence"]["run_records"] if row["SK"].startswith("OPA_FINAL#")]
            self.assertEqual(len(final_opa), 3)
            self.assertTrue(all(json.loads(row["opa_decision_json"])["decision_id"] for row in final_opa))
            self.assertIsNone(restarted.publish("empty-round"))
            self.assertIsNone(connect().publish("empty-round"))
            self.assertEqual(restarted.item(restarted.pk, "EMPTY#empty-round")["outcome"], "empty")
            # Force actual service failures with a valid pending update. A
            # failure must leave the already published pointer unchanged.
            task = restarted.issue(ORGANIZATIONS[0], 1, "fault-round")
            task = restarted.acknowledge(task["task_id"], 1, task)
            arrays = [np.array([4, 4], dtype=np.float32)]
            metadata = {**task, "sample_count": 2, "weights_digest": arrays_digest(arrays)}
            self.assertEqual(restarted.receive(task["task_id"], 1, metadata, arrays), "pending")
            pointer = restarted.item(restarted.pk, "POINTER")
            audit_head = restarted.item(restarted.pk, "AUDIT_HEAD")
            opa_name = services.identifier + "-opa"
            services.docker("stop", opa_name)
            try:
                with self.assertRaises(OpaUnavailable):
                    restarted.publish("fault-round")
                self.assertEqual(restarted.item(restarted.pk, "POINTER"), pointer)
                self.assertEqual(restarted.item(restarted.pk, "AUDIT_HEAD"), audit_head)
                self.assertEqual(restarted.item(restarted.pk, "ROUND#fault-round")["pending_count"], 1)
            finally:
                services.docker("start", opa_name)
            deadline = time.monotonic() + 15
            while True:
                try:
                    with urlopen(services.opa_endpoint + "/health", timeout=1) as response:
                        self.assertEqual(response.status, 200)
                    break
                except Exception:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.1)
            artifact = json.loads(restarted.item(restarted.pk, f"UPDATE_META#{task['update_id']}")["artifact_json"])
            services.s3.delete_object(Bucket=artifact["bucket"], Key=artifact["key"], VersionId=artifact["version_id"])
            with self.assertRaises(ClientError) as missing_version:
                restarted.publish("fault-round")
            self.assertEqual(missing_version.exception.response["ResponseMetadata"]["HTTPStatusCode"], 404)
            self.assertEqual(restarted.item(restarted.pk, "POINTER"), pointer)
            self.assertEqual(restarted.item(restarted.pk, "AUDIT_HEAD"), audit_head)
            self.assertEqual(restarted.item(restarted.pk, "ROUND#fault-round")["pending_count"], 1)
            # An explicit trusted failure finalizes the lost update; it cannot
            # be replaced by replaying a receipt with the same task identifier.
            self.assertEqual(restarted.fail(task["task_id"], "immutable_version_missing"), "rejected")
            self.assertEqual(restarted.receive(task["task_id"], 1, metadata, arrays), "rejected")
            self.assertIsNone(restarted.publish("fault-round"))
            ddb_name = services.identifier + "-dynamodb"
            services.docker("stop", ddb_name)
            try:
                with self.assertRaises(BotoCoreError):
                    restarted.publish("unavailable-round")
            finally:
                services.docker("start", ddb_name)
            deadline = time.monotonic() + 15
            while True:
                try:
                    recovered_pointer = restarted.item(restarted.pk, "POINTER")
                    break
                except Exception:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.1)
            self.assertEqual(recovered_pointer, pointer)
            final_evidence = restarted.evidence()
            self.assertTrue(verify_chain(final_evidence["audit"], final_evidence["anchor"]))
            report = {"recorded_at_utc": datetime.now(timezone.utc).isoformat(),
                "validation": "persistent-authority-local-api-integration", "status": "passed",
                "aws_resources_created": False, "aws_spend_usd": 0, "clinical_rows_in_report": 0,
                "cases": {"restart_between_issue_and_ack": True, "restart_published_pointer": True,
                    "revoke_regrant_interval_rejected": True, "publication_conflict_recomputed": True,
                    "receipt_idempotency": True, "native_opa_proof_and_audit": True, "durable_empty_round": True,
                    "opa_stopped_pointer_unchanged": True, "missing_s3_version_pointer_unchanged": True,
                    "dynamodb_stopped_pointer_unchanged": True},
                "remaining_gates": ["AWS IAM and account placement", "cloud deployment validation",
                    "IRB and real clinical data authorization", "research acceptance and full experiment matrix"]}
            from integration_services import IMAGES
            report["images"] = IMAGES
            report_path = Path(__file__).resolve().parents[1] / "reports/persistent_validation.json"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
