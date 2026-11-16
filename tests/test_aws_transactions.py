"""Contract tests for AWS requests; no credentials or cloud calls are used."""

from copy import deepcopy
import json
import unittest

from pcfl.aws_transactions import (
    MAX_REQUEST_BYTES, build_initialize_authority, build_initialize_run,
    build_policy_mutation, build_publication, build_register_update, build_rejection,
    build_task_authorization, candidate_digest, expected_outcome_digest,
    recovery_get_request, validate_transaction_request,
)
from pcfl.verifier import verify_chain


TABLE = "pcfl-test-state"
ZERO = "0" * 64


def event(order=2, epoch=1, kind="GRANT"):
    rules = [{"purpose": "readmission", "action": action, "effect": "allow"}
             for action in ("train", "submit_update", "aggregate")] if kind == "GRANT" else []
    return {"event_id": f"event-{order}", "org_id": "org_01", "order": order,
            "epoch": epoch, "kind": kind, "rules": rules}


def received_update(org="org_01", index=1):
    return {"update_id": f"update-{index}", "task_id": f"task-{index}", "org_id": org,
            "purpose": "readmission", "start_order": 3 + index, "sample_count": index * 10,
            "weights_digest": candidate_digest([index, index * 2]),
            "model_schema_hash": candidate_digest({"dimension": 2})}


def candidate(org_count=2):
    updates = [received_update(f"org_{i:02d}", i) for i in range(1, org_count + 1)]
    model_hash = candidate_digest([1.5, 3.0])
    result = {"snapshot_order": 20, "parent_manifest_id": None, "round_generation": org_count,
              "policy_epochs": {u["org_id"]: 1 for u in updates},
              "history_digests": {u["org_id"]: candidate_digest([u["org_id"], 1]) for u in updates},
              "model_schema_hash": updates[0]["model_schema_hash"],
              "rule_bundle_hash": candidate_digest({"rules": "test-only"}), "model_digest": model_hash,
              "s3": {"bucket": "pcfl-private-test", "key": "staging/model.json", "version_id": "v1",
                     "sha256": model_hash, "size_bytes": 100},
              "object_confirmation": {"version_id": "v1", "sha256": model_hash, "size_bytes": 100},
              "updates": [{k: v for k, v in update.items() if k != "model_schema_hash"} for update in updates]}
    result["candidate_id"] = candidate_digest(result)
    return result


def rehash(context):
    context["candidate_id"] = candidate_digest({k: v for k, v in context.items() if k != "candidate_id"})


def action_for(request, sk):
    matches = []
    for action in request["TransactItems"]:
        kind = next(iter(action))
        body = action[kind]
        key = body["Item"] if kind == "Put" else body["Key"]
        if key["SK"] == {"S": sk}:
            matches.append((kind, body))
    if len(matches) != 1:
        raise AssertionError(f"expected one {sk} action, found {len(matches)}")
    return matches[0]


def publish(context=None, count=0, head=ZERO):
    return build_publication(TABLE, run_id="run-1", round_id="round-1", txn_id="publish-1",
                             candidate=context or candidate(), expected_audit_count=count,
                             expected_audit_head=head)


class AwsTransactionTests(unittest.TestCase):
    def test_policy_mutation_guards_epoch_sequence_unique_history_and_outcome_together(self):
        request = build_policy_mutation(TABLE, expected_order=1, expected_epoch=0,
                                        event=event(), txn_id="grant-1")
        self.assertEqual(len(request["TransactItems"]), 5)
        self.assertEqual(action_for(request, "SEQUENCE")[1]["ExpressionAttributeValues"][":expected"], {"N": "1"})
        self.assertEqual(action_for(request, "SEQUENCE")[1]["ExpressionAttributeValues"][":next"], {"N": "2"})
        self.assertEqual(action_for(request, "CURRENT")[1]["ConditionExpression"], "attribute_not_exists(#pk)")
        history = action_for(request, "EVENT#00000000000000000002")[1]
        self.assertEqual(json.loads(history["Item"]["event_json"]["S"]), event())
        for sk in ("EVENT#00000000000000000002", "EVENT_ID#event-2", "TXN#grant-1"):
            self.assertEqual(action_for(request, sk)[1]["ConditionExpression"], "attribute_not_exists(#pk)")
        self.assertEqual(len(expected_outcome_digest(request)), 64)
        validate_transaction_request(request)

    def test_revocation_advances_existing_epoch_with_compare_and_swap(self):
        request = build_policy_mutation(TABLE, expected_order=20, expected_epoch=1,
                                        event=event(order=21, epoch=2, kind="REVOKE"), txn_id="revoke-1")
        current = action_for(request, "CURRENT")[1]
        self.assertEqual(current["ConditionExpression"], "#epoch = :expected")
        self.assertEqual(current["ExpressionAttributeValues"][":expected"], {"N": "1"})
        self.assertEqual(current["ExpressionAttributeValues"][":epoch"], {"N": "2"})

    def test_malformed_mutations_cannot_form_partial_transactions(self):
        for field, value in (("order", 9), ("epoch", 2), ("org_id", "org_99"),
                             ("kind", []), ("org_id", []), ("rules", None)):
            bad = event()
            bad[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                build_policy_mutation(TABLE, expected_order=1, expected_epoch=0, event=bad, txn_id="bad")
        bad = event(kind="REVOKE")
        bad["rules"] = event()["rules"]
        with self.assertRaises(ValueError):
            build_policy_mutation(TABLE, expected_order=1, expected_epoch=0, event=bad, txn_id="bad")

    def test_publication_guards_every_contributor_and_pending_membership(self):
        context = candidate(8)
        request = publish(context)
        self.assertEqual(len(request["TransactItems"]), 30)
        guards = [a["ConditionCheck"] for a in request["TransactItems"] if "ConditionCheck" in a]
        self.assertEqual({g["Key"]["PK"]["S"] for g in guards}, {f"POLICY#org_{i:02d}" for i in range(1, 9)})
        round_action = action_for(request, "ROUND#round-1")[1]
        self.assertIn("#generation = :generation", round_action["ConditionExpression"])
        self.assertIn("#pending = :included", round_action["ConditionExpression"])
        self.assertEqual(round_action["ExpressionAttributeValues"][":included"], {"N": "8"})
        self.assertEqual(round_action["ExpressionAttributeValues"][":zero"], {"N": "0"})
        self.assertEqual(action_for(request, "SEQUENCE")[1]["ExpressionAttributeValues"][":expected"], {"N": "20"})
        self.assertEqual(action_for(request, "SEQUENCE")[1]["ExpressionAttributeValues"][":next"], {"N": "21"})
        validate_transaction_request(request)

    def test_pointer_and_final_acceptances_share_transaction(self):
        context = candidate()
        request = publish(context)
        pointer = action_for(request, "POINTER")[1]
        self.assertIn("attribute_not_exists(#manifest)", pointer["ConditionExpression"])
        for update in context["updates"]:
            action = action_for(request, f"UPDATE#{update['update_id']}")[1]
            self.assertIn("#status = :pending", action["ConditionExpression"])
            for guard in ("#org", "#task", "#purpose", "#start", "#sample_count", "#schema", "#digest"):
                self.assertIn(guard, action["ConditionExpression"])
            decision = json.loads(action["ExpressionAttributeValues"][":decision"]["S"])
            self.assertEqual(decision["manifest_ref"], context["candidate_id"])
            self.assertEqual(decision["evaluation_order"], 21)
            self.assertEqual(decision["outcome"], "accepted")
        self.assertEqual(action_for(request, f"MANIFEST#{context['candidate_id']}")[0], "Put")
        self.assertEqual(action_for(request, "TXN#publish-1")[0], "Put")

    def test_parent_pointer_guard_is_exact(self):
        context = candidate()
        context["parent_manifest_id"] = "a" * 64
        rehash(context)
        pointer = action_for(publish(context), "POINTER")[1]
        self.assertIn("#manifest = :parent", pointer["ConditionExpression"])
        self.assertEqual(pointer["ExpressionAttributeValues"][":parent"], {"S": "a" * 64})

    def test_audit_generated_by_publication_passes_independent_checker(self):
        request = publish()
        records = [json.loads(a["Put"]["Item"]["event_json"]["S"]) for a in request["TransactItems"]
                   if "Put" in a and a["Put"]["Item"].get("record_type") == {"S": "audit_event"}]
        head = action_for(request, "AUDIT_HEAD")[1]["ExpressionAttributeValues"]
        anchor = {"count": int(head[":new_count"]["N"]), "head": head[":new_head"]["S"]}
        self.assertTrue(verify_chain(records, anchor))
        self.assertEqual(action_for(request, "AUDIT_HEAD")[1]["ExpressionAttributeValues"][":old_head"], {"S": ZERO})

    def test_duplicate_or_missing_policy_guards_and_bindings_are_rejected(self):
        mutations = [lambda c: c["policy_epochs"].pop("org_02"),
                     lambda c: c["history_digests"].pop("org_02"),
                     lambda c: c["policy_epochs"].update(org_03=1),
                     lambda c: c["updates"][1].update(org_id="org_01"),
                     lambda c: c["updates"][1].update(update_id="update-1"),
                     lambda c: c["updates"][0].update(sample_count=True),
                     lambda c: c["updates"][0].pop("purpose")]
        for mutation in mutations:
            context = candidate()
            mutation(context)
            rehash(context)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                publish(context)

    def test_unconfirmed_unversioned_or_modified_object_is_rejected(self):
        for mutation in (lambda c: c.update(object_confirmation={}),
                         lambda c: c["s3"].update(version_id="null"),
                         lambda c: c["s3"].update(sha256="f" * 64),
                         lambda c: c["object_confirmation"].update(size_bytes=99)):
            context = candidate()
            mutation(context)
            rehash(context)
            with self.assertRaises(ValueError):
                publish(context)
        context = candidate()
        context["policy_epochs"]["org_01"] = 2
        with self.assertRaisesRegex(ValueError, "candidate_metadata_digest_mismatch"):
            publish(context)

    def test_guard_refresh_changes_request_token_and_durable_operation_digest(self):
        original = publish()
        context = candidate()
        context["snapshot_order"] += 1
        context["policy_epochs"]["org_01"] += 1
        rehash(context)
        changed = publish(context)
        self.assertNotEqual(original["ClientRequestToken"], changed["ClientRequestToken"])
        self.assertNotEqual(expected_outcome_digest(original), expected_outcome_digest(changed))
        self.assertEqual(original, publish())
        self.assertLessEqual(len(original["ClientRequestToken"]), 36)

    def test_recovery_reads_durable_outcome_strongly_after_token_window(self):
        request = recovery_get_request(TABLE, "publish-1", run_id="run-1")
        self.assertTrue(request["ConsistentRead"])
        self.assertEqual(request["Key"], {"PK": {"S": "RUN#run-1"}, "SK": {"S": "TXN#publish-1"}})
        self.assertEqual(recovery_get_request(TABLE, "grant-1")["Key"]["PK"], {"S": "AUTHORITY"})

    def test_transaction_preflight_rejects_duplicate_items_action_limit_and_size(self):
        request = publish()
        request["TransactItems"].append(deepcopy(request["TransactItems"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate_transaction_item"):
            validate_transaction_request(request)
        with self.assertRaisesRegex(ValueError, "invalid_transaction_action_count"):
            validate_transaction_request({"TransactItems": [{}] * 101})
        request = publish()
        request["OversizedDiagnostic"] = "x" * MAX_REQUEST_BYTES
        with self.assertRaisesRegex(ValueError, "transaction_request_too_large"):
            validate_transaction_request(request)

    def test_bootstrap_is_conditional_and_creates_empty_pending_audit_state(self):
        authority = build_initialize_authority(TABLE, txn_id="init-authority")
        self.assertEqual(action_for(authority, "SEQUENCE")[1]["ConditionExpression"], "attribute_not_exists(#pk)")
        request = build_initialize_run(TABLE, run_id="run-1", round_id="round-1", expected_order=0, txn_id="init-run")
        round_item = action_for(request, "ROUND#round-1")[1]["Item"]
        self.assertEqual(round_item["pending_count"], {"N": "0"})
        self.assertEqual(round_item["generation"], {"N": "0"})
        self.assertNotIn("manifest_id", action_for(request, "POINTER")[1]["Item"])
        validate_transaction_request(request)

    def test_task_start_bound_to_policy_and_unique_org_assignment(self):
        task = {"task_id": "task-1", "org_id": "org_01", "purpose": "readmission", "start_order": 4,
                "policy_epoch": 1, "policy_hash": candidate_digest(event()),
                "model_schema_hash": candidate_digest({"dimension": 2}), "nonce_digest": "c" * 64}
        request = build_task_authorization(TABLE, run_id="run-1", round_id="round-1", expected_order=3,
                                           task=task, txn_id="authorize-1")
        self.assertEqual(action_for(request, "TASK_ORG#round-1#org_01")[1]["ConditionExpression"], "attribute_not_exists(#pk)")
        policy = action_for(request, "CURRENT")[1]
        self.assertIn("#hash = :hash", policy["ConditionExpression"])
        task["start_order"] = 5
        with self.assertRaises(ValueError):
            build_task_authorization(TABLE, run_id="run-1", round_id="round-1", expected_order=3,
                                     task=task, txn_id="authorize-1")

    def test_receipt_consumes_task_and_increments_membership_pending_atomically(self):
        kwargs = dict(run_id="run-1", round_id="round-1", expected_order=5, expected_round_generation=0,
                      update=received_update(), authenticated_org="org_01", observed_policy_epoch=1,
                      history_digest="d" * 64, txn_id="receive-1")
        request = build_register_update(TABLE, **kwargs)
        self.assertIn("ADD #pending :one", action_for(request, "ROUND#round-1")[1]["UpdateExpression"])
        self.assertIn("#status = :ack", action_for(request, "TASK#task-1")[1]["ConditionExpression"])
        self.assertEqual(action_for(request, "UPDATE#update-1")[1]["Item"]["status"], {"S": "pending"})
        validate_transaction_request(request)
        kwargs["authenticated_org"] = "org_02"
        with self.assertRaises(ValueError):
            build_register_update(TABLE, **kwargs)

    def test_rejection_has_no_pointer_change_and_decrements_pending_with_audit(self):
        request = build_rejection(TABLE, run_id="run-1", round_id="round-1", expected_order=21,
                                  update=received_update(), reason="authorization_interrupted", observed_policy_epoch=2,
                                  history_digest="d" * 64, rule_bundle_hash="e" * 64,
                                  expected_audit_count=0, expected_audit_head=ZERO, txn_id="reject-1")
        self.assertFalse(any(a.get("Update", {}).get("Key", {}).get("SK") == {"S": "POINTER"}
                             for a in request["TransactItems"]))
        self.assertEqual(action_for(request, "ROUND#round-1")[1]["ExpressionAttributeValues"][":minus_one"], {"N": "-1"})
        record = json.loads(action_for(request, "AUDIT#00000000000000000001")[1]["Item"]["event_json"]["S"])
        outcome = json.loads(action_for(request, "TXN#reject-1")[1]["Item"]["result_json"]["S"])
        self.assertTrue(verify_chain([record], {"count": outcome["audit_count"], "head": outcome["audit_head"]}))
        self.assertEqual(record["payload"]["outcome"], "rejected")
        validate_transaction_request(request)


if __name__ == "__main__":
    unittest.main()
