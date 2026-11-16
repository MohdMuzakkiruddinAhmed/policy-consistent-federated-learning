from copy import deepcopy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np
from flwr.app import ConfigRecord, Context, Message, RecordDict

from pcfl.contracts import ACTIONS
from pcfl.flower_app import RuntimeAuthority, acknowledge_task, arrays_digest, train_task, weighted_average
from pcfl.oracle import evaluate_interval
from pcfl.verifier import verify_chain


class RuntimeAuthorityTests(unittest.TestCase):
    def authority(self, baseline="P1"):
        return RuntimeAuthority(baseline, [np.array([0.0, 0.0], dtype=np.float32)], "a" * 64, max_examples=20)

    def task(self, authority, org="org_01", node=1, round_id="round-1"):
        task = authority.issue(org, node, round_id)
        return authority.acknowledge(task["task_id"], node, task)

    def metadata(self, task, arrays, count=2):
        return {**{key: task[key] for key in ("task_id", "update_id", "org_id", "round_id", "purpose",
                                             "start_order", "model_schema_hash", "nonce")},
                "weights_digest": arrays_digest(arrays), "sample_count": count}

    def receive(self, authority, task, weights=(1.0, 3.0), count=2):
        arrays = [np.array(weights, dtype=np.float32)]
        authority.receive(task["task_id"], task["node_id"], self.metadata(task, arrays, count), arrays)
        return arrays

    def test_stable_publication_weights_and_independent_oracle_audit(self):
        authority = self.authority()
        first, second = self.task(authority), self.task(authority, "org_02", 2)
        self.receive(authority, first, count=1)
        self.receive(authority, second, (5.0, 7.0), count=3)
        manifest = authority.publish("round-1")
        np.testing.assert_array_equal(authority.parameters()[0], [4.0, 6.0])
        evidence = authority.evidence()
        self.assertTrue(verify_chain(evidence["audit"], evidence["anchor"]))
        for task in (first, second):
            self.assertTrue(evaluate_interval(evidence["policy_events"], {"org_id": task["org_id"],
                "purpose": task["purpose"], "start_order": task["start_order"],
                "commit_order": manifest["commit_order"], "actions": list(ACTIONS)})["valid"])
        self.assertTrue(all("nonce" not in item for item in evidence["tasks"]))

    def test_mid_round_revocation_rejected_by_p1_but_admitted_by_b3(self):
        for baseline, accepted in (("P1", 1), ("B3", 2)):
            authority = self.authority(baseline)
            first, second = self.task(authority), self.task(authority, "org_02", 2)
            authority.mutate("org_01", "REVOKE")
            self.receive(authority, first)
            self.receive(authority, second, (5.0, 7.0))
            manifest = authority.publish("round-1")
            self.assertEqual(len(manifest["included_update_ids"]), accepted)
            if baseline == "P1":
                np.testing.assert_array_equal(authority.parameters()[0], [5.0, 7.0])
            else:
                invalid = evaluate_interval(authority.histories, {"org_id": "org_01", "purpose": "readmission",
                    "start_order": first["start_order"], "commit_order": manifest["commit_order"], "actions": list(ACTIONS)})
                self.assertFalse(invalid["valid"])

    def test_revoke_regrant_does_not_resurrect_old_lifecycle(self):
        authority = self.authority()
        old = self.task(authority)
        authority.mutate("org_01", "REVOKE")
        authority.mutate("org_01", "GRANT")
        self.receive(authority, old)
        self.assertIsNone(authority.publish("round-1"))
        new = self.task(authority, round_id="round-2")
        self.receive(authority, new)
        self.assertIsNotNone(authority.publish("round-2"))

    def test_admission_and_round_start_baselines_differ_between_rounds(self):
        for baseline, selected in (("B1", True), ("B2", True), ("B3", False), ("P1", False)):
            authority = self.authority(baseline)
            authority.mutate("org_01", "REVOKE")
            self.assertEqual(authority.issue("org_01", 1, "round-2") is not None, selected)

    def test_near_commit_revocation_forces_reaggregation(self):
        authority = self.authority()
        first, second = self.task(authority), self.task(authority, "org_02", 2)
        self.receive(authority, first)
        self.receive(authority, second, (5.0, 7.0))
        staged = []
        def stage(arrays, sha):
            staged.append(arrays[0].copy())
            return {"model_digest": sha}
        def race(attempt):
            if attempt == 0:
                authority.mutate("org_01", "REVOKE")
        manifest = authority.publish("round-1", stage=stage, before_commit=race)
        self.assertEqual(len(staged), 2)
        self.assertEqual(manifest["included_update_ids"], [second["update_id"]])
        np.testing.assert_array_equal(authority.parameters()[0], [5.0, 7.0])

    def test_new_receipt_during_staging_cannot_be_left_pending(self):
        authority = self.authority()
        first, second = self.task(authority), self.task(authority, "org_02", 2)
        self.receive(authority, first)
        def race(attempt):
            if attempt == 0:
                self.receive(authority, second, (5.0, 7.0))
        manifest = authority.publish("round-1", before_commit=race)
        self.assertEqual(len(manifest["included_update_ids"]), 2)
        self.assertEqual(len(authority.decisions), 2)

    def test_staging_failure_does_not_publish_or_finalize_acceptance(self):
        authority = self.authority()
        task = self.task(authority)
        self.receive(authority, task)
        def failed_stage(*args):
            raise OSError("storage_unavailable")
        with self.assertRaises(OSError):
            authority.publish("round-1", stage=failed_stage)
        self.assertEqual(authority.manifests, [])
        self.assertNotIn(task["update_id"], authority.decisions)

    def test_mutating_stage_callback_cannot_publish_different_model_bytes(self):
        authority = self.authority()
        task = self.task(authority)
        self.receive(authority, task)
        before = arrays_digest(authority.parameters())
        def corrupt(arrays, sha):
            arrays[0][0] = 99
            return {"backend": "test", "model_digest": sha}
        with self.assertRaisesRegex(ValueError, "staged_candidate_binding"):
            authority.publish("round-1", stage=corrupt)
        self.assertEqual(authority.manifests, [])
        self.assertEqual(arrays_digest(authority.parameters()), before)
        self.assertNotIn(task["update_id"], authority.decisions)

    def test_stage_artifact_metadata_is_bound_and_copied(self):
        authority = self.authority()
        task = self.task(authority)
        self.receive(authority, task)
        with self.assertRaisesRegex(ValueError, "staged_candidate_binding"):
            authority.publish("round-1", stage=lambda arrays, sha: {"model_digest": "f" * 64})
        returned = {}
        def stage(arrays, sha):
            returned.update({"model_digest": sha, "path": "immutable-checkpoint"})
            return returned
        def mutate_metadata(attempt):
            returned["model_digest"] = "f" * 64
            returned["path"] = "changed"
        manifest = authority.publish("round-1", stage=stage, before_commit=mutate_metadata)
        self.assertEqual(manifest["model_digest"], arrays_digest(authority.parameters()))
        self.assertEqual(manifest["artifact"]["model_digest"], manifest["model_digest"])
        self.assertEqual(manifest["artifact"]["path"], "immutable-checkpoint")

    def test_closed_round_rejects_new_tasks_and_finalizes_preissued_late_reply(self):
        authority = self.authority()
        first, late = self.task(authority), self.task(authority, "org_02", 2)
        self.receive(authority, first)
        authority.publish("round-1")
        with self.assertRaisesRegex(ValueError, "closed_round"):
            authority.issue("org_03", 3, "round-1")
        self.receive(authority, late)
        self.assertEqual(authority.decisions[late["update_id"]]["outcome"], "rejected")
        self.assertEqual(authority.decisions[late["update_id"]]["reason"], "round_already_closed")
        self.assertEqual(len(authority.audit), 2)

    def test_finalized_error_is_not_resurrected_by_late_valid_payload(self):
        authority = self.authority()
        task = self.task(authority)
        authority.fail(task["task_id"], "client_timeout")
        arrays = [np.array([1.0, 3.0], dtype=np.float32)]
        outcome = authority.receive(task["task_id"], 1, self.metadata(task, arrays), arrays)
        self.assertEqual(outcome, "error")
        self.assertNotIn(task["update_id"], authority.updates)
        self.assertEqual(len(authority.audit), 1)

    def test_acknowledgment_identity_and_policy_binding_are_checked(self):
        authority = self.authority()
        task = authority.issue("org_01", 1, "round-1")
        with self.assertRaises(ValueError):
            authority.acknowledge(task["task_id"], 2, task)
        authority.mutate("org_01", "REVOKE")
        with self.assertRaises(ValueError):
            authority.acknowledge(task["task_id"], 1, task)

    def test_update_payload_identity_nonce_count_and_schema_are_checked(self):
        authority = self.authority()
        task = self.task(authority)
        arrays = [np.array([1.0, 3.0], dtype=np.float32)]
        for mutation in ({"nonce": "forged"}, {"weights_digest": "f" * 64},
                         {"model_schema_hash": "f" * 64}, {"sample_count": True}, {"sample_count": 21}):
            metadata = {**self.metadata(task, arrays), **mutation}
            with self.assertRaises(ValueError):
                authority.receive(task["task_id"], 1, metadata, arrays)
        with self.assertRaises(ValueError):
            authority.receive(task["task_id"], 2, self.metadata(task, arrays), arrays)
        with self.assertRaises(ValueError):
            authority.receive(task["task_id"], 1, self.metadata(task, arrays), [arrays[0].astype(np.float64)])

    def test_duplicate_delivery_and_conflicting_sample_count(self):
        authority = self.authority()
        task = self.task(authority)
        arrays = self.receive(authority, task)
        self.assertEqual(authority.receive(task["task_id"], 1, self.metadata(task, arrays), arrays), "pending")
        with self.assertRaises(ValueError):
            authority.receive(task["task_id"], 1, self.metadata(task, arrays, 3), arrays)
        authority.publish("round-1")
        self.assertEqual(authority.receive(task["task_id"], 1, self.metadata(task, arrays), arrays), "accepted")
        self.assertEqual(len(authority.audit), 1)

    def test_array_digest_and_weighted_average_are_order_stable(self):
        first = np.array([1.0, 2.0], dtype=np.float32)
        self.assertNotEqual(arrays_digest([first]), arrays_digest([first.reshape(2, 1)]))
        updates = [{"org_id": "org_02", "update_id": "u2", "sample_count": 3, "arrays": [first * 2]},
                   {"org_id": "org_01", "update_id": "u1", "sample_count": 1, "arrays": [first]}]
        np.testing.assert_array_equal(weighted_average(updates, [first])[0],
                                      weighted_average(list(reversed(updates)), [first])[0])


class ClientHandshakeTests(unittest.TestCase):
    def context(self):
        return Context(run_id=1, node_id=1, node_config={"org-id": "org_01", "data-file": "own.csv",
            "preprocessor-path": "preprocessor.json"}, state=RecordDict(), run_config={})

    def test_client_rejects_claimed_other_organization_and_unacknowledged_train(self):
        authority = RuntimeAuthority("P1", [np.zeros(2, dtype=np.float32)], "a" * 64)
        task = authority.issue("org_02", 2, "round-1")
        request = Message(RecordDict({"config": ConfigRecord({"task_json": json.dumps(task)})}),
                          dst_node_id=1, message_type="query.ack")
        with self.assertRaises(ValueError):
            acknowledge_task(request, self.context())
        task = authority.issue("org_01", 1, "round-1")
        task = authority.acknowledge(task["task_id"], 1, task)
        request = Message(RecordDict({"config": ConfigRecord({"task_json": json.dumps(task)})}),
                          dst_node_id=1, message_type="train")
        with self.assertRaises(KeyError):
            train_task(request, self.context())


if __name__ == "__main__":
    unittest.main()
