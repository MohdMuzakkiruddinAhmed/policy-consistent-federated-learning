from copy import deepcopy
from dataclasses import replace
import threading
import unittest

from pcfl.contracts import ACTIONS, ModelUpdate, digest
from pcfl.oracle import evaluate_interval
from pcfl.state_model import ConditionalConflict, LocalProtocolModel, Unavailable
from pcfl.verifier import verify_chain


def rules(purpose="readmission"):
    return [{"purpose": purpose, "action": a, "effect": "allow"} for a in ACTIONS]


class ProtocolModelTests(unittest.TestCase):
    def setUp(self):
        self.model = LocalProtocolModel()
        for i in range(1, 9):
            self.model.mutate(f"org_{i:02d}", "GRANT", rules())

    def update(self, org="org_01", uid="u1", count=2, weights=(1.0, 3.0), round_id="r1"):
        task = self.model.authorize(org, "readmission", round_id)
        update = ModelUpdate.create(uid, task, count, weights)
        self.assertEqual(self.model.present(update, org), "pending")
        return update

    def assert_oracle_valid(self):
        evidence = self.model.evidence()
        tasks = {t["task_id"]: t for t in evidence["tasks"]}
        for manifest in evidence["manifests"]:
            for uid in manifest["update_ids"]:
                task = self.model._updates[uid].task
                query = {"org_id": task.org_id, "purpose": task.purpose,
                         "start_order": tasks[task.task_id]["start_order"],
                         "commit_order": manifest["commit_order"], "actions": list(ACTIONS)}
                self.assertTrue(evaluate_interval(evidence["policy_events"], query)["valid"])
        self.assertTrue(verify_chain(evidence["audit"], evidence["anchor"]))

    def test_eight_clients_weighted_average_and_oracle_membership(self):
        for i in range(1, 9):
            self.update(f"org_{i:02d}", f"u{i}", i, (float(i), float(i * 2)))
        candidate = self.model.prepare("r1")
        self.assertIsNone(self.model.read_published())
        manifest = self.model.commit(candidate)
        self.assertEqual(len(manifest["policy_epochs"]), 8)
        self.assertEqual(manifest["weights"], (204 / 36, 408 / 36))
        self.assert_oracle_valid()

    def test_revocation_after_stage_blocks_commit_then_recomputes(self):
        self.update()
        self.update("org_02", "u2", weights=(5.0, 7.0))
        stale = self.model.prepare("r1")
        self.model.mutate("org_01", "REVOKE", [])
        with self.assertRaises(ConditionalConflict):
            self.model.commit(stale)
        self.assertIsNone(self.model.read_published())
        fresh = self.model.prepare("r1")
        manifest = self.model.commit(fresh)
        self.assertEqual(manifest["update_ids"], ["u2"])
        self.assertEqual(manifest["weights"], (5.0, 7.0))
        self.assert_oracle_valid()

    def test_revoke_regrant_cannot_resurrect_old_update(self):
        self.update()
        self.model.mutate("org_01", "REVOKE", [])
        self.model.mutate("org_01", "GRANT", rules())
        self.assertIsNone(self.model.prepare("r1"))
        self.assertEqual(self.model.evidence()["decisions"]["u1"]["outcome"], "rejected")
        self.update(uid="u2", round_id="r2")
        self.model.commit(self.model.prepare("r2"))
        self.assert_oracle_valid()

    def test_all_ineligible_aborts_without_model(self):
        self.update()
        self.model.mutate("org_01", "EXPIRE", [])
        self.assertIsNone(self.model.prepare("r1"))
        self.assertIsNone(self.model.read_published())

    def test_unrelated_change_conflicts_but_keeps_semantic_eligibility(self):
        self.update()
        stale = self.model.prepare("r1")
        self.model.mutate("org_01", "CHANGE", rules() + rules("research_other"))
        with self.assertRaises(ConditionalConflict):
            self.model.commit(stale)
        self.model.commit(self.model.prepare("r1"))
        self.assert_oracle_valid()

    def test_post_publication_revoke_does_not_unlearn(self):
        self.update()
        candidate = self.model.prepare("r1")
        published = self.model.commit(candidate)
        self.model.mutate("org_01", "REVOKE", [])
        self.assertEqual(self.model.commit(candidate), published)
        self.assertEqual(self.model.read_published(), published)
        self.assert_oracle_valid()

    def test_duplicate_delivery_and_commit_are_idempotent(self):
        update = self.update()
        self.assertEqual(self.model.present(update, "org_01"), "pending")
        candidate = self.model.prepare("r1")
        manifest = self.model.commit(candidate)
        self.assertEqual(self.model.present(update, "org_01"), "accepted")
        self.assertEqual(self.model.commit(candidate), manifest)
        self.assertEqual(len(self.model.evidence()["audit"]), 1)
        with self.assertRaises(ValueError):
            self.model.present(ModelUpdate.create("u1", update.task, 2, (9.0, 3.0)), "org_01")

    def test_second_update_for_same_task_cannot_double_weight_client(self):
        update = self.update()
        duplicate_task = ModelUpdate.create("u2", update.task, 2, (9.0, 3.0))
        self.assertEqual(self.model.present(duplicate_task, "org_01"), "rejected")
        self.assertEqual(self.model.commit(self.model.prepare("r1"))["update_ids"], ["u1"])

    def test_missing_audit_blocks_publication_and_rejection(self):
        self.update()
        candidate = self.model.prepare("r1")
        self.model.audit_available = False
        with self.assertRaises(Unavailable):
            self.model.commit(candidate)
        self.assertIsNone(self.model.read_published())
        self.assertEqual(self.model.evidence()["decisions"], {})
        self.model.audit_available = True
        self.model.commit(candidate)
        self.assert_oracle_valid()

    def test_staging_failure_and_lost_object_do_not_publish(self):
        self.update()
        self.model.object_store_available = False
        with self.assertRaises(Unavailable):
            self.model.prepare("r1")
        self.model.object_store_available = True
        candidate = self.model.prepare("r1")
        self.model.object_store_available = False
        with self.assertRaises(Unavailable):
            self.model.commit(candidate)
        self.assertIsNone(self.model.read_published())

    def test_staged_content_corruption_blocks_publication(self):
        self.update()
        candidate = self.model.prepare("r1")
        self.model._candidates[candidate]["weights"] = (99.0, 99.0)
        with self.assertRaises(ValueError):
            self.model.commit(candidate)
        self.assertIsNone(self.model.read_published())

    def test_missing_authority_blocks_dispatch_receipt_and_commit(self):
        update = self.update()
        candidate = self.model.prepare("r1")
        self.model.authority_available = False
        for operation in (lambda: self.model.authorize("org_02", "readmission", "r2"),
                          lambda: self.model.present(update, "org_01"),
                          lambda: self.model.commit(candidate)):
            with self.assertRaises(Unavailable):
                operation()
        self.assertIsNone(self.model.read_published())

    def test_identity_binding_and_digest_fail_closed(self):
        task = self.model.authorize("org_01", "readmission", "r1")
        update = ModelUpdate.create("u1", task, 2, (1.0, 2.0))
        self.assertEqual(self.model.present(update, "org_02"), "rejected")
        self.assertIsNone(self.model.prepare("r1"))
        forged = replace(update, update_id="u2", weights_digest="0" * 64)
        with self.assertRaises(ValueError):
            self.model.present(forged, "org_01")
        forged_task = replace(task, purpose="other")
        rebound = ModelUpdate.create("u3", forged_task, 2, (1.0, 2.0))
        self.assertEqual(self.model.present(rebound, "org_01"), "rejected")

    def test_invalid_models_and_sample_counts(self):
        task = self.model.authorize("org_01", "readmission", "r1")
        for count in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                self.model.present(ModelUpdate.create("u1", task, count, (1.0, 2.0)), "org_01")
        with self.assertRaises(ValueError):
            ModelUpdate.create("nan", task, 2, (float("nan"), 1.0))
        malformed = ModelUpdate("bad", task, 1, (float("inf"), 1.0), "unused")
        with self.assertRaises(ValueError):
            self.model.present(malformed, "org_01")

    def test_concurrent_revoke_and_commit_have_one_valid_order(self):
        # Each trial forces contenders to wait at the same barrier.
        for _ in range(30):
            model = LocalProtocolModel()
            model.mutate("org_01", "GRANT", rules())
            task = model.authorize("org_01", "readmission", "r1")
            model.present(ModelUpdate.create("u1", task, 1, (1.0, 2.0)), "org_01")
            candidate = model.prepare("r1")
            barrier = threading.Barrier(2)
            errors = []
            def revoke():
                barrier.wait()
                model.mutate("org_01", "REVOKE", [])
            def publish():
                barrier.wait()
                try:
                    model.commit(candidate)
                except ConditionalConflict:
                    errors.append("conflict")
            threads = [threading.Thread(target=revoke), threading.Thread(target=publish)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            published = model.read_published()
            if published:
                query = {"org_id": "org_01", "purpose": "readmission", "start_order": task.start_order,
                         "commit_order": published["commit_order"], "actions": list(ACTIONS)}
                self.assertTrue(evaluate_interval(model.evidence()["policy_events"], query)["valid"])
            else:
                self.assertEqual(errors, ["conflict"])

    def test_audit_tamper_delete_reorder_replay_and_truncation_detected(self):
        self.update()
        self.update("org_02", "u2")
        self.model.commit(self.model.prepare("r1"))
        evidence = self.model.evidence()
        original, anchor = evidence["audit"], evidence["anchor"]
        self.assertTrue(verify_chain(original, anchor))
        changed = deepcopy(original)
        changed[0]["payload"]["reason"] = "modified"
        variants = [changed, original[1:], list(reversed(original)), original + [original[0]], original[:-1]]
        for records in variants:
            self.assertFalse(verify_chain(records, anchor))

    def test_manifest_reads_are_copies(self):
        self.update()
        manifest = self.model.commit(self.model.prepare("r1"))
        manifest["update_ids"].append("injected")
        self.assertEqual(self.model.read_published()["update_ids"], ["u1"])

    def test_two_prepared_rounds_cannot_overwrite_parent(self):
        self.update()
        self.update("org_02", "u2", round_id="r2")
        r1, r2 = self.model.prepare("r1"), self.model.prepare("r2")
        self.model.commit(r1)
        with self.assertRaises(ConditionalConflict):
            self.model.commit(r2)
        new_r2 = self.model.prepare("r2")
        manifest = self.model.commit(new_r2)
        self.assertEqual(manifest["parent_manifest"], r1)
        self.assert_oracle_valid()

    def test_new_receipt_after_prepare_forces_membership_refresh(self):
        self.update()
        later_task = self.model.authorize("org_02", "readmission", "r1")
        stale = self.model.prepare("r1")
        later = ModelUpdate.create("u2", later_task, 2, (5.0, 7.0))
        self.model.present(later, "org_02")
        with self.assertRaises(ConditionalConflict):
            self.model.commit(stale)
        manifest = self.model.commit(self.model.prepare("r1"))
        self.assertEqual(manifest["update_ids"], ["u1", "u2"])
        self.assertEqual(len(self.model.evidence()["decisions"]), 2)
        self.assert_oracle_valid()

    def test_missing_history_tail_is_detected_against_authoritative_epoch(self):
        self.update()
        self.model.mutate("org_01", "REVOKE", [])
        self.model._events.pop()
        with self.assertRaises(Unavailable):
            self.model.prepare("r1")
        self.assertIsNone(self.model.read_published())

    def test_duplicate_org_assignment_is_rejected(self):
        self.model.authorize("org_01", "readmission", "r1")
        with self.assertRaises(ValueError):
            self.model.authorize("org_01", "readmission", "r1")

    def test_audit_sequence_type_and_extra_fields_cannot_escape_integrity_check(self):
        self.update()
        self.model.commit(self.model.prepare("r1"))
        evidence = self.model.evidence()
        for sequence in (True, 1.0):
            altered = deepcopy(evidence["audit"])
            altered[0]["sequence"] = sequence
            self.assertFalse(verify_chain(altered, evidence["anchor"]))
        altered = deepcopy(evidence["audit"])
        altered[0]["injected"] = "not covered by original hash"
        self.assertFalse(verify_chain(altered, evidence["anchor"]))


if __name__ == "__main__":
    unittest.main()
