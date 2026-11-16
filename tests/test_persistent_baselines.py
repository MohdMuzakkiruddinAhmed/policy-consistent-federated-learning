"""Durable baseline semantics: synthetic arrays and optional real local SDKs."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import numpy as np

from pcfl import aws_transactions as tx
from pcfl.contracts import ORGANIZATIONS, digest
from pcfl.oracle import evaluate_interval
from pcfl.persistent import PersistentAuthority, PersistentUnavailable, arrays_digest
from pcfl.persistent_baselines import MODES, OMITTED_GUARDS, PersistentBaselineAuthority
from pcfl.verifier import verify_chain
from test_persistent import RULE_HASH, SCHEMA_HASH, TABLE, TEMPLATE, VersionedS3, candidate, make_authority


def authority(baseline, evaluator=None):
    return PersistentBaselineAuthority(Mock(), VersionedS3(), baseline_id=baseline,
        table_name=TABLE, bucket="pcfl-private-test", run_id="test-run", template=TEMPLATE,
        model_schema_hash=SCHEMA_HASH, rule_hash=RULE_HASH, policy_evaluator=evaluator)


def evaluation():
    return {"valid": True, "reason": "continuous_authorization", "decision_id": "actual-native-id",
            "rule_hash": RULE_HASH, "query": {"org_id": "org_01", "purpose": "readmission", "start_order": 8, "commit_order": 8,
                                             "actions": ["train", "submit_update", "aggregate"]}}


class PersistentBaselineTests(unittest.TestCase):
    def test_B1_performs_no_native_authorization_at_any_stage(self):
        forbidden = Mock(side_effect=AssertionError("OPA called by B1"))
        client = authority("B1", forbidden)
        for stage in ("issue", "acknowledge", "receipt", "publication", "final"):
            decision = client._authorization({}, "org_01", 10, 20, stage=stage, task_id="task")
            self.assertTrue(decision["valid"])
            self.assertIsNone(decision["decision_id"])
        forbidden.assert_not_called()

    def test_B2_reuses_durable_admission_across_all_later_checks(self):
        evaluator = Mock(side_effect=AssertionError("cached admission rechecked"))
        client = authority("B2", evaluator)
        snapshot = {"items": {"ADMISSION#org_01": {"opa_decision_json": json.dumps(evaluation())}}}
        for stage in ("issue", "acknowledge", "receipt", "publication", "final"):
            self.assertEqual(client._authorization(snapshot, "org_01", 10, 50, stage=stage), evaluation())
        evaluator.assert_not_called()
        with self.assertRaisesRegex(PersistentUnavailable, "admission_provenance_missing"):
            client._authorization({"items": {}}, "org_01", 10, 20, stage="receipt")

    def test_B3_calls_native_OPA_only_at_issue_and_uses_issued_provenance(self):
        evaluator = Mock(return_value=evaluation())
        client = authority("B3", evaluator)
        snapshot = {"events": [], "items": {"ISSUE#task": {"opa_decision_json": json.dumps(evaluation())}}}
        client._authorization(snapshot, "org_01", 8, 8, stage="issue", task_id="task")
        for stage in ("acknowledge", "receipt", "publication", "final"):
            self.assertEqual(client._authorization(snapshot, "org_01", 10, 30, stage=stage, task_id="task"), evaluation())
        self.assertEqual(evaluator.call_count, 1)

    def test_baseline_candidates_bind_omitted_guards_and_keep_durable_pointer_audit(self):
        for baseline in MODES:
            with self.subTest(baseline=baseline):
                client = authority(baseline, Mock(return_value=evaluation()))
                original = candidate()
                context = client._candidate_context({key: value for key, value in original.items() if key != "candidate_id"})
                actual = {**context, "candidate_id": digest(context)}
                request = client._publication_request(run_id="test-run", round_id="round-1", txn_id="publication-1",
                    candidate=actual, expected_audit_count=0, expected_audit_head="0" * 64)
                tx.validate_transaction_request(request)
                self.assertFalse(any(action.get("ConditionCheck", {}).get("Key", {}).get("PK", {}).get("S", "").startswith("POLICY#") for action in request["TransactItems"]))
                manifests = [json.loads(action["Put"]["Item"]["manifest_json"]["S"]) for action in request["TransactItems"]
                             if action.get("Put", {}).get("Item", {}).get("record_type") == {"S": "publication_manifest"}]
                self.assertEqual(manifests[0]["candidate"], actual)
                self.assertEqual(manifests[0]["manifest_id"], actual["candidate_id"])
                self.assertEqual(actual["policy_epochs"], {})
                self.assertEqual(actual["omitted_guards"], OMITTED_GUARDS)
                keys = [action["Update"]["Key"]["SK"]["S"] for action in request["TransactItems"] if "Update" in action]
                self.assertIn("POINTER", keys); self.assertIn("AUDIT_HEAD", keys)
                with patch.object(PersistentAuthority, "_transact", return_value={}) as shared:
                    client._transact(request, "publication-1")
                self.assertEqual(len(shared.call_args.args[0]["TransactItems"]), len(request["TransactItems"]))

    def test_baseline_final_provenance_has_no_fabricated_commit_OPA(self):
        client = authority("B1")
        context = client._candidate_context({key: value for key, value in candidate().items() if key != "candidate_id"})
        actual = {**context, "candidate_id": digest(context)}
        request = client._publication_request(run_id="test-run", round_id="round-1", txn_id="publication-1",
            candidate=actual, expected_audit_count=0, expected_audit_head="0" * 64)
        stub = client._authorization({}, "org_01", 1, 2, stage="publication")
        request = client._policy_evidence(request, {update["update_id"]: stub for update in actual["updates"]})
        puts = [action["Put"]["Item"] for action in request["TransactItems"] if "Put" in action]
        self.assertFalse(any(item["SK"]["S"].startswith("OPA_FINAL#") for item in puts))
        self.assertEqual(sum(item["SK"]["S"].startswith("BASELINE_FINAL#") for item in puts), 2)
        audits = sorted([json.loads(item["event_json"]["S"]) for item in puts if item.get("record_type") == {"S": "audit_event"}], key=lambda event: event["sequence"])
        self.assertTrue(verify_chain(audits, {"count": 2, "head": audits[-1]["event_hash"]}))
        self.assertTrue(all(record["payload"]["policy_decision_id"] is None for record in audits))

    def test_method_namespace_cannot_relabel_an_existing_baseline_model_as_P1(self):
        raw = {"candidate": {"baseline_id": "B1"}}
        with self.assertRaisesRegex(PersistentUnavailable, "method_mismatch"):
            make_authority()._normalized_manifest({"manifest_json": json.dumps(raw)})
        with self.assertRaisesRegex(PersistentUnavailable, "method_mismatch"):
            authority("B3", Mock(return_value=evaluation()))._normalized_manifest({"manifest_json": json.dumps(raw)})


@unittest.skipUnless(os.environ.get("PCFL_LOCAL_INTEGRATION") == "1", "explicit local SDK integration only")
class PersistentBaselineLiveTests(unittest.TestCase):
    def test_actual_durable_baseline_matrix_and_restart_semantics(self):
        from pcfl.governance_service import PolicyWriter
        from pcfl.opa import OpaClient
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from integration_services import LocalIntegrationServices
        results = []
        with tempfile.TemporaryDirectory(prefix="pcfl-baseline-live-") as directory, LocalIntegrationServices(directory) as services:
            operator = PolicyWriter(services.ddb, services.table)
            operator.initialize()
            for org in ORGANIZATIONS:
                operator.mutate(org, "GRANT")
            opa = OpaClient(services.opa_endpoint, allow_loopback_http=True)
            for baseline in ("B1", "B2", "B3", "P1"):
                for scenario in ("stable", "mid_round"):
                    native = Mock(wraps=opa.evaluate)
                    run_id = f"{baseline}-{scenario}"
                    def connect():
                        cls = PersistentAuthority if baseline == "P1" else PersistentBaselineAuthority
                        options = {} if baseline == "P1" else {"baseline_id": baseline}
                        return cls(services.ddb, services.s3, table_name=services.table, bucket=services.bucket,
                            run_id=run_id, template=TEMPLATE, model_schema_hash=SCHEMA_HASH, rule_hash=opa.rule_hash,
                            policy_evaluator=native, local_emulation=True, **options)
                    client = connect()
                    tasks = []
                    for index, org in enumerate(ORGANIZATIONS[:2], 1):
                        issued = client.issue(org, index, "round-1")
                        client = connect()
                        tasks.append(client.acknowledge(issued["task_id"], index, issued))
                    dispatch_calls = native.call_count
                    if scenario == "mid_round":
                        operator.mutate("org_01", "REVOKE")
                    for index, task in enumerate(tasks, 1):
                        arrays = [np.full_like(TEMPLATE[0], index)]
                        metadata = {**task, "sample_count": index, "weights_digest": arrays_digest(arrays)}
                        expected = "rejected" if baseline == "P1" and scenario == "mid_round" and index == 1 else "pending"
                        self.assertEqual(client.receive(task["task_id"], index, metadata, arrays), expected)
                    manifest = client.publish("round-1")
                    self.assertEqual(len(manifest["included_update_ids"]), 1 if baseline == "P1" and scenario == "mid_round" else 2)
                    self.assertEqual(connect().publish("round-1"), manifest)
                    np.testing.assert_array_equal(connect().parameters()[0], client.parameters()[0])
                    evidence = client.evidence()
                    self.assertTrue(verify_chain(evidence["audit"], evidence["anchor"]))
                    invalid = 0
                    for update in evidence["updates"]:
                        query = {"org_id": update["org_id"], "purpose": update["purpose"], "start_order": update["start_order"],
                                 "commit_order": manifest["commit_order"], "actions": ["train", "submit_update", "aggregate"]}
                        if update["update_id"] in manifest["included_update_ids"] and not evaluate_interval(evidence["policy_events"], query)["valid"]:
                            invalid += 1
                    self.assertEqual(invalid, 1 if scenario == "mid_round" and baseline != "P1" else 0)
                    if baseline == "B1":
                        self.assertEqual(native.call_count, 0)
                    elif baseline in {"B2", "B3"}:
                        self.assertEqual(native.call_count, dispatch_calls)
                    if scenario == "mid_round":
                        next_task = connect().issue("org_01", 1, "round-2")
                        self.assertEqual(next_task is None, baseline in {"B3", "P1"})
                        if baseline == "B2":
                            self.assertEqual(native.call_count, dispatch_calls)
                        operator.mutate("org_01", "GRANT")
                    results.append({"baseline": baseline, "scenario": scenario, "native_opa_calls": native.call_count,
                                    "invalid_incorporations": invalid, "durable_audit_verified": True})
            report = {"schema_version": "0.1.0", "successful": True, "kind": "synthetic-local-durable-comparators",
                      "aws_resources_created": False, "clinical_rows_used": 0, "final_holdout_opened": False, "cases": results}
            (Path(__file__).resolve().parents[1] / "reports/persistent_baselines_validation.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
