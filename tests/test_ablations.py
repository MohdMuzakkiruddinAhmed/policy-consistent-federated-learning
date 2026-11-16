"""Synthetic partial-protocol boundaries; no AWS or clinical data."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

from pcfl.ablations import PersistentAblationAuthority, VARIANTS
from pcfl.contracts import digest
from pcfl.persistent import PersistentAuthority
from test_persistent import RULE_HASH, SCHEMA_HASH, TABLE, TEMPLATE, VersionedS3, candidate

STAGE = Path(__file__).resolve().parents[1]
ROOT = STAGE if (STAGE / "pyproject.toml").is_file() else STAGE.parents[2]
sys.path.insert(0, str(STAGE / "scripts"))
from plan_phase10 import make_plan


def client(variant):
    def native(events, query):
        return {"valid": True, "reason": "continuous_authorization", "rule_hash": RULE_HASH,
                "decision_id": "synthetic-native-response", "query": query}
    return PersistentAblationAuthority(Mock(), VersionedS3(), ablation_id=variant, table_name=TABLE,
        bucket="pcfl-test", run_id="test-run", template=TEMPLATE, model_schema_hash=SCHEMA_HASH,
        policy_evaluator=native, rule_hash=RULE_HASH)


class AblationBoundaryTests(unittest.TestCase):
    def test_receipt_ablation_has_no_fake_native_decision_and_commit_remains_full_interval(self):
        authority = client("Abl-1")
        receipt = authority._authorization({"events": []}, "org_01", 10, 20, stage="receipt")
        self.assertIsNone(receipt["decision_id"])
        self.assertEqual(authority.native_policy_calls, 0)
        final = authority._authorization({"events": []}, "org_01", 10, 30, stage="publication")
        self.assertEqual(final["query"]["start_order"], 10)
        self.assertEqual(authority.native_policy_calls, 1)

    def test_current_state_ablation_sends_actual_point_query(self):
        authority = client("Abl-4")
        response = authority._authorization({"events": []}, "org_01", 10, 30, stage="publication")
        self.assertEqual(response["query"]["start_order"], 30)
        self.assertEqual(response["query"]["commit_order"], 30)
        self.assertEqual(authority.authorization_trace[-1]["actual_query"], response["query"])

    def request(self, authority):
        context = authority._candidate_context({k: v for k, v in candidate().items() if k != "candidate_id"})
        context["candidate_id"] = digest(context)
        return authority._publication_request(run_id="test-run", round_id="round-1", txn_id="publication-1",
            candidate=context, expected_audit_count=0, expected_audit_head="0" * 64)

    def test_epoch_ablation_retains_real_global_clock_CAS_and_structural_pointer(self):
        authority = client("Abl-2")
        request = self.request(authority)
        with patch.object(PersistentAuthority, "_transact", return_value={}) as parent:
            authority._transact(request, "publication-1")
        actual = parent.call_args.args[0]
        self.assertEqual(authority.transaction_trace[-1]["contributor_epoch_checks"], 0)
        sequence = next(a["Update"] for a in actual["TransactItems"] if a.get("Update", {}).get("Key", {}).get("PK") == {"S": "AUTHORITY"})
        self.assertEqual(sequence["ConditionExpression"], "#ord = :expected")
        self.assertTrue(any(a.get("Update", {}).get("Key", {}).get("SK") == {"S": "POINTER"} for a in actual["TransactItems"]))

    def test_audit_ablation_removes_persistence_and_labels_atomic_outcome(self):
        authority = client("Abl-3")
        request = self.request(authority)
        with patch.object(PersistentAuthority, "_transact", return_value={}) as parent:
            authority._transact(request, "publication-1")
        actual = parent.call_args.args[0]
        self.assertEqual(authority.transaction_trace[-1]["persistent_audit_actions"], 0)
        outcome = next(a["Put"]["Item"] for a in actual["TransactItems"] if a.get("Put", {}).get("Item", {}).get("record_type") == {"S": "transaction_outcome"})
        result = json.loads(outcome["result_json"]["S"])
        self.assertEqual(result["audit_persistence"], "omitted-by-Abl-3")
        self.assertNotIn("audit_head", result)

    def test_all_variant_fingerprints_have_explicit_partial_labels(self):
        for variant in VARIANTS:
            authority = client(variant)
            request = self.request(authority)
            record = next(a["Put"]["Item"] for a in request["TransactItems"] if a.get("Put", {}).get("Item", {}).get("record_type") == {"S": "publication_manifest"})
            candidate_record = json.loads(record["manifest_json"]["S"])["candidate"]
            self.assertFalse(candidate_record["full_protocol"])
            self.assertEqual(candidate_record["ablation_id"], variant)
            self.assertEqual(candidate_record["candidate_id"], digest({k: v for k, v in candidate_record.items() if k != "candidate_id"}))

    def test_future_cloud_registry_is_unrun_and_validation_only(self):
        result = make_plan(json.loads((ROOT / "experiments/locked_plan.json").read_text()))
        self.assertEqual(len(result["ablation_cells"]), 40)
        self.assertEqual(len(result["targeted_cells"]), 50)
        self.assertEqual(result["actual_AWS_trials_executed"], 0)
        self.assertTrue(all(c["status"] == "not_run" and c["evaluation_split"] == "validation" for c in result["ablation_cells"] + result["targeted_cells"]))


if __name__ == "__main__":
    unittest.main()
