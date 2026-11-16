"""Synthetic HOST semantic checks; no authority/model mutations or AWS calls."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "pyproject.toml").is_file())
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests"), str(ROOT / "src")]
import assess_pilots as assessor
from test_assess_pilots import sufficient_facts


def fixture(root, kind="opa_transport_unavailable"):
    app, cell, run = "synthetic-safety-app", "synthetic-S8-296", "synthetic-run"
    runtime = {"baseline_id": "P1", "scenario_id": "S8", "seed": 296, "scripted_fault": kind,
        "persistent_run_id": run, "rounds": 5, "validation_source_sha256": "a" * 64,
        "training": {"num_rounds": 5, "development_evaluation_split": "validation",
            "final_test_access_permitted": False, "confirmatory_frozen": False}}
    reason = "policy_evaluator_unavailable_or_invalid_response" if kind.startswith("opa") else "transaction_not_confirmed"
    raw = {"successful": False, "baseline_id": "P1", "scenario_id": "transport_fault", "seed": 296,
        "scripted_fault": kind, "reason": reason, "persistent_run_id": run, "cloud_campaign_id": app,
        "cell_id": cell, "validation_source_sha256": "a" * 64, "anchor": {"count": 3, "head": "b" * 64},
        "fault_trace": [{"phase": "fault_armed", "kind": kind, "round_id": "round-2", "published_models_before": 1,
            "anchor_before": {"count": 1, "head": "c" * 64}},
            {"phase": "fault_failed_closed", "kind": kind, "pointer_unchanged": True, "published_models_during_fault": 0,
             "recovery_errors": [], "blocked_calls": 1, "indeterminate_tasks_before_recovery": 2,
             "anchor_before_recovery": {"count": 1, "head": "c" * 64}, "anchor_after_recovery": {"count": 3, "head": "b" * 64}}],
        "published_manifests": [{"round_id": "round-1", "included_update_ids": ["prior-accepted"]}],
        "tasks": [], "updates": [], "decisions": {}, "audit": [], "durable_evidence": {"run_records": []},
        "runtime_observations": {"operations": [{"sequence": 3, "operation": "publish", "round_id": "round-2", "outcome": "exception"}], "stages": []}}
    for number in (1, 2):
        task = {"task_id": f"task{number}", "update_id": f"update{number}", "org_id": f"org_0{number}", "round_id": "round-2"}
        decision = {**task, "outcome": "rejected", "reason": "scripted_transport_fault_round_aborted", "manifest_ref": None,
            "policy_decision_id": f"native{number}"}
        raw["tasks"].append(task); raw["updates"].append(task); raw["decisions"][task["update_id"]] = decision
        raw["audit"].append({"payload": deepcopy(decision)})
        raw["durable_evidence"]["run_records"] += [{"SK": "UPDATE#" + task["update_id"], "decision_json": json.dumps(decision)},
            {"SK": "OPA_FINAL#" + task["update_id"], "opa_decision_json": json.dumps({"valid": True, "decision_id": f"native{number}"})}]
        raw["runtime_observations"]["operations"] += [{**task, "operation": "receive", "outcome": "pending", "sequence": number},
            {**task, "operation": "fail", "outcome": "rejected", "sequence": number + 3}]
    summary = {"protected_witness_verified": True, "audit_complete_for_all_final_outcomes": True,
        "attempt_accounting_complete": True, "indeterminate_count": 0, "final_deny_count": 2, "final_error_count": 0}
    image = "111111111111.dkr.ecr.us-east-1.amazonaws.com/synthetic/coordinator@sha256:" + "d" * 64
    inventory = {"foundation": {"bucket_name": "synthetic-owned-bucket"}, "image": {"reference": image}}
    plan = {"provenance": {"image_digests": {"runtime": image}, "source_files_sha256": {}}}
    for name in ("src/pcfl/flower_app.py", "src/pcfl/persistent.py", "src/pcfl/cloud_coordinator.py"):
        p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("synthetic pinned code:" + name)
        plan["provenance"]["source_files_sha256"][name] = hashlib.sha256(p.read_bytes()).hexdigest()
    scope = {"cell_id": cell, "application": app, "campaign_sha256": "e" * 64,
        "uploaded_versions": [{"kind": "campaign", "key": f"metadata/{app}/campaign.json", "version_id": "immutable-v1",
            "sha256": "e" * 64, "bucket": "synthetic-owned-bucket"}], "inventory": inventory,
        "placement_checks": {key: True for key in ("actual_image_manifest_relation", "source_snapshot_integrity",
            "snapshot_matches_current_image", "snapshot_matches_current_application", "snapshot_matches_current_config")},
        "plan": plan, "source_root": root, "partial_summary": summary}
    return raw, summary, runtime, scope


class OperationalFaultAccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.raw, self.summary, self.runtime, self.scope = fixture(Path(self.temp.name))

    def test_both_actual_failure_shapes_preserve_deny_and_error_counts(self):
        for kind in ("opa_transport_unavailable", "audit_transport_unavailable"):
            raw, summary, _, _ = fixture(Path(self.temp.name), kind)
            before = deepcopy(raw)
            proof = assessor.operational_fault_accounting(raw, summary)
            self.assertTrue(proof["verified"], proof)
            self.assertEqual((proof["final_deny_count"], proof["final_error_count"], proof["operational_abort_rejected_update_count"]), (2, 0, 2))
            self.assertEqual(raw, before)

    def test_policy_denials_or_unreceived_errors_are_not_post_receipt_aborts(self):
        for change in ("reason", "native-deny", "no-update", "not-pending"):
            raw = deepcopy(self.raw)
            if change == "reason": raw["decisions"]["update1"]["reason"] = "authorization_interrupted"
            if change == "native-deny":
                row = next(row for row in raw["durable_evidence"]["run_records"] if row["SK"] == "OPA_FINAL#update1")
                row["opa_decision_json"] = json.dumps({"valid": False, "decision_id": "native1"})
            if change == "no-update": raw["updates"].pop()
            if change == "not-pending": next(op for op in raw["runtime_observations"]["operations"] if op.get("operation") == "receive")["outcome"] = "rejected"
            self.assertFalse(assessor.operational_fault_accounting(raw, self.summary)["verified"], change)

    def test_audit_tamper_fail_order_inclusion_and_bad_recovery_fail_closed(self):
        for change in ("audit", "order", "included", "recovery", "pointer", "indeterminate"):
            raw = deepcopy(self.raw); summary = deepcopy(self.summary)
            if change == "audit": raw["audit"].pop()
            if change == "order": next(op for op in raw["runtime_observations"]["operations"] if op.get("operation") == "fail")["sequence"] = 1
            if change == "included": raw["published_manifests"][0]["included_update_ids"].append("update1")
            if change == "recovery": raw["fault_trace"][1]["recovery_errors"] = ["failure"]
            if change == "pointer": raw["fault_trace"][1]["pointer_unchanged"] = False
            if change == "indeterminate": summary["indeterminate_count"] = 1
            self.assertFalse(assessor.operational_fault_accounting(raw, summary)["verified"], change)

    def test_P7_requires_each_fault_to_have_native_error_or_verified_abort(self):
        plan, *parts = sufficient_facts()
        proof = assessor.operational_fault_accounting(self.raw, self.summary)
        for row in parts[4]:
            row["summary"].update(final_error_count=0, final_deny_count=2)
            row["operational_abort_accounting"] = proof
        checks, _, _ = assessor.derive_checks(plan, *parts, global_binding=True, errors=[])
        self.assertTrue(checks["P7_safety_audit"]["operational_errors_accounted"])
        parts[4][0].pop("operational_abort_accounting")
        checks, _, _ = assessor.derive_checks(plan, *parts, global_binding=True, errors=[])
        self.assertFalse(checks["P7_safety_audit"]["operational_errors_accounted"])

    def test_missing_raw_flag_has_explicit_exact_scope_provenance(self):
        proof = assessor.failed_validation_scope(self.runtime, self.raw, **self.scope)
        self.assertTrue(proof["verified"], proof)
        self.assertFalse(proof["test_accessed"])
        self.assertFalse(proof["raw_test_holdout_evaluated_present"])
        self.assertIsNone(proof["raw_test_holdout_evaluated"])
        self.assertEqual(proof["source"], "exact-immutable-prepared-runtime + pinned failed path")

    def test_final_holdout_test_authority_and_explicit_true_flag_are_rejected(self):
        for field in ("final_holdout", "expected_holdout", "accepted_plan", "test_metrics", "accepted_plan_digest",
                "holdout_authorization_digest", "test_source_sha256", "test_sha256"):
            runtime, raw = deepcopy(self.runtime), deepcopy(self.raw)
            runtime[field] = {"test-only": True}
            self.assertFalse(assessor.failed_validation_scope(runtime, raw, **self.scope)["verified"], field)
            runtime.pop(field); raw[field] = {"test-only": True}
            self.assertFalse(assessor.failed_validation_scope(runtime, raw, **self.scope)["verified"], field)
        self.raw["test_holdout_evaluated"] = True
        self.assertFalse(assessor.failed_validation_scope(self.runtime, self.raw, **self.scope)["verified"])

    def test_nested_evaluator_holdout_expectation_and_test_role_reject(self):
        for field, value in (("expected_holdout", {"plan_digest": "a" * 64}), ("accepted_plan", {}),
                ("holdout_authorization", {}), ("dataset_role", "test"), ("confirmatory", True)):
            runtime = deepcopy(self.runtime); runtime["evaluator"] = {field: value}
            self.assertFalse(assessor.failed_validation_scope(runtime, self.raw, **self.scope)["verified"], field)

    def test_rebound_campaign_wrong_run_missing_receipt_image_and_source_drift_reject(self):
        for change in ("sha", "run", "receipt", "version", "image", "source", "config", "later-model"):
            scope, runtime, raw = deepcopy(self.scope), deepcopy(self.runtime), deepcopy(self.raw)
            if change == "sha": scope["campaign_sha256"] = "f" * 64
            if change == "run": raw["persistent_run_id"] = "different-run"
            if change == "receipt": scope["uploaded_versions"] = []
            if change == "version": scope["uploaded_versions"][0]["version_id"] = "null"
            if change == "image": scope["inventory"]["image"]["reference"] += "wrong"
            if change == "source": scope["plan"]["provenance"]["source_files_sha256"]["src/pcfl/flower_app.py"] = "f" * 64
            if change == "config": scope["placement_checks"]["snapshot_matches_current_config"] = False
            if change == "later-model": raw["published_manifests"].append({"round_id": "round-5"})
            self.assertFalse(assessor.failed_validation_scope(runtime, raw, **scope)["verified"], change)

    def test_validation_only_training_and_round_two_failure_path_required(self):
        for change in ("split", "permission", "frozen", "rounds", "fault-round", "final-test-stage", "generic-evaluation-stage"):
            runtime, raw = deepcopy(self.runtime), deepcopy(self.raw)
            if change == "split": runtime["training"]["development_evaluation_split"] = "test"
            if change == "permission": runtime["training"]["final_test_access_permitted"] = True
            if change == "frozen": runtime["training"]["confirmatory_frozen"] = True
            if change == "rounds": runtime["rounds"] = 2
            if change == "fault-round": raw["fault_trace"][0]["round_id"] = "round-5"
            if change == "final-test-stage": raw["runtime_observations"]["stages"] = [{"name": "final_test_evaluation"}]
            if change == "generic-evaluation-stage": raw["runtime_observations"]["stages"] = [{"name": "evaluation"}]
            self.assertFalse(assessor.failed_validation_scope(runtime, raw, **self.scope)["verified"], change)

    def test_missing_unprotected_or_incomplete_partial_cannot_prove_missing_flag(self):
        for change in ("missing", "unprotected", "audit", "pending"):
            scope = deepcopy(self.scope)
            if change == "missing": scope["partial_summary"] = {}
            if change == "unprotected": scope["partial_summary"]["protected_witness_verified"] = False
            if change == "audit": scope["partial_summary"]["audit_complete_for_all_final_outcomes"] = False
            if change == "pending": scope["partial_summary"]["indeterminate_count"] = 1
            self.assertFalse(assessor.failed_validation_scope(self.runtime, self.raw, **scope)["verified"], change)
