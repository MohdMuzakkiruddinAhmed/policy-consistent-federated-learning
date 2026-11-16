"""Independent synthetic final-error/indeterminate accounting fixtures."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from pcfl.runtime_verify import verify_case
from test_runtime_verify import persistent_fixture


def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def native_response(evidence, org, order, identity):
    query = {"org_id": org, "purpose": "readmission", "start_order": order, "commit_order": order,
             "actions": ["train", "submit_update", "aggregate"]}
    past = [event for event in evidence["policy_events"] if event["order"] <= order]
    return {"valid": True, "reason": "continuous_authorization", "invalid_order": None,
        "query": query, "decision_id": identity, "request_binding": "binding-" + identity,
        "request_hash": hashed({"events": past, "query": query}), "history_digest": hashed(past),
        "rule_hash": evidence["policy_rule_hash"], "opa_version": "1.22.3", "protocol_revision": "pcfl-interval-v1"}


def error_fixture(directory, *, unfinalized=False):
    evidence = persistent_fixture(directory)
    run = evidence["persistent_run_id"]
    rows = evidence["durable_evidence"]["run_records"]
    org_event = next(event for event in evidence["policy_events"] if event["org_id"] == "org_03")
    task = {"task_id": "task-error", "update_id": "update-error", "org_id": "org_03", "node_id": 103,
        "round_id": "round-1", "purpose": "readmission", "issue_order": 13, "start_order": 14,
        "policy_epoch": 1, "policy_hash": hashed(org_event), "model_schema_hash": evidence["model_schema_hash"], "nonce_digest": "d" * 64}
    evidence["tasks"].append(task)
    issued = {key: value for key, value in task.items() if key != "nonce_digest"}; issued["start_order"] = None
    rows.extend([{"PK": "RUN#" + run, "SK": "ISSUE#task-error", "status": "ACKNOWLEDGED", "task_json": json.dumps(issued),
                  "nonce_digest": task["nonce_digest"], "opa_decision_json": json.dumps(native_response(evidence, "org_03", 12, "native-error-issue"))},
                 {"PK": "RUN#" + run, "SK": "TASK#task-error", "status": "ACKNOWLEDGED", **task,
                  "opa_decision_json": json.dumps(native_response(evidence, "org_03", 14, "native-error-ack"))}])
    error = {key: task[key] for key in ("task_id", "update_id", "org_id", "round_id", "purpose", "start_order")}
    error.update(run_id=run, outcome="error", reason="synthetic_client_crash", evaluation_order=17, observed_epoch=1,
        history_digest=hashed([org_event]), history_digest_scope="organization", manifest_ref=None,
        rule_bundle_hash=evidence["policy_rule_hash"], authorization_status="not_evaluated_operational_error",
        policy_decision_id=None, policy_query=None)
    evidence["attempt_failures"] = [error]
    rows.extend([{"PK": "RUN#" + run, "SK": "ATTEMPT#task-error", "decision_json": json.dumps(error)},
                 {"PK": "RUN#" + run, "SK": "TXN#error-transaction", "record_type": "transaction_outcome", "operation_kind": "attempt_error",
                  "order": 17, "request_digest": "7" * 64, "result_json": json.dumps({"update_id": error["update_id"], "outcome": "error"})}])
    if unfinalized:
        pending = {**issued, "task_id": "task-unfinalized", "update_id": "update-unfinalized", "org_id": "org_04", "node_id": 104,
                   "issue_order": 18, "policy_hash": hashed(next(e for e in evidence["policy_events"] if e["org_id"] == "org_04"))}
        rows.append({"PK": "RUN#" + run, "SK": "ISSUE#task-unfinalized", "status": "ISSUED", "task_json": json.dumps(pending),
                     "nonce_digest": "e" * 64, "opa_decision_json": json.dumps(native_response(evidence, "org_04", 17, "native-unfinalized-issue"))})
    rebuild_audit(evidence)
    return evidence


def rebuild_audit(evidence, *, include_errors=True):
    errors = evidence.get("attempt_failures", [])
    payloads = ([*errors] if include_errors else []) + [evidence["decisions"][uid] for uid in sorted(evidence["decisions"])]
    previous = "0" * 64; audits = []
    for sequence, payload in enumerate(payloads, 1):
        record = {"sequence": sequence, "prev_hash": previous, "payload": payload}
        previous = hashed(record); audits.append({**record, "event_hash": previous})
    evidence["audit"] = audits; evidence["anchor"] = {"count": len(audits), "head": previous}
    rows = evidence["durable_evidence"]["run_records"]
    rows[:] = [row for row in rows if not row["SK"].startswith("AUDIT#")]
    run_pk = "RUN#" + evidence["persistent_run_id"]
    rows.extend({"PK": run_pk, "SK": f"AUDIT#{event['sequence']:020d}", "record_type": "audit_event",
                 "event_json": json.dumps(event), "event_hash": event["event_hash"]} for event in audits)
    for row in rows:
        if row["SK"] == "AUDIT_HEAD":
            row.update(evidence["anchor"])
        elif row["SK"] == "ATTEMPT#task-error":
            row["decision_json"] = json.dumps(errors[0])
        elif row["SK"] == "TXN#publication-1":
            result = json.loads(row["result_json"]); result.update(audit_count=len(audits), audit_head=previous)
            row["result_json"] = json.dumps(result)


class RuntimeErrorAccountingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name); self.path = self.directory / "runtime_result.json"

    def write(self, evidence):
        self.path.write_text(json.dumps(evidence, allow_nan=False))
        return self.path

    def test_durable_error_without_received_arrays_is_counted_and_audited(self):
        result = verify_case(self.write(error_fixture(self.directory)))
        expected = {"assigned_tasks": 3, "acknowledged_tasks": 3, "unique_presented_updates": 2,
            "final_update_decisions": 2, "final_operational_errors": 1, "final_decisions": 3,
            "indeterminate_tasks": 0, "audited_final_decisions": 3, "audit_complete_decisions": 3}
        self.assertEqual({key: result[key] for key in expected}, expected)

    def test_issued_unfinalized_task_is_reported_as_indeterminate(self):
        result = verify_case(self.write(error_fixture(self.directory, unfinalized=True)))
        self.assertEqual(result["assigned_tasks"], 4)
        self.assertEqual(result["acknowledged_tasks"], 3)
        self.assertEqual(result["indeterminate_tasks"], 1)
        self.assertEqual(result["final_operational_errors"], 1)
        self.assertEqual(result["final_decisions"], 3)

    def test_error_audit_cannot_be_omitted_by_using_presented_updates_denominator(self):
        evidence = error_fixture(self.directory); rebuild_audit(evidence, include_errors=False)
        with self.assertRaises(ValueError):
            verify_case(self.write(evidence))

    def test_coherent_error_record_with_wrong_run_rule_history_or_native_query_rejects(self):
        for field, value in (("run_id", "different-run"), ("rule_bundle_hash", "0" * 64),
                             ("history_digest", "0" * 64), ("policy_query", {"org_id": "org_03"})):
            with self.subTest(field=field):
                evidence = error_fixture(self.directory)
                evidence["attempt_failures"][0][field] = value; rebuild_audit(evidence)
                with self.assertRaises(ValueError):
                    verify_case(self.write(evidence))

    def test_missing_or_rebound_error_transaction_outcome_rejects(self):
        for mode in ("missing", "wrong-order", "wrong-update"):
            with self.subTest(mode=mode):
                evidence = error_fixture(self.directory)
                rows = evidence["durable_evidence"]["run_records"]
                row = next(row for row in rows if row["SK"] == "TXN#error-transaction")
                if mode == "missing": rows.remove(row)
                elif mode == "wrong-order": row["order"] = 18
                else: row["result_json"] = json.dumps({"update_id": "another-update", "outcome": "error"})
                with self.assertRaises(ValueError):
                    verify_case(self.write(evidence))


if __name__ == "__main__":
    unittest.main()
