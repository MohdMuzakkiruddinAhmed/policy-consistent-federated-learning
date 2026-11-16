"""Independent synthetic observer evidence; no cloud, clocks or clinical rows."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from pcfl.analysis import analyze_registry
from pcfl.experiments import derive_verified_metrics, validate_attempt, validate_revocation_response
from pcfl.runtime_verify import verify_case, verify_runtime_observations
from pcfl.oracle import evaluate_interval
from test_experiments import example_attempt, example_plan
from test_runtime_verify import fixture, json_hash
from test_schemas import validate as validate_schema, ShapeError


def observed_fixture(*, rejection=None, revoke=True, regrant=False):
    rules = [{"purpose": "readmission", "action": action, "effect": "allow"}
             for action in ("train", "submit_update", "aggregate")]
    history = [{"event_id": f"grant-{number}", "org_id": f"org_{number:02d}", "kind": "GRANT", "order": number,
                "epoch": 1, "rules": deepcopy(rules)} for number in (1, 2)]
    if revoke:
        history.append({"event_id": "revoke-1", "org_id": "org_01", "kind": "REVOKE", "order": 8, "epoch": 2, "rules": []})
    if regrant:
        history.append({"event_id": "regrant-1", "org_id": "org_01", "kind": "GRANT", "order": 9, "epoch": 3, "rules": deepcopy(rules)})
    tasks = [{"task_id": f"task-{number}", "update_id": f"update-{number}", "org_id": f"org_{number:02d}",
              "round_id": "round-1", "issue_order": number + 2, "start_order": number + 3} for number in (1, 2)]
    updates = [{**task, "purpose": "readmission"} for task in tasks]
    members = ["update-2"] if rejection else ["update-1", "update-2"]
    manifest = {"manifest_id": "a" * 64, "round_id": "round-1", "included_update_ids": members, "commit_order": 11}
    decisions = {task["update_id"]: {"outcome": "rejected" if rejection and task["org_id"] == "org_01" else "accepted",
        "evaluation_order": 10 if rejection == "receipt" and task["org_id"] == "org_01" else 11} for task in tasks}
    ops = []
    def op(kind, start, end, outcome, task=None, **extra):
        record = {"sequence": len(ops) + 1, "operation": kind, "round_id": "round-1", "org_id": None,
            "task_id": None, "update_id": None, "start_ms": start, "end_ms": end, "outcome": outcome,
            "observation_order": None, "manifest_id": None, "included_update_ids": [], "excluded_update_ids": [], "pending_update_ids": []}
        if task:
            record.update({name: task[name] for name in ("org_id", "task_id", "update_id")})
        record.update(extra); ops.append(record)
    for index, task in enumerate(tasks):
        op("issue", 10 + index * 10, 15 + index * 10, "issued", task, observation_order=task["issue_order"])
    op("receive", 70, 80, "rejected" if rejection == "receipt" else "pending", tasks[0])
    op("receive", 81, 85, "pending", tasks[1])
    op("publish", 90, 100, "published", observation_order=11, manifest_id=manifest["manifest_id"], included_update_ids=members,
       excluded_update_ids=["update-1"] if rejection else [], pending_update_ids=["update-2"] if rejection == "receipt" else ["update-1", "update-2"])
    windows = [{**{name: event[name] for name in ("event_id", "org_id", "kind", "order", "epoch")}, "round_id": "round-1",
        "phase": "after_dispatch", "status": "bracketed-new-commit", "signal_start_ms": 50, "observed_end_ms": 60}
        for event in history if event["kind"] == "REVOKE"]
    return {"tasks": tasks, "updates": updates, "policy_events": history, "decisions": decisions, "published_manifests": [manifest],
        "runtime_observations": {"schema_version": "0.1.0", "clock": "coordinator-perf-counter-relative-ms", "run_id": "local-runtime",
            "policy_windows": windows, "operations": ops, "errors": [], "stages": [
                {"sequence": 1, "name": "publication", "round_id": "round-1", "start_ms": 90, "end_ms": 100, "status": "complete"},
                {"sequence": 2, "name": "run", "round_id": None, "start_ms": 0, "end_ms": 120, "status": "complete"}]}}


def persistent_observed_fixture(*, rejection=None, baseline="P1", ablation=None):
    """Synthetic wire proofs independently bind receipt and final policy queries."""
    raw = observed_fixture(rejection=rejection)
    run, rule = "synthetic-persistent-observer", "d" * 64
    raw.update(authority_backend="dynamodb-s3-opa", persistent_run_id=run, baseline_id=baseline, policy_rule_hash=rule)
    if ablation: raw["ablation_id"] = ablation
    trace = raw["runtime_observations"]; trace["run_id"] = run
    window = trace["policy_windows"][0]
    if rejection == "publication":
        window.update(phase="before_commit", signal_start_ms=95, observed_end_ms=98, order=9)
        raw["policy_events"][-1]["order"] = 9
        received_orders, final_order = (7, 8), 11
    else:
        received_orders, final_order = (9, 11), 12
    request = "scenario-" + json_hash([run, window["phase"], window["round_id"], 0, window["org_id"], window["kind"]])[:48]
    identity = "policy-" + hashlib.sha256(request.encode()).hexdigest()[:40]
    raw["policy_events"][-1]["event_id"] = identity; window["event_id"] = identity
    raw["published_manifests"][0]["commit_order"] = final_order
    trace["operations"][-1]["observation_order"] = final_order
    rows = []
    def wire_response(query, label):
        past = [event for event in raw["policy_events"] if event["order"] <= query["commit_order"]]
        verdict = evaluate_interval(raw["policy_events"], query)
        return {"valid": verdict["valid"], "reason": "continuous_authorization" if verdict["valid"] else "synthetic-denial",
            "invalid_order": verdict["invalid_order"], "query": deepcopy(query), "decision_id": "synthetic-" + label,
            "rule_hash": rule, "protocol_revision": "pcfl-interval-v1", "opa_version": "1.22.3",
            "request_binding": "synthetic-binding-" + label, "history_digest": json_hash(past),
            "request_hash": json_hash({"events": past, "query": query})}
    for number, (task, update, received) in enumerate(zip(raw["tasks"], raw["updates"], received_orders), 1):
        task.update(purpose="readmission", nonce_digest="c" * 64)
        if number == 2:
            task.update(issue_order=5, start_order=6)
            update.update(issue_order=5, start_order=6)
            trace["operations"][1]["observation_order"] = 5
        update["received_order"] = received
        decision = raw["decisions"][update["update_id"]]
        decision.update(evaluation_order=10 if rejection in {"receipt", "publication"} and number == 1 else final_order,
                        reason="authorization_interrupted" if decision["outcome"] == "rejected" else "continuous_authorization")
        query = {"org_id": task["org_id"], "purpose": "readmission", "actions": ["train", "submit_update", "aggregate"],
            "start_order": received if ablation == "Abl-4" else task["start_order"], "commit_order": received}
        receipt = wire_response(query, "receipt-" + str(number))
        if baseline != "P1":
            query.update(start_order=task["issue_order"] - 1, commit_order=task["issue_order"] - 1)
            source = wire_response(query, "dispatch-" + str(number))
            if baseline == "B1":
                source = {"valid": True, "reason": "baseline_no_policy_check", "decision_id": None,
                          "query": None, "policy_decision_mode": "none", "rule_hash": rule}
            receipt = deepcopy(source)
            issued = {**task, "start_order": None}
            rows.append({"PK": "RUN#" + run, "SK": "ISSUE#" + task["task_id"], "task_json": json.dumps(issued),
                         "nonce_digest": task["nonce_digest"], "opa_decision_json": json.dumps(source)})
            if baseline == "B2":
                rows.append({"PK": "RUN#" + run, "SK": "ADMISSION#" + task["org_id"], "opa_decision_json": json.dumps(source)})
        elif ablation == "Abl-1":
            receipt = {"valid": True, "reason": "Abl-1_receipt_check_omitted", "decision_id": None,
                       "query": None, "rule_hash": rule, "native_policy_checked": False}
        rows.append({"PK": "RUN#" + run, "SK": "UPDATE_META#" + update["update_id"], "opa_decision_json": json.dumps(receipt)})
        if baseline == "P1":
            query = {"org_id": task["org_id"], "purpose": "readmission", "actions": ["train", "submit_update", "aggregate"],
                "start_order": decision["evaluation_order"] if ablation == "Abl-4" else task["start_order"],
                "commit_order": decision["evaluation_order"]}
            rows.append({"PK": "RUN#" + run, "SK": "OPA_FINAL#" + update["update_id"],
                         "opa_decision_json": json.dumps(wire_response(query, "final-" + str(number)))})
    raw["durable_evidence"] = {"run_records": rows, "sequence": {"order": final_order}}
    return raw


class ObserverVerificationTests(unittest.TestCase):
    def response(self, raw):
        result = verify_runtime_observations(raw)
        self.assertTrue(validate_revocation_response(result["revocation_response"]))
        return result["revocation_response"]

    def test_receipt_enforcement_is_bound_interval_not_point(self):
        value = self.response(observed_fixture(rejection="receipt"))
        self.assertEqual(value["status"], "measured")
        event = value["events"][0]
        self.assertEqual((event["response_lower_ms"], event["response_upper_ms"]), (10, 30))
        self.assertEqual((event["event_id"], event["update_id"], event["operation"], event["enforcement_order"]), ("revoke-1", "update-1", "receive", 10))
        self.assertIsNone(event["exact_response_ms"])

    def test_commit_enforcement_requires_actual_pending_before_exclusion(self):
        raw = observed_fixture(rejection="publication")
        event = self.response(raw)["events"][0]
        self.assertEqual((event["operation"], event["response_lower_ms"], event["response_upper_ms"]), ("publish", 30, 50))
        raw["runtime_observations"]["operations"][-1]["pending_update_ids"] = ["update-2"]
        with self.assertRaisesRegex(ValueError, "pending_before"):
            self.response(raw)

    def test_unsafe_baseline_is_right_censored_with_independent_violation(self):
        raw = observed_fixture()
        result = verify_runtime_observations(raw)
        event = self.response(raw)["events"][0]
        self.assertEqual((event["status"], event["censor_lower_ms"], event["censor_upper_ms"]), ("right-censored", 60, 70))
        self.assertIsNone(event["operation"])
        self.assertEqual(result["oracle_post_authorization_loss_invalid_publications"], 1)

    def test_regrant_does_not_erase_old_task_interval_denial(self):
        event = self.response(observed_fixture(rejection="receipt", regrant=True))["events"][0]
        self.assertEqual(event["status"], "measured")
        self.assertEqual(event["enforcement_order"], 10)

    def test_denied_dispatch_binds_real_selection_and_null_task_identity(self):
        raw = observed_fixture()
        raw["selection"] = [{"org_id": "org_01", "round_id": "round-2", "selected": False, "order": 12}]
        denied = {**deepcopy(raw["runtime_observations"]["operations"][0]), "sequence": 6, "round_id": "round-2", "task_id": None,
            "update_id": None, "start_ms": 110, "end_ms": 115, "outcome": "denied", "observation_order": 12}
        raw["runtime_observations"]["operations"].append(denied)
        event = self.response(raw)["events"][0]
        self.assertEqual((event["operation"], event["response_lower_ms"], event["response_upper_ms"]), ("issue", 50, 65))
        self.assertIsNone(event["task_id"])
        denied["observation_order"] = 11
        with self.assertRaisesRegex(ValueError, "selection_binding"): self.response(raw)

    def test_persistent_window_cannot_relabel_actual_event_to_another_barrier(self):
        raw = persistent_observed_fixture(baseline="B1")
        trace = raw["runtime_observations"]
        window = trace["policy_windows"][0]
        self.assertEqual(self.response(raw)["status"], "right-censored")
        window["round_id"] = "round-2"
        with self.assertRaisesRegex(ValueError, "barrier_identity"): self.response(raw)

    def test_unrelated_policy_change_is_explicit_no_event(self):
        raw = observed_fixture(revoke=False)
        raw["policy_events"].append({**deepcopy(raw["policy_events"][0]), "event_id": "change-1", "kind": "CHANGE", "order": 8, "epoch": 2})
        result = self.response(raw)
        self.assertEqual((result["status"], result["opportunity_events"]), ("no-event", 0))

    def test_replay_missing_operation_and_observer_error_are_missing_not_censored(self):
        for change in ("replay", "coverage", "error", "window"):
            raw = observed_fixture()
            trace = raw["runtime_observations"]
            if change == "replay": trace["policy_windows"][0].update(status="preexisting-or-replayed", signal_start_ms=None, observed_end_ms=None)
            if change == "coverage":
                trace["operations"].pop(0)
                for sequence, operation in enumerate(trace["operations"], 1): operation["sequence"] = sequence
            if change == "error": trace["errors"].append({"source": "policy-read", "round_id": "round-1", "event_id": "revoke-1", "error_type": "OSError"})
            if change == "window": trace["policy_windows"] = []
            self.assertEqual(self.response(raw)["status"], "missing", change)
        raw = observed_fixture(); raw.pop("runtime_observations")
        result = self.response(raw)
        self.assertIsNone(result["opportunity_events"])

    def test_forged_event_task_manifest_clock_and_durable_denial_fail(self):
        mutations = [lambda t: t["policy_windows"][0].update(epoch=99), lambda t: t.update(run_id="another-run"),
            lambda t: t["operations"][2].update(update_id="another-update"),
            lambda t: t["operations"][-1].update(included_update_ids=["update-1"]),
            lambda t: t["operations"][2].update(start_ms=1),
            lambda t: t["policy_windows"][0].update(signal_start_ms=float("nan")),
            lambda t: t["operations"][3].update(outcome="rejected")]
        for mutate in mutations:
            raw = observed_fixture(rejection="receipt")
            mutate(raw["runtime_observations"])
            with self.assertRaises(ValueError): self.response(raw)

    def test_operational_error_is_not_authorization_denial(self):
        raw = observed_fixture()
        raw.update(updates=[], decisions={}, published_manifests=[], attempt_failures=[{"update_id": "update-1", "outcome": "error"}])
        trace = raw["runtime_observations"]
        trace["operations"] = trace["operations"][:2] + [{**trace["operations"][2], "sequence": 3, "operation": "fail", "outcome": "error"}]
        self.assertEqual(self.response(raw)["status"], "right-censored")

    def test_native_receipt_denial_cannot_be_relabelled_pending_then_publication_rejection(self):
        raw = persistent_observed_fixture(rejection="receipt")
        original = self.response(raw)["events"][0]
        self.assertEqual((original["operation"], original["response_lower_ms"], original["response_upper_ms"]), ("receive", 10, 30))
        raw["runtime_observations"]["operations"][2]["outcome"] = "pending"
        raw["runtime_observations"]["operations"][-1]["pending_update_ids"] = ["update-1", "update-2"]
        with self.assertRaisesRegex(ValueError, "contradicts_durable_policy_denial"):
            self.response(raw)

    def test_native_publication_mutation_inside_call_keeps_zero_lower_bound(self):
        raw = persistent_observed_fixture(rejection="publication")
        event = self.response(raw)["events"][0]
        self.assertEqual((event["operation"], event["response_lower_ms"], event["response_upper_ms"], event["enforcement_order"]), ("publish", 0, 5, 10))
        receipt = next(row for row in raw["durable_evidence"]["run_records"] if row["SK"] == "UPDATE_META#update-1")
        payload = json.loads(receipt["opa_decision_json"])
        payload["query"]["commit_order"] += 1
        receipt["opa_decision_json"] = json.dumps(payload)
        with self.assertRaisesRegex(ValueError, "opa_response_binding"):
            self.response(raw)

    def test_baseline_cached_modes_and_omitted_receipt_ablation_never_invent_native_receipt_checks(self):
        for baseline in ("B1", "B2", "B3"):
            with self.subTest(baseline=baseline):
                raw = persistent_observed_fixture(baseline=baseline)
                self.assertEqual(self.response(raw)["status"], "right-censored")
        raw = persistent_observed_fixture(rejection="publication", ablation="Abl-1")
        self.assertEqual(self.response(raw)["events"][0]["operation"], "publish")
        receipt = next(row for row in raw["durable_evidence"]["run_records"] if row["SK"] == "UPDATE_META#update-1")
        payload = json.loads(receipt["opa_decision_json"]); payload["native_policy_checked"] = True
        receipt["opa_decision_json"] = json.dumps(payload)
        with self.assertRaisesRegex(ValueError, "omitted_receipt_policy_binding"):
            self.response(raw)

    def test_prior_operational_finalization_cannot_be_new_publication_authorization_denial(self):
        raw = observed_fixture(rejection="publication")
        raw["decisions"]["update-1"]["reason"] = "client_artifact_failure"
        operations = raw["runtime_observations"]["operations"]
        failure = {**deepcopy(operations[2]), "operation": "fail", "start_ms": 86, "end_ms": 87, "outcome": "rejected"}
        operations.insert(4, failure)
        for sequence, op in enumerate(operations, 1): op["sequence"] = sequence
        self.assertEqual(self.response(raw)["status"], "right-censored")
        replay = {**deepcopy(operations[2]), "start_ms": 88, "end_ms": 89, "outcome": "pending"}
        operations.insert(5, replay)
        for sequence, op in enumerate(operations, 1): op["sequence"] = sequence
        with self.assertRaisesRegex(ValueError, "reopens_finalized"):
            self.response(raw)

    def test_duplicate_pending_before_finalization_preserves_publication_response_and_coverage(self):
        raw = persistent_observed_fixture(rejection="publication", ablation="Abl-1")
        operations = raw["runtime_observations"]["operations"]
        duplicate = {**deepcopy(operations[2]), "start_ms": 86, "end_ms": 88}
        operations.insert(4, duplicate)
        for sequence, op in enumerate(operations, 1): op["sequence"] = sequence
        result = self.response(raw)
        self.assertTrue(result["operation_coverage_complete"])
        self.assertEqual(result["events"][0]["operation"], "publish")

    def test_full_independent_case_includes_optional_observer_and_metrics(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            raw = fixture(directory)
            observed = observed_fixture(revoke=False)["runtime_observations"]
            for operation in observed["operations"]:
                if operation["operation"] == "issue": operation["observation_order"] = next(task["issue_order"] for task in raw["tasks"] if task["task_id"] == operation["task_id"])
                if operation["operation"] == "publish": operation.update(manifest_id=raw["published_manifests"][0]["manifest_id"], observation_order=10)
            raw["runtime_observations"] = observed
            raw["rounds"] = [{"duration_seconds": .12, "publication_seconds": .009}]
            path = directory / "runtime_result.json"; path.write_text(json.dumps(raw))
            summary = verify_case(path)
            self.assertTrue(summary["runtime_observations_verified"])
            metrics, sources = derive_verified_metrics(raw, summary)
            self.assertEqual(metrics["revocation_response"]["status"], "no-event")
            self.assertEqual(metrics["latency_ms"]["publication"], [10])
            self.assertIn("revocation_response", sources)

    def test_strict_registry_object_rejects_false_scalar_counts_and_rows(self):
        plan = example_plan(); row = example_attempt(plan)
        row["metrics"]["revocation_response"] = self.response(observed_fixture(rejection="receipt"))
        self.assertTrue(validate_attempt(plan, row))
        for mutate in (lambda v: v.update(exact_response_ms=20), lambda v: v.update(measured_events=2),
                       lambda v: v["events"][0].update(response_lower_ms=40), lambda v: v.update(labels=[1])):
            bad = deepcopy(row); mutate(bad["metrics"]["revocation_response"])
            with self.assertRaises(ValueError): validate_attempt(plan, bad)

    def test_strict_summary_schemas_support_both_roles_and_reject_row_data_and_scalar_lags(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); raw = fixture(directory)
            path = directory / "runtime_result.json"; path.write_text(json.dumps(raw))
            summary = verify_case(path)
        response = self.response(observed_fixture(rejection="receipt"))
        summary.update(runtime_observations_verified=True, revocation_response=response,
            runtime_stage_latency_ms={"publication": [10], "evaluation": [2]}, oracle_post_authorization_loss_invalid_publications=0)
        # Fixture's intentionally minimal utility is immaterial to this shape test.
        summary["validation_metrics"] = None
        test_summary = {key: value for key, value in summary.items() if key != "validation_metrics"}
        test_summary.update(test_metrics={"count": 2, "positive_count": 1, "prevalence": .5, "auroc": .5, "auprc": .5,
            "precision": .5, "recall": .5, "f1": .5, "threshold": .5, "loss": .7}, evaluation_split="test", final_holdout_authorization_verified=True,
            accepted_plan_digest="a" * 64, holdout_authorization_digest="b" * 64, cell_id="synthetic-cell",
            persistent_protocol_verified=True, committed_evaluation_response_verified=True)
        for name, value in (("metric-record", summary), ("metric-test-record", test_summary)):
            validate_schema(name, value)
            for mutate in (lambda v: v["revocation_response"].update(exact_response_ms=12),
                           lambda v: v["revocation_response"]["events"][0].update(labels=[1]),
                           lambda v: v["revocation_response"]["events"][0].update(status="right-censored"),
                           lambda v: v["runtime_stage_latency_ms"].update(patient_id=[1])):
                bad = deepcopy(value); mutate(bad)
                with self.assertRaises(ShapeError): validate_schema(name, bad)

    def test_analysis_keeps_event_intervals_and_censor_denominators(self):
        plan = example_plan(); attempts = []
        for index, raw in enumerate((observed_fixture(rejection="receipt"), observed_fixture(), observed_fixture(revoke=False))):
            row = example_attempt(plan, identity=f"timing-{index}")
            row["metrics"]["revocation_response"] = self.response(raw); attempts.append(row)
        missing = example_attempt(plan, identity="timing-missing"); attempts.append(missing)
        report = analyze_registry(plan, attempts)
        baseline = plan["primary_cells"][0]["baseline_id"]
        value = next(row for row in report["tables"]["responsiveness"] if row["baseline_id"] == baseline)
        self.assertEqual((value["measured_events"], value["right_censored_events"], value["no_event_attempts"], value["missing_trace_attempts"]), (1, 1, 1, 1))
        self.assertIsNone(value["opportunity_events"])
        self.assertEqual(value["observed_upper_bound_p95_ms"], 30)
        self.assertIsNone(value["exact_response_ms"])
        self.assertEqual(len(report["tables"]["responsiveness_intervals"]), 2)
        self.assertTrue(all(value["verdict"] == "inconclusive" for value in report["hypotheses"].values()))


if __name__ == "__main__": unittest.main()
