"""Independent hand-built evidence fixtures, without Flower producer imports."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

try:
    import numpy as np
    from pcfl.runtime_verify import verify_case
    RUNTIME_AVAILABLE = True
except ImportError:
    RUNTIME_AVAILABLE = False


def json_hash(value):
    serialized = json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def parameter_hash(arrays):
    descriptors = []
    for array in arrays:
        descriptors.append({"shape": list(array.shape), "dtype": array.dtype.str,
                            "sha256": hashlib.sha256(array.tobytes(order="C")).hexdigest()})
    return json_hash(descriptors)


def checkpoint(directory, name, arrays):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        np.savez(stream, *arrays)
    return {"backend": "local_immutable_checkpoint", "path": str(path),
            "model_digest": parameter_hash(arrays),
            "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def fixture(directory, *, baseline="P1", revoked=False, model_arrays=None, epoch_values=None,
            guarded_publication=None):
    schema = "a" * 64
    rules = [{"purpose": "readmission", "action": action, "effect": "allow"}
             for action in ("train", "submit_update", "aggregate")]
    events = [{"event_id": f"grant-{number}", "org_id": f"org_{number:02d}", "order": number,
               "epoch": 1, "kind": "GRANT", "rules": deepcopy(rules)} for number in (1, 2)]
    if revoked:
        events.append({"event_id": "revoke-1", "org_id": "org_01", "order": 8,
                       "epoch": 2, "kind": "REVOKE", "rules": []})
    task_records, update_records = [], []
    local_parameters = [[np.array([1.0, 3.0], dtype=np.float32), np.array([2.0], dtype=np.float32)],
                        [np.array([5.0, 7.0], dtype=np.float32), np.array([10.0], dtype=np.float32)]]
    for number in (1, 2):
        task = {"task_id": f"task-{number}", "update_id": f"update-{number}",
                "org_id": f"org_{number:02d}", "node_id": 100 + number, "round_id": "round-1",
                "purpose": "readmission", "issue_order": number + 1, "start_order": number + 2,
                "policy_epoch": 1, "policy_hash": json_hash(events[number - 1]),
                "model_schema_hash": schema, "nonce_digest": "d" * 64}
        task_records.append(task)
        arrays = local_parameters[number - 1]
        artifact = checkpoint(directory, f"updates/update-{number}.npz", arrays)
        update_records.append({key: task[key] for key in ("task_id", "update_id", "org_id", "node_id",
                                                          "round_id", "purpose", "start_order", "model_schema_hash")})
        update_records[-1].update({"sample_count": 1 if number == 1 else 3,
                                  "weights_digest": parameter_hash(arrays), "received_order": number + 4,
                                  "artifact": artifact})
    # Hand calculation: one quarter [1,3]/[2] plus three quarters [5,7]/[10].
    published = model_arrays if model_arrays is not None else [np.array([4.0, 6.0], dtype=np.float32),
                                                              np.array([8.0], dtype=np.float32)]
    artifact = checkpoint(directory, "models/published.npz", published)
    manifest = {"round_id": "round-1", "parent_manifest_id": None,
                "model_digest": parameter_hash(published), "model_schema_hash": schema,
                "included_update_ids": ["update-1", "update-2"],
                "policy_epochs": epoch_values or {"org_01": 2 if revoked and baseline == "P1" else 1,
                                                  "org_02": 1}, "commit_order": 10,
                "artifact": artifact, "guarded_policy_publication": baseline == "P1" if guarded_publication is None else guarded_publication}
    manifest["manifest_id"] = json_hash(manifest)
    decisions, audit = {}, []
    previous = "0" * 64
    for number, task in enumerate(task_records, 1):
        decision = {key: task[key] for key in ("update_id", "task_id", "org_id", "round_id", "purpose", "start_order")}
        decision.update({"outcome": "accepted", "reason": "continuous_authorization" if baseline == "P1" else "baseline_acceptance",
                         "evaluation_order": 10, "observed_epoch": 2 if revoked and number == 1 else 1,
                         "history_digest": json_hash(events), "manifest_ref": manifest["manifest_id"]})
        decisions[task["update_id"]] = decision
        record = {"sequence": number, "prev_hash": previous, "payload": decision}
        previous = json_hash(record)
        audit.append({**record, "event_hash": previous})
    return {"successful": True, "test_holdout_evaluated": False, "baseline_id": baseline,
            "scenario_id": "mid_round" if revoked else "stable", "model_schema_hash": schema,
            "policy_events": events, "tasks": task_records, "updates": update_records,
            "decisions": decisions, "published_manifests": [manifest], "audit": audit,
            "anchor": {"count": 2, "head": previous}, "current_model_digest": parameter_hash(published),
            "validation_metrics": {"count": 4, "auroc": 0.5}}


def persistent_fixture(directory, *, bad_candidate_history=False):
    """Hand-construct durable rows and native responses without producer imports."""
    evidence = fixture(directory)
    run_id = "independent-runtime"
    pk = f"RUN#{run_id}"
    rule_hash = hashlib.sha256((Path(__file__).resolve().parents[1] / "policies/rego/pcfl.rego").read_bytes()).hexdigest()
    history = evidence["policy_events"]
    for number in range(3, 9):
        history.append({**deepcopy(history[0]), "event_id": f"grant-{number}", "org_id": f"org_{number:02d}", "order": number})
    rows, policies = [], []

    def row(sk, **fields):
        record = {"PK": pk, "SK": sk, **fields}
        rows.append(record)
        return record

    def opa(query, identity):
        past = [event for event in history if event["order"] <= query["commit_order"]]
        return {"valid": True, "reason": "continuous_authorization", "invalid_order": None,
                "query": query, "decision_id": identity, "rule_hash": rule_hash,
                "opa_version": "1.22.3", "protocol_revision": "pcfl-interval-v1",
                "request_binding": "binding-" + identity, "history_digest": json_hash(past),
                "request_hash": json_hash({"events": past, "query": query})}

    def s3_export(local, key):
        return {"backend": "s3", "bucket": "independent-model-bucket", "key": key,
                "version_id": "version-" + local["model_digest"][:12], "sha256": local["file_sha256"],
                "size_bytes": Path(local["path"]).stat().st_size, "model_digest": local["model_digest"],
                "parameters_digest": local["model_digest"],
                "local_export": {key: local[key] for key in ("path", "file_sha256", "model_digest")}}

    for number, task in enumerate(evidence["tasks"], 1):
        task.update(issue_order=7 + 2 * number, start_order=8 + 2 * number)
        query = {"org_id": task["org_id"], "purpose": "readmission", "start_order": task["start_order"],
                 "commit_order": task["start_order"], "actions": ["train", "submit_update", "aggregate"]}
        row("TASK#" + task["task_id"], **task, status="ACKNOWLEDGED", opa_decision_json=json.dumps(opa(query, f"opa-task-{number}")))
        update = evidence["updates"][number - 1]
        update.update(start_order=task["start_order"], received_order=14 + number)
        update["artifact"] = s3_export(update["artifact"], f"evidence/{run_id}/updates/{update['update_id']}.npz")
    old = evidence["published_manifests"][0]
    artifact = s3_export(old["artifact"], f"models/candidates/{run_id}/{old['model_digest']}.npz")
    candidate = {"snapshot_order": 19, "parent_manifest_id": None, "round_generation": 2,
                 "policy_epochs": {"org_01": 1, "org_02": 1},
                 "history_digests": {org: json_hash([event for event in history if event["org_id"] == org])
                                     for org in ("org_01", "org_02")},
                 "model_schema_hash": evidence["model_schema_hash"], "rule_bundle_hash": rule_hash,
                 "model_digest": artifact["sha256"],
                 "s3": {key: artifact[key] for key in ("bucket", "key", "version_id", "sha256", "size_bytes")},
                 "object_confirmation": {key: artifact[key] for key in ("version_id", "sha256", "size_bytes")},
                 "updates": [{key: update[key] for key in ("update_id", "task_id", "org_id", "purpose", "start_order", "sample_count", "weights_digest")}
                             for update in evidence["updates"]]}
    if bad_candidate_history:
        candidate["history_digests"]["org_01"] = json_hash(history)
    candidate["candidate_id"] = json_hash(candidate)
    manifest = {"manifest_id": candidate["candidate_id"], "run_id": run_id, "round_id": "round-1",
                "parent_manifest_id": None, "model_digest": artifact["model_digest"], "model_schema_hash": evidence["model_schema_hash"],
                "included_update_ids": [update["update_id"] for update in evidence["updates"]],
                "policy_epochs": candidate["policy_epochs"], "commit_order": 20, "artifact": artifact,
                "guarded_policy_publication": True, "persistent_protocol": "ddb-v1", "candidate_metadata": candidate,
                "commit_txn_id": "publication-1"}
    evidence["published_manifests"] = [manifest]
    previous, audits = "0" * 64, []
    for number, update in enumerate(evidence["updates"], 1):
        query = {"org_id": update["org_id"], "purpose": "readmission", "start_order": update["start_order"],
                 "commit_order": 20, "actions": ["train", "submit_update", "aggregate"]}
        response = opa(query, f"opa-final-{number}")
        decision = evidence["decisions"][update["update_id"]]
        decision.update(start_order=update["start_order"], evaluation_order=20, manifest_ref=manifest["manifest_id"],
                        history_digest=json_hash([event for event in history if event["org_id"] == update["org_id"]]), history_digest_scope="organization",
                        policy_decision_id=response["decision_id"], policy_query=query, rule_bundle_hash=rule_hash)
        body = {"sequence": number, "prev_hash": previous, "payload": decision}
        previous = json_hash(body)
        audit = {**body, "event_hash": previous}
        audits.append(audit)
        row(f"AUDIT#{number:020d}", record_type="audit_event", event_hash=previous, event_json=json.dumps(audit))
        row("UPDATE#" + update["update_id"], **{key: value for key, value in update.items() if key not in {"artifact", "node_id"}},
            status="accepted", decision_json=json.dumps(decision), manifest_id=manifest["manifest_id"])
        row("UPDATE_META#" + update["update_id"], node_id=update["node_id"],
            artifact_json=json.dumps({key: value for key, value in update["artifact"].items() if key != "local_export"}))
        row("OPA_FINAL#" + update["update_id"], opa_decision_json=json.dumps(response))
    evidence["audit"], evidence["anchor"] = audits, {"count": 2, "head": previous}
    row("AUDIT_HEAD", **evidence["anchor"])
    row("POINTER", manifest_id=manifest["manifest_id"], round_id="round-1", commit_order=20)
    row("ROUND#round-1", status="CLOSED", pending_count=0, generation=2, manifest_id=manifest["manifest_id"], commit_order=20)
    raw = {key: manifest[key] for key in ("manifest_id", "run_id", "round_id", "commit_order", "commit_txn_id")}
    raw.update(candidate=candidate, parameters_digest=artifact["model_digest"],
               artifact={key: value for key, value in artifact.items() if key != "local_export"})
    row("MANIFEST#" + manifest["manifest_id"], record_type="publication_manifest", manifest_json=json.dumps(raw),
        commit_order=20, model_digest=candidate["model_digest"])
    row("TXN#publication-1", record_type="transaction_outcome", operation_kind="publication", order=20,
        request_digest="c" * 64, result_json=json.dumps({"manifest_id": manifest["manifest_id"], "commit_order": 20,
                                                       "audit_count": 2, "audit_head": previous}))
    for event in history:
        identity = {"PK": "POLICY#" + event["org_id"]}
        policies.append({**identity, "SK": f"EVENT#{event['order']:020d}", "record_type": "policy_event",
                         "epoch": event["epoch"], "order": event["order"], "policy_hash": json_hash(event), "event_json": json.dumps(event)})
        policies.append({**identity, "SK": "CURRENT", "epoch": event["epoch"], "effective_order": event["order"],
                         "policy_hash": json_hash(event), "event_json": json.dumps(event)})
    evidence.update(authority_backend="dynamodb-s3-opa", opa_used=True, persistent_run_id=run_id,
                    policy_rule_hash=rule_hash, model_metadata_digest="e" * 64, validation_source_sha256="f" * 64,
                    durable_evidence={"run_records": rows, "policy_records": policies,
                                      "sequence": {"PK": "AUTHORITY", "SK": "SEQUENCE", "order": 20}})
    evidence["validation_metrics"] = {"count": 4, "positive_count": 2, "prevalence": 0.5,
        "auroc": 0.5, "auprc": 0.5, "precision": 0.5, "recall": 0.5, "f1": 0.5, "threshold": 0.5, "loss": 0.7}
    evidence["evaluation_service_response"] = {"schema_version": "0.1.0", "request_id": "evaluation-final",
        "run_id": run_id, "manifest_id": manifest["manifest_id"], "round_id": "round-1",
        "model_schema_hash": evidence["model_schema_hash"], "parameters_digest": manifest["model_digest"],
        "model_sha256": artifact["sha256"], "metadata_digest": evidence["model_metadata_digest"],
        "validation_sha256": evidence["validation_source_sha256"], "validation_sample_digest": "d" * 64,
        "dataset_role": "validation", "final_test_evaluated": False, "manifest_verified": True,
        "metrics": evidence["validation_metrics"]}
    return evidence


def persistent_baseline_fixture(directory, baseline, *, revoked=False):
    evidence = persistent_fixture(directory)
    modes = {"B1": "none", "B2": "admission_cached", "B3": "dispatch_only"}
    mode = modes[baseline]
    manifest = evidence["published_manifests"][0]
    old_id = manifest["manifest_id"]
    candidate = manifest["candidate_metadata"]
    rows = evidence["durable_evidence"]["run_records"]
    pk = rows[0]["PK"]
    history = evidence["policy_events"]
    if revoked:
        event = {"event_id": "mid-round-revoke", "org_id": "org_01", "epoch": 2, "order": 17, "kind": "REVOKE", "rules": []}
        history.append(event)
        evidence["durable_evidence"]["policy_records"].append({"PK": "POLICY#org_01", "SK": f"EVENT#{17:020d}",
            "record_type": "policy_event", "epoch": 2, "order": 17, "policy_hash": json_hash(event), "event_json": json.dumps(event)})
        current = next(row for row in evidence["durable_evidence"]["policy_records"] if row["PK"] == "POLICY#org_01" and row["SK"] == "CURRENT")
        current.update(epoch=2, effective_order=17, policy_hash=json_hash(event), event_json=json.dumps(event))
        candidate["policy_epochs"]["org_01"] = 2
        candidate["history_digests"]["org_01"] = json_hash([event for event in history if event["org_id"] == "org_01"])
    candidate.update(baseline_id=baseline, policy_decision_mode=mode,
        omitted_guards=["receipt_authorization", "continuous_interval_authorization", "publication_policy_epoch"],
        observed_policy_epochs=candidate["policy_epochs"], policy_epochs={})
    candidate["candidate_id"] = json_hash({key: value for key, value in candidate.items() if key != "candidate_id"})
    manifest.update(guarded_policy_publication=False, baseline_id=baseline, baseline_comparator=True,
                    policy_decision_mode=mode, observed_policy_epochs=candidate["observed_policy_epochs"], policy_epochs={})
    # Replace the immutable identity throughout this independent synthetic
    # fixture, then recompute the final audit chain below.
    evidence = json.loads(json.dumps(evidence).replace(old_id, candidate["candidate_id"]))
    evidence.update(baseline_id=baseline, baseline_comparator=True, policy_decision_mode=mode,
                    publication_policy_epoch_guards=False, opa_used=baseline != "B1")
    manifest = evidence["published_manifests"][0]
    candidate = manifest["candidate_metadata"]
    rows = evidence["durable_evidence"]["run_records"]
    rows[:] = [row for row in rows if not row["SK"].startswith("OPA_FINAL#")]
    by_key = {row["SK"]: row for row in rows}
    previous = "0" * 64
    for task in evidence["tasks"]:
        uid, org = task["update_id"], task["org_id"]
        if baseline == "B1":
            source = {"valid": True, "reason": "baseline_no_policy_check", "decision_id": None,
                      "query": None, "policy_decision_mode": "none", "rule_hash": evidence["policy_rule_hash"]}
            reference = None
        else:
            order = 8 if baseline == "B2" else task["issue_order"] - 1
            query = {"org_id": org, "purpose": "readmission", "start_order": order, "commit_order": order,
                     "actions": ["train", "submit_update", "aggregate"]}
            past = [event for event in evidence["policy_events"] if event["order"] <= order]
            source = {"valid": True, "reason": "continuous_authorization", "invalid_order": None,
                "query": query, "decision_id": "native-" + org, "request_binding": "binding-" + org,
                "rule_hash": evidence["policy_rule_hash"], "opa_version": "1.22.3", "protocol_revision": "pcfl-interval-v1",
                "history_digest": json_hash(past), "request_hash": json_hash({"events": past, "query": query})}
            reference = ("ADMISSION#" + org) if baseline == "B2" else ("ISSUE#" + task["task_id"])
            if baseline == "B2":
                rows.append({"PK": pk, "SK": reference, "baseline_id": baseline, "policy_decision_mode": mode,
                             "opa_decision_json": json.dumps(source)})
        issue_task = {key: value for key, value in task.items() if key != "nonce_digest"}
        issue_task["start_order"] = None
        rows.append({"PK": pk, "SK": "ISSUE#" + task["task_id"], "task_json": json.dumps(issue_task),
                     "nonce_digest": task["nonce_digest"], "opa_decision_json": json.dumps(source), "status": "ACKNOWLEDGED"})
        by_key["TASK#" + task["task_id"]]["opa_decision_json"] = json.dumps(source)
        by_key["UPDATE_META#" + uid]["opa_decision_json"] = json.dumps(source)
        decision = evidence["decisions"][uid]
        decision.update(baseline_id=baseline, policy_decision_mode=mode, policy_evidence_ref=reference,
                        policy_query=source["query"], policy_decision_id=source["decision_id"], reason="baseline_acceptance",
                        observed_epoch=candidate["observed_policy_epochs"][org], history_digest=candidate["history_digests"][org])
        by_key["UPDATE#" + uid]["decision_json"] = json.dumps(decision)
        rows.append({"PK": pk, "SK": "BASELINE_FINAL#" + uid, "provenance_json": json.dumps({"baseline_id": baseline,
            "policy_decision_mode": mode, "policy_evidence_ref": reference, "policy_evaluation": source if reference else None})})
    for audit in evidence["audit"]:
        audit["payload"] = evidence["decisions"][audit["payload"]["update_id"]]
        audit["prev_hash"] = previous
        previous = audit["event_hash"] = json_hash({key: audit[key] for key in ("sequence", "prev_hash", "payload")})
        by_key[f"AUDIT#{audit['sequence']:020d}"].update(event_json=json.dumps(audit), event_hash=previous)
    evidence["anchor"]["head"] = previous
    by_key["AUDIT_HEAD"]["head"] = previous
    outcome = json.loads(by_key["TXN#publication-1"]["result_json"])
    outcome["audit_head"] = previous
    by_key["TXN#publication-1"]["result_json"] = json.dumps(outcome)
    raw = json.loads(by_key["MANIFEST#" + manifest["manifest_id"]]["manifest_json"])
    raw["candidate"] = candidate
    by_key["MANIFEST#" + manifest["manifest_id"]]["manifest_json"] = json.dumps(raw)
    return evidence


@unittest.skipUnless(RUNTIME_AVAILABLE, "Install runtime NumPy for retained-model verification tests")
class RuntimeVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.directory = self.parent / "case"
        self.directory.mkdir()
        self.path = self.directory / "runtime_result.json"

    def write(self, evidence):
        self.path.write_text(json.dumps(evidence, indent=2, allow_nan=False), encoding="utf-8")
        return self.path

    def test_valid_stable_hand_calculated_model_passes(self):
        result = verify_case(self.write(fixture(self.directory)))
        self.assertTrue(result["successful"])
        self.assertEqual(result["accepted_updates"], 2)
        self.assertEqual(result["oracle_invalid_presented"], 0)
        self.assertTrue(result["model_reconstruction_verified"])
        self.assertTrue(result["audit_verified"])

    def test_changed_model_bytes_fail_even_with_unchanged_metadata(self):
        evidence = fixture(self.directory)
        self.write(evidence)
        Path(evidence["published_manifests"][0]["artifact"]["path"]).write_bytes(b"modified checkpoint bytes")
        with self.assertRaisesRegex(ValueError, "artifact_file_digest_mismatch"):
            verify_case(self.path)

    def test_self_consistent_wrong_weighted_model_is_rejected(self):
        bad = [np.array([9.0, 9.0], dtype=np.float32), np.array([9.0], dtype=np.float32)]
        with self.assertRaisesRegex(ValueError, "not_reconstructed"):
            verify_case(self.write(fixture(self.directory, model_arrays=bad)))

    def test_trailing_parameter_arrays_cannot_be_omitted(self):
        partial = [np.array([4.0, 6.0], dtype=np.float32)]
        with self.assertRaises(ValueError):
            verify_case(self.write(fixture(self.directory, model_arrays=partial)))

    def test_parameter_shapes_cannot_pass_by_numpy_broadcasting(self):
        mismatched = [np.array([[4.0, 6.0]], dtype=np.float32), np.array([8.0], dtype=np.float32)]
        with self.assertRaises(ValueError):
            verify_case(self.write(fixture(self.directory, model_arrays=mismatched)))

    def test_p1_label_requires_guarded_publication_manifest(self):
        with self.assertRaises(ValueError):
            verify_case(self.write(fixture(self.directory, guarded_publication=False)))

    def test_invalid_history_in_p1_is_a_failure(self):
        with self.assertRaisesRegex(ValueError, "oracle_invalid_update"):
            verify_case(self.write(fixture(self.directory, baseline="P1", revoked=True)))

    def test_invalid_history_in_unsafe_comparator_is_counted(self):
        path = self.write(fixture(self.directory, baseline="B3", revoked=True))
        result = verify_case(path)
        self.assertEqual(result["oracle_invalid_presented"], 1)
        self.assertEqual(result["oracle_invalid_incorporations"], 1)
        with self.assertRaisesRegex(ValueError, "oracle_invalid_update"):
            verify_case(path, expect_safe=True)

    def test_self_consistent_incorrect_guarded_epoch_is_rejected(self):
        evidence = fixture(self.directory, epoch_values={"org_01": 999, "org_02": 1})
        with self.assertRaisesRegex(ValueError, "guarded_manifest_policy_epoch_mismatch"):
            verify_case(self.write(evidence))

    def test_missing_audit_or_outcome_is_not_accepted_as_success(self):
        evidence = fixture(self.directory)
        evidence["audit"].pop()
        with self.assertRaisesRegex(ValueError, "audit_integrity"):
            verify_case(self.write(evidence))
        evidence = fixture(self.directory)
        evidence["decisions"].pop("update-2")
        with self.assertRaisesRegex(ValueError, "incomplete_final_decision"):
            verify_case(self.write(evidence))

    def test_external_artifact_path_is_rejected(self):
        evidence = fixture(self.directory)
        external = self.parent / "external.npz"
        original = Path(evidence["updates"][0]["artifact"]["path"])
        external.write_bytes(original.read_bytes())
        evidence["updates"][0]["artifact"]["path"] = str(external)
        with self.assertRaisesRegex(ValueError, "artifact_outside_case_directory"):
            verify_case(self.write(evidence))

    def test_duplicate_update_identity_and_evaluation_on_test_fail(self):
        evidence = fixture(self.directory)
        evidence["updates"].append(deepcopy(evidence["updates"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate_update_or_task"):
            verify_case(self.write(evidence))
        evidence = fixture(self.directory)
        evidence["test_holdout_evaluated"] = True
        with self.assertRaisesRegex(ValueError, "validation_only"):
            verify_case(self.write(evidence))

    def persistent_row(self, evidence, sk):
        return next(record for record in evidence["durable_evidence"]["run_records"] if record["SK"] == sk)

    def test_hand_constructed_persistent_candidate_and_durable_chain_pass(self):
        evidence = persistent_fixture(self.directory)
        manifest = evidence["published_manifests"][0]
        self.assertNotEqual(manifest["manifest_id"], json_hash({key: value for key, value in manifest.items() if key != "manifest_id"}))
        result = verify_case(self.write(evidence))
        self.assertTrue(result["persistent_protocol_verified"])
        self.assertTrue(result["committed_evaluation_response_verified"])
        self.assertEqual(result["accepted_updates"], 2)

    def test_persistent_candidate_guard_cannot_change_without_fingerprint_change(self):
        evidence = persistent_fixture(self.directory)
        evidence["published_manifests"][0]["candidate_metadata"]["round_generation"] += 1
        with self.assertRaisesRegex(ValueError, "candidate_fingerprint"):
            verify_case(self.write(evidence))

    def test_self_consistent_candidate_fingerprint_cannot_hide_wrong_history_scope(self):
        evidence = persistent_fixture(self.directory, bad_candidate_history=True)
        with self.assertRaisesRegex(ValueError, "candidate_organization_history_digest"):
            verify_case(self.write(evidence))

    def test_persistent_decision_requires_organization_scoped_history_digest(self):
        evidence = persistent_fixture(self.directory)
        evidence["decisions"]["update-1"]["history_digest"] = json_hash(evidence["policy_events"])
        # Keep the audit coherent so its semantic history check must reject it.
        previous = "0" * 64
        for audit in evidence["audit"]:
            audit["prev_hash"] = previous
            previous = audit["event_hash"] = json_hash({key: audit[key] for key in ("sequence", "prev_hash", "payload")})
        evidence["anchor"]["head"] = previous
        with self.assertRaisesRegex(ValueError, "policy_history_digest"):
            verify_case(self.write(evidence))

    def test_persistent_native_opa_decision_and_input_cannot_be_rebound(self):
        for field, value in (("decision_id", "forged-native-id"), ("request_hash", "0" * 64), ("rule_hash", "0" * 64)):
            with self.subTest(field=field):
                evidence = persistent_fixture(self.directory)
                row = self.persistent_row(evidence, "OPA_FINAL#update-1")
                response = json.loads(row["opa_decision_json"])
                response[field] = value
                row["opa_decision_json"] = json.dumps(response)
                with self.assertRaisesRegex(ValueError, "opa_.*binding"):
                    verify_case(self.write(evidence))

    def test_persistent_durable_pointer_audit_and_outcome_cannot_diverge(self):
        for sk, field, value, reason in (("POINTER", "manifest_id", "0" * 64, "durable_model_pointer"),
                                        ("AUDIT_HEAD", "head", "0" * 64, "durable_audit_anchor"),
                                        ("TXN#publication-1", "order", 999, "durable_publication_outcome")):
            with self.subTest(sk=sk):
                evidence = persistent_fixture(self.directory)
                self.persistent_row(evidence, sk)[field] = value
                with self.assertRaisesRegex(ValueError, reason):
                    verify_case(self.write(evidence))

    def test_persistent_immutable_s3_export_cannot_substitute_reference(self):
        evidence = persistent_fixture(self.directory)
        evidence["updates"][0]["artifact"]["version_id"] = "substituted-version"
        with self.assertRaisesRegex(ValueError, "durable_update_export"):
            verify_case(self.write(evidence))
        evidence = persistent_fixture(self.directory)
        evidence["updates"][0]["artifact"]["local_export"]["file_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "s3_export_binding"):
            verify_case(self.write(evidence))

    def test_persistent_evaluation_requires_matching_frozen_provenance_and_validation_role(self):
        for field, value in (("manifest_verified", False), ("validation_sha256", "0" * 64),
                             ("dataset_role", "test"), ("metadata_digest", "0" * 64)):
            with self.subTest(field=field):
                evidence = persistent_fixture(self.directory)
                evidence["evaluation_service_response"][field] = value
                with self.assertRaisesRegex(ValueError, "isolated_evaluation_evidence"):
                    verify_case(self.write(evidence))

    def test_persistent_metric_payload_cannot_smuggle_record_level_values(self):
        evidence = persistent_fixture(self.directory)
        evidence["validation_metrics"]["labels"] = [0, 1, 0, 1]
        with self.assertRaisesRegex(ValueError, "aggregate_evaluation_metric_shape"):
            verify_case(self.write(evidence))

    def test_durable_baselines_verify_and_count_intentionally_unsafe_incorporations(self):
        for baseline in ("B1", "B2", "B3"):
            for revoked in (False, True):
                with self.subTest(baseline=baseline, revoked=revoked):
                    evidence = persistent_baseline_fixture(self.directory, baseline, revoked=revoked)
                    result = verify_case(self.write(evidence))
                    self.assertEqual(result["oracle_invalid_incorporations"], 1 if revoked else 0)
                    self.assertTrue(result["persistent_protocol_verified"])
                    if revoked:
                        with self.assertRaisesRegex(ValueError, "oracle_invalid_update"):
                            verify_case(self.path, expect_safe=True)

    def test_baseline_must_not_be_relabeled_guarded_or_claim_commit_OPA(self):
        evidence = persistent_baseline_fixture(self.directory, "B1")
        evidence["published_manifests"][0]["guarded_policy_publication"] = True
        with self.assertRaisesRegex(ValueError, "guard_label"):
            verify_case(self.write(evidence))
        evidence = persistent_baseline_fixture(self.directory, "B3")
        evidence["durable_evidence"]["run_records"].append({"PK": "RUN#independent-runtime", "SK": "OPA_FINAL#forged"})
        with self.assertRaisesRegex(ValueError, "commit_OPA"):
            verify_case(self.write(evidence))

    def test_baseline_cached_native_provenance_cannot_be_rebound(self):
        evidence = persistent_baseline_fixture(self.directory, "B2")
        row = self.persistent_row(evidence, "BASELINE_FINAL#update-1")
        payload = json.loads(row["provenance_json"])
        payload["policy_evaluation"]["decision_id"] = "different-native-id"
        row["provenance_json"] = json.dumps(payload)
        with self.assertRaisesRegex(ValueError, "baseline_final_policy_provenance"):
            verify_case(self.write(evidence))


if __name__ == "__main__":
    unittest.main()
