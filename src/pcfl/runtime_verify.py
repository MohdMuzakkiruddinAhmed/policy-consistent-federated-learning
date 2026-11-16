"""Independent offline checks of retained learning-pilot evidence.

No Flower application/enforcement or producer aggregation functions are imported.
Model updates are private artifacts; this verifier emits aggregate evidence only.
"""

import hashlib
from datetime import datetime
import io
import json
import math
from pathlib import Path
import re
import zipfile

import numpy as np

from .oracle import evaluate_interval
from .verifier import verify_chain

_MAX_MODEL_BYTES = 32 * 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ACTIONS = ["train", "submit_update", "aggregate"]
_ORGANIZATIONS = {f"org_{number:02d}" for number in range(1, 9)}


def _hash(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _parameter_digest(arrays):
    return _hash([{"dtype": value.dtype.str, "shape": list(value.shape),
                   "sha256": hashlib.sha256(value.tobytes(order="C")).hexdigest()} for value in arrays])


def _load_artifact(record, directory):
    original = record
    if record.get("backend") == "s3":
        record = record.get("local_export", {})
        if (not original.get("bucket") or not original.get("key") or not original.get("version_id")
                or original["version_id"] == "null" or record.get("file_sha256") != original.get("sha256")
                or record.get("model_digest") != original.get("model_digest")
                or original.get("parameters_digest") != original.get("model_digest")):
            raise ValueError("s3_export_binding_mismatch")
    path = Path(record["path"]).resolve()
    if not path.is_relative_to(directory.resolve()) or path.suffix != ".npz":
        raise ValueError("artifact_outside_case_directory")
    if path.stat().st_size > _MAX_MODEL_BYTES:
        raise ValueError("artifact_size_limit")
    content = path.read_bytes()
    if len(content) > _MAX_MODEL_BYTES or hashlib.sha256(content).hexdigest() != record["file_sha256"]:
        raise ValueError("artifact_file_digest_mismatch")
    if original.get("backend") == "s3" and (type(original.get("size_bytes")) is not int
                                             or len(content) != original["size_bytes"]):
        raise ValueError("s3_export_size_mismatch")
    with zipfile.ZipFile(io.BytesIO(content)) as bundle:
        names = bundle.namelist()
        if (len(names) != len(set(names)) or set(names) != {f"arr_{index}.npy" for index in range(len(names))}
                or sum(item.file_size for item in bundle.infolist()) > _MAX_MODEL_BYTES):
            raise ValueError("invalid_retained_parameter_archive")
        for name in names:
            with bundle.open(name) as member:
                version = np.lib.format.read_magic(member)
                if version not in {(1, 0), (2, 0)}:
                    raise ValueError("invalid_retained_array_format")
                reader = np.lib.format.read_array_header_1_0 if version == (1, 0) else np.lib.format.read_array_header_2_0
                shape, _, dtype = reader(member, max_header_size=4096)
                if dtype != np.dtype("float32") or math.prod(shape) * dtype.itemsize > _MAX_MODEL_BYTES:
                    raise ValueError("invalid_retained_array_header")
    with np.load(io.BytesIO(content), allow_pickle=False) as archive:
        if set(archive.files) != {f"arr_{i}" for i in range(len(archive.files))}:
            raise ValueError("unexpected_parameter_archive_keys")
        arrays = [archive[f"arr_{i}"].copy() for i in range(len(archive.files))]
    if not arrays or any(value.dtype != np.float32 or not np.isfinite(value).all() for value in arrays):
        raise ValueError("invalid_retained_model_arrays")
    if _parameter_digest(arrays) != record["model_digest"]:
        raise ValueError("parameter_digest_mismatch")
    return arrays


def _original_artifact(record):
    return {key: value for key, value in record.items() if key != "local_export"}


def _json_field(record, field):
    try:
        return json.loads(record[field])
    except (KeyError, TypeError, json.JSONDecodeError):
        raise ValueError("unreadable_durable_json_field") from None


def _rows_by_key(records, expected_pk=None):
    if not isinstance(records, list):
        raise ValueError("durable_rows_required")
    rows = {}
    for record in records:
        if (not isinstance(record, dict) or not isinstance(record.get("PK"), str)
                or not isinstance(record.get("SK"), str)
                or (expected_pk is not None and record["PK"] != expected_pk)):
            raise ValueError("durable_row_identity_mismatch")
        key = (record["PK"], record["SK"])
        if key in rows:
            raise ValueError("duplicate_durable_row")
        rows[key] = record
    return rows


def _verify_opa_response(response, query, history, rule_hash):
    past = [event for event in history if event["order"] <= query["commit_order"]]
    if (not isinstance(response, dict) or response.get("query") != query
            or not isinstance(response.get("decision_id"), str) or not response["decision_id"].strip()
            or response.get("opa_version") != "1.22.3" or response.get("protocol_revision") != "pcfl-interval-v1"
            or response.get("rule_hash") != rule_hash
            or not isinstance(response.get("request_binding"), str) or not response["request_binding"]
            or response.get("history_digest") != _hash(past)
            or response.get("request_hash") != _hash({"events": past, "query": query})
            or type(response.get("valid")) is not bool or "invalid_order" not in response):
        raise ValueError("native_opa_response_binding_mismatch")
    expected = evaluate_interval(history, query)
    if response["valid"] != expected["valid"] or response["invalid_order"] != expected["invalid_order"]:
        raise ValueError("native_opa_response_disagrees_with_oracle")
    if response["valid"] and response.get("reason") != "continuous_authorization":
        raise ValueError("native_opa_allow_reason_mismatch")


def _verify_aggregate_metrics(metrics):
    names = {"count", "positive_count", "prevalence", "auroc", "auprc", "precision", "recall", "f1", "threshold", "loss"}
    if (not isinstance(metrics, dict) or set(metrics) != names or type(metrics["count"]) is not int
            or metrics["count"] < 1 or type(metrics["positive_count"]) is not int
            or not 0 <= metrics["positive_count"] <= metrics["count"] or metrics["threshold"] != 0.5):
        raise ValueError("aggregate_evaluation_metric_shape_mismatch")
    for name in names - {"count", "positive_count"}:
        value = metrics[name]
        if value is None and name in {"auroc", "auprc"}:
            continue
        if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                or (name != "loss" and value > 1)):
            raise ValueError("aggregate_evaluation_metric_value_mismatch")
    if metrics["prevalence"] != metrics["positive_count"] / metrics["count"]:
        raise ValueError("aggregate_evaluation_prevalence_mismatch")


def _baseline_policy_source(rows, pk, task, baseline, history, rule_hash):
    issued = rows.get((pk, f"ISSUE#{task['task_id']}"), {})
    issued_task = _json_field(issued, "task_json")
    if any(issued_task.get(key) != value for key, value in task.items() if key not in {"start_order", "nonce_digest"}):
        raise ValueError("baseline_issued_task_binding_mismatch")
    if issued.get("nonce_digest") != task["nonce_digest"] or issued_task.get("start_order") is not None:
        raise ValueError("baseline_issued_nonce_binding_mismatch")
    cached = _json_field(issued, "opa_decision_json")
    if baseline == "B1":
        if cached.get("decision_id") is not None or cached.get("query") is not None or cached.get("valid") is not True:
            raise ValueError("B1_must_not_claim_native_policy_decision")
        return None, None
    reference = f"ADMISSION#{task['org_id']}" if baseline == "B2" else f"ISSUE#{task['task_id']}"
    source = _json_field(rows.get((pk, reference), {}), "opa_decision_json")
    query = source.get("query", {})
    if (query.get("org_id") != task["org_id"] or query.get("purpose") != task["purpose"]
            or query.get("actions") != _ACTIONS or query.get("start_order") != query.get("commit_order")
            or type(query.get("commit_order")) is not int or not 1 <= query["commit_order"] < task["issue_order"]
            or (baseline == "B3" and query["commit_order"] != task["issue_order"] - 1)
            or cached != source or source.get("valid") is not True):
        raise ValueError("baseline_native_policy_stage_binding_mismatch")
    _verify_opa_response(source, query, history, rule_hash)
    return reference, source


def _independent_holdout_scope(context, evidence):
    """Validate external expected authority without importing evaluator enforcement."""
    from .experiments import validate_plan
    if not isinstance(context, dict) or set(context) != {"accepted_plan", "authorization"}:
        raise ValueError("external_expected_test_authority_required")
    plan, authorization = context["accepted_plan"], context["authorization"]
    if not isinstance(plan, dict) or not isinstance(authorization, dict):
        raise ValueError("external_expected_test_authority_required")
    validate_plan(plan)
    training, source = plan.get("training_candidate", {}), plan.get("provenance", {})
    sources, images = source.get("source_files_sha256", {}), source.get("image_digests", {})
    if (plan.get("status") != "accepted_frozen" or plan.get("confirmatory_execution_enabled") is not True
            or training.get("confirmatory_frozen") is not True or training.get("pilot_only") is not False
            or training.get("final_test_access_permitted") is not False
            or type(training.get("num_rounds")) is not int or not 2 <= training["num_rounds"] <= 100
            or training.get("classification_threshold") != .5 or not sources
            or any(not isinstance(value, str) or not _HEX.fullmatch(value) for value in sources.values())
            or source.get("source_sha256") != _hash(sources) or not images
            or any(not isinstance(value, str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", value) for value in images.values())):
        raise ValueError("independent_accepted_test_plan_required")
    fields = {"schema_version", "kind", "authorization_id", "status", "scope", "issued_by", "issued_at_utc",
              "plan_digest", "test_sha256", "model_schema_hash", "runs", "authorization_digest"}
    identifier = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
    if (set(authorization) != fields or authorization.get("schema_version") != "0.1.0"
            or authorization.get("kind") != "pcfl-final-holdout-authorization" or authorization.get("status") != "authorized"
            or authorization.get("scope") != "final-committed-model-only"
            or authorization.get("plan_digest") != plan["plan_digest"]
            or authorization.get("authorization_digest") != _hash({key: value for key, value in authorization.items() if key != "authorization_digest"})
            or any(not isinstance(authorization.get(key), str) or not _HEX.fullmatch(authorization[key]) for key in
                   ("plan_digest", "authorization_digest", "test_sha256", "model_schema_hash"))
            or any(not isinstance(authorization.get(key), str) or not identifier.fullmatch(authorization[key]) for key in ("authorization_id", "issued_by"))):
        raise ValueError("independent_operator_test_authorization_invalid")
    try:
        if datetime.fromisoformat(authorization["issued_at_utc"].replace("Z", "+00:00")).tzinfo is None:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("independent_operator_test_timestamp_invalid") from None
    runs = authorization["runs"]
    if (not isinstance(runs, dict) or not 1 <= len(runs) <= 300
            or any(not isinstance(value, str) or not identifier.fullmatch(value) for value in [*runs, *runs.values()])
            or len(set(runs.values())) != len(runs)):
        raise ValueError("independent_test_run_mapping_invalid")
    all_cells = sum((plan[name] for name in ("primary_cells", "targeted_cells", "ablation_cells", "replication_cells")), [])
    registry = {cell["cell_id"]: cell for cell in all_cells}
    common_training = {key: value for key, value in training.items() if key not in {"seed", "pilot_only", "confirmatory_frozen", "acceptance_status"}}
    common_source = {key: value for key, value in source.items() if key != "git_commit"}
    for cell in all_cells:
        shared = cell["shared_config"]
        if (shared.get("test_holdout_sha256") != authorization["test_sha256"] or shared.get("source") != common_source
                or shared.get("training") != common_training or shared.get("data_manifest_digest") != plan["data_manifest_digest"]):
            raise ValueError("independent_registered_test_scope_mismatch")
    if any(cell_id not in registry or registry[cell_id].get("unsafe_comparator") is True
           or registry[cell_id].get("family") == "ablation" for cell_id in runs.values()):
        raise ValueError("independent_test_cell_not_registered")
    run_id = evidence.get("persistent_run_id")
    cell_id = runs.get(run_id)
    if cell_id is None:
        raise ValueError("independent_test_run_not_authorized")
    cell = registry[cell_id]
    expected_binding = {"plan_digest": plan["plan_digest"], "cell_id": cell_id, "equivalence_hash": cell["equivalence_hash"],
        "family": cell["family"], "policy_schedule_hash": cell["shared_config"]["policy_schedule_hash"], "source_sha256": source["source_sha256"]}
    if evidence.get("experiment_binding") != expected_binding:
        raise ValueError("independent_test_experiment_binding_mismatch")
    scenario = {"stable": "S0", "between_round": "S1", "mid_round": "S2", "delayed": "S3", "revoke_regrant": "S4",
                "purpose_change": "S5", "near_commit": "S6"}.get(evidence.get("scenario_id"), evidence.get("scenario_id"))
    if (evidence.get("cell_id") != cell_id or evidence.get("accepted_plan_digest") != plan["plan_digest"]
            or evidence.get("plan_digest") != plan["plan_digest"]
            or evidence.get("holdout_authorization_digest") != authorization["authorization_digest"]
            or evidence.get("test_source_sha256") != authorization["test_sha256"]
            or evidence.get("model_schema_hash") != authorization["model_schema_hash"]
            or evidence.get("baseline_id") != cell["baseline_id"] or scenario != cell["scenario_id"]
            or evidence.get("seed") != cell["seed"] or evidence.get("distribution") != cell["distribution"]
            or evidence.get("equivalence_hash") != cell["equivalence_hash"]):
        raise ValueError("independent_test_evidence_scope_binding_mismatch")
    return {"cell_id": cell_id, "plan_digest": plan["plan_digest"], "authorization_digest": authorization["authorization_digest"],
            "authorization_id": authorization["authorization_id"], "test_sha256": authorization["test_sha256"],
            "final_round": "round-" + str(training["num_rounds"])}


def _verify_persistent(evidence, history, updates, tasks, test_scope=None, errors=None):
    baseline = evidence["baseline_id"]
    modes = {"B1": "none", "B2": "admission_cached", "B3": "dispatch_only"}
    proposed = baseline == "P1"
    if evidence.get("opa_used") is not (baseline != "B1"):
        raise ValueError("persistent_policy_evaluator_usage_label_mismatch")
    if not proposed and (evidence.get("baseline_comparator") is not True or evidence.get("policy_decision_mode") != modes[baseline]
                         or evidence.get("publication_policy_epoch_guards") is not False):
        raise ValueError("persistent_baseline_comparator_provenance_required")
    run_id = evidence.get("persistent_run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("persistent_run_identity_required")
    pk = f"RUN#{run_id}"
    durable = evidence.get("durable_evidence", {})
    rows = _rows_by_key(durable.get("run_records"), pk)
    policies = _rows_by_key(durable.get("policy_records"))
    sequence = durable.get("sequence", {})
    rule_hash = hashlib.sha256((Path(__file__).resolve().parents[2] / "policies/rego/pcfl.rego").read_bytes()).hexdigest()
    if evidence.get("policy_rule_hash") != rule_hash:
        raise ValueError("pinned_policy_rule_hash_mismatch")
    if (sequence.get("PK") != "AUTHORITY" or sequence.get("SK") != "SEQUENCE"
            or type(sequence.get("order")) is not int or sequence["order"] < 1):
        raise ValueError("durable_authority_sequence_missing")
    policy_events, ids, orders = [], set(), set()
    for org in _ORGANIZATIONS:
        org_pk = f"POLICY#{org}"
        events = sorted([record for (record_pk, sk), record in policies.items()
                         if record_pk == org_pk and sk.startswith("EVENT#")], key=lambda record: record["SK"])
        current = policies.get((org_pk, "CURRENT"), {})
        for epoch, record in enumerate(events, 1):
            event = _json_field(record, "event_json")
            if (record.get("record_type") != "policy_event" or event.get("org_id") != org
                    or event.get("epoch") != epoch or record.get("epoch") != epoch
                    or type(event.get("order")) is not int or event["order"] < 1
                    or event["order"] > sequence["order"] or record.get("order") != event["order"]
                    or record["SK"] != f"EVENT#{event['order']:020d}" or record.get("policy_hash") != _hash(event)
                    or event.get("event_id") in ids or event["order"] in orders):
                raise ValueError("durable_policy_history_integrity_failed")
            ids.add(event["event_id"])
            orders.add(event["order"])
            policy_events.append(event)
        if not events:
            raise ValueError("durable_policy_history_missing")
        tail = _json_field(events[-1], "event_json")
        if (current.get("epoch") != tail["epoch"] or current.get("effective_order") != tail["order"]
                or current.get("policy_hash") != _hash(tail) or _json_field(current, "event_json") != tail):
            raise ValueError("durable_policy_tail_mismatch")
    if sorted(policy_events, key=lambda event: event["order"]) != history:
        raise ValueError("durable_policy_export_mismatch")
    if len(policies) != len(policy_events) + len(_ORGANIZATIONS):
        raise ValueError("unexpected_durable_policy_row")
    audit_rows = [record for (_, sk), record in rows.items() if sk.startswith("AUDIT#")]
    if len(audit_rows) != len(evidence["audit"]):
        raise ValueError("durable_audit_membership_mismatch")
    for audit in evidence["audit"]:
        record = rows.get((pk, f"AUDIT#{audit['sequence']:020d}"), {})
        if (record.get("record_type") != "audit_event" or record.get("event_hash") != audit["event_hash"]
                or _json_field(record, "event_json") != audit):
            raise ValueError("durable_audit_content_mismatch")
    head = rows.get((pk, "AUDIT_HEAD"), {})
    if {key: head.get(key) for key in ("count", "head")} != evidence["anchor"]:
        raise ValueError("durable_audit_anchor_mismatch")
    errors = errors or {}
    if len([sk for _, sk in rows if sk.startswith("ATTEMPT#")]) != len(errors):
        raise ValueError("durable_final_error_membership_mismatch")
    for task in tasks.values():
        record = rows.get((pk, f"TASK#{task['task_id']}"), {})
        if any(record.get(key) != value for key, value in task.items()):
            raise ValueError("durable_task_export_mismatch")
        policy_order = task["start_order"] if proposed else task["issue_order"]
        preceding = [event for event in history if event["org_id"] == task["org_id"] and event["order"] <= policy_order]
        if not preceding or task["policy_epoch"] != preceding[-1]["epoch"] or task["policy_hash"] != _hash(preceding[-1]):
            raise ValueError("durable_task_policy_binding_mismatch")
        if proposed:
            query = {"org_id": task["org_id"], "purpose": task["purpose"], "start_order": task["start_order"],
                     "commit_order": task["start_order"], "actions": _ACTIONS}
            _verify_opa_response(_json_field(record, "opa_decision_json"), query, history, rule_hash)
        else:
            reference, source = _baseline_policy_source(rows, pk, task, baseline, history, rule_hash)
            stored = _json_field(record, "opa_decision_json")
            if (source is not None and stored != source) or (source is None and stored.get("decision_id") is not None):
                raise ValueError("baseline_acknowledgment_recheck_detected")
    for uid, error in errors.items():
        required = {"update_id", "task_id", "org_id", "round_id", "purpose", "start_order", "run_id", "outcome", "reason",
            "evaluation_order", "observed_epoch", "history_digest", "history_digest_scope", "manifest_ref", "rule_bundle_hash",
            "authorization_status", "policy_decision_id", "policy_query"}
        task = tasks.get(error.get("task_id"))
        order = error.get("evaluation_order")
        if (set(error) != required or not task or error.get("run_id") != run_id or error.get("rule_bundle_hash") != rule_hash
                or error.get("authorization_status") != "not_evaluated_operational_error" or error.get("outcome") != "error"
                or error.get("policy_decision_id") is not None or error.get("policy_query") is not None or error.get("manifest_ref") is not None
                or not isinstance(error.get("reason"), str) or not error["reason"].strip()
                or type(order) is not int or not task["start_order"] <= order <= sequence["order"]
                or any(error.get(name) != task[name] for name in ("task_id", "update_id", "org_id", "round_id", "purpose", "start_order"))
                or _json_field(rows.get((pk, "ATTEMPT#" + task["task_id"]), {}), "decision_json") != error):
            raise ValueError("durable_final_operational_error_binding_mismatch")
        past = [event for event in history if event["org_id"] == error["org_id"] and event["order"] <= order]
        if not past or error.get("observed_epoch") != past[-1]["epoch"]:
            raise ValueError("final_operational_error_epoch_mismatch")
        outcomes = [row for (_, sk), row in rows.items() if sk.startswith("TXN#") and row.get("operation_kind") == "attempt_error"
            and row.get("order") == order and _json_field(row, "result_json") == {"update_id": uid, "outcome": "error"}]
        if (len(outcomes) != 1 or outcomes[0].get("record_type") != "transaction_outcome"
                or not isinstance(outcomes[0].get("request_digest"), str) or not _HEX.fullmatch(outcomes[0]["request_digest"])):
            raise ValueError("durable_final_error_transaction_outcome_mismatch")
    seen_opa = set()
    for uid, update in updates.items():
        record = rows.get((pk, f"UPDATE#{uid}"), {})
        meta = rows.get((pk, f"UPDATE_META#{uid}"), {})
        if (any(record.get(key) != value for key, value in update.items() if key not in {"artifact", "node_id"})
                or meta.get("node_id") != update["node_id"]
                or _json_field(meta, "artifact_json") != _original_artifact(update["artifact"])
                or _json_field(record, "decision_json") != evidence["decisions"][uid]
                or record.get("status") != evidence["decisions"][uid]["outcome"]):
            raise ValueError("durable_update_export_mismatch")
        decision = evidence["decisions"][uid]
        if proposed:
            query = {"org_id": update["org_id"], "purpose": update["purpose"], "start_order": update["start_order"],
                     "commit_order": decision["evaluation_order"], "actions": _ACTIONS}
            opa = _json_field(rows.get((pk, f"OPA_FINAL#{uid}"), {}), "opa_decision_json")
            _verify_opa_response(opa, query, history, rule_hash)
            if (decision.get("policy_decision_id") != opa["decision_id"] or decision.get("policy_query") != query
                    or decision.get("rule_bundle_hash") != rule_hash or opa["decision_id"] in seen_opa
                    or decision["evaluation_order"] > sequence["order"]):
                raise ValueError("final_opa_decision_binding_mismatch")
            seen_opa.add(opa["decision_id"])
            if decision["outcome"] == "accepted" and opa["valid"] is not True:
                raise ValueError("native_opa_denied_published_update")
        else:
            reference, source = _baseline_policy_source(rows, pk, tasks[update["task_id"]], baseline, history, rule_hash)
            expected = {"baseline_id": baseline, "policy_decision_mode": modes[baseline], "policy_evidence_ref": reference,
                        "policy_evaluation": source}
            if (_json_field(rows.get((pk, f"BASELINE_FINAL#{uid}"), {}), "provenance_json") != expected
                    or decision.get("baseline_id") != baseline or decision.get("policy_decision_mode") != modes[baseline]
                    or decision.get("policy_evidence_ref") != reference
                    or decision.get("policy_decision_id") != (source["decision_id"] if source else None)
                    or decision.get("policy_query") != (source["query"] if source else None)
                    or decision.get("rule_bundle_hash") != rule_hash or decision["evaluation_order"] > sequence["order"]):
                raise ValueError("baseline_final_policy_provenance_mismatch")
            receipt = _json_field(meta, "opa_decision_json")
            if (source is not None and receipt != source) or (source is None and receipt.get("decision_id") is not None):
                raise ValueError("baseline_receipt_recheck_detected")
    if not proposed and any(sk.startswith("OPA_FINAL#") for _, sk in rows):
        raise ValueError("baseline_must_not_claim_commit_OPA_checks")
    if baseline == "B1" and any(sk.startswith("ADMISSION#") for _, sk in rows):
        raise ValueError("B1_must_not_have_admission_policy_check")
    manifests = evidence["published_manifests"]
    if len([key for _, key in rows if key.startswith("MANIFEST#")]) != len(manifests):
        raise ValueError("durable_manifest_membership_mismatch")
    for manifest in manifests:
        candidate = manifest.get("candidate_metadata", {})
        fields = {"candidate_id", "snapshot_order", "parent_manifest_id", "round_generation", "policy_epochs",
                  "history_digests", "model_schema_hash", "rule_bundle_hash", "model_digest", "s3", "object_confirmation", "updates"}
        if not proposed:
            fields |= {"baseline_id", "policy_decision_mode", "omitted_guards", "observed_policy_epochs"}
        if (set(candidate) != fields or candidate["candidate_id"] != _hash({key: value for key, value in candidate.items() if key != "candidate_id"})
                or manifest["manifest_id"] != candidate["candidate_id"]):
            raise ValueError("persistent_candidate_fingerprint_mismatch")
        expected_updates = [{key: updates[uid][key] for key in ("update_id", "task_id", "org_id", "purpose", "start_order", "sample_count", "weights_digest")}
                            for uid in sorted(manifest["included_update_ids"], key=lambda uid: (updates[uid]["org_id"], uid))]
        if (candidate["updates"] != expected_updates or manifest.get("persistent_protocol") != "ddb-v1"
                or manifest.get("run_id") != run_id or candidate["rule_bundle_hash"] != rule_hash
                or candidate["model_schema_hash"] != evidence["model_schema_hash"]
                or candidate["policy_epochs"] != manifest["policy_epochs"]
                or candidate["parent_manifest_id"] != manifest["parent_manifest_id"]
                or type(candidate["snapshot_order"]) is not int or manifest["commit_order"] != candidate["snapshot_order"] + 1
                or type(candidate["round_generation"]) is not int or candidate["round_generation"] < 0
                or manifest["commit_order"] > sequence["order"]):
            raise ValueError("persistent_candidate_context_mismatch")
        observed_epochs = manifest["policy_epochs"] if proposed else candidate["observed_policy_epochs"]
        if not proposed and (candidate["baseline_id"] != baseline or candidate["policy_decision_mode"] != modes[baseline]
                or candidate["omitted_guards"] != ["receipt_authorization", "continuous_interval_authorization", "publication_policy_epoch"]
                or candidate["policy_epochs"] != {} or manifest.get("baseline_comparator") is not True
                or manifest.get("baseline_id") != baseline or manifest.get("policy_decision_mode") != modes[baseline]
                or manifest.get("observed_policy_epochs") != observed_epochs):
            raise ValueError("baseline_candidate_omitted_guards_binding_mismatch")
        for org in observed_epochs:
            past = [event for event in history if event["org_id"] == org and event["order"] <= candidate["snapshot_order"]]
            if candidate["history_digests"].get(org) != _hash(past) or not past or observed_epochs[org] != past[-1]["epoch"]:
                raise ValueError("candidate_organization_history_digest_mismatch")
        if set(candidate["history_digests"]) != set(observed_epochs):
            raise ValueError("candidate_history_guard_membership_mismatch")
        artifact = _original_artifact(manifest["artifact"])
        reference = {key: artifact.get(key) for key in ("bucket", "key", "version_id", "sha256", "size_bytes")}
        if (candidate["s3"] != reference or candidate["model_digest"] != reference["sha256"]
                or candidate["object_confirmation"] != {key: reference[key] for key in ("version_id", "sha256", "size_bytes")}
                or not reference["key"].startswith(f"models/candidates/{run_id}/")):
            raise ValueError("persistent_candidate_object_binding_mismatch")
        durable_record = rows.get((pk, f"MANIFEST#{manifest['manifest_id']}"), {})
        raw = _json_field(durable_record, "manifest_json")
        if (durable_record.get("record_type") != "publication_manifest" or raw.get("candidate") != candidate
                or raw.get("artifact") != artifact or raw.get("parameters_digest") != manifest["model_digest"]
                or durable_record.get("model_digest") != candidate["model_digest"]
                or any(raw.get(key) != manifest.get(key) for key in ("run_id", "round_id", "manifest_id", "commit_order", "commit_txn_id"))
                or durable_record.get("commit_order") != manifest["commit_order"]):
            raise ValueError("durable_manifest_export_mismatch")
        round_record = rows.get((pk, f"ROUND#{manifest['round_id']}"), {})
        if (round_record.get("status") != "CLOSED" or round_record.get("pending_count") != 0
                or round_record.get("generation") != candidate["round_generation"]
                or round_record.get("manifest_id") != manifest["manifest_id"]
                or round_record.get("commit_order") != manifest["commit_order"]):
            raise ValueError("durable_round_publication_mismatch")
        transaction = rows.get((pk, f"TXN#{manifest['commit_txn_id']}"), {})
        outcome = _json_field(transaction, "result_json")
        prefix = [record for record in evidence["audit"] if record["payload"]["evaluation_order"] <= manifest["commit_order"]]
        if (transaction.get("record_type") != "transaction_outcome" or transaction.get("operation_kind") != "publication"
                or transaction.get("order") != manifest["commit_order"]
                or not isinstance(transaction.get("request_digest"), str) or not _HEX.fullmatch(transaction["request_digest"])
                or outcome != {"manifest_id": manifest["manifest_id"], "commit_order": manifest["commit_order"],
                               "audit_count": len(prefix), "audit_head": prefix[-1]["event_hash"] if prefix else "0" * 64}):
            raise ValueError("durable_publication_outcome_mismatch")
    pointer = rows.get((pk, "POINTER"), {})
    if manifests and any(pointer.get(key) != manifests[-1][key] for key in ("manifest_id", "commit_order", "round_id")):
        raise ValueError("durable_model_pointer_mismatch")
    response = evidence.get("evaluation_service_response", {})
    if not manifests:
        raise ValueError("persistent_success_requires_evaluated_published_model")
    last = manifests[-1]
    bindings = {"run_id": run_id, "manifest_id": last["manifest_id"], "round_id": last["round_id"],
                "model_schema_hash": evidence["model_schema_hash"], "parameters_digest": last["model_digest"],
                "model_sha256": last["artifact"]["sha256"], "metadata_digest": evidence.get("model_metadata_digest"),
                "validation_sha256": evidence.get("validation_source_sha256"), "dataset_role": "validation",
                "final_test_evaluated": False, "manifest_verified": True, "metrics": evidence.get("validation_metrics")}
    sample_field, digest_fields = "validation_sample_digest", ("metadata_digest", "validation_sha256", "validation_sample_digest")
    if test_scope is not None:
        if last["round_id"] != test_scope["final_round"] or "validation_metrics" in evidence:
            raise ValueError("independent_final_model_test_summary_required")
        bindings.pop("validation_sha256")
        bindings.update(dataset_role="test", final_test_evaluated=True, metrics=evidence.get("test_metrics"),
            test_sha256=test_scope["test_sha256"], accepted_plan_digest=test_scope["plan_digest"],
            holdout_authorization_digest=test_scope["authorization_digest"], holdout_authorization_id=test_scope["authorization_id"],
            cell_id=test_scope["cell_id"])
        sample_field, digest_fields = "test_sample_digest", ("metadata_digest", "test_sha256", "test_sample_digest")
    if (not isinstance(response, dict)
            or set(response) != set(bindings) | {"schema_version", "request_id", sample_field}
            or response.get("schema_version") != "0.1.0"
            or any(response.get(key) != value for key, value in bindings.items())
            or response.get("final_test_evaluated") is not (test_scope is not None) or response.get("manifest_verified") is not True
            or any(not isinstance(response.get(key), str) or not _HEX.fullmatch(response[key])
                   for key in digest_fields)
            or not isinstance(response.get("request_id"), str) or not response["request_id"]
            or not isinstance(response.get("metrics"), dict)
            or {"labels", "rows", "predictions", "probabilities", "arrays", "validation_path"} & set(response)):
        raise ValueError("isolated_evaluation_evidence_binding_mismatch")
    _verify_aggregate_metrics(response["metrics"])


def verify_runtime_observations(evidence):
    """Bind local timing brackets to independent authority/decision evidence.

    These are source-pinned observer intervals, never exact commit timestamps or
    a second authorization mechanism. This helper also accepts already assessed
    partial protocol evidence; its result does not confer a full protocol pass.
    """
    trace = evidence.get("runtime_observations")
    empty = {"status": "missing", "clock": "coordinator-perf-counter-relative-ms", "events": [],
        "opportunity_events": None, "measured_events": 0, "right_censored_events": 0, "missing_events": None,
        "exact_response_ms": None, "operation_coverage_complete": False, "measurement_errors": None, "reason": "runtime-observations-absent"}
    if trace is None:
        return {"runtime_observations_verified": False, "revocation_response": empty, "runtime_stage_latency_ms": {}}
    envelope = {"schema_version", "clock", "run_id", "policy_windows", "operations", "stages", "errors"}
    run_id = evidence.get("persistent_run_id", "local-runtime")
    if (not isinstance(trace, dict) or set(trace) != envelope or trace["schema_version"] != "0.1.0"
            or trace["clock"] != empty["clock"] or trace["run_id"] != run_id):
        raise ValueError("runtime_observation_run_or_schema_mismatch")
    for name, limit in (("policy_windows", 1000), ("operations", 10000), ("stages", 5000), ("errors", 1000)):
        if not isinstance(trace[name], list) or len(trace[name]) > limit:
            raise ValueError("bounded_runtime_observation_records_required")
    def ms(value):
        return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 7 * 86400 * 1000
    def identifier(value, nullable=False):
        return value is None and nullable or isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None
    def interval(record):
        if not ms(record["start_ms"]) or not ms(record["end_ms"]) or record["end_ms"] < record["start_ms"]:
            raise ValueError("runtime_observation_interval_invalid")
    stage_fields = {"sequence", "name", "round_id", "start_ms", "end_ms", "status"}
    stages = trace["stages"]
    for sequence, stage in enumerate(stages, 1):
        if (not isinstance(stage, dict) or set(stage) != stage_fields or type(stage["sequence"]) is not int or stage["sequence"] != sequence
                or stage["name"] not in {"run_initialization", "issue_dispatch", "ack_wait", "ack_authorization", "train_dispatch", "policy_barrier", "train_wait", "receipt", "publication", "evaluation", "run"}
                or not identifier(stage["round_id"], True) or stage["status"] not in {"complete", "error"}):
            raise ValueError("runtime_observation_stage_binding_invalid")
        interval(stage)
    run_stages = [stage for stage in stages if stage["name"] == "run"]
    if len(run_stages) != 1 or run_stages[0]["start_ms"] != 0 or run_stages[0]["round_id"] is not None or stages[-1] is not run_stages[0]:
        raise ValueError("explicit_final_runtime_observation_stage_required")
    run_end = run_stages[0]["end_ms"]
    if any(stage["end_ms"] > run_end for stage in stages): raise ValueError("runtime_stage_outside_run_interval")
    for error in trace["errors"]:
        if (not isinstance(error, dict) or set(error) != {"source", "round_id", "event_id", "error_type"}
                or not all(identifier(error[name], name in {"round_id", "event_id"}) for name in error)):
            raise ValueError("runtime_observation_error_schema_invalid")
    history = evidence["policy_events"]
    events = {event["event_id"]: event for event in history}
    if len(events) != len(history): raise ValueError("runtime_observation_duplicate_policy_identity")
    tasks = {task["task_id"]: task for task in evidence["tasks"]}
    # Failed ACKs still have real issued tasks; they are not in the acknowledged
    # task list. The independently verified durable ISSUE records retain them.
    for row in evidence.get("durable_evidence", {}).get("run_records", []):
        if row.get("SK", "").startswith("ISSUE#"):
            task = _json_field(row, "task_json")
            tasks.setdefault(task["task_id"], task)
    updates = {row["update_id"]: row for row in evidence["updates"]}
    decisions, manifests = evidence["decisions"], {row["manifest_id"]: row for row in evidence["published_manifests"]}
    final_errors = {row["update_id"]: row for row in evidence.get("attempt_failures", [])}
    persistent_observations = evidence.get("authority_backend") == "dynamodb-s3-opa"
    durable_rows = _rows_by_key(evidence["durable_evidence"]["run_records"], "RUN#" + run_id) if persistent_observations else {}
    receipt_permissions = {}
    def receipt_permission(uid):
        """Bind receipt-stage permission, never substitute the final OPA result."""
        if not persistent_observations:
            return None
        if uid in receipt_permissions:
            return receipt_permissions[uid]
        update = updates[uid]
        receipt = _json_field(durable_rows.get(("RUN#" + run_id, "UPDATE_META#" + uid), {}), "opa_decision_json")
        baseline = evidence.get("baseline_id", "P1")
        rule_hash = evidence.get("policy_rule_hash")
        if not isinstance(rule_hash, str) or not _HEX.fullmatch(rule_hash):
            raise ValueError("runtime_receipt_policy_rule_binding_missing")
        if baseline in {"B1", "B2", "B3"}:
            _, source = _baseline_policy_source(durable_rows, "RUN#" + run_id, tasks[update["task_id"]], baseline, history, rule_hash)
            if source is None:
                if receipt.get("valid") is not True or receipt.get("query") is not None or receipt.get("decision_id") is not None:
                    raise ValueError("runtime_baseline_receipt_policy_binding_mismatch")
            elif receipt != source:
                raise ValueError("runtime_baseline_receipt_policy_binding_mismatch")
        elif evidence.get("ablation_id") == "Abl-1":
            expected = {"valid": True, "reason": "Abl-1_receipt_check_omitted", "decision_id": None,
                        "query": None, "rule_hash": rule_hash, "native_policy_checked": False}
            if receipt != expected:
                raise ValueError("runtime_omitted_receipt_policy_binding_mismatch")
        else:
            received = update.get("received_order")
            if type(received) is not int or received < update["start_order"]:
                raise ValueError("runtime_receipt_authority_order_missing")
            query = {"org_id": update["org_id"], "purpose": update["purpose"], "actions": _ACTIONS,
                "start_order": received if evidence.get("ablation_id") == "Abl-4" else update["start_order"], "commit_order": received}
            _verify_opa_response(receipt, query, history, rule_hash)
        receipt_permissions[uid] = receipt["valid"]
        return receipt["valid"]
    windows, seen_events = {}, set()
    window_fields = {"event_id", "org_id", "kind", "order", "epoch", "phase", "round_id", "status", "signal_start_ms", "observed_end_ms"}
    for window in trace["policy_windows"]:
        if not isinstance(window, dict) or set(window) != window_fields or window["event_id"] in seen_events:
            raise ValueError("runtime_policy_window_schema_or_duplicate_invalid")
        seen_events.add(window["event_id"])
        event = events.get(window["event_id"])
        if (event is None or any(window[name] != event[name] for name in ("event_id", "org_id", "kind", "order", "epoch"))
                or type(window["order"]) is not int or type(window["epoch"]) is not int
                or not identifier(window["phase"]) or not identifier(window["round_id"], True)):
            raise ValueError("runtime_policy_window_actual_event_binding_mismatch")
        if evidence.get("authority_backend") == "dynamodb-s3-opa":
            # Independently reproduce the public scenario request identity. A
            # real policy event cannot be relabelled as a different run/barrier.
            if window["phase"] not in {"before_run", "before_round", "after_dispatch", "before_commit"}:
                raise ValueError("runtime_policy_window_unknown_barrier")
            expected_ids = set()
            for index in range(8):
                request = "scenario-" + _hash([run_id, window["phase"], window["round_id"], index, window["org_id"], window["kind"]])[:48]
                expected_ids.add("policy-" + hashlib.sha256(request.encode()).hexdigest()[:40])
            if window["event_id"] not in expected_ids:
                raise ValueError("runtime_policy_window_run_barrier_identity_mismatch")
        if window["status"] == "bracketed-new-commit":
            if (not ms(window["signal_start_ms"]) or not ms(window["observed_end_ms"])
                    or not window["signal_start_ms"] <= window["observed_end_ms"] <= run_end):
                raise ValueError("runtime_policy_commit_bracket_invalid")
        elif window["status"] != "preexisting-or-replayed" or window["signal_start_ms"] is not None or window["observed_end_ms"] is not None:
            raise ValueError("runtime_replayed_policy_cannot_claim_commit_bracket")
        windows[window["event_id"]] = window
    op_fields = {"sequence", "operation", "round_id", "org_id", "task_id", "update_id", "start_ms", "end_ms", "outcome", "observation_order", "manifest_id",
                 "included_update_ids", "excluded_update_ids", "pending_update_ids"}
    previous_end, issued, received, published, failed, denied, candidates = 0, set(), set(), set(), set(), set(), []
    pending_by_round, rejected_receipts, finalized_returns = {}, set(), {}
    stage_binding_complete = True
    for sequence, op in enumerate(trace["operations"], 1):
        if (not isinstance(op, dict) or set(op) != op_fields or type(op["sequence"]) is not int or op["sequence"] != sequence
                or op["operation"] not in {"issue", "receive", "publish", "fail"}
                or not identifier(op["round_id"]) or any(not identifier(op[name], True) for name in ("task_id", "update_id"))
                or op["org_id"] is not None and op["org_id"] not in _ORGANIZATIONS
                or op["observation_order"] is not None and (type(op["observation_order"]) is not int or op["observation_order"] < 1)):
            raise ValueError("runtime_operation_schema_binding_invalid")
        interval(op)
        if op["start_ms"] < previous_end or op["end_ms"] > run_end: raise ValueError("runtime_operation_clock_sequence_invalid")
        previous_end = op["end_ms"]
        for name in ("included_update_ids", "excluded_update_ids", "pending_update_ids"):
            if not isinstance(op[name], list) or any(not identifier(uid) for uid in op[name]) or len(set(op[name])) != len(op[name]):
                raise ValueError("runtime_operation_update_set_invalid")
        task = tasks.get(op["task_id"])
        if op["operation"] != "publish" and (op["manifest_id"] is not None or any(op[name] for name in ("included_update_ids", "excluded_update_ids", "pending_update_ids"))):
            raise ValueError("runtime_nonpublication_cannot_claim_model_membership")
        if op["operation"] == "issue":
            if op["outcome"] not in {"issued", "denied", "exception"}: raise ValueError("runtime_issue_outcome_invalid")
            if op["outcome"] == "issued":
                if not task or any(op[name] != task[name] for name in ("task_id", "update_id", "org_id", "round_id")) or op["observation_order"] != task["issue_order"]:
                    raise ValueError("runtime_issued_task_binding_mismatch")
                issued.add(task["task_id"])
            elif op["outcome"] == "denied":
                if op["task_id"] is not None or op["update_id"] is not None or not any(row.get("selected") is False and all(row.get(name) == op[name] for name in ("org_id", "round_id")) and row.get("order") == op["observation_order"] for row in evidence.get("selection", [])):
                    raise ValueError("runtime_denied_selection_binding_mismatch")
                denied.add((op["org_id"], op["round_id"], op["observation_order"]))
                candidates.append((op, None, op["observation_order"]))
        elif op["operation"] in {"receive", "fail"}:
            if not task or any(op[name] != task[name] for name in ("task_id", "update_id", "org_id", "round_id")):
                raise ValueError("runtime_received_or_failed_task_binding_mismatch")
            allowed = {"pending", "accepted", "rejected", "error", "exception"} | ({None} if op["operation"] == "fail" and run_id == "local-runtime" else set())
            if op["outcome"] not in allowed: raise ValueError("runtime_receive_or_fail_outcome_invalid")
            uid = op["update_id"]
            if op["operation"] == "fail":
                failed.add(uid)
                if op["outcome"] in {"accepted", "rejected", "error"}:
                    actual = decisions.get(uid, final_errors.get(uid, {})).get("outcome")
                    if actual != op["outcome"] or uid in finalized_returns and finalized_returns[uid] != op["outcome"]:
                        raise ValueError("runtime_fail_final_outcome_binding_mismatch")
                    finalized_returns[uid] = op["outcome"]
            elif op["outcome"] != "exception":
                if uid not in updates: raise ValueError("runtime_received_update_missing_actual_record")
                received.add(uid)
                permission = receipt_permission(uid)
                prior_finalized = uid in finalized_returns
                if prior_finalized and op["outcome"] != finalized_returns[uid]:
                    raise ValueError("runtime_receipt_reopens_finalized_update")
                if op["outcome"] == "pending":
                    if permission is False:
                        raise ValueError("runtime_pending_receipt_contradicts_durable_policy_denial")
                    pending_by_round.setdefault(op["round_id"], set()).add(uid)
                if op["outcome"] == "rejected":
                    decision = decisions.get(uid, {})
                    if decision.get("outcome") != "rejected" or op["observation_order"] not in {None, decision.get("evaluation_order")}:
                        raise ValueError("runtime_receipt_rejection_decision_binding_mismatch")
                    if not prior_finalized and uid not in rejected_receipts:
                        if permission is True:
                            # This may be an idempotent replay of a previously
                            # finalized update, but it cannot establish a new
                            # receipt-stage rejection from an allowed receipt.
                            stage_binding_complete = False
                        else:
                            candidates.append((op, updates[uid], decision["evaluation_order"]))
                    rejected_receipts.add(uid); pending_by_round.setdefault(op["round_id"], set()).discard(uid)
                    finalized_returns[uid] = "rejected"
                elif op["outcome"] in {"accepted", "error"}:
                    if decisions.get(uid, final_errors.get(uid, {})).get("outcome") != op["outcome"]:
                        raise ValueError("runtime_receipt_final_outcome_binding_mismatch")
                    if not prior_finalized:
                        stage_binding_complete = False
                    finalized_returns[uid] = op["outcome"]
                    pending_by_round.setdefault(op["round_id"], set()).discard(uid)
        else:
            if op["org_id"] is not None or op["task_id"] is not None or op["update_id"] is not None or op["outcome"] not in {"published", "empty", "exception"}:
                raise ValueError("runtime_publication_outcome_or_scope_invalid")
            round_updates = {uid for uid, row in updates.items() if row["round_id"] == op["round_id"]}
            if not set(op["pending_update_ids"]) <= round_updates or not set(op["excluded_update_ids"]) <= round_updates:
                raise ValueError("runtime_publication_pending_or_excluded_binding_mismatch")
            if op["outcome"] == "published":
                manifest = manifests.get(op["manifest_id"])
                if (not manifest or manifest["round_id"] != op["round_id"] or set(manifest["included_update_ids"]) != set(op["included_update_ids"])
                        or op["observation_order"] != manifest["commit_order"]):
                    raise ValueError("runtime_publication_manifest_binding_mismatch")
                published.add(op["manifest_id"])
            elif op["manifest_id"] is not None or op["included_update_ids"] or op["observation_order"] is not None:
                raise ValueError("runtime_unpublished_operation_cannot_claim_manifest")
            if op["outcome"] != "exception":
                if set(op["pending_update_ids"]) != pending_by_round.get(op["round_id"], set()):
                    raise ValueError("runtime_publication_pending_before_mismatch")
                if set(op["excluded_update_ids"]) != round_updates - set(op["included_update_ids"]):
                    raise ValueError("runtime_publication_excluded_membership_mismatch")
                for uid in set(op["pending_update_ids"]) - set(op["included_update_ids"]) - set(finalized_returns):
                    decision = decisions.get(uid, {})
                    if decision.get("outcome") == "rejected":
                        # Receipt denial cannot be relabelled as publication
                        # revalidation. Earlier operational finalization is
                        # likewise not a newly observed authorization response.
                        if receipt_permission(uid) is False:
                            raise ValueError("runtime_publication_relabels_durable_receipt_denial")
                        if not persistent_observations or decision.get("reason") == "authorization_interrupted":
                            candidates.append((op, updates[uid], decision["evaluation_order"]))
                for uid in op["included_update_ids"]:
                    finalized_returns[uid] = "accepted"
                for uid in op["excluded_update_ids"]:
                    if decisions.get(uid, {}).get("outcome") == "rejected":
                        finalized_returns[uid] = "rejected"
                pending_by_round[op["round_id"]] = set()
    selection_denied = {(row["org_id"], row["round_id"], row["order"]) for row in evidence.get("selection", []) if row.get("selected") is False}
    coverage = stage_binding_complete and issued == set(tasks) and received == set(updates) and published == set(manifests) and set(final_errors) <= failed and selection_denied <= denied
    def point(org, order):
        if order < 1: return False
        return evaluate_interval(history, {"org_id": org, "purpose": "readmission", "actions": _ACTIONS, "start_order": order, "commit_order": order})["valid"]
    def loss(event):
        return event["kind"] in {"REVOKE", "EXPIRE", "CHANGE"} and point(event["org_id"], event["order"] - 1) and not point(event["org_id"], event["order"])
    def causal(event, start):
        if start <= event["order"]:
            return start == event["order"] or evaluate_interval(history, {"org_id": event["org_id"], "purpose": "readmission", "actions": _ACTIONS, "start_order": start, "commit_order": event["order"] - 1})["valid"]
        return not point(event["org_id"], start) and not any(point(event["org_id"], row["order"]) for row in history if row["org_id"] == event["org_id"] and event["order"] < row["order"] <= start)
    def policy_denial(update, order):
        query = {"org_id": update["org_id"], "purpose": update["purpose"], "actions": _ACTIONS,
                 "start_order": update["start_order"], "commit_order": order}
        if evaluate_interval(history, query)["valid"]: return False
        if evidence.get("authority_backend") == "dynamodb-s3-opa":
            final_opa = [row for row in evidence["durable_evidence"]["run_records"] if row.get("SK") == "OPA_FINAL#" + update["update_id"]]
            return len(final_opa) == 1 and _json_field(final_opa[0], "opa_decision_json").get("valid") is False
        return True
    own_orders = [row["issue_order"] for row in tasks.values()] + [row["order"] for row in evidence.get("selection", [])]
    own_orders += [window["order"] for window in windows.values()]
    upper = evidence.get("durable_evidence", {}).get("sequence", {}).get("order")
    if type(upper) is not int:
        upper = max([row["evaluation_order"] for row in decisions.values()] + [row["commit_order"] for row in manifests.values()] + own_orders, default=0)
    lower = min(own_orders, default=upper + 1)
    losses = [event for event in history if lower <= event["order"] <= upper and loss(event)]
    results, violations = [], set()
    for event in losses:
        window = windows.get(event["event_id"])
        record = {"run_id": run_id, "event_id": event["event_id"], "org_id": event["org_id"], "kind": event["kind"], "order": event["order"], "epoch": event["epoch"],
            "status": "missing", "response_lower_ms": None, "response_upper_ms": None, "exact_response_ms": None,
            "censor_lower_ms": None, "censor_upper_ms": None, "operation_sequence": None, "operation": None,
            "task_id": None, "update_id": None, "manifest_id": None, "enforcement_order": None, "reason": "policy-window-or-operation-coverage-missing"}
        if window and window["status"] == "bracketed-new-commit" and coverage and not trace["errors"]:
            eligible = []
            for op, update, order in candidates:
                if order < event["order"]: continue
                org = update["org_id"] if update else op["org_id"]
                if org != event["org_id"]: continue
                start = update["start_order"] if update else order
                if (not causal(event, start) or point(org, order) and update is None
                        or update is not None and not policy_denial(update, order)): continue
                if op["end_ms"] < window["signal_start_ms"]: raise ValueError("runtime_operation_clock_precedes_causal_policy_commit")
                eligible.append((op, update, order))
            if eligible:
                op, update, order = min(eligible, key=lambda item: item[0]["end_ms"])
                record.update(status="measured", response_lower_ms=max(0, op["start_ms"] - window["observed_end_ms"]),
                    response_upper_ms=op["end_ms"] - window["signal_start_ms"], operation_sequence=op["sequence"], operation=op["operation"],
                    task_id=update["task_id"] if update else op["task_id"], update_id=update["update_id"] if update else op["update_id"],
                    manifest_id=op["manifest_id"], enforcement_order=order, reason="first-eligible-durable-denial-interval")
            else:
                record.update(status="right-censored", censor_lower_ms=max(0, run_end - window["observed_end_ms"]),
                    censor_upper_ms=run_end - window["signal_start_ms"], reason="no-eligible-durable-denial-before-run-end")
        results.append(record)
        for manifest in manifests.values():
            for uid in manifest["included_update_ids"]:
                update = updates[uid]
                query = {"org_id": update["org_id"], "purpose": update["purpose"], "actions": _ACTIONS, "start_order": update["start_order"], "commit_order": manifest["commit_order"]}
                if (update["org_id"] == event["org_id"] and manifest["commit_order"] >= event["order"] and causal(event, update["start_order"])
                        and not evaluate_interval(history, query)["valid"]): violations.add(manifest["manifest_id"])
    counts = {status: sum(row["status"] == status for row in results) for status in ("measured", "right-censored", "missing")}
    overall = next(iter({row["status"] for row in results})) if results and len({row["status"] for row in results}) == 1 else "mixed" if results else "no-event"
    if not results and (trace["errors"] or not coverage): overall = "missing"
    response = {"status": overall, "clock": trace["clock"], "events": results, "opportunity_events": len(results),
        "measured_events": counts["measured"], "right_censored_events": counts["right-censored"], "missing_events": counts["missing"],
        "exact_response_ms": None, "operation_coverage_complete": coverage, "measurement_errors": len(trace["errors"]),
        "reason": "authority-bound-observer-brackets;not-exact-or-hardware-attested"}
    latencies = {}
    for stage in stages:
        name = stage["name"] if stage["status"] == "complete" else "failure"
        latencies.setdefault(name, []).append(stage["end_ms"] - stage["start_ms"])
    return {"runtime_observations_verified": True, "revocation_response": response, "runtime_stage_latency_ms": latencies,
            "oracle_post_authorization_loss_invalid_publications": len(violations)}


def verify_case(result_path, *, expect_safe=None, expect_test_authorization=None):
    path = Path(result_path)
    evidence = json.loads(path.read_text(encoding="utf-8"))
    if "ablation_id" in evidence or evidence.get("full_protocol", True) is not True:
        raise ValueError("partial_ablation_requires_separate_assessment_not_full_protocol_pass")
    test_scope = None
    if expect_test_authorization is None:
        if evidence.get("successful") is not True or evidence.get("test_holdout_evaluated") is not False:
            raise ValueError("successful_validation_only_case_required")
    else:
        if evidence.get("successful") is not True or evidence.get("test_holdout_evaluated") is not True:
            raise ValueError("successful_explicitly_authorized_test_case_required")
        test_scope = _independent_holdout_scope(expect_test_authorization, evidence)
        if evidence.get("baseline_id") == "P1" and expect_safe is False:
            raise ValueError("test_authorization_cannot_disable_P1_safety")
    if evidence.get("baseline_id") not in {"B1", "B2", "B3", "P1"}:
        raise ValueError("unknown_baseline_id")
    if not verify_chain(evidence["audit"], evidence["anchor"]):
        raise ValueError("audit_integrity_failed")
    updates = {record["update_id"]: record for record in evidence["updates"]}
    tasks = {record["task_id"]: record for record in evidence["tasks"]}
    if len(updates) != len(evidence["updates"]) or len(tasks) != len(evidence["tasks"]):
        raise ValueError("duplicate_update_or_task_identity")
    decisions = evidence["decisions"]
    raw_errors = evidence.get("attempt_failures", [])
    if not isinstance(raw_errors, list) or any(not isinstance(record, dict) or not isinstance(record.get("update_id"), str) for record in raw_errors):
        raise ValueError("malformed_final_operational_errors")
    errors = {record["update_id"]: record for record in raw_errors}
    if len(errors) != len(raw_errors) or set(errors) & set(decisions) or set(errors) & set(updates):
        raise ValueError("duplicate_final_operational_error")
    final = {**decisions, **errors}
    if set(updates) != set(decisions) or len(evidence["audit"]) != len(final):
        raise ValueError("incomplete_final_decision_evidence")
    if {record["payload"]["update_id"] for record in evidence["audit"]} != set(final):
        raise ValueError("audit_outcome_membership_mismatch")
    for record in evidence["audit"]:
        if record["payload"] != final[record["payload"]["update_id"]]:
            raise ValueError("audit_outcome_content_mismatch")
    history = sorted(evidence["policy_events"], key=lambda record: record["order"])
    persistent = evidence.get("authority_backend") == "dynamodb-s3-opa"
    if errors and not persistent:
        raise ValueError("final_operational_errors_require_durable_evidence")
    if test_scope is not None and not persistent:
        raise ValueError("final_holdout_requires_verified_persistent_publication")
    if not persistent and any(manifest.get("persistent_protocol") for manifest in evidence["published_manifests"]):
        raise ValueError("persistent_authority_label_required")
    for decision in final.values():
        observed = [event for event in history if event["order"] <= decision["evaluation_order"]]
        if persistent:
            if decision.get("history_digest_scope") != "organization":
                raise ValueError("organization_history_digest_scope_required")
            observed = [event for event in observed if event["org_id"] == decision["org_id"]]
        if decision["history_digest"] != _hash(observed):
            raise ValueError("decision_policy_history_digest_mismatch")
    if persistent:
        _verify_persistent(evidence, history, updates, tasks, test_scope=test_scope, errors=errors)
    assigned = {task["update_id"]: task for task in tasks.values()}
    if len(assigned) != len(tasks):
        raise ValueError("duplicate_assigned_update_identity")
    if persistent:
        for row in evidence["durable_evidence"]["run_records"]:
            if row["SK"].startswith("ISSUE#"):
                task = _json_field(row, "task_json")
                if (row["SK"] != "ISSUE#" + task.get("task_id", "") or task.get("start_order") is not None
                        or not isinstance(task.get("update_id"), str) or not task["update_id"]):
                    raise ValueError("durable_assigned_task_identity_mismatch")
                previous = assigned.get(task["update_id"])
                if previous and any(previous.get(name) != value for name, value in task.items() if name != "start_order"):
                    raise ValueError("durable_assigned_task_rebound")
                assigned.setdefault(task["update_id"], task)
    if not set(final) <= set(assigned):
        raise ValueError("final_outcome_without_assigned_task")
    parameters = {}
    for uid, record in updates.items():
        parameters[uid] = _load_artifact(record["artifact"], path.parent)
        if record["weights_digest"] != record["artifact"]["model_digest"]:
            raise ValueError("update_artifact_binding_mismatch")
        task = tasks[record["task_id"]]
        for field in ("update_id", "org_id", "round_id", "purpose", "start_order", "node_id", "model_schema_hash"):
            if task[field] != record[field]:
                raise ValueError("update_task_binding_mismatch")
        for field in ("update_id", "task_id", "org_id", "round_id", "purpose", "start_order"):
            if decisions[uid].get(field) != record[field]:
                raise ValueError("decision_update_binding_mismatch")
        if record["model_schema_hash"] != evidence["model_schema_hash"]:
            raise ValueError("update_global_model_schema_mismatch")
        if type(record["sample_count"]) is not int or record["sample_count"] <= 0:
            raise ValueError("invalid_retained_sample_count")
    manifests, included, round_commits = evidence["published_manifests"], set(), {}
    previous = None
    for manifest in manifests:
        if (type(manifest.get("guarded_policy_publication")) is not bool
                or manifest["guarded_policy_publication"] != (evidence["baseline_id"] == "P1")):
            raise ValueError("baseline_publication_guard_label_mismatch")
        if not persistent and manifest["manifest_id"] != _hash({key: value for key, value in manifest.items() if key != "manifest_id"}):
            raise ValueError("manifest_digest_mismatch")
        if manifest["parent_manifest_id"] != previous:
            raise ValueError("model_parent_chain_broken")
        if manifest["model_schema_hash"] != evidence["model_schema_hash"]:
            raise ValueError("manifest_global_model_schema_mismatch")
        previous = manifest["manifest_id"]
        members = manifest["included_update_ids"]
        if not members or len(members) != len(set(members)) or included & set(members):
            raise ValueError("empty_or_duplicated_model_inclusion")
        if not set(members) <= set(updates):
            raise ValueError("unknown_included_update")
        included.update(members)
        round_commits[manifest["round_id"]] = manifest["commit_order"]
        model = _load_artifact(manifest["artifact"], path.parent)
        if manifest["model_digest"] != _parameter_digest(model):
            raise ValueError("manifest_model_digest_mismatch")
        ordered = sorted(members, key=lambda uid: (updates[uid]["org_id"], uid))
        if any(len(parameters[uid]) != len(model) for uid in ordered):
            raise ValueError("published_model_parameter_count_mismatch")
        counts = np.asarray([updates[uid]["sample_count"] for uid in ordered], dtype=np.float64)
        weights = counts / counts.sum()
        epochs = manifest.get("observed_policy_epochs", {}) if persistent and not manifest["guarded_policy_publication"] else manifest["policy_epochs"]
        if {updates[uid]["org_id"] for uid in members} != set(epochs):
            raise ValueError("missing_contributing_policy_epoch")
        for org, epoch in epochs.items():
            if type(epoch) is not int or epoch < 1:
                raise ValueError("invalid_manifest_policy_epoch")
            if manifest["guarded_policy_publication"]:
                preceding = [event for event in history if event["org_id"] == org and event["order"] <= manifest["commit_order"]]
                if not preceding or preceding[-1]["epoch"] != epoch:
                    raise ValueError("guarded_manifest_policy_epoch_mismatch")
        for index, value in enumerate(model):
            if any(parameters[uid][index].shape != value.shape for uid in ordered):
                raise ValueError("published_model_parameter_shape_mismatch")
            stack = np.stack([parameters[uid][index].astype(np.float64) for uid in ordered])
            expected = np.tensordot(weights, stack, axes=(0, 0)).astype(np.float32)
            if not np.allclose(value, expected, rtol=1e-6, atol=1e-7):
                raise ValueError("published_model_not_reconstructed_from_declared_updates")
        for uid in members:
            if (updates[uid]["round_id"] != manifest["round_id"]
                    or decisions[uid]["outcome"] != "accepted"
                    or decisions[uid]["evaluation_order"] != manifest["commit_order"]
                    or decisions[uid]["manifest_ref"] != manifest["manifest_id"]):
                raise ValueError("acceptance_manifest_binding_mismatch")
            if manifest["guarded_policy_publication"] and decisions[uid]["observed_epoch"] != manifest["policy_epochs"][updates[uid]["org_id"]]:
                raise ValueError("decision_guarded_epoch_mismatch")
    if {uid for uid, record in decisions.items() if record["outcome"] == "accepted"} != included:
        raise ValueError("accepted_outcome_missing_from_manifest")
    invalid, invalid_included, valid_rejected = set(), set(), set()
    for uid, update in updates.items():
        end = round_commits.get(update["round_id"], decisions[uid]["evaluation_order"])
        query = {"org_id": update["org_id"], "purpose": update["purpose"], "start_order": update["start_order"],
                 "commit_order": end, "actions": ["train", "submit_update", "aggregate"]}
        valid = evaluate_interval(evidence["policy_events"], query)["valid"]
        if not valid:
            invalid.add(uid)
            if uid in included:
                invalid_included.add(uid)
        elif decisions[uid]["outcome"] == "rejected":
            valid_rejected.add(uid)
    if expect_safe is None:
        expect_safe = evidence["baseline_id"] == "P1"
    if expect_safe and invalid_included:
        raise ValueError("oracle_invalid_update_in_published_model")
    if manifests and evidence["current_model_digest"] != manifests[-1]["model_digest"]:
        raise ValueError("current_model_pointer_mismatch")
    return {"successful": True, "baseline_id": evidence["baseline_id"], "scenario_id": evidence["scenario_id"],
            "unique_presented_updates": len(updates), "oracle_invalid_presented": len(invalid),
            "oracle_invalid_incorporations": len(invalid_included), "oracle_valid_rejections": len(valid_rejected),
            "accepted_updates": len(included), "final_decisions": len(final), "published_models": len(manifests),
            "assigned_tasks": len(assigned), "acknowledged_tasks": len(tasks), "final_update_decisions": len(decisions),
            "final_operational_errors": len(errors), "indeterminate_tasks": len(set(assigned) - set(final)),
            "audited_final_decisions": len(evidence["audit"]), "audit_complete_decisions": len(final),
            "audit_verified": True, "model_reconstruction_verified": True,
            "persistent_protocol_verified": persistent, "committed_evaluation_response_verified": persistent,
            "model_digests": [record["model_digest"] for record in manifests],
            **verify_runtime_observations(evidence),
            **({"test_metrics": evidence.get("test_metrics"), "evaluation_split": "test", "final_holdout_authorization_verified": True,
                "accepted_plan_digest": test_scope["plan_digest"], "holdout_authorization_digest": test_scope["authorization_digest"],
                "cell_id": test_scope["cell_id"]} if test_scope is not None else {"validation_metrics": evidence.get("validation_metrics")}),
            "is_confirmatory": False}
