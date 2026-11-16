"""Independent partial-protocol checks; never certify an ablation as full P1.

No authority, transaction-builder, aggregation or OPA-client imports. Witness
verification requires a caller-provided external public-key fingerprint.
"""

import base64
import hashlib
import json
from pathlib import Path

import numpy as np

from .oracle import evaluate_interval
from .runtime_verify import _load_artifact
from .verifier import verify_chain

_ACTIONS = ["train", "submit_update", "aggregate"]
_OMITTED = {"Abl-1": ["receipt_native_authorization"], "Abl-2": ["publication_contributor_epoch_checks"],
            "Abl-3": ["persistent_audit_chain"], "Abl-4": ["continuous_authorization_history"]}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def verify_protected_witness(witness, public_key_pem, expected_public_key_sha256):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
            return False
        public = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if (witness.get("algorithm") != "ECDSA-P384-SHA384" or hashlib.sha256(public).hexdigest() != expected_public_key_sha256
                or witness.get("public_key_sha256") != expected_public_key_sha256
                or witness.get("payload_sha256") != digest(witness["payload"])):
            return False
        key.verify(base64.b64decode(witness["signature_base64"], validate=True), canonical(witness["payload"]), ec.ECDSA(hashes.SHA384()))
        return True
    except (KeyError, ValueError, TypeError, InvalidSignature):
        return False


def _json(record, field):
    try:
        return json.loads(record[field])
    except (KeyError, TypeError, json.JSONDecodeError):
        raise ValueError("partial_protocol_durable_json_missing") from None


def assess_case(path, *, witness, public_key_pem, expected_public_key_sha256):
    path = Path(path)
    raw = path.read_bytes()
    evidence = json.loads(raw)
    if not verify_protected_witness(witness, public_key_pem, expected_public_key_sha256):
        raise ValueError("protected_witness_signature_or_external_pin_failed")
    run_id = evidence["persistent_run_id"]
    binding = witness["payload"]
    if (binding.get("raw_result_sha256") != hashlib.sha256(raw).hexdigest() or binding.get("run_id") != run_id
            or binding.get("anchor") != evidence["anchor"]):
        raise ValueError("protected_witness_evidence_binding_failed")
    variant = evidence.get("ablation_id")
    if variant is not None and (variant not in _OMITTED or evidence.get("full_protocol") is not False
                               or evidence.get("ablated_safeguards") != _OMITTED[variant]):
        raise ValueError("explicit_partial_protocol_variant_required")
    history = sorted(evidence["policy_events"], key=lambda event: event["order"])
    tasks = {task["task_id"]: task for task in evidence["tasks"]}
    updates = {update["update_id"]: update for update in evidence["updates"]}
    if len(tasks) != len(evidence["tasks"]) or len(updates) != len(evidence["updates"]):
        raise ValueError("duplicate_partial_protocol_identity")
    final = dict(evidence["decisions"])
    for error in evidence.get("attempt_failures", []):
        if error["update_id"] in final or error.get("outcome") != "error":
            raise ValueError("duplicate_or_invalid_final_error_record")
        final[error["update_id"]] = error
    rows = {}
    for row in evidence["durable_evidence"]["run_records"]:
        if row["PK"] != "RUN#" + run_id or row["SK"] in rows:
            raise ValueError("partial_durable_row_identity_failed")
        rows[row["SK"]] = row
    assigned = {task["update_id"] for task in tasks.values()}
    for key, row in rows.items():
        if key.startswith("ISSUE#"):
            assigned.add(_json(row, "task_json")["update_id"])
    if not set(final) <= assigned:
        raise ValueError("final_decision_without_assigned_task")
    pending = sorted(assigned - set(final))
    native_hash = hashlib.sha256((Path(__file__).resolve().parents[2] / "policies/rego/pcfl.rego").read_bytes()).hexdigest()
    if evidence["policy_rule_hash"] != native_hash:
        raise ValueError("partial_policy_source_hash_mismatch")
    for uid, decision in final.items():
        task = tasks.get(decision["task_id"])
        required = {"update_id", "task_id", "org_id", "round_id", "purpose", "start_order", "outcome", "reason",
                    "evaluation_order", "observed_epoch", "history_digest", "history_digest_scope", "manifest_ref", "run_id", "rule_bundle_hash"}
        if (not required <= set(decision) or not task or decision["outcome"] not in {"accepted", "rejected", "error"}
                or decision["run_id"] != run_id or decision["rule_bundle_hash"] != native_hash
                or any(decision[field] != task[field] for field in ("update_id", "task_id", "org_id", "round_id", "purpose", "start_order"))):
            raise ValueError("mandatory_final_allow_deny_error_fields_missing")
        past = [event for event in history if event["org_id"] == decision["org_id"] and event["order"] <= decision["evaluation_order"]]
        if decision["history_digest_scope"] != "organization" or digest(past) != decision["history_digest"]:
            raise ValueError("final_outcome_history_binding_failed")
        if decision["outcome"] == "error":
            if (uid in updates or decision.get("authorization_status") != "not_evaluated_operational_error"
                    or decision.get("policy_decision_id") is not None or decision.get("policy_query") is not None
                    or _json(rows.get("ATTEMPT#" + task["task_id"], {}), "decision_json") != decision):
                raise ValueError("final_operational_error_not_durably_attributable")
        else:
            if uid not in updates or _json(rows.get("UPDATE#" + uid, {}), "decision_json") != decision:
                raise ValueError("final_update_decision_not_durable")
            response = _json(rows.get("OPA_FINAL#" + uid, {}), "opa_decision_json")
            start = decision["evaluation_order"] if variant == "Abl-4" else decision["start_order"]
            query = {"org_id": decision["org_id"], "purpose": decision["purpose"], "start_order": start,
                     "commit_order": decision["evaluation_order"], "actions": _ACTIONS}
            global_past = [event for event in history if event["order"] <= query["commit_order"]]
            expected = evaluate_interval(history, query)
            if (response.get("query") != query or response.get("decision_id") != decision.get("policy_decision_id")
                    or decision.get("policy_query") != query or response.get("rule_hash") != native_hash
                    or response.get("history_digest") != digest(global_past)
                    or response.get("request_hash") != digest({"events": global_past, "query": query})
                    or response.get("opa_version") != "1.22.3" or response.get("protocol_revision") != "pcfl-interval-v1"
                    or response.get("valid") != expected["valid"] or not response.get("request_binding")):
                raise ValueError("actual_native_ablation_query_binding_failed")
    audit = evidence["audit"]
    head = rows.get("AUDIT_HEAD", {})
    if {field: head.get(field) for field in ("count", "head")} != evidence["anchor"]:
        raise ValueError("partial_durable_audit_head_binding_failed")
    if not verify_chain(audit, evidence["anchor"]):
        raise ValueError("partial_protocol_audit_chain_corrupt")
    audited = {event["payload"]["update_id"] for event in audit}
    for event in audit:
        uid = event["payload"]["update_id"]
        stored = rows.get(f"AUDIT#{event['sequence']:020d}", {})
        if event["payload"] != final.get(uid) or _json(stored, "event_json") != event or stored.get("event_hash") != event["event_hash"]:
            raise ValueError("final_allow_deny_error_audit_binding_failed")
    if not audited <= set(final):
        raise ValueError("audit_without_final_outcome")
    missing_audit = sorted(set(final) - audited)
    if variant != "Abl-3" and missing_audit:
        raise ValueError("mandatory_final_outcome_audit_missing")
    pointer = rows.get("POINTER", {})
    manifests, seen = evidence["published_manifests"], set()
    last = None
    parameters = {}
    for uid, update in updates.items():
        parameters[uid] = _load_artifact(update["artifact"], path.parent)
        stored_update = rows.get("UPDATE#" + uid, {})
        meta = rows.get("UPDATE_META#" + uid, {})
        original_artifact = {field: value for field, value in update["artifact"].items() if field != "local_export"}
        fields = ("update_id", "task_id", "org_id", "round_id", "purpose", "start_order", "sample_count", "weights_digest", "model_schema_hash")
        if (any(stored_update.get(field) != update[field] for field in fields)
                or update["weights_digest"] != update["artifact"]["model_digest"]
                or _json(meta, "artifact_json") != original_artifact or meta.get("node_id") != update["node_id"]):
            raise ValueError("partial_immutable_update_binding_failed")
    invalid_presented, invalid_included = 0, 0
    for manifest in manifests:
        candidate = manifest["candidate_metadata"]
        if (candidate.get("candidate_id") != digest({key: value for key, value in candidate.items() if key != "candidate_id"})
                or manifest["manifest_id"] != candidate["candidate_id"] or manifest["parent_manifest_id"] != last
                or candidate["snapshot_order"] + 1 != manifest["commit_order"] or manifest["model_schema_hash"] != evidence["model_schema_hash"]):
            raise ValueError("partial_candidate_fingerprint_or_chain_failed")
        if variant is not None and (candidate.get("ablation_id") != variant or candidate.get("full_protocol") is not False
                                   or candidate.get("ablated_safeguards") != _OMITTED[variant]):
            raise ValueError("partial_candidate_variant_binding_failed")
        stored = _json(rows.get("MANIFEST#" + manifest["manifest_id"], {}), "manifest_json")
        artifact = {field: value for field, value in manifest["artifact"].items() if field != "local_export"}
        reference = {field: artifact[field] for field in ("bucket", "key", "version_id", "sha256", "size_bytes")}
        if (stored.get("candidate") != candidate or stored.get("parameters_digest") != manifest["model_digest"]
                or stored.get("artifact") != artifact or manifest["model_digest"] != artifact["model_digest"]
                or any(stored.get(field) != manifest[field] for field in ("run_id", "round_id", "manifest_id", "commit_order", "commit_txn_id"))
                or candidate["s3"] != reference or candidate["model_digest"] != artifact["sha256"]
                or candidate["object_confirmation"] != {field: reference[field] for field in ("version_id", "sha256", "size_bytes")}):
            raise ValueError("partial_model_manifest_not_durable")
        model = _load_artifact(manifest["artifact"], path.parent)
        members = sorted(manifest["included_update_ids"], key=lambda uid: (updates[uid]["org_id"], uid))
        if not members or len(set(members)) != len(members) or seen & set(members):
            raise ValueError("duplicate_or_empty_partial_model_membership")
        candidate_updates = [{field: updates[uid][field] for field in ("update_id", "task_id", "org_id", "purpose", "start_order", "sample_count", "weights_digest")}
                             for uid in members]
        if candidate["updates"] != candidate_updates:
            raise ValueError("partial_candidate_membership_binding_failed")
        observed = candidate.get("observed_policy_epochs", candidate["policy_epochs"])
        if set(observed) != {updates[uid]["org_id"] for uid in members}:
            raise ValueError("partial_candidate_organization_guards_missing")
        for org, epoch in observed.items():
            past = [event for event in history if event["org_id"] == org and event["order"] <= candidate["snapshot_order"]]
            if not past or past[-1]["epoch"] != epoch or digest(past) != candidate["history_digests"].get(org):
                raise ValueError("partial_candidate_history_binding_failed")
        if variant == "Abl-2" and (candidate["policy_epochs"] != {} or candidate["guard_configuration"].get("global_policy_sequence_CAS") is not True):
            raise ValueError("epoch_ablation_must_declare_retained_global_fence")
        counts = np.asarray([updates[uid]["sample_count"] for uid in members], dtype=np.float64)
        if np.any(counts <= 0) or not np.isfinite(counts).all():
            raise ValueError("invalid_partial_weight_counts")
        for index, value in enumerate(model):
            if any(len(parameters[uid]) != len(model) or parameters[uid][index].shape != value.shape for uid in members):
                raise ValueError("partial_model_parameter_shape_mismatch")
            expected = np.tensordot(counts / counts.sum(), np.stack([parameters[uid][index].astype(np.float64) for uid in members]), axes=(0, 0)).astype(np.float32)
            if not np.allclose(value, expected, rtol=1e-6, atol=1e-7):
                raise ValueError("partial_weighted_model_reconstruction_failed")
        for uid in members:
            decision = final[uid]
            if decision["outcome"] != "accepted" or decision["manifest_ref"] != manifest["manifest_id"] or decision["evaluation_order"] != manifest["commit_order"]:
                raise ValueError("partial_acceptance_manifest_binding_failed")
        transaction = rows.get("TXN#" + manifest["commit_txn_id"], {})
        outcome = _json(transaction, "result_json")
        if (transaction.get("operation_kind") != "publication" or transaction.get("order") != manifest["commit_order"]
                or outcome.get("manifest_id") != manifest["manifest_id"] or outcome.get("commit_order") != manifest["commit_order"]):
            raise ValueError("partial_publication_transaction_binding_failed")
        prefix = [record for record in audit if record["payload"]["evaluation_order"] <= manifest["commit_order"]]
        if variant == "Abl-3":
            if outcome.get("audit_persistence") != "omitted-by-Abl-3" or "audit_head" in outcome or "audit_count" in outcome:
                raise ValueError("audit_ablation_must_not_claim_persisted_chain")
        elif outcome.get("audit_count") != len(prefix) or outcome.get("audit_head") != (prefix[-1]["event_hash"] if prefix else "0" * 64):
            raise ValueError("partial_publication_audit_prefix_binding_failed")
        seen.update(members); last = manifest["manifest_id"]
    if {uid for uid, value in final.items() if value["outcome"] == "accepted"} != seen:
        raise ValueError("partial_acceptance_missing_model")
    if manifests:
        if (pointer.get("manifest_id") != last or pointer.get("commit_order") != manifests[-1]["commit_order"]
                or pointer.get("round_id") != manifests[-1]["round_id"] or binding.get("manifest_id") != last
                or binding.get("model_digest") != manifests[-1]["model_digest"] or binding.get("commit_order") != manifests[-1]["commit_order"]
                or binding.get("model_schema_hash") != evidence["model_schema_hash"]):
            raise ValueError("protected_partial_model_pointer_mismatch")
    elif pointer.get("manifest_id") or binding.get("manifest_id") is not None or binding.get("commit_order") != 0:
        raise ValueError("unexpected_partial_published_pointer")
    for uid, update in updates.items():
        end = final.get(uid, {}).get("evaluation_order", evidence["durable_evidence"]["sequence"]["order"])
        query = {"org_id": update["org_id"], "purpose": update["purpose"], "start_order": update["start_order"],
                 "commit_order": end, "actions": _ACTIONS}
        if not evaluate_interval(history, query)["valid"]:
            invalid_presented += 1; invalid_included += int(uid in seen)
    return {"schema_version": "0.1.0", "assessment_scope": "independent-partial-protocol", "ablation_id": variant,
        "full_protocol_pass": False, "protected_witness_verified": True, "weighted_models_tested": len(manifests),
        "weighted_models_verified": len(manifests), "model_pointer_verified": True,
        "task_assignment_count": len(assigned), "acknowledged_task_count": len(tasks), "presented_update_count": len(updates),
        "final_allow_count": sum(value["outcome"] == "accepted" for value in final.values()),
        "final_deny_count": sum(value["outcome"] == "rejected" for value in final.values()),
        "final_error_count": sum(value["outcome"] == "error" for value in final.values()),
        "indeterminate_count": len(pending), "indeterminate_update_ids": pending,
        "final_audit_expected_count": len(final), "final_audit_recorded_count": len(audited),
        "missing_final_audit_update_ids": missing_audit,
        "audit_complete_for_all_final_outcomes": not missing_audit,
        "attempt_accounting_complete": not pending,
        "oracle_invalid_presented": invalid_presented, "oracle_invalid_incorporations": invalid_included}
