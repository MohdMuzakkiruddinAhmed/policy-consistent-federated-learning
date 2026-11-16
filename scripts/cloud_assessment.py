"""Host-only protected witness binding and explicitly partial aggregate metrics."""
from collections import Counter
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re

from pcfl.experiments import COUNT_METRICS, UTILITY_METRICS, validate_revocation_response
from pcfl.oracle import evaluate_interval
from pcfl.runtime_verify import _verify_aggregate_metrics, verify_runtime_observations
from anchor_evidence import verify_witness

HEX = re.compile(r"[0-9a-f]{64}")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def regular_owned_file(root, value):
    root, path = Path(root).resolve(), Path(value).absolute()
    if not path.resolve().is_relative_to(root) or not path.is_file():
        raise ValueError("protected_witness_outside_owned_case")
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("linked_protected_witness_forbidden")
        if part == root:
            break
    return path


def verify_retained_witness(inventory, *, application, cell_id, raw_path, public_key_path, public_key_pin):
    """Pin is supplied externally; never obtain trust from a witness's own key."""
    if public_key_path is None or not isinstance(public_key_pin, str) or not HEX.fullmatch(public_key_pin):
        raise ValueError("external_operator_public_key_and_pin_required")
    raw_path = Path(raw_path).resolve()
    body, raw = raw_path.read_bytes(), json.loads(raw_path.read_text(encoding="utf-8"))
    raw_sha = hashlib.sha256(body).hexdigest()
    records = [row for row in inventory.get("protected_operator_witnesses", []) if row.get("cell_id") == cell_id
        and row.get("application_campaign_id", inventory["campaign_id"]) == application and row.get("raw_result_sha256") == raw_sha]
    if len(records) != 1:
        raise ValueError("one_exact_protected_operator_witness_required")
    record = records[0]
    sha, version = record.get("sha256"), record.get("version_id")
    if (not isinstance(sha, str) or not HEX.fullmatch(sha) or not isinstance(version, str) or not version.strip()
            or version == "null" or record.get("public_key_sha256") != public_key_pin
            or record.get("bucket", inventory["foundation"]["bucket_name"]) != inventory["foundation"]["bucket_name"]):
        raise ValueError("protected_witness_version_owner_or_external_pin_mismatch")
    expected_key = f"anchors/{inventory['campaign_id']}/{hashlib.sha256(cell_id.encode()).hexdigest()[:24]}/{sha}.json"
    if record.get("key") != expected_key:
        raise ValueError("protected_witness_not_in_exact_operator_anchor_namespace")
    path = regular_owned_file(raw_path.parent, record["local_path"])
    witness_body = path.read_bytes()
    if hashlib.sha256(witness_body).hexdigest() != sha:
        raise ValueError("protected_witness_retained_bytes_mismatch")
    witness = json.loads(witness_body)
    public_path = Path(public_key_path)
    if public_path.is_symlink() or not public_path.is_file():
        raise ValueError("external_regular_operator_public_key_required")
    public = public_path.read_bytes()
    if not verify_witness(witness, public, expected_public_key_sha256=public_key_pin):
        raise ValueError("protected_witness_signature_or_external_pin_failed")
    last = raw["published_manifests"][-1] if raw.get("published_manifests") else None
    expected = {"schema_version": "0.1.0", "campaign_id": inventory["campaign_id"], "application_campaign_id": application,
        "cell_id": cell_id, "run_id": raw["persistent_run_id"], "raw_result_sha256": raw_sha, "anchor": raw["anchor"],
        "manifest_id": last["manifest_id"] if last else None, "model_schema_hash": raw["model_schema_hash"],
        "model_digest": last["model_digest"] if last else None, "commit_order": last["commit_order"] if last else 0,
        "execution_successful": raw.get("successful") is True}
    payload = witness["payload"]
    if (set(payload) != set(expected) | {"operator_observed_at_utc"}
            or any(payload.get(name) != value for name, value in expected.items())
            or type(payload.get("execution_successful")) is not bool
            or datetime.fromisoformat(payload["operator_observed_at_utc"].replace("Z", "+00:00")).tzinfo is None):
        raise ValueError("protected_witness_case_run_pointer_or_execution_binding_failed")
    provenance = {"protected_witness_verified": True, "external_public_key_sha256": public_key_pin,
        "public_key_pem_sha256": hashlib.sha256(public).hexdigest(),
        "witness": {"bucket": inventory["foundation"]["bucket_name"], "key": record["key"], "version_id": version,
            "sha256": sha, "raw_result_sha256": raw_sha}, "source": "external operator key pin plus retained versioned anchors receipt"}
    return witness, public, provenance


def validation_utility(raw):
    """Bind a validation response to the actually reconstructed final pointer."""
    if raw.get("test_holdout_evaluated") is True or "test_metrics" in raw:
        raise ValueError("partial_assessment_cannot_authorize_holdout")
    if raw.get("successful") is not True:
        return None
    if raw.get("test_holdout_evaluated") is not False:
        raise ValueError("successful_partial_case_requires_explicit_validation_scope")
    manifests = raw.get("published_manifests", [])
    if not manifests:
        raise ValueError("successful_partial_case_requires_final_evaluated_model")
    last = manifests[-1]
    expected = {"run_id": raw["persistent_run_id"], "manifest_id": last["manifest_id"], "round_id": last["round_id"],
        "model_schema_hash": raw["model_schema_hash"], "parameters_digest": last["model_digest"],
        "model_sha256": last["artifact"]["sha256"], "metadata_digest": raw.get("model_metadata_digest"),
        "validation_sha256": raw.get("validation_source_sha256"), "dataset_role": "validation",
        "final_test_evaluated": False, "manifest_verified": True, "metrics": raw.get("validation_metrics")}
    response = raw.get("evaluation_service_response")
    if (not isinstance(response, dict) or set(response) != set(expected) | {"schema_version", "request_id", "validation_sample_digest"}
            or response.get("schema_version") != "0.1.0" or any(response.get(key) != value for key, value in expected.items())
            or response.get("final_test_evaluated") is not False or response.get("manifest_verified") is not True
            or not isinstance(response.get("request_id"), str) or not response["request_id"]
            or any(not isinstance(response.get(key), str) or not HEX.fullmatch(response[key])
                   for key in ("metadata_digest", "validation_sha256", "validation_sample_digest"))):
        raise ValueError("partial_final_validation_response_not_bound_to_committed_model")
    _verify_aggregate_metrics(response["metrics"])
    return response["metrics"]


def derive_partial_metrics(raw, assessment):
    if assessment.get("protected_witness_verified") is not True or assessment.get("full_protocol_pass") is not False:
        raise ValueError("protected_independent_partial_assessment_required")
    metrics, sources = {}, {}
    mapping = {"unique_presented_updates": "presented_update_count", "oracle_invalid_presented": "oracle_invalid_presented",
        "oracle_invalid_incorporations": "oracle_invalid_incorporations", "accepted_updates": "final_allow_count",
        "final_decisions": "final_audit_expected_count", "audit_complete_decisions": "final_audit_recorded_count", "published_models": "weighted_models_verified"}
    for name, field in mapping.items():
        metrics[name], sources[name] = assessment[field], "independent-protected-partial-assessment." + field
    tasks = {row["task_id"]: row for row in raw["tasks"]}
    updates = {row["update_id"]: row for row in raw["updates"]}
    final = {**raw["decisions"], **{row["update_id"]: row for row in raw.get("attempt_failures", [])}}
    metrics["oracle_valid_presented"] = assessment["presented_update_count"] - assessment["oracle_invalid_presented"]
    valid_rejected = 0
    for uid, update in updates.items():
        end = final.get(uid, {}).get("evaluation_order", raw["durable_evidence"]["sequence"]["order"])
        query = {"org_id": update["org_id"], "purpose": update["purpose"], "start_order": update["start_order"],
            "commit_order": end, "actions": ["train", "submit_update", "aggregate"]}
        if evaluate_interval(raw["policy_events"], query)["valid"] and final.get(uid, {}).get("outcome") == "rejected":
            valid_rejected += 1
    metrics["oracle_valid_rejections"] = valid_rejected
    for name in ("oracle_valid_presented", "oracle_valid_rejections"):
        sources[name] = "independent-oracle;partial-horizon=each-final-evaluation-order-or-coherent-snapshot-for-pending"
    metrics.update(audit_record_sets_tested=1, audit_record_sets_verified=int(assessment["audit_complete_for_all_final_outcomes"]))
    for name in ("audit_record_sets_tested", "audit_record_sets_verified"):
        sources[name] = "protected-partial-audit-check;missing-required-final-audit-records-count-as-unverified"
    issued = [json.loads(row["task_json"]) for row in raw["durable_evidence"]["run_records"] if row["SK"].startswith("ISSUE#")]
    for issued_task in issued:
        task = tasks.get(issued_task.get("task_id"))
        if task is not None and any(issued_task.get(key) != task.get(key) for key in
                ("update_id", "task_id", "org_id", "node_id", "round_id", "purpose", "issue_order", "model_schema_hash")):
            raise ValueError("partial_issued_and_acknowledged_task_binding_mismatch")
    assigned = {row["update_id"]: row for row in [*tasks.values(), *issued]}
    if len(assigned) != assessment["task_assignment_count"]:
        raise ValueError("partial_assignment_count_binding_mismatch")
    if all(row.get("org_id") in {f"org_{i:02d}" for i in range(1, 9)} for row in assigned.values()):
        metrics["selected_eligible_clients"] = len({row["org_id"] for row in assigned.values()})
        sources["selected_eligible_clients"] = "distinct-assessed-acknowledged-and-issued-organizations;includes-unacknowledged-assignment"
    members = {uid for manifest in raw["published_manifests"] for uid in manifest["included_update_ids"]}
    metrics["accepted_clients"] = len({updates[uid]["org_id"] for uid in members})
    sources["accepted_clients"] = "distinct-organizations-in-independently-reconstructed-partial-manifests"
    orders = [row.get("issue_order") for row in assigned.values()]
    if orders and all(type(value) is int for value in orders):
        end = max([row["evaluation_order"] for row in final.values()] + [raw["durable_evidence"]["sequence"]["order"]])
        revokes = [event for event in raw["policy_events"] if event["kind"] == "REVOKE" and min(orders) <= event["order"] <= end]
        metrics["revocations"] = len(revokes)
        invalid_publications = set()
        for manifest in raw["published_manifests"]:
            for uid in manifest["included_update_ids"]:
                update = updates[uid]
                query = {"org_id": update["org_id"], "purpose": update["purpose"], "start_order": update["start_order"],
                    "commit_order": manifest["commit_order"], "actions": ["train", "submit_update", "aggregate"]}
                if (not evaluate_interval(raw["policy_events"], query)["valid"] and any(event["org_id"] == update["org_id"]
                        and update["start_order"] <= event["order"] <= manifest["commit_order"] for event in revokes)):
                    invalid_publications.add(manifest["manifest_id"])
        metrics["post_revocation_invalid_publications"] = len(invalid_publications)
        for name in ("revocations", "post_revocation_invalid_publications"):
            sources[name] = "partial-assessed-issued-to-final/coherent-snapshot-order-horizon;independent-manifest-membership-and-oracle"
    records = raw["durable_evidence"]["run_records"]
    metrics["coordination_operations"] = sum(row.get("record_type") == "transaction_outcome" for row in records)
    sources["coordination_operations"] = "partial-assessed-run-namespace-transaction-outcome-rows;not-SDK-attempts-or-full-transaction-proof"
    instrument = raw.get("measurement_manifest")
    if instrument is not None:
        if (not isinstance(instrument, dict) or set(instrument) != {"schema_version", "tamper_scope", "tamper_mode", "tamper_results"}
                or instrument["schema_version"] != "0.1.0" or instrument["tamper_scope"] != "this-runtime-invocation"
                or instrument["tamper_mode"] not in {"none_declared", "injected"} or not isinstance(instrument["tamper_results"], list)):
            raise ValueError("invalid_partial_runtime_measurement_manifest")
        attacks = instrument["tamper_results"]
        if (any(not isinstance(row, dict) or set(row) != {"attack_id", "detected"} or not isinstance(row["attack_id"], str)
                or not ID.fullmatch(row["attack_id"]) or type(row["detected"]) is not bool for row in attacks)
                or len({row["attack_id"] for row in attacks}) != len(attacks)
                or (instrument["tamper_mode"] == "none_declared" and attacks) or (instrument["tamper_mode"] == "injected" and not attacks)):
            raise ValueError("invalid_partial_actual_tamper_measurements")
        metrics.update(tamper_attempted=len(attacks), tamper_detected=sum(row["detected"] for row in attacks))
        for name in ("tamper_attempted", "tamper_detected"):
            sources[name] = "exact-runtime-measurement-manifest;this-invocation-only;no-backfilled-host-attacks"
    metric_errors = []
    try:
        utility = validation_utility(raw)
    except (ValueError, KeyError, TypeError) as error:
        utility = None
        metric_errors.append({"component": "validation_utility", "type": type(error).__name__, "code": str(error)[:200]})
    metrics.update(data_kind="clinical", evaluation_split="validation" if utility else "none")
    if utility:
        metrics.update({key: utility[key] for key in UTILITY_METRICS if key in utility})
        for key in UTILITY_METRICS & set(metrics):
            sources[key] = "strict-validation-response-bound-to-independently-reconstructed-final-partial-model"
    latencies = {}
    def numbers(values):
        if any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in values):
            raise ValueError("finite_nonnegative_partial_latency_required")
        return values
    if "policy_rpc_metrics" in raw:
        latencies["opa"] = numbers([row["duration_ms"] for row in raw["policy_rpc_metrics"]])
    for name, field in (("round", "duration_seconds"), ("publication", "publication_seconds")):
        if isinstance(raw.get("rounds"), list) and all(field in row for row in raw["rounds"]):
            latencies[name] = numbers([row[field] * 1000 for row in raw["rounds"]])
    try:
        timing = verify_runtime_observations(raw)
    except (ValueError, KeyError, TypeError) as error:
        timing = {"runtime_observations_verified": False}
        metric_errors.append({"component": "runtime_observations", "type": type(error).__name__, "code": str(error)[:200]})
    if timing["runtime_observations_verified"] is True:
        latencies.update(timing["runtime_stage_latency_ms"])
        validate_revocation_response(timing["revocation_response"])
        metrics["revocation_response"] = timing["revocation_response"]
        sources["revocation_response"] = "independently-authority-bound-partial-observer-intervals;not-full-protocol-certification"
    if latencies:
        metrics["latency_ms"] = latencies
        sources["latency_ms"] = "observed-native-policy/round-values;independently-bound-stage-intervals-where-verified"
    timing["committed_validation_response_verified"] = utility is not None
    timing["partial_metric_errors"] = metric_errors
    return metrics, sources, timing
