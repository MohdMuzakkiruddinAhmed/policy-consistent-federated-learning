"""Exercise staged P10 variants with synthetic arrays and owned local services.

This is not a clinical/Fargate trial runner. No final holdout or AWS calls.
"""

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import time
import traceback
import uuid
from unittest.mock import patch
from urllib.request import urlopen

SOURCE = Path(__file__).resolve().parents[1]
ROOT = SOURCE if (SOURCE / "pyproject.toml").is_file() else SOURCE.parents[2]
STAGE = SOURCE if SOURCE != ROOT else ROOT / "results/development/phase10"
RUN = STAGE / "runs" / ("r-" + uuid.uuid4().hex[:8])
sys.path.insert(0, str(SOURCE / "src"))

import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pcfl.ablations import PersistentAblationAuthority
from pcfl.ablation_verify import assess_case
from pcfl.contracts import ORGANIZATIONS
from pcfl.governance_service import PolicyWriter
from pcfl.opa import OpaClient
from pcfl.persistent import PersistentAuthority, arrays_digest

sys.path.append(str(ROOT / "scripts"))
from integration_services import LocalIntegrationServices


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(content):
    return hashlib.sha256(content).hexdigest()


def sign(payload, key):
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"schema_version": "0.1.0", "algorithm": "ECDSA-P384-SHA384", "payload": payload,
        "payload_sha256": sha(canonical(payload)), "public_key_sha256": sha(public),
        "signature_base64": base64.b64encode(key.sign(canonical(payload), ec.ECDSA(hashes.SHA384()))).decode()}


def export_models(value, s3, directory, cache):
    if isinstance(value, dict):
        if value.get("backend") == "s3" and "version_id" in value:
            binding = tuple(value[field] for field in ("bucket", "key", "version_id"))
            if binding not in cache:
                response = s3.get_object(Bucket=binding[0], Key=binding[1], VersionId=binding[2])
                try:
                    content = response["Body"].read()
                finally:
                    response["Body"].close()
                if response.get("VersionId") != binding[2] or len(content) != value["size_bytes"] or sha(content) != value["sha256"]:
                    raise ValueError("staged_ablation_object_export_mismatch")
                path = directory / ("v" + str(len(cache)) + ".npz")
                path.write_bytes(content); cache[binding] = path
            value["local_export"] = {"path": str(cache[binding].resolve()), "file_sha256": value["sha256"], "model_digest": value["model_digest"]}
        for item in list(value.values()):
            export_models(item, s3, directory, cache)
    elif isinstance(value, list):
        for item in value:
            export_models(item, s3, directory, cache)


def retain_case(authority, services, name, key):
    directory = RUN / "e" / name
    directory.mkdir(parents=True, exist_ok=False)
    evidence = authority.evidence()
    evidence.update(schema_version="0.1.0", baseline_id="P1", test_holdout_evaluated=False,
        kind="synthetic-array-partial-protocol", clinical_rows_used=0, registered_cloud_trial=False)
    export_models(evidence, services.s3, directory, {})
    path = directory / "evidence.json"
    path.write_bytes(canonical(evidence) + b"\n")
    head = authority.item(authority.pk, "AUDIT_HEAD")
    pointer = authority.item(authority.pk, "POINTER")
    if {field: head[field] for field in ("count", "head")} != evidence["anchor"]:
        raise ValueError("operator_strong_read_head_changed")
    last = evidence["published_manifests"][-1] if evidence["published_manifests"] else None
    if pointer.get("manifest_id") != (last["manifest_id"] if last else None):
        raise ValueError("operator_strong_read_pointer_changed")
    payload = {"schema_version": "0.1.0", "campaign_id": "phase10-local-array", "cell_id": name,
        "run_id": authority.run_id, "raw_result_sha256": sha(path.read_bytes()), "anchor": evidence["anchor"],
        "manifest_id": last["manifest_id"] if last else None, "model_schema_hash": evidence["model_schema_hash"],
        "model_digest": last["model_digest"] if last else None, "commit_order": last["commit_order"] if last else 0,
        "operator_observed_at_utc": datetime.now(timezone.utc).isoformat(), "evidence_representation": "phase10-local-export-v1"}
    witness = sign(payload, key)
    body = canonical(witness)
    response = services.s3.put_object(Bucket=services.bucket, Key="anchors/phase10/" + name + "/" + sha(body) + ".json", Body=body)
    if not response.get("VersionId") or response["VersionId"] == "null":
        raise ValueError("local_test_witness_version_missing")
    (directory / "witness.json").write_bytes(body)
    public_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    result = assess_case(path, witness=witness, public_key_pem=public_pem, expected_public_key_sha256=witness["public_key_sha256"])
    result.update(case_id=name, evidence_file=str(path), witness_file=str(directory / "witness.json"),
                  witness_object_version=response["VersionId"], native_policy_calls=getattr(authority, "native_policy_calls", None))
    return result, evidence, witness, public_pem


def tamper_checks(path, evidence, witness, public_pem):
    mutations = []
    changed = deepcopy(evidence); changed["audit"][0]["payload"]["reason"] = "modified"; mutations.append(("modification", changed, deepcopy(witness), public_pem))
    changed = deepcopy(evidence); changed["audit"].pop(); mutations.append(("deletion", changed, deepcopy(witness), public_pem))
    changed = deepcopy(evidence); changed["audit"] = list(reversed(changed["audit"])); mutations.append(("reordering", changed, deepcopy(witness), public_pem))
    changed = deepcopy(evidence); changed["audit"].append(deepcopy(changed["audit"][0])); mutations.append(("duplicate_replay", changed, deepcopy(witness), public_pem))
    changed = deepcopy(evidence); changed["audit"][0]["payload"]["reason"] = "coherently-resealed"
    previous = "0" * 64
    for record in changed["audit"]:
        record["prev_hash"] = previous; previous = record["event_hash"] = sha(canonical({k: record[k] for k in ("sequence", "prev_hash", "payload")}))
    changed["anchor"]["head"] = previous
    forged = deepcopy(witness); forged["payload"]["anchor"] = changed["anchor"]
    forged["payload"]["raw_result_sha256"] = sha(canonical(changed) + b"\n"); forged["payload_sha256"] = sha(canonical(forged["payload"]))
    mutations.append(("rechain_and_replace_colocated_anchor", changed, forged, public_pem))
    attacker = ec.generate_private_key(ec.SECP384R1())
    attacker_pem = attacker.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    mutations.append(("replace_witness_and_untrusted_public_key", deepcopy(evidence), sign(witness["payload"], attacker), attacker_pem))
    results = []
    for index, (name, changed, supplied, supplied_key) in enumerate(mutations):
        target = path.parent / ("tamper" + str(index) + ".json")
        target.write_bytes(canonical(changed) + b"\n")
        try:
            assess_case(target, witness=supplied, public_key_pem=supplied_key, expected_public_key_sha256=witness["public_key_sha256"])
        except ValueError as error:
            results.append({"manipulation": name, "detected": True, "reason": str(error)})
        else:
            raise AssertionError("externally_pinned_witness_did_not_detect_manipulation")
    return results


def run_case(services, operator, opa, variant, scenario, index, key):
    for org in ORGANIZATIONS:
        operator.mutate(org, "GRANT")
    name = (variant or "P1") + "-" + scenario
    run_id = "p10-" + str(index) + "-" + (variant or "P1")
    template = [np.array([0, 0], dtype=np.float32)]
    schema_hash = sha(b"phase10-synthetic-two-parameter-schema")
    def connect():
        cls = PersistentAblationAuthority if variant else PersistentAuthority
        extra = {"ablation_id": variant} if variant else {}
        return cls(services.ddb, services.s3, table_name=services.table, bucket=services.bucket, run_id=run_id,
            template=template, model_schema_hash=schema_hash, policy_evaluator=opa.evaluate, rule_hash=opa.rule_hash,
            local_emulation=True, **extra)
    authority = connect()
    tasks = []
    process_roundtrips = {}
    def client_process(operation, task, number):
        process = subprocess.run([sys.executable, str(SOURCE / "scripts/array_client.py")],
            input=json.dumps({"operation": operation, "task": task, "number": number}), capture_output=True, text=True, timeout=20, check=True)
        return json.loads(process.stdout)
    for number, org in enumerate(ORGANIZATIONS[:2], 1):
        task = authority.issue(org, number, "round-1")
        if scenario == "duplicate_restart":
            authority = connect()
            echoed = client_process("ack", task, number)
            process_roundtrips[number] = {"acknowledgment_pid": echoed["pid"]}
            task = echoed["task"]
        tasks.append(authority.acknowledge(task["task_id"], number, task))
    if scenario in {"mid_round", "revoke_regrant"}:
        operator.mutate("org_01", "REVOKE")
        if scenario == "revoke_regrant":
            operator.mutate("org_01", "GRANT")
    order = [1, 0] if scenario == "duplicate_restart" else [0, 1]
    receipts = {}
    for task_index in order:
        task = tasks[task_index]; number = task_index + 1
        arrays = [np.array([number, number], dtype=np.float32)]
        metadata = {**task, "sample_count": number, "weights_digest": arrays_digest(arrays), "client_wall_clock_ms": -60000 if number == 1 else 60000}
        if scenario == "duplicate_restart":
            reply = client_process("train", task, number)
            arrays = [np.asarray(value, dtype=np.float32) for value in reply["arrays"]]
            metadata = reply["metadata"]
            process_roundtrips[number]["training_pid"] = reply["pid"]
            assert reply["pid"] != process_roundtrips[number]["acknowledgment_pid"]
        receipts[number] = authority.receive(task["task_id"], number, metadata, arrays)
        if scenario == "duplicate_restart":
            assert authority.receive(task["task_id"], number, metadata, arrays) == receipts[number]
            altered = {**metadata, "sample_count": number + 5}
            try:
                authority.receive(task["task_id"], number, altered, arrays)
            except ValueError:
                pass
            else:
                raise AssertionError("rebound_update_was_not_rejected")
    if scenario == "final_error":
        third = authority.issue("org_03", 3, "round-1")
        third = authority.acknowledge(third["task_id"], 3, third)
        assert authority.fail(third["task_id"], "synthetic_client_crash") == "error"
        assert authority.fail(third["task_id"], "synthetic_client_crash") == "error"
        authority.issue("org_04", 4, "round-1")  # No acknowledgment: indeterminate, not fabricated final error.
    details = {"receipts": receipts, "publication_attempt_status": "committed"}
    if scenario == "duplicate_restart":
        details.update(synthetic_client_process_roundtrips=process_roundtrips,
            client_state_handoff="serialized nonce-bound task passed between exited/restarted worker processes",
            actual_Flower_network_restart_tested=False, authority_object_restart_tested=True)
    pointer, head = authority.item(authority.pk, "POINTER"), authority.item(authority.pk, "AUDIT_HEAD")
    if scenario == "near_commit":
        def race(attempt):
            if attempt == 0:
                operator.mutate("org_01", "REVOKE")
        authority.publish("round-1", before_commit=race)
        details["policy_sequence_conflicts"] = authority.conflicts
    elif scenario == "audit_failure":
        from botocore.exceptions import ClientError
        actual = services.ddb.transact_write_items
        def fail_audit(**request):
            if any("AUDIT" in action.get("Put", action.get("Update", {})).get("Item", action.get("Update", {}).get("Key", {})).get("SK", {}).get("S", "") for action in request["TransactItems"]):
                raise ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "synthetic_audit_store_failure"}}, "TransactWriteItems")
            return actual(**request)
        failed = False
        with patch.object(services.ddb, "transact_write_items", side_effect=fail_audit):
            try:
                authority.publish("round-1")
            except Exception:
                failed = True
        assert failed == (variant != "Abl-3")
        details.update(audit_failure_injection="SDK_transaction_boundary", publication_failed_as_expected=failed)
        details["publication_attempt_status"] = "indeterminate_not_committed" if failed else "committed_without_persistent_audit"
        if failed:
            assert authority.item(authority.pk, "POINTER") == pointer and authority.item(authority.pk, "AUDIT_HEAD") == head
            details["indeterminate_before_recovery"] = 2
            for task in tasks:
                authority.fail(task["task_id"], "synthetic_audit_outage_recovered")
    elif scenario in {"opa_outage", "ddb_outage"}:
        role = "opa" if scenario == "opa_outage" else "dynamodb"
        container = services.identifier + "-" + role
        services.docker("stop", container)
        try:
            try:
                authority.publish("round-1")
            except Exception as error:
                details["outage_exception_type"] = type(error).__name__
            else:
                raise AssertionError("unavailable_service_did_not_close_publication")
        finally:
            services.docker("start", container)
        deadline = time.monotonic() + 25
        while True:
            try:
                if role == "opa":
                    with urlopen(services.opa_endpoint + "/health", timeout=1) as response:
                        assert response.status == 200
                else:
                    authority.item(authority.pk, "POINTER")
                break
            except Exception:
                if time.monotonic() >= deadline: raise
                time.sleep(.1)
        assert authority.item(authority.pk, "POINTER") == pointer and authority.item(authority.pk, "AUDIT_HEAD") == head
        details.update(service_actually_stopped=True, indeterminate_before_recovery=2)
        details["publication_attempt_status"] = "indeterminate_not_committed"
        for task in tasks:
            authority.fail(task["task_id"], "synthetic_service_outage_recovered")
    else:
        authority.publish("round-1")
    if scenario == "duplicate_restart":
        reopened = connect()
        np.testing.assert_array_equal(reopened.parameters()[0], authority.parameters()[0])
        assert len(reopened.publish("round-1")["included_update_ids"]) == 2
    result, evidence, witness, public = retain_case(authority, services, name, key)
    result["details"] = details
    if variant == "Abl-1":
        assert all(not item["native_policy_checked"] for item in evidence["ablation_authorization_trace"] if item["stage"] == "receipt")
        assert result["oracle_invalid_incorporations"] == 0
    if variant == "Abl-2":
        assert result["oracle_invalid_incorporations"] == 0 and authority.conflicts >= 1
        assert all(item["global_sequence_CAS_retained"] and item["contributor_epoch_checks"] == 0 for item in evidence["ablation_transaction_trace"])
        result["negative_finding"] = "Removing contributor epoch checks did not defeat the retained global policy-sequence CAS in this race."
    if variant == "Abl-3":
        assert not result["audit_complete_for_all_final_outcomes"] and result["missing_final_audit_update_ids"]
    if variant == "Abl-4":
        assert result["oracle_invalid_incorporations"] == 1
        assert all(item["actual_query"]["start_order"] == item["actual_query"]["commit_order"] for item in evidence["ablation_authorization_trace"]
                   if item["stage"] in {"receipt", "publication", "final"})
    if scenario == "final_error":
        assert result["final_error_count"] == 1 and result["indeterminate_count"] == 1
        assert result["final_audit_expected_count"] == 3
        assert result["final_audit_recorded_count"] == (0 if variant == "Abl-3" else 3)
    if variant is None and scenario == "stable":
        result["protected_tamper_checks"] = tamper_checks(Path(result["evidence_file"]), evidence, witness, public)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-services", action="store_true", help="Explicitly start only owned Docker emulators")
    args = parser.parse_args()
    if not args.local_services:
        print(json.dumps({"executed": False, "reason": "explicit_local_services_flag_required", "AWS_calls": False}))
        return
    report = {"schema_version": "0.1.0", "successful": False, "scope": "local-synthetic-array-protocol-tests",
        "AWS_calls": False, "clinical_rows_used": 0, "final_holdout_accessed": False, "registered_cloud_trials_run": 0, "cases": [], "run_root": str(RUN)}
    report.update(actual_AWS_anchor_write_denial_tested=False,
        operator_public_pin_supplied_outside_untrusted_evidence=True,
        tamper_scope="ECDSA witness authenticity and body/count/head/pointer binding; operator/public pin trusted")
    selected = list((SOURCE / "src/pcfl").glob("*.py"))
    selected += [SOURCE / "scripts" / name for name in ("array_client.py", "run_ablation_protocol.py", "verify_ablation_case.py", "plan_phase10.py")]
    selected += [SOURCE / "configs/phase10.json", SOURCE / "policies/rego/pcfl.rego"]
    report["source_files_sha256"] = {file.relative_to(SOURCE).as_posix(): sha(file.read_bytes()) for file in sorted(selected)}
    RUN.mkdir(parents=True, exist_ok=False)
    (STAGE / "reports").mkdir(parents=True, exist_ok=True)
    previous = STAGE / "reports/protocol_validation.json"
    if previous.exists():
        (STAGE / "reports" / ("attempt-" + sha(previous.read_bytes())[:12] + ".json")).write_bytes(previous.read_bytes())
    def save():
        body = json.dumps(report, indent=2) + "\n"
        (RUN / "report.json").write_text(body)
        (STAGE / "reports/protocol_validation.json").write_text(body)
    key = ec.generate_private_key(ec.SECP384R1())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (RUN / "operator-public.pem").write_bytes(public)
    report["operator_public_key_file"] = str(RUN / "operator-public.pem")
    report["trusted_operator_public_key_sha256"] = sha(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    cases = [(None, "stable"), ("Abl-1", "mid_round"), ("Abl-2", "near_commit"), ("Abl-3", "stable"),
             ("Abl-4", "revoke_regrant"), (None, "duplicate_restart"), (None, "final_error"),
             ("Abl-3", "final_error"),
             (None, "audit_failure"), ("Abl-3", "audit_failure"), (None, "opa_outage"), (None, "ddb_outage")]
    try:
        with LocalIntegrationServices(RUN / "s") as services:
            writer = PolicyWriter(services.ddb, services.table); writer.initialize()
            opa = OpaClient(services.opa_endpoint, allow_loopback_http=True)
            for index, (variant, scenario) in enumerate(cases):
                item = run_case(services, writer, opa, variant, scenario, index, key)
                report["cases"].append(item)
                save()
        report["successful"] = True
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        (RUN / "error.log").write_text(traceback.format_exc())
        raise
    finally:
        report["no_ablation_claimed_as_full_protocol_pass"] = all(item["full_protocol_pass"] is False for item in report["cases"])
        save()
    print(json.dumps({"successful": report["successful"], "local_cases": len(report["cases"]), "actual_cloud_trials": 0}))


if __name__ == "__main__":
    main()
