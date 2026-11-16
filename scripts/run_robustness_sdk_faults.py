"""Owned loopback SDK/OPA mechanisms with synthetic arrays; never clinical/AWS."""
import argparse
from contextlib import redirect_stdout
import hashlib
import json
from pathlib import Path
import sys
import threading
import time
import traceback
import uuid
from unittest.mock import patch

STAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STAGE / "src"))

import numpy as np
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pcfl.contracts import ORGANIZATIONS, digest
from pcfl.governance_service import PolicyWriter
from pcfl.opa import OpaClient
from pcfl.persistent import PersistentAuthority, arrays_digest
from pcfl.robust_policy import RobustScenarioSignal, RobustScenarioWatcher
from pcfl.robustness import DEFAULTS, PROTOCOL, adapter_source_digest, targets
from integration_services import LocalIntegrationServices
import run_ablation_protocol as retained

CASES = ("ddb_cancel", "stale_token", "s3_stage_failure", "delayed_policy", "coordinator_authority_restart")


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def run_case(services, writer, opa, name, witness_key):
    run_id = "robust-sdk-" + name.replace("_", "-")
    template = [np.zeros(2, dtype=np.float32)]
    schema = hashlib.sha256(b"exploratory-two-parameter-synthetic-schema").hexdigest()
    def connect():
        return PersistentAuthority(services.ddb, services.s3, table_name=services.table, bucket=services.bucket,
            run_id=run_id, template=template, model_schema_hash=schema, policy_evaluator=opa.evaluate,
            rule_hash=opa.rule_hash, local_emulation=True)
    detail = {"scope": "owned loopback SDK/OPA mechanism; synthetic two-parameter arrays", "clinical_rows_used": 0,
        "actual_Flower_network_restart_tested": False, "actual_Fargate_or_AWS_tested": False}
    watcher = None
    release, blocked = threading.Event(), threading.Event()
    if name == "delayed_policy":
        class DelayedWriter:
            ddb, table = writer.ddb, writer.table
            def mutate(self, org, kind, **kwargs):
                if kind == "REVOKE":
                    blocked.set()
                    if not release.wait(5): raise TimeoutError("test_delayed_policy_not_released")
                return writer.mutate(org, kind, **kwargs)
        watcher = RobustScenarioWatcher(DelayedWriter(), {"protocol_id": PROTOCOL,
            "runs": [{"run_id": run_id, "seed": 296, "rounds": 5, "factors": DEFAULTS}]}).start()
        signal = RobustScenarioSignal(services.ddb, services.table, run_id, "robustness", value=DEFAULTS, seed=296, rounds=5, timeout=6)
        signal.reach("before_run")
    else:
        for org in ORGANIZATIONS: writer.mutate(org, "GRANT")
    authority = connect()
    tasks = []
    chosen_orgs = list(ORGANIZATIONS[:2])
    if name == "delayed_policy":
        chosen_orgs = [targets(296, 1, DEFAULTS)[0], next(org for org in ORGANIZATIONS if org not in targets(296, 1, DEFAULTS))]
    for node, org in enumerate(chosen_orgs, 1):
        task = authority.issue(org, node, "round-1")
        if name == "coordinator_authority_restart": authority = connect()
        tasks.append(authority.acknowledge(task["task_id"], node, task))
    def present(task, node, **overrides):
        arrays = [np.full(2, node, dtype=np.float32)]
        metadata = {**task, "sample_count": node, "weights_digest": arrays_digest(arrays), **overrides}
        return authority.receive(task["task_id"], node, metadata, arrays)
    if name == "stale_token":
        before = authority.evidence()
        try: present(tasks[0], 1, nonce="synthetic-invalid-token")
        except ValueError as error:
            if str(error) != "update_nonce_mismatch": raise
            detail.update(rejected_before_update_persistence=True, rejection_reason=str(error))
        else: raise AssertionError("wrong_token_was_accepted")
        after = authority.evidence()
        assert before["updates"] == after["updates"] and before["published_manifests"] == after["published_manifests"]
        authority.fail(tasks[0]["task_id"], "test_stale_nonce_rejected")
        present(tasks[1], 2)
    else:
        for node, task in enumerate(tasks, 1): present(task, node)
    if name == "coordinator_authority_restart": authority = connect()
    pointer, head = authority.item(authority.pk, "POINTER"), authority.item(authority.pk, "AUDIT_HEAD")
    try:
        if name == "ddb_cancel":
            api = services.ddb.transact_write_items
            observed = []
            def actual_sdk(**request):
                try: return api(**request)
                except Exception as error:
                    observed.append(getattr(error, "response", {}).get("Error", {}).get("Code", type(error).__name__))
                    raise
            def race(attempt):
                if attempt == 0: writer.mutate("org_01", "REVOKE")
            with patch.object(services.ddb, "transact_write_items", side_effect=actual_sdk):
                manifest = authority.publish("round-1", before_commit=race)
            assert "TransactionCanceledException" in observed and authority.conflicts >= 1
            assert manifest["included_update_ids"] == [tasks[1]["update_id"]]
            detail.update(actual_sdk_error_codes=observed, policy_fence_conflicts=authority.conflicts, stale_candidate_not_published=True)
        elif name == "s3_stage_failure":
            api, observed = services.s3.put_object, []
            missing = services.identifier + "-intentionally-absent"
            def absent_bucket(**request):
                if request["Key"].startswith("models/candidates/" + run_id + "/"):
                    request = {**request, "Bucket": missing}
                try: return api(**request)
                except Exception as error:
                    observed.append(getattr(error, "response", {}).get("Error", {}).get("Code", type(error).__name__))
                    raise
            with patch.object(services.s3, "put_object", side_effect=absent_bucket):
                try: authority.publish("round-1")
                except Exception as error: detail["failed_publication_exception"] = type(error).__name__
                else: raise AssertionError("absent_candidate_bucket_did_not_fail")
            assert "NoSuchBucket" in observed
            assert authority.item(authority.pk, "POINTER") == pointer and authority.item(authority.pk, "AUDIT_HEAD") == head
            detail.update(actual_sdk_error_codes=observed, failed_attempt_pointer_and_audit_unchanged=True,
                injection="candidate PutObject redirected to owned nonexistent emulator bucket; not an AWS outage")
            manifest = authority.publish("round-1")
            detail["recovery_publication_committed"] = manifest is not None
        elif name == "delayed_policy":
            errors = []
            def reach():
                try: signal.reach("after_dispatch", "round-1")
                except Exception as error: errors.append(type(error).__name__)
            barrier = threading.Thread(target=reach, daemon=True)
            started = time.monotonic(); barrier.start()
            assert blocked.wait(3)
            time.sleep(.15)
            assert barrier.is_alive() and authority.item(authority.pk, "POINTER") == pointer
            release.set(); barrier.join(timeout=6)
            assert not barrier.is_alive() and not errors and watcher.error is None
            manifest = authority.publish("round-1")
            expected = {task["update_id"] for task in tasks if task["org_id"] not in targets(296, 1, DEFAULTS)}
            assert set(manifest["included_update_ids"]) == expected
            assert len(expected) == 1
            detail.update(policy_barrier_waited_seconds=time.monotonic()-started, barrier_did_not_ack_before_actual_commit=True,
                blocked_policy_actor_before_mutation=True, publication_followed_committed_revocation=True)
        else:
            manifest = authority.publish("round-1")
        if name == "coordinator_authority_restart":
            recovered = connect()
            repeated = recovered.publish("round-1")
            assert repeated == manifest and len(recovered.evidence()["published_manifests"]) == 1
            np.testing.assert_array_equal(recovered.parameters()[0], np.full(2, 5/3, dtype=np.float32))
            authority = recovered
            detail.update(authority_object_recreations=4, durable_task_nonce_binding_recovered=True,
                duplicate_publication_returned_same_immutable_version=True,
                limitation="Authority object/process-state recovery only; actual Flower/Fargate replacement is a separate clinical run")
        result, evidence, witness, pem = retained.retain_case(authority, services, name, witness_key)
        attacks = retained.tamper_checks(Path(result["evidence_file"]), evidence, witness, pem)
        assert result["oracle_invalid_incorporations"] == 0
        return {"case_id": name, "status": "passed", "mechanism": detail, "independent_assessment": result,
            "actual_tamper_results": attacks, "registered_clinical_trial": False, "final_holdout_accessed": False}
    finally:
        release.set()
        if watcher: watcher.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-services", action="store_true", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or STAGE / "results/development/robustness_sdk" / ("sdk-" + uuid.uuid4().hex[:8])
    if output.exists(): raise ValueError("new_owned_evidence_directory_required")
    output.mkdir(parents=True)
    retained.RUN = output
    report = {"schema_version": "0.1.0", "kind": "exploratory-local-sdk-mechanism-validation", "clinical_rows_used": 0,
        "actual_cloud_trials_executed": 0, "final_holdout_accessed": False, "aws_resources_created": False,
        "evidence_representation": "phase10-local-export-v1 reused by independent partial-protocol checker",
        "assessment_claim": "synthetic mechanism checks only; not complete clinical eight-client robustness trials", "attempts": []}
    key = ec.generate_private_key(ec.SECP384R1())
    public = key.public_key()
    (output / "operator-public-key.pem").write_bytes(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    report["operator_public_key_sha256"] = hashlib.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    report["driver_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report["adapter_source_sha256"] = adapter_source_digest()
    report["runtime_source_files_sha256"] = {path.relative_to(STAGE).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (STAGE / "src/pcfl").glob("*.py")}
    report["helper_sources_sha256"] = {name: hashlib.sha256((STAGE / "scripts" / name).read_bytes()).hexdigest()
        for name in ("run_ablation_protocol.py", "integration_services.py", "run_flower.py")}
    with (output / "mechanism.log").open("w", encoding="utf-8") as log, redirect_stdout(log):
        try:
            with LocalIntegrationServices(output / "services") as services:
                writer = PolicyWriter(services.ddb, services.table); writer.initialize()
                opa = OpaClient(services.opa_endpoint, allow_loopback_http=True)
                for name in CASES:
                    started = time.perf_counter()
                    try: attempt = run_case(services, writer, opa, name, key)
                    except Exception as error:
                        traceback.print_exc(file=log)
                        attempt = {"case_id": name, "status": "failed", "error_type": type(error).__name__, "reason": str(error)}
                    attempt["elapsed_seconds"] = time.perf_counter()-started
                    report["attempts"].append(attempt); write(output / "sdk_fault_validation.json", report)
        except Exception as error:
            traceback.print_exc(file=log)
            report["service_error"] = {"type": type(error).__name__, "reason": str(error)}
    report["passed"] = len(report["attempts"]) == len(CASES) and all(attempt["status"] == "passed" for attempt in report["attempts"]) and "service_error" not in report
    write(output / "sdk_fault_validation.json", report)
    print(json.dumps({"passed": report["passed"], "cases": len(report["attempts"]), "report": str(output / "sdk_fault_validation.json")}))
    if not report["passed"]: raise SystemExit(1)


if __name__ == "__main__": main()
