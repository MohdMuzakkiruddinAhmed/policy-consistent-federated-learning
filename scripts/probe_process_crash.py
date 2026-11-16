"""Crash a synthetic protocol-coordinator process against owned local APIs.

This probes durable authority recovery, not Flower/Fargate supervisor recovery.
It uses no clinical data, final holdout, AWS credentials or AWS resources.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlparse
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"src"))
sys.path.insert(0, str(ROOT/"scripts"))
SOURCE_FILES = ("scripts/probe_process_crash.py", "scripts/run_ablation_protocol.py", "scripts/integration_services.py", "scripts/run_flower.py",
    "src/pcfl/persistent.py", "src/pcfl/aws_transactions.py", "src/pcfl/opa.py", "src/pcfl/ablation_verify.py",
    "src/pcfl/runtime_verify.py", "src/pcfl/oracle.py", "src/pcfl/contracts.py", "src/pcfl/verifier.py", "src/pcfl/service_io.py",
    "src/pcfl/governance_service.py", "policies/rego/pcfl.rego", "policies/rego/data.json", "requirements-runtime.lock")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def owned(root, relative):
    if (not isinstance(relative, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", relative)
            or relative.startswith("/") or any(part in {"", ".", ".."} for part in relative.split("/"))):
        raise ValueError("crash_custody_relative_owned_path_required")
    path = root / relative
    if (not path.resolve().is_relative_to(root.resolve()) or not path.is_file()
            or any(item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction())
                   for item in (path, *path.parents) if item != root and item.is_relative_to(root))):
        raise ValueError("crash_custody_path_outside_owned_directory")
    return path


def model_digest(content):
    """Independently digest the probe's fixed, two-float array archive."""
    import numpy as np
    if len(content) > 1024 * 1024:
        raise ValueError("bounded_synthetic_crash_model_required")
    with zipfile.ZipFile(io.BytesIO(content)) as packed:
        if packed.namelist() != ["arr_0.npy"] or sum(row.file_size for row in packed.infolist()) > 1024:
            raise ValueError("synthetic_crash_model_archive_schema_mismatch")
    with np.load(io.BytesIO(content), allow_pickle=False) as archive:
        value = archive["arr_0"]
        if value.dtype != np.dtype("float32") or value.shape != (2,) or not np.isfinite(value).all():
            raise ValueError("synthetic_crash_model_array_schema_mismatch")
        descriptor = [{"shape": [2], "dtype": value.dtype.str, "sha256": hashlib.sha256(value.tobytes(order="C")).hexdigest()}]
        return hashlib.sha256(canonical(descriptor)).hexdigest(), value.copy()


def retain_staged_candidate(s3, *, bucket, run_id, logical_digest, output):
    """Fetch only the exact model key/version already staged by this worker."""
    if (not bucket.startswith("pcfl-int-") or not re.fullmatch(r"crash-probe-[12]", run_id)
            or not re.fullmatch(r"[0-9a-f]{64}", logical_digest)):
        raise ValueError("owned_exact_crash_candidate_scope_required")
    object_key = f"models/candidates/{run_id}/{logical_digest}.npz"
    versions, markers, token, seen = [], [], {}, set()
    for _ in range(16):
        page = s3.list_object_versions(Bucket=bucket, Prefix=object_key, MaxKeys=1000, **token)
        versions.extend(row for row in page.get("Versions", []) if row.get("Key") == object_key)
        markers.extend(row for row in page.get("DeleteMarkers", []) if row.get("Key") == object_key)
        if not page.get("IsTruncated"): break
        pair = page.get("NextKeyMarker"), page.get("NextVersionIdMarker")
        if not all(isinstance(value, str) and value for value in pair) or pair in seen:
            raise ValueError("crash_candidate_version_pagination_invalid")
        seen.add(pair); token = {"KeyMarker": pair[0], "VersionIdMarker": pair[1]}
    else: raise ValueError("crash_candidate_version_scan_bound_exceeded")
    latest = [row for row in versions if row.get("IsLatest") is True]
    if len(latest) != 1 or any(row.get("IsLatest") is True for row in markers) or latest[0].get("VersionId") in {None, "", "null"}:
        raise ValueError("exact_latest_staged_candidate_version_required")
    version = latest[0]["VersionId"]
    head = s3.head_object(Bucket=bucket, Key=object_key, VersionId=version)
    result = s3.get_object(Bucket=bucket, Key=object_key, VersionId=version)
    try: content = result["Body"].read(1024 * 1024 + 1)
    finally: result["Body"].close()
    logical, _ = model_digest(content)
    byte_digest = hashlib.sha256(content).hexdigest()
    if (result.get("VersionId") != version or head.get("VersionId") != version or logical != logical_digest
            or len(content) != head.get("ContentLength") or len(content) != latest[0].get("Size")
            or head.get("Metadata", {}).get("sha256") != byte_digest
            or head.get("Metadata", {}).get("parameters-digest") != logical):
        raise ValueError("staged_crash_candidate_exact_version_or_digest_mismatch")
    output = Path(output)
    with output.open("xb") as stream:
        stream.write(content); stream.flush(); os.fsync(stream.fileno())
    return {"backend": "s3", "bucket": bucket, "key": object_key, "version_id": version, "sha256": byte_digest,
        "size_bytes": len(content), "model_digest": logical, "parameters_digest": logical, "local_path": output.name}


def custody_files(root):
    paths = []
    for current, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            path = Path(current) / name
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise ValueError("crash_custody_directory_link_forbidden")
        for name in files:
            relative = (Path(current) / name).relative_to(root).as_posix()
            if relative in {"report.json", "custody_receipt.json"}: continue
            path = owned(root, relative)
            if path.suffix.lower() not in {".json", ".npz", ".log", ".pem"} or "private" in name.lower() or path.name.endswith("-key.pem"):
                raise ValueError("unexpected_or_private_crash_custody_artifact")
            if path.suffix == ".pem" and b"PRIVATE KEY" in path.read_bytes():
                raise ValueError("private_key_must_not_enter_crash_custody")
            paths.append({"path": relative, "sha256": sha(path), "size_bytes": path.stat().st_size})
    return sorted(paths, key=lambda value: value["path"])


def write_custody(root):
    services = json.loads((root / "s/services.json").read_text())
    if services.get("stopped") is not True:
        raise ValueError("crash_custody_requires_completed_local_cleanup")
    files = custody_files(root)
    receipt = {"schema_version": "0.1.0", "kind": "local-synthetic-process-crash-artifact-custody",
        "after_services_cleanup": True, "private_key_retained": False, "files": files, "file_count": len(files)}
    write(root / "custody_receipt.json", receipt)
    return {"path": "custody_receipt.json", "sha256": sha(root / "custody_receipt.json"), "size_bytes": (root / "custody_receipt.json").stat().st_size}


def verify_custody(report_path, *, expected_report_sha256, verify_protocol=True):
    """Offline replay with a caller-pinned report; neither network nor source writes."""
    report_path = Path(report_path).resolve(); root = report_path.parent
    if not re.fullmatch(r"[0-9a-f]{64}", expected_report_sha256 or "") or sha(report_path) != expected_report_sha256:
        raise ValueError("externally_pinned_crash_report_required")
    report = json.loads(report_path.read_text())
    if (report.get("kind") != "actual-local-protocol-process-crash-probe" or report.get("successful") is not True
            or report.get("aws_used") is not False or report.get("clinical_rows_used") != 0
            or report.get("test_holdout_evaluated") is not False or report.get("full_flower_supervisor_restart") is not False):
        raise ValueError("successful_local_synthetic_crash_report_required")
    ref = report["custody_receipt"]; path = owned(root, ref["path"])
    if path.name != "custody_receipt.json" or sha(path) != ref["sha256"] or path.stat().st_size != ref["size_bytes"]:
        raise ValueError("crash_custody_receipt_bytes_changed")
    receipt = json.loads(path.read_text())
    if (set(receipt) != {"schema_version", "kind", "after_services_cleanup", "private_key_retained", "files", "file_count"}
            or receipt["schema_version"] != "0.1.0" or receipt["kind"] != "local-synthetic-process-crash-artifact-custody"
            or receipt["after_services_cleanup"] is not True or receipt["private_key_retained"] is not False
            or receipt["file_count"] != len(receipt["files"]) or receipt["files"] != custody_files(root)):
        raise ValueError("crash_custody_file_set_or_bytes_changed")
    required = {"operator-public.pem", "s/services.json", *[str(index) + suffix for index in (1, 2) for suffix in
        ("-config.json", "-crash.json", "-recovery.json", "-crash.log", "-recovery.log")], "1-crash-staged.npz"}
    names = {row["path"] for row in receipt["files"]}
    if not required <= names or len(report["cases"]) != 2 or {row["stage"] for row in report["cases"]} != {"before-publication", "after-publication"}:
        raise ValueError("complete_crash_artifact_custody_required")
    services = json.loads(owned(root, "s/services.json").read_text())
    if services.get("stopped") is not True or services.get("aws_resources_created") is not False:
        raise ValueError("local_crash_services_not_cleaned")
    public = owned(root, "operator-public.pem").read_bytes()
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_public_key(public)
    pin = hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    if pin != report["operator_public_key_sha256"]: raise ValueError("crash_operator_public_key_pin_mismatch")
    for index, case in enumerate(report["cases"], 1):
        config = json.loads(owned(root, f"{index}-config.json").read_text()); validate_local(config)
        crash = json.loads(owned(root, f"{index}-crash.json").read_text())
        recovered = json.loads(owned(root, f"{index}-recovery.json").read_text())
        if (case["crash_exit_code"] != 137 or case["crash_pid"] != crash["pid"] or case["recovery_pid"] != recovered["pid"]
                or crash["pid"] == recovered["pid"] or case["recovery"] != recovered or recovered["idempotent_second_publish"] is not True
                or recovered["published_models"] != 1 or config["bucket"] != services["bucket"] or config["table"] != services["table_name"]
                or config["run_id"] != f"crash-probe-{index}" or config["storage"] != services["storage"] or config["opa_endpoint"] != services["opa_endpoint"]):
            raise ValueError("original_crash_recovery_process_binding_mismatch")
        if case["stage"] == "before-publication":
            artifact = crash["staged_artifact"]; staged = owned(root, artifact["local_path"])
            logical, _ = model_digest(staged.read_bytes())
            if (crash["phase"] != "after-immutable-staging-before-publication" or crash["pointer"].get("manifest_id")
                    or artifact["bucket"] != config["bucket"] or artifact["key"] != f"models/candidates/{config['run_id']}/{logical}.npz"
                    or artifact["version_id"] in {None, "", "null"} or artifact["sha256"] != sha(staged) or artifact["size_bytes"] != staged.stat().st_size
                    or artifact["model_digest"] != logical or artifact["parameters_digest"] != logical or crash["staged_parameters_digest"] != logical):
                raise ValueError("orphan_staged_candidate_custody_mismatch")
        elif (crash["phase"] != "after-durable-publication" or crash["pointer"] != recovered["pointer_before"]
                or crash["pointer"] != recovered["pointer_after"] or crash["anchor"] != recovered["anchor"]):
            raise ValueError("original_post_commit_pointer_or_head_changed")
        case_name = "process-" + case["stage"]
        for name in ("evidence.json", "witness.json"):
            if f"e/{case_name}/{name}" not in names: raise ValueError("crash_signed_protocol_evidence_missing")
        if verify_protocol:
            # Translate only local cache locations, preserving signed raw bytes
            # and exact immutable S3 identities, so retained directories can move.
            from unittest.mock import patch
            from pcfl import ablation_verify
            raw = json.loads(owned(root, f"e/{case_name}/evidence.json").read_text())
            witness = json.loads(owned(root, f"e/{case_name}/witness.json").read_text())
            manifests = raw.get("published_manifests", [])
            if (raw.get("persistent_run_id") != config["run_id"] or witness.get("payload", {}).get("cell_id") != case_name
                    or len(manifests) != 1 or manifests[0]["manifest_id"] != recovered.get("manifest_id")
                    or recovered["pointer_after"].get("manifest_id") != recovered.get("manifest_id")
                    or set(manifests[0]["included_update_ids"]) != set(recovered.get("included_update_ids", []))
                    or raw["anchor"] != {name: recovered["anchor"].get(name) for name in ("count", "head")}):
                raise ValueError("crash_recovery_signed_protocol_binding_mismatch")
            original = ablation_verify._load_artifact
            def load_local(artifact, directory):
                from copy import deepcopy
                candidates = [owned(root, row["path"]) for row in receipt["files"]
                    if row["path"].startswith(f"e/{case_name}/") and row["path"].endswith(".npz") and row["sha256"] == artifact.get("sha256")]
                if not candidates: raise ValueError("crash_protocol_model_exact_bytes_missing")
                replacement = deepcopy(artifact)
                replacement["local_export"]["path"] = str(candidates[0])
                return original(replacement, directory)
            with patch.object(ablation_verify, "_load_artifact", side_effect=load_local):
                assessed = ablation_verify.assess_case(owned(root, f"e/{case_name}/evidence.json"),
                    witness=witness,
                    public_key_pem=public, expected_public_key_sha256=pin)
                import numpy as np
                values = load_local(manifests[0]["artifact"], root/"e"/case_name)
                if not np.array_equal(np.asarray(recovered.get("parameters")), np.asarray(values)):
                    raise ValueError("crash_recovery_values_differ_from_verified_model")
            fields = ("protected_witness_verified", "model_pointer_verified", "audit_complete_for_all_final_outcomes", "attempt_accounting_complete")
            if (not all(assessed.get(name) is True for name in fields) or assessed["weighted_models_verified"] != 1
                    or assessed["oracle_invalid_incorporations"] != 0):
                raise ValueError("crash_protocol_offline_replay_failed")
    return {"successful": True, "kind": "offline-pinned-crash-probe-custody-verification", "report_sha256": expected_report_sha256,
        "files_checked": len(names), "cases_checked": 2, "orphan_staged_versions_checked": 1, "protocol_replayed": verify_protocol,
        "AWS_calls": False, "full_flower_supervisor_restart": False}


def write(path, value):
    with Path(path).open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def validate_local(config):
    storage = config["storage"]
    if storage.get("local_emulation") is not True:
        raise ValueError("explicit_local_services_required")
    for endpoint in (storage["dynamodb_endpoint"], storage["s3_endpoint"], config["opa_endpoint"]):
        parsed = urlparse(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or not parsed.port:
            raise ValueError("crash_probe_requires_loopback_services")
    if not config["table"].startswith("pcfl-int-") or not config["bucket"].startswith("pcfl-int-"):
        raise ValueError("owned_local_resource_names_required")


def connect(config):
    validate_local(config)
    import numpy as np
    from pcfl.opa import OpaClient
    from pcfl.persistent import PersistentAuthority
    from pcfl.service_io import sdk_clients
    ddb, s3 = sdk_clients(config["storage"])
    opa = OpaClient(config["opa_endpoint"], allow_loopback_http=True)
    authority = PersistentAuthority(ddb, s3, table_name=config["table"], bucket=config["bucket"],
        run_id=config["run_id"], template=[np.zeros(2, dtype=np.float32)],
        model_schema_hash=hashlib.sha256(b"synthetic-process-crash-two-float-schema").hexdigest(),
        policy_evaluator=opa.evaluate, rule_hash=opa.rule_hash, local_emulation=True)
    return authority


def worker(config, operation, output):
    import numpy as np
    from pcfl.persistent import arrays_digest
    authority = connect(config)
    if operation in {"crash-before-publication", "crash-after-publication"}:
        for index in (1, 2):
            task = authority.issue(f"org_{index:02d}", index, "round-1")
            task = authority.acknowledge(task["task_id"], index, task)
            arrays = [np.full(2, index, dtype=np.float32)]
            authority.receive(task["task_id"], index, {**task, "sample_count": index,
                "weights_digest": arrays_digest(arrays), "client_wall_clock_ms": 0}, arrays)
        def crash_after_stage(arrays, model_digest):
            artifact = retain_staged_candidate(authority.s3, bucket=authority.bucket, run_id=authority.run_id,
                logical_digest=model_digest, output=Path(output).with_name(Path(output).stem + "-staged.npz"))
            write(output, {"pid": os.getpid(), "phase": "after-immutable-staging-before-publication",
                "staged_parameters_digest": model_digest, "staged_artifact": artifact,
                "pointer": authority.item(authority.pk, "POINTER"),
                "anchor": authority.item(authority.pk, "AUDIT_HEAD")})
            os._exit(137)
        manifest = authority.publish("round-1", stage=crash_after_stage if operation == "crash-before-publication" else None)
        write(output, {"pid": os.getpid(), "phase": "after-durable-publication",
            "manifest_id": manifest["manifest_id"], "pointer": authority.item(authority.pk, "POINTER"),
            "anchor": authority.item(authority.pk, "AUDIT_HEAD")})
        os._exit(137)
    if operation != "recover":
        raise ValueError("unknown_crash_probe_operation")
    before = authority.item(authority.pk, "POINTER")
    manifest = authority.publish("round-1")
    head = authority.item(authority.pk, "AUDIT_HEAD")
    again = authority.publish("round-1")
    write(output, {"pid": os.getpid(), "phase": "fresh-process-recovery", "pointer_before": before,
        "manifest_id": manifest["manifest_id"], "included_update_ids": manifest["included_update_ids"],
        "parameters": [value.tolist() for value in authority.parameters()],
        "pointer_after": authority.item(authority.pk, "POINTER"), "anchor": head,
        "idempotent_second_publish": again["manifest_id"] == manifest["manifest_id"]
            and authority.item(authority.pk, "AUDIT_HEAD") == head,
        "published_models": len(authority.evidence()["published_manifests"])})
    return 0


def execute(output):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from pcfl.contracts import ORGANIZATIONS
    from pcfl.governance_service import PolicyWriter
    from integration_services import LocalIntegrationServices
    import run_ablation_protocol as protocol
    source_hashes = {name: sha(ROOT/name) for name in SOURCE_FILES}
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    protocol.RUN = output
    cases = []
    key = ec.generate_private_key(ec.SECP384R1())
    public = key.public_key()
    (output/"operator-public.pem").write_bytes(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    public_pin = hashlib.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    # Child sdk_clients supplies explicit dummy credentials for loopback APIs.
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("AWS_")}
    environment.update(PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    with LocalIntegrationServices(output/"s") as services:
        writer = PolicyWriter(services.ddb, services.table)
        writer.initialize()
        for org in ORGANIZATIONS:
            writer.mutate(org, "GRANT")
        for index, stage in enumerate(("before-publication", "after-publication"), 1):
            if index > 1:
                writer.mutate("org_01", "GRANT")
            config = {"storage": services.storage, "opa_endpoint": services.opa_endpoint,
                "table": services.table, "bucket": services.bucket, "run_id": "crash-probe-"+str(index)}
            config_path, crash_path, recovery_path = (output/(str(index)+suffix+".json") for suffix in ("-config", "-crash", "-recovery"))
            write(config_path, config)
            command = [sys.executable, str(Path(__file__).resolve()), "--worker-config", str(config_path)]
            crashed = subprocess.run([*command, "--operation", "crash-"+stage, "--output", str(crash_path)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, env=environment, check=False)
            (output/(str(index)+"-crash.log")).write_text(crashed.stdout+crashed.stderr, encoding="utf-8")
            if crashed.returncode != 137 or not crash_path.is_file():
                raise RuntimeError("expected_protocol_process_crash_not_observed")
            crash = json.loads(crash_path.read_text())
            if stage == "before-publication":
                if crash["pointer"].get("manifest_id"):
                    raise ValueError("candidate_published_before_crash_hook")
                writer.mutate("org_01", "REVOKE")
            recovered = subprocess.run([*command, "--operation", "recover", "--output", str(recovery_path)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, env=environment, check=False)
            (output/(str(index)+"-recovery.log")).write_text(recovered.stdout+recovered.stderr, encoding="utf-8")
            if recovered.returncode:
                raise RuntimeError("fresh_protocol_process_recovery_failed")
            recovery = json.loads(recovery_path.read_text())
            expected = 2.0 if stage == "before-publication" else 5/3
            if (crash["pid"] == recovery["pid"] or not recovery["idempotent_second_publish"]
                    or recovery["published_models"] != 1
                    or any(abs(value-expected) > 1e-6 for value in recovery["parameters"][0])):
                raise ValueError("process_recovery_state_or_weighting_mismatch")
            if stage == "after-publication" and (crash["pointer"] != recovery["pointer_after"] or crash["anchor"] != recovery["anchor"]):
                raise ValueError("committed_model_or_audit_duplicated_after_process_crash")
            verified, _, _, _ = protocol.retain_case(connect(config), services, "process-"+stage, key)
            independent_checks = {name: verified.get(name) is True for name in (
                "protected_witness_verified", "model_pointer_verified", "audit_complete_for_all_final_outcomes", "attempt_accounting_complete")}
            independent_checks.update(weighted_model_verified=verified.get("weighted_models_tested") == verified.get("weighted_models_verified") == 1,
                zero_oracle_invalid_incorporations=verified.get("oracle_invalid_incorporations") == 0)
            if not all(independent_checks.values()):
                raise ValueError("independent_process_recovery_verification_failed")
            cases.append({"stage": stage, "crash_exit_code": crashed.returncode, "crash_pid": crash["pid"],
                "recovery_pid": recovery["pid"], "recovery": recovery, "verification": verified, "checks": independent_checks})
    if source_hashes != {name: sha(ROOT/name) for name in SOURCE_FILES}:
        raise ValueError("crash_probe_source_changed_during_execution")
    report = {"kind": "actual-local-protocol-process-crash-probe", "successful": len(cases) == 2,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(), "cases": cases,
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "operator_public_key_sha256": public_pin,
        "source_files_sha256": source_hashes,
        "local_service_images": json.loads((output/"s/services.json").read_text())["images"],
        "aws_used": False, "clinical_rows_used": 0, "test_holdout_evaluated": False,
        "full_flower_supervisor_restart": False, "G1_established": False, "formal_P10_acceptance": False,
        "limitations": ["Synthetic two-client array protocol against owned local API emulators",
            "A real separate protocol-coordinator process exits137; this is not a Fargate/Flower service crash",
            "The pre-publication recovery revokes one organization and recomputes rather than publishing its old staged candidate",
            "The post-publication recovery preserves the committed pointer/audit and idempotent publication"]}
    report["custody_receipt"] = write_custody(output)
    write(output/"report.json", report)
    try:
        verify_custody(output/"report.json", expected_report_sha256=sha(output/"report.json"))
    except Exception as error:
        report.update(successful=False, custody_verification_error={"type": type(error).__name__, "reason": str(error)[:240]})
        write(output/"report.json", report)
        raise
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-report", type=Path)
    parser.add_argument("--expected-report-sha256")
    parser.add_argument("--worker-config", type=Path)
    parser.add_argument("--operation", choices=("crash-before-publication", "crash-after-publication", "recover"))
    args = parser.parse_args()
    if args.verify_report:
        if args.output or args.worker_config or args.operation:
            parser.error("--verify-report cannot run a worker or create probe output")
        print(json.dumps(verify_custody(args.verify_report, expected_report_sha256=args.expected_report_sha256), sort_keys=True))
        return 0
    if not args.output:
        parser.error("--output is required when executing a probe")
    if args.worker_config:
        return worker(json.loads(args.worker_config.read_text()), args.operation, args.output)
    existed = args.output.exists()
    try:
        report = execute(args.output)
    except Exception as error:
        if not existed and args.output.is_dir():
            failure = {"kind": "failed-local-protocol-process-crash-probe", "successful": False, "aws_used": False,
                "clinical_rows_used": 0, "error_type": type(error).__name__, "reason": str(error)[:240]}
            with (args.output/"failure.json").open("x", encoding="utf-8") as stream:
                json.dump(failure, stream, sort_keys=True, indent=2); stream.write("\n")
        raise
    print(json.dumps({"successful": report["successful"], "actual_process_crashes": len(report["cases"]), "aws_used": False}))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
