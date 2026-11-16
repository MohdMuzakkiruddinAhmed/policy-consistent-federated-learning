"""Bounded private-task supervisor for real Flower deployment and evidence export."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from urllib.parse import urlsplit

from .contracts import ORGANIZATIONS
from .service_io import sdk_clients
from .service_runtime import materialize_tls, validate_pinned_reference


def json_file(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _public_identities(public_keys):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.exceptions import UnsupportedAlgorithm
    from flwr.supercore.primitives.asymmetric import public_key_to_bytes
    if not isinstance(public_keys, dict) or set(public_keys) != set(ORGANIZATIONS):
        raise ValueError("eight_distinct_public_node_identities_required")
    encoded_keys, fingerprints = {}, set()
    for org in ORGANIZATIONS:
        if not isinstance(public_keys[org], str):
            raise ValueError("unique_P384_node_keys_required")
        encoded = public_keys[org].encode()
        try:
            key = serialization.load_ssh_public_key(encoded)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            raise ValueError("unique_P384_node_keys_required") from None
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
            raise ValueError("unique_P384_node_keys_required")
        encoded_keys[org] = public_key_to_bytes(key)
        fingerprint = hashlib.sha256(encoded_keys[org]).hexdigest()
        if fingerprint in fingerprints:
            raise ValueError("unique_P384_node_keys_required")
        fingerprints.add(fingerprint)
    return encoded_keys


def _budget(deadline, maximum, stage):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("campaign_deadline_reached:" + stage)
    return min(maximum, remaining)


def register_nodes(stub, public_keys, *, deadline=None):
    from flwr.proto.control_pb2 import RegisterNodeRequest
    encoded_keys = _public_identities(public_keys)
    registry = {}
    for org in ORGANIZATIONS:
        timeout = _budget(deadline, 10, "registration") if deadline is not None else 10
        response = stub.RegisterNode(RegisterNodeRequest(public_key=encoded_keys[org]), timeout=timeout)
        if not response.node_id or str(response.node_id) in registry:
            raise ValueError("registration_not_unique")
        registry[str(response.node_id)] = org
    return registry


def wait_online(stub, registry, process, *, timeout):
    from flwr.proto.control_pb2 import ListNodesRequest
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("invalid_online_wait_timeout")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("superlink_exited_before_fleet_ready")
        response = stub.ListNodes(ListNodesRequest(), timeout=_budget(deadline, 10, "online_wait"))
        # Flower 1.27 ControlServicer returns now().isoformat(), while each
        # NodeInfo.online_until is an epoch-seconds double on the wire.
        observed = datetime.fromisoformat(response.now.replace("Z", "+00:00"))
        if observed.tzinfo is None:
            raise ValueError("superlink_now_requires_timezone")
        online = {str(node.node_id) for node in response.nodes_info if node.online_until > observed.timestamp()}
        if online == set(registry):
            return
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))
    raise TimeoutError("eight_authenticated_clients_not_online")


def export_case(s3, directory, *, bucket, prefix, owner, deadline=None):
    """Upload exact evidence versions; metadata is returned only after all writes."""
    directory = Path(directory).resolve()
    if (not isinstance(owner, str) or not re.fullmatch(r"[0-9]{12}", owner)
            or not isinstance(prefix, str) or any(part in {"", ".", ".."} for part in prefix.rstrip("/").split("/"))
            or not (directory / "runtime_result.json").is_file() or (directory / "runtime_result.json").is_symlink()):
        raise ValueError("invalid_case_export_scope_or_missing_result")
    exported = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix not in {".json", ".npz", ".log"}:
            continue
        if not path.resolve().is_relative_to(directory) or path.stat().st_size > 100_000_000:
            raise ValueError("invalid_case_export_file")
        if deadline is not None:
            _budget(deadline, 1, "evidence_export")
        content = path.read_bytes()
        key = prefix.rstrip("/") + "/" + path.relative_to(directory).as_posix()
        response = s3.put_object(Bucket=bucket, Key=key, Body=content, ServerSideEncryption="AES256",
                                 ExpectedBucketOwner=owner, IfNoneMatch="*")
        version = response.get("VersionId")
        if not isinstance(version, str) or not version or version == "null":
            raise RuntimeError("export_requires_versioned_bucket")
        response = s3.get_object(Bucket=bucket, Key=key, VersionId=version, ExpectedBucketOwner=owner)
        try:
            if (response.get("VersionId") != version or type(response.get("ContentLength")) is not int
                    or response.get("ContentLength") != len(content)):
                raise RuntimeError("exported_version_or_size_mismatch")
            retained = response["Body"].read(len(content) + 1)
        finally:
            response["Body"].close()
        if retained != content:
            raise RuntimeError("exported_version_body_mismatch")
        exported.append({"bucket": bucket, "key": key, "version_id": version,
                         "sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)})
    if not any(record["key"].endswith("/runtime_result.json") for record in exported):
        raise RuntimeError("runtime_result_missing_from_export")
    return exported


def transport_app(source, destination):
    import shutil
    import tomli_w
    shutil.copytree(source, destination / "pcfl", ignore=shutil.ignore_patterns("__pycache__"))
    document = {"project": {"name": "pcfl-private-runtime", "version": "0.1.0",
        "description": "Private PCFL research transport", "authors": [{"name": "PCFL Research"}], "dependencies": []},
        "tool": {"flwr": {"app": {"publisher": "pcfl-research", "components": {
            "serverapp": "pcfl.robust_flower_app:server_app", "clientapp": "pcfl.robust_flower_client:client_app"}, "config": {}}}}}
    (destination / "pyproject.toml").write_text(tomli_w.dumps(document), encoding="utf-8")


def _preflight(config, *, require_cases):
    """Reject a malformed public campaign before SDK calls or child processes."""
    if not isinstance(config, dict) or not isinstance(config.get("campaign_id"), str) or not re.fullmatch(
            r"[a-zA-Z0-9][a-zA-Z0-9_-]{1,80}", config["campaign_id"]):
        raise ValueError("invalid_campaign_identity")
    timeout = config.get("task_deadline_seconds", 3600)
    if type(timeout) is not int or not 60 <= timeout <= 86400:
        raise ValueError("invalid_task_deadline")
    if "stop_on_failure" in config and type(config["stop_on_failure"]) is not bool:
        raise ValueError("invalid_campaign_failure_policy")
    storage = config.get("storage")
    if (not isinstance(storage, dict) or not isinstance(storage.get("expected_account_id"), str)
            or not re.fullmatch(r"[0-9]{12}", storage["expected_account_id"])
            or not isinstance(config.get("bucket"), str) or not config["bucket"].strip()):
        raise ValueError("explicit_storage_owner_and_bucket_required")
    tls = config.get("service_tls")
    if (not isinstance(tls, dict) or set(tls) != {"ca_pem", "client_cert_pem", "client_key_pem"}
            or any(not isinstance(value, str) or not value.strip() for value in tls.values())):
        raise ValueError("coordinator_client_identity_secret_required")
    _public_identities(config.get("node_public_keys"))
    if config.get("campaign_object"):
        reference = config["campaign_object"]
        validate_pinned_reference(reference, expected_owner=storage["expected_account_id"])
        if not reference["key"].startswith("metadata/"):
            raise ValueError("coordinator_campaign_prefix_mismatch")
    if not require_cases and "cases" not in config:
        return
    cases = config.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 300:
        raise ValueError("invalid_bounded_campaign")
    from .evaluation import create_model_from_metadata
    from .learning import _training_configuration
    identities, run_ids = set(), set()
    for case in cases:
        cell_id = case.get("cell_id") if isinstance(case, dict) else None
        if not isinstance(cell_id, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{1,120}", cell_id) or cell_id in identities:
            raise ValueError("invalid_or_duplicate_case_identity")
        identities.add(cell_id)
        runtime = case.get("runtime")
        if not isinstance(runtime, dict) or any(key in runtime for key in (
                "data_dir", "preprocessor_path", "validation_path", "benchmark_policy_writer")):
            raise ValueError("cloud_coordinator_received_forbidden_private_data_or_writer_identity")
        run_id = runtime.get("persistent_run_id")
        if (not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", run_id)
                or run_id in run_ids):
            raise ValueError("invalid_or_duplicate_persistent_run_identity")
        run_ids.add(run_id)
        from .robustness import adapter_source_digest, validate_descriptor
        robust = validate_descriptor(runtime.get("robustness"), seed=runtime.get("seed", 296))
        if (robust["adapter_source_sha256"] != adapter_source_digest() or "final_holdout" in runtime
                or runtime.get("scenario_id") != "robustness" or runtime.get("scenario_control") is not True
                or runtime.get("baseline_id") != "P1" or runtime.get("authority_backend") != "dynamodb-s3-opa"
                or runtime.get("experiment_binding", {}).get("family") != "exploratory"):
            raise ValueError("explicit_exploratory_transport_case_required")
        baseline = runtime.get("baseline_id", "P1")
        ablation = runtime.get("authority_backend") == "dynamodb-s3-ablation"
        if (runtime.get("authority_backend"), baseline) not in {
                ("dynamodb-s3-opa", "P1"), ("dynamodb-s3-comparator", "B1"),
                ("dynamodb-s3-comparator", "B2"), ("dynamodb-s3-comparator", "B3"), ("dynamodb-s3-ablation", "P1")}:
            raise ValueError("invalid_private_authority_baseline_binding")
        if ablation:
            from .ablations import VARIANTS
            if runtime.get("ablation_id") not in VARIANTS or runtime.get("full_protocol", False) is not False:
                raise ValueError("explicit_partial_protocol_ablation_binding_required")
        elif "ablation_id" in runtime or runtime.get("full_protocol", True) is not True:
            raise ValueError("ablation_cannot_be_labeled_full_protocol")
        if config.get("plan_digest") is not None:
            for name, expected in (("plan_digest", config["plan_digest"]), ("cell_id", cell_id),
                                   ("equivalence_hash", case.get("equivalence_hash")), ("match_id", case.get("match_id"))):
                if runtime.get(name) != expected or expected is None:
                    raise ValueError("case_runtime_registered_scope_binding_mismatch")
            if (not isinstance(config["plan_digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", config["plan_digest"])
                    or not isinstance(case.get("equivalence_hash"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", case["equivalence_hash"])
                    or runtime.get("distribution") not in {"iid", "non_iid"}):
                raise ValueError("registered_plan_and_equivalence_hashes_required")
            binding = runtime.get("experiment_binding")
            if (not isinstance(binding, dict) or set(binding) != {"plan_digest", "cell_id", "equivalence_hash", "family", "policy_schedule_hash", "source_sha256"}
                    or any(binding.get(name) != runtime[name] for name in ("plan_digest", "cell_id", "equivalence_hash"))
                    or binding.get("family") not in {"primary", "targeted", "ablation", "replication", "exploratory"}
                    or (binding["family"] == "ablation") != ablation
                    or any(not isinstance(binding.get(name), str) or not re.fullmatch(r"[0-9a-f]{64}", binding[name])
                           for name in ("policy_schedule_hash", "source_sha256"))):
                raise ValueError("explicit_experiment_binding_required")
        elif any(name in runtime for name in ("plan_digest", "equivalence_hash", "cell_id", "match_id")):
            raise ValueError("case_registered_scope_requires_campaign_plan_digest")
        if "final_holdout" in runtime:
            from .holdout import validate_expectation
            final_holdout = validate_expectation(runtime["final_holdout"])
            if (ablation or final_holdout["plan_digest"] != config.get("plan_digest")
                    or final_holdout["cell_id"] != cell_id):
                raise ValueError("final_holdout_case_scope_mismatch")
        if type(runtime.get("rounds", 1)) is not int or not 1 <= runtime.get("rounds", 1) <= 100:
            raise ValueError("invalid_case_round_count")
        if type(runtime.get("seed", 296)) is not int or not 0 <= runtime.get("seed", 296) < 2**32:
            raise ValueError("invalid_case_seed")
        if runtime.get("scenario_id", "stable") not in {"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "stable",
                "between_round", "mid_round", "delayed", "revoke_regrant", "purpose_change", "expiry", "near_commit", "duplicate_restart", "transport_fault", "robustness"}:
            raise ValueError("invalid_case_scenario")
        from .runtime_faults import validate_host_restart
        scenario = runtime.get("scenario_id", "stable")
        restart = validate_host_restart(runtime["host_restart"], run_id, scenario=scenario, rounds=runtime.get("rounds", 1)) if "host_restart" in runtime else None
        if scenario in {"S7", "duplicate_restart"} and (not restart or restart["phase"] != "between-rounds"):
            raise ValueError("S7_requires_explicit_persistent_host_restart")
        fault = runtime.get("scripted_fault")
        if (scenario in {"S8", "transport_fault"}) != (fault is not None) or (fault is not None and
                (runtime.get("rounds", 1) < 2 or fault not in {"opa_transport_unavailable", "audit_transport_unavailable"}
                 or (fault == "opa_transport_unavailable" and baseline == "B1") or "final_holdout" in runtime)):
            raise ValueError("explicit_S8_transport_fault_and_two_rounds_required")
        message_timeout = runtime.get("message_timeout_seconds", 300)
        if type(message_timeout) not in (int, float) or not math.isfinite(message_timeout) or not 0 < message_timeout <= 1800:
            raise ValueError("invalid_case_message_timeout")
        if not isinstance(runtime.get("validation_source_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", runtime["validation_source_sha256"]):
            raise ValueError("invalid_case_validation_binding")
        if not isinstance(runtime.get("table_name"), str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", runtime["table_name"]):
            raise ValueError("invalid_case_state_table")
        for name in ("opa", "evaluator"):
            value = runtime.get(name)
            endpoint = urlsplit(value.get("endpoint", "")) if isinstance(value, dict) else None
            if (endpoint is None or endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password
                    or endpoint.query or endpoint.fragment or endpoint.path not in ("", "/")):
                raise ValueError("private_service_https_endpoint_required")
            endpoint.port  # Reject malformed/out-of-range explicit ports now.
        if not isinstance(runtime["opa"].get("expected_rule_hash"), str) or not re.fullmatch(r"[0-9a-f]{64}", runtime["opa"]["expected_rule_hash"]):
            raise ValueError("pinned_case_rule_hash_required")
        create_model_from_metadata(runtime.get("model_metadata"))
        _training_configuration(runtime.get("training", {}))


def supervise(config, *, ca, certificate, private_key):
    import grpc
    from flwr.proto.control_pb2_grpc import ControlStub
    import tomli_w
    config = deepcopy(config)
    _preflight(config, require_cases=not bool(config.get("campaign_object")))
    for path in (ca, certificate, private_key):
        if not Path(path).is_file():
            raise ValueError("coordinator_tls_file_missing")
    root = Path(config.get("runtime_directory", "/runtime"))
    campaign_id = config["campaign_id"]
    deadline = time.monotonic() + config.get("task_deadline_seconds", 3600)
    report = {"schema_version": "0.1.0", "campaign_id": campaign_id, "successful": False, "cases": [],
              "started_at_utc": datetime.now(timezone.utc).isoformat(), "actual_fargate_placement_verified": False}
    process, channel, s3, primary = None, None, None, None
    owner = config["storage"]["expected_account_id"]

    def persist():
        json_file(root / "campaign_result.json", report)

    def versioned_index(key):
        content = json.dumps(report, sort_keys=True, allow_nan=False).encode()
        response = s3.put_object(Bucket=config["bucket"], Key=key,
            Body=content,
            ServerSideEncryption="AES256", ExpectedBucketOwner=owner, IfNoneMatch="*")
        version = response.get("VersionId")
        if not isinstance(version, str) or not version or version == "null":
            raise RuntimeError("campaign_index_requires_versioned_bucket")
        saved = s3.get_object(Bucket=config["bucket"], Key=key, VersionId=version, ExpectedBucketOwner=owner)
        try:
            if saved.get("VersionId") != version or saved.get("ContentLength") != len(content) or saved["Body"].read(len(content) + 1) != content:
                raise RuntimeError("campaign_index_version_body_mismatch")
        finally:
            saved["Body"].close()
        return {"bucket": config["bucket"], "key": key, "version_id": version,
                "sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)}

    try:
        persist()
        _budget(deadline, 1, "storage_setup")
        ddb, s3 = sdk_clients(config["storage"])
        if config.get("campaign_object"):
            from .service_runtime import fetch_pinned
            reference = config["campaign_object"]
            _budget(deadline, 1, "campaign_fetch")
            path = fetch_pinned(s3, reference, root / "public-campaign.json", expected_owner=owner)
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            allowed = {"campaign_id", "cases", "task_deadline_seconds", "stop_on_failure", "plan_digest",
                       "source_files_sha256", "dataset_manifest_sha256"}
            if not isinstance(payload, dict) or payload.get("campaign_id") != campaign_id or set(payload) - allowed:
                raise ValueError("public_campaign_contract_mismatch")
            config.update(payload)
            _preflight(config, require_cases=True)
        cases = config["cases"]
        _budget(deadline, 1, "input_materialization")
        files = materialize_tls({"tls": config["service_tls"]}, root / "service-client")["tls_files"]
        app = root / "fab"
        transport_app(Path(__file__).resolve().parent, app)
        home = root / "operator-home"
        home.mkdir(parents=True, exist_ok=True)
        (home / "config.toml").write_text(tomli_w.dumps({"superlink": {"default": "private", "private": {
            "address": "127.0.0.1:9093", "root-certificates": str(ca), "insecure": False}}}), encoding="utf-8")
        active = root / "active.json"
        env = {**os.environ, "PCFL_RUNTIME_CONFIG": str(active), "FLWR_HOME": str(home), "FLWR_TELEMETRY_ENABLED": "0"}
        command = ["flower-superlink", "--enable-supernode-auth", "--ssl-ca-certfile", str(ca),
            "--ssl-certfile", str(certificate), "--ssl-keyfile", str(private_key),
            "--fleet-api-address", "0.0.0.0:9092", "--control-api-address", "127.0.0.1:9093",
            "--serverappio-api-address", "127.0.0.1:9091", "--database", str(root / "superlink.sqlite"),
            "--storage-dir", str(root / "storage")]
        _budget(deadline, 1, "superlink_start")
        process = subprocess.Popen(command, env=env)
        channel = grpc.secure_channel("127.0.0.1:9093", grpc.ssl_channel_credentials(Path(ca).read_bytes()))
        grpc.channel_ready_future(channel).result(timeout=_budget(deadline, 30, "control_channel"))
        stub = ControlStub(channel)
        registry = register_nodes(stub, config["node_public_keys"], deadline=deadline)
        report["node_registry"] = registry
        json_file(root / "node_registry.json", registry)
        print(json.dumps({"ready": True, "role": "coordinator", "registered_organizations": len(registry)}), flush=True)
        wait_online(stub, registry, process, timeout=_budget(deadline, 600, "fleet_start"))
        for index, case in enumerate(cases):
            cell_id = case["cell_id"]
            directory = root / "cases" / cell_id
            directory.mkdir(parents=True, exist_ok=True)
            result_path = directory / "runtime_result.json"
            runtime = deepcopy(case["runtime"])
            runtime.update(node_registry=registry, output_dir=str(directory), storage=config["storage"])
            runtime["opa"].update(ca_file=str(ca), client_cert=files["client_cert"], client_key=files["client_key"])
            runtime["evaluator"].update(ca_cert=str(ca), client_cert=files["client_cert"], client_key=files["client_key"])
            case_record = {"cell_id": cell_id, "successful": False, "status": "running", "artifacts": []}
            report["cases"].append(case_record)
            persist()
            started, case_error, result = time.monotonic(), None, None
            case_started_at_utc = datetime.now(timezone.utc).isoformat()
            try:
                remaining = _budget(deadline, 1800, "case_start")
                if remaining < 30:
                    raise TimeoutError("campaign_deadline_reached:case_start")
                if runtime.get("host_restart", {}).get("phase") == "before-case":
                    from .runtime_faults import host_restart_barrier
                    case_record["host_restart"] = host_restart_barrier(ddb, runtime["table_name"], runtime["host_restart"],
                        timeout=_budget(deadline, 300, "host_client_restart"))
                    wait_online(stub, registry, process, timeout=_budget(deadline, 300, "post_restart_authenticated_fleet"))
                    case_record["host_restart"]["authenticated_registry_unchanged"] = True
                if runtime.get("scenario_control"):
                    from .robust_policy import RobustScenarioSignal as ScenarioSignal
                    ScenarioSignal(ddb, runtime["table_name"], runtime["persistent_run_id"], runtime["scenario_id"],
                                   timeout=_budget(deadline, 60, "before_run_barrier"), value=runtime["robustness"]["factors"], seed=runtime["seed"], rounds=runtime["rounds"]).reach("before_run")
                json_file(active, runtime)
                remaining = _budget(deadline, 1800, "flower_run")
                # Reserve a bounded interval for failure/evidence retention.
                if remaining <= 15:
                    raise TimeoutError("campaign_deadline_reached:flower_run")
                run = subprocess.run(["flwr", "run", str(app), "private", "--stream", "--format", "json"], env=env,
                    cwd=app, capture_output=True, text=True, timeout=remaining - 15, check=False)
                (directory / "flower-cli.log").write_text(run.stdout + run.stderr, encoding="utf-8")
                result = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else {
                    "successful": False, "error": "missing_runtime_result"}
                if not isinstance(result, dict):
                    raise ValueError("runtime_result_object_required")
                if run.returncode or type(result.get("successful")) is not bool:
                    result["successful"] = False
            except Exception as error:
                case_error = error
                if result_path.exists():
                    try:
                        previous = json.loads(result_path.read_text(encoding="utf-8"))
                        if isinstance(previous, dict):
                            result = previous
                    except (ValueError, OSError):
                        pass
                result = result if isinstance(result, dict) else {}
                result.update(successful=False, error=type(error).__name__, reason=str(error))
                if isinstance(error, subprocess.TimeoutExpired):
                    def decoded(value):
                        return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")
                    (directory / "flower-cli.log").write_text(decoded(error.stdout) + decoded(error.stderr), encoding="utf-8")
                    result["case_timed_out"] = True
            result.update(model_metadata_digest=runtime["model_metadata"]["metadata_digest"],
                validation_source_sha256=runtime["validation_source_sha256"], elapsed_seconds=time.monotonic()-started,
                case_started_at_utc=case_started_at_utc, case_finished_at_utc=datetime.now(timezone.utc).isoformat(),
                cloud_campaign_id=campaign_id, cell_id=cell_id, match_id=case.get("match_id"),
                equivalence_hash=case.get("equivalence_hash"), plan_digest=config.get("plan_digest"))
            json_file(result_path, result)
            case_record.update(successful=result["successful"], status="completed" if result["successful"] else "failed")
            if case_error is not None:
                case_record.update(error=type(case_error).__name__, reason=str(case_error))
            prefix = f"evidence/campaigns/{campaign_id}/{cell_id}"
            try:
                case_record["artifacts"] = export_case(s3, directory, bucket=config["bucket"], prefix=prefix, owner=owner,
                                                       deadline=deadline)
                case_record["index"] = versioned_index(f"evidence/campaigns/{campaign_id}/index-{index:04d}.json")
            except Exception as export_error:
                case_record.update(successful=False, status="evidence_export_failed",
                                   export_error=type(export_error).__name__, export_reason=str(export_error))
                result.update(successful=False, evidence_export_error=type(export_error).__name__)
                json_file(result_path, result)
                if case_error is None:
                    case_error = RuntimeError("case_evidence_export_failed")
            persist()
            if case_error is not None and (config.get("stop_on_failure", True) or isinstance(case_error, (TimeoutError, subprocess.TimeoutExpired))):
                raise case_error
            if not case_record["successful"] and config.get("stop_on_failure", True):
                raise RuntimeError("case_failed_evidence_preserved")
        report["successful"] = len(report["cases"]) == len(cases) and all(case["successful"] for case in report["cases"])
        return report
    except BaseException as error:
        primary = error
        report.update(successful=False, error=type(error).__name__, reason=str(error))
        raise
    finally:
        cleanup_errors = []
        if channel is not None:
            try:
                channel.close()
            except Exception as error:
                cleanup_errors.append("channel:" + type(error).__name__)
        if process is not None:
            try:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            except Exception as error:
                cleanup_errors.append("process:" + type(error).__name__)
        if cleanup_errors:
            report.update(successful=False, cleanup_errors=cleanup_errors)
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        persist()
        export_error = None
        if s3 is not None:
            try:
                report["campaign_index"] = versioned_index(f"evidence/campaigns/{campaign_id}/campaign_result.json")
            except Exception as error:
                export_error = error
                report.update(successful=False, campaign_export_error=type(error).__name__)
            persist()
        if primary is None and (export_error is not None or cleanup_errors):
            raise RuntimeError("campaign_cleanup_or_final_export_failed") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "ca", "certificate", "private-key"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    result = supervise(config, ca=args.ca, certificate=args.certificate, private_key=args.private_key)
    raise SystemExit(0 if result["successful"] else 1)


if __name__ == "__main__":
    main()
