"""Role-specific container services with private mTLS and version-pinned inputs."""

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from .service_io import sdk_clients


def write_private(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(content.encode() if isinstance(content, str) else content)
    return str(path)


def materialize_tls(config, directory):
    """Convert an injected per-role secret into local paths; never log the input."""
    config = deepcopy(config)
    if "tls_files" in config:
        raise ValueError("preexisting_service_tls_paths_forbidden")
    tls = config.get("tls", {})
    allowed = {"ca_pem": "ca_cert", "server_cert_pem": "server_cert", "server_key_pem": "server_key",
               "client_cert_pem": "client_cert", "client_key_pem": "client_key"}
    if not isinstance(tls, dict) or set(tls) - set(allowed):
        raise ValueError("unexpected_service_tls_secret_fields")
    if any(not isinstance(value, str) or not value.strip() for value in tls.values()):
        raise ValueError("invalid_service_tls_secret_value")
    for field, target in allowed.items():
        if field in tls:
            config.setdefault("tls_files", {})[target] = write_private(Path(directory) / (target + ".pem"), tls[field])
    config.pop("tls", None)
    return config


def validate_pinned_reference(reference, *, expected_owner, maximum_bytes=100_000_000):
    if (not isinstance(reference, dict) or not {"bucket", "key", "version_id", "sha256"} <= set(reference)
            or not isinstance(reference["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])
            or any(not isinstance(reference[name], str) or not reference[name].strip() for name in ("bucket", "key", "version_id"))
            or reference["version_id"] == "null" or any(part in {"", ".", ".."} for part in reference["key"].split("/"))
            or not isinstance(expected_owner, str) or not re.fullmatch(r"[0-9]{12}", expected_owner)
            or type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 100_000_000
            or ("size_bytes" in reference and (type(reference["size_bytes"]) is not int or not 1 <= reference["size_bytes"] <= maximum_bytes))):
        raise ValueError("pinned_service_object_required")


def fetch_pinned(client, reference, destination, *, expected_owner, maximum_bytes=100_000_000):
    validate_pinned_reference(reference, expected_owner=expected_owner, maximum_bytes=maximum_bytes)
    response = client.get_object(Bucket=reference["bucket"], Key=reference["key"],
                                 VersionId=reference["version_id"], ExpectedBucketOwner=expected_owner)
    try:
        length = response.get("ContentLength")
        if (response.get("VersionId") != reference["version_id"] or type(length) is not int or not 0 < length <= maximum_bytes
                or ("size_bytes" in reference and reference["size_bytes"] != length)):
            raise ValueError("service_object_version_or_size_mismatch")
        content = response["Body"].read(maximum_bytes + 1)
    finally:
        response["Body"].close()
    if len(content) != length or len(content) > maximum_bytes or hashlib.sha256(content).hexdigest() != reference["sha256"]:
        raise ValueError("service_object_checksum_mismatch")
    return write_private(destination, content)


def serve_governance(config):
    from .governance_service import PolicyWriter, create_policy_server
    reference = config.get("campaign_object")
    if reference and (not isinstance(reference, dict) or not isinstance(reference.get("key"), str)
                      or not reference["key"].startswith("policies/") or ".." in reference["key"].split("/")):
        raise ValueError("governance_campaign_prefix_mismatch")
    if reference:
        validate_pinned_reference(reference, expected_owner=config["storage"]["expected_account_id"])
    ddb, s3 = sdk_clients(config["storage"])
    writer = PolicyWriter(ddb, config["table_name"])
    watcher = None
    if reference:
        from .scenarios import ScenarioWatcher
        path = fetch_pinned(s3, reference, Path(config.get("runtime_directory", "/runtime")) / "policy-campaign.json",
                            expected_owner=config["storage"]["expected_account_id"])
        watcher = ScenarioWatcher(writer, json.loads(Path(path).read_text()))
    writer.initialize()
    if watcher:
        watcher.start()
    server = create_policy_server(writer, config.get("host", "0.0.0.0"), config.get("port", 8443),
                                  **config["tls_files"])
    print(json.dumps({"ready": True, "role": "governance", "mutual_tls": True}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        if watcher:
            watcher.stop()


def serve_evaluation(config):
    from .evaluation import DynamoManifestResolver, EvaluationService, create_model_from_metadata, make_evaluation_server
    from .holdout import strict_json, validate_authorization
    role = config.get("dataset_role", "validation")
    if role not in {"validation", "test"} or (role == "validation" and config.get("confirmatory", False)):
        raise ValueError("final_test_requires_separate_accepted_experiment_authorization")
    owner = None
    authorization, plan = None, None
    if role == "test":
        if any(name not in config for name in ("accepted_plan_object", "authorization_object", "test_object")):
            raise ValueError("final_test_requires_separate_accepted_experiment_authorization")
        owner = config.get("storage", {}).get("expected_account_id")
        if "accepted_plan" in config or "holdout_authorization" in config:
            raise ValueError("inline_holdout_authority_is_not_accepted")
        for name in ("accepted_plan_object", "authorization_object"):
            reference = config[name]
            validate_pinned_reference(reference, expected_owner=owner)
            if (reference["bucket"] != config["bucket"] or not reference["key"].startswith("evaluation/accepted/")
                    or not reference["key"].endswith(".json")):
                raise ValueError("accepted_holdout_objects_require_evaluation_role_prefix")
        reference = config["test_object"]
        validate_pinned_reference(reference, expected_owner=owner)
        if reference["bucket"] != config["bucket"] or reference["key"] != "evaluation/frozen/test.csv":
            raise ValueError("test_role_object_prefix_mismatch")
    else:
        reference = config["validation_object"]
        if (not isinstance(reference, dict) or not isinstance(reference.get("key"), str)
                or not reference["key"].startswith("evaluation/") or not reference["key"].endswith("/validation.csv")
                or any(part in {"", ".", ".."} for part in reference["key"].split("/"))):
            raise ValueError("validation_role_object_prefix_mismatch")
        validate_pinned_reference(reference, expected_owner=config.get("storage", {}).get("expected_account_id"))
    create_model_from_metadata(config["model_metadata"])
    ddb, s3 = sdk_clients(config["storage"])
    root = Path(config.get("runtime_directory", "/runtime"))
    if role == "test":
        # These pinned objects come from the operator's deployment secret and an
        # evaluation-only read prefix. HTTP callers cannot supply authority.
        plan_path = fetch_pinned(s3, config["accepted_plan_object"], root / "accepted/plan.json", expected_owner=owner)
        authorization_path = fetch_pinned(s3, config["authorization_object"], root / "accepted/authorization.json", expected_owner=owner)
        plan = strict_json(Path(plan_path).read_bytes())
        authorization = strict_json(Path(authorization_path).read_bytes())
        scope = validate_authorization(plan, authorization, model_schema_hash=config["model_metadata"]["model_schema_hash"])
        if scope.test_sha256 != reference["sha256"]:
            raise ValueError("test_object_not_bound_to_operator_authorization")
    dataset_path = fetch_pinned(s3, reference, root / ("data/" + role + ".csv"),
                                expected_owner=config["storage"]["expected_account_id"])
    service = EvaluationService(config["model_metadata"], dataset_path, reference["sha256"],
        max_examples=config.get("max_examples", 100000), seed=config.get("seed", 296),
        s3_client=s3, allowed_bucket=config["bucket"], allowed_prefix="models/candidates/",
        manifest_resolver=DynamoManifestResolver(ddb, config["table_name"], require_current=role == "test"),
        dataset_role=role, accepted_plan=plan, holdout_authorization=authorization)
    tls = config["tls_files"]
    server = make_evaluation_server(service, (config.get("host", "0.0.0.0"), config.get("port", 8443)),
        certificate=tls["server_cert"], private_key=tls["server_key"], client_ca=tls["ca_cert"], private_network=True,
        expected_client_cn="pcfl-coordinator")
    print(json.dumps({"ready": True, "role": "evaluation", "dataset_role": role, "mutual_tls": True}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


def opa_command(config):
    tls = config["tls_files"]
    policies = Path(config.get("policy_directory", "/app/policies/rego"))
    from .opa import policy_hash
    if policy_hash(policies / "pcfl.rego") != config["rule_hash"]:
        raise ValueError("image_policy_bundle_hash_mismatch")
    return ["opa", "run", "--server", "--addr=https://0.0.0.0:" + str(config.get("port", 8443)),
            "--authentication=tls", "--authorization=basic", "--min-tls-version=1.2", "--skip-version-check",
            "--tls-cert-file", tls["server_cert"], "--tls-private-key-file", tls["server_key"],
            "--tls-ca-cert-file", tls["ca_cert"], "--set", "decision_logs.console=true",
            str(policies / "pcfl.rego"), str(policies / "data.json"), str(policies / "log_mask.rego"),
            str(policies / "api_authz.rego")]


def probe_access(config):
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    if config["storage"].get("local_emulation"):
        raise ValueError("AWS_identity_and_IAM_probe_cannot_use_emulators")
    role_kind = config.get("role_kind", "client")
    org_id = config.get("org_id")
    if role_kind not in {"client", "coordinator"} or (role_kind == "client" and org_id not in {f"org_{index:02d}" for index in range(1, 9)}):
        raise ValueError("invalid_probe_role_binding")
    own = {**config["allowed_object"], "bucket": config["bucket"]}
    key = own.get("key", "")
    if (role_kind == "coordinator" and (not isinstance(key, str) or not key.startswith("metadata/"))) or (
            role_kind == "client" and (not isinstance(key, str) or not re.fullmatch(
                rf"partitions/(iid|non_iid)/{org_id}/[^/]+", key))):
        raise ValueError("probe_allowed_object_role_mismatch")
    validate_pinned_reference(own, expected_owner=config["storage"]["expected_account_id"])
    anchor = config.get("protected_anchor_object")
    if anchor is not None:
        validate_pinned_reference(anchor, expected_owner=config["storage"]["expected_account_id"])
        if anchor["bucket"] != config["bucket"] or not anchor["key"].startswith("anchors/"):
            raise ValueError("probe_protected_anchor_scope_mismatch")
    ddb, s3 = sdk_clients(config["storage"])
    identity = boto3.client("sts", region_name=config["storage"]["region"],
        config=Config(ignore_configured_endpoint_urls=True)).get_caller_identity()
    role_name = config["expected_task_role_arn"].rsplit("/", 1)[-1]
    if ":assumed-role/" + role_name + "/" not in identity["Arn"]:
        raise ValueError("probe_not_running_with_expected_task_role")
    path = fetch_pinned(s3, own, Path(config.get("runtime_directory", "/runtime")) / "probe-own.csv",
                        expected_owner=config["storage"]["expected_account_id"])
    Path(path).unlink()
    denied = []
    for reference in config["denied_objects"]:
        try:
            response = s3.get_object(Bucket=config["bucket"], Key=reference["key"], VersionId=reference["version_id"],
                                     ExpectedBucketOwner=config["storage"]["expected_account_id"])
            response["Body"].close()
            raise ValueError("probe_cross_boundary_read_was_allowed")
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code not in {"AccessDenied", "AccessDeniedException"}:
                raise ValueError("probe_denial_not_attributable_to_access_control") from None
            denied.append({"key_sha256": hashlib.sha256(reference["key"].encode()).hexdigest(), "code": code})
    try:
        ddb.put_item(TableName=config["table_name"],
            Item={"PK": {"S": "POLICY#" + (org_id if role_kind == "client" else "org_01")}, "SK": {"S": "PROBE_NO_WRITE"}},
            ConditionExpression="attribute_exists(PK) AND PK = :never",
            ExpressionAttributeValues={":never": {"S": "IMPOSSIBLE#PROBE"}})
        raise ValueError("probe_impossible_condition_was_not_enforced")
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") not in {"AccessDenied", "AccessDeniedException"}:
            raise ValueError("client_policy_write_permission_not_denied") from None
    result = {"successful": True, "role": role_kind + "-isolation-probe", "role_kind": role_kind,
              "task_role_arn": config["expected_task_role_arn"], "own_object_sha256": own["sha256"],
              "denied_reads": denied, "policy_write_denied": True, "record_rows_exported": False}
    if anchor is not None:
        try:
            s3.put_object(Bucket=anchor["bucket"], Key=anchor["key"], Body=b"pcfl-denied-anchor-probe",
                IfNoneMatch="*", ServerSideEncryption="AES256", ExpectedBucketOwner=config["storage"]["expected_account_id"])
            raise ValueError("probe_anchor_write_was_allowed")
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") not in {"AccessDenied", "AccessDeniedException"}:
                raise ValueError("probe_anchor_write_permission_not_denied") from None
        result["anchor_write_denied"] = True
    if role_kind == "client":
        result.update(org_id=org_id, own_partition_sha256=own["sha256"])
    else:
        result["own_metadata_sha256"] = own["sha256"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("governance", "evaluation", "opa", "operator"))
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.role == "operator":
        if config.get("operation") != "probe-access":
            raise ValueError("unsupported_operator_operation")
        print(json.dumps(probe_access(config), allow_nan=False), flush=True)
        return
    config = materialize_tls(config, Path(config.get("runtime_directory", "/runtime")) / "service-tls")
    if args.role == "opa":
        command = opa_command(config)
        os.execvp(command[0], command)
    elif args.role == "evaluation":
        serve_evaluation(config)
    else:
        serve_governance(config)


if __name__ == "__main__":
    main()
