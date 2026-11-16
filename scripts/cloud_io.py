"""Bounded cloud campaign I/O. Every target is explicit; no secret is printed."""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import os


def file_sha256(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def short_object_path(directory, key, version_id, *, filename=None):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    identity = hashlib.sha256((key + "\0" + version_id).encode()).hexdigest()
    path = directory / (filename or (identity[:16] + Path(key).suffix))
    marker = path.with_name(path.name + ".id")
    if marker.exists() and marker.read_text(encoding="ascii") != identity:
        raise ValueError("short_artifact_name_collision")
    if not marker.exists():
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(identity)
    return path


def validate_upload(spec):
    expected = {"source_path", "key", "sha256", "kind"}
    if not isinstance(spec, dict) or set(spec) != expected or not re.fullmatch(r"[0-9a-f]{64}", spec["sha256"]):
        raise ValueError("invalid_upload_contract")
    key, kind = spec["key"], spec["kind"]
    if not isinstance(key, str) or any(part in {"", ".", ".."} for part in key.split("/")):
        raise ValueError("unsafe_upload_key")
    own = re.fullmatch(r"partitions/(iid|non_iid)/org_0[1-8]/(train\.csv|preprocessor\.json)", key)
    valid = (own and ((kind == "partition" and key.endswith("/train.csv")) or (kind == "preprocessor" and key.endswith("/preprocessor.json"))))
    valid = valid or (kind in {"validation", "test"} and key == f"evaluation/frozen/{kind}.csv")
    valid = valid or (kind in {"model_metadata", "campaign"} and re.fullmatch(r"metadata/[A-Za-z0-9._/-]+\.json", key))
    valid = valid or (kind == "policy_schedule" and re.fullmatch(r"policies/(?:[A-Za-z0-9._-]+\.json|[A-Za-z0-9._-]{1,81}/campaign\.json)", key))
    valid = valid or (kind in {"accepted_plan", "accepted_authorization"}
                     and re.fullmatch(r"evaluation/accepted/[0-9a-f]{64}/" + kind.removeprefix("accepted_") + r"\.json", key))
    if not valid or file_sha256(spec["source_path"]) != spec["sha256"]:
        raise ValueError("upload_scope_or_source_digest_mismatch")


def upload_version(s3, *, bucket, account, spec):
    validate_upload(spec)
    with Path(spec["source_path"]).open("rb") as stream:
        response = s3.put_object(Bucket=bucket, Key=spec["key"], Body=stream, ExpectedBucketOwner=account,
            ServerSideEncryption="AES256", Metadata={"sha256": spec["sha256"]},
            ChecksumSHA256=base64.b64encode(bytes.fromhex(spec["sha256"])).decode())
    version = response.get("VersionId")
    if not isinstance(version, str) or not version or version == "null":
        raise RuntimeError("immutable_upload_version_required")
    response = s3.get_object(Bucket=bucket, Key=spec["key"], VersionId=version, ExpectedBucketOwner=account)
    result = hashlib.sha256()
    try:
        for block in iter(lambda: response["Body"].read(1024 * 1024), b""):
            result.update(block)
    finally:
        response["Body"].close()
    if response.get("VersionId") != version or result.hexdigest() != spec["sha256"]:
        raise RuntimeError("uploaded_version_body_mismatch")
    return {"bucket": bucket, "key": spec["key"], "version_id": version, "sha256": spec["sha256"], "kind": spec["kind"]}


def registry_config_matches(ecr, repository_name, image_manifest, expected_local_image_id):
    # Docker's containerd store can report the image INDEX digest as .Id;
    # classic stores report a leaf config digest. Bind exact manifest bytes
    # first, then resolve the traditional config identity when appropriate.
    if "sha256:" + hashlib.sha256(image_manifest.encode()).hexdigest() == expected_local_image_id:
        return True
    manifest = json.loads(image_manifest)
    if manifest.get("config", {}).get("digest") == expected_local_image_id:
        return True
    children = [item for item in manifest.get("manifests", []) if item.get("platform", {}).get("os") == "linux"
                and item.get("platform", {}).get("architecture") == "amd64"]
    if len(children) != 1:
        return False
    response = ecr.batch_get_image(repositoryName=repository_name, imageIds=[{"imageDigest": children[0]["digest"]}])
    images = response.get("images", [])
    return len(images) == 1 and json.loads(images[0]["imageManifest"]).get("config", {}).get("digest") == expected_local_image_id


def publish_image(ecr, *, account, region, repository, local_tag, campaign_id, source_hash, expected_local_image_id, run=subprocess.run):
    if not re.fullmatch(rf"{account}\.dkr\.ecr\.{re.escape(region)}\.amazonaws\.com/[a-z0-9._/-]+", repository):
        raise ValueError("same_account_private_repository_required")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+", local_tag):
        raise ValueError("invalid_local_image_tag")
    tag = "campaign-" + hashlib.sha256((campaign_id + source_hash).encode()).hexdigest()[:32]
    target = repository + ":" + tag
    repo_name = repository.split("/", 1)[1]
    existing = ecr.batch_get_image(repositoryName=repo_name, imageIds=[{"imageTag": tag}])
    if existing.get("images"):
        if len(existing["images"]) != 1:
            raise ValueError("ambiguous_immutable_registry_tag")
        image = existing["images"][0]
        if not registry_config_matches(ecr, repo_name, image["imageManifest"], expected_local_image_id):
            raise ValueError("registry_tag_does_not_match_verified_local_image")
        actual = image["imageId"]["imageDigest"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", actual):
            raise ValueError("invalid_existing_registry_manifest_digest")
        return {"reference": repository + "@" + actual, "image_tag": tag, "source_hash": source_hash}
    if any(error.get("failureCode") != "ImageNotFound" for error in existing.get("failures", [])):
        raise RuntimeError("registry_tag_lookup_failed")
    auth = ecr.get_authorization_token(registryIds=[account])["authorizationData"]
    if len(auth) != 1 or auth[0]["proxyEndpoint"] != "https://" + repository.split("/")[0]:
        raise ValueError("registry_authorization_target_mismatch")
    username, password = base64.b64decode(auth[0]["authorizationToken"]).decode().split(":", 1)
    with tempfile.TemporaryDirectory(prefix="pcfl-ecr-auth-") as directory:
        env = {**os.environ, "DOCKER_CONFIG": directory}
        commands = [(["docker", "login", "--username", username, "--password-stdin", auth[0]["proxyEndpoint"]], password + "\n"),
                    (["docker", "tag", local_tag, target], None), (["docker", "push", target], None)]
        for command, stdin in commands:
            result = run(command, input=stdin, env=env, text=True, capture_output=True, timeout=900, check=False)
            if result.returncode:
                # Docker output can contain registry details; retain no token or secret.
                raise RuntimeError("private_image_publish_failed:" + command[1])
    image = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": tag}])["imageDetails"]
    if len(image) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", image[0]["imageDigest"]):
        raise RuntimeError("actual_ecr_manifest_digest_required")
    manifests = ecr.batch_get_image(repositoryName=repo_name, imageIds=[{"imageDigest": image[0]["imageDigest"]}]).get("images", [])
    if len(manifests) != 1 or not registry_config_matches(ecr, repo_name, manifests[0]["imageManifest"], expected_local_image_id):
        raise RuntimeError("published_image_config_not_verified_local_image")
    return {"reference": repository + "@" + image[0]["imageDigest"], "image_tag": tag, "source_hash": source_hash}


def bound_task_request(contract, name, campaign_id, *, overrides=None):
    if name not in contract["task_definition_arns"] or name not in contract["security_group_ids"]:
        raise ValueError("unregistered_task_target")
    result = {"cluster": contract["cluster_arn"], "taskDefinition": contract["task_definition_arns"][name],
        "count": 1, "launchType": "FARGATE", "platformVersion": "1.4.0", "enableExecuteCommand": False,
        "startedBy": "pcfl-" + hashlib.sha256(campaign_id.encode()).hexdigest()[:30], "propagateTags": "TASK_DEFINITION",
        "networkConfiguration": {"awsvpcConfiguration": {"subnets": contract["subnet_ids"],
            "securityGroups": [contract["security_group_ids"][name]], "assignPublicIp": "DISABLED"}}}
    if overrides:
        result["overrides"] = overrides
    return result


def task_evidence(task, account, region, cluster_arn):
    prefix = f"arn:aws:ecs:{region}:{account}:task/{cluster_arn.rsplit('/', 1)[-1]}/"
    if not task.get("taskArn", "").startswith(prefix):
        raise ValueError("task_outside_recorded_cluster")
    interfaces = [value["details"] for value in task.get("attachments", []) if value.get("type") == "ElasticNetworkInterface"]
    values = {item["name"]: item["value"] for details in interfaces for item in details}
    return {"task_arn": task["taskArn"], "task_definition_arn": task["taskDefinitionArn"],
        "private_ip": values.get("privateIPv4Address"), "eni_id": values.get("networkInterfaceId"),
        "last_status": task["lastStatus"], "cpu": int(task["cpu"]), "memory_mib": int(task["memory"]),
        "started_at": task.get("startedAt").isoformat() if task.get("startedAt") else None,
        "billing_started_at": (task.get("pullStartedAt") or task.get("createdAt") or task.get("startedAt")).isoformat() if (task.get("pullStartedAt") or task.get("createdAt") or task.get("startedAt")) else None,
        "stopped_at": task.get("stoppedAt").isoformat() if task.get("stoppedAt") else None,
        "container_exit_codes": [value.get("exitCode") for value in task.get("containers", [])],
        "image_digests": [value.get("imageDigest") for value in task.get("containers", [])],
        "containers": [{"name": value.get("name"), "image": value.get("image"), "image_digest": value.get("imageDigest"),
                        "exit_code": value.get("exitCode"), "runtime_id": value.get("runtimeId")} for value in task.get("containers", [])],
        "task_role_override": task.get("overrides", {}).get("taskRoleArn"),
        "launch_token": next((tag["value"] for tag in task.get("tags", []) if tag["key"] == "LaunchToken"), None)}


def validate_probe_evidence(value, config):
    allowed = {"successful", "role", "role_kind", "task_role_arn", "own_object_sha256", "denied_reads", "policy_write_denied",
               "record_rows_exported", "org_id", "own_partition_sha256", "own_metadata_sha256", "anchor_write_denied"}
    kind = config.get("role_kind", "client")
    expected = {hashlib.sha256(item["key"].encode()).hexdigest() for item in config["denied_objects"]}
    denied = value.get("denied_reads", []) if isinstance(value, dict) else []
    if (not isinstance(value, dict) or set(value) - allowed or value.get("successful") is not True
            or value.get("role_kind") != kind or value.get("role") != kind + "-isolation-probe"
            or value.get("task_role_arn") != config["expected_task_role_arn"]
            or value.get("own_object_sha256") != config["allowed_object"]["sha256"]
            or value.get("policy_write_denied") is not True or value.get("record_rows_exported") is not False
            or len(denied) != len(config["denied_objects"]) or {item.get("key_sha256") for item in denied} != expected
            or any(set(item) != {"key_sha256", "code"} or item.get("code") not in {"AccessDenied", "AccessDeniedException"} for item in denied)
            or (config.get("protected_anchor_object") is not None and value.get("anchor_write_denied") is not True)
            or (kind == "client" and value.get("org_id") != config["org_id"])):
        raise ValueError("probe_logs_do_not_establish_required_identity_and_denials")
    return value


def export_owned_versions(s3, *, bucket, account, destination, max_bytes=8 * 1024 ** 3,
                          protected_anchors=(), anchor_prefix="anchors/", prior_records=(), cache_root=None, metadata_references=()):
    """Retain exact private artifact versions, including abandoned candidates.

    Prefixes are fixed; training/holdout bytes are never exported by this helper.
    Cached versions retain their original paths and require reverified bytes.
    """
    destination = Path(destination)
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("positive_artifact_export_bound_required")
    anchors, prior = list(protected_anchors), {}
    root = Path(cache_root).absolute() if cache_root is not None else None
    prior_records = list(prior_records)
    if prior_records and (root is None or not root.is_dir() or root.is_symlink() or (hasattr(root, "is_junction") and root.is_junction())):
        raise ValueError("owned_artifact_cache_root_required")
    anchor_bindings = {(item.get("bucket", bucket), item.get("key"), item.get("version_id")): item.get("sha256") for item in anchors}
    metadata_bindings = {(item.get("bucket"), item.get("key"), item.get("version_id")): item.get("sha256") for item in metadata_references}
    total = 0
    for record in prior_records:
        key, version_id = record.get("key"), record.get("version_id")
        identity = record.get("bucket"), key, version_id
        private = isinstance(key, str) and key.startswith(("evidence/", "models/candidates/"))
        # Recovered public inputs may already be retained. Verify/count them as
        # history only; this helper never lists or newly fetches metadata/.
        metadata = (isinstance(key, str) and key.startswith("metadata/") and key.endswith(".json")
                    and identity in metadata_bindings and metadata_bindings[identity] == record.get("sha256"))
        anchor = (isinstance(key, str) and key.startswith(anchor_prefix) and key.endswith(".json")
                  and identity in anchor_bindings and anchor_bindings[identity] == record.get("sha256"))
        if (record.get("bucket") != bucket or not (private or anchor or metadata)
                or any(part in {"", ".", ".."} for part in key.split("/")) or Path(key).suffix not in {".json", ".npz", ".log"}
                or not isinstance(version_id, str) or not version_id.strip() or version_id == "null"
                or not isinstance(record.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
                or type(record.get("size_bytes")) is not int or record["size_bytes"] < 0
                or (anchor and record["size_bytes"] > 1024 * 1024) or identity in prior):
            raise ValueError("cached_artifact_reference_outside_recorded_scope")
        path = Path(record["local_path"])
        if not path.is_absolute():
            path = root / path
        if ".." in path.parts or not path.absolute().is_relative_to(root):
            raise ValueError("cached_artifact_path_outside_owned_root")
        for component in (path, *path.parents):
            if component.is_symlink() or (hasattr(component, "is_junction") and component.is_junction()):
                raise ValueError("cached_artifact_symlink_forbidden")
            if component == root:
                break
        if (not path.is_file() or not path.resolve().is_relative_to(root.resolve())
                or path.stat().st_size != record["size_bytes"] or file_sha256(path) != record["sha256"]):
            raise ValueError("cached_artifact_missing_or_corrupt")
        prior[identity] = dict(record)
        total += record["size_bytes"]
        if total > max_bytes or len(prior) > 100000:
            raise RuntimeError("bounded_artifact_export_size_exceeded")
    retained, seen = [], set()
    for prefix in ("evidence/", "models/candidates/"):
        request = {"Bucket": bucket, "Prefix": prefix, "ExpectedBucketOwner": account}
        for _ in range(1000):
            response = s3.list_object_versions(**request)
            for version in response.get("Versions", []):
                key, version_id = version["Key"], version["VersionId"]
                if (not key.startswith(prefix) or any(part in {"", ".", ".."} for part in key.split("/"))
                        or Path(key).suffix not in {".json", ".npz", ".log"}
                        or not isinstance(version_id, str) or not version_id.strip() or version_id == "null"
                        or type(version["Size"]) is not int or version["Size"] < 0):
                    raise ValueError("unexpected_private_artifact_key")
                identity = bucket, key, version_id
                if identity in seen:
                    raise ValueError("duplicate_listed_artifact_version")
                seen.add(identity)
                cached = prior.get(identity)
                if cached is not None:
                    if cached["size_bytes"] != version["Size"]:
                        raise ValueError("cached_artifact_listed_size_mismatch")
                    retained.append(cached)
                    continue
                total += version["Size"]
                if total > max_bytes or len(set(prior) | seen) > 100000:
                    raise RuntimeError("bounded_artifact_export_size_exceeded")
                response_body = s3.get_object(Bucket=bucket, Key=key, VersionId=version_id, ExpectedBucketOwner=account)
                path = short_object_path(destination, key, version_id)
                result = hashlib.sha256()
                try:
                    with path.open("wb") as stream:
                        for block in iter(lambda: response_body["Body"].read(1024 * 1024), b""):
                            stream.write(block)
                            result.update(block)
                finally:
                    response_body["Body"].close()
                if response_body.get("VersionId") != version_id or path.stat().st_size != version["Size"]:
                    path.unlink(missing_ok=True)
                    raise RuntimeError("exported_version_size_or_identity_mismatch")
                retained.append({"bucket": bucket, "key": key, "version_id": version_id, "sha256": result.hexdigest(),
                                 "size_bytes": version["Size"], "local_path": str(path)})
            if not response.get("IsTruncated"):
                break
            request.update(KeyMarker=response["NextKeyMarker"], VersionIdMarker=response["NextVersionIdMarker"])
        else:
            raise RuntimeError("bounded_artifact_version_pagination_exhausted")
    # Anchors have a separate writer boundary. Fetch only versions explicitly
    # recorded by the protected operator, never discover/adopt arbitrary keys.
    for anchor in anchors:
        key, version_id, expected = anchor.get("key"), anchor.get("version_id"), anchor.get("sha256")
        if (anchor.get("bucket", bucket) != bucket or not isinstance(key, str) or not key.startswith(anchor_prefix)
                or not key.endswith(".json") or any(part in {"", ".", ".."} for part in key.split("/"))
                or not isinstance(version_id, str) or not version_id or version_id == "null"
                or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError("protected_anchor_reference_outside_recorded_scope")
        identity = bucket, key, version_id
        cached = prior.get(identity)
        if cached is not None:
            # Anchors are deliberately not prefix-listed. Exact version HEAD
            # supplies the immutable size check without downloading its body.
            confirmed = s3.head_object(Bucket=bucket, Key=key, VersionId=version_id, ExpectedBucketOwner=account)
            if confirmed.get("VersionId") != version_id or confirmed.get("ContentLength") != cached["size_bytes"]:
                raise ValueError("cached_anchor_version_or_size_mismatch")
            retained.append(cached)
            continue
        response = s3.get_object(Bucket=bucket, Key=key, VersionId=version_id, ExpectedBucketOwner=account)
        try:
            body = response["Body"].read(1024 * 1024 + 1)
        finally:
            response["Body"].close()
        if len(body) > 1024 * 1024 or response.get("VersionId") != version_id or hashlib.sha256(body).hexdigest() != expected:
            raise ValueError("protected_anchor_version_or_digest_mismatch")
        total += len(body)
        if total > max_bytes:
            raise RuntimeError("bounded_artifact_export_size_exceeded")
        path = short_object_path(destination, key, version_id)
        path.write_bytes(body)
        retained.append({"bucket": bucket, "key": key, "version_id": version_id, "sha256": expected,
                         "size_bytes": len(body), "local_path": str(path),
                         "protected_operator_witness": anchor.get("kind") != "operator-probe-only-anchor-sentinel",
                         **({"operator_probe_sentinel": True} if anchor.get("kind") == "operator-probe-only-anchor-sentinel" else {})})
    return retained


def purge_recorded_versions(s3, *, bucket, account, references, project):
    tags = s3.get_bucket_tagging(Bucket=bucket, ExpectedBucketOwner=account)["TagSet"]
    if {item["Key"]: item["Value"] for item in tags}.get("Project") != project:
        raise ValueError("refusing_bucket_without_owned_project_tag")
    references = list(references)
    retained = {(item["key"], item["version_id"]) for item in references}
    sentinel_keys = {item["key"] for item in references if item.get("operator_probe_sentinel") is True}
    keys = {item["key"] for item in references}
    discovered, request = [], {"Bucket": bucket, "ExpectedBucketOwner": account}
    for _ in range(1000):
        response = s3.list_object_versions(**request)
        for version in response.get("Versions", []):
            identity = (version["Key"], version["VersionId"])
            if identity not in retained:
                raise ValueError("refusing_to_delete_unretained_bucket_version")
            discovered.append({"Key": identity[0], "VersionId": identity[1]})
        for marker in response.get("DeleteMarkers", []):
            if marker["Key"] not in keys or marker["Key"] in sentinel_keys:
                raise ValueError("refusing_unrecorded_delete_marker")
            discovered.append({"Key": marker["Key"], "VersionId": marker["VersionId"]})
        if not response.get("IsTruncated"):
            break
        request.update(KeyMarker=response["NextKeyMarker"], VersionIdMarker=response["NextVersionIdMarker"])
    else:
        raise RuntimeError("bucket_inventory_pagination_exhausted")
    for start in range(0, len(discovered), 1000):
        result = s3.delete_objects(Bucket=bucket, ExpectedBucketOwner=account, Delete={"Objects": discovered[start:start + 1000], "Quiet": True})
        if result.get("Errors"):
            raise RuntimeError("recorded_version_cleanup_incomplete")
    return len(discovered)
