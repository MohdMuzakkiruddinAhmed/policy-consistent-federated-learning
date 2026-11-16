"""Materialize task-scoped inputs without printing secrets, then start Flower.

Cloud orchestration must remain blocked until its production publication adapter
and independent readiness evidence exist. This is not an AWS provisioning tool.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


RUNTIME = Path("/runtime")


def _required(environ, name):
    value = environ.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("missing_" + name.lower())
    return value


def write_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)
    path.chmod(0o600)


def _materialize(environ, name, relative_path):
    value = _required(environ, name)
    path = RUNTIME / relative_path
    write_private(path, value)
    environ.pop(name, None)
    return path


def fetch_verified(client, *, bucket, key, version_id, checksum, owner, destination):
    if not re.fullmatch(r"[0-9a-f]{64}", checksum) or not version_id or version_id == "null":
        raise ValueError("immutable_data_version_and_digest_required")
    response = client.get_object(Bucket=bucket, Key=key, VersionId=version_id, ExpectedBucketOwner=owner)
    try:
        if response.get("VersionId") != version_id or response.get("ContentLength", 0) > 100 * 1024 * 1024:
            raise ValueError("unexpected_data_version_or_size")
        content = response["Body"].read(100 * 1024 * 1024 + 1)
    finally:
        response["Body"].close()
    if len(content) > 100 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != checksum:
        raise ValueError("data_checksum_mismatch")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
    destination.chmod(0o400)


def build_command(role, environ):
    """Return an argv list after local input preparation; no shell interpolation."""
    for name in ("tmp", "data", "certs", "keys", "flower"):
        (RUNTIME / name).mkdir(parents=True, exist_ok=True)
    if role in {"governance", "evaluation", "opa", "operator"}:
        config_name = "PCFL_" + role.upper() + "_CONFIG_JSON"
        config = json.loads(_required(environ, config_name))
        if not isinstance(config, dict):
            raise ValueError("service_config_must_be_object")
        path = RUNTIME / (role + "-config.json")
        write_private(path, json.dumps(config, allow_nan=False))
        environ.pop(config_name, None)
        return ["python", "-m", "pcfl.service_runtime", role, "--config", str(path)]
    ca = _materialize(environ, "PCFL_ROOT_CA_PEM", "certs/ca.crt")
    if role == "coordinator":
        cert = _materialize(environ, "PCFL_SERVER_CERT_PEM", "certs/server.pem")
        key = _materialize(environ, "PCFL_SERVER_KEY_PEM", "keys/server.key")
        config_text = _required(environ, "PCFL_RUNTIME_CONFIG_JSON")
        config = json.loads(config_text)
        if not isinstance(config, dict):
            raise ValueError("runtime_config_must_be_object")
        path = RUNTIME / "config.json"
        write_private(path, config_text)
        environ.pop("PCFL_RUNTIME_CONFIG_JSON", None)
        environ["PCFL_RUNTIME_CONFIG"] = str(path)
        if environ.pop("PCFL_COORDINATOR_AUTORUN", "false").lower() == "true":
            return ["python", "-m", "pcfl.cloud_coordinator", "--config", str(path),
                    "--ca", str(ca), "--certificate", str(cert), "--private-key", str(key)]
        return ["flower-superlink", "--ssl-ca-certfile", str(ca), "--ssl-certfile", str(cert),
                "--ssl-keyfile", str(key), "--enable-supernode-auth", "--isolation", "subprocess",
                "--fleet-api-address", "0.0.0.0:9092", "--control-api-address", "0.0.0.0:9093",
                "--serverappio-api-address", "127.0.0.1:9091", "--database", str(RUNTIME / "flower/superlink.sqlite"),
                "--storage-dir", str(RUNTIME / "flower/ffs")]
    if role != "client":
        raise ValueError("invalid_container_role")
    org = _required(environ, "PCFL_ORG_ID")
    if not re.fullmatch(r"org_0[1-8]", org):
        raise ValueError("invalid_organization")
    key_path = _materialize(environ, "PCFL_NODE_PRIVATE_KEY_PEM", "keys/node.key")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    private_key = serialization.load_ssh_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP384R1):
        raise ValueError("flower_auth_requires_nist_p384_private_key")
    owner = _required(environ, "PCFL_AWS_ACCOUNT_ID")
    if not re.fullmatch(r"[0-9]{12}", owner):
        raise ValueError("invalid_expected_bucket_owner")
    bucket = _required(environ, "PCFL_DATA_BUCKET")
    paths = {}
    import boto3
    if environ.get("PCFL_LOCAL_EMULATION_CONFIG_JSON"):
        from pcfl.service_io import sdk_clients
        storage = json.loads(environ.pop("PCFL_LOCAL_EMULATION_CONFIG_JSON"))
        if storage.get("local_emulation") is not True or storage.get("isolated_container_emulation") is not True:
            raise ValueError("explicit_isolated_container_test_mode_required")
        _, client = sdk_clients(storage)
    else:
        client = boto3.client("s3", region_name=_required(environ, "AWS_REGION"))
    for kind, filename in (("DATA", "partition.csv"), ("PREPROCESSOR", "preprocessor.json")):
        object_key = _required(environ, f"PCFL_{kind}_KEY")
        if not re.fullmatch(rf"partitions/(iid|non_iid)/{org}/[^/]+", object_key):
            raise ValueError("cross_organization_input_forbidden")
        path = RUNTIME / "data" / filename
        fetch_verified(client, bucket=bucket, key=object_key,
                       version_id=_required(environ, f"PCFL_{kind}_VERSION_ID"),
                       checksum=_required(environ, f"PCFL_{kind}_SHA256"), owner=owner, destination=path)
        paths[kind] = path
    superlink = _required(environ, "PCFL_SUPERLINK_ADDRESS")
    if not re.fullmatch(r"[A-Za-z0-9.-]+:9092", superlink):
        raise ValueError("invalid_tls_fleet_endpoint")
    node_config = (f'org-id="{org}" data-file="{paths["DATA"]}" '
                   f'preprocessor-path="{paths["PREPROCESSOR"]}"')
    return ["flower-supernode", "--root-certificates", str(ca), "--superlink", superlink,
            "--auth-supernode-private-key", str(key_path), "--clientappio-api-address", "127.0.0.1:9094",
            "--isolation", "subprocess", "--max-retries", "10", "--max-wait-time", "120",
            "--node-config", node_config]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("client", "coordinator", "governance", "evaluation", "opa", "operator"))
    args = parser.parse_args()
    command = build_command(args.role, os.environ)
    os.execvpe(command[0], command, os.environ)


if __name__ == "__main__":
    main()
