"""Run private Linux-container Flower campaigns with owned, bounded emulators.

No AWS resources, account credentials, final test data, or public actor listeners.
Failures retain sanitized manifests/logs and still clean up only owned resources.
"""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pcfl.evaluation import build_model_metadata
from pcfl.opa import policy_hash
from pcfl.runtime_verify import verify_case
from pcfl.service_io import sdk_clients, service_identities
from run_flower import create_identity_files, reserve_ports, write_json

DDB_IMAGE = "amazon/dynamodb-local@sha256:6ada631ec7aa5fc83446855eb17233e3dad184fec47477e8140c6c569cfe0c86"
S3_IMAGE = "motoserver/moto@sha256:0361ac8f0cc6687dcf3835da1d60e31cf457fb0d49229d56586f2aa5c510f170"
ORGANIZATIONS = [f"org_{i:02d}" for i in range(1, 9)]
LABEL = "pcfl.container-campaign"


def sha(content):
    return hashlib.sha256(content).hexdigest()


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class PrivateCampaign:
    def __init__(self, output, image, *, timeout=900):
        self.output = Path(output).resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.identifier = "pcfl-cc-" + uuid.uuid4().hex[:10]
        self.image, self.timeout = image, timeout
        self.network = self.identifier + "-network"
        self.bootstrap_network = self.identifier + "-bootstrap"
        self.containers, self.volumes, self.records, self.cleaned = [], [], [], set()
        self.network_created = False
        self.bootstrap_network_created = False
        self.report = {"schema_version": "0.1.0", "kind": "private-linux-container-campaign", "successful": False,
            "campaign_id": self.identifier, "output_directory": str(self.output), "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "aws_resources_created": False, "aws_credentials_forwarded": False, "final_test_opened": False,
            "actual_fargate_placement_verified": False, "containers": self.records, "cases": [], "cleanup": {}}

    def docker(self, *args, timeout=60):
        result = subprocess.run(["docker", *map(str, args)], capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=timeout, check=False)
        if result.returncode:
            # Never serialize argv/env or Docker error text that might echo a
            # secret argument. Per-container application logs remain available.
            raise RuntimeError("owned_docker_command_failed_" + str(result.returncode))
        return (result.stdout + result.stderr if args and args[0] == "logs" else result.stdout).strip()

    def inspect(self, name):
        return json.loads(self.docker("inspect", name))[0]

    def save(self):
        write_json(self.output / "campaign_manifest.json", self.report)

    def _remember(self, name, role):
        item = self.inspect(name)
        if item.get("Config", {}).get("Labels", {}).get(LABEL) != self.identifier:
            raise ValueError("container_ownership_label_mismatch")
        mounts = [{"type": mount["Type"], "destination": mount["Destination"], "volume_name": mount.get("Name"),
                   "read_write": mount["RW"]} for mount in item.get("Mounts", [])]
        volume_ids = [mount["volume_name"] for mount in mounts if mount["volume_name"]]
        self.volumes.extend(name for name in volume_ids if name not in self.volumes)
        record = {"name": name, "role": role, "container_id": item["Id"], "image_id": item["Image"],
            "mounts": mounts, "environment_names": sorted(value.split("=", 1)[0] for value in item["Config"].get("Env", [])),
            "read_only_root": item["HostConfig"]["ReadonlyRootfs"],
            "network_ips": {key: value["IPAddress"] for key, value in item["NetworkSettings"].get("Networks", {}).items()},
            "published_ports": item["HostConfig"].get("PortBindings") or {},
            "state": item["State"]["Status"], "exit_code": item["State"]["ExitCode"]}
        self.records.append(record)
        self.save()
        return record

    def create(self, role, image, command=(), *, aliases=(), environment=None, published=(), runtime=False):
        name = self.identifier + "-" + role
        args = ["create", "--name", name, "--label", LABEL + "=" + self.identifier,
                "--network", self.bootstrap_network if published else self.network, "--stop-timeout", "10"]
        for alias in aliases:
            args += ["--network-alias", alias]
        for port in published:
            args += ["--publish", port]
        if runtime:
            # Explicit, independently owned runtime storage. No clinical host
            # directory or evaluator volume is mounted into another actor.
            volume = name + "-runtime"
            self.docker("volume", "create", "--label", LABEL + "=" + self.identifier, volume)
            self.volumes.append(volume)
            args += ["--mount", "type=volume,source=" + volume + ",target=/runtime", "--read-only",
                     "--tmpfs", "/tmp:rw,noexec,nosuid,size=134217728", "--security-opt", "no-new-privileges",
                     "--cap-drop", "ALL", "--memory", "2g" if role == "coordinator" else "1g", "--cpus", "1"]
        for key, value in (environment or {}).items():
            if not key.startswith(("PCFL_", "AWS_REGION", "FLWR_", "OMP_", "MKL_")):
                raise ValueError("unapproved_container_environment_name")
            args += ["--env", key + "=" + value]
        args += [image, *command]
        self.docker(*args)
        self.containers.append(name)
        if published:
            connection = ["network", "connect"]
            for alias in aliases:
                connection += ["--alias", alias]
            self.docker(*connection, self.network, name)
        record = self._remember(name, role)
        self.docker("start", name)
        started = self.inspect(name)
        record.update(network_ips={key: value["IPAddress"] for key, value in started["NetworkSettings"].get("Networks", {}).items()},
                      state=started["State"]["Status"])
        self.save()
        return name

    def logs_ready(self, name, marker, *, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.inspect(name)["State"]
            logs = self.docker("logs", name)
            if marker in logs:
                return
            if not state["Running"]:
                (self.output / (name + ".log")).write_text(logs, encoding="utf-8")
                raise RuntimeError("owned_service_exited_before_ready")
            time.sleep(.5)
        raise TimeoutError("owned_service_readiness_timeout")

    def verify_actor_isolation(self):
        actors = [record for record in self.records if record["role"] not in {"dynamodb", "s3", "image-inspection"}]
        clients = [record for record in actors if record["role"] in ORGANIZATIONS]
        ips = [record["network_ips"].get(self.network) for record in actors]
        volume_ids = [mount["volume_name"] for record in actors for mount in record["mounts"] if mount["destination"] == "/runtime"]
        if (len(actors) != 12 or len(clients) != 8 or len({record["container_id"] for record in actors}) != 12
                or len(set(ips)) != 12 or not all(ips) or len(volume_ids) != 12 or len(set(volume_ids)) != 12
                or any(set(record["network_ips"]) != {self.network} for record in actors)
                or any(record["published_ports"] or not record["read_only_root"] for record in actors)
                or any((mount["type"], mount["destination"]) not in {("volume", "/runtime"), ("tmpfs", "/tmp")}
                       for record in actors for mount in record["mounts"])):
            raise ValueError("private_actor_container_or_mount_isolation_failed")
        self.report["actor_isolation"] = {"runtime_actor_count": 12, "client_actor_count": 8,
            "distinct_private_ips": 12, "distinct_runtime_volumes": 12, "host_clinical_mounts": False,
            "actor_ports_published": False, "read_only_actor_roots": True,
            "S3_role_authorization_enforced": False}

    def stop(self):
        errors = []
        for name in reversed(self.containers):
            if name in self.cleaned:
                continue
            try:
                item = self.inspect(name)
                if item["Config"].get("Labels", {}).get(LABEL) != self.identifier:
                    raise ValueError("refusing_unowned_container_cleanup")
                for record in self.records:
                    if record["name"] == name:
                        record.update(state=item["State"]["Status"], exit_code=item["State"]["ExitCode"],
                            network_ips={key: value["IPAddress"] for key, value in item["NetworkSettings"].get("Networks", {}).items()})
                (self.output / (name + ".log")).write_text(self.docker("logs", name), encoding="utf-8")
                self.docker("rm", "-f", "-v", name)
                self.cleaned.add(name)
            except Exception as error:
                errors.append({"kind": "container", "name": name, "error": type(error).__name__})
        # Named task volumes are not removed by rm -v. Verify their labels
        # individually; anonymous image volumes were removed by rm -v above.
        try:
            remaining = set(self.docker("volume", "ls", "--format", "{{.Name}}").splitlines())
        except Exception as error:
            remaining = set()
            errors.append({"kind": "volume-inventory", "error": type(error).__name__})
        for volume in set(self.volumes) & remaining:
            try:
                item = json.loads(self.docker("volume", "inspect", volume))[0]
                if item.get("Labels", {}).get(LABEL) != self.identifier:
                    raise ValueError("refusing_unowned_volume_cleanup")
                self.docker("volume", "rm", volume)
            except Exception as error:
                errors.append({"kind": "volume", "name": volume, "error": type(error).__name__})
        for network, created in ((self.network, self.network_created), (self.bootstrap_network, self.bootstrap_network_created)):
            if not created:
                continue
            try:
                item = json.loads(self.docker("network", "inspect", network))[0]
                if item.get("Labels", {}).get(LABEL) != self.identifier:
                    raise ValueError("refusing_unowned_network_cleanup")
                self.docker("network", "rm", network)
            except Exception as error:
                errors.append({"kind": "network", "name": network, "error": type(error).__name__})
        try:
            existing_containers = set(self.docker("ps", "-a", "--format", "{{.Names}}").splitlines())
            existing_volumes = set(self.docker("volume", "ls", "--format", "{{.Name}}").splitlines())
            existing_networks = set(self.docker("network", "ls", "--format", "{{.Name}}").splitlines())
        except Exception as error:
            existing_containers, existing_volumes = set(self.containers), set(self.volumes)
            existing_networks = {self.network, self.bootstrap_network}
            errors.append({"kind": "cleanup-inventory", "error": type(error).__name__})
        owned_networks = ([self.network] if self.network_created else []) + ([self.bootstrap_network] if self.bootstrap_network_created else [])
        self.report["cleanup"] = {"owned_container_names": self.containers, "owned_volume_ids": sorted(set(self.volumes)),
            "all_owned_containers_removed": not set(self.containers) & existing_containers,
            "all_owned_volumes_removed": not set(self.volumes) & existing_volumes, "errors": errors,
            "owned_network_names": owned_networks, "all_owned_networks_removed": not set(owned_networks) & existing_networks,
            "global_prune_used": False}
        if errors or not all(self.report["cleanup"][key] for key in ("all_owned_containers_removed", "all_owned_volumes_removed", "all_owned_networks_removed")):
            self.report["successful"] = False
        self.report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        self.save()

    def pin_image(self):
        image = json.loads(self.docker("image", "inspect", self.image))[0]
        if any(value.split("=", 1)[0] in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "OPENAI_API_KEY"}
               for value in image.get("Config", {}).get("Env", [])):
            raise ValueError("runtime_image_must_not_embed_account_credentials")
        self.image = image["Id"]
        self.report["runtime_image_id"] = self.image
        # Inspect the baked allowlist through a stopped, labeled container;
        # remember/remove its anonymous VOLUME before launching actual actors.
        name = self.identifier + "-image-inspection"
        self.docker("create", "--name", name, "--label", LABEL + "=" + self.identifier, "--network", "none", self.image)
        self.containers.append(name)
        self._remember(name, "image-inspection")
        destination = self.output / "image_source.json"
        self.docker("cp", name + ":/app/containers/build-source.json", destination)
        baked = json.loads(destination.read_text())
        for path, expected in baked["files_sha256"].items():
            if sha((ROOT / path).read_bytes()) != expected:
                raise ValueError("runtime_image_source_does_not_match_current_allowlist")
        self.report["source_files_sha256"] = baked["files_sha256"]
        self.report["image_source_matches_worktree"] = True

    def prepare_storage(self):
        self.docker("network", "create", "--internal", "--label", LABEL + "=" + self.identifier, self.network)
        self.network_created = True
        self.docker("network", "create", "--label", LABEL + "=" + self.identifier, self.bootstrap_network)
        self.bootstrap_network_created = True
        network = json.loads(self.docker("network", "inspect", self.network))[0]
        if network.get("Internal") is not True or network.get("Labels", {}).get(LABEL) != self.identifier:
            raise ValueError("private_network_internal_property_or_label_mismatch")
        self.report["private_network"] = {"name": self.network, "network_id": network["Id"], "internal": True,
            "bootstrap_network": self.bootstrap_network, "bootstrap_connected_roles": ["dynamodb", "s3"]}
        ddb_port, s3_port = reserve_ports(2)
        self.create("dynamodb", DDB_IMAGE, ("-Xms64m", "-Xmx256m", "-jar", "DynamoDBLocal.jar", "-sharedDb"),
                    aliases=("pcfl-dynamodb",), published=(f"127.0.0.1:{ddb_port}:8000",))
        self.create("s3", S3_IMAGE, aliases=("pcfl-s3",), published=(f"127.0.0.1:{s3_port}:5000",))
        host = {"local_emulation": True, "region": "us-east-1", "expected_account_id": "123456789012",
                "dynamodb_endpoint": f"http://127.0.0.1:{ddb_port}", "s3_endpoint": f"http://127.0.0.1:{s3_port}"}
        self.storage = {**host, "isolated_container_emulation": True,
                        "dynamodb_endpoint": "http://pcfl-dynamodb:8000", "s3_endpoint": "http://pcfl-s3:5000"}
        self.ddb, self.s3 = sdk_clients(host)
        deadline = time.monotonic() + 60
        while True:
            try:
                self.ddb.list_tables(); self.s3.list_buckets()
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise TimeoutError("private_storage_emulator_readiness_timeout")
                time.sleep(.3)
        self.table, self.bucket = self.identifier + "-state", self.identifier + "-inputs"
        self.ddb.create_table(TableName=self.table, BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"}, {"AttributeName": "SK", "AttributeType": "S"}])
        self.s3.create_bucket(Bucket=self.bucket)
        self.s3.put_bucket_versioning(Bucket=self.bucket, VersioningConfiguration={"Status": "Enabled"})

    def put(self, key, content):
        response = self.s3.put_object(Bucket=self.bucket, Key=key, Body=content)
        version = response.get("VersionId")
        if not version or version == "null":
            raise ValueError("container_inputs_require_immutable_versions")
        return {"bucket": self.bucket, "key": key, "version_id": version, "sha256": sha(content)}

    def launch(self, *, matrix=False, data_dir=None):
        self.pin_image()
        self.prepare_storage()
        data = Path(data_dir or ROOT / "data/processed/uci296-v0.1.0-seed296")
        self.identities = service_identities(self.output / "keys", dns_names={
            "governance": ["governance"], "evaluation": ["evaluation"], "opa": ["opa"], "superlink": ["superlink"]},
            additional_servers=("opa", "superlink"))
        nodes = create_identity_files(self.output / "node-keys")["nodes"]
        ca = Path(self.identities["ca"]).read_text()
        def tls(role, *, client=False):
            identity = self.identities[role]
            return {"ca_pem": ca, ("client_cert_pem" if client else "server_cert_pem"): Path(identity["cert"]).read_text(),
                    ("client_key_pem" if client else "server_key_pem"): Path(identity["key"]).read_text()}
        metadata = build_model_metadata(data / "preprocessor.json")
        validation = self.put("evaluation/frozen/validation.csv", (data / "validation.csv").read_bytes())
        own = {}
        for org in ORGANIZATIONS:
            own[org] = {"data": self.put(f"partitions/iid/{org}/partition.csv", (data / "iid" / (org + ".csv")).read_bytes()),
                        "preprocessor": self.put(f"partitions/iid/{org}/preprocessor.json", (data / "preprocessor.json").read_bytes())}
        methods = ("B1", "B2", "B3", "P1") if matrix else ("P1",)
        scenarios = ("stable", "mid_round") if matrix else ("stable",)
        cases, runs = [], []
        for baseline in methods:
            for scenario in scenarios:
                cell = baseline + "-" + scenario
                run_id = self.identifier + "-" + cell
                runtime = {"baseline_id": baseline, "scenario_id": scenario, "rounds": 1, "seed": 296,
                    "max_examples_per_client": 64, "validation_max_examples": 128,
                    "authority_backend": "dynamodb-s3-opa" if baseline == "P1" else "dynamodb-s3-comparator",
                    "model_metadata": metadata, "validation_source_sha256": validation["sha256"],
                    "table_name": self.table, "bucket": self.bucket, "persistent_run_id": run_id, "scenario_control": True,
                    "message_timeout_seconds": 180, "training": {"local_epochs": 1, "batch_size": 64, "learning_rate": .001, "cpu_threads": 1, "optimizer": "adam"},
                    "opa": {"endpoint": "https://opa:8443", "expected_rule_hash": policy_hash()},
                    "evaluator": {"endpoint": "https://evaluation:8443"}}
                cases.append({"cell_id": cell, "runtime": runtime})
                runs.append({"run_id": run_id, "scenario_id": scenario, "rounds": 1})
        policy_object = self.put("policies/campaign.json", json_bytes({"runs": runs}))
        public_object = self.put("metadata/campaign.json", json_bytes({"campaign_id": self.identifier, "cases": cases,
            "task_deadline_seconds": self.timeout, "stop_on_failure": True}))
        common = {"storage": self.storage, "runtime_directory": "/runtime"}
        self.create("opa", self.image, ("opa",), aliases=("opa",), runtime=True,
            environment={"PCFL_OPA_CONFIG_JSON": json_bytes({"tls": tls("opa"), "rule_hash": policy_hash()}).decode()})
        self.create("governance", self.image, ("governance",), aliases=("governance",), runtime=True,
            environment={"PCFL_GOVERNANCE_CONFIG_JSON": json_bytes({**common, "tls": tls("governance"),
                "table_name": self.table, "campaign_object": policy_object}).decode()})
        self.logs_ready(self.identifier + "-governance", '"ready": true')
        self.create("evaluation", self.image, ("evaluation",), aliases=("evaluation",), runtime=True,
            environment={"PCFL_EVALUATION_CONFIG_JSON": json_bytes({**common, "tls": tls("evaluation"),
                "table_name": self.table, "bucket": self.bucket, "model_metadata": metadata, "validation_object": validation,
                "dataset_role": "validation", "max_examples": 128, "seed": 296}).decode()})
        self.logs_ready(self.identifier + "-evaluation", '"ready": true')
        coordinator = {**common, "campaign_id": self.identifier, "campaign_object": public_object, "bucket": self.bucket,
            "service_tls": tls("coordinator", client=True),
            "node_public_keys": {org: nodes[org]["public"].read_text() for org in ORGANIZATIONS}}
        self.coordinator = self.create("coordinator", self.image, ("coordinator",), aliases=("superlink",), runtime=True,
            environment={"PCFL_COORDINATOR_AUTORUN": "true", "PCFL_ROOT_CA_PEM": ca,
                "PCFL_SERVER_CERT_PEM": Path(self.identities["superlink"]["cert"]).read_text(),
                "PCFL_SERVER_KEY_PEM": Path(self.identities["superlink"]["key"]).read_text(),
                "PCFL_RUNTIME_CONFIG_JSON": json_bytes(coordinator).decode()})
        self.logs_ready(self.coordinator, '"registered_organizations": 8')
        for org in ORGANIZATIONS:
            env = {"PCFL_ORG_ID": org, "PCFL_ROOT_CA_PEM": ca, "PCFL_NODE_PRIVATE_KEY_PEM": nodes[org]["private"].read_text(),
                "PCFL_AWS_ACCOUNT_ID": "123456789012", "PCFL_DATA_BUCKET": self.bucket, "PCFL_SUPERLINK_ADDRESS": "superlink:9092",
                "PCFL_LOCAL_EMULATION_CONFIG_JSON": json_bytes(self.storage).decode()}
            for name, reference in own[org].items():
                for field, source in (("KEY", "key"), ("VERSION_ID", "version_id"), ("SHA256", "sha256")):
                    env["PCFL_" + name.upper() + "_" + field] = reference[source]
            self.create(org, self.image, ("client",), runtime=True, environment=env)
        self.verify_actor_isolation()
        deadline = time.monotonic() + self.timeout + 30
        while time.monotonic() < deadline:
            state = self.inspect(self.coordinator)["State"]
            if not state["Running"]:
                break
            if any(not self.inspect(self.identifier + "-" + org)["State"]["Running"] for org in ORGANIZATIONS):
                raise RuntimeError("client_container_exited_before_campaign_finished")
            time.sleep(1)
        else:
            raise TimeoutError("private_container_campaign_deadline")
        self.docker("cp", self.coordinator + ":/runtime/campaign_result.json", self.output / "campaign_result.json")
        campaign = json.loads((self.output / "campaign_result.json").read_text())
        if not campaign.get("successful"):
            self.report["coordinator_error"] = {"type": campaign.get("error", "CaseFailure"), "code": "coordinator_campaign_failed"}
        for case in campaign["cases"]:
            cell = case["cell_id"]
            destination = self.output / "cases" / cell
            destination.parent.mkdir(parents=True, exist_ok=True)
            self.docker("cp", self.coordinator + ":/runtime/cases/" + cell, destination)
            path = destination / "runtime_result.json"
            result = json.loads(path.read_text())
            self.export_objects(result, destination)
            write_json(path, result)
            checked = verify_case(path)
            checked["cell_id"] = cell
            self.report["cases"].append(checked)
        self.report.update(successful=campaign["successful"] and state["ExitCode"] == 0,
            runtime_actor_count=12, backend_container_count=2, eight_client_containers=True,
            evaluator_data_separate_runtime_volume=True, model_metadata_digest=metadata["metadata_digest"],
            validation_source_sha256=validation["sha256"], native_mutual_tls_services=True,
            native_opa_rule_hash=policy_hash(), matrix=matrix)
        self.save()

    def export_objects(self, value, directory):
        if isinstance(value, dict):
            if value.get("backend") == "s3" and "version_id" in value:
                response = self.s3.get_object(Bucket=value["bucket"], Key=value["key"], VersionId=value["version_id"])
                try:
                    content = response["Body"].read()
                finally:
                    response["Body"].close()
                if sha(content) != value["sha256"] or len(content) != value["size_bytes"]:
                    raise ValueError("container_campaign_object_export_mismatch")
                # Keep Windows host paths below MAX_PATH despite the long
                # project directory. The full committed digest still binds
                # every byte; a prefix collision fails instead of overwriting.
                path = directory / "s3_exports" / (value["sha256"][:20] + ".npz")
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.exists() and sha(path.read_bytes()) != value["sha256"]:
                    raise ValueError("host_export_filename_collision_or_modified_bytes")
                path.write_bytes(content)
                value["local_export"] = {"path": str(path.resolve()), "file_sha256": value["sha256"], "model_digest": value["model_digest"]}
            for child in list(value.values()):
                self.export_objects(child, directory)
        elif isinstance(value, list):
            for child in value:
                self.export_objects(child, directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="pcfl-runtime:0.1.0")
    parser.add_argument("--output")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--matrix", action="store_true")
    args = parser.parse_args()
    if not 120 <= args.timeout <= 7200:
        raise ValueError("bounded_campaign_timeout_required")
    output = Path(args.output) if args.output else ROOT / "results/integration" / ("container-campaign-" + uuid.uuid4().hex[:8])
    campaign = PrivateCampaign(output, args.image, timeout=args.timeout)
    try:
        campaign.launch(matrix=args.matrix)
    except Exception as error:
        campaign.report.update(successful=False, error={"type": type(error).__name__, "code": str(error) if str(error).replace("_", "").isalnum() else "container_campaign_failed"})
        (campaign.output / "harness_error.log").write_text(traceback.format_exc(), encoding="utf-8")
    finally:
        campaign.stop()
    public = deepcopy(campaign.report)
    public["limitations"] = ["Linux containers on one local Docker host do not prove Fargate placement, IAM boundaries or cloud durability.",
        "Shared emulator credentials deliberately do not emulate per-role AWS authorization.",
        "One small validation-only engineering campaign; no confirmatory hypothesis result."]
    history = []
    for path in sorted((ROOT / "results/integration").glob("container-campaign-*/campaign_manifest.json")):
        previous = json.loads(path.read_text(encoding="utf-8"))
        history.append({"campaign_id": previous["campaign_id"], "successful": previous["successful"],
            "manifest_sha256": sha(path.read_bytes()), "error": previous.get("error") or previous.get("coordinator_error"),
            "all_owned_containers_removed": previous.get("cleanup", {}).get("all_owned_containers_removed", False),
            "all_owned_volumes_removed": previous.get("cleanup", {}).get("all_owned_volumes_removed", False)})
    public["attempt_history"] = history
    write_json(ROOT / "reports/container_campaign_validation.json", public)
    print(json.dumps({"successful": public["successful"], "cases": len(public["cases"]),
                      "cleanup": public["cleanup"], "manifest": str(output / "campaign_manifest.json")}))
    raise SystemExit(0 if public["successful"] else 1)


if __name__ == "__main__":
    main()
