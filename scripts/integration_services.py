"""Pinned localhost services for integration tests; never provisions AWS resources."""

import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pcfl.service_io import sdk_clients
from run_flower import reserve_ports, write_json

IMAGES = {
    "dynamodb": "amazon/dynamodb-local@sha256:6ada631ec7aa5fc83446855eb17233e3dad184fec47477e8140c6c569cfe0c86",
    "s3": "motoserver/moto@sha256:0361ac8f0cc6687dcf3835da1d60e31cf457fb0d49229d56586f2aa5c510f170",
    "opa": "openpolicyagent/opa@sha256:a6ccb6e0cc91b2d1807b1b65a844b189249b9ab33d126e0bca30c0cf43b0ae07",
}


class LocalIntegrationServices:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.identifier = "pcfl-int-" + uuid.uuid4().hex[:8]
        self.names = []
        ddb_port, s3_port, opa_port = reserve_ports(3)
        self.storage = {"local_emulation": True, "region": "us-east-1",
                        "dynamodb_endpoint": f"http://127.0.0.1:{ddb_port}",
                        "s3_endpoint": f"http://127.0.0.1:{s3_port}"}
        self.opa_endpoint = f"http://127.0.0.1:{opa_port}"
        self.ports = {"dynamodb": ddb_port, "s3": s3_port, "opa": opa_port}
        self.table = self.identifier + "-state"
        self.bucket = self.identifier + "-models"

    def docker(self, *args):
        result = subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8",
                                errors="replace", check=False, timeout=90)
        if result.returncode:
            raise RuntimeError("local_container_command_failed: " + result.stderr.splitlines()[-1][:200])
        return result.stdout.strip()

    def start(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            for role in IMAGES:
                name = self.identifier + "-" + role
                args = ["run", "-d", "--name", name, "--label", "pcfl.integration=" + self.identifier,
                        "-p", f"127.0.0.1:{self.ports[role]}:" + {"dynamodb": "8000", "s3": "5000", "opa": "8181"}[role]]
                if role == "dynamodb":
                    args += [IMAGES[role], "-Xms64m", "-Xmx256m", "-jar", "DynamoDBLocal.jar", "-sharedDb"]
                elif role == "opa":
                    args += ["--mount", f"type=bind,source={(ROOT / 'policies/rego').as_posix()},target=/policies,readonly",
                             IMAGES[role], "run", "--server", "--addr=0.0.0.0:8181",
                             "--set", "decision_logs.console=true", "/policies/pcfl.rego", "/policies/data.json"]
                else:
                    args += [IMAGES[role]]
                self.docker(*args)
                self.names.append(name)
            self.ddb, self.s3 = sdk_clients(self.storage)
            deadline = time.monotonic() + 50
            while True:
                try:
                    self.ddb.list_tables()
                    self.s3.list_buckets()
                    with urlopen(self.opa_endpoint + "/health", timeout=2) as response:
                        if response.status != 200:
                            raise RuntimeError("OPA not healthy")
                    break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("local_backend_startup_timeout")
                    time.sleep(0.3)
            self.ddb.create_table(TableName=self.table, BillingMode="PAY_PER_REQUEST",
                KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
                AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"}, {"AttributeName": "SK", "AttributeType": "S"}])
            self.ddb.get_waiter("table_exists").wait(TableName=self.table, WaiterConfig={"Delay": 1, "MaxAttempts": 10})
            self.s3.create_bucket(Bucket=self.bucket)
            self.s3.put_bucket_versioning(Bucket=self.bucket, VersioningConfiguration={"Status": "Enabled"})
            self.save(False)
            return self
        except Exception:
            self.stop()
            raise

    def save(self, stopped):
        write_json(self.directory / "services.json", {"kind": "local-api-integration-services",
                   "aws_resources_created": False, "identifier": self.identifier, "storage": self.storage,
                   "opa_endpoint": self.opa_endpoint, "table_name": self.table, "bucket": self.bucket,
                   "images": IMAGES, "container_names": self.names, "stopped": stopped,
                   "limitations": ["DynamoDB Local does not demonstrate AWS IAM or cloud placement",
                       "Moto S3 is an API emulator, not an S3 durability/performance measurement"]})

    def stop(self):
        errors = []
        for name in reversed(self.names):
            try:
                label = self.docker("inspect", "--format", '{{index .Config.Labels "pcfl.integration"}}', name)
                if label != self.identifier:
                    raise RuntimeError("refusing_unowned_container_cleanup")
                logs = self.docker("logs", name)
                (self.directory / (name + ".log")).write_text(logs, encoding="utf-8")
                self.docker("rm", "-f", name)
            except RuntimeError as error:
                errors.append(name)
                write_json(self.directory / (name + "-cleanup-error.json"), {"reason": str(error)})
        if self.directory.exists():
            self.save(not errors)
        if errors:
            raise RuntimeError("local_service_cleanup_incomplete")

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


if __name__ == "__main__":
    directory = ROOT / "results/integration" / ("services-" + uuid.uuid4().hex[:8])
    with LocalIntegrationServices(directory) as services:
        print(json.dumps({"services_started": True, "table": services.table, "bucket": services.bucket,
                          "opa_endpoint": services.opa_endpoint}, indent=2))
