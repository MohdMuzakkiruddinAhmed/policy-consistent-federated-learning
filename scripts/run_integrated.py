"""Exercise eight real Flower nodes with local persistent APIs and mTLS actors.

No paid AWS resources are created. Validation runs in a separate process; this
host pilot does not claim filesystem isolation between processes of one user.
"""

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from integration_services import IMAGES, LocalIntegrationServices
from run_flower import file_digest, reserve_ports, run_pilot, runtime_environment, wait_for_port, write_json
from pcfl.contracts import ORGANIZATIONS
from pcfl.evaluation import build_model_metadata
from pcfl.governance_service import PolicyClient
from pcfl.opa import policy_hash
from pcfl.service_io import service_identities


class IntegratedActors:
    def __init__(self, services, args):
        self.services, self.args = services, args
        self.directory = services.directory
        self.identities = service_identities(self.directory / "keys")
        self.processes, self.logs = [], []
        self.gov_port, self.eval_port = reserve_ports(2)
        self.metadata = build_model_metadata(ROOT / "data/processed/uci296-v0.1.0-seed296/preprocessor.json", seed=args.seed)

    def start(self, role, script, config, port):
        config_path = self.directory / (role + "-config.json")
        write_json(config_path, config)
        log = (self.directory / (role + ".log")).open("w", encoding="utf-8")
        self.logs.append(log)
        env = {**runtime_environment(os.environ), "PYTHONPATH": str(ROOT / "src"),
               "OMP_NUM_THREADS": "1", "MKL_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1",
               "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        command = [sys.executable, str(ROOT / "scripts" / script), "--config", str(config_path)]
        if role == "evaluation":
            command += ["--port", str(port)]
        flags = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, **flags)
        self.processes.append(process)
        wait_for_port(port, process, timeout=45)

    def __enter__(self):
        try:
            identity = self.identities
            self.start("governance", "serve_governance.py", {
                "storage": self.services.storage, "table_name": self.services.table, "port": self.gov_port,
                "tls": {"server_cert": identity["governance"]["cert"], "server_key": identity["governance"]["key"],
                        "ca_cert": identity["ca"]}}, self.gov_port)
            self.policy_config = {"endpoint": f"https://127.0.0.1:{self.gov_port}", "ca_cert": identity["ca"],
                                  "client_cert": identity["policy-operator"]["cert"], "client_key": identity["policy-operator"]["key"]}
            self.policy = PolicyClient(**self.policy_config)
            for org in ORGANIZATIONS:
                self.policy.mutate(org, "GRANT", request_id="initial-" + org)
            data_dir = ROOT / "data/processed/uci296-v0.1.0-seed296"
            self.start("evaluation", "evaluate_model.py", {
                "model_metadata": self.metadata, "validation_path": str(data_dir / "validation.csv"),
                "validation_sha256": file_digest(data_dir / "validation.csv"), "max_examples": self.args.validation_examples,
                "seed": self.args.seed,
                "tls": {"server_cert": identity["evaluation"]["cert"], "server_key": identity["evaluation"]["key"],
                        "client_ca": identity["ca"]},
                "aws": {"local_emulator": True, "region": "us-east-1",
                        "dynamodb_endpoint": self.services.storage["dynamodb_endpoint"],
                        "s3_endpoint": self.services.storage["s3_endpoint"],
                        "local_access_key": "pcfllocal", "local_secret_key": "pcfl-local-test-only",
                        "bucket": self.services.bucket, "table": self.services.table}}, self.eval_port)
            self.evaluation_config = {"endpoint": f"https://127.0.0.1:{self.eval_port}", "ca_cert": identity["ca"],
                                      "client_cert": identity["coordinator"]["cert"], "client_key": identity["coordinator"]["key"]}
            return self
        except Exception:
            self.__exit__()
            raise

    def prepare_case(self, runtime, *, directory, data_dir):
        runtime = deepcopy(runtime)
        # A fresh permission is a new lifecycle; prior revoked work remains invalid.
        for org in ORGANIZATIONS:
            self.policy.mutate(org, "GRANT")
        runtime.pop("data_dir")
        runtime.pop("preprocessor_path")
        runtime.update(authority_backend="dynamodb-s3-opa", model_metadata=self.metadata,
            storage=self.services.storage, table_name=self.services.table, bucket=self.services.bucket,
            persistent_run_id="integrated-" + uuid.uuid4().hex[:16],
            opa={"endpoint": self.services.opa_endpoint, "expected_rule_hash": policy_hash(), "allow_loopback_http": True},
            evaluator=self.evaluation_config)
        if runtime["scenario_id"] != "stable":
            # Synthetic adversarial trace only, never a production coordinator role.
            runtime["benchmark_policy_writer"] = self.policy_config
        return runtime

    def finish_case(self, path):
        result = json.loads(path.read_text(encoding="utf-8"))
        exported = {}
        def export(record):
            if not isinstance(record, dict):
                return
            if record.get("backend") == "s3" and "version_id" in record:
                binding = (record["bucket"], record["key"], record["version_id"])
                if binding not in exported:
                    response = self.services.s3.get_object(Bucket=binding[0], Key=binding[1], VersionId=binding[2])
                    content = response["Body"].read()
                    if hashlib.sha256(content).hexdigest() != record["sha256"] or len(content) != record["size_bytes"]:
                        raise ValueError("exported_object_confirmation_failed")
                    destination = path.parent / "s3_exports" / (record["sha256"] + ".npz")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                    exported[binding] = str(destination)
                record["local_export"] = {"path": exported[binding], "file_sha256": record["sha256"],
                                           "model_digest": record.get("parameters_digest", record["model_digest"])}
            for value in list(record.values()):
                if isinstance(value, dict):
                    export(value)
                elif isinstance(value, list):
                    for child in value:
                        export(child)
        export(result)
        result["model_metadata_digest"] = self.metadata["metadata_digest"]
        result["validation_source_sha256"] = file_digest(ROOT / "data/processed/uci296-v0.1.0-seed296/validation.csv")
        result["integration_services"] = {"images": IMAGES, "services_manifest": str(self.directory / "services.json"),
            "local_emulation": True, "aws_resources_created": False, "filesystem_isolation_enforced": False,
            "evaluation_process_separate": True, "mutual_tls_service_calls": True}
        write_json(path, result)

    def __exit__(self, *_):
        for process in reversed(self.processes):
            if process.poll() is None:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False)
                else:
                    import signal
                    os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=15)
        for log in self.logs:
            log.close()
        write_json(self.directory / "actors.json", {"all_processes_stopped": all(p.poll() is not None for p in self.processes),
                   "process_ids": [p.pid for p in self.processes], "separate_processes": True,
                   "filesystem_isolation_enforced": False, "validation_only": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--scenarios", nargs="+", choices=("stable", "mid_round", "revoke_regrant", "near_commit"))
    parser.add_argument("--scenario", choices=("stable", "mid_round", "revoke_regrant", "near_commit"), default="stable")
    parser.add_argument("--distribution", choices=("iid", "non_iid"), default="iid")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--max-examples", type=int, default=64)
    parser.add_argument("--validation-examples", type=int, default=128)
    parser.add_argument("--seed", type=int, default=296)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 5 or not 1 <= args.max_examples <= 2048 or not 2 <= args.validation_examples <= 4096:
        raise ValueError("pilot_size_limits_exceeded")
    args.baseline, args.baselines = "P1", ["P1"]
    directory = ROOT / "results/integration" / ("integrated-" + uuid.uuid4().hex[:8])
    with LocalIntegrationServices(directory) as services:
        with IntegratedActors(services, args) as actors:
            result = run_pilot(args, integration=actors)
            write_json(directory / "flower_run.json", result)


if __name__ == "__main__":
    main()
