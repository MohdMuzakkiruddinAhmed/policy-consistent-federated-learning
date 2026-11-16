"""Verify native OPA mTLS/API restrictions and separate container filesystems."""

from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcfl.opa import OpaClient, OpaUnavailable, policy_hash
from pcfl.service_io import service_identities


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="pcfl-runtime:0.1.0")
    args = parser.parse_args()
    run_id = "pcfl-service-" + uuid.uuid4().hex[:8]
    directory = ROOT / "results/integration" / run_id
    directory.mkdir(parents=True)
    identity = service_identities(directory / "keys", additional_servers=("opa",))
    image = args.image
    def docker(*args, check=True):
        result = subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        if check and result.returncode:
            raise RuntimeError("service_container_command_failed")
        return result
    image_id = docker("image", "inspect", "--format", "{{.Id}}", image).stdout.strip()
    config = {"rule_hash": policy_hash(), "tls": {"ca_pem": Path(identity["ca"]).read_text(),
        "server_cert_pem": Path(identity["opa"]["cert"]).read_text(),
        "server_key_pem": Path(identity["opa"]["key"]).read_text()}}
    environment = directory / "opa.env"
    environment.write_text("PCFL_OPA_CONFIG_JSON=" + json.dumps(config, separators=(",", ":")) + "\n", encoding="utf-8")
    os.chmod(environment, 0o600)
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
    names = []
    report = {"schema_version": "0.1.0", "checked_at_utc": datetime.now(timezone.utc).isoformat(),
              "local_image_id": image_id, "aws_resources_created": False, "checks": {}, "successful": False}
    try:
        name = run_id + "-opa"
        docker("run", "-d", "--read-only", "--name", name, "--label", "pcfl.service-test=" + run_id,
               "-p", f"127.0.0.1:{port}:8443", "--env-file", str(environment), image, "opa")
        names.append(name)
        endpoint = f"https://127.0.0.1:{port}"
        client_args = {"endpoint": endpoint, "expected_rule_hash": policy_hash(), "ca_file": identity["ca"],
                       "client_cert": identity["coordinator"]["cert"], "client_key": identity["coordinator"]["key"]}
        client = OpaClient(**client_args)
        fixtures = json.loads((ROOT / "policies/fixtures/interval_traces.json").read_text())
        deadline = time.monotonic() + 30
        while True:
            try:
                first = client.evaluate(fixtures[0]["events"], fixtures[0]["query"])
                break
            except OpaUnavailable:
                if time.monotonic() >= deadline:
                    logs = docker("logs", name, check=False).stdout
                    (directory / "opa.log").write_text(logs, encoding="utf-8")
                    raise RuntimeError("native_mtls_opa_not_ready") from None
                time.sleep(0.2)
        for fixture in fixtures:
            answer = client.evaluate(fixture["events"], fixture["query"])
            if answer["valid"] != fixture["expected_valid"]:
                raise ValueError("native_opa_fixture_disagreement")
        report["checks"]["native_mtls_16_fixtures"] = True
        for label, changes in (("missing_client_certificate", {"client_cert": None, "client_key": None}),
            ("wrong_client_identity", {"client_cert": identity["policy-operator"]["cert"], "client_key": identity["policy-operator"]["key"]})):
            try:
                OpaClient(**{**client_args, **changes}).evaluate(fixtures[0]["events"], fixtures[0]["query"])
                raise AssertionError("untrusted_opa_caller_was_accepted")
            except OpaUnavailable:
                report["checks"][label + "_rejected"] = True
        context = ssl.create_default_context(cafile=identity["ca"])
        context.load_cert_chain(identity["coordinator"]["cert"], identity["coordinator"]["key"])
        for label, method, path, content in (("policy_write", "PUT", "/v1/policies/evil", b"package evil\nallow:=true"),
                                             ("broad_data_read", "GET", "/v1/data", None)):
            try:
                with urlopen(Request(endpoint + path, data=content, method=method), context=context, timeout=3):
                    raise AssertionError("forbidden_opa_api_was_accepted")
            except HTTPError as error:
                if error.code not in {401, 403}:
                    raise
                report["checks"][label + "_rejected"] = True
                report["checks"][label + "_status"] = error.code
        # The marker is synthetic and exists only in a separate task's ephemeral
        # volume. The coordinator image has no evaluator data mount or Docker socket.
        eval_name = run_id + "-evaluation-boundary"
        docker("run", "-d", "--read-only", "--name", eval_name, "--label", "pcfl.service-test=" + run_id,
               "--entrypoint", "python", image, "-c", "from pathlib import Path;import time;Path('/runtime/validation-only-marker').write_text('synthetic');time.sleep(60)")
        names.append(eval_name)
        deadline = time.monotonic() + 5
        while docker("exec", eval_name, "test", "-f", "/runtime/validation-only-marker", check=False).returncode:
            if time.monotonic() >= deadline:
                raise RuntimeError("evaluation_boundary_marker_not_created")
            time.sleep(0.1)
        code = "from pathlib import Path;import os;assert os.getuid()==10001;assert not Path('/runtime/validation-only-marker').exists();assert not Path('/data').exists();assert not Path('/var/run/docker.sock').exists();print('separate-volume-verified')"
        checked = docker("run", "--rm", "--read-only", "--entrypoint", "python", image, "-c", code).stdout
        if "separate-volume-verified" not in checked:
            raise AssertionError("separate_runtime_filesystem_check_failed")
        report["checks"]["distinct_nonroot_runtime_filesystems"] = True
        report["successful"] = True
    finally:
        cleanup = []
        for name in reversed(names):
            label = docker("inspect", "--format", '{{index .Config.Labels "pcfl.service-test"}}', name).stdout.strip()
            if label != run_id:
                raise RuntimeError("unowned_service_cleanup_refused")
            logs = docker("logs", name, check=False)
            (directory / (name + ".log")).write_text(logs.stdout + logs.stderr, encoding="utf-8")
            docker("rm", "-f", "-v", name)
            cleanup.append(name)
        report["owned_containers_removed"] = cleanup
        report["limitations"] = ["Local Linux container boundaries, not AWS task IAM or distributed placement",
                                 "Synthetic filesystem marker, not a cloud holdout access probe"]
        (ROOT / "reports/service_container_validation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"successful": report["successful"], "checks": report["checks"]}, indent=2))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
