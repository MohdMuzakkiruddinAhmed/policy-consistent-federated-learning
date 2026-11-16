"""Run eight real, authenticated localhost SuperNodes for a learning pilot.

No Ray simulator, AWS calls, final test holdout, or confirmatory inference.
Use the optional pinned CPU runtime environment to execute this script.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def file_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_environment(base):
    """Forward host execution essentials; learning workers need no account secrets."""
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
               "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432",
               "COMSPEC", "PATHEXT", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "LANG", "LC_ALL",
               "LC_CTYPE", "HOME", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    return {key: value for key, value in base.items() if key.upper() in allowed}


def cleanup_worker_helpers(executable_dir, owned_ports):
    """Stop only this runtime's SuperExec helpers on this launch's loopback ports."""
    if os.name != "nt":
        return []  # POSIX workers share the terminated process session.
    query = "Get-CimInstance Win32_Process -Filter \"Name = 'flower-superexec.exe'\" | Select-Object ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
    response = subprocess.run(["powershell.exe", "-NoProfile", "-Command", query],
                              capture_output=True, text=True, check=False, timeout=20)
    if response.returncode:
        raise RuntimeError("worker_cleanup_inventory_unavailable")
    records = json.loads(response.stdout) if response.stdout.strip() else []
    if isinstance(records, dict):
        records = [records]
    expected = str((executable_dir / "flower-superexec.exe").resolve()).casefold()
    stopped = []
    for record in records:
        if str(record.get("ExecutablePath", "")).casefold() != expected:
            continue
        port = re.search(r"--appio-api-address\s+127\.0\.0\.1:(\d+)(?:\s|$)", record.get("CommandLine") or "")
        if not port or int(port.group(1)) not in owned_ports:
            continue
        pid = record["ProcessId"]
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False, timeout=20)
        stopped.append(pid)
    return stopped


def reserve_ports(number):
    sockets = []
    try:
        for _ in range(number):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def create_identity_files(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    def write_key(name, key, *, node=False):
        path = directory / name
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.OpenSSH if node else serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        os.chmod(path, 0o600)
        return path
    ca_key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PCFL local pilot CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(ca_key, hashes.SHA384()))
    ca_path = directory / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    key = ec.generate_private_key(ec.SECP384R1())
    server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
              .issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), True).sign(ca_key, hashes.SHA384()))
    server_path = directory / "server.pem"
    server_path.write_bytes(server.public_bytes(serialization.Encoding.PEM))
    server_key = write_key("server.key", key)
    identities = {}
    for number in range(1, 10):
        org = f"org_{number:02d}" if number <= 8 else "unregistered-probe"
        node_key = ec.generate_private_key(ec.SECP384R1())
        private = write_key(org + ".key", node_key, node=True)
        public = directory / (org + ".pub")
        public.write_bytes(node_key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                            serialization.PublicFormat.OpenSSH))
        identities[org] = {"private": private, "public": public, "key": node_key}
    return {"ca": ca_path, "server": server_path, "server_key": server_key, "nodes": identities}


def wait_for_port(port, process, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("runtime_process_exited_before_listening")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("runtime_listener_timeout")


def run_pilot(args, *, integration=None):
    import grpc
    import importlib.metadata
    from flwr.proto.control_pb2 import RegisterNodeRequest
    from flwr.proto.control_pb2_grpc import ControlStub
    from flwr.supercore.primitives.asymmetric import public_key_to_bytes
    import tomli_w
    if importlib.metadata.version("flwr") != "1.27.0":
        raise RuntimeError("pinned_flower_1_27_0_required")
    # Keep artifact paths short enough for Windows libraries without long-path support.
    run_id = "fp-" + uuid.uuid4().hex[:8]
    directory = ROOT / "results/runtime" / run_id
    directory.mkdir(parents=True)
    data_dir = ROOT / "data/processed/uci296-v0.1.0-seed296"
    manifest_path = ROOT / "data_manifests/dataset.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # Verify exact frozen clinical artifacts before any child can load them.
    for relative, expected in manifest["private_artifacts_sha256"].items():
        if file_digest(data_dir / relative) != expected:
            raise ValueError("frozen_data_artifact_hash_mismatch")
    training = json.loads((ROOT / "configs/training.json").read_text(encoding="utf-8"))
    app = directory / "app"
    shutil.copytree(ROOT / "src/pcfl", app / "pcfl", ignore=shutil.ignore_patterns("__pycache__"))
    app_config = {"project": {"name": "pcfl-runtime", "version": "0.1.0", "description": "PCFL local deployment pilot",
                              "license": "Apache-2.0", "authors": [{"name": "PCFL Research"}], "dependencies": []},
                  "tool": {"flwr": {"app": {"publisher": "pcfl-research", "components": {
                       "serverapp": "pcfl.flower_app:server_app", "clientapp": "pcfl.flower_client:client_app"}, "config": {}}}}}
    # No user source/license declaration is inferred: the generated package is a
    # private transport bundle, and its bundled source retains its existing status.
    app_config["project"].pop("license")
    (app / "pyproject.toml").write_text(tomli_w.dumps(app_config), encoding="utf-8")
    identity = create_identity_files(directory / "keys")
    appio, fleet, control, *node_ports = reserve_ports(12)
    active_config = directory / "active.json"
    flower_home = Path.home() / ".pcfl/runs" / run_id
    flower_home.mkdir(parents=True)
    connection = {"superlink": {"default": "pcfl-local", "pcfl-local": {
        "address": f"127.0.0.1:{control}", "root-certificates": identity["ca"].as_posix(), "insecure": False}}}
    (flower_home / "config.toml").write_text(tomli_w.dumps(connection), encoding="utf-8")
    env = {**runtime_environment(os.environ), "FLWR_HOME": str(flower_home), "PCFL_RUNTIME_CONFIG": str(active_config),
           "PYTHONPATH": str(app), "FLWR_TELEMETRY_ENABLED": "0", "OMP_NUM_THREADS": "1", "MKL_NUM_THREADS": "1",
           "OPENBLAS_NUM_THREADS": "1", "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    executable_dir = Path(sys.executable).parent
    env["PATH"] = str(executable_dir) + os.pathsep + env.get("PATH", "")
    suffix = ".exe" if os.name == "nt" else ""
    processes, logs = [], []
    result = {"schema_version": "0.1.0", "run_id": run_id, "kind": "localhost_deployment_learning_pilot",
              "governance_mode": "persistent-api-integration" if integration is not None else "local-memory",
              "aws_resources_created": False, "is_confirmatory": False, "final_test_holdout_read": False,
              "flwr_version": "1.27.0", "dataset_manifest_sha256": file_digest(manifest_path),
              "launcher_source_sha256": file_digest(Path(__file__)),
              "aws_credentials_forwarded": any(key.upper().startswith("AWS_") for key in env),
              "pilot_configuration": {"distribution": args.distribution, "rounds": args.rounds,
                  "max_examples_per_client": args.max_examples, "validation_max_examples": args.validation_examples,
                  "seed": args.seed, "training": training},
              "runtime_packages": {name: importlib.metadata.version(name) for name in
                   ("flwr", "torch", "numpy", "scikit-learn", "grpcio", "cryptography")},
              "source_files_sha256": {p.relative_to(app).as_posix(): file_digest(p) for p in (app / "pcfl").glob("*.py")},
              "processes": [], "cases": [], "security_checks": {}}
    def start(role, command, *, worker_home=None):
        log = (directory / (role + ".log")).open("w", encoding="utf-8")
        logs.append(log)
        kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        worker_env = dict(env)
        if worker_home is not None:
            worker_home.mkdir(parents=True)
            worker_env["FLWR_HOME"] = str(worker_home)
        process = subprocess.Popen(command, cwd=app, env=worker_env, stdout=log, stderr=subprocess.STDOUT, **kwargs)
        processes.append(process)
        result["processes"].append({"role": role, "pid": process.pid, "flower_home": worker_env["FLWR_HOME"]})
        return process
    def stop(process):
        if process.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False)
            else:
                import signal
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    try:
        superlink = start("superlink", [str(executable_dir / ("flower-superlink" + suffix)),
            "--enable-supernode-auth", "--ssl-ca-certfile", str(identity["ca"]),
            "--ssl-certfile", str(identity["server"]), "--ssl-keyfile", str(identity["server_key"]),
            "--fleet-api-address", f"127.0.0.1:{fleet}", "--control-api-address", f"127.0.0.1:{control}",
            "--serverappio-api-address", f"127.0.0.1:{appio}", "--database", str(directory / "state.sqlite"),
            "--storage-dir", str(directory / "storage")])
        wait_for_port(control, superlink)
        wait_for_port(fleet, superlink)
        context = ssl.create_default_context(cafile=str(identity["ca"]))
        with context.wrap_socket(socket.socket(), server_hostname="localhost") as sock:
            sock.settimeout(5)
            sock.connect(("127.0.0.1", fleet))
            result["security_checks"]["trusted_ca_tls_handshake"] = bool(sock.getpeercert())
        try:
            with ssl.create_default_context().wrap_socket(socket.socket(), server_hostname="localhost") as sock:
                sock.settimeout(5)
                sock.connect(("127.0.0.1", fleet))
            raise AssertionError("unknown_ca_was_trusted")
        except ssl.SSLCertVerificationError:
            result["security_checks"]["unknown_ca_rejected"] = True
        channel = grpc.secure_channel(f"127.0.0.1:{control}", grpc.ssl_channel_credentials(identity["ca"].read_bytes()))
        grpc.channel_ready_future(channel).result(timeout=20)
        stub = ControlStub(channel)
        registry = {}
        for org, node in identity["nodes"].items():
            if org == "unregistered-probe":
                continue
            registered = stub.RegisterNode(RegisterNodeRequest(public_key=public_key_to_bytes(node["key"].public_key())), timeout=10)
            if not registered.node_id or str(registered.node_id) in registry:
                raise AssertionError("registration_did_not_create_unique_node")
            registry[str(registered.node_id)] = org
        channel.close()
        result["node_registry"] = registry
        for i, (node_id, org) in enumerate(registry.items()):
            node_config = " ".join(key + "=" + json.dumps(value) for key, value in {
                "org-id": org, "data-file": (data_dir / args.distribution / (org + ".csv")).as_posix(),
                "preprocessor-path": (data_dir / "preprocessor.json").as_posix()}.items())
            process = start(org, [str(executable_dir / ("flower-supernode" + suffix)), "--root-certificates", str(identity["ca"]),
                "--superlink", f"127.0.0.1:{fleet}", "--clientappio-api-address", f"127.0.0.1:{node_ports[i]}",
                "--auth-supernode-private-key", str(identity["nodes"][org]["private"]), "--node-config", node_config],
                worker_home=flower_home / org)
            wait_for_port(node_ports[i], process)
        # A separately generated unregistered key must never join this federation.
        rogue = start("unregistered-probe", [str(executable_dir / ("flower-supernode" + suffix)),
            "--root-certificates", str(identity["ca"]), "--superlink", f"127.0.0.1:{fleet}",
            "--clientappio-api-address", f"127.0.0.1:{node_ports[8]}", "--auth-supernode-private-key",
            str(identity["nodes"]["unregistered-probe"]["private"])], worker_home=flower_home / "unregistered-probe")
        # Bounded wait is local to the authentication probe, not training timing.
        try:
            rogue.wait(timeout=8)
        except subprocess.TimeoutExpired:
            pass
        probe_log = directory / "unregistered-probe.log"
        probe_text = probe_log.read_text(encoding="utf-8", errors="replace")
        result["security_checks"]["unregistered_node_rejected"] = any(
            word in probe_text.lower() for word in ("permission_denied", "not authorized", "not registered", "unauthenticated")) or (
                "failed_precondition" in probe_text.lower() and "no supernode found with the given public key" in probe_text.lower())
        if not result["security_checks"]["unregistered_node_rejected"]:
            raise AssertionError("unregistered_node_rejection_not_observed")
        stop(rogue)
        cases = [(baseline, scenario) for baseline in args.baselines
                 for scenario in ("stable", "mid_round")] if args.matrix else [(args.baseline, args.scenario)]
        if integration is not None and getattr(args, "scenarios", None):
            cases = [("P1", scenario) for scenario in args.scenarios]
        for baseline, scenario in cases:
            output_dir = directory / f"{baseline}-{scenario}"
            runtime = {"node_registry": registry, "data_dir": str(data_dir), "preprocessor_path": str(data_dir / "preprocessor.json"),
                       "training": training, "rounds": args.rounds, "baseline_id": baseline, "scenario_id": scenario,
                       "output_dir": str(output_dir), "seed": args.seed, "distribution": args.distribution,
                       "max_examples_per_client": args.max_examples, "validation_max_examples": args.validation_examples,
                       "reply_timeout": 180}
            if integration is not None:
                runtime = integration.prepare_case(runtime, directory=output_dir, data_dir=data_dir)
            write_json(active_config, runtime)
            write_json(output_dir / "launch_config.json", runtime)
            cli = executable_dir / ("flwr" + suffix)
            case = {"baseline_id": baseline, "scenario_id": scenario, "attempted": True}
            result["cases"].append(case)
            print(f"Running {baseline}/{scenario} with eight authenticated SuperNodes", flush=True)
            run = subprocess.run([str(cli), "run", str(app), "pcfl-local", "--stream", "--format", "json"],
                                 cwd=app, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                 timeout=300, check=False)
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "flower-cli.log").write_text(run.stdout + run.stderr, encoding="utf-8")
            path = output_dir / "runtime_result.json"
            if run.returncode or not path.is_file() or not json.loads(path.read_text(encoding="utf-8")).get("successful"):
                case["successful"] = False
                raise RuntimeError(f"flower_case_failed; inspect {output_dir.relative_to(ROOT).as_posix()}")
            case["successful"] = True
            if integration is not None:
                integration.finish_case(path)
            case["result_file"] = path.relative_to(ROOT).as_posix()
            case["result_sha256"] = file_digest(path)
        result["successful"] = True
    except Exception as error:
        result["successful"] = False
        result["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        for process in reversed(processes):
            stop(process)
        for log in logs:
            log.close()
        try:
            result["orphan_worker_helpers_stopped"] = cleanup_worker_helpers(executable_dir, {appio, *node_ports})
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
            result["worker_cleanup_error"] = type(error).__name__
            result["successful"] = False
        result["all_launched_parents_stopped"] = all(process.poll() is not None for process in processes)
        live_ports = []
        for port in (appio, fleet, control, *node_ports):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    live_ports.append(port)
            except OSError:
                pass
        result["all_launch_listeners_stopped"] = not live_ports
        result["remaining_listening_ports"] = live_ports
        result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(directory / "run_manifest.json", result)
        write_json(ROOT / "results/runtime/latest.json", {"run_manifest": str(directory / "run_manifest.json")})
        print(f"Saved {directory.relative_to(ROOT).as_posix()}/run_manifest.json", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--baseline", choices=("B1", "B2", "B3", "P1"), default="P1")
    parser.add_argument("--baselines", nargs="+", choices=("B1", "B2", "B3", "P1"), default=["B1", "B2", "B3", "P1"])
    parser.add_argument("--scenario", choices=("stable", "mid_round", "revoke_regrant", "near_commit"), default="stable")
    parser.add_argument("--distribution", choices=("iid", "non_iid"), default="iid")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--max-examples", type=int, default=256)
    parser.add_argument("--validation-examples", type=int, default=512)
    parser.add_argument("--seed", type=int, default=296)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 5 or not 1 <= args.max_examples <= 2048 or not 2 <= args.validation_examples <= 4096:
        raise ValueError("pilot_size_limits_exceeded")
    run_pilot(args)


if __name__ == "__main__":
    main()
