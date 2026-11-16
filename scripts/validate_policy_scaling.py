"""Measure synthetic full-history decisions on pinned, CPU-capped local OPA.

No AWS access or dataset rows. The original pre-optimization report is retained
separately; this command records the new rule and full oracle/negative tests.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from pcfl.opa import OPA_IMAGE, OpaClient
from run_flower import reserve_ports


def main():
    name, port = "pcfl-history-" + uuid.uuid4().hex[:8], reserve_ports(1)[0]
    endpoint = f"http://127.0.0.1:{port}"
    report = {"kind": "local-pinned-opa-synthetic-global-history-scaling", "aws_api_calls": False,
        "cpu_quota": .25, "memory_gib": 1, "image": OPA_IMAGE, "results": [],
        "policy_sha256": hashlib.sha256((ROOT / "policies/rego/pcfl.rego").read_bytes()).hexdigest(),
        "benchmark_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    baseline = ROOT / "reports/policy_history_scaling.json"
    if baseline.is_file():
        report["pre_optimization_report_sha256"] = hashlib.sha256(baseline.read_bytes()).hexdigest()
    command = ["docker", "run", "-d", "--name", name, "--cpus=0.25", "--memory=1g", "--label", "pcfl.history_stress=" + name,
        "-p", f"127.0.0.1:{port}:8181", "--mount", f"type=bind,source={(ROOT / 'policies/rego').as_posix()},target=/policies,readonly",
        OPA_IMAGE, "run", "--server", "--addr=0.0.0.0:8181", "--set", "decision_logs.console=true",
        "/policies/pcfl.rego", "/policies/data.json"]
    try:
        subprocess.run(command, capture_output=True, text=True, check=True, timeout=60)
        deadline = time.monotonic() + 15
        while True:
            try:
                with urlopen(endpoint + "/health", timeout=.5) as response:
                    if response.status == 200:
                        break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("local_opa_startup_timeout")
                time.sleep(.1)
        client = OpaClient(endpoint, allow_loopback_http=True, timeout=3)
        for count in (80, 256, 512, 1024, 2064, 4096):
            events = [{"event_id": "policy-" + hashlib.sha256(str(index).encode()).hexdigest()[:40],
                "org_id": f"org_{index % 8 + 1:02d}", "order": index + 1, "epoch": index // 8 + 1,
                "kind": "GRANT", "rules": [{"purpose": "readmission", "action": action, "effect": "allow"}
                    for action in ("train", "submit_update", "aggregate")]} for index in range(count)]
            query = {"org_id": "org_01", "purpose": "readmission", "start_order": count,
                "commit_order": count, "actions": ["train", "submit_update", "aggregate"]}
            row = {"event_count": count, "canonical_events_bytes": len(json.dumps(events, sort_keys=True, separators=(",", ":")).encode())}
            started = time.perf_counter()
            try:
                result = client(events, query)
                row.update(successful=result["valid"], decision_id_present=bool(result["decision_id"]))
            except Exception as error:
                row.update(successful=False, error_type=type(error).__name__, reason=str(error))
            row["wall_seconds"] = round(time.perf_counter() - started, 4)
            report["results"].append(row)
            print(json.dumps(row), flush=True)
        tested = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_opa.py", "-v"], cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src"), "PCFL_OPA_TEST_URL": endpoint}, capture_output=True, text=True, timeout=90)
        report["oracle_and_contract_tests"] = {"successful": tested.returncode == 0, "output_sha256": hashlib.sha256((tested.stdout + tested.stderr).encode()).hexdigest(),
            "test_source_sha256": hashlib.sha256((ROOT / "tests/test_opa.py").read_bytes()).hexdigest(), "output": tested.stdout + tested.stderr}
        if tested.returncode:
            print(tested.stdout + tested.stderr)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=60)
        report["container_removed"] = subprocess.run(["docker", "inspect", name], capture_output=True, timeout=30).returncode != 0
        report["limitations"] = ["Synthetic history; no clinical rows", "Docker CPU quota is not a Fargate latency measurement", "The full growing history remains an execution-order latency covariate"]
        report["successful"] = bool(report["results"]) and all(row["successful"] for row in report["results"]) and report.get("oracle_and_contract_tests", {}).get("successful") is True and report["container_removed"]
        (ROOT / "reports/policy_history_scaling_optimized.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
