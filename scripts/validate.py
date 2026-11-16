"""One-command local validation with honest, hash-addressed execution evidence."""

from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from demo import run_demo


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def git_output(*args):
    try:
        result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except FileNotFoundError:
        return None


def input_hashes():
    files = set()
    for directory in ("src", "tests", "scripts", "schemas", "configs", "docs", "spec", "policies", "containers"):
        files.update(p for p in (ROOT / directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    for directory in ("infra", "data_manifests"):
        files.update(p for p in (ROOT / directory).rglob("*") if p.is_file() and ".terraform" not in p.parts
                     and (p.suffix in {".tf", ".tftpl", ".hcl", ".md", ".json"})
                     and not p.name.endswith((".tfvars.json", ".tfplan.json")))
    for filename in ("theoretical.md", "plan (3).md", "plan.md", "README.md", "pyproject.toml",
                     "requirements.lock", "requirements-runtime.in", "requirements-runtime.lock",
                     "Makefile", ".python-version", ".gitignore", "reports/phase_status.md"):
        files.add(ROOT / filename)
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(files) if p.is_file()}


def main() -> int:
    if importlib.util.find_spec("flwr") is None:
        candidate = Path.home() / ".pcfl/flwr127" / ("Scripts/python.exe" if platform.system() == "Windows" else "bin/python")
        if candidate.is_file():
            return subprocess.run([str(candidate), str(Path(__file__).resolve())], cwd=ROOT, check=False).returncode
        print("Full validation requires the optional runtime: python scripts/bootstrap_runtime.py")
        return 1
    started = datetime.now(timezone.utc).isoformat()
    output = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    demo_status, demo_summary = "not_run", None
    if result.wasSuccessful():
        try:
            demo = run_demo()
            write_json(ROOT / "results/local/latest/demo.json", demo)
            demo_summary = demo["summary"]
            demo_status = "passed"
        except Exception:
            demo_status = "failed"
            output.write(traceback.format_exc())
    successful = result.wasSuccessful() and demo_status == "passed"
    transcript = output.getvalue()
    report_dir = ROOT / "reports"
    report_dir.mkdir(exist_ok=True)
    transcript_path = report_dir / "local_validation.txt"
    transcript_path.write_text(transcript, encoding="utf-8")
    files = input_hashes()
    canonical_hashes = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    source_digest = hashlib.sha256(canonical_hashes).hexdigest()
    report = {"schema_version": "0.1.0", "kind": "local_specification_validation",
              "started_at_utc": started, "finished_at_utc": datetime.now(timezone.utc).isoformat(),
              "command": "python scripts/validate.py", "python": platform.python_version(),
              "tested_interpreter_pin_matches": platform.python_version() == "3.12.10",
              "platform": platform.system(), "successful": successful,
              "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "demo_status": demo_status, "demo_summary": demo_summary,
              "source_input_digest": source_digest,
              "transcript_sha256": hashlib.sha256(transcript_path.read_bytes()).hexdigest(),
              "research_gates_passed": [], "hypothesis_verdicts": {},
              "integration_modes": {name: os.environ.get(name, "") for name in
                  ("PCFL_LOCAL_INTEGRATION", "PCFL_GOVERNANCE_TEST_LOCAL")},
              "opa_service_integration_enabled": bool(os.environ.get("PCFL_OPA_TEST_URL")),
              "limitations": ["This command runs automated tests and a local synthetic demo; explicit flags enable local service containers",
                              "AWS smoke and real-data preparation have separate evidence records",
                              "Unit tests exercise PyTorch on synthetic data; actual Flower pilots have separate evidence",
                              "Local service tests do not establish AWS IAM, cloud placement or confirmatory results",
                              "No hardened production audit anchor or complete process-crash campaign",
                              "Finite tests are not a universal proof"]}
    write_json(report_dir / "local_validation.json", report)
    manifest = {"schema_version": "0.1.0", "kind": "local_specification_validation",
                "source_input_digest": source_digest, "source_files_sha256": files,
                "git_commit": git_output("rev-parse", "HEAD"),
                "git_dirty": bool(git_output("status", "--porcelain")),
                "dataset_checksum": None, "container_image_digests": [],
                "aws_task_definitions": [], "aws_task_ids": [],
                "baseline_id": None, "scenario_id": "local-race-demo",
                "seed": None, "ordering": "authority-assigned integer events; deterministic trace",
                "model_configuration": {"kind": "synthetic_vector", "dimension": 2},
                "partition_hash": None,
                "policy_fixture_sha256": files.get("policies/fixtures/interval_traces.json"),
                "not_applicable_reason": "Local specification validation; no dataset, training or cloud resources used",
                "started_at_utc": started, "successful": successful}
    write_json(ROOT / "results/local/latest/run_manifest.json", manifest)
    print(transcript, end="")
    print(f"Local demo: {demo_status}")
    print("Saved reports/local_validation.json and reports/local_validation.txt")
    return 0 if successful else 1


if __name__ == "__main__":
    raise SystemExit(main())
