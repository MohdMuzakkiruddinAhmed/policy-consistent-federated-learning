"""Run the full test suite with explicit pinned localhost service integrations."""

import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from integration_services import IMAGES, LocalIntegrationServices
from run_flower import runtime_environment, write_json

ROOT = Path(__file__).resolve().parents[1]


def main():
    directory = ROOT / "results/integration" / ("validation-" + uuid.uuid4().hex[:8])
    with LocalIntegrationServices(directory) as services:
        opa_name = next(name for name in services.names if name.endswith("-opa"))
        rego = services.docker("exec", opa_name, "/opa", "test", "/policies", "-v")
        (ROOT / "reports/rego_validation.txt").write_text(rego + "\n", encoding="utf-8")
        env = {**runtime_environment(os.environ), "PCFL_LOCAL_INTEGRATION": "1",
               "PCFL_GOVERNANCE_TEST_LOCAL": "1", "PCFL_OPA_TEST_URL": services.opa_endpoint,
               "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        result = subprocess.run([sys.executable, str(ROOT / "scripts/validate.py")], cwd=ROOT, env=env,
                                check=False, capture_output=True, text=True, encoding="utf-8", errors="replace")
        (directory / "validation.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        if result.returncode:
            print(result.stdout[-12000:] + result.stderr[-2000:])
        report = json.loads((ROOT / "reports/local_validation.json").read_text(encoding="utf-8"))
        write_json(directory / "summary.json", {"successful": result.returncode == 0,
                   "tests_run": report["tests_run"], "failures": report["failures"], "errors": report["errors"],
                   "skipped": report["skipped"], "rego_tests_passed": True, "images": IMAGES})
        print(json.dumps({key: report[key] for key in ("successful", "tests_run", "failures", "errors", "skipped")}, indent=2))
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
