"""Additive adapter routing; leaves the frozen image's entrypoint byte-identical."""
import argparse
import importlib.util
import json
import os
from pathlib import Path


def build_command(role, environ, frozen):
    if role == "coordinator":
        config = json.loads(environ["PCFL_RUNTIME_CONFIG_JSON"])
        for case in config.get("cases", []):
            runtime = case["runtime"]
            if "robustness" not in runtime or "final_holdout" in runtime:
                raise ValueError("adapter_requires_exploratory_validation_cases")
    command = frozen.build_command(role, environ)
    if len(command) >= 3 and command[:2] == ["python", "-m"]:
        if command[2] == "pcfl.cloud_coordinator":
            command[2] = "pcfl.robust_cloud_coordinator"
        elif command[2] == "pcfl.service_runtime":
            command[2] = "pcfl.robust_service_runtime"
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("client", "coordinator", "governance", "evaluation", "opa", "operator"))
    args = parser.parse_args()
    path = Path("/app/containers/entrypoint.py")
    spec = importlib.util.spec_from_file_location("frozen_pcfl_entrypoint", path)
    frozen = importlib.util.module_from_spec(spec); spec.loader.exec_module(frozen)
    command = build_command(args.role, os.environ, frozen)
    os.execvpe(command[0], command, os.environ)


if __name__ == "__main__":
    main()
