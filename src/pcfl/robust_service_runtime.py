"""Future exploratory service entry point; frozen service module is unchanged."""
import argparse
import json
import os
from pathlib import Path

from . import service_runtime as frozen
from .governance_service import PolicyWriter, create_policy_server
from .robust_policy import RobustScenarioWatcher


def serve_governance(config):
    reference = config.get("campaign_object")
    if (not isinstance(reference, dict) or not isinstance(reference.get("key"), str)
            or not reference["key"].startswith("policies/") or ".." in reference["key"].split("/")):
        raise ValueError("fixed_exploratory_policy_object_required")
    frozen.validate_pinned_reference(reference, expected_owner=config["storage"]["expected_account_id"])
    ddb, s3 = frozen.sdk_clients(config["storage"])
    path = frozen.fetch_pinned(s3, reference, Path(config.get("runtime_directory", "/runtime")) / "exploratory-policy.json",
        expected_owner=config["storage"]["expected_account_id"])
    writer = PolicyWriter(ddb, config["table_name"])
    watcher = RobustScenarioWatcher(writer, json.loads(Path(path).read_bytes()))
    writer.initialize()
    watcher.start()
    server = create_policy_server(writer, config.get("host", "0.0.0.0"), config.get("port", 8443), **config["tls_files"])
    print(json.dumps({"ready": True, "role": "exploratory-governance", "mutual_tls": True}), flush=True)
    try:
        server.serve_forever(poll_interval=.2)
    finally:
        server.server_close(); watcher.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("governance", "evaluation", "opa", "operator"))
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_bytes())
    if args.role == "operator":
        print(json.dumps(frozen.probe_access(config), allow_nan=False), flush=True)
        return
    if args.role == "evaluation" and (config.get("dataset_role", "validation") != "validation"
            or any(name in config for name in ("accepted_plan_object", "authorization_object", "test_object"))):
        raise ValueError("exploratory_actor_is_validation_only")
    config = frozen.materialize_tls(config, Path(config.get("runtime_directory", "/runtime")) / "service-tls")
    if args.role == "governance":
        serve_governance(config)
    elif args.role == "evaluation":
        frozen.serve_evaluation(config)
    else:
        command = frozen.opa_command(config)
        os.execvp(command[0], command)


if __name__ == "__main__":
    main()
