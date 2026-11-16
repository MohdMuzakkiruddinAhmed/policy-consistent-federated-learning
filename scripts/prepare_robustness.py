"""Prepare future exploratory actor inputs from metadata only; never calls AWS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

STAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STAGE / "src"))
from pcfl.robustness import adapter_source_digest, deployment_inputs, register
from pcfl.robust_host import public_documents


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accepted-main-plan", type=Path, required=True)
    parser.add_argument("--base-data-manifest", type=Path, required=True)
    parser.add_argument("--alpha1-data-manifest", type=Path, required=True)
    parser.add_argument("--data-preparation-report", type=Path, required=True)
    parser.add_argument("--model-metadata", type=Path, required=True)
    parser.add_argument("--public-runtime-template", type=Path, required=True)
    parser.add_argument("--adapter-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    paths = {name: getattr(args, name) for name in ("accepted_main_plan", "base_data_manifest", "alpha1_data_manifest",
        "data_preparation_report", "model_metadata", "public_runtime_template")}
    values = {name: json.loads(path.read_bytes()) for name, path in paths.items()}
    registry = register(values["accepted_main_plan"], values["base_data_manifest"], values["alpha1_data_manifest"],
        values["data_preparation_report"], values["model_metadata"], adapter_source_sha256=adapter_source_digest(), adapter_image=args.adapter_image)
    deployments = deployment_inputs(registry, values["public_runtime_template"])
    args.output.mkdir(parents=True, exist_ok=False)
    write(args.output / "registry.json", registry)
    for group in deployments["groups"]:
        directory = args.output / group["group_id"]
        write(directory / "cases.json", {"plan_digest": registry["registry_digest"], "cases": group["cases"]})
        write(directory / "policy-campaign.json", group["policy_campaign"])
        write(directory / "actor-overrides.json", {key: group[key] for key in ("group_id", "distribution", "partition_hashes", "evaluation_override")})
        write(directory / "group.json", group)
        documents = public_documents(registry, group)
        for kind in ("campaign", "policy", "model"):
            write(directory / (kind + ".json"), documents[kind])
        write(directory / "public-upload-spec.json", {"application_campaign_id": documents["application_campaign_id"],
            "uploads": [{"kind": kind, "source_path": str((directory / (kind + ".json")).resolve()),
                "key": documents[kind + "_key"], "sha256": hashlib.sha256((directory / (kind + ".json")).read_bytes()).hexdigest()}
                for kind in ("campaign", "policy", "model")], "AWS_calls": False})
    write(args.output / "preparation.json", {"schema_version": "0.1.0", "kind": "exploratory-input-preparation",
        "source_inputs_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()},
        "registry_digest": registry["registry_digest"], "cases_prepared": len(registry["cases"]),
        "excluded_preparation_attempts": len(registry["excluded_preparation_attempts"]), "deployment_groups": len(deployments["groups"]),
        "clinical_execution_performed": False, "dataset_rows_read": False, "AWS_calls": False,
        "final_holdout_accessed": False, "execution_authorized": False})
    print(json.dumps({"cases_prepared": len(registry["cases"]), "deployment_groups": len(deployments["groups"]), "actual_cloud_trials": 0}))


if __name__ == "__main__":
    main()
