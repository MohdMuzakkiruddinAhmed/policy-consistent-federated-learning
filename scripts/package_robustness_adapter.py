"""Prepare an additive exploratory image manifest; never build, push or deploy."""
import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcfl.contracts import digest
from pcfl.experiments import file_digest, validate_plan
from pcfl.robustness import ADAPTER_MODULES


def owned_source(root, name):
    path = root / name
    if Path(name).is_absolute() or ".." in Path(name).parts or not path.resolve().is_relative_to(root):
        raise ValueError("owned_adapter_source_required")
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("linked_adapter_source_forbidden")
        if part == root:
            break
    if not path.is_file():
        raise ValueError("adapter_source_file_required")
    return path


def package(plan, frozen_image, *, source_root=ROOT):
    validate_plan(plan)
    if plan["status"] != "accepted_frozen":
        raise ValueError("accepted_main_plan_required")
    if (not isinstance(frozen_image, str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", frozen_image)
            or frozen_image.rsplit("@", 1)[1] != plan["provenance"]["image_digests"]["runtime"].rsplit("@", 1)[1]):
        raise ValueError("immutable_accepted_main_image_digest_required")
    root = Path(source_root).resolve()
    expected = plan["provenance"]["source_files_sha256"]
    names = ["src/pcfl/" + name for name in ADAPTER_MODULES]
    names += ["containers/robustness/entrypoint.py"]
    if (digest(expected) != plan["provenance"]["source_sha256"]
            or any(name not in expected for name in names)):
        raise ValueError("adapter_must_be_in_preaccepted_source_inventory")
    for name, sha in expected.items():
        if file_digest(owned_source(root, name)) != sha:
            raise ValueError("frozen_adapter_or_base_source_changed")
    files = {name: file_digest(owned_source(root, name)) for name in
             [*names, "containers/robustness/Dockerfile"]}
    return {"schema_version": "0.1.0", "kind": "additive-exploratory-adapter-manifest",
        "accepted_main_plan_digest": plan["plan_digest"], "frozen_main_image": frozen_image,
        "accepted_source_sha256": plan["provenance"]["source_sha256"],
        "adapter_source_sha256": digest({name: files["src/pcfl/" + name] for name in ADAPTER_MODULES}),
        "new_files_sha256": files,
        "unchanged_frozen_files_sha256": {name: sha for name, sha in expected.items()
            if (name.startswith("src/pcfl/") and name not in names) or name.startswith("policies/rego/")
            or name == "containers/entrypoint.py"},
        "image_built": False, "registry_pushed": False, "AWS_calls": False,
        "clinical_execution_performed": False, "final_holdout_accessed": False,
        "main_source_changed": False, "execution_authorized": False,
        "activation_requires": ["main_P9_and_targeted_ablation_P10_complete", "actual_adapter_source_image_role_and_service_probes",
            "separate_operator_scoped_deployment_and_cost_authorization", "validation_only_exploratory_registry_and_bound_upload_versions"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accepted-main-plan", required=True, type=Path)
    parser.add_argument("--frozen-image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = package(json.loads(args.accepted_main_plan.read_bytes()), args.frozen_image)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"adapter_source_sha256": report["adapter_source_sha256"], "image_built": False, "execution_authorized": False}))


if __name__ == "__main__":
    main()
