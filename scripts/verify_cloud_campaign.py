"""Independently verify exact cloud exports through a scoped local-byte cache."""

import argparse
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcfl import runtime_verify
from cloud_assessment import verify_retained_witness


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@contextmanager
def scoped_artifact_cache(case_directory):
    """Adapt paths on a copy; original manifests and their hashes never change."""
    directory = Path(case_directory).resolve()
    mapping = json.loads((directory / "artifact_paths.json").read_text(encoding="utf-8"))
    if (not isinstance(mapping, dict) or any(not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key)
            or not isinstance(value, str) for key, value in mapping.items())):
        raise ValueError("invalid_case_artifact_cache")
    original_loader = runtime_verify._load_artifact
    def load(record, requested_directory):
        if Path(requested_directory).resolve() != directory:
            raise ValueError("cache_used_outside_its_case")
        value = deepcopy(record)
        expected = value.get("sha256") if value.get("backend") == "s3" else value.get("file_sha256")
        if expected not in mapping:
            raise ValueError("exact_retained_artifact_missing")
        destination = Path(mapping[expected])
        if not destination.is_absolute():
            destination = directory / destination
        destination = destination.resolve()
        if not destination.is_relative_to(directory) or destination.suffix != ".npz" or destination.is_symlink():
            raise ValueError("cache_artifact_outside_case")
        if file_sha(destination) != expected:
            raise ValueError("cache_artifact_byte_digest_mismatch")
        if value.get("backend") == "s3":
            value["local_export"] = {"path": str(destination), "file_sha256": expected, "model_digest": value["model_digest"]}
        else:
            value["path"] = str(destination)
        return original_loader(value, directory)
    try:
        from pcfl import ablation_verify
    except ImportError:
        ablation_verify = None  # Historical frozen images predate this verifier.
    from contextlib import ExitStack
    with ExitStack() as patches:
        patches.enter_context(patch.object(runtime_verify, "_load_artifact", load))
        if ablation_verify is not None:
            patches.enter_context(patch.object(ablation_verify, "_load_artifact", load))
        yield


def verify_export(inventory_path, *, expect_test_authorization=None, witness_public_key=None, witness_public_key_sha256=None):
    if (witness_public_key is None) != (witness_public_key_sha256 is None):
        raise ValueError("external_operator_public_key_and_pin_required_together")
    inventory_path = Path(inventory_path).resolve()
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    directory = Path(inventory["export"].get("export_root", inventory_path.parent / "r")).resolve()
    if not directory.is_relative_to(inventory_path.parent):
        raise ValueError("export_root_outside_owned_inventory")
    application = inventory["export"].get("application_campaign_id", inventory["campaign_id"])
    if (inventory.get("application_campaign_id", application) != application
            or inventory["export"].get("index_key") != f"evidence/campaigns/{application}/campaign_result.json"
            or inventory["export"].get("index_version_id") in {None, "", "null"}):
        raise ValueError("exact_application_index_key_and_version_required")
    index_path = directory / "campaign_result.json"
    if file_sha(index_path) != inventory["export"]["index_sha256"]:
        raise ValueError("retained_campaign_index_changed")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if index.get("campaign_id") != application:
        raise ValueError("campaign_export_identity_mismatch")
    summaries, failures, partial, seen, unprotected = [], [], [], set(), []
    for case in index["cases"]:
        cell_id = case["cell_id"]
        if cell_id in seen:
            raise ValueError("duplicate_exported_cell_identity")
        seen.add(cell_id)
        case_directory = directory / hashlib.sha256(cell_id.encode()).hexdigest()[:8]
        marker = json.loads((case_directory / "cell.json").read_text())
        if marker != {"cell_id": cell_id}:
            raise ValueError("retained_case_directory_binding_mismatch")
        path = case_directory / "runtime_result.json"
        expected_key = f"evidence/campaigns/{application}/{cell_id}/runtime_result.json"
        references = [reference for reference in case["artifacts"] if reference["key"] == expected_key]
        if (len(references) != 1 or references[0]["bucket"] != inventory["foundation"]["bucket_name"]
                or not references[0].get("version_id") or references[0]["version_id"] == "null"
                or file_sha(path) != references[0]["sha256"] or path.stat().st_size != references[0]["size_bytes"]):
            raise ValueError("exact_runtime_result_version_digest_mismatch")
        evidence = json.loads(path.read_text(encoding="utf-8"))
        is_partial = "ablation_id" in evidence or evidence.get("full_protocol", True) is not True or evidence.get("successful") is not True
        witness, public, protection = None, None, {"protected_witness_verified": False}
        if witness_public_key is not None:
            witness, public, protection = verify_retained_witness(inventory, application=application, cell_id=cell_id,
                raw_path=path, public_key_path=witness_public_key, public_key_pin=witness_public_key_sha256)
        else:
            unprotected.append(cell_id)
        if is_partial and witness_public_key is not None:
            from pcfl.ablation_verify import assess_case
            with scoped_artifact_cache(case_directory):
                assessment = assess_case(path, witness=witness, public_key_pem=public, expected_public_key_sha256=witness_public_key_sha256)
            partial.append({"cell_id": cell_id, "raw_result_sha256": file_sha(path), "summary": assessment,
                            "execution_successful": evidence.get("successful") is True, "protected_operator_witness": protection})
        if evidence.get("successful") is not True or case.get("successful") is not True:
            failures.append({"cell_id": cell_id, "reason": evidence.get("reason", evidence.get("error", "case_failed"))})
            continue
        if is_partial:
            continue
        before = file_sha(path)
        with scoped_artifact_cache(case_directory):
            summary = (runtime_verify.verify_case(path, expect_test_authorization=expect_test_authorization)
                       if expect_test_authorization is not None else runtime_verify.verify_case(path))
        if file_sha(path) != before:
            raise ValueError("verifier_modified_original_evidence")
        summaries.append({"cell_id": cell_id, "raw_result_sha256": before, "summary": summary,
                          "protected_operator_witness": protection})
    task_rows = inventory.get("observed_tasks", [])
    registry = inventory.get("runtime_contract", {}).get("task_definition_arns", {})
    clients = [task for task in task_rows if task.get("task_definition_arn") in {registry.get(f"org_{i:02d}") for i in range(1, 9)}]
    unique_clients = {task["task_definition_arn"]: task for task in clients}
    placement = (len(unique_clients) == 8 and len({row["task_arn"] for row in unique_clients.values()}) == 8
        and len({row["private_ip"] for row in unique_clients.values()}) == 8
        and all(row["private_ip"] for row in unique_clients.values())
        and len({row.get("task_role_arn") for row in unique_clients.values()}) == 8)
    return {"schema_version": "0.1.0", "kind": "independent-cloud-campaign-export-validation",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(), "campaign_id": inventory["campaign_id"],
        "application_campaign_id": application,
        "account_id": inventory["account_id"], "region": inventory["region"],
        "successful": index.get("successful") is True and bool(summaries) and not failures and not partial and not unprotected,
        "verified_cases": summaries, "failed_cases": failures, "partial_assessments": partial,
        "eight_distinct_client_task_identity_records": placement,
        "externally_protected_witnesses_verified": not unprotected,
        "unprotected_case_ids": unprotected,
        "original_result_bytes_preserved": True, "test_holdout_evaluated": any(row["summary"].get("evaluation_split") == "test" for row in summaries),
        "limitations": ["Placement rows alone do not demonstrate all IAM/TLS/availability gates",
                        "Access probes, protected anchors, replication and measured costs require separate evidence"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--output", default="reports/cloud_campaign_validation.json")
    parser.add_argument("--accepted-plan")
    parser.add_argument("--holdout-authorization")
    parser.add_argument("--witness-public-key")
    parser.add_argument("--witness-public-key-sha256")
    args = parser.parse_args()
    if bool(args.accepted_plan) != bool(args.holdout_authorization):
        raise ValueError("both_external_accepted_plan_and_authorization_required")
    expectation = ({"accepted_plan": json.loads(Path(args.accepted_plan).read_text()),
                    "authorization": json.loads(Path(args.holdout_authorization).read_text())} if args.accepted_plan else None)
    report = verify_export(args.inventory, expect_test_authorization=expectation,
        witness_public_key=args.witness_public_key, witness_public_key_sha256=args.witness_public_key_sha256)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"successful": report["successful"], "verified_cases": len(report["verified_cases"]),
                      "failed_cases": len(report["failed_cases"]), "partial_assessments": len(report["partial_assessments"])}, indent=2))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
