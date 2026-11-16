"""Issue a separate operator record only for accepted, prepared registered runs."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcfl.experiments import digest, file_digest, validate_plan
from pcfl.holdout import validate_authorization


def authorization_for(plan, campaign, *, model_schema_hash, user_authorization):
    validate_plan(plan)
    if (user_authorization.get("source") != "explicit-user-instruction"
            or user_authorization.get("instruction") != "OK please work and finish all the phases"):
        raise ValueError("recorded_research_execution_instruction_required")
    if plan["status"] != "accepted_frozen" or campaign.get("plan_digest") != plan["plan_digest"]:
        raise ValueError("accepted_plan_and_prepared_campaign_required")
    cells = {cell["cell_id"]: cell for family in ("primary_cells", "targeted_cells", "ablation_cells", "replication_cells") for cell in plan[family]}
    runs = {}
    for case in campaign["cases"]:
        cell_id = case["cell_id"]
        runtime = case["runtime"]
        cell = cells.get(cell_id)
        if (not cell or cell["family"] == "ablation" or cell.get("unsafe_comparator")
                or runtime.get("plan_digest") != plan["plan_digest"] or runtime.get("cell_id") != cell_id
                or runtime.get("equivalence_hash") != cell["equivalence_hash"]
                or runtime.get("training") != plan["training_candidate"]
                or runtime.get("rounds") != plan["training_candidate"]["num_rounds"]
                or runtime.get("max_examples_per_client") != plan["training_candidate"]["max_examples_per_client"]
                or runtime.get("validation_max_examples") != plan["training_candidate"]["max_validation_examples"]
                or runtime.get("baseline_id") != cell["baseline_id"]
                or runtime.get("scenario_id") != cell["scenario_id"]
                or runtime.get("scenario_target_org") != cell["shared_config"]["policy_schedule"]["target_org"]
                or runtime.get("scenario_control") is not True
                or runtime.get("authority_backend") != ("dynamodb-s3-opa" if cell["baseline_id"] == "P1" else "dynamodb-s3-comparator")
                or runtime.get("seed") != cell["seed"] or runtime.get("distribution") != cell["distribution"]
                or runtime.get("model_metadata", {}).get("model_schema_hash") != model_schema_hash):
            raise ValueError("prepared_registered_final_holdout_scope_mismatch")
        run_id = runtime["persistent_run_id"]
        if run_id in runs or cell_id in runs.values():
            raise ValueError("duplicate_authorized_run_or_cell")
        runs[run_id] = cell_id
    if not runs:
        raise ValueError("explicit_registered_runs_required")
    test_hashes = {cells[cell]["shared_config"]["test_holdout_sha256"] for cell in runs.values()}
    if len(test_hashes) != 1:
        raise ValueError("single_frozen_test_digest_required")
    value = {"schema_version": "0.1.0", "kind": "pcfl-final-holdout-authorization",
        "authorization_id": "holdout-" + hashlib.sha256(campaign["campaign_id"].encode()).hexdigest()[:24],
        "status": "authorized", "scope": "final-committed-model-only", "issued_by": "codex-project-operator",
        "issued_at_utc": datetime.now(timezone.utc).isoformat(), "plan_digest": plan["plan_digest"],
        "test_sha256": next(iter(test_hashes)), "model_schema_hash": model_schema_hash, "runs": runs}
    value["authorization_digest"] = digest(value)
    validate_authorization(plan, value, model_schema_hash=model_schema_hash)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    plan = json.loads(Path(args.plan).read_text())
    campaign = json.loads(Path(args.campaign).read_text())
    user_record = ROOT / "configs/research_execution_authorization.json"
    schema_hashes = {case["runtime"]["model_metadata"]["model_schema_hash"] for case in campaign["cases"]}
    if len(schema_hashes) != 1:
        raise ValueError("one_registered_model_schema_required")
    value = authorization_for(plan, campaign, model_schema_hash=next(iter(schema_hashes)),
                              user_authorization=json.loads(user_record.read_text()))
    if not args.apply:
        print(json.dumps({"authorization_proposed": True, "run_count": len(value["runs"]), "test_rows_opened": False}))
        return
    # Check the frozen scientific source before the operator issues authority.
    for name, expected in plan["provenance"]["source_files_sha256"].items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or file_digest(path) != expected:
            raise ValueError("scientific_source_changed_since_accepted_freeze")
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        previous = json.loads(destination.read_text())
        validate_authorization(plan, previous, model_schema_hash=value["model_schema_hash"])
        if any(previous[key] != value[key] for key in value if key not in {"issued_at_utc", "authorization_digest"}):
            raise ValueError("existing_authorization_differs_use_new_versioned_output")
        value = previous
    else:
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"operator_authorization_recorded": True, "run_count": len(value["runs"]),
        "plan_digest": value["plan_digest"], "authorization_digest": value["authorization_digest"],
        "user_instruction_record_sha256": file_digest(user_record), "test_rows_opened": False}))


if __name__ == "__main__":
    main()
