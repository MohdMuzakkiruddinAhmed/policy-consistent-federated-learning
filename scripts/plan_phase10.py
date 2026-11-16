"""Register future P10 trials without executing AWS, FL, or a clinical holdout."""

import argparse
import hashlib
import json
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
ROOT = SOURCE if (SOURCE / "pyproject.toml").is_file() else SOURCE.parents[2]
STAGE = SOURCE if SOURCE != ROOT else ROOT / "results/development/phase10"


def make_plan(registry):
    groups = {}
    for family, expected in (("ablation_cells", 40), ("targeted_cells", 50)):
        cells = registry[family]
        if len(cells) != expected:
            raise ValueError("complete_reference_registry_required")
        groups[family] = [{"registry_cell_id": cell["cell_id"], "registry_equivalence_hash": cell["equivalence_hash"],
            "ablation_id": cell["variant"], "distribution": cell["distribution"], "scenario_id": cell["scenario_id"], "seed": cell["seed"],
            "unsafe_comparator": cell["unsafe_comparator"],
            "status": "not_run", "evaluation_split": "validation", "final_test_access_permitted": False,
            "requires": ["P9_primary_complete", "P10_versioned_source_and_config", "approved_actual_trial_cost", "independent_audit_model_oracle_checks"]}
            for cell in cells]
    config = json.loads((SOURCE / "configs/phase10.json").read_text())
    if config["final_test_access_permitted"] is not False or config["preserve_global_policy_sequence_CAS"] is not True:
        raise ValueError("safe_phase10_preparation_scope_required")
    factors, defaults = config["factors"], config["defaults"]
    sensitivity = [{"factor": factor, "value": value, "fixed_other_factors": {k: v for k, v in defaults.items() if k != factor},
                    "status": "registered_not_run", "design": "one-factor-at-a-time", "confirmatory": False,
                    "requires_actual_post_P9_trial": True} for factor, values in factors.items() for value in values]
    distinct = {json.dumps({**item["fixed_other_factors"], item["factor"]: item["value"]}, sort_keys=True) for item in sensitivity}
    return {"schema_version": "0.1.0", "phase": "P10", "reference_registry_plan_digest": registry["plan_digest"],
        "reference_registry_status": registry["status"], "reference_only_not_a_new_accepted_lock": True,
        **groups, "robustness_factors": sensitivity,
        "distinct_robustness_configurations": len(distinct), "default_factor_configuration": defaults,
        "shared_control_policy": "one shared baseline per seed/distribution unless versioned paired controls explicitly scheduled",
        "fault_registry": [{"fault": fault, "status": "registered_not_run", "requires_actual_post_P9_trial": True} for fault in
            ["OPA_timeout", "DDB_transaction_cancel", "stale_token", "S3_staging_failure", "audit_store_failure", "duplicate_reordered_reply",
             "delayed_policy", "coordinator_restart", "external_anchor_tamper"]],
        "actual_AWS_trials_executed": 0, "clinical_FL_trials_executed": 0,
        "local_protocol_tests_do_not_count_as_registry_trials": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=ROOT / "experiments/locked_plan.json")
    parser.add_argument("--output", type=Path, default=STAGE / "plans/phase10_trials.json")
    args = parser.parse_args()
    raw = args.registry.read_bytes()
    result = make_plan(json.loads(raw))
    result["reference_registry_file_sha256"] = hashlib.sha256(raw).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"ablations_registered": 40, "targeted_registered": 50, "robustness_settings_registered": len(result["robustness_factors"]),
                      "actual_trials_run": 0}))


if __name__ == "__main__":
    main()
