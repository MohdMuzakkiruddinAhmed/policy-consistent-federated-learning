"""Join actual, hash-bound phase evidence; no source, network or AWS mutations.

The operator reviews which report leaf supports each named criterion. Pass/status
booleans cannot be supplied: all statuses are derived from retained report data.
"""
import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcfl.analysis import analyze_registry
from pcfl.experiments import canonical, digest, file_digest, load_attempts

PHASES = {
    "P0": ("scope_ethics", "no_human_collection", "cost_controls"),
    "P1": ("requirements_invariants", "literature_scope", "independent_oracle_spec"),
    "P2": ("data_integrity", "patient_disjointness", "frozen_preprocessing_and_holdout"),
    "P3": ("protocol_contracts", "atomic_transactions", "authenticated_architecture"),
    "P4": ("actual_distribution", "isolation_and_tls", "independent_restart"),
    "P5": ("baseline_equivalence", "full_partition_training", "frozen_training_protocol"),
    "P6": ("native_opa_oracle", "continuous_interval", "atomic_policy_mutation"),
    "P7": ("guarded_publication", "complete_audit", "fail_closed_recovery"),
    "P8": ("locked_paired_matrix", "accepted_pilots", "automated_attempt_accounting"),
    "P9": ("repeated_primary_trials", "statistical_analysis", "traceable_claims"),
    "P10": ("ablations", "robustness_and_faults", "tamper_validation"),
    "P11": ("fresh_replication", "frozen_analysis", "limitations"),
    "P12": ("reproducibility", "manuscript", "teardown"),
}
GATES = {
    "G1": ("actual_tasks", "actual_network_authentication", "actual_iam_denials", "restart_proof"),
    "G2": ("oracle_parity", "revoke_regrant", "versioned_histories"),
    "G3": ("guarded_commit", "negative_races", "membership_reconstruction"),
    "G4": ("all_four_methods", "matched_configurations", "repeated_matrix"),
    "G5": ("final_outcomes_audited", "protected_anchors", "tamper_checker"),
    "G6": ("seed_intervals", "ablation_robustness", "replication", "reproducibility_limitations"),
}
TEARDOWN_CHECKS = {"no_active_owned_tasks", "no_owned_ecs_services", "no_owned_interface_endpoints",
                   "no_owned_runtime_vpc", "foundation_removed", "all_recorded_evidence_retained", "all_recorded_stacks_destroyed"}
ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError)


def scoped_file(root, value):
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("relative_owned_evidence_path_required")
    path = root / path
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("owned_regular_evidence_file_required")
    return path


def read_bound(root, spec):
    if not isinstance(spec, dict) or set(spec) != {"path", "sha256"} or not re.fullmatch(r"[0-9a-f]{64}", spec["sha256"]):
        raise ValueError("strict_hash_bound_evidence_required")
    path = scoped_file(root, spec["path"])
    if file_digest(path) != spec["sha256"]:
        raise ValueError("evidence_digest_changed")
    return json.loads(path.read_text(encoding="utf-8"))


def pointer(document, value):
    if not isinstance(value, str) or not value.startswith("/") or re.search(r"~(?![01])", value):
        raise ValueError("explicit_json_pointer_required")
    result = document
    for token in value[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(result, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token):
                raise ValueError("canonical_array_index_required")
            result = result[int(token)]
        else:
            result = result[token]
    return result


def accurate_scope(scope):
    return (scope.get("source") == "user-statement-in-project-conversation"
        and scope.get("project_type") == "independent-computational-research"
        and scope.get("institutional_determination_required_per_user") is False
        and scope.get("institutional_determination_issued") is False and scope.get("irb_approval_claimed") is False
        and scope.get("human_participant_data_collection") is False
        and set(scope.get("inputs", [])) == {"public-secondary-UCI-296", "synthetic-policies-and-organizations"})


def _finalize(recipe, plan, attempts, *, root=ROOT):
    root, errors, reports = Path(root), [], {}
    required = {"schema_version", "kind", "artifact_version", "plan_digest", "reports", "phases", "gates", "teardown", "research_scope", "qualifications"}
    schema_ok = (isinstance(recipe, dict) and set(recipe) == required and recipe.get("schema_version") == "0.1.0"
        and recipe.get("kind") == "research-phase-evidence-map" and recipe.get("plan_digest") == plan["plan_digest"]
        and isinstance(recipe.get("artifact_version"), str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", recipe["artifact_version"]) is not None)
    if not schema_ok:
        errors.append("strict_phase_evidence_map_schema_or_plan_mismatch")
    recipe = recipe if isinstance(recipe, dict) else {}
    source_ok = True
    for name, sha in plan["provenance"]["source_files_sha256"].items():
        try:
            if file_digest(scoped_file(root, name)) != sha:
                raise ValueError("frozen_source_changed")
        except ERRORS:
            source_ok = False
    report_specs = recipe.get("reports", {})
    if not isinstance(report_specs, dict):
        errors.append("report_map_object_required")
        report_specs = {}
    for name, spec in report_specs.items():
        try:
            report = read_bound(root, spec)
            if not isinstance(report, dict):
                raise ValueError("json_report_object_required")
            hashes = [report.get("source_sha256"), report.get("source_files_sha256"),
                report.get("verification", {}).get("source_manifest", {}).get("files_sha256")]
            for mapping in hashes:
                if isinstance(mapping, dict):
                    for path, sha in mapping.items():
                        if file_digest(scoped_file(root, path)) != sha:
                            raise ValueError("report_recorded_source_changed")
                        if path in plan["provenance"]["source_files_sha256"] and plan["provenance"]["source_files_sha256"][path] != sha:
                            raise ValueError("report_source_not_frozen_plan_source")
            reports[name] = report
        except ERRORS as error:
            errors.append("report:" + name + ":" + str(error))

    def checklist(section, specifications):
        supplied, result = recipe.get(section, {}), {}
        if not isinstance(supplied, dict) or set(supplied) != set(specifications):
            errors.append("exact_" + section + "_ids_required")
            supplied = supplied if isinstance(supplied, dict) else {}
        for group, names in specifications.items():
            given, checks = supplied.get(group, {}), {}
            if not isinstance(given, dict) or set(given) != set(names):
                errors.append("exact_named_criteria_required:" + group)
                given = given if isinstance(given, dict) else {}
            for criterion in names:
                spec, passed, observed = given.get(criterion), False, None
                try:
                    if not isinstance(spec, dict) or set(spec) != {"report", "pointer", "expected"} or type(spec["expected"]) is not bool:
                        raise ValueError("report_leaf_predicate_required")
                    observed = pointer(reports[spec["report"]], spec["pointer"])
                    passed = type(observed) is bool and observed is spec["expected"]
                except ERRORS:
                    pass
                checks[criterion] = {"passed": passed, "observed": observed if type(observed) is bool else None, "reference": spec}
            result[group] = {"status": "passed" if all(row["passed"] for row in checks.values()) else "incomplete", "checks": checks}
        return result

    phases, gates = checklist("phases", PHASES), checklist("gates", GATES)
    analysis = analyze_registry(plan, attempts)
    analysis_ok = (analysis["primary_matrix_complete"] is True and analysis["confirmatory_verdict_permitted"] is True
        and all(analysis["hypotheses"][name]["verdict"] in {"supported", "not supported"} for name in ("H1", "H2", "H4"))
        and all(row["unattempted"] == 0 for row in analysis["coverage"].values())
        and bool(analysis["tables"]["replications"]) and all(row["fresh_deployment_metadata_verified"] is True for row in analysis["tables"]["replications"]))
    scope_ok = False
    try:
        scope_ok = accurate_scope(read_bound(root, recipe["research_scope"]))
    except ERRORS:
        pass
    qualifications = {}
    qualification_specs = recipe.get("qualifications", {})
    if not isinstance(qualification_specs, dict):
        qualification_specs = {}
        errors.append("qualification_map_object_required")
    for code, alias in qualification_specs.items():
        report, valid = reports.get(alias, {}), False
        if code == "abstract-only-related-work":
            valid = (report.get("kind") == "user-provided-literature-abstract-provenance" and report.get("available_content") == "abstract-only"
                and report.get("full_text_read") is False and report.get("retrieval_status") == "stopped-per-user-confirmed-abstract-only-boundary"
                and bool(report.get("unknown_from_available_abstract")))
        elif code == "bounded-data-preparation-failure":
            failures = [row for row in report.get("attempts", []) if row.get("alpha") == .1]
            valid = (report.get("kind") == "non-iid-sensitivity-data-preparation" and len(failures) == 1 and failures[0].get("status") == "failed"
                and failures[0].get("clinical_training_executed") is False and failures[0].get("constraints_weakened") is False
                and failures[0].get("retry_limit") == 200 and failures[0].get("minimum_patient_groups") == 100
                and failures[0].get("minimum_positive_encounters") == 25)
        qualifications[code] = {"verified": valid, "report": alias}
        if not valid:
            errors.append("unverified_qualification:" + code)
    if qualifications.get("abstract-only-related-work", {}).get("verified"):
        if phases["P1"]["status"] == "passed": phases["P1"]["status"] = "qualified"
    if analysis["hypotheses"]["H3"]["verdict"] == "inconclusive":
        qualifications["H3-inconclusive"] = {"verified": True, "basis": "recomputed_aggregate_analysis", "claim": "H3 remains inconclusive; no support claimed"}
        for phase in ("P9", "P11", "P12"):
            if phases[phase]["status"] == "passed": phases[phase]["status"] = "qualified"
    if qualifications.get("bounded-data-preparation-failure", {}).get("verified"):
        for phase in ("P10", "P11", "P12"):
            if phases[phase]["status"] == "passed": phases[phase]["status"] = "qualified"
    teardown_ok, campaigns = True, set()
    try:
        teardown = recipe["teardown"]
        if set(teardown) != {"inventories", "readbacks", "budget_ledger", "authorization"} or not teardown["inventories"] or len(teardown["inventories"]) != len(teardown["readbacks"]):
            raise ValueError("paired_final_teardown_evidence_required")
        ledger, authorization = read_bound(root, teardown["budget_ledger"]), read_bound(root, teardown["authorization"])
        if (ledger.get("authorization_sha256") != teardown["authorization"]["sha256"] or authorization.get("approved") is not True
                or authorization.get("authorization_scope") != "remaining-phases-cloud-campaign-including-replication"
                or not ledger.get("deployments") or any(not row.get("finished_at") for row in ledger["deployments"].values())):
            raise ValueError("all_approved_deployment_clocks_must_be_closed")
        if authorization.get("kind") == "campaign-authorization-amendment":
            from campaign_budget import validate_ledger_lineage
            historical_inventories = [read_bound(root, spec) for spec in teardown["inventories"]]
            validate_ledger_lineage({"authorization": teardown["authorization"],
                "account_id": authorization["account_id"], "region": authorization["region"]},
                ledger, root=root, campaign_inventories={item["campaign_id"]: item for item in historical_inventories})
        needed_campaigns = {row["campaign_id"] for row in ledger["deployments"].values()} | {
            row["campaign_id"] for row in ledger.get("tasks", {}).values()}
        for inventory_spec, readback_spec in zip(teardown["inventories"], teardown["readbacks"]):
            inv, readback = read_bound(root, inventory_spec), read_bound(root, readback_spec)
            campaign = inv["campaign_id"]
            if (campaign in campaigns or inv.get("teardown_complete") is not True
                    or readback.get("kind") != "actual-aws-campaign-teardown-validation" or readback.get("successful") is not True
                    or readback.get("performed_read_only") is not True or readback.get("inventory_sha256") != inventory_spec["sha256"]
                    or any(readback.get(key) != inv.get(key) for key in ("account_id", "region", "project_id", "campaign_id"))
                    or inv.get("account_id") != authorization.get("account_id") or inv.get("region") != authorization.get("region")
                    or set(readback.get("checks", {})) != TEARDOWN_CHECKS or any(readback["checks"][key] is not True for key in TEARDOWN_CHECKS)):
                raise ValueError("actual_final_teardown_not_verified")
            campaigns.add(campaign)
            if not inv.get("state_paths"):
                raise ValueError("owned_stack_states_required")
            originals = inv.get("pre_teardown_state_snapshots", {})
            if set(originals) != {"foundation", "runtime"}:
                raise ValueError("full_pre_teardown_state_snapshots_required")
            for original in originals.values():
                path = Path(original["path"])
                if not path.is_absolute(): path = root / path
                if (not path.resolve().is_relative_to(root.resolve()) or path.is_symlink() or file_digest(path) != original["sha256"]
                        or not json.loads(path.read_text(encoding="utf-8")).get("resources")):
                    raise ValueError("original_stack_inventory_missing_or_changed")
            for name in inv["state_paths"].values():
                state_path = Path(name)
                if not state_path.is_absolute(): state_path = root / state_path
                if not state_path.resolve().is_relative_to(root.resolve()) or json.loads(state_path.read_text(encoding="utf-8")).get("resources"):
                    raise ValueError("recorded_stack_not_empty_after_destroy")
            for artifact in inv.get("retained_artifact_versions", []):
                retained = Path(artifact["local_path"])
                if not retained.is_absolute(): retained = root / retained
                if not retained.resolve().is_relative_to(root.resolve()) or retained.is_symlink() or file_digest(retained) != artifact["sha256"]:
                    raise ValueError("retained_private_evidence_missing_or_changed")
        if {row["execution"]["deployment_id"] for row in attempts} - campaigns:
            raise ValueError("attempted_deployment_missing_teardown")
        if campaigns != needed_campaigns:
            raise ValueError("every_budget_recorded_campaign_requires_final_teardown")
    except ERRORS as error:
        teardown_ok = False
        errors.append("teardown:" + str(error))
    checks = {"strict_schema": schema_ok, "frozen_source_current": source_ok, "scope_record_accurate": scope_ok,
        "all_phase_criteria": all(row["status"] in {"passed", "qualified"} for row in phases.values()),
        "all_gate_criteria": all(row["status"] == "passed" for row in gates.values()), "analysis_and_attempt_coverage": analysis_ok,
        "abstract_boundary_disclosed": qualifications.get("abstract-only-related-work", {}).get("verified") is True,
        "final_aws_teardown_verified": teardown_ok, "every_requested_report_valid": not errors}
    return {"schema_version": "0.1.0", "kind": "research-phase-finalization-evidence", "artifact_version": recipe.get("artifact_version"),
        "plan_digest": plan["plan_digest"], "attempts_digest": digest(attempts), "source_sha256": plan["provenance"]["source_sha256"],
        "analysis_digest": digest(analysis), "recipe": recipe, "phases": phases, "gates": gates, "qualifications": qualifications,
        "checks": checks, "errors": errors, "all_phases_complete": all(checks.values()),
        "limitations": ["The operator reviews the semantic adequacy of each actual report-to-criterion mapping",
            "Qualified completion preserves disclosed limitations and inconclusive hypotheses; it does not assert hypothesis support",
            "Private artifacts are hashed for retention checks and are excluded from the public reproduction bundle"]}


def finalize(recipe, plan, attempts, *, root=ROOT):
    try:
        return _finalize(recipe, plan, attempts, root=root)
    except ERRORS as error:
        # Malformed/missing leaves must produce an incomplete result, including
        # malformed optional qualification or teardown documents.
        return {"schema_version": "0.1.0", "kind": "research-phase-finalization-evidence",
            "artifact_version": recipe.get("artifact_version") if isinstance(recipe, dict) else None,
            "plan_digest": plan.get("plan_digest"), "attempts_digest": digest(attempts), "recipe": recipe,
            "checks": {"well_formed_evidence": False}, "phases": {}, "gates": {}, "qualifications": {},
            "errors": ["malformed_evidence:" + type(error).__name__], "all_phases_complete": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--attempts", required=True, type=Path)
    parser.add_argument("--evidence-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    result = finalize(json.loads(args.evidence_map.read_text(encoding="utf-8")), plan, load_attempts(args.attempts, plan))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical(result) + b"\n")
    print(json.dumps({"all_phases_complete": result["all_phases_complete"], "checks": result["checks"]}, sort_keys=True))
    return 0 if result["all_phases_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
