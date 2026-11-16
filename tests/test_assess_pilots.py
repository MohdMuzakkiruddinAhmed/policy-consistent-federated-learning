"""Synthetic pilot-gate tests; never train, call AWS or read clinical rows."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from assess_pilots import (ORGS, TAMPER_KINDS, assess_pilots, control_facts, derive_checks,
    full_cloud_case, local_training_facts, permitted_pilot_image, write_assessments)
from pcfl.experiments import GATE_CHECKS, SEEDS, build_plan, digest
from test_experiments import example_plan


def model_fixture():
    template = example_plan()
    sources = {name: digest(name) for name in ("scripts/pilot_training.py", "src/pcfl/learning.py", "src/pcfl/data.py",
        "src/pcfl/contracts.py", "src/pcfl/evaluation.py", "requirements-runtime.lock")}
    artifacts = {f"{distribution}/{org}.csv": digest([distribution, org]) for distribution in ("iid", "non_iid") for org in ORGS}
    artifacts.update({name: digest(name) for name in ("preprocessor.json", "validation.csv", "test.csv")})
    dataset = {"private_artifacts_sha256": artifacts, "source": {"csv_sha256": digest("synthetic-test-only-dataset")},
        "checks": {key: True for key in ("patient_disjoint_splits", "preprocessing_fit_training_only", "test_holdout_frozen")},
        "splits": {"validation": {"encounters": 16}}, "partitions": {distribution: {"organizations": {org: {"encounters": 10 + index} for index, org in enumerate(ORGS)}} for distribution in ("iid", "non_iid")}}
    provenance = {"source_files_sha256": sources, "source_sha256": digest(sources), "git_commit": None,
                  "image_digests": template["provenance"]["image_digests"]}
    training = deepcopy(template["training_candidate"])
    training.update(pilot_only=False, confirmatory_frozen=False)
    plan = build_plan(template["configuration"], training, dataset, provenance)
    report = {"successful": True, "kind": "full-data-local-training-protocol-pilot", "source_sha256": sources,
        "training_configuration": training, "training_config_digest": digest(training), "verified_input_sha256": {key: value for key, value in artifacts.items() if key != "test.csv"},
        "source_dataset_sha256": dataset["source"]["csv_sha256"], "final_test_accessed": False,
        "attempts": [], "planned_attempts": 10, "completed_attempts": 10, "failed_attempts": 0}
    for distribution in ("iid", "non_iid"):
        for seed in SEEDS:
            counts = {org: row["encounters"] for org, row in dataset["partitions"][distribution]["organizations"].items()}
            curves = [{"round": number, "validation_metrics": {"count": 16, "threshold": .5, "auroc": .5 + seed / 100000 + number / 1000,
                "auprc": .2, "f1": .1, "precision": .2, "recall": .2, "prevalence": .2, "loss": .7 - number / 100}}
                for number in range(training["num_rounds"] + 1)]
            report["attempts"].append({"successful": True, "distribution": distribution, "seed": seed,
                "training_counts": counts, "validation_count": 16, "final_test_accessed": False, "is_confirmatory": False,
                "initial_parameters_digest": digest(["initial", seed]), "curves": curves,
                "rounds": [{"round": number, "clients": [{"org_id": org, "sample_count": counts[org], "example_exposures": counts[org],
                    "epochs": 1, "optimizer": "adam", "seed": seed + number * 100 + index, "batches": 1,
                    "loss": .5, "loss_before": .7, "loss_after": .5, "duration_seconds": .1} for index, org in enumerate(ORGS)]}
                    for number in range(1, training["num_rounds"] + 1)]})
    return plan, dataset, report


def raw_control_fixture():
    account, region, campaign = "111111111111", "us-east-1", "synthetic-deployment"
    topic, queue = f"arn:aws:sns:{region}:{account}:synthetic", f"arn:aws:sqs:{region}:{account}:synthetic"
    inventory = {"campaign_id": campaign, "account_id": account, "region": region}
    report = {**inventory, "successful": True, "performed_read_only": True, "cost_alert_billing_delivery_observed": False,
        "checks": {"machine_budget_subscription_confirmed": True, "two_enabled_active_expiry_backstops": True},
        "schedules": [{"schedule_arn": f"schedule-{number}", "function_arn": f"arn:aws:lambda:{region}:{account}:function:cleanup-{number}",
            "target": {"Arn": f"arn:aws:lambda:{region}:{account}:function:cleanup-{number}"},
            "state": "ENABLED", "function_state": "Active", "last_update_status": "Successful", "timezone": "UTC",
            "flexible_time_window": {"Mode": "OFF"}, "expression": "at(2027-01-01T00:00:00)", "function_code_sha256": "synthetic-code"} for number in (1, 2)],
        "machine_alert_evidence": {"queue": {"QueueArn": queue, "SqsManagedSseEnabled": "true"}, "expected_topic_arn": topic,
            "subscribers_query_notification": {"NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN", "Threshold": 80, "ThresholdType": "PERCENTAGE"},
            "notifications": [{"NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN", "Threshold": 80}],
            "subscriptions": [{"Protocol": "sqs", "Endpoint": queue, "TopicArn": topic, "Owner": account, "SubscriptionArn": topic + ":confirmed"}],
            "subscribers": [{"SubscriptionType": "SNS", "Address": topic}]}}
    return inventory, report


def sufficient_facts():
    plan, dataset, report = model_fixture()
    local = local_training_facts(report, dataset, plan)
    services = {"successful": True, "named_checks": {name: True for name in ("native_oracle", "races_and_regrant", "comparators", "duplicate_restart", "fault_recovery", "error_accounting")}}
    container = {"successful": True, "source_current": True, "native_mutual_tls_services": True, "eight_client_containers": True, "cases": [{}] * 8}
    rows = []
    for distribution in ("iid", "non_iid"):
        for scenario in ("S0", "S1", "S2", "S3"):
            for baseline in ("B1", "B2", "B3", "P1"):
                invalid = int(scenario in {"S2", "S3"})
                rows.append({"cell_id": f"synthetic-{distribution}-{scenario}-{baseline}", "baseline": baseline,
                    "distribution": distribution, "scenario": scenario, "seed": 296, "anchored": True, "test_accessed": False,
                    "facts": {"protocol": True, "partitions": True, "full": True, "seed": True, "validation_full": True, "validation_only": True, "resources": True,
                        "shared_digest": digest([distribution, scenario]), "final_model_digest": digest(["stable-final", distribution])},
                    "summary": {"successful": True, "persistent_protocol_verified": True, "model_reconstruction_verified": True, "published_models": 5,
                        "oracle_invalid_presented": invalid, "oracle_invalid_incorporations": invalid if baseline != "P1" else 0,
                        "audit_verified": True, "audit_complete_decisions": 40, "final_decisions": 40,
                        "runtime_observations_verified": True, "revocation_response": {"operation_coverage_complete": True,
                            "measurement_errors": 0, "missing_events": 0, "opportunity_events": int(scenario != "S0"),
                            "status": "no-event" if scenario == "S0" else "right-censored" if baseline == "B1" else "measured"}},
                    "initialization_config_digest": digest("same-constructor-and-seed"), "native_opa_calls": 0 if baseline == "B1" else 8,
                    "policy_trace": [] if scenario == "S0" else [{"kind": "REVOKE", "after_first_commit": scenario == "S1"}],
                    "execution_successful": True})
    placement = {name: True for name in ("simultaneously_running_fargate", "actual_linux_amd64_platform", "eight_distinct_learning_clients",
        "distinct_task_eni_and_private_ip", "actual_role_and_org_binding", "nine_actual_attributable_iam_probes", "actual_private_network_boundary",
        "actual_private_subnets", "no_internal_appio_ports", "actual_image_manifest_relation", "source_snapshot_integrity", "snapshot_matches_current_image", "snapshot_matches_current_application")}
    inventory, controls = raw_control_fixture()
    clouds = [{"rows": rows, "placement_successful": True, "placement": placement, "inventory": inventory,
        "image_reference": plan["provenance"]["image_digests"]["runtime"], "all_case_outcomes_retained": True}]
    faults = [{"ablation_id": None, "scripted_fault": kind, "test_accessed": False,
        "summary": {"audit_complete_for_all_final_outcomes": True, "final_audit_expected_count": 8, "final_audit_recorded_count": 8,
                    "attempt_accounting_complete": True, "indeterminate_count": 0, "final_error_count": 8, "protected_witness_verified": True},
        "fault_trace": [{"phase": "fault_failed_closed", "pointer_unchanged": True, "published_models_during_fault": 0, "recovery_errors": [], "blocked_calls": 1}],
        "protected_tamper_checks": [{"attack_id": name, "detected": True} for name in TAMPER_KINDS]}
        for kind in ("audit_transport_unavailable", "opa_transport_unavailable")]
    costs = {"operator_budget": True, "current_spend_accounted": True, "projected_cost": True}
    return plan, local, services, container, clouds, faults, [controls], costs


class PilotAssessmentTests(unittest.TestCase):
    def test_one_complete_cloud_seed_plus_five_full_local_seeds_is_sufficient(self):
        plan, *parts = sufficient_facts()
        checks, reasons, facts = derive_checks(plan, *parts, global_binding=True, errors=[])
        self.assertEqual(facts["cloud296_observed_cells"], 32)
        self.assertTrue(all(all(group.values()) for group in checks.values()), reasons)
        self.assertEqual(set(checks), set(GATE_CHECKS))

    def test_missing_cloud_cell_unsafe_oracle_mismatch_and_b1_overhead_fail(self):
        for mutation, gate in (("missing", "P8_pilot"), ("unsafe", "baseline_oracle"), ("b1opa", "baseline_oracle")):
            plan, *parts = sufficient_facts()
            rows = parts[3][0]["rows"]
            if mutation == "missing": rows.pop()
            if mutation == "unsafe":
                next(row for row in rows if row["baseline"] == "B2" and row["scenario"] == "S2")["summary"]["oracle_invalid_incorporations"] = 0
            if mutation == "b1opa": rows[0]["native_opa_calls"] = 1
            checks, _, _ = derive_checks(plan, *parts, global_binding=True, errors=[])
            self.assertFalse(all(checks[gate].values()))

    def test_performance_review_requires_all32_complete_verified_observer_traces(self):
        for mode in ("absent", "unverified", "coverage", "error", "missing-event", "wrong-no-event", "zero-opportunity"):
            plan, *parts = sufficient_facts()
            row = next(row for row in parts[3][0]["rows"] if row["scenario"] == "S2")
            response = row["summary"]["revocation_response"]
            if mode == "absent": del row["summary"]["revocation_response"]
            if mode == "unverified": row["summary"]["runtime_observations_verified"] = False
            if mode == "coverage": response["operation_coverage_complete"] = False
            if mode == "error": response["measurement_errors"] = 1
            if mode == "missing-event": response["missing_events"] = 1
            if mode == "wrong-no-event": response["status"] = "no-event"
            if mode == "zero-opportunity": response["opportunity_events"] = 0
            checks, _, facts = derive_checks(plan, *parts, global_binding=True, errors=[])
            self.assertFalse(checks["P8_pilot"]["performance_review"], mode)
            self.assertFalse(facts["cloud_observer_coverage_complete"], mode)

    def test_full_local_counts_sources_and_validation_roles_are_derived(self):
        plan, dataset, report = model_fixture()
        self.assertTrue(local_training_facts(report, dataset, plan)["full"])
        report["attempts"][0]["rounds"][0]["clients"][0]["sample_count"] = 1
        self.assertFalse(local_training_facts(report, dataset, plan)["full"])
        report["source_sha256"]["src/pcfl/learning.py"] = "0" * 64
        self.assertFalse(local_training_facts(report, dataset, plan)["protocol"])
        report["final_test_accessed"] = True
        self.assertFalse(local_training_facts(report, dataset, plan)["validation_only"])

    def test_full_cloud_counts_bind_prepared_runtime_and_real_seeded_client_rounds(self):
        plan, dataset, local = model_fixture()
        attempt = local["attempts"][0]
        runtime = {"distribution": "iid", "training": plan["training_candidate"], "rounds": 5,
            "max_examples_per_client": 100000, "validation_max_examples": 100000,
            "validation_source_sha256": dataset["private_artifacts_sha256"]["validation.csv"],
            "baseline_id": "P1", "scenario_id": "S0", "seed": 296, "persistent_run_id": "synthetic-run",
            "model_metadata": {"metadata_digest": digest("synthetic-metadata"), "model_schema_hash": digest("synthetic-schema"), "hidden_dims": [64, 32]}}
        raw = {"baseline_id": "P1", "scenario_id": "S0", "seed": 296, "persistent_run_id": "synthetic-run",
            "cloud_campaign_id": "synthetic-application", "client_training": [{**row, "round_id": "round-" + str(round_["round"])}
                for round_ in attempt["rounds"] for row in round_["clients"]],
            "updates": [{"round_id": "round-" + str(round_["round"]), "org_id": row["org_id"], "sample_count": row["sample_count"]}
                for round_ in attempt["rounds"] for row in round_["clients"]],
            "validation_metrics": {"count": 16, "threshold": .5}, "test_holdout_evaluated": False,
            "model_metadata_digest": digest("synthetic-metadata"), "model_schema_hash": digest("synthetic-schema")}
        inventory = {"campaign_id": "synthetic-deployment", "export": {"application_campaign_id": "synthetic-application"},
            "image": {"reference": next(iter(plan["provenance"]["image_digests"].values()))},
            "uploads": [{"sha256": value, "version_id": "synthetic-version"} for key, value in dataset["private_artifacts_sha256"].items() if key.startswith("iid/") or key == "preprocessor.json"]}
        facts = full_cloud_case(runtime, raw, dataset, plan, inventory)
        self.assertTrue(all(facts[name] for name in ("protocol", "partitions", "full", "seed", "validation_full", "validation_only")))
        raw["client_training"][0]["sample_count"] = 1
        self.assertFalse(full_cloud_case(runtime, raw, dataset, plan, inventory)["full"])
        raw["client_training"][0]["seed"] += 1
        self.assertFalse(full_cloud_case(runtime, raw, dataset, plan, inventory)["seed"])
        runtime["rounds"] = 1
        self.assertFalse(full_cloud_case(runtime, raw, dataset, plan, inventory)["protocol"])

    def test_historical_pilot_repository_requires_exact_content_and_fresh_runtime_placement(self):
        plan, *parts = sufficient_facts()
        original = plan["provenance"]["image_digests"]["runtime"]
        fresh = "fresh.invalid/runtime@sha256:" + original.split("@sha256:")[-1]
        plan["provenance"]["image_digests"].update(runtime=fresh, pilot_runtime=original)
        self.assertTrue(permitted_pilot_image(original, plan))
        self.assertFalse(permitted_pilot_image("other.invalid/runtime@sha256:" + "b" * 64, plan))
        checks, _, _ = derive_checks(plan, *parts, global_binding=True, errors=[])
        self.assertFalse(all(checks["fargate_isolation"].values()))
        isolation = {key: value for key, value in parts[3][0].items() if key != "rows"}
        isolation["image_reference"] = fresh
        checks, _, _ = derive_checks(plan, *parts, global_binding=True, errors=[], isolations=[isolation])
        self.assertTrue(all(checks["fargate_isolation"].values()))
        plan["provenance"]["image_digests"]["pilot_runtime"] = original[:-1] + "0"
        self.assertFalse(permitted_pilot_image(original[:-1] + "0", plan))

    def test_schedule_or_partition_or_initial_model_difference_breaks_equivalence(self):
        for key, replacement in (("policy_trace", []), ("initialization_config_digest", "wrong"), ("shared_digest", "wrong")):
            plan, *parts = sufficient_facts()
            row = next(row for row in parts[3][0]["rows"] if row["scenario"] == "S1")
            (row["facts"] if key == "shared_digest" else row)[key] = replacement
            checks, _, _ = derive_checks(plan, *parts, global_binding=True, errors=[])
            self.assertFalse(all(checks["manifest_equivalence"].values()))

    def test_protected_error_or_tamper_gaps_cannot_pass_safety(self):
        for mutation in ("indeterminate", "missing-audit", "pointer", "tamper"):
            plan, *parts = sufficient_facts()
            faults = parts[4]
            if mutation == "indeterminate": faults[0]["summary"].update(indeterminate_count=1, attempt_accounting_complete=False)
            if mutation == "missing-audit": faults[0]["summary"]["final_audit_recorded_count"] = 7
            if mutation == "pointer": faults[0]["fault_trace"][0]["pointer_unchanged"] = False
            if mutation == "tamper":
                for fault in faults: fault["protected_tamper_checks"][0]["detected"] = False
            checks, _, _ = derive_checks(plan, *parts, global_binding=True, errors=[])
            self.assertFalse(all(checks["P7_safety_audit"].values()))

    def test_controls_use_raw_observations_not_pass_booleans(self):
        inventory, report = raw_control_fixture()
        observed = control_facts(report, inventory)
        self.assertTrue(observed["expiry"])
        self.assertTrue(observed["notifications"])
        self.assertFalse(observed["billing_delivery_observed"])
        report["machine_alert_evidence"]["subscriptions"] = []
        self.assertFalse(control_facts(report, inventory)["notifications"])
        report["schedules"][0]["state"] = "DISABLED"
        self.assertFalse(control_facts(report, inventory)["expiry"])

    def test_missing_actual_inputs_emit_failing_assessments_not_a_freeze(self):
        with tempfile.TemporaryDirectory() as temp:
            plan = example_plan()
            result = assess_pilots(plan, {}, temp)
            self.assertFalse(result["successful"])
            paths = write_assessments(plan, result, Path(temp) / "assessments", temp)
            self.assertEqual(set(paths), set(GATE_CHECKS))
            for path in paths.values():
                self.assertFalse(json.loads((Path(temp) / path).read_text())["successful"])
            self.assertFalse((Path(temp) / "accepted.json").exists())


if __name__ == "__main__":
    unittest.main()
