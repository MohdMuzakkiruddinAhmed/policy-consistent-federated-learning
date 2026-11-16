"""Synthetic HOST gate replay tests. No AWS, training or clinical-row access."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

STAGE = Path(__file__).resolve().parent
ROOT = next(path for path in STAGE.parents if (path / "src/pcfl/experiments.py").is_file())
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(STAGE))
import forecast_remaining_campaign as forecast
import test_remaining_campaign_forecast as model_fixture
from test_remaining_campaign_forecast import digest, write

# Staged assessor now; after adoption this resolves to the active scripts file.
ASSESSOR = STAGE / "assess_pilots.py" if (STAGE / "assess_pilots.py").is_file() else ROOT / "scripts/assess_pilots.py"
module_spec = importlib.util.spec_from_file_location("forecast_gate_assessor", ASSESSOR)
assessor = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(assessor)
import reconcile_campaign_cost as reconciliation


class RemainingForecastGateTests(unittest.TestCase):
    def setUp(self):
        original = tempfile.TemporaryDirectory
        with patch.object(tempfile, "TemporaryDirectory", lambda: original(dir=STAGE)):
            self.fixture = model_fixture.ForecastTests()
            self.fixture.setUp()
        f = self.fixture
        f.server_scale = .7  # Explicit synthetic fast stratum, not actual pilot timing.
        f.batch("iid"); f.batch("non_iid")
        self.root, self.doc, self.cost, self.dataset = f.root, f.doc, f.cost, f.manifest
        self.plan = json.loads(Path(self.doc["plan"]["path"]).read_text())
        self.plan["training_candidate"] = {"num_rounds": 5}
        self.plan["provenance"] = {"source_files_sha256": {
            "scripts/reconcile_campaign_cost.py": forecast.sha(ROOT / "scripts/reconcile_campaign_cost.py"),
            forecast.SOURCE_NAME: forecast.sha(forecast.__file__)}}
        self.plan.pop("plan_digest")
        self.plan["plan_digest"] = digest(self.plan)
        self.doc["plan"] = write(self.root / "plan.json", self.plan)
        self.cost.update(source_sha256={"scripts/reconcile_campaign_cost.py": self.plan["provenance"]["source_files_sha256"]["scripts/reconcile_campaign_cost.py"]},
            cumulative_fleet_equivalent_hours=2,
            remaining_work_assumptions={"cells": 292, "future_deployments": 3, "application_launches": 16, "bounded_fault_events": 36},
            checks={"operator_budget": True, "current_spend_accounted": True, "projected_cost": False,
                    "cumulative_resource_hours_within_authorization": False},
            projected_total_conservative_estimate_usd=100, measurement="inferred", actual_bill_reconciled=False)
        self.doc["priced_usage"] = write(self.root / "priced_usage.json", self.cost)
        self.input_path = self.root / "forecast_input.json"
        write(self.input_path, self.doc)
        self.report = forecast.build_report(self.input_path)
        self.report_path = self.root / "forecast_report.json"
        write(self.report_path, self.report)
        fresh_rows = []
        for batch in self.doc["pilot_batches"]:
            verified = json.loads(Path(batch["verification"]["path"]).read_text())
            for row in verified["verified_cases"]:
                if "-S0" not in row["cell_id"]:
                    continue
                method = row["cell_id"].split("-")[-2]
                fresh_rows.append({"cell_id": row["cell_id"], "baseline": method, "distribution": batch["distribution"],
                    "scenario": "S0", "seed": 296, "raw_result_sha256": row["raw_result_sha256"], "anchored": True,
                    "test_accessed": False, "execution_successful": True, "facts": {"full": True, "protocol": True},
                    "summary": row["summary"]})
        self.clouds = [{"rows": fresh_rows}]
        self.spec = {"report": self.doc["priced_usage"]["path"],
            "request": write(self.root / "request.json", {})["path"], "quote": self.doc["quote"]["path"],
            "catalog": write(self.root / "catalog.json", {})["path"],
            "remaining_forecast": {"input": str(self.input_path), "report": str(self.report_path)}}

    def tearDown(self):
        self.fixture.tearDown()

    def facts(self):
        # The existing priced-ledger calculator has its own native tests. Keep
        # that component fixed here and exercise real new forecast+assessor glue.
        with patch.object(reconciliation, "load_scope", return_value=({}, self.fixture.authorization, {}, {}, [])), \
             patch.object(reconciliation, "price_basis", return_value=(self.fixture.quote, self.cost["price_basis"]["rates_usd"])), \
             patch.object(reconciliation, "prepared_pilot_campaigns", return_value={}), \
             patch.object(reconciliation, "pilot_throughput", return_value={"both_distributions_observed": True}), \
             patch.object(reconciliation, "reconcile", return_value=deepcopy(self.cost)):
            return assessor.cost_facts(self.spec, assessor.Evidence(ROOT), self.plan, self.dataset, self.clouds)

    def test_assessor_replays_corrected_source_bound_forecast_instead_of_legacy_flat_verdict(self):
        value = self.facts()
        self.assertTrue(value["reproduced"])
        self.assertTrue(value["projected_cost"])
        self.assertLess(value["projected_total_usd"], 20)
        self.assertEqual(value["legacy_flat_projected_total_usd"], 100)
        self.assertEqual(value["remaining_forecast"]["work_counts"], {**forecast.COUNTS, "safety_pilot": 12, "fresh_g1": 1})

    def test_missing_forecast_cannot_fall_back_to_old258_or_pass_boolean(self):
        self.spec.pop("remaining_forecast")
        value = self.facts()
        self.assertFalse(value["projected_cost"])
        self.assertIsNone(value["projected_total_usd"])
        self.assertTrue(value["operator_budget"])
        self.assertTrue(value["current_spend_accounted"])

    def test_modified_or_cheaper_report_is_not_reproduced(self):
        self.report["priced_comparison"]["models"]["stratified"]["projected_total_usd"] = 1
        write(self.report_path, self.report)
        with self.assertRaisesRegex(ValueError, "not_reproduced"):
            self.facts()

    def test_forecast_plan_or_current_source_rebinding_rejects(self):
        self.plan["provenance"]["source_files_sha256"][forecast.SOURCE_NAME] = "0" * 64
        with self.assertRaisesRegex(ValueError, "plan_data_and_priced_usage"):
            self.facts()

    def test_calibration_must_equal_fresh_independent_raw_hash_and_run_duration(self):
        for mode in ("raw", "time", "anchor", "missing"):
            old = deepcopy(self.clouds)
            if mode == "raw": self.clouds[0]["rows"][0]["raw_result_sha256"] = "0" * 64
            if mode == "time": self.clouds[0]["rows"][0]["summary"]["runtime_stage_latency_ms"]["run"] = [1]
            if mode == "anchor": self.clouds[0]["rows"][0]["anchored"] = False
            if mode == "missing": self.clouds[0]["rows"].pop()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.facts()
            self.clouds = old

    def test_arithmetic_over_original_cap_fails_without_changing_authorization(self):
        self.cost["current_conservative_planning_estimate_usd"] = 19.9
        self.doc["priced_usage"] = write(self.root / "priced_usage.json", self.cost)
        write(self.input_path, self.doc)
        write(self.report_path, forecast.build_report(self.input_path))
        value = self.facts()
        self.assertFalse(value["projected_cost"])
        self.assertGreater(value["projected_total_usd"], 20)
        self.assertEqual(value["approved_total_usd"], 20)

    def test_fleet_hour_cap_is_enforced_even_when_usd_estimate_fits(self):
        self.cost["cumulative_fleet_equivalent_hours"] = 10
        self.doc["priced_usage"] = write(self.root / "priced_usage.json", self.cost)
        write(self.input_path, self.doc)
        write(self.report_path, forecast.build_report(self.input_path))
        value = self.facts()
        self.assertFalse(value["projected_cost"])
        self.assertLess(value["projected_total_usd"], 20)
        self.assertGreater(value["projected_cumulative_fleet_hours"], 32)

    def test_application_or_current_project_expiry_failure_blocks_gate_even_with_budget(self):
        for mode in ("application", "current-project"):
            doc = deepcopy(self.doc)
            if mode == "application":
                doc["operational_allowances"]["per_launch_allowance_seconds"] = 13 * 3600
            else:
                self.cost["resources"]["deployments"][0]["elapsed_hours"] = 23.99
                doc["priced_usage"] = write(self.root / "priced_usage.json", self.cost)
            write(self.input_path, doc)
            repeated = forecast.build_report(self.input_path)
            write(self.report_path, repeated)
            value = self.facts()
            self.assertFalse(value["projected_cost"], mode)
            self.assertFalse(value["remaining_forecast"]["scheduling_feasible"], mode)

    def test_safety_zero_requires_all_twelve_current_protected_outcomes(self):
        rows, hashes = [], {}
        for distribution in forecast.DISTRIBUTIONS:
            for scenario, seed in [*((f"S{n}", 296) for n in range(4, 9)), ("S8", 593)]:
                cell = f"safety-{distribution}-{scenario}-{seed}"
                raw = digest(cell); hashes[cell] = raw
                row = {"cell_id": cell, "distribution": distribution, "scenario": scenario, "seed": seed,
                    "baseline": "P1", "raw_result_sha256": raw, "anchored": True, "test_accessed": False,
                    "execution_successful": scenario != "S8", "summary": {"successful": True,
                        "persistent_protocol_verified": True, "runtime_observations_verified": True}}
                if scenario == "S8":
                    row.update(scripted_fault="audit_transport_unavailable" if seed == 593 else "opa_transport_unavailable",
                        partial={"protected_witness_verified": True, "attempt_accounting_complete": True,
                            "indeterminate_count": 0, "audit_complete_for_all_final_outcomes": True,
                            "final_audit_expected_count": 8, "final_audit_recorded_count": 8},
                        fault_trace=[{"phase": "fault_failed_closed", "pointer_unchanged": True,
                            "published_models_during_fault": 0, "recovery_errors": [], "blocked_calls": 1}])
                rows.append(row)
        self.assertTrue(forecast.verified_safety_completion(rows, hashes))
        for mode in ("missing", "hash", "failed-status", "audit", "indeterminate", "wrong-kind", "unblocked-audit"):
            changed = deepcopy(rows)
            if mode == "missing": changed.pop()
            if mode == "hash": changed[0]["raw_result_sha256"] = "0" * 64
            fault = next(row for row in changed if row["scenario"] == "S8")
            if mode == "failed-status": fault["execution_successful"] = True
            if mode == "audit": fault["partial"]["final_audit_recorded_count"] = 0
            if mode == "indeterminate": fault["partial"]["indeterminate_count"] = 1
            if mode == "wrong-kind": next(row for row in changed if row["scenario"] == "S8" and row["seed"] == 593)["scripted_fault"] = "opa_transport_unavailable"
            if mode == "unblocked-audit": next(row for row in changed if row["scenario"] == "S8" and row["seed"] == 593)["fault_trace"][0]["blocked_calls"] = 0
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                forecast.verified_safety_completion(changed, hashes)
        document = deepcopy(self.doc)
        document.update(pending_safety_pilot_cases=0, completed_safety_raw_sha256=hashes)
        result = forecast.generate(document, base=self.root, verified_safety_rows=rows)
        self.assertEqual(result["total_remaining_work"], 280)
        self.assertTrue(result["completed_safety_subtraction_freshly_replayed"])
        self.assertNotIn("safety_pilot", result["work_counts"])
        document["completed_safety_pilot_replay"] = [{"synthetic": "iid"}, {"synthetic": "non_iid"}]
        with patch.dict(sys.modules, {"assess_pilots": assessor}), patch.object(assessor, "cloud_pilot_facts",
                side_effect=[{"rows": rows[:6]}, {"rows": rows[6:]}]) as replay:
            cli_path_result = forecast.generate(document, base=self.root, project_root=ROOT)
        self.assertTrue(cli_path_result["forecast_ready"])
        self.assertEqual(len(cli_path_result["pilot_calibration"]), 8)
        self.assertEqual(replay.call_count, 2)

    def test_whole_app_shared_residual_scales_per_case_and_S3_delay_is_explicit(self):
        value = self.report["duration_model"]
        self.assertEqual(value["observed_shared_application_upper_per_case_seconds"], 13.5)
        s3 = [row for row in value["work"] if row["scenario_id"] == "S3"]
        self.assertEqual(len(s3), 44)
        self.assertTrue(all(row["scheduled_delay_allowance_seconds"] == 1 for row in s3))
        # Eighty future cases each pay their share of observed16-case gaps.
        iid_primary = [row for row in value["work"] if row["family"] == "primary" and row["distribution"] == "iid"]
        self.assertEqual(sum(row["shared_export_supervisor_seconds"] for row in iid_primary), 80 * 13.5)

    def test_new_project_bootstrap_is_charged_and_not_added_to_continued_safety_clock(self):
        operational = self.report["operational_allowances"]
        self.assertEqual(operational["per_new_deployment_bootstrap_allowance_seconds"], 3600)
        self.assertGreaterEqual(operational["additional_bootstrap_export_collection_seconds"], 3 * 3600)
        projects = {row["project_group"]: row for row in self.report["deployment_schedule"]["projects"]}
        self.assertEqual(projects["continued-current-pilot"]["new_project_bootstrap_allowance_hours"], 0)
        self.assertEqual(sum(row["new_project_bootstrap_allowance_hours"] for row in projects.values()), 3)
        self.assertEqual(projects["continued-current-pilot"]["already_elapsed_project_hours"], 4)

    def test_prior_orphan_task_and_missing_shared_timing_never_become_zero(self):
        inventory = json.loads(Path(self.doc["pilot_batches"][0]["inventory"]["path"]).read_text())
        inventory["task_arns"].append("synthetic-historical-orphan")
        orphan_ref = write(self.root / "orphan-inventory.json", inventory)
        self.cost["source_inputs"].append(orphan_ref)
        self.doc["priced_usage"] = write(self.root / "priced_usage.json", self.cost)
        self.assertFalse(forecast.generate(self.doc, base=self.root)["forecast_ready"])
        batch = self.doc["pilot_batches"][0]
        self.fixture.mutate_bound(batch, "inventory", lambda value: value.update(observed_tasks=[]))
        result = forecast.generate(self.doc, base=self.root)
        self.assertFalse(result["observed_shared_application_envelopes_complete"])
        self.assertIsNone(result["priced_comparison"])


if __name__ == "__main__":
    unittest.main()
