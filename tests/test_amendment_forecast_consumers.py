"""Typed successor forecast contracts use fictional local decision records."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

STAGE = Path(__file__).resolve().parent
ROOT = next(path for path in STAGE.parents if (path / "pyproject.toml").is_file())
sys.path[:0] = [str(STAGE), str(STAGE.parent), str(ROOT / "tests"), str(ROOT / "scripts")]
import campaign_budget as budget
import test_amendment_cost_consumers as native_cost_fixture
import test_remaining_campaign_forecast as model_fixture
FORECAST_SOURCE = STAGE / "forecast_remaining_campaign.py" if (STAGE / "forecast_remaining_campaign.py").is_file() else ROOT / "scripts/forecast_remaining_campaign.py"
spec = importlib.util.spec_from_file_location("successor_forecast", FORECAST_SOURCE)
forecast = importlib.util.module_from_spec(spec); spec.loader.exec_module(forecast)


class AmendmentForecastConsumerTests(unittest.TestCase):
    def setUp(self):
        self.f = native_cost_fixture.AmendmentCostConsumerTests(); self.f.setUp()
        self.root = self.f.root
        self.report = self.f.report()
        self.plan = model_fixture.plan_fixture()
        self.plan["provenance"] = {"source_files_sha256": {"scripts/campaign_budget.py": forecast.sha(budget.__file__)}}
        self.plan.pop("plan_digest"); self.plan["plan_digest"] = model_fixture.digest(self.plan)
        dataset = {"partitions": {distribution: {"organizations": {f"org_{n:02d}": {"encounters": 10}
            for n in range(1, 9)}} for distribution in forecast.DISTRIBUTIONS}, "splits": {"validation": {"encounters": 15}}}
        self.doc = {"schema_version": "0.1.0", "kind": "remaining-campaign-forecast-input",
            "authorization": self.f.request["authorization"], "quote": self.f.f.quote_ref,
            "campaign_request": self.f.request_ref,
            "successor_ledger": {"path": self.f.ledger_relative, "sha256": forecast.sha(self.root / self.f.ledger_relative)},
            "priced_usage": self.f.f.put("current-cost.json", self.report), "plan": self.f.f.put("plan.json", self.plan),
            "base_data_manifest": self.f.f.put("base.json", dataset), "alternate_data_manifest": self.f.f.put("alt.json", dataset),
            "expected_image_digest": "sha256:" + "f" * 64, "external_witness_public_key_sha256": "e" * 64,
            "pilot_batches": [], "pending_safety_pilot_cases": 12,
            "operational_allowances": {"application_launches": 16, "remaining_deployments": 3, "bounded_fault_events": 36,
                "per_launch_allowance_seconds": 300, "per_fault_allowance_seconds": 300,
                "per_new_deployment_bootstrap_allowance_seconds": 3600, "additional_bootstrap_export_collection_seconds": 10800,
                "incremental_nonendpoint_service_reserve_usd": 0, "endpoint_az_count": 1}}

    def tearDown(self): self.f.tearDown()

    def generate(self):
        with patch.dict(sys.modules, {"reconcile_campaign_cost": native_cost_fixture.cost}):
            return forecast.generate(self.doc, base=self.root, project_root=self.root)

    def test_actual_typed_limits_and_exact_predecessor_context_replace_legacy_limits(self):
        value = self.generate()
        self.assertEqual(value["authorization_limits"]["approved_cumulative_total_usd"], 30)
        self.assertEqual(value["authorization_limits"]["maximum_cumulative_fleet_hours"], 60)
        self.assertNotIn("original_limits_unchanged", value)
        self.assertEqual(value["predecessor_budget_context"]["usage_floors"]["conservative_planning_usd"], 12)
        self.assertEqual(value["budget_semantics"], "cumulative-inclusive-of-predecessors")
        self.assertFalse(value["forecast_ready"])
        self.assertIsNone(value["priced_comparison"])
        self.assertFalse(value["execution_authorized"])

    def test_real_pricer_uses_cumulative_past_usage_and_dynamic_capacity_not_new_zero_budget(self):
        approval = self.f.f.approval
        operation = {"application_launches": 0, "bounded_fault_events": 0, "remaining_deployments": 0,
            "total_allowance_seconds": 0, "incremental_nonendpoint_service_reserve_usd": 0, "endpoint_az_count": 1}
        compared = forecast.price_models({"seconds": {"stratified": 40 * 3600}}, operation, self.report, approval)
        model = compared["models"]["stratified"]
        self.assertGreater(model["projected_total_usd"], 20)
        self.assertLess(model["projected_total_usd"], approval["approved_total_usd"])
        self.assertGreater(model["projected_cumulative_fleet_hours"], 32)
        self.assertLess(model["projected_cumulative_fleet_hours"], approval["max_cumulative_fleet_hours"])
        self.assertEqual(model["past_and_reserved_usage_usd"], self.report["current_conservative_planning_estimate_usd"])

    def test_native_report_cannot_downgrade_to_ancestor_twenty_dollar_authority(self):
        self.doc["authorization"] = self.f.f.old_auth_ref
        self.doc["quote"] = self.f.f.old_quote_ref
        with self.assertRaisesRegex(ValueError, "cannot_downgrade"):
            self.generate()

    def test_missing_activation_or_exact_ledger_or_source_binding_is_fail_closed(self):
        for mode in ("missing-ledger-pin", "wrong-request-pin", "missing-source-validator", "wrong-family"):
            doc = deepcopy(self.doc)
            if mode == "missing-ledger-pin": self.doc.pop("successor_ledger")
            if mode == "wrong-request-pin": self.doc["campaign_request"]["sha256"] = "0" * 64
            if mode == "missing-source-validator":
                plan = deepcopy(self.plan); plan["provenance"]["source_files_sha256"] = {}; plan.pop("plan_digest"); plan["plan_digest"] = model_fixture.digest(plan)
                self.doc["plan"] = self.f.f.put("plan-wrong.json", plan)
            if mode == "wrong-family":
                report = deepcopy(self.report); report["budget_lineage"]["budget_family_id"] = "0" * 64
                self.doc["priced_usage"] = self.f.f.put("wrong-cost.json", report)
            with self.subTest(mode=mode), self.assertRaises((ValueError, KeyError)):
                self.generate()
            self.doc = doc

    def test_priced_currency_floor_or_omitted_old_task_cannot_be_hidden(self):
        for mode in ("floor", "task"):
            report = deepcopy(self.report)
            if mode == "floor": report["current_conservative_planning_estimate_usd"] = 1
            else: report["resources"]["tasks"].pop(self.f.f.old_arns[0])
            self.doc["priced_usage"] = self.f.f.put("wrong-" + mode + ".json", report)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.generate()


if __name__ == "__main__": unittest.main()
