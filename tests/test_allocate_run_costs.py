import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("allocate_run_costs", Path(__file__).resolve().parents[1]/"scripts/allocate_run_costs.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class RunCostAllocationTests(unittest.TestCase):
    def fixtures(self):
        task = {"task_arn": "task-one", "cpu": 1024, "memory_mib": 2048,
            "billing_started_at": "2026-01-01T00:00:00Z", "stopped_at": "2026-01-01T00:03:00Z"}
        inventory = {"account_id": "123456789012", "region": "us-east-1", "campaign_id": "deployment-one",
            "task_arns": ["task-one"], "observed_tasks": [task]}
        cost = {"kind": "campaign-priced-usage-reconciliation", "current_spend_accounted": True,
            "measurement": "inferred", "account_id": inventory["account_id"], "region": inventory["region"],
            "price_basis": {"rates_usd": {"cpu": .04, "memory": .004}},
            "resources": {"tasks": {"task-one": {"vcpu_hours": .05, "gib_hours": .1}}},
            "current_conservative_planning_estimate_usd": 1.0024}
        cases = []
        for index in range(2):
            raw = {"successful": index == 0, "published_manifests": [{}] if index == 0 else [],
                "case_started_at_utc": f"2026-01-01T00:0{index}:00Z",
                "case_finished_at_utc": f"2026-01-01T00:0{index+1}:00Z", "elapsed_seconds": 60.}
            cases.append({"cell_id": "cell-"+str(index), "application_campaign_id": "application-one",
                "deployment_id": "deployment-one", "raw_result": {"sha256": str(index)*64}, "raw": raw})
        return cost, [(inventory, cases)]

    def test_direct_usage_and_all_shared_allowances_conserve_total_for_failed_and_successful(self):
        cost, sources = self.fixtures()
        report = MOD.allocate(cost, sources)
        self.assertTrue(report["successful"])
        self.assertFalse(report["actual_invoice"])
        self.assertAlmostEqual(report["direct_compute_usd"], 120*(.04+2*.004)/3600)
        self.assertAlmostEqual(sum(r["cost_usd"]["planning_upper_allocation"] for r in report["runs"]), cost["current_conservative_planning_estimate_usd"])
        self.assertIsNone(report["runs"][1]["cost_usd"]["per_published_round_planning_upper"])
        self.assertEqual(report["runs"][0]["resources"], {"vcpu_seconds": 60., "memory_gib_seconds": 120.})

    def test_missing_case_clock_is_pending_and_never_zero_filled(self):
        cost, sources = self.fixtures()
        del sources[0][1][0]["raw"]["case_started_at_utc"]
        report = MOD.allocate(cost, sources)
        self.assertFalse(report["successful"])
        self.assertIsNone(report["runs"][0]["resources"])
        self.assertIsNone(report["runs"][0]["cost_usd"])

    def test_overlapping_cases_and_undersized_billed_usage_fail(self):
        cost, sources = self.fixtures()
        sources[0][1][1]["raw"]["case_started_at_utc"] = "2026-01-01T00:00:30Z"
        sources[0][1][1]["raw"]["case_finished_at_utc"] = "2026-01-01T00:01:30Z"
        with self.assertRaisesRegex(ValueError, "overlapping"):
            MOD.allocate(cost, sources)
        cost, sources = self.fixtures()
        cost["resources"]["tasks"]["task-one"]["vcpu_hours"] = .001
        with self.assertRaisesRegex(ValueError, "exceeds_recorded"):
            MOD.allocate(cost, sources)

    def test_missing_task_coverage_is_pending_and_foreign_account_rejected(self):
        cost, sources = self.fixtures()
        sources[0][0]["observed_tasks"][0]["billing_started_at"] = "2026-01-01T00:02:30Z"
        report = MOD.allocate(cost, sources)
        self.assertFalse(report["successful"])
        self.assertEqual(report["runs"][0]["timing_status"], "no-task-usage-coverage")
        self.assertIsNone(report["runs"][0]["cost_usd"])
        cost, sources = self.fixtures()
        sources[0][0]["account_id"] = "999999999999"
        with self.assertRaisesRegex(ValueError, "account_or_region"):
            MOD.allocate(cost, sources)

    def test_original_app_scoped_raw_version_is_required_and_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, app, cell = Path(temp), "app-one", "cell-one"
            export = root/"r/apphash"
            case = export/hashlib.sha256(cell.encode()).hexdigest()[:8]
            case.mkdir(parents=True)
            raw = case/"runtime_result.json"
            raw.write_text(json.dumps({"cell_id": cell, "cloud_campaign_id": app}))
            (case/"cell.json").write_text(json.dumps({"cell_id": cell}))
            reference = {"bucket": "owned", "key": f"evidence/campaigns/{app}/{cell}/runtime_result.json",
                "version_id": "immutable-version", "sha256": MOD.sha(raw), "size_bytes": raw.stat().st_size}
            index = export/"campaign_result.json"
            index.write_text(json.dumps({"campaign_id": app, "cases": [{"cell_id": cell, "artifacts": [reference]}]}))
            inv = root/"app-inventory.json"
            inv.write_text(json.dumps({"campaign_id": "master", "foundation": {"bucket_name": "owned"},
                "retained_artifact_versions": [dict(reference, local_path=str(raw)),
                    {"bucket": "owned", "key": f"evidence/campaigns/{app}/campaign_result.json", "version_id": "index-version",
                     "sha256": MOD.sha(index), "size_bytes": index.stat().st_size, "local_path": str(index)}],
                "export": {"application_campaign_id": app, "export_root": str(export), "index_sha256": MOD.sha(index),
                    "index_key": f"evidence/campaigns/{app}/campaign_result.json", "index_version_id": "index-version"}}))
            self.assertEqual(MOD.load_cases(inv)[1][0]["cell_id"], cell)
            raw.write_text('{}')
            with self.assertRaisesRegex(ValueError, "raw_version"):
                MOD.load_cases(inv)

    def test_partial_task_clocks_and_omitted_apps_are_explicit(self):
        cost, sources = self.fixtures()
        sources[0][0]["task_arns"].append("missing-task")
        sources[0][0]["exports_by_application"] = {"older-application": {}}
        report = MOD.allocate(cost, sources)
        self.assertFalse(report["successful"])
        self.assertFalse(report["runs"][0]["resource_coverage_complete"])
        self.assertEqual(report["known_retained_applications_omitted"], ["older-application"])

    def test_conflicting_final_clocks_and_negative_intervals_fail(self):
        cost, sources = self.fixtures()
        old = dict(sources[0][0]["observed_tasks"][0], stopped_at="2026-01-01T00:02:59Z")
        sources[0][0]["task_observation_history"] = {"task-one": old}
        with self.assertRaisesRegex(ValueError, "clock_rebound"):
            MOD.allocate(cost, sources)
        cost, sources = self.fixtures()
        sources[0][0]["observed_tasks"][0]["stopped_at"] = "2025-12-31T23:59:59Z"
        with self.assertRaisesRegex(ValueError, "negative_task"):
            MOD.allocate(cost, sources)

    def test_null_case_clock_is_missing_and_not_an_unhandled_attribute_error(self):
        cost, sources = self.fixtures()
        sources[0][1][0]["raw"]["case_started_at_utc"] = None
        self.assertFalse(MOD.allocate(cost, sources)["successful"])


if __name__ == "__main__":
    unittest.main()
