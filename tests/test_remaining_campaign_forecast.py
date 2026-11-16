"""Synthetic JSON-only checks of the staged model, not cloud protocol evidence."""
from copy import deepcopy
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import itertools
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "scripts/reconcile_campaign_cost.py").is_file())
sys.path.insert(0, str(ROOT / "scripts"))
if (Path(__file__).resolve().parent / "forecast_remaining_campaign.py").is_file():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import forecast_remaining_campaign as forecast


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    return forecast.ref(path)


def plan_fixture():
    plan = {"status": "candidate_locked", "schema_version": "0.1.0"}
    specifications = {
        "primary_cells": [(method, distribution, f"S{scenario}", seed, None) for method, distribution, scenario, seed in
            itertools.product(forecast.METHODS, forecast.DISTRIBUTIONS, range(4), (296, 593, 887, 1181, 1483))],
        "targeted_cells": [("P1", distribution, f"S{scenario}", seed, None) for distribution, scenario, seed in
            itertools.product(forecast.DISTRIBUTIONS, range(4, 9), (296, 593, 887, 1181, 1483))],
        "ablation_cells": [("P1", distribution, scenario, seed, variant) for (variant, scenario), distribution, seed in
            itertools.product((("Abl1", "S2"), ("Abl2", "S6"), ("Abl3", "S8"), ("Abl4", "S4")),
                forecast.DISTRIBUTIONS, (296, 593, 887, 1181, 1483))],
        "replication_cells": [(method, distribution, scenario, 296, None) for method, distribution, scenario in
            itertools.product(("B3", "P1"), forecast.DISTRIBUTIONS, ("S2", "S3"))]}
    for family, rows in specifications.items():
        plan[family] = [{"cell_id": f"synthetic-{family}-{index}", "baseline_id": method, "distribution": distribution,
            "scenario_id": scenario, "seed": seed, "variant": variant}
            for index, (method, distribution, scenario, seed, variant) in enumerate(rows)]
    plan["plan_digest"] = digest(plan)
    return plan


class ForecastTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.account, self.region, self.pin = "123456789012", "us-east-1", "e" * 64
        self.image = "sha256:" + "f" * 64
        self.manifest = {"partitions": {distribution: {"organizations": {f"org_{n:02d}": {"encounters": 10}
            for n in range(1, 9)}} for distribution in forecast.DISTRIBUTIONS},
            "splits": {"validation": {"encounters": 15}}}
        self.quote = {"account_id": self.account, "region": self.region, "requested_additional_total_usd": 20,
            "rates": {"cpu": {"usd": ".04"}, "memory": {"usd": ".004"}}}
        self.doc = {"kind": "remaining-campaign-forecast-input", "schema_version": "0.1.0",
            "expected_image_digest": self.image, "external_witness_public_key_sha256": self.pin,
            "quote": write(self.root / "quote.json", self.quote), "plan": write(self.root / "plan.json", plan_fixture()),
            "base_data_manifest": write(self.root / "base.json", self.manifest),
            "alternate_data_manifest": write(self.root / "alternate.json", self.manifest),
            "pilot_batches": [], "operational_allowances": {"application_launches": 16, "remaining_deployments": 3,
                "bounded_fault_events": 36, "per_launch_allowance_seconds": 300, "per_fault_allowance_seconds": 300,
                "additional_bootstrap_export_collection_seconds": 11400, "per_new_deployment_bootstrap_allowance_seconds": 3600,
                "incremental_nonendpoint_service_reserve_usd": .25,
                "endpoint_az_count": 1}}
        self.authorization = {"account_id": self.account, "region": self.region, "approved": True,
            "approved_total_usd": 20, "max_cumulative_fleet_hours": 32, "max_vcpu": 4, "max_memory_gib": 14,
            "proposal_sha256": self.doc["quote"]["sha256"]}
        self.doc["authorization"] = write(self.root / "authorization.json", self.authorization)
        self.cost = {"kind": "campaign-priced-usage-reconciliation", "aws_mutations": False,
            "account_id": self.account, "region": self.region, "campaign_id": "synthetic-past", "as_of_utc": "2026-11-13T10:00:00+00:00",
            "current_spend_accounted": True, "current_conservative_planning_estimate_usd": 8,
            "cumulative_fleet_equivalent_hours": 4,
            "price_basis": {"rates_usd": {"cpu": .04, "memory": .004, "interface_endpoint_az_hour": .01,
                "interface_endpoint_data_gb": .01, "private_dns_zone_month": .50}},
            "current_unmetered_service_reserves_usd": {"endpoint_data_processing_up_to_30GB": .30,
                "two_private_dns_namespaces_and_discovery": 2.10},
            "image_pull_endpoint_planning_envelope": {"available": True, "maximum_observed_compressed_image_bytes": 500_000_000,
                "current_image_payload_bytes_envelope": 20_000_000_000},
            "resources": {"tasks": {}, "deployments": [{"campaign_id": "synthetic-past", "elapsed_hours": 4}]}, "source_inputs": [self.doc["authorization"]]}

    def tearDown(self):
        self.temp.cleanup()

    def batch(self, distribution):
        directory = self.root / distribution
        app = "synthetic-pilot-" + distribution
        bucket = "synthetic-owned"
        config, index, verification = {"campaign_id": app, "cases": []}, {"campaign_id": app, "cases": []}, {
            "kind": "independent-cloud-campaign-export-validation", "account_id": self.account, "region": self.region,
            "application_campaign_id": app, "successful": True, "externally_protected_witnesses_verified": True,
            "test_holdout_evaluated": False, "failed_cases": [], "partial_assessments": [], "unprotected_case_ids": [], "verified_cases": []}
        case_dirs, restart_events = {}, {}
        first = datetime(2026, 11, 13, 6, tzinfo=timezone.utc)
        clock = first
        for method, scenario in itertools.product(forecast.METHODS, range(4)):
            cell = f"{distribution}-{method}-S{scenario}"
            server = ((100 if distribution == "iid" else 200) + 10 * forecast.METHODS.index(method)) * getattr(self, "server_scale", 1)
            overhead = 12 if (distribution, method) == ("non_iid", "B2") else 10
            restart = method == "P1" and scenario == 0
            runtime = {"baseline_id": method, "distribution": distribution, "scenario_id": f"S{scenario}",
                "persistent_run_id": "run-" + cell, "rounds": 5, "model_metadata": {"hidden_dims": [64, 32]},
                "training": {"optimizer": "adam", "learning_rate": .001, "batch_size": 64, "local_epochs": 1,
                    "num_rounds": 5, "hidden_dims": [64, 32], "cpu_threads": 1, "device": "cpu"}}
            if restart:
                runtime["host_restart"] = {"request_id": "restart-" + cell, "run_id": runtime["persistent_run_id"]}
                restart_events["restart-" + cell] = {"synthetic_fixture": True}
            raw = {"successful": True, "aws_used": True, "test_holdout_evaluated": False,
                "cloud_campaign_id": app, "cell_id": cell, "persistent_run_id": runtime["persistent_run_id"],
                "baseline_id": method, "scenario_id": ("stable", "between_round", "mid_round", "delayed")[scenario],
                "elapsed_seconds": server + (100 if restart else overhead),
                "case_started_at_utc": clock.isoformat(),
                "case_finished_at_utc": (clock + timedelta(seconds=server + (100 if restart else overhead))).isoformat(),
                "rounds": [{"round_id": n} for n in range(5)],
                "validation_metrics": {"count": 15},
                "client_training": [{"org_id": f"org_{org:02d}", "round_id": f"round-{n}", "sample_count": 10}
                    for org in range(1, 9) for n in range(1, 6)],
                "runtime_observations": {"stages": [{"name": "run", "start_ms": 0, "end_ms": server * 1000, "status": "complete"}]}}
            raw_path = directory / "export" / cell / "runtime_result.json"
            raw_pin = write(raw_path, raw)
            clock = datetime.fromisoformat(raw["case_finished_at_utc"]) + timedelta(seconds=1)
            case_dirs[cell] = str(raw_path.parent)
            artifact = {"bucket": bucket, "key": f"evidence/campaigns/{app}/{cell}/runtime_result.json",
                "version_id": "synthetic-version-" + cell, "sha256": raw_pin["sha256"], "size_bytes": raw_path.stat().st_size}
            index["cases"].append({"cell_id": cell, "successful": True, "artifacts": [artifact]})
            config["cases"].append({"cell_id": cell, "runtime": runtime})
            verification["verified_cases"].append({"cell_id": cell, "raw_result_sha256": raw_pin["sha256"],
                "protected_operator_witness": {"protected_witness_verified": True, "external_public_key_sha256": self.pin,
                    "witness": {"raw_result_sha256": raw_pin["sha256"]}},
                "summary": {"successful": True, "persistent_protocol_verified": True, "runtime_observations_verified": True,
                    "committed_evaluation_response_verified": True, "runtime_stage_latency_ms": {"run": [server * 1000]}}})
        config_pin = write(directory / "prepared.json", config)
        index_pin = write(directory / "export" / "campaign_result.json", index)
        placement = {"kind": "actual-aws-learning-placement-validation", "account_id": self.account, "region": self.region,
            "successful": True, "checks": {"synthetic_fixture_gate": True}, "client_restart_evidence": {"verified": list(restart_events)},
            "source_snapshot": {"application_campaign_id": app, "image_relations": {self.image: {"verified": True}}}}
        inventory = {"account_id": self.account, "region": self.region, "application_campaign_id": app,
            "image": {"reference": "synthetic/own@" + self.image}, "foundation": {"bucket_name": bucket},
            "uploads": [{"sha256": config_pin["sha256"], "key": "metadata/prepared.json", "version_id": "synthetic-config-version"}],
            "exports_by_application": {app: {"index_sha256": index_pin["sha256"], "index_version_id": "synthetic-index-version",
                "index_key": f"evidence/campaigns/{app}/campaign_result.json", "export_root": str(directory / "export"),
                "case_directories": case_dirs}}, "task_arns": ["synthetic-task-" + distribution], "client_restart_events": restart_events,
            "shutdown_confirmation": {"confirmed": True, "at_utc": "2026-11-13T09:30:00+00:00"},
            "runtime_contract": {"task_definition_arns": {"coordinator": "synthetic-definition"}},
            "observed_tasks": [{"task_arn": "synthetic-task-" + distribution, "task_definition_arn": "synthetic-definition",
                "billing_started_at": (first - timedelta(seconds=100)).isoformat(),
                "stopped_at": (clock + timedelta(seconds=100)).isoformat()}]}
        self.cost["resources"]["tasks"]["synthetic-task-" + distribution] = {"synthetic_fixture": True}
        result = {"distribution": distribution, "verification": write(directory / "verification.json", verification),
            "placement": write(directory / "placement.json", placement), "inventory": write(directory / "inventory.json", inventory),
            "prepared_campaign": config_pin, "export_index": index_pin}
        self.doc["pilot_batches"].append(result)
        self.cost["source_inputs"].append(result["inventory"])
        return result

    def generate(self):
        self.doc["priced_usage"] = write(self.root / "cost.json", self.cost)
        return forecast.generate(self.doc, base=self.root)

    def mutate_bound(self, batch, field, change):
        path = Path(batch[field]["path"])
        value = json.loads(path.read_text())
        change(value)
        batch[field] = write(path, value)

    def test_both_complete_batches_compare_same_past_and_allowances(self):
        self.batch("iid"); self.batch("non_iid")
        result = self.generate()
        self.assertTrue(result["forecast_ready"])
        self.assertEqual(result["work_counts"], {**forecast.COUNTS, "safety_pilot": 12, "fresh_g1": 1})
        self.assertEqual(result["total_remaining_work"], 292)
        self.assertEqual(result["operational_allowances"]["scheduled_S7_S8_fault_cases"], 36)
        self.assertEqual(result["duration_model"]["maximum_nonrestart_supervisor_seconds"], 12)
        self.assertEqual(result["duration_model"]["worst_outer_seconds_including_deliberate_restart"], 330)
        comparison = result["priced_comparison"]
        self.assertEqual(comparison["future_task_pull_allowance"], 372)
        for model in comparison["models"].values():
            self.assertEqual(model["past_and_reserved_usage_usd"], 8)
            self.assertEqual(model["past_normalized_fleet_hours"], 4)
            self.assertEqual(model["operational_allowance_seconds"], 27000)
            # Endpoint floor is charged once: (20GB+372*.5GB)*.01 - existing$.30.
            self.assertAlmostEqual(model["incremental_image_as_metered_reserve_usd"], 1.760)
        self.assertFalse(result["execution_authorized"])
        self.assertIsNone(result["budget_fit_verdict"])

    def test_missing_distribution_never_publishes_projected_totals(self):
        self.batch("iid")
        result = self.generate()
        self.assertFalse(result["forecast_ready"])
        self.assertIsNone(result["priced_comparison"])
        self.assertTrue(all(value is None for value in result["duration_model"]["seconds"].values()))
        fallback = [row for row in result["duration_model"]["strata"] if row["distribution"] == "non_iid"]
        self.assertTrue(all(row["server_seconds"] == 130 and row["basis"] == "global-server-maximum" for row in fallback))

    def test_stale_priced_usage_cannot_discount_completed_pilots(self):
        self.batch("iid"); self.batch("non_iid")
        self.cost["as_of_utc"] = "2026-11-13T08:00:00+00:00"
        self.assertIsNone(self.generate()["priced_comparison"])
        self.cost["as_of_utc"] = "2026-11-13T10:00:00+00:00"
        self.cost["resources"]["tasks"].pop("synthetic-task-iid")
        self.assertFalse(self.generate()["forecast_ready"])

    def test_large_architecture_scales_entire_server_without_selective_discount(self):
        self.batch("iid"); self.batch("non_iid")
        rows = self.generate()["duration_model"]["work"]
        large = next(row for row in rows if row["distribution"] == "non_iid" and row["architecture_multiplier"] == 4.01)
        self.assertAlmostEqual(large["stratified_buffered_seconds"], 1.5 * (230 * 4.01 + 12 + 13.5 * 4.01))
        partial = next(row for row in rows if row.get("factors", {}).get("participation_fraction") == .5 and row["distribution"] == "non_iid")
        self.assertEqual(partial["stratified_buffered_seconds"], 1.5 * (230 + 12 + 13.5))
        omissions = [row for row in rows if row["family"] == "ablation"]
        self.assertTrue(all(row["stratified_buffered_seconds"] >= 1.5 * (130 + 12) for row in omissions))

    def test_alternate_partition_growth_and_application_delay_have_no_free_discount(self):
        alternate = deepcopy(self.manifest)
        alternate["partitions"]["non_iid"]["organizations"]["org_01"]["encounters"] = 30
        rows = forecast.exploratory_work(self.manifest, alternate)
        alpha = next(row for row in rows if row["factors"]["non_iid_alpha"] == 1)
        self.assertEqual(alpha["partition_multiplier"], 3)
        self.assertEqual(sum(row["architecture_multiplier"] == 4.01 for row in rows), 2)
        self.assertEqual([row["added_delay_seconds"] for row in rows if row["factors"]["artificial_latency_ms"] == 1000], [40, 40])
        self.assertEqual(Counter(row["distribution"] for row in rows), {"iid": 10, "non_iid": 11})

    def test_input_digest_rebinding_rejected(self):
        path = Path(self.doc["plan"]["path"])
        path.write_text("{}")
        with self.assertRaisesRegex(ValueError, "input_digest"):
            self.generate()

    def test_unprotected_or_wrong_key_pilot_rejected(self):
        batch = self.batch("iid")
        self.mutate_bound(batch, "verification", lambda value: value["verified_cases"][0]["protected_operator_witness"].update(external_public_key_sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "full_protected"):
            self.generate()

    def test_mismatched_actual_placement_image_rejected(self):
        batch = self.batch("iid")
        self.mutate_bound(batch, "placement", lambda value: value["source_snapshot"].update(image_relations={}))
        with self.assertRaisesRegex(ValueError, "placement"):
            self.generate()

    def test_missing_raw_version_rejected(self):
        batch = self.batch("iid")
        self.mutate_bound(batch, "export_index", lambda value: value["cases"][0]["artifacts"][0].update(version_id="null"))
        self.mutate_bound(batch, "inventory", lambda value: value["exports_by_application"]["synthetic-pilot-iid"].update(index_sha256=batch["export_index"]["sha256"]))
        with self.assertRaisesRegex(ValueError, "versioned_raw"):
            self.generate()

    def test_mismatched_verified_run_stage_rejected(self):
        batch = self.batch("iid")
        self.mutate_bound(batch, "verification", lambda value: value["verified_cases"][0]["summary"]["runtime_stage_latency_ms"].update(run=[999]))
        with self.assertRaisesRegex(ValueError, "complete_run_stage"):
            self.generate()

    def test_unverified_restart_cannot_be_removed_from_overhead(self):
        batch = self.batch("iid")
        self.mutate_bound(batch, "inventory", lambda value: value.update(client_restart_events={}))
        with self.assertRaisesRegex(ValueError, "actual_verified_event"):
            self.generate()

    def test_shortened_launch_fault_or_missing_groups_rejected(self):
        for key, value in (("per_launch_allowance_seconds", 299), ("per_fault_allowance_seconds", 299),
                           ("application_launches", 15), ("bounded_fault_events", 35), ("remaining_deployments", 2),
                           ("additional_bootstrap_export_collection_seconds", 10799)):
            with self.subTest(key=key):
                old = self.doc["operational_allowances"][key]
                self.doc["operational_allowances"][key] = value
                with self.assertRaises(ValueError):
                    self.generate()
                self.doc["operational_allowances"][key] = old

    def test_authorization_cannot_be_increased_by_forecast(self):
        self.authorization["approved_total_usd"] = 25
        self.doc["authorization"] = write(self.root / "authorization.json", self.authorization)
        self.cost["source_inputs"] = [self.doc["authorization"]]
        with self.assertRaisesRegex(ValueError, "original_authorization"):
            self.generate()

    def test_no_eligible_supervisor_observation_stays_missing(self):
        self.assertIsNone(forecast.duration_model([{"host_restart_present": True, "server_run_seconds": 100,
            "outer_seconds": 300, "nonrestart_supervisor_seconds": None}], []))


if __name__ == "__main__":
    unittest.main()
