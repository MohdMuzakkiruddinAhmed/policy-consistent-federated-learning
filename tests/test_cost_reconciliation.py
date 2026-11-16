"""Usage accounting and projection are tested without AWS or clinical rows."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import reconcile_campaign_cost as cost

NOW = datetime(2026, 11, 13, 3, tzinfo=timezone.utc)
ACCOUNT = "123456789012"
IMAGE = ACCOUNT + ".dkr.ecr.us-east-1.amazonaws.com/pcfl-test/runtime@sha256:" + "b" * 64


def image_observations(size=500_000_000):
    return {"images": [{"reference": IMAGE, "compressed_image_bytes": size,
        "pushed_at": (NOW - timedelta(hours=1)).isoformat(), "source": "ecr.DescribeImages"}]}


def fixture():
    request = {"account_id": ACCOUNT, "region": "us-east-1", "campaign_id": "campaign-one"}
    approval = {"approved": True, "approved_total_usd": 20, "max_vcpu": 4, "max_memory_gib": 14, "max_cumulative_fleet_hours": 32}
    contract = {"interface_endpoint_ids": [f"vpce-{index}" for index in range(5)], "endpoint_az_count": 1, "secret_arns": {str(index): "recorded-secret" for index in range(16)}}
    inv = {"project_id": "pcfl-test", "task_arns": ["recorded-task"], "observed_tasks": [], "runtime_contract": contract,
        "image": {"reference": IMAGE}, "foundation": {"image_repositories": {"runtime": IMAGE.split("@")[0]}}}
    ledger = {"tasks": {"recorded-task": {"vcpu_hours": .25, "gib_hours": 1, "last_status": "STOPPED"}},
        "deployments": {"one": {"campaign_id": "campaign-one", "project_id": "pcfl-test", "started_at": (NOW - timedelta(minutes=61)).isoformat(), "finished_at": None}}}
    quote = {"catalog_sha256": "a" * 64, "checked_at_utc": "2026-11-13T00:00:00Z", "other_allowances_usd": {
        "endpoint_data_processing_up_to_30GB": .3, "secrets_and_api_calls": .6, "two_private_dns_namespaces_and_discovery": 1.1,
        "ECR_storage": .3, "S3_storage_requests_and_export": 1, "DynamoDB_requests_storage_backup": 2, "bounded_masked_logs": 1,
        "scheduler_lambda_SQS_and_monitoring": .2}}
    return request, approval, ledger, {"campaign-one": inv}, quote, {**cost.FIXED_RATES, "cpu": .04048, "memory": .004445}


def throughput(ready=True, seconds=100):
    return {"both_distributions_observed": ready, "worst_observed_case_seconds": seconds if ready else None}


class CostTests(unittest.TestCase):
    def test_partial_endpoint_hours_round_up_for_each_distinct_deployment(self):
        _, _, ledger, invs, _, rates = fixture()
        first = ledger["deployments"]["one"]
        first.update(started_at=(NOW - timedelta(minutes=90)).isoformat(), finished_at=(NOW - timedelta(hours=1)).isoformat())
        ledger["deployments"]["two"] = {**first, "started_at": (NOW - timedelta(minutes=30)).isoformat(), "finished_at": NOW.isoformat()}
        rows = cost.priced_deployments(ledger, invs, NOW, rates)
        self.assertEqual(sum(row["charged_endpoint_az_hours_upper_estimate"] for row in rows), 10)
        self.assertAlmostEqual(sum(row["endpoint_usd_upper_estimate"] for row in rows), .10)

    def test_fargate_uses_pull_time_ceil_seconds_minimum_and_never_drops_failed_usage(self):
        _, _, ledger, invs, _, _ = fixture()
        ledger["tasks"]["recorded-task"].update(vcpu_hours=0, gib_hours=0)
        invs["campaign-one"]["observed_tasks"] = [{"task_arn": "recorded-task", "cpu": 256, "memory_mib": 1024,
            "billing_started_at": (NOW - timedelta(seconds=61.1)).isoformat(), "stopped_at": NOW.isoformat(), "last_status": "STOPPED", "container_exit_codes": [1]}]
        rows, covered = cost.priced_tasks(ledger, invs, NOW)
        self.assertTrue(covered)
        self.assertEqual(rows["recorded-task"]["billed_seconds_model"], 62)
        self.assertAlmostEqual(rows["recorded-task"]["vcpu_hours"], 62 / 3600 * .25)
        invs["campaign-one"]["observed_tasks"][0]["billing_started_at"] = (NOW - timedelta(seconds=10)).isoformat()
        self.assertEqual(cost.priced_tasks(ledger, invs, NOW)[0]["recorded-task"]["billed_seconds_model"], 60)

    def test_missing_live_time_or_unrecorded_task_cannot_establish_accounting(self):
        _, _, ledger, invs, _, _ = fixture()
        ledger["tasks"]["recorded-task"]["last_status"] = "RUNNING"
        self.assertFalse(cost.priced_tasks(ledger, invs, NOW)[1])
        ledger["tasks"]["foreign"] = dict(ledger["tasks"]["recorded-task"])
        with self.assertRaisesRegex(ValueError, "missing_owned_inventory"):
            cost.priced_tasks(ledger, invs, NOW)

    def test_exact_fresh_task_observation_closes_pending_budget_ledger_poll_gap(self):
        _, _, ledger, invs, _, _ = fixture()
        invs["campaign-one"]["task_arns"].append("fresh-recorded-task")
        self.assertFalse(cost.priced_tasks(ledger, invs, NOW)[1])
        observed = {"tasks": [{"task_arn": "fresh-recorded-task", "billing_started_at": (NOW - timedelta(seconds=12)).isoformat(),
                               "cpu": 256, "memory_mib": 1024, "stopped_at": None}]}
        rows, complete = cost.priced_tasks(ledger, invs, NOW, observed)
        self.assertTrue(complete)
        self.assertEqual(rows["fresh-recorded-task"]["billed_seconds_model"], 60)
        self.assertEqual(len(ledger["tasks"]), 1)

    def test_projection_requires_real_full_data_both_distribution_pilots(self):
        args = fixture()
        report = cost.reconcile(*args, now=NOW, throughput=throughput(False))
        self.assertTrue(report["current_spend_accounted"])
        self.assertFalse(report["successful"])
        self.assertIsNone(report["projected_total_conservative_estimate_usd"])
        self.assertFalse(report["actual_bill_reconciled"])
        self.assertEqual(report["measurement"], "inferred")
        report = cost.reconcile(*args, now=NOW, throughput=throughput(True), observations=image_observations())
        self.assertTrue(report["successful"], report["checks"])
        self.assertGreater(report["projected_total_conservative_estimate_usd"], report["current_conservative_planning_estimate_usd"])
        self.assertLess(report["projected_total_conservative_estimate_usd"], 20)
        slow = cost.reconcile(*args, now=NOW, throughput=throughput(True, 600), observations=image_observations())
        self.assertFalse(slow["successful"])
        self.assertFalse(slow["checks"]["cumulative_resource_hours_within_authorization"])

    def test_final_teardown_projection_adds_no_fictitious_future_launches(self):
        report = cost.reconcile(*fixture(), now=NOW, throughput=throughput(False), remaining_cells=0, observations=image_observations())
        self.assertEqual(report["projected_remaining_wall_hours"], 0)
        self.assertEqual(report["current_conservative_planning_estimate_usd"], report["projected_total_conservative_estimate_usd"])

    def test_delayed_zero_billing_never_erases_usage_or_reserves(self):
        normal = cost.reconcile(*fixture(), now=NOW, throughput=throughput())
        delayed = cost.reconcile(*fixture(), now=NOW, throughput=throughput(), observations={"cost_explorer": {"estimated": True, "amount_usd": 0}})
        self.assertEqual(normal["current_conservative_planning_estimate_usd"], delayed["current_conservative_planning_estimate_usd"])
        self.assertGreater(delayed["measured_usage_priced_lower_bound_usd"], 0)

    def test_observed_log_storage_beyond_reserves_increases_projection(self):
        base = cost.reconcile(*fixture(), now=NOW, throughput=throughput(), observations=image_observations())
        big = cost.reconcile(*fixture(), now=NOW, throughput=throughput(), observations={**image_observations(), "logs": [{"incoming_bytes": 10 * 1024 ** 3}]})
        self.assertGreater(big["projected_total_conservative_estimate_usd"], base["projected_total_conservative_estimate_usd"])
        self.assertEqual(big["current_unmetered_service_reserves_usd"]["bounded_masked_logs"], 5)

    def test_proration_uses_each_calendar_month_without_whole_secret_month_charge(self):
        self.assertAlmostEqual(cost.month_fraction(datetime(2026, 11, 1, tzinfo=timezone.utc), datetime(2026, 12, 1, tzinfo=timezone.utc)), 1)
        self.assertAlmostEqual(cost.month_fraction(datetime(2026, 11, 30, 12, tzinfo=timezone.utc), datetime(2026, 12, 1, 12, tzinfo=timezone.utc)), .5 / 30 + .5 / 31)

    def test_all_image_bytes_are_only_a_planning_scenario_and_uplift_is_not_counted_twice(self):
        args = fixture()
        # The task list is the retained launch scope, including failed probes.
        args[3]["campaign-one"]["task_arns"] = [f"owned-{index}" for index in range(45)]
        args[2]["tasks"] = {arn: {"vcpu_hours": 0, "gib_hours": 0, "last_status": "STOPPED"}
                             for arn in args[3]["campaign-one"]["task_arns"]}
        report = cost.reconcile(*args, now=NOW, throughput=throughput(), remaining_cells=321,
            application_launches=17, fault_events=0, observations=image_observations(431_975_960))
        model = report["image_pull_endpoint_planning_envelope"]
        self.assertEqual(model["future_pull_allowance"], 357)
        self.assertEqual(model["current_recorded_task_pull_allowance"], 45)
        self.assertEqual(model["total_image_payload_bytes_envelope"], 402 * 431_975_960)
        self.assertIsNone(model["actual_paid_endpoint_bytes"])
        self.assertIsNone(model["actual_paid_endpoint_cost_usd"])
        self.assertFalse(model["network_bytes_measured"])
        self.assertFalse(model["cache_assumed"])
        self.assertIn("S3 gateway", model["documented_layer_route"])
        self.assertEqual(report["current_unmetered_service_reserves_usd"]["endpoint_data_processing_up_to_30GB"], .3)
        self.assertAlmostEqual(model["incremental_future_reserve_uplift_usd"], 402 * 431_975_960 / 1e9 * .01 - .3)
        # Changing only future pull assumptions changes projection by the uplift
        # delta, without another complete endpoint floor or compute charge.
        less = cost.reconcile(*args, now=NOW, throughput=throughput(), remaining_cells=321,
            application_launches=17, fault_events=0, observations=image_observations(431_975_960), probe_pulls_per_application=0)
        delta = model["incremental_future_reserve_uplift_usd"] - less["image_pull_endpoint_planning_envelope"]["incremental_future_reserve_uplift_usd"]
        self.assertAlmostEqual(report["projected_total_conservative_estimate_usd"] - less["projected_total_conservative_estimate_usd"], delta)

    def test_current_envelope_can_uplift_floor_and_final_zero_future_has_no_double_charge(self):
        args = fixture()
        # One observed 40GB image exceeds the quoted 30GB allowance.
        report = cost.reconcile(*args, now=NOW, throughput=throughput(False), remaining_cells=0,
                                observations=image_observations(40_000_000_000))
        model = report["image_pull_endpoint_planning_envelope"]
        self.assertAlmostEqual(report["current_unmetered_service_reserves_usd"]["endpoint_data_processing_up_to_30GB"], .4)
        self.assertEqual(model["future_pull_allowance"], 0)
        self.assertEqual(model["incremental_future_reserve_uplift_usd"], 0)
        self.assertEqual(report["current_conservative_planning_estimate_usd"], report["projected_total_conservative_estimate_usd"])

    def test_unknown_sizes_block_projection_and_foreign_or_rebound_metadata_is_rejected(self):
        report = cost.reconcile(*fixture(), now=NOW, throughput=throughput())
        self.assertFalse(report["checks"]["image_pull_planning_envelope_available"])
        self.assertFalse(report["checks"]["projected_cost"])
        self.assertIsNone(report["projected_total_conservative_estimate_usd"])
        args = fixture()
        observed = image_observations()
        observed["images"][0]["reference"] = observed["images"][0]["reference"].replace(ACCOUNT, "999999999999")
        with self.assertRaisesRegex(ValueError, "not_in_owned_history"):
            cost.reconcile(*args, now=NOW, throughput=throughput(), observations=observed)
        with self.assertRaisesRegex(ValueError, "metadata_rebound"):
            cost.reconcile(*args, now=NOW, throughput=throughput(), observations=image_observations(), retained_observations=image_observations(1))
        for bad in (True, -1, 0, float("inf")):
            with self.subTest(size=bad), self.assertRaisesRegex(ValueError, "image_size"):
                cost.reconcile(*args, now=NOW, throughput=throughput(), observations=image_observations(bad))

    def test_retained_bound_report_supports_offline_teardown_without_any_sdk(self):
        args = fixture()
        report = cost.reconcile(*args, now=NOW, throughput=throughput(), observations=image_observations())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "retained.json"
            path.write_text(json.dumps(report))
            prior = cost.retained_image_observations(path, cost.file_sha256(path), request=args[0], now=NOW)
            args[3]["campaign-one"]["teardown_complete"] = True
            offline = cost.reconcile(*args, now=NOW, throughput=throughput(False), remaining_cells=0, retained_observations=prior)
            self.assertTrue(offline["image_pull_endpoint_planning_envelope"]["available"])
            self.assertEqual(offline["aws_observations"]["retained_image_observation_reports"][0]["sha256"], cost.file_sha256(path))
            with self.assertRaisesRegex(ValueError, "bound_prior"):
                cost.retained_image_observations(path, "0" * 64, request=args[0], now=NOW)
            changed = deepcopy(report)
            changed["account_id"] = "999999999999"
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "scope_mismatch"):
                cost.retained_image_observations(path, cost.file_sha256(path), request=args[0], now=NOW)

    def test_explicit_future_probe_replacement_assumptions_and_original_caps_are_preserved(self):
        args = fixture()
        report = cost.reconcile(*args, now=NOW, throughput=throughput(), observations=image_observations(),
            application_launches=2, fault_events=3, runtime_pulls_per_application=12, probe_pulls_per_application=9, replacement_pulls_per_fault=2)
        self.assertEqual(report["image_pull_endpoint_planning_envelope"]["future_pull_allowance"], 48)
        self.assertLessEqual(report["projected_total_conservative_estimate_usd"], args[1]["approved_total_usd"])
        self.assertEqual(args[1]["approved_total_usd"], 20)
        self.assertEqual(args[1]["max_cumulative_fleet_hours"], 32)
        for value in (True, -1, 101):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "pull_assumptions"):
                cost.reconcile(*args, now=NOW, throughput=throughput(), observations=image_observations(), probe_pulls_per_application=value)

    def test_readonly_observation_checks_account_before_resource_reads(self):
        request, _, _, inventories, _, _ = fixture()
        clients = {name: Mock() for name in ("sts", "ecs", "cloudwatch", "ec2", "ecr", "ce")}
        clients["sts"].get_caller_identity.return_value = {"Account": "999999999999"}
        with self.assertRaisesRegex(ValueError, "account_mismatch"):
            cost.observe_resources(request, inventories, clients=clients, now=NOW)
        clients["ecs"].describe_tasks.assert_not_called()
        clients["ce"].get_cost_and_usage.assert_not_called()

    def test_sdk_image_size_observation_is_bound_to_exact_owned_account_repository_and_digest(self):
        request, _, _, inventories, _, _ = fixture()
        inv = inventories["campaign-one"]
        inv.update(teardown_complete=True, task_arns=[])
        inv["runtime_contract"]["cluster_arn"] = f"arn:aws:ecs:us-east-1:{ACCOUNT}:cluster/pcfl-test-runtime"
        clients = {name: Mock() for name in ("sts", "ecs", "cloudwatch", "ec2", "ecr", "ce")}
        clients["sts"].get_caller_identity.return_value = {"Account": ACCOUNT}
        image = {"registryId": ACCOUNT, "repositoryName": "pcfl-test/runtime", "imageDigest": "sha256:" + "b" * 64,
                 "imageSizeInBytes": 431_975_960, "imagePushedAt": NOW - timedelta(hours=1)}
        clients["ecr"].describe_images.return_value = {"imageDetails": [image]}
        result = cost.observe_resources(request, inventories, clients=clients, now=NOW)
        clients["ecr"].describe_images.assert_called_once_with(registryId=ACCOUNT, repositoryName="pcfl-test/runtime", imageIds=[{"imageDigest": image["imageDigest"]}])
        self.assertEqual(result["images"][0]["compressed_image_bytes"], 431_975_960)
        self.assertIn("not network", result["images"][0]["basis"])
        for field, replacement in (("registryId", "999999999999"), ("repositoryName", "foreign"), ("imageDigest", "sha256:" + "c" * 64)):
            clients["ecr"].describe_images.return_value = {"imageDetails": [{**image, field: replacement}]}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "binding_mismatch"):
                cost.observe_resources(request, inventories, clients=clients, now=NOW)
        inv["image"]["reference"] = IMAGE.replace(ACCOUNT, "999999999999")
        clients["ecr"].reset_mock()
        with self.assertRaisesRegex(ValueError, "scope_mismatch"):
            cost.observe_resources(request, inventories, clients=clients, now=NOW)
        clients["ecr"].describe_images.assert_not_called()

    def test_raw_pilot_bindings_full_partitions_and_validation_scope_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root, inventories = Path(directory), {"campaign-one": {"campaign_id": "campaign-one", "exports_by_application": {}}}
            manifest = {"partitions": {distribution: {"organizations": {f"org_{i:02d}": {"encounters": 10 + i} for i in range(1, 9)}} for distribution in ("iid", "non_iid")}}
            for distribution in ("iid", "non_iid"):
                export = root / distribution
                export.mkdir()
                case = export / "case"
                case.mkdir()
                result = {"successful": True, "aws_used": True, "scenario_id": "S0", "baseline_id": "P1", "distribution": distribution,
                    "rounds": [{}, {}], "elapsed_seconds": 123, "test_holdout_evaluated": False,
                    "client_training": [{"org_id": org, "round_id": f"round-{number}", "sample_count": sizes["encounters"]}
                                        for org, sizes in manifest["partitions"][distribution]["organizations"].items() for number in (1, 2)]}
                path = case / "runtime_result.json"
                path.write_text(json.dumps(result))
                index = {"campaign_id": distribution, "cases": [{"cell_id": distribution, "successful": True, "artifacts": [{"key": "evidence/" + distribution + "/runtime_result.json", "sha256": cost.file_sha256(path), "size_bytes": path.stat().st_size}]}]}
                index_path = export / "campaign_result.json"
                index_path.write_text(json.dumps(index))
                inventories["campaign-one"]["exports_by_application"][distribution] = {"export_root": str(export), "case_directories": {distribution: str(case)}, "index_sha256": cost.file_sha256(index_path)}
            measured = cost.pilot_throughput(inventories, manifest, 2)
            self.assertTrue(measured["both_distributions_observed"])
            self.assertEqual(len(measured["qualifying_cases"]), 2)
            self.assertFalse(cost.pilot_throughput(inventories, manifest, 5)["both_distributions_observed"])
            path.write_text("tampered")
            with self.assertRaisesRegex(ValueError, "not_bound_to_raw_index"):
                cost.pilot_throughput(inventories, manifest, 2)

    def test_development_distribution_is_bound_to_uploaded_prepared_campaign_not_cell_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"partitions": {"non_iid": {"organizations": {f"org_{i:02d}": {"encounters": i + 10} for i in range(1, 9)}}}}
            runtime = {"persistent_run_id": "run-pinned", "baseline_id": "P1", "distribution": "non_iid", "rounds": 2}
            # The misleading cell name cannot determine the distribution.
            cell = "training-pilot-iid-looking-name"
            prepared = root / "prepared.json"
            prepared.write_text(json.dumps({"campaign_id": "app-one", "cases": [{"cell_id": cell, "runtime": runtime}]}))
            spec = {"kind": "campaign", "key": "metadata/app-one/campaign.json", "source_path": str(prepared), "sha256": cost.file_sha256(prepared)}
            upload = {"bucket": "owned-bucket", "key": spec["key"], "sha256": spec["sha256"], "version_id": "version-pinned"}
            inv = {"campaign_id": "master", "foundation": {"bucket_name": "owned-bucket"}, "uploads": [upload]}
            bound = cost.prepared_pilot_campaigns({"data_uploads": [spec]}, {"master": inv})
            self.assertEqual(bound["app-one"]["cases"][cell]["distribution"], "non_iid")
            result = {"cloud_campaign_id": "app-one", "cell_id": cell, "persistent_run_id": "run-pinned", "baseline_id": "P1", "successful": True,
                "aws_used": True, "scenario_id": "S0", "test_holdout_evaluated": False, "elapsed_seconds": 40, "rounds": [{}, {}],
                "client_training": [{"org_id": org, "round_id": f"round-{number}", "sample_count": sizes["encounters"]}
                    for org, sizes in manifest["partitions"]["non_iid"]["organizations"].items() for number in (1, 2)]}
            path = root / "runtime_result.json"
            index_path = root / "campaign_result.json"
            def retain():
                path.write_text(json.dumps(result))
                index_path.write_text(json.dumps({"campaign_id": "app-one", "cases": [{"cell_id": cell, "successful": True,
                    "artifacts": [{"key": "evidence/app-one/runtime_result.json", "sha256": cost.file_sha256(path), "size_bytes": path.stat().st_size}]}]}))
                inv["export"] = {"application_campaign_id": "app-one", "export_root": str(root), "case_directories": {cell: str(root)}, "index_sha256": cost.file_sha256(index_path)}
            retain()
            measured = cost.pilot_throughput({"master": inv}, manifest, 2, bound)
            self.assertEqual(measured["qualifying_cases"][0]["distribution"], "non_iid")
            self.assertEqual(measured["qualifying_cases"][0]["prepared_campaign_uploaded_versions"], [upload])
            self.assertFalse(cost.pilot_throughput({"master": inv}, manifest, 2)["qualifying_cases"])
            result["persistent_run_id"] = "unrelated-run"
            retain()
            with self.assertRaisesRegex(ValueError, "runtime_result_binding_mismatch"):
                cost.pilot_throughput({"master": inv}, manifest, 2, bound)
            prepared.write_text("changed")
            with self.assertRaisesRegex(ValueError, "source_changed"):
                cost.prepared_pilot_campaigns({"data_uploads": [spec]}, {"master": inv})

    def test_legitimate_connectivity_round_budget_is_ignored_before_full_pilot_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"partitions": {"iid": {"organizations": {f"org_{i:02d}": {"encounters": 10 + i} for i in range(1, 9)}}}}
            cell, application, run = "connectivity-P1-S0-296", "initial-connectivity", "run-original"
            result = {"cloud_campaign_id": application, "cell_id": cell, "persistent_run_id": run, "baseline_id": "P1",
                "successful": True, "aws_used": True, "scenario_id": "S0", "test_holdout_evaluated": False,
                "elapsed_seconds": 30, "rounds": [{}], "client_training": []}
            runtime = {"persistent_run_id": run, "baseline_id": "P1", "distribution": "iid", "rounds": 1}
            path, index = root / "runtime_result.json", root / "campaign_result.json"
            def retain():
                path.write_text(json.dumps(result))
                index.write_text(json.dumps({"campaign_id": application, "cases": [{"cell_id": cell, "successful": True,
                    "artifacts": [{"key": "evidence/initial/runtime_result.json", "sha256": cost.file_sha256(path), "size_bytes": path.stat().st_size}]}]}))
                return {"campaign_id": "master", "application_campaign_id": "current-partial-app",
                    "export": {"application_campaign_id": application, "export_root": str(root), "case_directories": {cell: str(root)}, "index_sha256": cost.file_sha256(index)},
                    "operator_recoveries": [{"application_campaign_id": "current-partial-app", "recovery_id": "recovery-real", "campaign_successful": False}]}
            prepared = {application: {"cases": {cell: runtime}, "source": {"sha256": "a" * 64}, "uploaded_versions": []}}
            inventory = retain()
            report = cost.pilot_throughput({"master": inventory}, manifest, 5, prepared)
            self.assertEqual(report["qualifying_cases"], [])
            self.assertFalse(report["both_distributions_observed"])
            self.assertEqual(len(report["ignored_cases"]), 2)
            self.assertTrue(any("operator_partial_recovery" in row["reason"] for row in report["ignored_cases"]))
            # The qualification fix must not hide a contradictory completed
            # producer result or permit a different run to reuse the metadata.
            result["rounds"] = [{}, {}]
            inventory = retain()
            with self.assertRaisesRegex(ValueError, "round_count_mismatch"):
                cost.pilot_throughput({"master": inventory}, manifest, 5, prepared)
            result["rounds"], result["persistent_run_id"] = [{}], "different-run"
            inventory = retain()
            with self.assertRaisesRegex(ValueError, "runtime_result_binding_mismatch"):
                cost.pilot_throughput({"master": inventory}, manifest, 5, prepared)


if __name__ == "__main__":
    unittest.main()
