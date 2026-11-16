"""Staged resume/read-retry regressions. All SDK calls are mocked."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "scripts/aws_campaign.py").is_file())
sys.path.insert(0, str(ROOT / "scripts"))
candidate = Path(__file__).with_name("aws_campaign.py")
source = candidate if candidate.is_file() else ROOT / "scripts/aws_campaign.py"
spec = importlib.util.spec_from_file_location("host_resume_campaign", source)
campaign = importlib.util.module_from_spec(spec); spec.loader.exec_module(campaign)

from botocore.exceptions import ClientError, EndpointConnectionError


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
        account, region, project, application = "123456789012", "us-east-1", "pcfl-test", "application-existing"
        auth = Path(directory) / "approval.json"
        approval = {"approved": True, "source": "user-conversation", "authorization_scope": campaign.SCOPE,
            "account_id": account, "region": region, "approved_total_usd": 20, "max_cumulative_fleet_hours": 32,
            "max_vcpu": 4, "max_memory_gib": 14, "per_deployment_max_hours": 24}
        auth.write_text(json.dumps(approval))
        request = {"account_id": account, "region": region, "project_id": project, "campaign_id": "campaign-one",
            "application_campaign_id": application, "preparation_stage": "development-pilot",
            "authorization": {"path": str(auth), "sha256": campaign.file_sha256(auth)}, "data_uploads": []}
        clients = {name: Mock() for name in ("sts", "ecs", "ecr", "servicediscovery", "dynamodb")}
        clients["sts"].get_caller_identity.return_value = {"Account": account}
        runner = campaign.CampaignRunner(request, apply=True, clients=clients, sleep=Mock())
        runner.approval = approval
        cluster = f"arn:aws:ecs:{region}:{account}:cluster/{project}-runtime"
        task = cluster.replace(":cluster/", ":task/") + "/" + "a" * 32
        definition = f"arn:aws:ecs:{region}:{account}:task-definition/{project}-runtime-coordinator:5"
        role = f"arn:aws:iam::{account}:role/{project}-coordinator"
        repository = f"{account}.dkr.ecr.{region}.amazonaws.com/{project}/coordinator"
        image_manifest = json.dumps({"schemaVersion": 2, "config": {"digest": "sha256:" + "b" * 64}})
        image_digest = "sha256:" + hashlib.sha256(image_manifest.encode()).hexdigest()
        image = repository + "@" + image_digest
        discovery = {"ServiceId": "srv-recorded", "InstanceId": "campaign-" + hashlib.sha256(application.encode()).hexdigest()[:24]}
        runner.inventory.update(application_campaign_id=application, task_arns=[task],
            foundation={"bucket_name": f"{project}-{account}-{region}", "state_table_name": "owned-table", "image_repositories": {"coordinator": repository}},
            runtime_contract={"cluster_arn": cluster, "task_definition_arns": {"coordinator": definition},
                "task_role_arns": {"coordinator": role}, "discovery_service_ids": {"coordinator": "srv-recorded"}, "service_names": {}},
            task_definition_history={definition: {"name": "coordinator", "task_role_arn": role,
                "containers": [{"name": "coordinator", "image": image}], "container_commands": {"coordinator": ["coordinator"]}}},
            secret_versions={"coordinator-config": {"version_id": "recorded-secret-version", "sha256": "c" * 64}},
            runtime_variables={"hard_expiry_utc": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()},
            image={"reference": image}, discovery_instance=discovery)
        runner.inventory["runtime_generation"] = runner.expected_generation()
        definition_body = {"taskDefinitionArn": definition, "taskRoleArn": role,
            "runtimePlatform": {"cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX"},
            "containerDefinitions": [{"name": "coordinator", "image": image, "command": ["coordinator"]}]}
        raw = {"taskArn": task, "clusterArn": cluster, "taskDefinitionArn": definition, "launchType": "FARGATE",
            "lastStatus": "RUNNING", "cpu": "1024", "memory": "2048", "createdAt": datetime.now(timezone.utc),
            "containers": [{"name": "coordinator", "image": image, "imageDigest": image_digest}],
            "overrides": {}, "tags": [{"key": key, "value": value} for key, value in {"Project": project, "Stage": "runtime",
                "Campaign": "campaign-one", "ApplicationCampaign": application, "RuntimeGeneration": runner.expected_generation()}.items()],
            "attachments": [{"type": "ElasticNetworkInterface", "details": [{"name": "privateIPv4Address", "value": "10.0.1.10"}]}]}
        clients["ecs"].describe_task_definition.return_value = {"taskDefinition": definition_body}
        clients["ecs"].describe_tasks.return_value = {"tasks": [raw], "failures": []}
        clients["ecr"].batch_get_image.return_value = {"images": [{"imageManifest": image_manifest}]}
        clients["servicediscovery"].get_instance.return_value = {"Instance": {"Id": discovery["InstanceId"],
            "Attributes": {"AWS_INSTANCE_IPV4": "10.0.1.10", "AWS_INSTANCE_PORT": "9092"}}}
        runner.start_task = Mock(side_effect=AssertionError("resume_must_not_launch_a_fresh_fleet"))
        def stopped(): runner.inventory["shutdown_confirmation"] = {"confirmed": True}
        runner.stop_recorded = Mock(side_effect=stopped)
        yield runner, clients, raw, definition_body


class HostResumeTests(unittest.TestCase):
    def test_exact_existing_job_uses_budget_restart_watch_and_final_shutdown_without_fleet_launch(self):
        with fixture() as (runner, clients, raw, definition):
            arn = raw["taskArn"]
            running = {"task_arn": arn, "last_status": "RUNNING", "container_exit_codes": [None]}
            stopped = {**running, "last_status": "STOPPED", "container_exit_codes": [0]}
            runner.budget_check = Mock(side_effect=[[running], [stopped]])
            runner.request["host_restarts"] = [{"request_id": "bounded-restart-existing"}]
            def acknowledge(*args):
                runner.inventory.setdefault("client_restart_events", {})["bounded-restart-existing"] = {"control_acknowledged": {"status": "ACKNOWLEDGED"}}
            with patch("cloud_faults.handle_client_restarts", side_effect=acknowledge) as restart:
                result = runner.resume_campaign(arn)
            self.assertTrue(result["campaign_job_completed"])
            self.assertEqual(result["coordinator_task_arn"], arn)
            self.assertEqual(runner.budget_check.call_count, 2)
            self.assertEqual(restart.call_count, 2)
            runner.start_task.assert_not_called()
            clients["ecs"].run_task.assert_not_called()
            clients["ecs"].update_service.assert_not_called()
            clients["servicediscovery"].register_instance.assert_not_called()
            runner.stop_recorded.assert_called_once()
            self.assertEqual(runner.inventory["host_resume_sessions"][0]["runtime_generation"], runner.expected_generation())

    def test_foreign_or_changed_task_definition_image_application_generation_role_and_discovery_never_attach_or_stop(self):
        for mode in ("unrecorded", "cluster", "definition", "image", "digest", "application", "generation", "role", "command", "account", "discovery"):
            with self.subTest(mode=mode), fixture() as (runner, clients, raw, definition):
                arn = raw["taskArn"]
                if mode == "unrecorded": runner.inventory["task_arns"] = []
                elif mode == "cluster": raw["clusterArn"] = "other-cluster"
                elif mode == "definition": raw["taskDefinitionArn"] += "9"
                elif mode == "image": raw["containers"][0]["image"] = "unrelated-image"
                elif mode == "digest": raw["containers"][0]["imageDigest"] = "sha256:" + "f" * 64
                elif mode == "application": next(row for row in raw["tags"] if row["key"] == "ApplicationCampaign")["value"] = "another-application"
                elif mode == "generation": runner.inventory["secret_versions"]["coordinator-config"]["version_id"] = "new-version"
                elif mode == "role": definition["taskRoleArn"] = "foreign-role"
                elif mode == "command": raw["overrides"] = {"containerOverrides": [{"name": "coordinator", "command": ["operator"]}]}
                elif mode == "account": clients["sts"].get_caller_identity.return_value = {"Account": "999999999999"}
                else: clients["servicediscovery"].get_instance.return_value["Instance"]["Attributes"]["AWS_INSTANCE_IPV4"] = "10.0.1.99"
                with self.assertRaises(ValueError): runner.resume_campaign(arn)
                runner.stop_recorded.assert_not_called()
                runner.start_task.assert_not_called()
                clients["ecs"].run_task.assert_not_called()
                clients["ecs"].stop_task.assert_not_called()

    def test_terminal_execution_failure_is_not_retried_or_converted_to_success_and_secondary_shutdown_is_retained(self):
        with fixture() as (runner, clients, raw, definition):
            runner.budget_check = Mock(return_value=[{"task_arn": raw["taskArn"], "last_status": "STOPPED", "container_exit_codes": [1]}])
            runner.stop_recorded.side_effect = LookupError("synthetic-shutdown-failure")
            runner.inventory["shutdown_confirmation"] = {"confirmed": True, "from_prior_invocation": True}
            with self.assertRaisesRegex(RuntimeError, "coordinator_job_failed") as raised:
                runner.resume_campaign(raw["taskArn"])
            self.assertIn("shutdown remains unconfirmed", " ".join(raised.exception.__notes__))
            self.assertIsInstance(raised.exception.shutdown_error, LookupError)
            self.assertFalse(runner.inventory["shutdown_confirmation"]["confirmed"])
            retained = runner.inventory["host_lifecycle_failures"][-1]
            self.assertEqual(retained["primary_error"]["reason_code"], "coordinator_job_failed_evidence_collection_required")
            self.assertEqual(retained["shutdown_error"]["error_type"], "LookupError")
            self.assertEqual(runner.budget_check.call_count, 1)
            runner.stop_recorded.assert_called_once()

    def test_successful_coordinator_with_failed_shutdown_does_not_return_success(self):
        with fixture() as (runner, clients, raw, definition):
            runner.budget_check = Mock(return_value=[{"task_arn": raw["taskArn"], "last_status": "STOPPED", "container_exit_codes": [0]}])
            failure = EndpointConnectionError(endpoint_url="https://synthetic.invalid")
            runner.stop_recorded.side_effect = failure
            with self.assertRaises(EndpointConnectionError) as raised: runner.resume_campaign(raw["taskArn"])
            self.assertIs(raised.exception, failure)
            self.assertFalse(runner.inventory["shutdown_confirmation"]["confirmed"])
            self.assertIsNone(runner.inventory["host_lifecycle_failures"][-1]["primary_error"])

    def test_missing_coordinator_and_resource_cap_fail_without_claiming_stopped(self):
        for mode in ("missing", "budget"):
            with self.subTest(mode=mode), fixture() as (runner, clients, raw, definition):
                runner.budget_check = Mock(return_value=[])
                if mode == "budget": runner.budget_check.side_effect = RuntimeError("campaign_resource_or_duration_budget_exhausted")
                with self.assertRaisesRegex(RuntimeError, "unconfirmed|budget_exhausted"): runner.resume_campaign(raw["taskArn"])
                runner.stop_recorded.assert_called_once()
                runner.start_task.assert_not_called()

    def test_already_stopped_exact_job_can_finish_without_recreating_missing_discovery(self):
        with fixture() as (runner, clients, raw, definition):
            raw["lastStatus"] = "STOPPED"
            raw["containers"][0]["exitCode"] = 0
            runner.inventory.pop("discovery_instance")
            runner.budget_check = Mock(return_value=[{"task_arn": raw["taskArn"], "last_status": "STOPPED", "container_exit_codes": [0]}])
            self.assertTrue(runner.resume_campaign(raw["taskArn"])["campaign_job_completed"])
            clients["servicediscovery"].get_instance.assert_not_called()
            clients["servicediscovery"].register_instance.assert_not_called()
            runner.start_task.assert_not_called()
            runner.stop_recorded.assert_called_once()

    def test_resume_defaults_to_zero_api_plan_and_apply_requires_bound_existing_task(self):
        with fixture() as (runner, clients, raw, definition):
            runner.apply = False
            self.assertFalse(runner.execute("resume")["mutations_enabled"])
            clients["sts"].get_caller_identity.assert_not_called()
            runner.apply = True
            with self.assertRaisesRegex(ValueError, "exact_recorded"):
                runner.execute("resume", coordinator_task_arn=None)
            runner.stop_recorded.assert_not_called()
            runner.start_task.assert_not_called()


class ReadRetryTests(unittest.TestCase):
    def test_resumed_real_budget_observation_recovers_a_transient_ecs_read_and_accounts_stopped_usage(self):
        with fixture() as (runner, clients, raw, definition):
            raw["lastStatus"] = "STOPPED"
            raw["createdAt"] = datetime.now(timezone.utc) - timedelta(seconds=30)
            raw["stoppedAt"] = datetime.now(timezone.utc)
            raw["containers"][0]["exitCode"] = 0
            failure = EndpointConnectionError(endpoint_url="https://synthetic.invalid")
            clients["ecs"].list_tasks.side_effect = [failure, {"taskArns": []}, {"taskArns": [raw["taskArn"]]}]
            result = runner.resume_campaign(raw["taskArn"])
            self.assertTrue(result["campaign_job_completed"])
            self.assertEqual(len(runner.inventory["transient_read_failures"]), 1)
            self.assertGreaterEqual(runner.inventory["fleet_ledger"][raw["taskArn"]]["billed_duration_lower_bound_seconds"], 60)
            self.assertEqual(clients["ecs"].list_tasks.call_count, 3)
            clients["ecs"].run_task.assert_not_called()

    def test_transient_read_retry_recovers_with_finite_backoff_and_preserves_mutation_single_call(self):
        with fixture() as (runner, clients, raw, definition):
            failure = EndpointConnectionError(endpoint_url="https://synthetic.invalid")
            clients["ecs"].list_tasks.side_effect = [failure, failure, {"taskArns": []}]
            sdk = runner.sdk()
            self.assertEqual(sdk["ecs"].list_tasks(cluster="owned"), {"taskArns": []})
            self.assertEqual(runner.sleep.call_args_list, [call(1), call(2)])
            self.assertEqual(len(runner.inventory["transient_read_failures"]), 2)
            runner.sleep.reset_mock()
            clients["ecs"].run_task.side_effect = failure
            with self.assertRaises(EndpointConnectionError): sdk["ecs"].run_task(cluster="owned")
            clients["ecs"].run_task.assert_called_once()
            runner.sleep.assert_not_called()

    def test_read_exhaustion_rethrows_original_after_six_attempts_without_asserting_shutdown(self):
        with fixture() as (runner, clients, raw, definition):
            failure = EndpointConnectionError(endpoint_url="https://synthetic.invalid")
            clients["ecs"].describe_tasks.side_effect = failure
            with self.assertRaises(EndpointConnectionError) as raised: runner.sdk()["ecs"].describe_tasks(cluster="owned", tasks=["exact"])
            self.assertIs(raised.exception, failure)
            self.assertEqual(clients["ecs"].describe_tasks.call_count, 6)
            self.assertEqual(runner.sleep.call_args_list, [call(1), call(2), call(4), call(8), call(16)])
            self.assertFalse(runner.inventory["transient_read_failures"][-1]["retry_planned"])
            self.assertNotIn("shutdown_confirmation", runner.inventory)

    def test_throttling_is_retried_but_access_denial_and_execution_errors_are_not(self):
        with fixture() as (runner, clients, raw, definition):
            throttled = ClientError({"Error": {"Code": "ThrottlingException"}}, "DescribeTasks")
            clients["ecs"].describe_tasks.side_effect = [throttled, {"tasks": []}]
            self.assertEqual(runner.sdk()["ecs"].describe_tasks(), {"tasks": []})
            self.assertEqual(clients["ecs"].describe_tasks.call_count, 2)
            for error in (ClientError({"Error": {"Code": "AccessDeniedException"}}, "DescribeTasks"), RuntimeError("coordinator_job_failed_evidence_collection_required")):
                clients["ecs"].describe_tasks.reset_mock(); runner.sleep.reset_mock()
                clients["ecs"].describe_tasks.side_effect = error
                with self.assertRaises(type(error)): runner.sdk()["ecs"].describe_tasks()
                clients["ecs"].describe_tasks.assert_called_once()
                runner.sleep.assert_not_called()

    def test_launch_primary_and_sts_shutdown_dns_failures_are_both_preserved(self):
        with fixture() as (runner, clients, raw, definition):
            primary = EndpointConnectionError(endpoint_url="https://primary.synthetic.invalid")
            shutdown = EndpointConnectionError(endpoint_url="https://shutdown.synthetic.invalid")
            clients["sts"].get_caller_identity.side_effect = [primary] * 6 + [shutdown] * 6
            runner.stop_recorded = campaign.CampaignRunner.stop_recorded.__get__(runner)
            runner.inventory["shutdown_confirmation"] = {"confirmed": True, "from_prior_invocation": True}
            with self.assertRaises(EndpointConnectionError) as raised: runner.run_campaign()
            self.assertIs(raised.exception, primary)
            self.assertIs(raised.exception.shutdown_error, shutdown)
            self.assertEqual(clients["sts"].get_caller_identity.call_count, 12)
            self.assertFalse(runner.inventory["shutdown_confirmation"]["confirmed"])
            self.assertEqual(runner.inventory["host_lifecycle_failures"][-1]["primary_error"]["error_type"], "EndpointConnectionError")
            self.assertEqual(runner.inventory["host_lifecycle_failures"][-1]["shutdown_error"]["error_type"], "EndpointConnectionError")
            clients["ecs"].update_service.assert_not_called()
            clients["ecs"].run_task.assert_not_called()


if __name__ == "__main__": unittest.main()
