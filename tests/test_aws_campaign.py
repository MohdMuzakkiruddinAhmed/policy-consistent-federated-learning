"""Campaign safety/recovery contracts; every cloud/process boundary is mocked."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import aws_campaign as campaign
import cloud_io


class AtomicInventoryWriteTests(unittest.TestCase):
    def test_transient_file_lock_keeps_old_inventory_until_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.json"
            campaign.write_json(path, {"version": 1})
            original, calls = campaign.os.replace, []
            def replace(source, destination):
                calls.append(1)
                if len(calls) <= 2:
                    self.assertEqual(json.loads(path.read_text()), {"version": 1})
                    raise PermissionError("synthetic_transient_windows_lock")
                return original(source, destination)
            with patch.object(campaign.os, "replace", side_effect=replace), patch.object(campaign.time, "sleep"):
                campaign.write_json(path, {"version": 2})
            self.assertEqual(len(calls), 3)
            self.assertEqual(json.loads(path.read_text()), {"version": 2})

    def test_permanent_file_lock_is_bounded_and_never_reports_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.json"
            campaign.write_json(path, {"version": 1})
            with (patch.object(campaign.os, "replace", side_effect=PermissionError("permanent_lock")) as replace,
                  patch.object(campaign.time, "sleep")):
                with self.assertRaises(PermissionError):
                    campaign.write_json(path, {"version": 2})
            self.assertEqual(replace.call_count, 6)
            self.assertEqual(json.loads(path.read_text()), {"version": 1})


def approval():
    return {"approved": True, "source": "user-conversation", "authorization_scope": campaign.SCOPE,
        "account_id": "123456789012", "region": "us-east-1", "approved_total_usd": 20,
        "max_cumulative_fleet_hours": 32, "max_vcpu": 4, "max_memory_gib": 14, "per_deployment_max_hours": 24}


def request(directory, name="campaign-one"):
    directory = Path(directory)
    auth = directory / "authorization.json"
    auth.write_text(json.dumps(approval()), encoding="utf-8")
    return {"schema_version": "0.1", "account_id": "123456789012", "region": "us-east-1", "project_id": "pcfl-test",
        "campaign_id": name, "namespace": "pcfl-test.internal", "foundation_vars": str(directory / "foundation.json"),
        "runtime_vars": str(directory / "runtime.json"), "local_image_tag": "pcfl-runtime:0.1.0",
        "authorization": {"path": str(auth), "sha256": cloud_io.file_sha256(auth)}, "data_uploads": [], "secrets": []}


def clients():
    result = {name: Mock() for name in ("sts", "s3", "dynamodb", "ecr", "ecs", "ec2", "servicediscovery", "secretsmanager", "logs")}
    result["sts"].get_caller_identity.return_value = {"Account": "123456789012"}
    return result


def contract():
    return {"cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/pcfl-test-runtime",
        "task_definition_arns": {"org_01": "arn:aws:ecs:us-east-1:123456789012:task-definition/pcfl-test-org_01:1"},
        "subnet_ids": ["subnet-0123456789abcdef0"], "security_group_ids": {"org_01": "sg-0123456789abcdef0"}, "service_names": {}}


def stopped_task():
    now = datetime.now(timezone.utc)
    return {"taskArn": "arn:aws:ecs:us-east-1:123456789012:task/pcfl-test-runtime/" + "a" * 32,
        "taskDefinitionArn": contract()["task_definition_arns"]["org_01"], "lastStatus": "STOPPED", "cpu": "4096", "memory": "14336",
        "startedAt": now - timedelta(hours=2), "stoppedAt": now, "containers": [{"exitCode": 0}],
        "attachments": [{"type": "ElasticNetworkInterface", "details": [{"name": "privateIPv4Address", "value": "10.73.1.25"}]}]}


def recovered_producer_fixture(runner):
    """Original producer bytes are retained under hash names, not export names."""
    application, bucket = "campaign-one-aborted", "own-test"
    records, cases = [], []
    def retain(key, document, version):
        body = json.dumps(document, sort_keys=True).encode()
        digest = hashlib.sha256(body).hexdigest()
        path = runner.directory / "r/abort-case/v" / (digest[:16] + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        record = {"bucket": bucket, "key": key, "version_id": version, "sha256": digest,
            "size_bytes": len(body), "local_path": str(path)}
        records.append(record)
        return record
    for number in range(5):
        cell, run = "synthetic-cell-" + str(number), "synthetic-completed-run-" + str(number)
        pointer = {"PK": "RUN#" + run, "SK": "POINTER", "manifest_id": str(number) * 64, "commit_order": 10 + number}
        raw = {"persistent_run_id": run, "successful": True,
            "durable_evidence": {"run_records": [pointer], "sequence": {"order": 20 + number}}}
        ref = retain(f"evidence/campaigns/{application}/{cell}/runtime_result.json", raw, "raw-v" + str(number))
        cases.append({"cell_id": cell, "artifacts": [{key: ref[key] for key in ("bucket", "key", "version_id", "sha256", "size_bytes")}]})
    index = retain(f"evidence/campaigns/{application}/index-0004.json", {"campaign_id": application, "successful": False, "cases": cases}, "index-v1")
    recovery = {"kind": "registered-operator-partial-cloud-recovery", "application_campaign_id": application,
        "orphan_discovery_complete": True, "campaign_successful": False, "status": "operator-aborted-development",
        "source_index": deepcopy(index), "operator_observations": []}
    runner.inventory.update(foundation={"bucket_name": bucket, "state_table_name": "own-table", "image_repositories": {}},
        retained_artifact_versions=records, operator_recoveries=[recovery])
    return recovery, records


def explicit_zero_secret_fixture(runner):
    """No secret authority in this synthetic teardown fixture, in all sources."""
    assert runner.request["secrets"] == []
    runtime = runner.inventory.setdefault("runtime_contract", {})
    assert runtime.get("secret_arns", {}) == {}
    runtime["secret_arns"] = {}
    runner.inventory["secret_versions"] = {}
    current = runner.directory / "state/runtime.tfstate"
    before = runner.directory / "state/runtime-before-destroy.json"
    campaign.write_json(current, {"version": 4, "lineage": "explicit-zero-secret-fixture", "serial": 2, "resources": []})
    campaign.write_json(before, {"version": 4, "lineage": "explicit-zero-secret-fixture", "serial": 1, "resources": []})
    runner.inventory.setdefault("state_paths", {})["runtime"] = str(current)
    runner.inventory.setdefault("pre_teardown_state_snapshots", {})["runtime"] = {
        "path": str(before), "sha256": cloud_io.file_sha256(before)}
    runner.inventory["shutdown_confirmation"] = {"confirmed": True, "unresolved_task_arns": [], "uncertain_launch_tokens": []}
    runner.inventory["shared_fleet_ledger"] = {arn: {"last_status": "STOPPED"} for arn in runner.inventory.get("task_arns", [])}


class CampaignTests(unittest.TestCase):
    def test_default_plan_and_unapplied_stages_make_no_aws_calls(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            runner = campaign.CampaignRunner(request(directory), clients=aws)
            for stage in ("plan", "bootstrap", "publish-inputs", "register-runtime", "run", "probe", "teardown"):
                self.assertFalse(runner.execute(stage)["mutations_enabled"])
            self.assertFalse((Path(directory) / "results").exists())
            aws["sts"].get_caller_identity.assert_not_called()
            aws["s3"].put_object.assert_not_called()

    def test_new_approval_scope_target_and_finite_limits_required(self):
        with tempfile.TemporaryDirectory() as directory:
            base = request(directory)
            self.assertEqual(campaign.validate_authorization(base)["approved_total_usd"], 20)
            for change in ({"approved": False}, {"authorization_scope": "first-smoke-test-total"},
                           {"account_id": "999999999999"}, {"approved_total_usd": 21},
                           {"max_cumulative_fleet_hours": 33}, {"max_vcpu": 8}, {"max_memory_gib": 15},
                           {"per_deployment_max_hours": 25}, {"approved_total_usd": float("inf")}):
                path = Path(directory) / "bad.json"
                path.write_text(json.dumps({**approval(), **change}), encoding="utf-8")
                changed = {**base, "authorization": {"path": str(path), "sha256": cloud_io.file_sha256(path)}}
                with self.subTest(change=change), self.assertRaises(ValueError):
                    campaign.validate_authorization(changed)
            Path(base["authorization"]["path"]).write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest_mismatch"):
                campaign.validate_authorization(base)

    def test_application_namespace_validation_and_generation_do_not_change_owner(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            value = request(directory)
            runner = campaign.CampaignRunner(value)
            runner.inventory.update(runtime_contract=contract(), secret_versions={"coordinator-config": {"version_id": "v1", "sha256": "a" * 64}})
            initial = runner.generation()
            self.assertEqual(initial, runner.generation())
            value["application_campaign_id"] = "campaign-one-training-pilot-iid"
            self.assertNotEqual(initial, runner.generation())
            self.assertEqual(runner.inventory["campaign_id"], "campaign-one")
            self.assertEqual(runner.inventory["application_campaign_id"], value["application_campaign_id"])
            self.assertEqual(runner.directory, Path(directory) / "results/aws/campaign-one")
            path = Path(directory) / "request.json"
            for invalid in ("../another", "", None, "a" * 82):
                path.write_text(json.dumps({**value, "application_campaign_id": invalid}), encoding="utf-8")
                with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "application_campaign_identity"):
                    campaign.load_request(path)

    def test_wrong_account_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            aws["sts"].get_caller_identity.return_value = {"Account": "999999999999"}
            runner = campaign.CampaignRunner(request(directory), apply=True, clients=aws)
            with self.assertRaisesRegex(ValueError, "account_mismatch"):
                runner.sdk()
            aws["s3"].put_object.assert_not_called()

    def test_emergency_cleanup_does_not_require_current_build_reports_but_checks_owned_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            runner = campaign.CampaignRunner(request(directory), apply=True)
            self.assertEqual(runner.authorize(cleanup=True)["approved_total_usd"], 20)
            runner.inventory["state_paths"] = {"runtime": str(Path(directory) / "other.tfstate")}
            with self.assertRaisesRegex(ValueError, "owned_campaign"):
                runner.authorize(cleanup=True)
            state = runner.directory / "state/runtime.tfstate"
            campaign.write_json(state, {"resources": [{"instances": [{"attributes": {"tags_all": {"Project": "unrelated-project"}}}]}]})
            runner.inventory["state_paths"] = {"runtime": str(state)}
            with self.assertRaisesRegex(ValueError, "other_project"):
                runner.authorize(cleanup=True)

    def test_terraform_state_data_and_plan_are_isolated_per_campaign(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)), patch.object(campaign, "RUNTIME_CACHE_ROOT", Path(directory) / "cache"):
            run = Mock(return_value=SimpleNamespace(returncode=0, stdout="{}", stderr=""))
            one = campaign.CampaignRunner(request(directory, "campaign-one"), apply=True, run=run)
            one.terraform_step("foundation", {"synthetic": "metadata-only"})
            two = campaign.CampaignRunner(request(directory, "campaign-two"), apply=True, run=run)
            two.terraform_step("foundation", {"synthetic": "metadata-only"})
            init = [call for call in run.call_args_list if "init" in call.args[0]]
            self.assertEqual(len(init), 2)
            paths = [next(value for value in call.args[0] if value.startswith("-backend-config=path=")) for call in init]
            self.assertNotEqual(paths[0], paths[1])
            self.assertIn("campaign-one", paths[0])
            self.assertIn("campaign-two", paths[1])
            self.assertNotEqual(init[0].kwargs["env"]["TF_DATA_DIR"], init[1].kwargs["env"]["TF_DATA_DIR"])
            self.assertTrue(all("-reconfigure" in call.args[0] for call in init))
            self.assertFalse((Path(directory) / "infra/terraform/terraform.tfstate").exists())

    def test_existing_bucket_cannot_be_adopted_into_fresh_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            target = request(directory)
            Path(target["runtime_vars"]).write_text(json.dumps({"expected_account_id": target["account_id"],
                "aws_region": target["region"], "project_id": target["project_id"],
                "hard_expiry_utc": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}))
            runner = campaign.CampaignRunner(target, apply=True, clients=clients())
            runner.approval = approval()
            with patch.object(runner, "terraform_step") as terraform, self.assertRaisesRegex(ValueError, "preexisting_bucket"):
                runner.bootstrap()
            terraform.assert_not_called()

    def test_launch_refuses_concurrency_over_4_cpu_14_gib(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            runner = campaign.CampaignRunner(request(directory), apply=True, clients=aws)
            runner.approval = approval()
            runner.inventory.update(runtime_contract=contract(), runtime_plan={"task_definitions": {"org_01": {"cpu": "256", "memory": "1024"}}},
                runtime_variables={"hard_expiry_utc": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()})
            live = [{"task_arn": "existing", "last_status": "RUNNING", "cpu": 4096, "memory_mib": 14336}]
            with patch.object(runner, "observed_tasks", return_value=live), self.assertRaisesRegex(RuntimeError, "budget_exhausted"):
                runner.start_task("org_01")
            aws["ecs"].run_task.assert_not_called()

    def test_fleet_ledger_does_not_reset_for_new_campaign(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            aws["ecs"].list_tasks.return_value = {"taskArns": [stopped_task()["taskArn"]]}
            aws["ecs"].describe_tasks.return_value = {"tasks": [stopped_task()]}
            aws["ecs"].describe_task_definition.return_value = {"taskDefinition": {"taskRoleArn": "arn:aws:iam::123456789012:role/pcfl-org_01"}}
            one = campaign.CampaignRunner(request(directory, "campaign-one"), apply=True, clients=aws)
            one.inventory["runtime_contract"] = contract()
            one.observed_tasks()
            aws["ecs"].list_tasks.return_value = {"taskArns": []}
            aws["ecs"].describe_tasks.return_value = {"tasks": []}
            two = campaign.CampaignRunner(request(directory, "campaign-two"), apply=True, clients=aws)
            two.approval = {**approval(), "max_cumulative_fleet_hours": 1}
            two.inventory.update(runtime_contract=contract(), runtime_variables={"hard_expiry_utc": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()})
            with self.assertRaisesRegex(RuntimeError, "budget_exhausted"):
                two.budget_check()

    def test_task_definition_history_keeps_prior_actual_registered_revisions(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            task = stopped_task()
            aws["ecs"].list_tasks.return_value = {"taskArns": [task["taskArn"]]}
            aws["ecs"].describe_tasks.return_value = {"tasks": [task]}
            runner = campaign.CampaignRunner(request(directory), clients=aws)
            current = contract()
            current["task_definition_arns"]["org_01"] = current["task_definition_arns"]["org_01"].removesuffix(":1") + ":2"
            runner.inventory.update(runtime_contract=current, task_definition_history={task["taskDefinitionArn"]: {"task_role_arn": "arn:aws:iam::123456789012:role/pcfl-org_01", "container_commands": {"org_01": ["client"]}}})
            evidence = runner.observed_tasks()
            self.assertEqual(evidence[0]["task_definition_arn"], task["taskDefinitionArn"])
            aws["ecs"].describe_task_definition.assert_not_called()

    def test_expired_stopped_description_never_blocks_shutdown_or_erases_billing_history(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws, sleeper = clients(), Mock()
            task = stopped_task()
            task["stoppedAt"] -= timedelta(hours=2)
            task["startedAt"] = task["stoppedAt"] - timedelta(minutes=10)
            prior = cloud_io.task_evidence(task, "123456789012", "us-east-1", contract()["cluster_arn"])
            arn = prior["task_arn"]
            aws["ecs"].list_tasks.return_value = {"taskArns": []}
            aws["ecs"].describe_tasks.return_value = {"tasks": [], "failures": [{"arn": arn, "reason": "MISSING"}]}
            runner = campaign.CampaignRunner(request(directory), clients=aws, sleep=sleeper)
            runner.inventory.update(runtime_contract=contract(), task_arns=[arn], observed_tasks=[prior])
            runner.stop_recorded()
            self.assertTrue(runner.inventory["shutdown_confirmation"]["confirmed"])
            self.assertEqual(runner.inventory["task_observation_history"][arn]["stopped_at"], prior["stopped_at"])
            self.assertEqual(runner.inventory["observed_tasks"][0]["stopped_at"], prior["stopped_at"])
            self.assertTrue(runner.inventory["observed_tasks"][0]["historical_only"])
            self.assertGreater(runner.inventory["fleet_ledger"][arn]["vcpu_hours"], 0)
            aws["ecs"].stop_task.assert_not_called()
            aws["ecs"].get_waiter.assert_not_called()
            sleeper.assert_not_called()

    def test_new_missing_then_pending_launch_blocks_until_actual_stopped(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws, sleeper = clients(), Mock()
            stopped = stopped_task()
            stopped.update(cpu="256", memory="1024", createdAt=datetime.now(timezone.utc) - timedelta(seconds=10))
            arn = stopped["taskArn"]
            pending = {**stopped, "lastStatus": "PENDING", "containers": []}
            pending.pop("stoppedAt")
            pending.pop("startedAt")
            aws["ecs"].list_tasks.side_effect = [{"taskArns": []}, {"taskArns": []},
                {"taskArns": [arn]}, {"taskArns": []}, {"taskArns": []}, {"taskArns": [arn]}]
            aws["ecs"].describe_tasks.side_effect = [{"tasks": [], "failures": [{"arn": arn, "reason": "MISSING"}]},
                {"tasks": [pending]}, {"tasks": [stopped]}]
            aws["ecs"].describe_task_definition.return_value = {"taskDefinition": {"taskRoleArn": "arn:aws:iam::123456789012:role/pcfl-org_01", "containerDefinitions": [{"name": "org_01", "command": ["client"]}]}}
            runner = campaign.CampaignRunner(request(directory), clients=aws, sleep=sleeper)
            runner.inventory.update(runtime_contract=contract(), task_arns=[arn], reservations={arn: {"cpu": 256, "memory_mib": 1024}})
            runner.stop_recorded()
            self.assertEqual(sleeper.call_count, 2)
            aws["ecs"].stop_task.assert_called_once_with(cluster=contract()["cluster_arn"], task=arn, reason="PCFL campaign bounded shutdown")
            self.assertTrue(runner.inventory["shutdown_confirmation"]["confirmed"])
            self.assertEqual(runner.inventory["task_observation_history"][arn]["last_status"], "STOPPED")
            self.assertNotIn(arn, runner.inventory["reservations"])

    def test_never_visible_new_missing_task_is_not_declared_gone(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws, sleeper = clients(), Mock()
            arn = stopped_task()["taskArn"]
            aws["ecs"].list_tasks.return_value = {"taskArns": []}
            aws["ecs"].describe_tasks.return_value = {"tasks": [], "failures": [{"arn": arn, "reason": "MISSING"}]}
            runner = campaign.CampaignRunner(request(directory), clients=aws, sleep=sleeper)
            runner.inventory.update(runtime_contract=contract(), task_arns=[arn])
            # This test exercises sixty actual MISSING SDK responses. Repeated
            # atomic file replacement is a separate persistence boundary, not
            # part of the missing-task polling contract.
            with patch.object(campaign, "write_json"), self.assertRaisesRegex(RuntimeError, "task_stop_confirmation") as caught:
                runner.stop_recorded()
            self.assertIsNone(caught.exception.__cause__)
            self.assertFalse(runner.inventory["shutdown_confirmation"]["confirmed"])
            self.assertEqual(runner.inventory["shutdown_confirmation"]["unresolved_task_arns"], [arn])
            self.assertEqual(runner.inventory["shutdown_confirmation"]["polls"], 60)
            self.assertIsNone(runner.inventory["shutdown_confirmation"]["observation_error_type"])
            self.assertEqual(aws["ecs"].describe_tasks.call_count, 60)
            aws["ecs"].stop_task.assert_not_called()
            self.assertEqual(sleeper.call_count, 59)

    def test_shutdown_observation_error_keeps_failed_confirmation_and_original_cause(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            runner = campaign.CampaignRunner(request(directory), clients=clients(), sleep=Mock())
            runner.inventory.update(runtime_contract=contract(), task_arns=[stopped_task()["taskArn"]])
            failure = PermissionError("synthetic ledger unavailable")
            with patch.object(runner, "observed_tasks", side_effect=failure), self.assertRaisesRegex(RuntimeError, "task_stop_confirmation") as caught:
                runner.stop_recorded()
            self.assertIs(caught.exception.__cause__, failure)
            self.assertFalse(runner.inventory["shutdown_confirmation"]["confirmed"])
            self.assertEqual(runner.inventory["shutdown_confirmation"]["observation_error_type"], "PermissionError")
            self.assertEqual(runner.inventory["shutdown_confirmation"]["polls"], 1)

    def test_task_requests_bind_private_network_identity_and_one_task(self):
        value = cloud_io.bound_task_request(contract(), "org_01", "campaign-one")
        self.assertEqual(value["count"], 1)
        self.assertEqual(value["networkConfiguration"]["awsvpcConfiguration"]["assignPublicIp"], "DISABLED")
        self.assertEqual(value["taskDefinition"], contract()["task_definition_arns"]["org_01"])
        self.assertFalse(value["enableExecuteCommand"])
        foreign = stopped_task()
        foreign["taskArn"] = foreign["taskArn"].replace("pcfl-test-runtime", "unrelated-cluster")
        with self.assertRaisesRegex(ValueError, "recorded_cluster"):
            cloud_io.task_evidence(foreign, "123456789012", "us-east-1", contract()["cluster_arn"])

    def test_billing_metadata_keeps_pull_time_and_actual_container_leaf_digest(self):
        task = stopped_task()
        task["pullStartedAt"] = task["startedAt"] - timedelta(minutes=4)
        task["createdAt"] = task["pullStartedAt"] - timedelta(minutes=1)
        task["containers"][0].update(image="registry/image@sha256:index", imageDigest="sha256:leaf", name="org_01")
        evidence = cloud_io.task_evidence(task, "123456789012", "us-east-1", contract()["cluster_arn"])
        self.assertEqual(evidence["billing_started_at"], task["pullStartedAt"].isoformat())
        self.assertEqual(evidence["containers"][0]["image_digest"], "sha256:leaf")
        self.assertEqual(evidence["containers"][0]["image"], "registry/image@sha256:index")

    def test_pending_launch_reserves_capacity_before_visibility_and_uses_client_token(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            arn = "arn:aws:ecs:us-east-1:123456789012:task/pcfl-test-runtime/" + "b" * 32
            aws["ecs"].run_task.return_value = {"tasks": [{"taskArn": arn}]}
            runner = campaign.CampaignRunner(request(directory), apply=True, clients=aws)
            runner.approval = approval()
            runner.inventory.update(runtime_contract=contract(), runtime_plan={"task_definitions": {"org_01": {"cpu": "256", "memory": "1024"}}},
                runtime_variables={"hard_expiry_utc": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()})
            live = [{"task_arn": "live-fleet", "last_status": "PROVISIONING", "cpu": 3840, "memory_mib": 13312}]
            with patch.object(runner, "observed_tasks", return_value=live):
                self.assertEqual(runner.start_task("org_01"), arn)
                with self.assertRaisesRegex(RuntimeError, "budget_exhausted"):
                    runner.start_task("org_01")
            self.assertEqual(aws["ecs"].run_task.call_count, 1)
            self.assertEqual(len(aws["ecs"].run_task.call_args.kwargs["clientToken"]), 64)

    def test_restart_launch_intent_is_distinct_and_retry_token_is_stable(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            aws["ecs"].run_task.return_value = {"tasks": [{"taskArn": "recorded-task"}]}
            runner = campaign.CampaignRunner(request(directory), apply=True, clients=aws)
            runner.inventory.update(runtime_contract=contract(), runtime_plan={"task_definitions": {"org_01": {"cpu": "256", "memory": "1024"}}})
            with patch.object(runner, "budget_check"):
                runner.start_task("org_01")
                runner.start_task("org_01", launch_intent="host-restart:restart-one")
                runner.start_task("org_01", launch_intent="host-restart:restart-one")
            tokens = [call.kwargs["clientToken"] for call in aws["ecs"].run_task.call_args_list]
            self.assertNotEqual(tokens[0], tokens[1])
            self.assertEqual(tokens[1], tokens[2])

    def test_endpoint_hours_survive_idle_fleet_and_new_campaign_ids(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            one = campaign.CampaignRunner(request(directory, "campaign-one"))
            one.approval = approval()
            one.deployment_clock()
            ledger = json.loads(one.budget_ledger_path.read_text(encoding="utf-8"))
            ledger["deployments"][one.inventory["endpoint_deployment_key"]]["started_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
            campaign.write_json(one.budget_ledger_path, ledger)
            two = campaign.CampaignRunner(request(directory, "campaign-two"))
            two.approval = {**approval(), "max_cumulative_fleet_hours": 1}
            with self.assertRaisesRegex(RuntimeError, "endpoint_deployment_budget"):
                two.deployment_clock()

    def test_upload_allowlist_rejects_wrong_prefix_kind_and_changed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.csv"
            source.write_bytes(b"synthetic-only")
            spec = {"source_path": str(source), "key": "partitions/iid/org_01/train.csv", "kind": "partition", "sha256": cloud_io.file_sha256(source)}
            cloud_io.validate_upload(spec)
            for change in ({"key": "partitions/iid/org_99/train.csv"}, {"key": "metadata/../escape.json", "kind": "campaign"},
                           {"key": "evaluation/frozen/test.csv"}, {"sha256": "0" * 64}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    cloud_io.validate_upload({**spec, **change})

    def test_upload_version_is_confirmed_by_owner_version_and_body_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.csv"
            content = b"synthetic-only"
            source.write_bytes(content)
            spec = {"source_path": str(source), "key": "partitions/iid/org_01/train.csv", "kind": "partition", "sha256": cloud_io.file_sha256(source)}
            s3 = Mock()
            s3.put_object.return_value = {"VersionId": "version-1"}
            s3.get_object.return_value = {"VersionId": "version-1", "Body": io.BytesIO(content)}
            reference = cloud_io.upload_version(s3, bucket="own-test", account="123456789012", spec=spec)
            self.assertEqual(reference["version_id"], "version-1")
            self.assertEqual(s3.get_object.call_args.kwargs["ExpectedBucketOwner"], "123456789012")
            s3.get_object.return_value = {"VersionId": "version-1", "Body": io.BytesIO(b"changed")}
            with self.assertRaisesRegex(RuntimeError, "body_mismatch"):
                cloud_io.upload_version(s3, bucket="own-test", account="123456789012", spec=spec)

    def test_private_registry_password_only_flows_through_stdin(self):
        ecr, run = Mock(), Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
        registry = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
        ecr.get_authorization_token.return_value = {"authorizationData": [{"proxyEndpoint": "https://" + registry,
            "authorizationToken": base64.b64encode(b"AWS:private-password").decode()}]}
        ecr.describe_images.return_value = {"imageDetails": [{"imageDigest": "sha256:" + "a" * 64}]}
        ecr.batch_get_image.side_effect = [{"images": [], "failures": [{"failureCode": "ImageNotFound"}]},
            {"images": [{"imageManifest": json.dumps({"config": {"digest": "sha256:" + "c" * 64}})}]}]
        result = cloud_io.publish_image(ecr, account="123456789012", region="us-east-1", repository=registry + "/project/coordinator",
            local_tag="pcfl-runtime:0.1.0", campaign_id="campaign-one", source_hash="b" * 64, expected_local_image_id="sha256:" + "c" * 64, run=run)
        self.assertTrue(result["reference"].endswith("@sha256:" + "a" * 64))
        self.assertEqual(run.call_args_list[0].kwargs["input"], "private-password\n")
        self.assertTrue(all("private-password" not in " ".join(call.args[0]) for call in run.call_args_list))

    def test_oci_index_is_resolved_to_verified_linux_amd64_config(self):
        ecr = Mock()
        manifest = {"manifests": [{"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}},
                                  {"digest": "sha256:" + "b" * 64, "platform": {"os": "unknown", "architecture": "unknown"}}]}
        ecr.batch_get_image.return_value = {"images": [{"imageManifest": json.dumps({"config": {"digest": "sha256:" + "c" * 64}})}]}
        self.assertTrue(cloud_io.registry_config_matches(ecr, "project/coordinator", json.dumps(manifest), "sha256:" + "c" * 64))
        self.assertEqual(ecr.batch_get_image.call_args.kwargs["imageIds"], [{"imageDigest": "sha256:" + "a" * 64}])

    def test_containerd_local_index_identity_uses_exact_registry_manifest_bytes(self):
        import hashlib
        ecr = Mock()
        raw = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
            {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}}]}, indent=3)
        local_index_id = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
        self.assertTrue(cloud_io.registry_config_matches(ecr, "project/coordinator", raw, local_index_id))
        ecr.batch_get_image.assert_not_called()
        ecr.batch_get_image.return_value = {"images": [{"imageManifest": json.dumps({"config": {"digest": "sha256:" + "b" * 64}})}]}
        self.assertFalse(cloud_io.registry_config_matches(ecr, "project/coordinator", raw + "\n", local_index_id))

    def test_probe_logs_require_actual_attributable_denials_and_bound_identity(self):
        import hashlib
        config = {"role_kind": "client", "org_id": "org_01", "expected_task_role_arn": "arn:aws:iam::123456789012:role/pcfl-org_01",
            "allowed_object": {"sha256": "c" * 64}, "denied_objects": [{"key": "partitions/iid/org_02/train.csv"}, {"key": "evaluation/frozen/test.csv"}]}
        good = {"successful": True, "role": "client-isolation-probe", "role_kind": "client", "org_id": "org_01",
            "task_role_arn": config["expected_task_role_arn"], "own_object_sha256": "c" * 64,
            "denied_reads": [{"key_sha256": hashlib.sha256(item["key"].encode()).hexdigest(), "code": "AccessDenied"} for item in config["denied_objects"]],
            "policy_write_denied": True, "record_rows_exported": False}
        self.assertEqual(cloud_io.validate_probe_evidence(good, config), good)
        wrong = deepcopy(good)
        wrong["denied_reads"][0]["code"] = "NoSuchKey"
        for value in (wrong, {**good, "task_role_arn": "other-role"}, {**good, "rows": []}, {**good, "denied_reads": good["denied_reads"][:1]}):
            with self.assertRaisesRegex(ValueError, "required_identity_and_denials"):
                cloud_io.validate_probe_evidence(value, config)
        protected = {**config, "protected_anchor_object": {"key": "anchors/campaign-one/witness.json"}}
        with self.assertRaisesRegex(ValueError, "required_identity_and_denials"):
            cloud_io.validate_probe_evidence(good, protected)
        self.assertEqual(cloud_io.validate_probe_evidence({**good, "anchor_write_denied": True}, protected)["anchor_write_denied"], True)

    def test_publish_new_verified_image_preserves_history_and_same_id_retry(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws, value = clients(), request(directory)
            repository = "123456789012.dkr.ecr.us-east-1.amazonaws.com/pcfl-test/coordinator"
            report_path = Path(directory) / "container-report.json"
            report_path.write_text(json.dumps({"local_image_id": "sha256:" + "b" * 64}), encoding="utf-8")
            value["source_reports"] = {"container": {"path": str(report_path), "sha256": cloud_io.file_sha256(report_path)}}
            run = Mock(return_value=SimpleNamespace(returncode=0, stdout="sha256:" + "b" * 64 + "\n", stderr=""))
            runner = campaign.CampaignRunner(value, clients=aws, run=run)
            old = {"reference": repository + "@sha256:" + "a" * 64, "local_image_id": "sha256:" + "a" * 64}
            runner.inventory.update(foundation={"bucket_name": "own-test", "image_repositories": {"coordinator": repository}}, image=old)
            published = {"reference": repository + "@sha256:" + "c" * 64, "image_tag": "immutable-new-build", "source_hash": value["source_reports"]["container"]["sha256"]}
            with patch.object(campaign, "publish_image", return_value=published) as publish:
                runner.publish_inputs()
                publish.assert_called_once()
                self.assertIn(old, runner.inventory["image_history"])
                self.assertEqual(runner.inventory["image"]["local_image_id"], "sha256:" + "b" * 64)
                aws["ecr"].batch_get_image.return_value = {"images": [{"imageId": {"imageDigest": "sha256:" + "c" * 64},
                    "imageManifest": json.dumps({"config": {"digest": "sha256:" + "b" * 64}})}]}
                runner.publish_inputs()
                self.assertEqual(publish.call_count, 1)
                self.assertEqual(len(runner.inventory["image_history"]), 2)
                # A stale registry object cannot downgrade the newly verified
                # build just because a prior inventory entry exists.
                aws["ecr"].batch_get_image.return_value["images"][0]["imageManifest"] = json.dumps({"config": {"digest": "sha256:" + "a" * 64}})
                with self.assertRaisesRegex(ValueError, "no_longer_matches"):
                    runner.publish_inputs()
                self.assertEqual(runner.inventory["image"]["reference"], published["reference"])

    def test_lost_push_retry_recovers_only_matching_verified_image_config(self):
        ecr, run = Mock(), Mock()
        registry = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
        ecr.batch_get_image.return_value = {"images": [{"imageManifest": json.dumps({"config": {"digest": "sha256:" + "c" * 64}}),
            "imageId": {"imageDigest": "sha256:" + "a" * 64}}]}
        options = dict(account="123456789012", region="us-east-1", repository=registry + "/project/coordinator",
            local_tag="pcfl-runtime:0.1.0", campaign_id="campaign-one", source_hash="b" * 64, expected_local_image_id="sha256:" + "c" * 64, run=run)
        self.assertTrue(cloud_io.publish_image(ecr, **options)["reference"].endswith("a" * 64))
        run.assert_not_called()
        with self.assertRaisesRegex(ValueError, "verified_local_image"):
            cloud_io.publish_image(ecr, **{**options, "expected_local_image_id": "sha256:" + "d" * 64})

    def test_artifact_export_retains_all_exact_versions_and_no_dataset_prefix(self):
        s3 = Mock()
        s3.list_object_versions.side_effect = [
            {"Versions": [{"Key": "evidence/run/update.npz", "VersionId": "v1", "Size": 3}]},
            {"Versions": [{"Key": "models/candidates/run/model.npz", "VersionId": "v2", "Size": 3}]}]
        s3.get_object.side_effect = [{"VersionId": "v1", "Body": io.BytesIO(b"one")}, {"VersionId": "v2", "Body": io.BytesIO(b"two")}]
        with tempfile.TemporaryDirectory() as directory:
            references = cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=directory)
            self.assertEqual({item["version_id"] for item in references}, {"v1", "v2"})
            self.assertTrue(all(cloud_io.file_sha256(item["local_path"]) == item["sha256"] for item in references))
        prefixes = {call.kwargs["Prefix"] for call in s3.list_object_versions.call_args_list}
        self.assertEqual(prefixes, {"evidence/", "models/candidates/"})

    def test_protected_anchor_export_requires_explicit_operator_version_and_hash(self):
        import hashlib
        s3 = Mock()
        s3.list_object_versions.return_value = {"Versions": []}
        body = b'{"signed":"operator-witness"}'
        anchor = {"key": "anchors/campaign-one/cell/witness.json", "version_id": "anchor-v1", "sha256": hashlib.sha256(body).hexdigest()}
        s3.get_object.return_value = {"VersionId": "anchor-v1", "Body": io.BytesIO(body)}
        with tempfile.TemporaryDirectory() as directory:
            references = cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=directory,
                protected_anchors=[anchor], anchor_prefix="anchors/campaign-one/")
            self.assertEqual(len(references), 1)
            self.assertTrue(references[0]["protected_operator_witness"])
            self.assertEqual(Path(references[0]["local_path"]).read_bytes(), body)
            with self.assertRaisesRegex(ValueError, "recorded_scope"):
                cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=directory,
                    protected_anchors=[{**anchor, "key": "anchors/unrelated/witness.json"}], anchor_prefix="anchors/campaign-one/")

    def test_version_export_reuses_only_verified_exact_prior_identity_and_downloads_new_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root, s3 = Path(directory), Mock()
            path = root / "earlier-cache/old.npz"
            path.parent.mkdir()
            path.write_bytes(b"old")
            prior = {"bucket": "own-test", "key": "evidence/run/update.npz", "version_id": "old-version", "sha256": hashlib.sha256(b"old").hexdigest(), "size_bytes": 3, "local_path": str(path)}
            s3.list_object_versions.side_effect = [{"Versions": [{"Key": prior["key"], "VersionId": "old-version", "Size": 3},
                {"Key": prior["key"], "VersionId": "new-version", "Size": 3}]}, {"Versions": []}]
            s3.get_object.return_value = {"VersionId": "new-version", "Body": io.BytesIO(b"new")}
            output = cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=root / "next-app/v",
                prior_records=[prior], cache_root=root)
            s3.get_object.assert_called_once_with(Bucket="own-test", Key=prior["key"], VersionId="new-version", ExpectedBucketOwner="123456789012")
            self.assertEqual(output[0], prior)
            self.assertEqual(path.read_bytes(), b"old")
            self.assertEqual(Path(output[1]["local_path"]).read_bytes(), b"new")
            self.assertFalse((root / "next-app/v" / path.name).exists())

    def test_cached_corruption_missing_foreign_scope_and_outside_path_never_redownload(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            path = root / "old.npz"
            path.write_bytes(b"old")
            foreign = Path(outside) / "foreign.npz"
            foreign.write_bytes(b"old")
            good = {"bucket": "own-test", "key": "models/candidates/run/model.npz", "version_id": "v1", "sha256": hashlib.sha256(b"old").hexdigest(), "size_bytes": 3, "local_path": str(path)}
            for change in ({"sha256": "0" * 64}, {"local_path": str(root / "missing.npz")}, {"local_path": str(foreign)},
                           {"bucket": "foreign-bucket"}, {"key": "partitions/iid/org_01/train.csv"}, {"version_id": "null"}):
                s3 = Mock()
                with self.subTest(change=change), self.assertRaises(ValueError):
                    cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=root / "new",
                        prior_records=[{**good, **change}], cache_root=root)
                s3.get_object.assert_not_called()
            path.write_bytes(b"bad")
            with self.assertRaisesRegex(ValueError, "missing_or_corrupt"):
                cloud_io.export_owned_versions(Mock(), bucket="own-test", account="123456789012", destination=root / "new", prior_records=[good], cache_root=root)

    def test_cached_size_and_total_union_bound_include_old_unlisted_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root, s3 = Path(directory), Mock()
            path = root / "old.npz"
            path.write_bytes(b"old")
            prior = {"bucket": "own-test", "key": "evidence/run/old.npz", "version_id": "v1", "sha256": hashlib.sha256(b"old").hexdigest(), "size_bytes": 3, "local_path": str(path)}
            s3.list_object_versions.return_value = {"Versions": [{"Key": prior["key"], "VersionId": "v1", "Size": 4}]}
            with self.assertRaisesRegex(ValueError, "listed_size_mismatch"):
                cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=root / "new", prior_records=[prior], cache_root=root)
            s3.get_object.assert_not_called()
            s3.list_object_versions.return_value = {"Versions": [{"Key": "evidence/run/new.npz", "VersionId": "v2", "Size": 3}]}
            with self.assertRaisesRegex(RuntimeError, "size_exceeded"):
                cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=root / "new", prior_records=[prior], cache_root=root, max_bytes=5)
            s3.get_object.assert_not_called()

    def test_cached_anchor_requires_exact_version_head_and_operator_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root, s3 = Path(directory), Mock()
            path = root / "witness.json"
            path.write_bytes(b"witness")
            prior = {"bucket": "own-test", "key": "anchors/campaign-one/cell/witness.json", "version_id": "anchor-v1", "sha256": hashlib.sha256(b"witness").hexdigest(), "size_bytes": 7,
                "local_path": str(path), "protected_operator_witness": True}
            s3.list_object_versions.return_value = {"Versions": []}
            s3.head_object.return_value = {"VersionId": "anchor-v1", "ContentLength": 7}
            output = cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=root / "new", prior_records=[prior], cache_root=root,
                protected_anchors=[prior], anchor_prefix="anchors/campaign-one/")
            self.assertEqual(output, [prior])
            s3.get_object.assert_not_called()
            s3.head_object.return_value["VersionId"] = "wrong-version"
            with self.assertRaisesRegex(ValueError, "anchor_version_or_size"):
                cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=root / "new", prior_records=[prior], cache_root=root,
                    protected_anchors=[prior], anchor_prefix="anchors/campaign-one/")

    def test_prior_public_metadata_is_history_only_and_requires_actual_upload_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root, s3 = Path(directory), Mock()
            path = root / "campaign.json"
            path.write_bytes(b'{"campaign_id":"owned"}')
            prior = {"bucket": "own-test", "key": "metadata/owned/campaign.json", "version_id": "metadata-v1", "sha256": cloud_io.file_sha256(path), "size_bytes": path.stat().st_size, "local_path": str(path)}
            s3.list_object_versions.return_value = {"Versions": []}
            with self.assertRaisesRegex(ValueError, "recorded_scope"):
                cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=root / "new", prior_records=[prior], cache_root=root)
            result = cloud_io.export_owned_versions(s3, bucket="own-test", account="123456789012", destination=root / "new", prior_records=[prior], cache_root=root,
                metadata_references=[{key: prior[key] for key in ("bucket", "key", "version_id", "sha256")}])
            self.assertEqual(result, [])
            s3.get_object.assert_not_called()
            self.assertEqual({call.kwargs["Prefix"] for call in s3.list_object_versions.call_args_list}, {"evidence/", "models/candidates/"})

    def test_purge_never_deletes_an_unretained_version(self):
        s3 = Mock()
        s3.get_bucket_tagging.return_value = {"TagSet": [{"Key": "Project", "Value": "pcfl-test"}]}
        s3.list_object_versions.return_value = {"Versions": [{"Key": "metadata/unretained.json", "VersionId": "v2"}]}
        with self.assertRaisesRegex(ValueError, "unretained"):
            cloud_io.purge_recorded_versions(s3, bucket="own-test", account="123456789012", references=[], project="pcfl-test")
        s3.delete_objects.assert_not_called()

    def test_failed_job_without_export_removes_cost_runtime_but_retains_foundation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            runner = campaign.CampaignRunner(request(directory), apply=True, clients=clients())
            runner.inventory.update(task_arns=["recorded-task"], runtime_variables={"reviewed": True})
            with patch.object(runner, "stop_recorded"), patch.object(runner, "terraform_step") as terraform, \
                 self.assertRaisesRegex(RuntimeError, "foundation_retained"):
                runner.teardown()
            terraform.assert_called_once_with("runtime", {"reviewed": True}, destroy=True)

    def test_incomplete_operator_orphan_discovery_preserves_foundation_and_pointers(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            runner = campaign.CampaignRunner(request(directory), clients=aws)
            runner.inventory.update(runtime_variables={"owned": True}, operator_recoveries=[{"orphan_discovery_complete": False, "status": "operator-aborted-development"}])
            with patch.object(runner, "stop_recorded"), patch.object(runner, "terraform_step") as terraform, patch.object(runner, "deployment_clock"), \
                 self.assertRaisesRegex(RuntimeError, "foundation_retained_until_complete_orphan_discovery"):
                runner.teardown()
            terraform.assert_called_once_with("runtime", {"owned": True}, destroy=True)
            aws["dynamodb"].update_item.assert_not_called()
            aws["s3"].delete_objects.assert_not_called()

    def test_pre_teardown_snapshots_keep_first_full_state_across_partial_destroy(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            runner = campaign.CampaignRunner(request(directory))
            path = runner.directory / "state/runtime.tfstate"
            full = {"resources": [{"mode": "managed", "type": "aws_vpc_endpoint", "instances": [
                {"attributes": {"id": "vpce-first"}}, {"attributes": {"id": "vpce-second"}}]}]}
            campaign.write_json(path, full)
            runner.inventory["state_paths"] = {"runtime": str(path)}
            runner.retain_pre_teardown_states()
            reference = deepcopy(runner.inventory["pre_teardown_state_snapshots"]["runtime"])
            self.assertEqual(Path(reference["path"]).read_bytes(), path.read_bytes())
            campaign.write_json(path, {"resources": [{"mode": "managed", "type": "aws_vpc_endpoint", "instances": [full["resources"][0]["instances"][1]]}]})
            runner.retain_pre_teardown_states()
            self.assertEqual(runner.inventory["pre_teardown_state_snapshots"]["runtime"], reference)
            self.assertEqual(len(json.loads(Path(reference["path"]).read_text())["resources"][0]["instances"]), 2)
            campaign.write_json(path, {"resources": [{"mode": "managed", "type": "aws_vpc_endpoint", "instances": [{"attributes": {"id": "vpce-new-unrecorded"}}]}]})
            with self.assertRaisesRegex(ValueError, "new_resources_after"):
                runner.retain_pre_teardown_states()
            Path(reference["path"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "missing_or_changed"):
                runner.retain_pre_teardown_states()

    def test_teardown_deletes_every_recorded_owned_build_and_tolerates_already_gone(self):
        from test_ecr_manifest_cleanup import ECRManifestCleanupTests, digest, index
        fixture = ECRManifestCleanupTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            repository = "123456789012.dkr.ecr.us-east-1.amazonaws.com/pcfl-test/coordinator"
            fixture.project, fixture.name, fixture.uri = "pcfl-test", "pcfl-test/coordinator", repository
            fixture.arn = "arn:aws:ecr:us-east-1:123456789012:repository/pcfl-test/coordinator"
            fixture.ecr.list_tags_for_resource.return_value = {"tags": [{"Key": "Project", "Value": "pcfl-test"}]}
            second = index(fixture.leaf); fixture.remote[digest(second)] = second
            references = sorted(repository + "@" + item for item in (fixture.root_digest, digest(second)))
            aws["ecr"] = fixture.ecr
            runner = campaign.CampaignRunner(request(directory), apply=True, clients=aws)
            runner.inventory.update(runtime_variables={}, foundation_variables={}, foundation={"bucket_name": "own-test", "state_table_name": "own-table", "image_repositories": {"coordinator": repository}},
                image={"reference": references[1]}, image_history=[{"reference": item} for item in references])
            explicit_zero_secret_fixture(runner)
            campaign.write_json(Path(directory) / "results/aws/project-ownership.json", {})
            original_list = fixture.list
            def already_gone(**kwargs):
                # Complete graph was captured before this idempotent absence.
                fixture.remote.pop(fixture.root_digest, None)
                return original_list(**kwargs)
            fixture.ecr.list_images.side_effect = already_gone
            with patch.object(runner, "stop_recorded"), patch.object(runner, "terraform_step"), patch.object(runner, "deployment_clock"), patch.object(campaign, "purge_recorded_versions", return_value=0):
                self.assertTrue(runner.teardown()["teardown_complete"])
            self.assertEqual(aws["ecr"].batch_delete_image.call_count, 3)
            self.assertEqual(runner.inventory["removed_owned_image_references"], references)
            self.assertTrue(runner.inventory["ecr_manifest_cleanup"]["successful"])
            self.assertFalse(fixture.remote)

    def test_teardown_retires_typed_aborted_pointer_only_after_strong_current_match(self):
        for matches in (True, False):
            with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
                aws = clients()
                runner = campaign.CampaignRunner(request(directory), clients=aws)
                pointer = {"PK": {"S": "RUN#aborted-run"}, "SK": {"S": "POINTER"}, "manifest_id": {"S": "a" * 64}}
                body = {"kind": "operator-observed-partial-persistent-state", "producer_runtime_result": False, "full_protocol_pass": False,
                    "successful": False, "snapshot_coherent": True, "run_id": "aborted-run", "table_name": "own-table", "authority_order": 10,
                    "sequence": {"order": {"N": "10"}}, "run_records": [pointer], "model_pointer": pointer}
                path = runner.directory / "r/abort-case/d/run.json"
                campaign.write_json(path, body)
                observation = {"path": str(path), "sha256": cloud_io.file_sha256(path), "run_id": "aborted-run", "authority_order": 10}
                runner.inventory.update(runtime_variables={}, foundation_variables={},
                    foundation={"bucket_name": "own-test", "state_table_name": "own-table", "image_repositories": {}},
                    operator_recoveries=[{"orphan_discovery_complete": True, "status": "operator-aborted-development", "operator_observations": [observation]}])
                explicit_zero_secret_fixture(runner)
                campaign.write_json(Path(directory) / "results/aws/project-ownership.json", {})
                aws["dynamodb"].get_item.return_value = {"Item": {"manifest_id": {"S": ("a" if matches else "b") * 64}}}
                with patch.object(runner, "stop_recorded"), patch.object(runner, "terraform_step"), patch.object(runner, "deployment_clock"), \
                     patch.object(campaign, "purge_recorded_versions", return_value=0) as purge:
                    if matches:
                        self.assertTrue(runner.teardown()["teardown_complete"])
                        self.assertEqual(runner.inventory["retired_publication_pointers"], [{"run_pk": "RUN#aborted-run", "manifest_id": "a" * 64}])
                        update = aws["dynamodb"].update_item.call_args.kwargs
                        self.assertEqual(update["ConditionExpression"], "#manifest = :manifest")
                        self.assertEqual(update["ExpressionAttributeValues"][":manifest"], {"S": "a" * 64})
                    else:
                        with self.assertRaisesRegex(ValueError, "unexported_publication_pointer"):
                            runner.teardown()
                        aws["dynamodb"].update_item.assert_not_called()
                        purge.assert_not_called()
                self.assertTrue(aws["dynamodb"].get_item.call_args.kwargs["ConsistentRead"])
                self.assertFalse(json.loads(path.read_text())["successful"])

    def test_recovered_completed_producer_pointers_resolve_exact_five_hash_named_raw_versions(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            runner = campaign.CampaignRunner(request(directory))
            recovery, records = recovered_producer_fixture(runner)
            self.assertEqual(list((runner.directory / "r").rglob("runtime_result.json")), [])
            actual = runner.retirement_pointer_bindings()
            expected = {"RUN#synthetic-completed-run-" + str(number): {"manifest_id": str(number) * 64, "order": 20 + number}
                        for number in range(5)}
            self.assertEqual(actual, expected)
            self.assertFalse(recovery["campaign_successful"])
            self.assertEqual(recovery["status"], "operator-aborted-development")
            self.assertEqual(json.loads(Path(records[-1]["local_path"]).read_text())["successful"], False)

    def test_recovered_completed_pointer_scope_version_bytes_and_run_binding_fail_closed(self):
        for mode in ("raw-bytes", "version", "bucket", "index-application", "raw-run", "missing-raw", "duplicate-case", "outside-file"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
                runner = campaign.CampaignRunner(request(directory))
                recovery, records = recovered_producer_fixture(runner)
                index_path, raw_path = Path(records[-1]["local_path"]), Path(records[0]["local_path"])
                index = json.loads(index_path.read_text())
                if mode == "raw-bytes": raw_path.write_bytes(raw_path.read_bytes() + b"changed")
                elif mode == "version": index["cases"][0]["artifacts"][0]["version_id"] = "unretained-version"
                elif mode == "bucket": index["cases"][0]["artifacts"][0]["bucket"] = "foreign-bucket"
                elif mode == "index-application": index["campaign_id"] = "other-application"
                elif mode == "raw-run":
                    raw = json.loads(raw_path.read_text()); raw["persistent_run_id"] = "unrelated-run"
                    raw_path.write_text(json.dumps(raw)); records[0].update(sha256=cloud_io.file_sha256(raw_path), size_bytes=raw_path.stat().st_size)
                    index["cases"][0]["artifacts"][0].update(sha256=records[0]["sha256"], size_bytes=records[0]["size_bytes"])
                elif mode == "missing-raw": index["cases"][0]["artifacts"] = []
                elif mode == "duplicate-case": index["cases"].append(deepcopy(index["cases"][0]))
                else:
                    outside = Path(directory) / "outside-owned-campaign.json"; outside.write_bytes(raw_path.read_bytes())
                    records[0]["local_path"] = str(outside)
                if mode not in {"raw-bytes", "outside-file"}:
                    index_path.write_text(json.dumps(index))
                    records[-1].update(sha256=cloud_io.file_sha256(index_path), size_bytes=index_path.stat().st_size)
                    recovery["source_index"].update(sha256=records[-1]["sha256"], size_bytes=records[-1]["size_bytes"])
                with self.assertRaises(ValueError):
                    runner.retirement_pointer_bindings()

    def test_teardown_strong_compares_and_conditionally_retires_all_five_recovered_completed_pointers(self):
        for matches in (True, False):
            with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
                aws = clients()
                runner = campaign.CampaignRunner(request(directory), clients=aws)
                recovered_producer_fixture(runner)
                runner.inventory.update(runtime_variables={}, foundation_variables={})
                explicit_zero_secret_fixture(runner)
                campaign.write_json(Path(directory) / "results/aws/project-ownership.json", {})
                def current(**kwargs):
                    self.assertTrue(kwargs["ConsistentRead"])
                    number = kwargs["Key"]["PK"]["S"].rsplit("-", 1)[-1]
                    return {"Item": {"manifest_id": {"S": number * 64 if matches else "f" * 64}}}
                aws["dynamodb"].get_item.side_effect = current
                with patch.object(runner, "stop_recorded"), patch.object(runner, "terraform_step"), patch.object(runner, "deployment_clock"), \
                     patch.object(campaign, "purge_recorded_versions", return_value=0) as purge:
                    if matches:
                        self.assertTrue(runner.teardown()["teardown_complete"])
                        self.assertEqual(aws["dynamodb"].update_item.call_count, 5)
                        for call in aws["dynamodb"].update_item.call_args_list:
                            self.assertEqual(call.kwargs["ConditionExpression"], "#manifest = :manifest")
                        self.assertEqual(len(runner.inventory["retired_publication_pointers"]), 5)
                    else:
                        with self.assertRaisesRegex(ValueError, "unexported_publication_pointer"):
                            runner.teardown()
                        aws["dynamodb"].update_item.assert_not_called()
                        purge.assert_not_called()

    def test_collect_rejects_reference_outside_campaign(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            report = {"campaign_id": "campaign-one", "successful": True, "cases": [{"artifacts": [{"bucket": "own-test", "key": "evidence/campaigns/other/file.json"}]}]}
            aws["s3"].get_object.return_value = {"VersionId": "index-v1", "Body": io.BytesIO(json.dumps(report).encode())}
            runner = campaign.CampaignRunner(request(directory), clients=aws)
            runner.inventory["foundation"] = {"bucket_name": "own-test"}
            with self.assertRaisesRegex(ValueError, "outside_campaign"):
                runner.collect()
            self.assertEqual(aws["s3"].get_object.call_count, 1)

    def test_collect_preserves_raw_index_and_model_version_inside_short_case(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            prefix = "evidence/campaigns/campaign-one/"
            canonical_bytes = b"canonical-npz-version"
            local_bytes = b"different-local-encoding"
            canonical_sha = hashlib.sha256(canonical_bytes).hexdigest()
            reference = {"backend": "s3", "bucket": "own-test", "key": "evidence/run/update.npz", "version_id": "canonical-v1", "sha256": canonical_sha}
            raw_result = json.dumps({"updates": [{"artifact": reference}]}, indent=5).encode() + b"\n"
            case_key, local_key = prefix + "cell/runtime_result.json", prefix + "cell/local.npz"
            report = {"campaign_id": "campaign-one", "successful": True, "cases": [{"cell_id": "full-cell-identity", "artifacts": [
                {"bucket": "own-test", "key": case_key, "version_id": "result-v1", "sha256": hashlib.sha256(raw_result).hexdigest(), "size_bytes": len(raw_result)},
                {"bucket": "own-test", "key": local_key, "version_id": "local-v1", "sha256": hashlib.sha256(local_bytes).hexdigest(), "size_bytes": len(local_bytes)}]}]}
            raw_index = json.dumps(report, indent=3).encode() + b"\n\n"
            objects = {prefix + "campaign_result.json": ("index-v1", raw_index), case_key: ("result-v1", raw_result),
                       local_key: ("local-v1", local_bytes), reference["key"]: ("canonical-v1", canonical_bytes)}
            def get(**kwargs):
                version, value = objects[kwargs["Key"]]
                self.assertIn(kwargs.get("VersionId", version), {version})
                return {"VersionId": version, "Body": io.BytesIO(value)}
            aws["s3"].get_object.side_effect = get
            aws["s3"].list_object_versions.side_effect = [{"Versions": [{"Key": reference["key"], "VersionId": "canonical-v1", "Size": len(canonical_bytes)}]}, {"Versions": []}]
            runner = campaign.CampaignRunner(request(directory), clients=aws)
            runner.inventory["foundation"] = {"bucket_name": "own-test"}
            runner.inventory["operator_recoveries"] = [{"kind": "registered-operator-partial-cloud-recovery", "orphan_discovery_complete": False,
                "status": "operator-aborted-development", "campaign_successful": False}]
            exported = runner.collect()
            self.assertEqual((runner.directory / "r/campaign_result.json").read_bytes(), raw_index)
            case = Path(exported["case_directories"]["full-cell-identity"])
            self.assertEqual((case / "runtime_result.json").read_bytes(), raw_result)
            sidecar = json.loads((case / "artifact_paths.json").read_text(encoding="utf-8"))
            self.assertFalse(Path(sidecar[canonical_sha]).is_absolute())
            self.assertEqual((case / sidecar[canonical_sha]).read_bytes(), canonical_bytes)
            recovery = runner.inventory["operator_recoveries"][0]
            self.assertTrue(recovery["orphan_discovery_complete"])
            self.assertEqual(recovery["status"], "operator-aborted-development")
            self.assertFalse(recovery["campaign_successful"])
            self.assertEqual(cloud_io.file_sha256(recovery["orphan_discovery_receipt"]["path"]), recovery["orphan_discovery_receipt"]["sha256"])

    def test_application_exports_append_without_rewriting_prior_raw_evidence(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws, value = clients(), request(directory)
            runner = campaign.CampaignRunner(value, clients=aws)
            runner.inventory["foundation"] = {"bucket_name": "own-test"}
            objects, exports = {}, []
            def get(**kwargs):
                version, body = objects[kwargs["Key"]]
                self.assertEqual(kwargs.get("VersionId", version), version)
                return {"VersionId": version, "Body": io.BytesIO(body)}
            aws["s3"].get_object.side_effect = get
            with patch.object(campaign, "export_owned_versions", return_value=[]):
                for application_id in ("campaign-one", "campaign-one-training-pilot-iid"):
                    value["application_campaign_id"] = application_id
                    prefix = "evidence/campaigns/" + application_id + "/"
                    raw_result = json.dumps({"application": application_id}, indent=3).encode() + b"\n"
                    result_key = prefix + "same-cell/runtime_result.json"
                    report = {"campaign_id": application_id, "successful": True, "cases": [{"cell_id": "same-cell", "artifacts": [{
                        "bucket": "own-test", "key": result_key, "version_id": "result-" + application_id,
                        "sha256": hashlib.sha256(raw_result).hexdigest(), "size_bytes": len(raw_result)}]}]}
                    raw_index = json.dumps(report, indent=4).encode() + b"\n\n"
                    objects.update({prefix + "campaign_result.json": ("index-" + application_id, raw_index),
                                    result_key: ("result-" + application_id, raw_result)})
                    exported = runner.collect()
                    exports.append((exported, raw_index, raw_result))
                first, second = exports[0][0], exports[1][0]
                self.assertEqual(Path(first["export_root"]), runner.directory / "r")
                self.assertEqual(Path(second["export_root"]).parent, runner.directory / "r")
                self.assertLess(len(Path(second["export_root"]).name), 10)
                self.assertNotEqual(first["case_directories"], second["case_directories"])
                for exported, raw_index, raw_result in exports:
                    self.assertEqual((Path(exported["export_root"]) / "campaign_result.json").read_bytes(), raw_index)
                    self.assertEqual((Path(exported["case_directories"]["same-cell"]) / "runtime_result.json").read_bytes(), raw_result)
                    self.assertEqual(runner.inventory["exports_by_application"][exported["application_campaign_id"]], exported)
                # Identical-byte retries recover; a later version of the index
                # cannot silently replace a retained application's provenance.
                self.assertEqual(runner.collect(), second)
                active_key = second["index_key"]
                objects[active_key] = ("unexpected-new-version", objects[active_key][1])
                with self.assertRaisesRegex(ValueError, "immutable_application_index_version_changed"):
                    runner.collect()
                self.assertEqual((Path(first["export_root"]) / "campaign_result.json").read_bytes(), exports[0][1])

    def test_collect_keeps_union_of_exact_retained_versions_for_teardown(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
            aws = clients()
            runner = campaign.CampaignRunner(request(directory), clients=aws)
            runner.inventory["foundation"] = {"bucket_name": "own-test"}
            old = {"bucket": "own-test", "key": "evidence/old.json", "version_id": "old", "sha256": "a" * 64, "size_bytes": 3, "local_path": "original-private-path"}
            new = {**old, "key": "evidence/new.json", "version_id": "new", "local_path": "new-private-path"}
            runner.inventory["retained_artifact_versions"] = [old]
            aws["s3"].get_object.return_value = {"VersionId": "index-v1", "Body": io.BytesIO(json.dumps({"campaign_id": "campaign-one", "successful": False, "cases": []}).encode())}
            with patch.object(campaign, "export_owned_versions", return_value=[{**old, "local_path": "duplicate-new-path"}, new]):
                runner.collect()
            self.assertEqual(runner.inventory["retained_artifact_versions"], [old, new])


if __name__ == "__main__":
    unittest.main()
