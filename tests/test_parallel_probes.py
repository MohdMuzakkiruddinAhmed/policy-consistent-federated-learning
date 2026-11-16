"""SDK-mocked tests for the staged parallel-probe change; no AWS calls."""
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
from unittest.mock import Mock, patch

ROOT = next(path for path in Path(__file__).resolve().parents if (path / "scripts/aws_campaign.py").is_file())
sys.path.insert(0, str(ROOT / "scripts"))
STAGED_SOURCE = Path(__file__).with_name("aws_campaign.py")
SOURCE = STAGED_SOURCE if STAGED_SOURCE.is_file() else ROOT / "scripts/aws_campaign.py"
spec = importlib.util.spec_from_file_location("parallel_probe_campaign", SOURCE)
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)

NAMES = [f"org_{number:02d}" for number in range(1, 9)] + ["coordinator"]
ACCOUNT = "123456789012"
CLUSTER = f"arn:aws:ecs:us-east-1:{ACCOUNT}:cluster/pcfl-test-runtime"


def probe_config(name):
    kind = "coordinator" if name == "coordinator" else "client"
    denied = [f"partitions/iid/org_{number:02d}/train.csv" for number in range(1, 9) if f"org_{number:02d}" != name]
    denied += ["evaluation/frozen/validation.csv", "evaluation/frozen/test.csv"]
    config = {"role_kind": kind, "org_id": name, "expected_task_role_arn": f"arn:aws:iam::{ACCOUNT}:role/pcfl-test-{name}",
        "allowed_object": {"sha256": hashlib.sha256(name.encode()).hexdigest()},
        "denied_objects": [{"key": key} for key in denied], "protected_anchor_object": {"key": "anchors/campaign/witness.json"}}
    return config


def response(name):
    config = probe_config(name)
    return {"successful": True, "role": config["role_kind"] + "-isolation-probe", "role_kind": config["role_kind"],
        "org_id": name, "task_role_arn": config["expected_task_role_arn"], "own_object_sha256": config["allowed_object"]["sha256"],
        "denied_reads": [{"key_sha256": hashlib.sha256(item["key"].encode()).hexdigest(), "code": "AccessDenied"}
                         for item in config["denied_objects"]],
        "policy_write_denied": True, "anchor_write_denied": True, "record_rows_exported": False}


def template(name):
    return {"task_definition_name": name, "overrides": {"containerOverrides": [{"name": name, "command": ["operator"],
        "environment": [{"name": "PCFL_OPERATOR_CONFIG_JSON", "value": json.dumps(probe_config(name))}]}]}}


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory() as directory, patch.object(campaign, "ROOT", Path(directory)):
        clients = {name: Mock() for name in ("sts", "ecs", "logs")}
        clients["sts"].get_caller_identity.return_value = {"Account": ACCOUNT}
        request = {"account_id": ACCOUNT, "region": "us-east-1", "project_id": "pcfl-test", "campaign_id": "campaign-test"}
        runner = campaign.CampaignRunner(request, clients=clients, sleep=Mock())
        runner.approval = {"max_vcpu": 4, "max_memory_gib": 14, "max_cumulative_fleet_hours": 32}
        runner.inventory.update(runtime_contract={"cluster_arn": CLUSTER, "log_groups": {name: "/pcfl-test/" + name for name in NAMES},
                "task_definition_arns": {name: "definition-" + name for name in NAMES}},
            runtime_plan={"client_access_probe_templates": [template(name) for name in NAMES[:-1]],
                "coordinator_access_probe_template": template("coordinator"),
                "task_definitions": {name: {"cpu": "1024" if name == "coordinator" else "256",
                    "memory": "2048" if name == "coordinator" else "1024"} for name in NAMES}},
            runtime_variables={"hard_expiry_utc": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()},
            task_arns=[])
        launched, rows = [], []
        def start(name, **kwargs):
            arn = CLUSTER.replace(":cluster/", ":task/") + "/" + name
            launched.append(arn)
            rows.append({"task_arn": arn, "last_status": "STOPPED", "container_exit_codes": [0]})
            return arn
        runner.start_task = Mock(side_effect=start)
        runner.budget_check = Mock(side_effect=lambda **kwargs: deepcopy(rows))
        runner.observed_tasks = Mock(side_effect=lambda: deepcopy(rows))
        clients["logs"].get_log_events.side_effect = lambda **kwargs: {
            "events": [{"message": json.dumps(response(kwargs["logStreamName"].split("/")[1]))}]}
        yield runner, clients, launched, rows


class ParallelProbeTests(unittest.TestCase):
    def test_all_nine_launch_before_first_wait_and_evidence_is_saved_incrementally(self):
        with fixture() as (runner, clients, launched, rows):
            old = {"task_arn": "prior-probe", "probe_response": {"historical": True}}
            runner.inventory["client_probe_tasks"] = [old]
            waits = []
            def wait(**kwargs):
                self.assertEqual(len(launched), 9)
                self.assertEqual(len(runner.inventory["client_probe_tasks"]), len(waits))
                persisted = json.loads(runner.inventory_path.read_text())
                self.assertEqual(len(persisted["client_probe_tasks"]), len(waits))
                self.assertEqual(kwargs["tasks"], [launched[len(waits)]])
                waits.append(kwargs)
            clients["ecs"].get_waiter.return_value.wait.side_effect = wait
            result = runner.probe()
            self.assertEqual(result, {"actual_probe_tasks_completed": 9, "cloud_validation_complete": False})
            self.assertEqual(runner.inventory["client_probe_task_history"], [old])
            self.assertEqual(len(runner.inventory["client_probe_tasks"]), 9)
            self.assertEqual(len(waits), 9)
            for row in runner.inventory["client_probe_tasks"]:
                self.assertEqual(row["probe_log_reference"]["response_sha256"],
                    hashlib.sha256(json.dumps(row["probe_response"], sort_keys=True).encode()).hexdigest())
            clients["ecs"].stop_task.assert_not_called()

    def test_real_denial_validation_failure_retains_prior_successes_and_cleans_only_launched_probes(self):
        with fixture() as (runner, clients, launched, rows):
            def logs(**kwargs):
                name = kwargs["logStreamName"].split("/")[1]
                value = response(name)
                if name == "org_03":
                    value["denied_reads"][0]["code"] = "NoSuchKey"
                return {"events": [{"message": json.dumps(value)}]}
            clients["logs"].get_log_events.side_effect = logs
            with self.assertRaisesRegex(ValueError, "required_identity_and_denials"):
                runner.probe()
            self.assertEqual(len(runner.inventory["client_probe_tasks"]), 2)
            self.assertEqual(len(json.loads(runner.inventory_path.read_text())["client_probe_tasks"]), 2)
            stopped = {call.kwargs["task"] for call in clients["ecs"].stop_task.call_args_list}
            self.assertEqual(stopped, set(launched[3:]))
            self.assertTrue(runner.inventory["probe_failure_cleanup"]["complete"])
            self.assertEqual(set(runner.inventory["probe_failure_cleanup"]["task_arns"]), set(launched))
            clients["ecs"].update_service.assert_not_called()

    def test_cleanup_errors_remain_secondary_to_original_probe_failure(self):
        with fixture() as (runner, clients, launched, rows):
            failure = RuntimeError("synthetic_probe_wait_failure")
            clients["ecs"].get_waiter.return_value.wait.side_effect = failure
            clients["ecs"].stop_task.side_effect = OSError("synthetic_cleanup_stop_failure")
            runner.observed_tasks.side_effect = OSError("synthetic_cleanup_observation_failure")
            with self.assertRaises(RuntimeError) as raised:
                runner.probe()
            self.assertIs(raised.exception, failure)
            self.assertEqual(len(clients["ecs"].stop_task.call_args_list), 9)
            self.assertEqual(clients["ecs"].get_waiter.return_value.wait.call_count, 2)
            cleanup_wait = clients["ecs"].get_waiter.return_value.wait.call_args.kwargs
            self.assertEqual(cleanup_wait["WaiterConfig"], {"Delay": 5, "MaxAttempts": 12})
            self.assertEqual(set(cleanup_wait["tasks"]), set(launched))
            self.assertFalse(runner.inventory["probe_failure_cleanup"]["complete"])
            self.assertEqual({item["stage"] for item in runner.inventory["probe_failure_cleanup"]["errors"]}, {"stop", "wait", "observe"})

    def test_partial_launch_failure_cleans_only_returned_arns_without_waiting_on_foreign_tasks(self):
        with fixture() as (runner, clients, launched, rows):
            original_start = runner.start_task.side_effect
            failure = RuntimeError("synthetic_capacity_guard")
            def start(name, **kwargs):
                if len(launched) == 2:
                    raise failure
                return original_start(name, **kwargs)
            runner.start_task.side_effect = start
            with self.assertRaises(RuntimeError) as raised:
                runner.probe()
            self.assertIs(raised.exception, failure)
            self.assertEqual(len(launched), 2)
            self.assertEqual({call.kwargs["task"] for call in clients["ecs"].stop_task.call_args_list}, set(launched))
            self.assertEqual(clients["ecs"].get_waiter.return_value.wait.call_count, 1)
            self.assertEqual(runner.inventory["client_probe_tasks"], [])

    def test_actual_start_task_cap_counts_every_pending_reservation_before_next_launch(self):
        with fixture() as (runner, clients, launched, rows):
            runner.start_task = campaign.CampaignRunner.start_task.__get__(runner)
            runner.budget_check = campaign.CampaignRunner.budget_check.__get__(runner)
            live = [{"task_arn": "owned-live-baseline", "last_status": "RUNNING", "cpu": 3072, "memory_mib": 3072}]
            runner.observed_tasks = Mock(return_value=live)
            accepted = []
            def run_task(**kwargs):
                arn = CLUSTER.replace(":cluster/", ":task/") + "/accepted-" + str(len(accepted))
                accepted.append(arn)
                return {"tasks": [{"taskArn": arn}]}
            clients["ecs"].run_task.side_effect = run_task
            with patch.object(campaign, "bound_task_request", side_effect=lambda contract, name, campaign_id, **kwargs:
                              {"cluster": contract["cluster_arn"], "taskDefinition": contract["task_definition_arns"][name]}):
                with self.assertRaisesRegex(RuntimeError, "resource_or_duration_budget_exhausted"):
                    runner.probe()
            # Four 0.25-vCPU probes fit alongside the 3-vCPU baseline. The
            # fifth is rejected while the four accepted tasks are still absent
            # from DescribeTasks and exist only as pending reservations.
            self.assertEqual(len(accepted), 4)
            self.assertEqual(set(runner.inventory["reservations"]), set(accepted))
            self.assertEqual({call.kwargs["task"] for call in clients["ecs"].stop_task.call_args_list}, set(accepted))
            self.assertNotIn("owned-live-baseline", runner.inventory["probe_failure_cleanup"]["task_arns"])


if __name__ == "__main__":
    unittest.main()
