"""Exact task/log custody using mocked read-only SDK calls only."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cloud_io import file_sha256, task_evidence
from retain_probe_logs import retain_probe_logs


class AwsError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


def fixture(directory):
    account, region, project = "123456789012", "us-east-1", "pcfl-synthetic"
    cluster = f"arn:aws:ecs:{region}:{account}:cluster/{project}-runtime"
    image = f"{account}.dkr.ecr.{region}.amazonaws.com/{project}/coordinator@sha256:" + "a" * 64
    inventory = {"account_id": account, "region": region, "project_id": project, "campaign_id": "synthetic-campaign",
        "runtime_contract": {"cluster_arn": cluster, "task_role_arns": {}, "log_groups": {}}, "task_definition_history": {}, "observed_tasks": []}
    actual, definitions = {}, {}
    for name, number, command in (("org_01", 1, "operator"), ("coordinator", 2, "operator"), ("org_02", 3, "client")):
        definition = f"arn:aws:ecs:{region}:{account}:task-definition/{project}-{name}:1"
        role = f"arn:aws:iam::{account}:role/{project}-{name}"
        arn = cluster.replace(":cluster/", ":task/") + "/" + str(number) * 32
        task = {"taskArn": arn, "taskDefinitionArn": definition, "lastStatus": "STOPPED", "cpu": "256", "memory": "1024",
            "createdAt": datetime(2026, 1, 1, tzinfo=timezone.utc), "stoppedAt": datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
            "containers": [{"name": name, "image": image, "exitCode": 137 if name == "coordinator" else 0}],
            "tags": [{"key": key, "value": value} for key, value in {"Project": project, "Stage": "runtime", "Campaign": "synthetic-campaign"}.items()],
            "overrides": {"containerOverrides": [{"name": name, "command": [command]}]}}
        row = task_evidence(task, account, region, cluster)
        row.update(task_role_arn=role, effective_commands={name: [command]})
        inventory["observed_tasks"].append(row)
        inventory["runtime_contract"]["task_role_arns"][name] = role
        inventory["runtime_contract"]["log_groups"][name] = "/" + project + "/" + name
        inventory["task_definition_history"][definition] = {"name": name, "task_role_arn": role, "containers": [{"name": name, "image": image}]}
        definitions[definition] = {"taskDefinitionArn": definition, "taskRoleArn": role, "containerDefinitions": [{"name": name, "image": image}]}
        actual[arn] = task
    path = directory / "inventory.json"
    path.write_text(json.dumps(inventory))
    sdk = {name: Mock() for name in ("sts", "ecs", "logs")}
    sdk["sts"].get_caller_identity.return_value = {"Account": account}
    sdk["ecs"].describe_task_definition.side_effect = lambda **kwargs: {"taskDefinition": definitions[kwargs["taskDefinition"]]}
    sdk["ecs"].describe_tasks.side_effect = lambda **kwargs: {"tasks": [actual[kwargs["tasks"][0]]], "failures": []}
    sdk["logs"].get_log_events.return_value = {"events": [{"timestamp": 1, "message": "synthetic interrupted probe", "ingestionTime": 2}]}
    return path, inventory, sdk, actual


class ProbeLogRetentionTests(unittest.TestCase):
    def test_only_exact_operator_tasks_and_streams_are_retained_without_changing_inventory_or_grading_iam(self):
        with tempfile.TemporaryDirectory() as directory:
            path, inventory, sdk, actual = fixture(Path(directory))
            before = file_sha256(path)
            output = Path(directory) / "probe-retention.json"
            result = retain_probe_logs(path, sdk, output)
            self.assertTrue(result["successful"])
            self.assertTrue(result["performed_read_only"])
            self.assertFalse(result["iam_probe_validation_performed"])
            self.assertEqual(result["inventory_sha256"], before)
            self.assertEqual(file_sha256(path), before)
            self.assertEqual(len(result["tasks"]), 2)
            for receipt in result["tasks"]:
                body = json.loads(Path(receipt["path"]).read_text())
                self.assertEqual(file_sha256(receipt["path"]), receipt["sha256"])
                self.assertEqual(body["task"]["task_arn"], receipt["task_arn"])
                self.assertEqual(body["log_stream"], receipt["log_stream"])
                self.assertEqual(body["task_observation_source"], "AWS_DescribeTasks")
                self.assertTrue(body["pagination_complete"])
            streams = {call.kwargs["logStreamName"] for call in sdk["logs"].get_log_events.call_args_list}
            self.assertEqual(streams, {"runtime/org_01/" + "1" * 32, "runtime/coordinator/" + "2" * 32})
            sdk["ecs"].stop_task.assert_not_called()
            sdk["ecs"].run_task.assert_not_called()

    def test_foreign_role_command_tags_output_or_group_is_rejected_before_log_read(self):
        for mode in ("role", "command", "tag", "output", "group", "image"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path, inventory, sdk, actual = fixture(Path(directory))
                first = inventory["observed_tasks"][0]
                output = Path(directory) / "report.json"
                if mode == "role": first["task_role_arn"] = "foreign-role"
                elif mode == "command": actual[first["task_arn"]]["overrides"]["containerOverrides"][0]["command"] = ["client"]
                elif mode == "tag": actual[first["task_arn"]]["tags"][0]["value"] = "other-project"
                elif mode == "output": output = Path(directory).parent / "outside-synthetic-owned-campaign.json"
                elif mode == "group": inventory["runtime_contract"]["log_groups"]["org_01"] = "/unrelated/group"
                else: inventory["task_definition_history"][first["task_definition_arn"]]["containers"][0]["image"] = "foreign-image"
                path.write_text(json.dumps(inventory))
                with self.assertRaises(ValueError): retain_probe_logs(path, sdk, output)
                sdk["logs"].get_log_events.assert_not_called()
                self.assertFalse(output.exists())

    def test_expired_stopped_task_is_labeled_historical_but_new_missing_task_never_means_stopped(self):
        for stopped in (True, False):
            with tempfile.TemporaryDirectory() as directory:
                path, inventory, sdk, actual = fixture(Path(directory))
                inventory["observed_tasks"] = inventory["observed_tasks"][:1]
                inventory["observed_tasks"][0]["last_status"] = "STOPPED" if stopped else "PROVISIONING"
                path.write_text(json.dumps(inventory))
                sdk["ecs"].describe_tasks.side_effect = lambda **kwargs: {"tasks": [], "failures": [{"arn": kwargs["tasks"][0], "reason": "MISSING"}]}
                sdk["logs"].get_log_events.side_effect = AwsError("ResourceNotFoundException")
                output = Path(directory) / "report.json"
                if stopped:
                    result = retain_probe_logs(path, sdk, output)
                    self.assertEqual(result["tasks"][0]["task_observation_source"], "retained_historical_STOPPED_with_current_exact_MISSING")
                    self.assertEqual(result["tasks"][0]["log_stream_state"], "explicit_stream_not_found")
                    self.assertEqual(result["tasks"][0]["event_count"], 0)
                else:
                    with self.assertRaisesRegex(ValueError, "absence_unconfirmed"):
                        retain_probe_logs(path, sdk, output)
                    sdk["logs"].get_log_events.assert_not_called()

    def test_byte_bounds_pagination_cycles_and_unknown_permissions_never_report_complete(self):
        for mode in ("bytes", "cycle", "permission", "live-task", "inventory-change"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path, inventory, sdk, actual = fixture(Path(directory))
                output = Path(directory) / "report.json"
                if mode == "cycle": sdk["logs"].get_log_events.side_effect = [
                    {"events": [], "nextForwardToken": "a"}, {"events": [], "nextForwardToken": "b"}, {"events": [], "nextForwardToken": "a"}]
                elif mode == "permission": sdk["logs"].get_log_events.side_effect = AwsError("AccessDeniedException")
                elif mode == "live-task": actual[inventory["observed_tasks"][0]["task_arn"]]["lastStatus"] = "RUNNING"
                elif mode == "inventory-change":
                    def change(**kwargs):
                        path.write_text(json.dumps({**inventory, "changed_during_read": True}))
                        return {"events": []}
                    sdk["logs"].get_log_events.side_effect = change
                with self.assertRaises((ValueError, AwsError)):
                    retain_probe_logs(path, sdk, output, max_task_bytes=1 if mode == "bytes" else 1024)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
